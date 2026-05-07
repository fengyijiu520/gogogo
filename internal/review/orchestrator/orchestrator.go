package orchestrator

import (
	"fmt"
	"strings"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
	"skill-scanner/internal/review/evidence"
	"skill-scanner/internal/review/intent"
	"skill-scanner/internal/review/sandbox"
	"skill-scanner/internal/review/scoring"
	"skill-scanner/internal/review/ti"
)

type Input struct {
	Description  string
	Permissions  []string
	ScanPath     string
	BaseScore    float64
	BaseFindings []plugins.Finding

	DifferentialEnabled bool
	DelayThresholdSecs  int
}

type Orchestrator struct {
	sandbox *sandbox.Runner
	intent  *intent.Engine
	ti      *ti.Adapter
	score   *scoring.Engine
}

func New() *Orchestrator {
	return &Orchestrator{
		sandbox: sandbox.NewRunner(),
		intent:  intent.NewEngine(),
		ti:      ti.NewAdapter(),
		score:   scoring.NewEngine(),
	}
}

func (o *Orchestrator) Run(in Input) (review.Result, error) {
	result := review.Result{Findings: in.BaseFindings}
	result.Pipeline = append(result.Pipeline, review.PipelineStage{
		Name:       "sandbox_prepare",
		Purpose:    "确认运行行为分析环境可用",
		Status:     "running",
		Input:      in.ScanPath,
		Benefit:    "避免在关键执行证据缺失时生成低可信报告",
		MethodNote: "先确认关键运行证据能力，再进入后续分析阶段",
	})

	if err := o.sandbox.Prepare(); err != nil {
		result.Summary = o.score.ComputeByRisk(1, 0, 0, true, "SANDBOX_NOT_READY")
		result.Pipeline[len(result.Pipeline)-1].Status = "failed"
		result.Pipeline[len(result.Pipeline)-1].Output = err.Error()
		return result, fmt.Errorf("沙箱功能不可用，已阻断扫描，请启用并修复沙箱运行环境后重试: %w", err)
	}
	result.Pipeline[len(result.Pipeline)-1].Status = "completed"
	result.Pipeline[len(result.Pipeline)-1].Output = "沙箱环境可用"
	result.Pipeline = append(result.Pipeline, review.PipelineStage{
		Name:       "sandbox_execute",
		Purpose:    "执行隔离探针并提取下载、执行、外联、凭据访问、持久化等行为证据",
		Status:     "running",
		Input:      in.ScanPath,
		Benefit:    "把静态规则看不到的真实运行行为纳入用户决策证据链",
		MethodNote: "行为证据与状态追踪分阶段输出，便于定位漏检原因",
	})

	behavior, iocs, err := o.sandbox.Execute(in.ScanPath, sandbox.ExecuteOptions{
		DifferentialEnabled: in.DifferentialEnabled,
		DelayThresholdSecs:  in.DelayThresholdSecs,
	})
	if err != nil {
		result.Summary = o.score.ComputeByRisk(1, 0, 0, true, "SANDBOX_EXEC_FAILED")
		result.Pipeline[len(result.Pipeline)-1].Status = "failed"
		result.Pipeline[len(result.Pipeline)-1].Output = err.Error()
		return result, fmt.Errorf("沙箱行为分析执行失败，已阻断扫描，请检查沙箱镜像、运行时和待扫描文件后重试: %w", err)
	}
	result.Behavior = behavior
	applyStaticBehaviorCrossChecks(&result.Behavior, in.BaseFindings)
	result.Evasion = assessEvasion(behavior)
	result.Pipeline[len(result.Pipeline)-1].Status = "completed"
	result.Pipeline[len(result.Pipeline)-1].Output = fmt.Sprintf("提取行为证据类别 %d 类，IoC %d 个", evidence.CountBehaviorCategories(behavior), len(iocs))
	result.Pipeline = append(result.Pipeline, review.PipelineStage{
		Name:       "intent_compare",
		Purpose:    "对比技能声明、用户权限声明与沙箱实际行为",
		Status:     "running",
		Input:      in.Description,
		Benefit:    "发现声明没有说但代码实际做了的高风险能力",
		MethodNote: "把声明、权限和行为放入同一证据链做一致性复核",
	})

	_, diffs := o.intent.Evaluate(in.Description, in.Permissions, behavior)
	result.IntentDiffs = diffs
	result.Pipeline[len(result.Pipeline)-1].Status = "completed"
	result.Pipeline[len(result.Pipeline)-1].Output = fmt.Sprintf("发现声明/行为差异 %d 项", len(diffs))
	result.Pipeline = append(result.Pipeline, review.PipelineStage{
		Name:       "threat_intel",
		Purpose:    "查询外联目标和 IoC 的信誉信息",
		Status:     "running",
		Input:      fmt.Sprintf("IoC %d 个", len(iocs)),
		Benefit:    "区分普通网络访问与可疑外联、C2、数据外发目标",
		MethodNote: "将信誉信息并入攻击路径与影响判断",
	})

	reputations, malicious, tiAdjustment := o.ti.Query(iocs)
	result.TIReputations = reputations
	result.Pipeline[len(result.Pipeline)-1].Status = "completed"
	result.Pipeline[len(result.Pipeline)-1].Output = fmt.Sprintf("信誉结果 %d 项，可疑=%t，调整=%.1f", len(reputations), malicious, tiAdjustment)

	behaviorDeduction, behaviorVeto, behaviorReason := assessBehaviorRisk(behavior)

	vetoReason := ""
	if malicious {
		vetoReason = "命中可疑外联目标"
	}
	if behaviorVeto {
		malicious = true
		if vetoReason != "" {
			vetoReason += "；"
		}
		vetoReason += behaviorReason
	}
	if result.Evasion.Detected {
		malicious = true
		if vetoReason != "" {
			vetoReason += "；"
		}
		vetoReason += "命中反沙箱/反虚拟机逃逸迹象"
	}

	high, medium, low := deriveCalibratedRiskCounts(result.Findings, diffs, reputations, behavior, result.Evasion, malicious, behaviorVeto)
	result.Summary = o.score.ComputeByRisk(high, medium, low, malicious, vetoReason)
	result.Summary.BaseScore = in.BaseScore
	result.Summary.ICS = 100 - minFloat(100, behaviorDeduction)
	result.Summary.TIAdjustment = tiAdjustment
	result.EvidenceInventory = evidence.BuildInventory(behavior, diffs, reputations, result.Evasion)
	result.OptimizationNotes = defaultOptimizationNotes()
	result.Pipeline = append(result.Pipeline, review.PipelineStage{
		Name:       "risk_calibration",
		Purpose:    "合并静态发现、行为证据、意图差异、威胁情报和逃逸信号",
		Status:     "completed",
		Output:     fmt.Sprintf("高:%d 中:%d 低:%d 风险等级:%s", high, medium, low, result.Summary.RiskLevel),
		Benefit:    "避免单条规则直接替用户下结论，改为解释风险来源和校准依据",
		MethodNote: "按多源证据统一校准风险，而不是依赖单点命中",
	})
	return result, nil
}

func applyStaticBehaviorCrossChecks(behavior *review.BehaviorProfile, findings []plugins.Finding) {
	if behavior == nil {
		return
	}
	staticExternal := false
	staticExec := false
	staticCredential := false
	for _, finding := range findings {
		text := strings.ToLower(strings.Join([]string{finding.RuleID, finding.Title, finding.Description, finding.CodeSnippet}, " "))
		if strings.Contains(text, "外联") || strings.Contains(text, "network") || strings.Contains(text, "http") || strings.Contains(text, "url") || strings.Contains(text, "c2") || strings.Contains(text, "远程") {
			staticExternal = true
		}
		if strings.Contains(text, "执行") || strings.Contains(text, "command") || strings.Contains(text, "shell") || strings.Contains(text, "exec") {
			staticExec = true
		}
		if strings.Contains(text, "凭据") || strings.Contains(text, "credential") || strings.Contains(text, "token") || strings.Contains(text, "secret") || strings.Contains(text, "key") {
			staticCredential = true
		}
	}
	addWarning := func(warning string) {
		for _, existing := range behavior.ProbeWarnings {
			if existing == warning {
				return
			}
		}
		behavior.ProbeWarnings = append(behavior.ProbeWarnings, warning)
	}
	if staticExternal && len(behavior.OutboundIOCs) == 0 && len(behavior.NetworkTargets) == 0 {
		addWarning("静态/LLM 发现外联迹象，但沙箱外联证据未检出；需检查动态拼接 URL、条件执行、入口未触发或探针覆盖不足")
	}
	if staticExec && len(behavior.ExecuteIOCs) == 0 {
		addWarning("静态/LLM 发现命令执行迹象，但沙箱执行证据未检出；需检查入口未触发、条件分支或探针覆盖不足")
	}
	if staticCredential && len(behavior.CredentialIOCs) == 0 {
		addWarning("静态/LLM 发现凭据访问迹象，但沙箱凭据证据未检出；需检查动态路径、环境依赖或探针覆盖不足")
	}
}

func limitStrings(items []string, limit int) []string {
	if len(items) <= limit {
		return append([]string{}, items...)
	}
	return append([]string{}, items[:limit]...)
}

func defaultOptimizationNotes() []review.OptimizationNote {
	return []review.OptimizationNote{
		{Change: "引入阶段化 Pipeline", Reason: "原扫描链路只暴露最终结果，用户难以判断每个关键分析阶段是否真实完成", Benefit: "报告可以展示每个阶段的输入、输出、状态和收益，分析过程更可解释"},
		{Change: "归一化证据目录", Reason: "静态发现、沙箱行为、意图差异和威胁情报分散在不同结构里", Benefit: "用户可以按证据类别快速理解技能整体行为，而不是只看规则命中列表"},
		{Change: "风险校准与用户决策分离", Reason: "系统自动给出可用/不可用容易掩盖业务上下文和授权差异", Benefit: "系统负责证据和风险解释，用户负责最终使用判断，降低误判带来的决策风险"},
		{Change: "增强误报复核链路", Reason: "单条规则命中不等于真实攻击路径成立", Benefit: "通过行为链、时序、IoC 和声明差异共同校准风险，减少孤立信号导致的误报"},
		{Change: "增加静态/沙箱交叉校验", Reason: "静态规则或 LLM 可能发现外联、执行、凭据访问，但沙箱因入口未触发、动态拼接或探针覆盖不足未检出", Benefit: "报告会显式暴露证据矛盾，避免用户误以为沙箱未检出就代表相关能力不存在"},
		{Change: "引入能力一致性矩阵", Reason: "声明、静态规则、LLM、沙箱和情报结果原本分散展示，难以判断每类能力是否真正被验证", Benefit: "按能力聚合多源证据和缺口，直接暴露已声明未验证、未声明但检出、沙箱盲区等系统性问题"},
	}
}

func hasHighRiskIntentDiff(diffs []review.IntentDiff) bool {
	for _, diff := range diffs {
		switch diff.Type {
		case "unexpected_exec", "unexpected_data_collection", "unexpected_external_dependency", "unsafe_declaration_prompt":
			return true
		}
	}
	return false
}

func deriveCalibratedRiskCounts(findings []plugins.Finding, diffs []review.IntentDiff, reputations []review.TIReputation, behavior review.BehaviorProfile, evasion review.EvasionAssessment, malicious bool, behaviorVeto bool) (int, int, int) {
	high, medium, low := countFindingRisks(findings)
	if hasHighRiskIntentDiff(diffs) {
		high++
	} else if len(diffs) > 0 {
		medium++
	}
	if hasSuspiciousReputation(reputations) {
		medium++
	}
	if hasModerateBehaviorSignals(behavior) {
		medium++
	}
	if malicious || behaviorVeto || evasion.Detected {
		high++
	}
	return high, medium, low
}

func hasSuspiciousReputation(reputations []review.TIReputation) bool {
	for _, item := range reputations {
		label := strings.ToLower(strings.TrimSpace(item.Reputation))
		if label == "malicious" || label == "suspicious" || label == "high-risk" {
			return true
		}
	}
	return false
}

func hasModerateBehaviorSignals(behavior review.BehaviorProfile) bool {
	if len(behavior.SequenceAlerts) > 0 || len(behavior.BehaviorChains) > 0 {
		return true
	}
	if len(behavior.ProbeWarnings) > 0 && (len(behavior.ExecuteIOCs) > 0 || len(behavior.OutboundIOCs) > 0 || len(behavior.CredentialIOCs) > 0) {
		return true
	}
	if len(behavior.CredentialIOCs) > 0 || len(behavior.PrivEscIOCs) > 0 || len(behavior.C2BeaconIOCs) > 0 || len(behavior.CollectionIOCs) > 0 {
		return true
	}
	return false
}

func countFindingRisks(findings []plugins.Finding) (int, int, int) {
	high, medium, low := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "高风险", "high", "critical":
			high++
		case "中风险", "medium":
			medium++
		default:
			low++
		}
	}
	return high, medium, low
}

func assessBehaviorRisk(behavior review.BehaviorProfile) (float64, bool, string) {
	deduction := 0.0
	reasons := make([]string, 0, 8)
	veto := false

	if len(behavior.BehaviorChains) > 0 {
		deduction += minFloat(18, float64(len(behavior.BehaviorChains))*3)
		reasons = append(reasons, "命中高风险行为链路")
	}
	if len(behavior.PersistenceIOCs) > 0 {
		deduction += minFloat(10, float64(len(behavior.PersistenceIOCs))*2)
		reasons = append(reasons, "命中持久化迹象")
	}
	if len(behavior.PrivEscIOCs) > 0 {
		deduction += minFloat(12, float64(len(behavior.PrivEscIOCs))*3)
		reasons = append(reasons, "命中提权迹象")
	}
	if len(behavior.CredentialIOCs) > 0 {
		deduction += minFloat(12, float64(len(behavior.CredentialIOCs))*3)
		reasons = append(reasons, "命中凭据访问迹象")
	}
	if len(behavior.DefenseEvasionIOCs) > 0 {
		deduction += minFloat(10, float64(len(behavior.DefenseEvasionIOCs))*2)
		reasons = append(reasons, "命中防御规避迹象")
	}
	if len(behavior.LateralMoveIOCs) > 0 {
		deduction += minFloat(10, float64(len(behavior.LateralMoveIOCs))*2)
		reasons = append(reasons, "命中横向移动迹象")
	}
	if len(behavior.CollectionIOCs) > 0 {
		deduction += minFloat(8, float64(len(behavior.CollectionIOCs))*2)
		reasons = append(reasons, "命中数据收集/打包迹象")
	}
	if len(behavior.C2BeaconIOCs) > 0 {
		deduction += minFloat(12, float64(len(behavior.C2BeaconIOCs))*3)
		reasons = append(reasons, "命中C2信标迹象")
	}
	if len(behavior.SequenceAlerts) > 0 {
		deduction += minFloat(12, float64(len(behavior.SequenceAlerts))*3)
		reasons = append(reasons, "命中恶意行为时序")
	}

	if len(behavior.ProbeWarnings) > 0 {
		deduction += minFloat(6, float64(len(behavior.ProbeWarnings)))
	}

	if len(behavior.PrivEscIOCs) > 0 && (len(behavior.ExecuteIOCs) > 0 || len(behavior.BehaviorChains) > 0) {
		veto = true
	}
	if len(behavior.CredentialIOCs) > 0 && len(behavior.OutboundIOCs) > 0 {
		veto = true
	}
	if len(behavior.DefenseEvasionIOCs) > 0 && len(behavior.ExecuteIOCs) > 0 {
		veto = true
	}
	if len(behavior.LateralMoveIOCs) > 0 && (len(behavior.C2BeaconIOCs) > 0 || len(behavior.ExecuteIOCs) > 0) {
		veto = true
	}
	if len(behavior.CollectionIOCs) > 0 && len(behavior.OutboundIOCs) > 0 {
		veto = true
	}
	if len(behavior.C2BeaconIOCs) > 0 && len(behavior.ExecuteIOCs) > 0 {
		veto = true
	}
	for _, alert := range behavior.SequenceAlerts {
		if alert == "命中凭据访问后外联时序" || alert == "命中防御规避后执行时序" || alert == "命中横向移动联动控制时序" {
			veto = true
			break
		}
	}

	if !veto {
		return deduction, false, ""
	}
	return deduction, true, joinReasons(reasons)
}

func joinReasons(reasons []string) string {
	if len(reasons) == 0 {
		return "命中恶意行为证据"
	}
	out := ""
	for i, reason := range reasons {
		if i > 0 {
			out += "，"
		}
		out += reason
	}
	return out
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

func assessEvasion(behavior review.BehaviorProfile) review.EvasionAssessment {
	assessment := review.EvasionAssessment{
		Detected:      false,
		Severity:      "low",
		Signals:       behavior.EvasionSignals,
		Differentials: behavior.Differentials,
	}

	if len(behavior.EvasionSignals) == 0 {
		assessment.Recommendation = "未发现明确反分析迹象，建议持续保持差分执行审计。"
		return assessment
	}

	assessment.Detected = true
	assessment.Severity = "critical"
	assessment.Recommendation = "请移除环境识别与反分析分支，改为显式能力开关；修复后在多画像环境下复测并确认行为一致。"
	return assessment
}

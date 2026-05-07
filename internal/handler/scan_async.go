package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"

	"skill-scanner/internal/analyzer"
	"skill-scanner/internal/config"
	"skill-scanner/internal/docx"
	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/models"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
	"skill-scanner/internal/review/evidence"
	"skill-scanner/internal/review/inventory"
	"skill-scanner/internal/review/orchestrator"
	reviewreport "skill-scanner/internal/review/report"
	"skill-scanner/internal/storage"
)

type customRuleInput struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Layer    string   `json:"layer"`
	Patterns []string `json:"patterns"`
	Reason   string   `json:"reason"`
}

type differentialOptions struct {
	Enabled            bool
	DelayThresholdSecs int
}

type baseScanOutput struct {
	findings         []plugins.Finding
	evalLogs         []ruleEvaluationLog
	trace            []analysisTraceEvent
	score            float64
	p0               bool
	reasons          []string
	totalRules       int
	evaluatedRules   int
	uncheckedRules   []string
	coverageNote     string
	v5Coverage       v5CoverageSummary
	intentSummary    intentReportSummary
	profile          skillAnalysisProfile
	ruleProfile      ruleSetProfile
	ruleExplanations []review.RuleExplanation
	llmClient        llm.Client
	sourceRoot       string
	sourceFiles      []evaluator.SourceFile
	cacheStats       incrementalCacheStats
}

type incrementalCacheStats struct {
	Enabled       bool
	Candidate     int
	Hit           int
	Miss          int
	CacheFilePath string
}

type scanFileFingerprint struct {
	RelPath  string `json:"rel_path"`
	Language string `json:"language"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	ModUnix  int64  `json:"mod_unix"`
}

type cachedSourceArtifact struct {
	Fingerprint scanFileFingerprint `json:"fingerprint"`
	Source      evaluator.SourceFile `json:"source"`
}

type sourceArtifactCache struct {
	Version string                           `json:"version"`
	Order   []string                         `json:"order,omitempty"`
	Files   map[string]cachedSourceArtifact  `json:"files"`
}

const sourceArtifactCacheVersion = "v1"

type skillAnalysisProfile = inventory.Profile

type analysisTraceEvent struct {
	Stage   string `json:"stage"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

type riskCalibrationSummary struct {
	Policy             string   `json:"policy"`
	RiskLevel          string   `json:"risk_level"`
	Decision           string   `json:"decision"`
	UserActionRequired bool     `json:"user_action_required"`
	Basis              []string `json:"basis"`
	ConfidenceNotes    []string `json:"confidence_notes"`
}

const reportGeneratorNote = "Skill Scanner 结构化审查流水线"

type ruleSetProfile struct {
	Version         string   `json:"version"`
	Total           int      `json:"total"`
	ByLayer         []string `json:"by_layer"`
	BySeverity      []string `json:"by_severity"`
	ByDetectionType []string `json:"by_detection_type"`
	BlockedRules    []string `json:"blocked_rules"`
	ReviewRules     []string `json:"review_rules"`
	Reason          string   `json:"reason"`
	Benefit         string   `json:"benefit"`
}

type intentReportSummary struct {
	Available            bool     `json:"available"`
	DeclaredIntent       string   `json:"declared_intent"`
	ActualBehavior       string   `json:"actual_behavior"`
	DeclaredCapabilities []string `json:"declared_capabilities,omitempty"`
	ActualCapabilities   []string `json:"actual_capabilities,omitempty"`
	ConsistencyEvidence  []string `json:"consistency_evidence,omitempty"`
	IntentRiskLevel      string   `json:"intent_risk_level"`
	IntentMismatch       string   `json:"intent_mismatch,omitempty"`
	UnavailableReason    string   `json:"unavailable_reason,omitempty"`
}

type v5CoverageSummary struct {
	Version          string
	AutoTotal        int
	AutoCovered      int
	AutoUncovered    []string
	ManualTotal      int
	ManualCandidates []string
	Note             string
}

type ruleEvaluationLog struct {
	RuleID            string   `json:"rule_id"`
	RuleName          string   `json:"rule_name"`
	Layer             string   `json:"layer"`
	DetectionType     string   `json:"detection_type"`
	DetectionProcess  string   `json:"detection_process"`
	DetectionResult   string   `json:"detection_result"`
	RiskLabel         string   `json:"risk_label"`
	Evaluated         bool     `json:"evaluated"`
	EvidenceLocations []string `json:"evidence_locations,omitempty"`
}

func handleScanAsync(store *storage.Store, w http.ResponseWriter, r *http.Request, sess *Session) bool {
	for _, item := range store.AnalyzerFalsePositiveFeedback() {
		analyzer.LearnFalsePositives(item.RuleID, item.Tokens)
	}
	taskStore.pruneExpired(scanTaskTTL)
	if ok, reason := taskStore.canCreate(sess.Username); !ok {
		sendJSON(w, http.StatusTooManyRequests, map[string]string{"error": reason})
		return true
	}

	if err := ValidateScanPreflight(store, sess.Username); err != nil {
		sendJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error":      "扫描前置自检未通过",
			"details":    err.Error(),
			"suggestion": "请根据错误详情逐项修复后重试；如涉及 LLM，请先在个人中心完成配置。",
		})
		return true
	}

	if err := r.ParseMultipartForm(100 << 20); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "文件太大或解析失败"})
		return true
	}
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "请上传至少一个文件"})
		return true
	}
	if err := validateUploadedFiles(files); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return true
	}

	originalName := files[0].Filename
	if len(files) > 1 {
		originalName = fmt.Sprintf("%s 等 %d 个文件", originalName, len(files))
	}

	taskID, err := storage.GenerateID()
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "生成任务ID失败"})
		return true
	}
	taskDir := filepath.Join(store.DataDir(), "tasks", taskID)
	if err := os.MkdirAll(taskDir, 0755); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "创建任务目录失败"})
		return true
	}

	for _, fh := range files {
		if fh.Size == 0 {
			continue
		}
		relPath := filepath.Clean(fh.Filename)
		destPath := filepath.Join(taskDir, relPath)
		if !storage.IsPathSafe(taskDir, relPath) {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "文件路径不安全"})
			return true
		}
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "创建目录失败"})
			return true
		}
		src, openErr := fh.Open()
		if openErr != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "读取文件失败"})
			return true
		}
		dst, createErr := os.Create(destPath)
		if createErr != nil {
			src.Close()
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "保存文件失败"})
			return true
		}
		_, copyErr := io.Copy(dst, src)
		src.Close()
		dst.Close()
		if copyErr != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "写入文件失败"})
			return true
		}
	}

	if err := validateExtractedFiles(taskDir); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return true
	}

	description := r.FormValue("description")
	permissions := parsePermissions(r.FormValue("permissions"))
	selectedRuleIDs := parseSelectedRuleIDs(r.FormValue("selected_rule_ids"))
	customRules := parseCustomRules(r.FormValue("custom_rules"))
	diffOptions := differentialOptions{
		Enabled:            parseBoolWithDefault(r.FormValue("differential_enabled"), readDifferentialEnabled()),
		DelayThresholdSecs: parsePositiveIntWithDefault(r.FormValue("evasion_delay_threshold_secs"), readDelayThresholdSec()),
	}
	taskStore.create(taskID, sess.Username, originalName)

	go runScanTask(store, taskID, taskDir, sess.Username, originalName, description, permissions, selectedRuleIDs, customRules, diffOptions)

	sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":   true,
		"task_id":   taskID,
		"status":    review.PhaseQueued,
		"file_name": originalName,
	})
	return true
}

func runScanTask(store *storage.Store, taskID, scanPath, username, originalName, description string, permissions []string, selectedRuleIDs []string, customRules []customRuleInput, diffOptions differentialOptions) {
	defer os.RemoveAll(scanPath)
	description = resolveSkillDescription(description, scanPath)
	trace := []analysisTraceEvent{
		newAnalysisTraceEvent("queued", "completed", "扫描任务已入队并完成技能声明解析", originalName),
	}

	taskStore.update(taskID, func(t *scanTask) {
		t.Status = review.PhaseP0
		t.Message = "执行高优先级风险检测"
		t.Progress["p0"] = true
	})

	base, err := performBaseScan(store, username, scanPath, originalName, description, permissions, selectedRuleIDs, customRules)
	if err != nil {
		taskStore.release(taskID, review.PhaseFailed, err.Error())
		return
	}
	base.trace = append(trace, base.trace...)

	taskStore.update(taskID, func(t *scanTask) {
		t.Status = review.PhaseP1
		t.Message = "执行重点风险复核"
		t.Progress["p1"] = true
	})

	orc := orchestrator.New()
	refined, reviewErr := orc.Run(orchestrator.Input{
		Description:         description,
		Permissions:         permissions,
		ScanPath:            scanPath,
		BaseScore:           base.score,
		BaseFindings:        base.findings,
		DifferentialEnabled: diffOptions.Enabled,
		DelayThresholdSecs:  diffOptions.DelayThresholdSecs,
	})
	if reviewErr != nil {
		taskStore.release(taskID, review.PhaseFailed, reviewErr.Error())
		return
	}
	refined.ObfuscationEvidence = buildObfuscationEvidence(base.sourceFiles)
	base.trace = append(base.trace, newAnalysisTraceEvent("behavior_review", "completed", "沙箱行为、差分执行和威胁情报复核完成", fmt.Sprintf("行为证据类别: %d", countBehaviorEvidenceCategories(refined.Behavior))))

	taskStore.update(taskID, func(t *scanTask) {
		t.Status = review.PhaseP2
		t.Message = "执行低风险整改检测"
		t.Progress["p2"] = true
	})

	findings := append([]plugins.Finding{}, refined.Findings...)
	findings = append(findings, synthesizeIntentFindings(refined.IntentDiffs)...)
	findings = append(findings, synthesizeTIFindings(refined.TIReputations)...)
	findings = append(findings, synthesizeEvasionFindings(refined.Evasion)...)
	findings = append(findings, synthesizeBehaviorFindings(refined.Behavior)...)
	findings = append(findings, synthesizeV5CoverageFindings(base.v5Coverage)...)
	findings = localizeFindings(findings)
	refined.StructuredFindings = buildStructuredFindings(findings, refined, base.sourceRoot, base.sourceFiles)
	refined.VulnerabilityBlocks = buildVulnerabilityBlocks(refined.StructuredFindings)
	refined.RuleExplanations = markTriggeredRuleExplanations(base.ruleExplanations, findings)
	refined.FalsePositiveReviews = buildFalsePositiveReviews(refined.StructuredFindings, refined)
	refined.DetectionComparison = buildDetectionChainComparison(base, refined)
	refined.OptimizationNotes = append(refined.OptimizationNotes, buildDetectionComparisonOptimizationNotes(refined.DetectionComparison)...)
	refined.ReviewAgentTasks = buildReviewAgentTasks(refined)
	deterministicVerdicts, deterministicStats := executeDeterministicReviewAgentWithStats(refined)
	refined.ReviewAgentVerdicts = deterministicVerdicts
	if deterministicStats.TaskCount > 0 {
		refined.ReviewAgentStats = append(refined.ReviewAgentStats, deterministicStats)
	}
	if len(refined.ReviewAgentTasks) > 0 {
		llmVerdicts, llmStats, llmReviewErr := executeLLMReviewAgentWithStats(context.Background(), base.llmClient, refined)
		if llmStats.TaskCount > 0 {
			refined.ReviewAgentStats = append(refined.ReviewAgentStats, llmStats)
		}
		if llmReviewErr != nil {
			taskStore.release(taskID, review.PhaseFailed, "LLM 二次复核执行失败，扫描无法完成: "+llmReviewErr.Error())
			return
		}
		refined.ReviewAgentVerdicts = mergeReviewAgentVerdicts(refined.ReviewAgentVerdicts, llmVerdicts)
	}
	applyAutomaticFalsePositiveFeedback(store, refined)
	refined.CapabilityMatrix = buildCapabilityMatrix(findings, base, refined)
	refined.AuditEvents = buildAuditEvents(base, refined)
	refined.Summary.HighRisk, refined.Summary.MediumRisk, refined.Summary.LowRisk = countReviewedFindingRisks(findings, refined)
	refined.Summary.RiskLevel, refined.Summary.Admission = decisionFromReviewedFindings(base, refined)
	base.trace = append(base.trace, newAnalysisTraceEvent("risk_calibration", "completed", "风险等级已按证据重新校准，结论保留为用户决策", fmt.Sprintf("高:%d 中:%d 低:%d", refined.Summary.HighRisk, refined.Summary.MediumRisk, refined.Summary.LowRisk)))

	taskStore.update(taskID, func(t *scanTask) {
		t.Status = review.PhaseScoring
		t.Message = "汇总风险等级并生成报告"
		t.Progress["scoring"] = true
	})

	reportID, pdfTrace, reportErr := persistReports(store, taskID, username, originalName, description, findings, base, refined)
	if reportErr != nil {
		taskStore.update(taskID, func(t *scanTask) {
			t.Status = review.PhaseFailed
			t.Message = reportErr.Error()
			t.PDFTrace = pdfTrace.TraceMessage()
			t.PDFEngine = pdfTrace.Engine
			t.PDFFontFile = pdfTrace.FontFile
		})
		return
	}

	taskStore.update(taskID, func(t *scanTask) {
		t.Status = review.PhaseDone
		t.Message = fmt.Sprintf("扫描完成（高:%d 中:%d 低:%d）", refined.Summary.HighRisk, refined.Summary.MediumRisk, refined.Summary.LowRisk)
		t.ReportID = reportID
		t.FindingCount = len(findings)
		t.HighRisk = refined.Summary.HighRisk
		t.MediumRisk = refined.Summary.MediumRisk
		t.LowRisk = refined.Summary.LowRisk
		t.PDFTrace = pdfTrace.TraceMessage()
		t.PDFEngine = pdfTrace.Engine
		t.PDFFontFile = pdfTrace.FontFile
	})
}

func applyAutomaticFalsePositiveFeedback(store *storage.Store, refined review.Result) {
	if store == nil || len(refined.StructuredFindings) == 0 || len(refined.ReviewAgentVerdicts) == 0 {
		return
	}
	verdicts := preferredVerdictsByFinding(refined.ReviewAgentVerdicts)
	for _, finding := range refined.StructuredFindings {
		verdict, ok := verdicts[finding.ID]
		if !ok || verdict.Verdict != "likely_false_positive" {
			continue
		}
		tokens := extractFalsePositiveFeedbackTokens(finding)
		if len(tokens) == 0 {
			continue
		}
		ruleID := strings.TrimSpace(finding.RuleID)
		for _, token := range tokens {
			_ = store.AddAnalyzerFalsePositiveFeedback(ruleID, token)
		}
		analyzer.LearnFalsePositives(ruleID, tokens)
	}
}

func extractFalsePositiveFeedbackTokens(finding review.StructuredFinding) []string {
	set := map[string]bool{}
	for _, ev := range finding.Evidence {
		line := strings.ToLower(strings.TrimSpace(ev))
		if line == "" {
			continue
		}
		for _, token := range []string{"localhost", "127.0.0.1", "0.0.0.0", "::1", "readme.md", "skill.md", "docs/", "examples/", "testdata/"} {
			if strings.Contains(line, token) {
				set[token] = true
			}
		}
	}
	out := make([]string, 0, len(set))
	for token := range set {
		out = append(out, token)
	}
	sort.Strings(out)
	return out
}

func resolveSkillDescription(formDescription, scanPath string) string {
	return reviewreport.ResolveSkillDescription(formDescription, scanPath)
}

func extractSkillDeclaration(scanPath string) string {
	return reviewreport.ExtractSkillDeclaration(scanPath)
}

func performBaseScan(store *storage.Store, username, scanPath, originalName, description string, permissions []string, selectedRuleIDs []string, customRules []customRuleInput) (baseScanOutput, error) {
	out := baseScanOutput{score: 100}
	out.trace = append(out.trace, newAnalysisTraceEvent("preflight", "running", "开始关键组件自检", "语义模型、LLM、规则矩阵"))
	cfg, err := config.Load(config.RulesConfigPath())
	if err != nil {
		cfg = getDefaultConfig()
	}
	cfg = buildEffectiveConfig(cfg, selectedRuleIDs, customRules)
	out.totalRules = len(cfg.Rules)
	out.ruleProfile = buildRuleSetProfile(cfg)
	out.ruleExplanations = buildRuleExplanations(cfg)
	v5Matrix, matrixErr := config.LoadV5Matrix("config/v7_matrix.yaml")

	if globalEmbedder == nil || embedderInitError != nil {
		errMsg := "模型未初始化"
		if embedderInitError != nil {
			errMsg = embedderInitError.Error()
		}
		return out, fmt.Errorf("语义引擎不可用，已阻断扫描，请启用并修复语义模型后重试: %s", errMsg)
	}

	var llmClient llm.Client
	userLLM := store.GetUserLLMConfig(username)
	if userLLM != nil && userLLM.Enabled && userLLM.APIKey != "" {
		switch userLLM.Provider {
		case "deepseek":
			llmClient = llm.NewDeepSeekClient(userLLM.APIKey)
		case "minimax":
			if userLLM.MiniMaxGroupID != "" {
				llmClient = llm.NewMiniMaxClient(userLLM.MiniMaxGroupID, userLLM.APIKey)
			}
		}
	}
	if llmClient == nil {
		return out, fmt.Errorf("LLM 功能未启用，已阻断扫描，请在个人中心配置可用的 LLM 后重试")
	}
	out.llmClient = llmClient
	out.trace = append(out.trace, newAnalysisTraceEvent("preflight", "completed", "关键组件自检通过", fmt.Sprintf("规则数:%d", out.totalRules)))

	eval := evaluator.NewEvaluator(globalEmbedder, llmClient, cfg)
	files, dependencies, cacheStats := collectSourceArtifacts(scanPath, llmClient)
	out.sourceRoot = scanPath
	out.sourceFiles = append([]evaluator.SourceFile{}, files...)
	out.cacheStats = cacheStats
	out.profile = buildSkillAnalysisProfile(scanPath, files, dependencies, permissions)
	out.trace = append(out.trace, newAnalysisTraceEvent("artifact_collection", "completed", "已收集技能声明、源码和依赖画像", fmt.Sprintf("文件:%d 依赖:%d", out.profile.SourceFileCount, out.profile.DependencyCount)))
	if cacheStats.Enabled {
		hitRate := incrementalCacheHitRate(cacheStats)
		out.trace = append(out.trace, newAnalysisTraceEvent("incremental_cache", "completed", "增量扫描缓存统计", fmt.Sprintf("模式:增量 候选:%d 命中:%d 未命中:%d 命中率:%.1f%%", cacheStats.Candidate, cacheStats.Hit, cacheStats.Miss, hitRate)))
	} else {
		out.trace = append(out.trace, newAnalysisTraceEvent("incremental_cache", "completed", "增量扫描缓存统计", "模式:全量重建（缓存关闭）"))
	}
	skill := &evaluator.Skill{
		Name:         originalName,
		Description:  description,
		Files:        files,
		Dependencies: dependencies,
		Permissions:  permissions,
	}
	result, evalErr := eval.EvaluateWithCascade(context.Background(), skill)
	if evalErr != nil {
		return out, fmt.Errorf("级联评估执行失败，已阻断扫描，请修复评估引擎后重试: %w", evalErr)
	}
	if result.IntentAnalysis == nil {
		return out, fmt.Errorf("LLM 意图分析未返回有效结果，已阻断扫描，请检查 LLM 配置、网络和服务可用性后重试")
	}
	out.trace = append(out.trace, newAnalysisTraceEvent("semantic_evaluation", "completed", "V7 规则、语义模型和 LLM 意图分析完成", fmt.Sprintf("已评估规则:%d", len(result.ItemScores))))
	out.findings = convertResultToFindings(result, cfg)
	out.evalLogs = buildRuleEvaluationLogs(cfg.Rules, result.ItemScores, result.FindingDetails)
	out.score = result.Score
	out.p0 = result.P0Blocked
	out.reasons = result.P0Reasons
	out.intentSummary = buildIntentReportSummary(result.IntentAnalysis)
	out.evaluatedRules = len(result.ItemScores)
	out.uncheckedRules = collectUncheckedRuleIDs(cfg, result.ItemScores)
	out.v5Coverage = buildV5CoverageSummary(v5Matrix, matrixErr, cfg, result.ItemScores)
	if len(out.uncheckedRules) == 0 {
		out.coverageNote = buildCoverageNote("已完成当前规则集全量检测；系统仅提供证据、风险标记和复核建议，最终是否使用由用户判断", out.v5Coverage)
	} else {
		out.coverageNote = buildCoverageNote("当前规则集中存在未评估项，请优先修复引擎或补齐规则实现后复扫", out.v5Coverage)
	}
	return out, nil
}

func buildIntentReportSummary(analysis *llm.AnalysisResult) intentReportSummary {
	if analysis == nil {
		return intentReportSummary{
			Available:         false,
			UnavailableReason: "LLM 未启用或本次未返回有效的声明意图分析，因此报告不展示原始声明替代分析结论。",
		}
	}
	return intentReportSummary{
		Available:            true,
		DeclaredIntent:       localizeFreeText(defaultIfEmpty(strings.TrimSpace(analysis.StatedIntent), "LLM 未给出明确的声明意图摘要。")),
		ActualBehavior:       localizeFreeText(defaultIfEmpty(strings.TrimSpace(analysis.ActualBehavior), "LLM 未给出明确的实际行为摘要。")),
		DeclaredCapabilities: localizeList(analysis.DeclaredCapabilities),
		ActualCapabilities:   localizeList(analysis.ActualCapabilities),
		ConsistencyEvidence:  localizeList(analysis.ConsistencyEvidence),
		IntentRiskLevel:      localizeIntentRiskLevel(analysis.IntentRiskLevel),
		IntentMismatch:       localizeFreeText(strings.TrimSpace(analysis.IntentMismatch)),
	}
}

func toDocxIntentSummary(summary intentReportSummary) docx.IntentSummary {
	return docx.IntentSummary{
		Available:            summary.Available,
		DeclaredIntent:       summary.DeclaredIntent,
		ActualBehavior:       summary.ActualBehavior,
		DeclaredCapabilities: summary.DeclaredCapabilities,
		ActualCapabilities:   summary.ActualCapabilities,
		ConsistencyEvidence:  summary.ConsistencyEvidence,
		IntentRiskLevel:      summary.IntentRiskLevel,
		IntentMismatch:       summary.IntentMismatch,
		UnavailableReason:    summary.UnavailableReason,
	}
}

func toDocxAnalysisProfile(profile skillAnalysisProfile) docx.AnalysisProfile {
	return docx.AnalysisProfile{
		AnalysisMode:       profile.AnalysisMode,
		DeclarationSources: profile.DeclarationSources,
		SourceFiles:        profile.SourceFiles,
		Dependencies:       profile.Dependencies,
		Permissions:        profile.Permissions,
		LanguageSummary:    profile.LanguageSummary,
		CapabilitySignals:  profile.CapabilitySignals,
	}
}

func localizeIntentRiskLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high", "高风险", "critical", "block":
		return "高风险"
	case "medium", "中风险", "review":
		return "中风险"
	case "low", "低风险":
		return "低风险"
	case "none", "pass", "无风险", "":
		return "无风险"
	default:
		return localizeFreeText(level)
	}
}

func localizeList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, localizeFreeText(item))
		}
	}
	return out
}

func localizeFreeText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" || containsCJK(text) {
		return text
	}
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "read") && strings.Contains(lower, "blockchain"):
		return "读取链上公开数据。"
	case strings.Contains(lower, "network"):
		return "使用网络访问外部服务。"
	case strings.Contains(lower, "file"):
		return "读取或处理文件内容。"
	case strings.Contains(lower, "command") || strings.Contains(lower, "shell"):
		return "涉及命令或 Shell 执行能力。"
	case strings.Contains(lower, "credential") || strings.Contains(lower, "secret") || strings.Contains(lower, "token"):
		return "涉及凭据、密钥或令牌相关数据。"
	default:
		return "LLM 返回了英文分析内容，需在报告复核时翻译确认: " + text
	}
}

func containsCJK(text string) bool {
	for _, r := range text {
		if r >= '\u4e00' && r <= '\u9fff' {
			return true
		}
	}
	return false
}

func collectRuleIDs(cfg *config.Config) []string {
	out := make([]string, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		out = append(out, rule.ID)
	}
	return out
}

func buildV5CoverageSummary(matrix *config.V5Matrix, matrixErr error, cfg *config.Config, itemScores map[string]float64) v5CoverageSummary {
	summary := v5CoverageSummary{}
	if matrixErr != nil || matrix == nil {
		summary.Note = "V7 评估矩阵未加载，无法区分自动评估项与人工评估项"
		return summary
	}

	summary.Version = strings.TrimSpace(matrix.Version)
	ruleSet := make(map[string]struct{}, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		ruleSet[strings.TrimSpace(rule.ID)] = struct{}{}
	}

	evaluatedSet := make(map[string]struct{}, len(itemScores))
	for ruleID := range itemScores {
		evaluatedSet[strings.TrimSpace(ruleID)] = struct{}{}
	}

	autoUncovered := make([]string, 0)
	manualCandidates := make([]string, 0)

	for _, item := range matrix.Items {
		mode := strings.ToLower(strings.TrimSpace(item.EvaluationMode))
		mappingType := strings.ToLower(strings.TrimSpace(item.MappingType))
		mappingID := strings.TrimSpace(item.MappingID)
		if mode == "" && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(item.ID)), "V7-") {
			mode = "auto"
		}
		if mappingType == "" && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(item.ID)), "V7-") {
			mappingType = "rule"
		}
		if mappingID == "" && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(item.ID)), "V7-") {
			mappingID = strings.TrimSpace(item.ID)
		}
		name := strings.TrimSpace(item.Name)
		if name == "" {
			name = strings.TrimSpace(item.ID)
		}

		if mode == "auto" {
			summary.AutoTotal++
			covered := false
			switch mappingType {
			case "rule":
				if _, exists := ruleSet[mappingID]; exists {
					if len(evaluatedSet) == 0 {
						covered = true
					} else {
						_, covered = evaluatedSet[mappingID]
					}
				}
			case "runtime":
				covered = true
			}
			if covered {
				summary.AutoCovered++
			} else {
				autoUncovered = append(autoUncovered, name)
			}
			continue
		}

		summary.ManualTotal++
		manualCandidates = append(manualCandidates, name)
	}

	summary.AutoUncovered = autoUncovered
	if len(manualCandidates) > 12 {
		summary.ManualCandidates = manualCandidates[:12]
	} else {
		summary.ManualCandidates = manualCandidates
	}

	if summary.AutoTotal == 0 {
		summary.Note = "V7 矩阵未定义可自动评估项"
	} else if len(summary.AutoUncovered) == 0 {
		summary.Note = fmt.Sprintf("V7 可自动评估项已覆盖：%d/%d；其余 %d 项需人工评估", summary.AutoCovered, summary.AutoTotal, summary.ManualTotal)
	} else {
		summary.Note = fmt.Sprintf("V7 可自动评估项覆盖不足：%d/%d；未覆盖项需优先补齐", summary.AutoCovered, summary.AutoTotal)
	}

	return summary
}

func buildCoverageNote(base string, v5 v5CoverageSummary) string {
	base = strings.TrimSpace(base)
	v5Note := strings.TrimSpace(v5.Note)
	if v5Note == "" {
		return base
	}
	if base == "" {
		return v5Note
	}
	return base + "；" + v5Note
}

func buildRuleEvaluationLogs(rules []config.Rule, itemScores map[string]float64, details []evaluator.FindingDetail) []ruleEvaluationLog {
	detailMap := make(map[string][]evaluator.FindingDetail)
	for _, d := range details {
		rid := strings.TrimSpace(d.RuleID)
		if rid == "" {
			continue
		}
		detailMap[rid] = append(detailMap[rid], d)
	}

	logs := make([]ruleEvaluationLog, 0, len(rules))
	for _, rule := range rules {
		score, evaluated := itemScores[rule.ID]
		riskLabel := "未评估"
		resultText := "未执行该评估项（引擎降级、规则未接入或执行失败）。"
		if evaluated {
			riskLabel = riskLabelFromRule(rule, score, detailMap[rule.ID])
			if riskLabel == "无风险" {
				resultText = "未发现风险。"
			} else {
				evDesc, evLoc := summarizeRuleEvidence(detailMap[rule.ID])
				if evDesc == "" {
					evDesc = "检测命中风险条件。"
				}
				resultText = evDesc
				logs = append(logs, ruleEvaluationLog{
					RuleID:            rule.ID,
					RuleName:          rule.Name,
					Layer:             rule.Layer,
					DetectionType:     normalizeDetectionType(rule.Detection.Type),
					DetectionProcess:  buildDetectionProcessText(rule),
					DetectionResult:   resultText,
					RiskLabel:         riskLabel,
					Evaluated:         true,
					EvidenceLocations: evLoc,
				})
				continue
			}
		}

		logs = append(logs, ruleEvaluationLog{
			RuleID:           rule.ID,
			RuleName:         rule.Name,
			Layer:            rule.Layer,
			DetectionType:    normalizeDetectionType(rule.Detection.Type),
			DetectionProcess: buildDetectionProcessText(rule),
			DetectionResult:  resultText,
			RiskLabel:        riskLabel,
			Evaluated:        evaluated,
		})
	}
	return logs
}

func normalizeDetectionType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "pattern":
		return "模式匹配"
	case "function":
		return "函数检测"
	case "semantic":
		return "语义检测"
	default:
		if strings.TrimSpace(v) == "" {
			return "未定义"
		}
		return v
	}
}

func buildDetectionProcessText(rule config.Rule) string {
	base := fmt.Sprintf("检测方式: %s", normalizeDetectionType(rule.Detection.Type))
	switch strings.ToLower(strings.TrimSpace(rule.Detection.Type)) {
	case "pattern":
		if len(rule.Detection.Patterns) == 0 {
			return base + "；匹配规则未配置"
		}
		limit := len(rule.Detection.Patterns)
		if limit > 3 {
			limit = 3
		}
		return base + "；关键模式: " + strings.Join(rule.Detection.Patterns[:limit], " | ")
	case "function":
		if strings.TrimSpace(rule.Detection.Function) == "" {
			return base + "；检测函数未配置"
		}
		return base + "；执行函数: " + rule.Detection.Function
	case "semantic":
		return fmt.Sprintf("%s；阈值区间: %.2f - %.2f", base, rule.Detection.ThresholdLow, rule.Detection.ThresholdHigh)
	default:
		return base
	}
}

func riskLabelFromRule(rule config.Rule, score float64, details []evaluator.FindingDetail) string {
	_ = score
	for _, detail := range details {
		if detail.Severity == "高风险" || detail.Severity == "中风险" || detail.Severity == "低风险" {
			return detail.Severity
		}
	}
	severity := strings.TrimSpace(rule.Severity)
	if severity == "高风险" || severity == "中风险" || severity == "低风险" {
		return "无风险"
	}
	if strings.EqualFold(strings.TrimSpace(rule.Layer), "P0") {
		return "无风险"
	}
	if strings.EqualFold(strings.TrimSpace(rule.Layer), "P1") {
		return "无风险"
	}
	return "无风险"
}

func summarizeRuleEvidence(items []evaluator.FindingDetail) (string, []string) {
	if len(items) == 0 {
		return "", nil
	}
	max := 2
	if len(items) < max {
		max = len(items)
	}
	descParts := make([]string, 0, max)
	locs := make([]string, 0, max)
	for i := 0; i < max; i++ {
		d := items[i]
		if strings.TrimSpace(d.Description) != "" {
			descParts = append(descParts, d.Description)
		}
		if strings.TrimSpace(d.Location) != "" {
			locs = append(locs, d.Location)
		}
	}
	return strings.Join(descParts, "；"), uniqueStringsLocal(locs)
}

func uniqueStringsLocal(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func collectUncheckedRuleIDs(cfg *config.Config, itemScores map[string]float64) []string {
	out := make([]string, 0)
	for _, rule := range cfg.Rules {
		if _, ok := itemScores[rule.ID]; !ok {
			out = append(out, rule.ID)
		}
	}
	return out
}

func parseSelectedRuleIDs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		id := strings.TrimSpace(p)
		if id == "" {
			continue
		}
		if len(id) > 64 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
		if len(out) >= 512 {
			break
		}
	}
	return out
}

func parseBoolWithDefault(raw string, def bool) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return def
	}
	return s == "true" || s == "1" || s == "on" || s == "enabled"
}

func parsePositiveIntWithDefault(raw string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		return def
	}
	if v > 86400 {
		return 86400
	}
	return v
}

func parseCustomRules(raw string) []customRuleInput {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	if len(raw) > 256<<10 {
		return nil
	}
	var in []customRuleInput
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil
	}
	if len(in) > maxCustomRuleCount {
		in = in[:maxCustomRuleCount]
	}
	out := make([]customRuleInput, 0, len(in))
	for _, item := range in {
		name := strings.TrimSpace(item.Name)
		severity := normalizeCustomRuleSeverity(item.Severity)
		if severity == "" {
			severity = severityFromLegacyLayer(item.Layer)
		}
		reason := strings.TrimSpace(item.Reason)
		if name == "" || severity == "" || len(name) > 128 {
			continue
		}
		patterns := make([]string, 0, len(item.Patterns))
		for _, p := range item.Patterns {
			p = strings.TrimSpace(p)
			if p != "" && len(p) <= 512 {
				patterns = append(patterns, p)
				if len(patterns) >= maxCustomRulePatterns {
					break
				}
			}
		}
		if len(patterns) == 0 {
			continue
		}
		if reason == "" {
			reason = "命中自定义规则"
		}
		if len(reason) > 256 {
			reason = reason[:256]
		}
		item.Name = name
		item.Severity = severity
		item.Layer = legacyLayerFromSeverity(severity)
		item.Patterns = patterns
		item.Reason = reason
		out = append(out, item)
	}
	return out
}

func normalizeCustomRuleSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "高风险", "high":
		return "高风险"
	case "中风险", "medium":
		return "中风险"
	case "低风险", "low":
		return "低风险"
	default:
		return ""
	}
}

func severityFromLegacyLayer(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "P0":
		return "高风险"
	case "P1":
		return "中风险"
	case "P2":
		return "低风险"
	default:
		return ""
	}
}

func legacyLayerFromSeverity(severity string) string {
	switch severity {
	case "高风险":
		return "P0"
	case "中风险":
		return "P1"
	case "低风险":
		return "P2"
	default:
		return ""
	}
}

func buildEffectiveConfig(base *config.Config, selectedRuleIDs []string, customRules []customRuleInput) *config.Config {
	if base == nil {
		base = getDefaultConfig()
	}

	selected := make(map[string]struct{}, len(selectedRuleIDs))
	for _, id := range selectedRuleIDs {
		selected[id] = struct{}{}
	}

	rules := make([]config.Rule, 0, len(base.Rules)+len(customRules))
	if len(selected) == 0 {
		rules = append(rules, base.Rules...)
	} else {
		for _, rule := range base.Rules {
			if _, ok := selected[rule.ID]; ok {
				rules = append(rules, rule)
			}
		}
	}

	for i, cr := range customRules {
		id := strings.TrimSpace(cr.ID)
		if id == "" {
			id = fmt.Sprintf("CUSTOM-%d", i+1)
		}
		severity := normalizeCustomRuleSeverity(cr.Severity)
		if severity == "" {
			severity = severityFromLegacyLayer(cr.Layer)
		}
		layer := legacyLayerFromSeverity(severity)
		action := "remediate"
		if severity == "高风险" {
			action = "block"
		} else if severity == "中风险" {
			action = "review"
		}
		rules = append(rules, config.Rule{
			ID:       id,
			Name:     cr.Name,
			Severity: severity,
			Layer:    layer,
			Detection: config.Detection{
				Type:     "pattern",
				Patterns: cr.Patterns,
			},
			OnFail: config.OnFail{
				Action: action,
				Reason: cr.Reason,
			},
		})
	}

	return &config.Config{
		Version:    base.Version,
		RiskLevels: base.RiskLevels,
		Rules:      rules,
	}
}

func collectSourceArtifacts(scanPath string, llmClient llm.Client) ([]evaluator.SourceFile, []evaluator.Dependency, incrementalCacheStats) {
	var files []evaluator.SourceFile
	var dependencies []evaluator.Dependency
	stats := incrementalCacheStats{Enabled: config.IncrementalScanCacheEnabled(), CacheFilePath: filepath.Join(scanPath, ".scan-cache.json")}
	maxEntries := config.IncrementalScanCacheMaxEntries()
	cache := loadSourceArtifactCache(stats.CacheFilePath)
	if cache.Files == nil {
		cache.Files = make(map[string]cachedSourceArtifact)
	}
	nextCache := sourceArtifactCache{Version: sourceArtifactCacheVersion, Files: make(map[string]cachedSourceArtifact), Order: make([]string, 0, len(cache.Order))}

	_ = filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Base(path), ".scan-cache.json") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		baseName := strings.ToLower(filepath.Base(path))
		lang := ""
		switch {
		case baseName == "go.mod":
			lang = "gomod"
		case baseName == "package.json":
			lang = "json"
		case ext == ".md":
			if baseName != "skill.md" && baseName != "readme.md" && baseName != "description.md" && baseName != "manifest.md" {
				return nil
			}
			lang = "markdown"
		case ext == ".go":
			lang = "go"
		case ext == ".js":
			lang = "javascript"
		case ext == ".ts":
			lang = "typescript"
		case ext == ".py":
			lang = "python"
		case ext == ".java":
			lang = "java"
		case ext == ".rs":
			lang = "rust"
		case ext == ".php":
			lang = "php"
		case ext == ".rb":
			lang = "ruby"
		case ext == ".sh" || ext == ".bash" || ext == ".zsh":
			lang = "shell"
		case ext == ".sql":
			lang = "sql"
		case ext == ".html" || ext == ".htm":
			lang = "html"
		case ext == ".css":
			lang = "css"
		case ext == ".c" || ext == ".h":
			lang = "c"
		case ext == ".cpp" || ext == ".cc" || ext == ".hpp":
			lang = "cpp"
		default:
			return nil
		}
		stats.Candidate++
		fp, fpErr := buildScanFileFingerprint(scanPath, path, info, lang)
		if fpErr == nil && stats.Enabled {
			if cached, ok := cache.Files[fp.RelPath]; ok && sameFingerprint(cached.Fingerprint, fp) {
				files = append(files, cached.Source)
				nextCache.Files[fp.RelPath] = cached
				nextCache.Order = append(nextCache.Order, fp.RelPath)
				stats.Hit++
				if baseName == "go.mod" {
					if deps, parseErr := parseGoMod(cached.Source.Content); parseErr == nil {
						dependencies = append(dependencies, deps...)
					}
				}
				if baseName == "package.json" {
					var pkg struct {
						Dependencies map[string]string `json:"dependencies"`
					}
					if json.Unmarshal([]byte(cached.Source.Content), &pkg) == nil {
						for name, version := range pkg.Dependencies {
							dependencies = append(dependencies, evaluator.Dependency{Name: name, Version: version})
						}
					}
				}
				return nil
			}
		}
		stats.Miss++
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		content := string(data)
		source := evaluator.BuildSourceFile(context.Background(), llmClient, path, content, lang)
		files = append(files, source)
		if fp, fpErr := buildScanFileFingerprint(scanPath, path, info, lang); fpErr == nil {
			nextCache.Files[fp.RelPath] = cachedSourceArtifact{Fingerprint: fp, Source: source}
			nextCache.Order = append(nextCache.Order, fp.RelPath)
		}

		if baseName == "go.mod" {
			if deps, parseErr := parseGoMod(string(data)); parseErr == nil {
				dependencies = append(dependencies, deps...)
			}
		}
		if baseName == "package.json" {
			var pkg struct {
				Dependencies map[string]string `json:"dependencies"`
			}
			if json.Unmarshal(data, &pkg) == nil {
				for name, version := range pkg.Dependencies {
					dependencies = append(dependencies, evaluator.Dependency{Name: name, Version: version})
				}
			}
		}

		if lang == "go" {
			_ = analyzer.AnalyzeGoCode(files[len(files)-1].AnalysisContent(), path)
		}
		return nil
	})
	if stats.Enabled {
		trimSourceArtifactCache(&nextCache, maxEntries)
		_ = saveSourceArtifactCache(stats.CacheFilePath, nextCache)
	}

	depMap := make(map[string]evaluator.Dependency)
	for _, dep := range dependencies {
		key := dep.Name + "@" + dep.Version
		depMap[key] = dep
	}
	unique := make([]evaluator.Dependency, 0, len(depMap))
	for _, dep := range depMap {
		unique = append(unique, dep)
	}

	return files, unique, stats
}

func buildSkillAnalysisProfile(scanPath string, files []evaluator.SourceFile, dependencies []evaluator.Dependency, permissions []string) skillAnalysisProfile {
	return inventory.BuildProfile(scanPath, files, dependencies, permissions)
}

func buildScanFileFingerprint(root, path string, info os.FileInfo, language string) (scanFileFingerprint, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return scanFileFingerprint{}, err
	}
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if rel == "" || strings.HasPrefix(rel, "../") {
		return scanFileFingerprint{}, fmt.Errorf("invalid relative path: %s", path)
	}
	hash, err := fileSHA256(path)
	if err != nil {
		return scanFileFingerprint{}, err
	}
	return scanFileFingerprint{
		RelPath:  rel,
		Language: strings.TrimSpace(language),
		SHA256:   hash,
		Size:     info.Size(),
		ModUnix:  info.ModTime().Unix(),
	}, nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func sameFingerprint(a, b scanFileFingerprint) bool {
	return strings.TrimSpace(a.RelPath) == strings.TrimSpace(b.RelPath) && strings.TrimSpace(a.Language) == strings.TrimSpace(b.Language) && strings.TrimSpace(a.SHA256) == strings.TrimSpace(b.SHA256) && a.Size == b.Size
}

func loadSourceArtifactCache(path string) sourceArtifactCache {
	cache := sourceArtifactCache{Version: sourceArtifactCacheVersion, Files: map[string]cachedSourceArtifact{}}
	data, err := os.ReadFile(path)
	if err != nil {
		return cache
	}
	if json.Unmarshal(data, &cache) != nil {
		return sourceArtifactCache{Version: sourceArtifactCacheVersion, Files: map[string]cachedSourceArtifact{}}
	}
	if strings.TrimSpace(cache.Version) != sourceArtifactCacheVersion {
		return sourceArtifactCache{Version: sourceArtifactCacheVersion, Files: map[string]cachedSourceArtifact{}}
	}
	if cache.Files == nil {
		cache.Files = make(map[string]cachedSourceArtifact)
	}
	return cache
}

func saveSourceArtifactCache(path string, cache sourceArtifactCache) error {
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func trimSourceArtifactCache(cache *sourceArtifactCache, maxEntries int) {
	if cache == nil || maxEntries <= 0 {
		return
	}
	if cache.Files == nil {
		cache.Files = make(map[string]cachedSourceArtifact)
		cache.Order = nil
		return
	}
	seen := make(map[string]struct{}, len(cache.Order))
	orderedUnique := make([]string, 0, len(cache.Order))
	for _, key := range cache.Order {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, ok := cache.Files[key]; !ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		orderedUnique = append(orderedUnique, key)
	}
	if len(orderedUnique) < len(cache.Files) {
		for key := range cache.Files {
			if _, ok := seen[key]; ok {
				continue
			}
			orderedUnique = append(orderedUnique, key)
		}
	}
	if len(orderedUnique) > maxEntries {
		removeCount := len(orderedUnique) - maxEntries
		for i := 0; i < removeCount; i++ {
			delete(cache.Files, orderedUnique[i])
		}
		orderedUnique = orderedUnique[removeCount:]
	}
	cache.Order = orderedUnique
}

func incrementalCacheHitRate(stats incrementalCacheStats) float64 {
	if stats.Candidate <= 0 {
		return 0
	}
	if stats.Hit <= 0 {
		return 0
	}
	return float64(stats.Hit) * 100 / float64(stats.Candidate)
}

func writeInvalidSourceArtifactCache(path string) error {
	return os.WriteFile(path, []byte("{invalid-json"), 0600)
}

func inferCapabilitySignals(content string) []string {
	return inventory.InferCapabilitySignals(content)
}

func uniqueStrings(items []string) []string {
	return inventory.UniqueStrings(items)
}

func limitList(items []string, limit int) []string {
	if limit <= 0 {
		return append([]string{}, items...)
	}
	if len(items) <= limit {
		return append([]string{}, items...)
	}
	return append([]string{}, items[:limit]...)
}

func buildReportBaseName(sourceName string, createdAt time.Time) string {
	name := strings.TrimSpace(sourceName)
	if name == "" {
		name = "skill-scan-report"
	}
	base := strings.TrimSuffix(filepath.Base(name), filepath.Ext(filepath.Base(name)))
	base = strings.TrimSpace(base)
	if base == "" || base == "." {
		base = "skill-scan-report"
	}
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' || r == 0:
			return '-'
		case unicode.IsSpace(r):
			return '_'
		default:
			return r
		}
	}, base)
	cleaned = strings.Trim(cleaned, "-_.")
	if cleaned == "" {
		cleaned = "skill-scan-report"
	}
	return cleaned + "_" + createdAt.Format("20060102_150405")
}

func newAnalysisTraceEvent(stage, status, message, detail string) analysisTraceEvent {
	return analysisTraceEvent{Stage: stage, Status: status, Message: message, Detail: strings.TrimSpace(detail)}
}

func countBehaviorEvidenceCategories(behavior review.BehaviorProfile) int {
	return evidence.CountBehaviorCategories(behavior)
}

func displayRelPath(root, path string) string {
	return inventory.DisplayRelPath(root, path)
}

func countLocalizedFindingRisks(findings []plugins.Finding) (int, int, int) {
	high, medium, low := 0, 0, 0
	for _, f := range findings {
		switch localizeSeverity(f.Severity) {
		case "高风险":
			high++
		case "中风险":
			medium++
		default:
			low++
		}
	}
	return high, medium, low
}

func countReviewedFindingRisks(findings []plugins.Finding, refined review.Result) (int, int, int) {
	if len(refined.StructuredFindings) == 0 || len(refined.ReviewAgentVerdicts) == 0 {
		return countLocalizedFindingRisks(findings)
	}
	verdicts := preferredVerdictsByFinding(refined.ReviewAgentVerdicts)
	high, medium, low := 0, 0, 0
	for _, finding := range refined.StructuredFindings {
		verdict, ok := verdicts[finding.ID]
		tier := evidenceTierForFinding(finding, verdict, refined)
		if ok && verdict.Verdict == "likely_false_positive" && tier != evidenceTierStrong {
			low++
			continue
		}
		severity := localizeSeverity(finding.Severity)
		if severity == "高风险" && tier == evidenceTierStrong && (!ok || verdict.Verdict == "confirmed") {
			high++
			continue
		}
		if ok && verdict.Verdict == "needs_manual_review" && severity == "高风险" {
			medium++
			continue
		}
		if severity == "中风险" && tier == evidenceTierWeak {
			low++
			continue
		}
		switch severity {
		case "高风险":
			medium++
		case "中风险":
			medium++
		default:
			low++
		}
	}
	return high, medium, low
}

func preferredVerdictsByFinding(verdicts []review.ReviewAgentVerdict) map[string]review.ReviewAgentVerdict {
	grouped := map[string][]review.ReviewAgentVerdict{}
	for _, verdict := range verdicts {
		if strings.TrimSpace(verdict.FindingID) == "" {
			continue
		}
		grouped[verdict.FindingID] = append(grouped[verdict.FindingID], verdict)
	}
	out := make(map[string]review.ReviewAgentVerdict, len(grouped))
	for findingID, items := range grouped {
		out[findingID] = synthesizePreferredVerdict(items)
	}
	return out
}

func synthesizePreferredVerdict(items []review.ReviewAgentVerdict) review.ReviewAgentVerdict {
	if len(items) == 0 {
		return review.ReviewAgentVerdict{}
	}
	byVerdict := map[string][]review.ReviewAgentVerdict{}
	for _, item := range items {
		key := normalizedReviewVerdict(item.Verdict)
		if key == "" {
			key = "needs_manual_review"
		}
		byVerdict[key] = append(byVerdict[key], item)
	}
	if len(byVerdict) == 1 {
		for _, sameVerdicts := range byVerdict {
			return strongestVerdict(sameVerdicts)
		}
	}
	return mergeConflictingVerdicts(items, byVerdict)
}

func strongestVerdict(items []review.ReviewAgentVerdict) review.ReviewAgentVerdict {
	best := items[0]
	for _, item := range items[1:] {
		if confidencePriority(item.Confidence) > confidencePriority(best.Confidence) {
			best = item
			continue
		}
		if confidencePriority(item.Confidence) == confidencePriority(best.Confidence) && reviewerPriority(item.Reviewer) > reviewerPriority(best.Reviewer) {
			best = item
		}
	}
	return best
}

func mergeConflictingVerdicts(items []review.ReviewAgentVerdict, byVerdict map[string][]review.ReviewAgentVerdict) review.ReviewAgentVerdict {
	merged := strongestVerdict(items)
	merged.Verdict = "needs_manual_review"
	merged.Confidence = "低"
	merged.Reviewer = joinVerdictReviewers(items)
	merged.Reason = fmt.Sprintf("复核结论存在分歧: %s，已回退为需人工复核。", strings.Join(sortedVerdictLabels(byVerdict), " / "))
	merged.MissingEvidence = uniqueStrings(append(merged.MissingEvidence, collectVerdictMissingEvidence(items)...))
	merged.StandardsApplied = uniqueStrings(collectVerdictStandards(items))
	if strings.TrimSpace(merged.Fix) == "" {
		merged.Fix = "复核结论不一致，请补充可达性、运行链路和真实影响证据后再判断。"
		return merged
	}
	merged.Fix = merged.Fix + "；若复核结论仍不一致，请补充可达性、运行链路和真实影响证据。"
	return merged
}

func sortedVerdictLabels(byVerdict map[string][]review.ReviewAgentVerdict) []string {
	labels := make([]string, 0, len(byVerdict))
	for verdict := range byVerdict {
		labels = append(labels, localizeReviewVerdict(verdict))
	}
	sort.Strings(labels)
	return labels
}

func collectVerdictMissingEvidence(items []review.ReviewAgentVerdict) []string {
	out := make([]string, 0, len(items)*2)
	for _, item := range items {
		out = append(out, item.MissingEvidence...)
	}
	return out
}

func collectVerdictStandards(items []review.ReviewAgentVerdict) []string {
	out := make([]string, 0, len(items)*2)
	for _, item := range items {
		out = append(out, item.StandardsApplied...)
	}
	return out
}

func joinVerdictReviewers(items []review.ReviewAgentVerdict) string {
	reviewers := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		reviewer := strings.TrimSpace(item.Reviewer)
		if reviewer == "" || seen[reviewer] {
			continue
		}
		seen[reviewer] = true
		reviewers = append(reviewers, reviewer)
	}
	if len(reviewers) == 0 {
		return "multi-review"
	}
	sort.Strings(reviewers)
	return strings.Join(reviewers, "+")
}

func reviewerPriority(reviewer string) int {
	reviewer = strings.ToLower(strings.TrimSpace(reviewer))
	if strings.Contains(reviewer, "deterministic") {
		return 2
	}
	if strings.Contains(reviewer, "llm") {
		return 1
	}
	return 0
}

func confidencePriority(confidence string) int {
	switch strings.TrimSpace(confidence) {
	case "高":
		return 4
	case "中高":
		return 3
	case "中":
		return 2
	case "中低":
		return 1
	case "低":
		return 0
	default:
		return -1
	}
}

func normalizedReviewVerdict(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed", "needs_manual_review", "likely_false_positive":
		return strings.ToLower(strings.TrimSpace(verdict))
	default:
		return ""
	}
}

func decisionFromRiskCounts(high, medium int) (string, string) {
	if high > 0 {
		return "high", "UserDecisionRequired"
	}
	if medium > 0 {
		return "medium", "UserDecisionRequired"
	}
	return "low", "UserDecisionRequired"
}

func decisionFromReviewedFindings(base baseScanOutput, refined review.Result) (string, string) {
	if base.p0 || refined.Evasion.Detected {
		return "high", "UserDecisionRequired"
	}
	if len(refined.StructuredFindings) == 0 {
		return decisionFromRiskCounts(refined.Summary.HighRisk, refined.Summary.MediumRisk)
	}
	verdicts := preferredVerdictsByFinding(refined.ReviewAgentVerdicts)
	highSignals := 0
	mediumSignals := 0
	for _, finding := range refined.StructuredFindings {
		verdict, hasVerdict := verdicts[finding.ID]
		tier := evidenceTierForFinding(finding, verdict, refined)
		if hasVerdict && verdict.Verdict == "likely_false_positive" && tier != evidenceTierStrong {
			continue
		}
		severity := localizeSeverity(finding.Severity)
		switch {
		case severity == "高风险" && tier == evidenceTierStrong && (!hasVerdict || verdict.Verdict == "confirmed"):
			highSignals++
		case severity == "高风险":
			mediumSignals++
		case severity == "中风险" && (tier == evidenceTierStrong || tier == evidenceTierModerate):
			mediumSignals++
		}
	}
	if highSignals > 0 {
		return "high", "UserDecisionRequired"
	}
	if mediumSignals > 0 {
		return "medium", "UserDecisionRequired"
	}
	if refined.Summary.HighRisk > 0 || refined.Summary.MediumRisk > 1 {
		return "medium", "UserDecisionRequired"
	}
	return "low", "UserDecisionRequired"
}

func buildRiskCalibrationSummary(findings []plugins.Finding, base baseScanOutput, refined review.Result) riskCalibrationSummary {
	built := reviewreport.BuildRiskCalibrationSummary(reviewreport.RiskCalibrationInput{
		RiskLevel:             localizeRiskLevel(refined.Summary.RiskLevel),
		Decision:              localizeAdmission(refined.Summary.Admission),
		HighRisk:              refined.Summary.HighRisk,
		MediumRisk:            refined.Summary.MediumRisk,
		LowRisk:               refined.Summary.LowRisk,
		IntentDiffCount:       len(refined.IntentDiffs),
		BehaviorCategoryCount: countBehaviorEvidenceCategories(refined.Behavior),
		EvasionDetected:       refined.Evasion.Detected,
		P0Detected:            base.p0,
		P0Reasons:             append([]string{}, base.reasons...),
		FindingCount:          len(findings),
		EvaluatedRules:        base.evaluatedRules,
		TotalRules:            base.totalRules,
		UncheckedRules:        append([]string{}, base.uncheckedRules...),
		IntentSummaryReady:    base.intentSummary.Available,
	})
	return riskCalibrationSummary(built)
}

func buildRuleSetProfile(cfg *config.Config) ruleSetProfile {
	profile := ruleSetProfile{
		Version: cfg.Version,
		Total:   len(cfg.Rules),
		Reason:  "规则不再只作为命中列表，而是作为可解释的审查矩阵参与覆盖率、优先级、复核和整改分层。",
		Benefit: "用户能看到规则体系本身是否完整、哪些规则需要优先整改、哪些规则负责复核，从而判断报告可信度。",
	}
	layers := map[string]int{}
	severities := map[string]int{}
	detectionTypes := map[string]int{}
	for _, rule := range cfg.Rules {
		layers[defaultIfEmpty(rule.Layer, "未分层")]++
		severities[localizeSeverity(rule.Severity)]++
		detectionTypes[defaultIfEmpty(rule.Detection.Type, "unknown")]++
		label := strings.TrimSpace(rule.ID + " " + rule.Name)
		switch strings.ToLower(strings.TrimSpace(rule.OnFail.Action)) {
		case "block":
			profile.BlockedRules = append(profile.BlockedRules, label)
		case "review":
			profile.ReviewRules = append(profile.ReviewRules, label)
		}
	}
	profile.ByLayer = countMapToSortedList(layers)
	profile.BySeverity = countMapToSortedList(severities)
	profile.ByDetectionType = countMapToSortedList(detectionTypes)
	sort.Strings(profile.BlockedRules)
	sort.Strings(profile.ReviewRules)
	return profile
}

func buildRuleExplanations(cfg *config.Config) []review.RuleExplanation {
	if cfg == nil {
		return nil
	}
	out := make([]review.RuleExplanation, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		category := structuredFindingCategory(plugins.Finding{RuleID: rule.ID, Title: rule.Name, Description: rule.OnFail.Reason})
		criteria := mergeRuleMetadata(rule.Review.DetectionCriteria, ruleDetectionCriteria(rule))
		exclusions := mergeRuleMetadata(rule.Review.ExclusionConditions, ruleExclusionConditions(category))
		verification := mergeRuleMetadata(rule.Review.VerificationRequirements, ruleVerificationRequirements(category))
		outputs := mergeRuleMetadata(rule.Review.OutputRequirements, ruleOutputRequirements(category))
		promptSummary := strings.TrimSpace(rule.Review.PromptTemplate)
		if promptSummary == "" {
			promptSummary = buildRulePromptTemplateSummary(rule, category, criteria)
		}
		remediationFocus := strings.TrimSpace(rule.Review.RemediationFocus)
		if remediationFocus == "" {
			remediationFocus = ruleRemediationFocus(category)
		}
		out = append(out, review.RuleExplanation{
			RuleID:                   rule.ID,
			Name:                     rule.Name,
			Severity:                 rule.Severity,
			DetectionType:            rule.Detection.Type,
			Action:                   defaultIfEmpty(rule.OnFail.Action, "review"),
			DetectionCriteria:        criteria,
			ExclusionConditions:      exclusions,
			VerificationRequirements: verification,
			OutputRequirements:       outputs,
			PromptTemplateSummary:    promptSummary,
			RemediationFocus:         remediationFocus,
		})
	}
	return out
}

func mergeRuleMetadata(primary, fallback []string) []string {
	if len(primary) == 0 {
		return fallback
	}
	return uniqueStrings(append(append([]string{}, primary...), fallback...))
}

func markTriggeredRuleExplanations(explanations []review.RuleExplanation, findings []plugins.Finding) []review.RuleExplanation {
	triggered := map[string]bool{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.RuleID) != "" {
			triggered[finding.RuleID] = true
		}
	}
	out := append([]review.RuleExplanation(nil), explanations...)
	for i := range out {
		out[i].Triggered = triggered[out[i].RuleID]
	}
	return out
}

func ruleDetectionCriteria(rule config.Rule) []string {
	criteria := []string{fmt.Sprintf("检测方式: %s", defaultIfEmpty(rule.Detection.Type, "未声明"))}
	switch rule.Detection.Type {
	case "pattern":
		if len(rule.Detection.Patterns) == 0 {
			criteria = append(criteria, "未配置正则模式，需补齐后才能可靠检测。")
		} else {
			criteria = append(criteria, fmt.Sprintf("正则模式数量: %d", len(rule.Detection.Patterns)))
			criteria = append(criteria, "必须存在与风险语义一致的源码、配置或声明证据，不能只依赖无上下文关键词。")
		}
	case "function":
		criteria = append(criteria, "由专用检测函数执行上下文分析: "+defaultIfEmpty(rule.Detection.Function, "未声明函数"))
		criteria = append(criteria, "需要结合定位、代码片段和规则原因确认风险链条成立。")
	case "semantic", "llm_intent":
		criteria = append(criteria, "由语义模型或 LLM 对声明、源码和实际行为做一致性判断。")
		criteria = append(criteria, "必须输出可核验证据，不能仅凭推测标记风险。")
	default:
		criteria = append(criteria, "按规则配置的检测器执行，需在报告中保留原始证据。")
	}
	if strings.TrimSpace(rule.OnFail.Reason) != "" {
		criteria = append(criteria, "风险触发原因: "+rule.OnFail.Reason)
	}
	return criteria
}

func ruleExclusionConditions(category string) []string {
	conditions := []string{
		"只有在已确认相关代码、脚本或配置不会进入发布包、运行镜像、动态加载链路时，才能按非风险处理。",
		"只有在已验证白名单、固定参数、最小权限和显式用户授权能实际约束危险影响时，才能降级处理。",
	}
	switch category {
	case "外联与情报":
		conditions = append(conditions, "若目标限定为受控白名单、开发回环地址或内部服务，仍需确认不会传输敏感数据且不存在重定向、代理转发或动态改写。")
	case "命令执行":
		conditions = append(conditions, "只有在已确认命令参数不可控、不进入 shell 且影响范围受限时，才能按低风险或非风险处理。")
	case "凭据访问":
		conditions = append(conditions, "只有在已确认读取对象是公开模板、占位符或脱敏演示数据，且不存在后续外联、落地或权限放大链路时，才能排除风险。")
	case "声明与行为差异":
		conditions = append(conditions, "不要报告声明中已经明确解释且行为证据与声明一致的能力。")
	}
	return conditions
}

func ruleVerificationRequirements(category string) []string {
	reqs := []string{
		"确认入口可达性: 风险代码是否会被技能主流程调用。",
		"确认证据完整性: 至少包含位置、片段、规则原因或行为证据之一。",
		"确认影响成立: 风险是否可能造成数据泄露、越权执行、持久化或用户误导。",
	}
	switch category {
	case "外联与情报":
		reqs = append(reqs, "确认目标域名、请求方法、传输数据和威胁情报结论。")
	case "命令执行":
		reqs = append(reqs, "确认命令参数是否可控、是否进入 shell、是否有白名单限制。")
	case "凭据访问":
		reqs = append(reqs, "确认凭据来源、访问授权、后续外联或落地链路。")
	case "反分析/逃逸":
		reqs = append(reqs, "确认是否存在差分执行、环境探测、延迟触发或规避沙箱证据。")
	}
	return reqs
}

func ruleOutputRequirements(category string) []string {
	return []string{
		"输出具体文件路径或证据定位。",
		"输出触发代码片段或行为证据摘要。",
		"输出攻击路径、影响评估、误报检查和一一对应修复建议。",
		"若证据不足，应标记为待复核而不是直接下结论。",
		"分类标签: " + category,
	}
}

func buildRulePromptTemplateSummary(rule config.Rule, category string, criteria []string) string {
	return fmt.Sprintf("作为安全审计员，仅在满足 %s 相关具体证据时报告 %s；必须先检查排除条件，再给出攻击路径、影响、证据和修复建议。核心检测条件: %s", category, rule.Name, strings.Join(limitList(criteria, 3), "；"))
}

func limitRuleExplanations(items []review.RuleExplanation, max int) []review.RuleExplanation {
	if len(items) <= max {
		return items
	}
	selected := make([]review.RuleExplanation, 0, max)
	for _, item := range items {
		if item.Triggered {
			selected = append(selected, item)
			if len(selected) == max {
				return selected
			}
		}
	}
	for _, item := range items {
		if !item.Triggered {
			selected = append(selected, item)
			if len(selected) == max {
				return selected
			}
		}
	}
	return selected
}

func ruleRemediationFocus(category string) string {
	switch category {
	case "外联与情报":
		return "收敛外联目标到白名单，最小化传输字段，记录用户授权与用途。"
	case "命令执行":
		return "移除 shell 拼接，改用参数数组和白名单，禁止用户输入直接进入命令。"
	case "凭据访问":
		return "移除硬编码凭据，改用受控密钥管理，并阻断凭据外发链路。"
	case "持久化":
		return "移除自启动、计划任务或隐式落地逻辑，保留显式用户触发路径。"
	case "反分析/逃逸":
		return "删除环境探测、延迟触发和差分执行逻辑，确保沙箱与真实环境行为一致。"
	case "声明与行为差异":
		return "补齐声明与权限说明，或移除未声明能力，复扫确认一致。"
	default:
		return "按证据定位最小化危险能力，并补充测试或声明以便复核。"
	}
}

func countMapToSortedList(counts map[string]int) []string {
	out := make([]string, 0, len(counts))
	for key, count := range counts {
		out = append(out, fmt.Sprintf("%s:%d", key, count))
	}
	sort.Strings(out)
	return out
}

func persistReports(store *storage.Store, taskID, username, originalName, declaredDescription string, findings []plugins.Finding, base baseScanOutput, refined review.Result) (string, pdfRenderTrace, error) {
	trace := pdfRenderTrace{}
	reportID, err := storage.GenerateID()
	if err != nil {
		return "", trace, err
	}
	reportCreatedAt := time.Now()
	reportBaseName := buildReportBaseName(originalName, reportCreatedAt)
	htmlReport := buildHTMLReport(originalName, declaredDescription, findings, base, refined, base.evalLogs)
	textReport := docx.TextFromHTMLReport(htmlReport)

	gen := docx.NewGenerator()
	docxName := reportBaseName + ".docx"
	docxPath := filepath.Join(store.ReportsDir(), docxName)
	if err := gen.GenerateFromHTMLReport(reportBaseName, htmlReport, docxPath); err != nil {
		return "", trace, err
	}

	htmlName := reportBaseName + ".html"
	htmlPath := filepath.Join(store.ReportsDir(), htmlName)
	if err := os.WriteFile(htmlPath, []byte(htmlReport), 0600); err != nil {
		return "", trace, err
	}

	jsonName := reportBaseName + ".json"
	jsonPath := filepath.Join(store.ReportsDir(), jsonName)
	jsonPayload := buildJSONReportPayload(htmlReport, textReport, findings, base, refined)
	jsonData, _ := json.MarshalIndent(jsonPayload, "", "  ")
	if err := os.WriteFile(jsonPath, jsonData, 0600); err != nil {
		return "", trace, err
	}

	pdfName := reportBaseName + ".pdf"
	pdfPath := filepath.Join(store.ReportsDir(), pdfName)
	pdfErrMsg := ""
	pdfTrace, err := renderPDFReport(htmlPath, docxPath, pdfPath)
	trace = pdfTrace
	if err != nil {
		pdfErrMsg = err.Error()
		trace.Error = pdfErrMsg
		pdfName = ""
	}

	high, medium, low := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "高风险":
			high++
		case "中风险":
			medium++
		default:
			low++
		}
	}

	user := store.GetUser(username)
	team := ""
	if user != nil {
		team = user.Team
	}

	rep := &models.Report{
		ID:               reportID,
		TaskID:           taskID,
		Status:           string(review.PhaseDone),
		Username:         username,
		Team:             team,
		FileName:         reportBaseName,
		FilePath:         docxName,
		HTMLPath:         htmlName,
		JSONPath:         jsonName,
		PDFPath:          pdfName,
		PDFError:         pdfErrMsg,
		CreatedAt:        reportCreatedAt.Unix(),
		FindingCount:     len(findings),
		HighRisk:         high,
		MediumRisk:       medium,
		LowRisk:          low,
		NoRisk:           len(findings) == 0,
		Score:            0,
		RiskLevel:        refined.Summary.RiskLevel,
		Decision:         refined.Summary.Admission,
		TrustScore:       refined.Summary.TrustScore,
		RiskScore:        refined.Summary.RiskScore,
		Exploitability:   refined.Summary.Exploitability,
		BusinessImpact:   refined.Summary.BusinessImpact,
		ICS:              refined.Summary.ICS,
		P0Blocked:        base.p0,
		P0Reasons:        base.reasons,
		RuleTotal:        base.totalRules,
		RuleEvaluated:    base.evaluatedRules,
		RuleUnchecked:    len(base.uncheckedRules),
		RuleUncheckedIDs: base.uncheckedRules,
		CoverageNote:     base.coverageNote,
		ItemScores: map[string]float64{
			"rule_total":     float64(base.totalRules),
			"rule_evaluated": float64(base.evaluatedRules),
			"rule_unchecked": float64(len(base.uncheckedRules)),
		},
	}

	if err := store.AddReport(rep); err != nil {
		return "", trace, err
	}
	return reportID, trace, nil
}

type pdfRenderTrace struct {
	Engine       string
	FontFile     string
	FontDir      string
	UsedFallback bool
	Error        string
}

func (t pdfRenderTrace) TraceMessage() string {
	parts := make([]string, 0, 5)
	if strings.TrimSpace(t.Engine) != "" {
		parts = append(parts, "engine="+strings.TrimSpace(t.Engine))
	}
	if strings.TrimSpace(t.FontFile) != "" {
		parts = append(parts, "font_file="+strings.TrimSpace(t.FontFile))
	}
	if strings.TrimSpace(t.FontDir) != "" {
		parts = append(parts, "font_dir="+strings.TrimSpace(t.FontDir))
	}
	if t.UsedFallback {
		parts = append(parts, "fallback=docx")
	} else {
		parts = append(parts, "fallback=none")
	}
	if strings.TrimSpace(t.Error) != "" {
		parts = append(parts, "error="+strings.TrimSpace(t.Error))
	}
	return strings.Join(parts, "; ")
}

func buildJSONReportPayload(htmlReport, textReport string, findings []plugins.Finding, base baseScanOutput, refined review.Result) map[string]interface{} {
	riskCalibration := buildRiskCalibrationSummary(findings, base, refined)
	coverage := map[string]interface{}{
		"rule_total":         base.totalRules,
		"rule_evaluated":     base.evaluatedRules,
		"rule_unchecked":     len(base.uncheckedRules),
		"unchecked_rule_ids": base.uncheckedRules,
		"note":               base.coverageNote,
		"incremental_cache": map[string]interface{}{
			"enabled":        base.cacheStats.Enabled,
			"candidate_files": base.cacheStats.Candidate,
			"hit_files":      base.cacheStats.Hit,
			"miss_files":     base.cacheStats.Miss,
			"cache_file":     base.cacheStats.CacheFilePath,
		},
		"v6": map[string]interface{}{
			"version":             base.v5Coverage.Version,
			"auto_total":          base.v5Coverage.AutoTotal,
			"auto_covered":        base.v5Coverage.AutoCovered,
			"auto_uncovered":      base.v5Coverage.AutoUncovered,
			"manual_total":        base.v5Coverage.ManualTotal,
			"manual_candidates":   base.v5Coverage.ManualCandidates,
			"classification_note": base.v5Coverage.Note,
		},
	}
	return reviewreport.BuildJSONReportPayload(reviewreport.JSONReportPayloadInput{
		Generator:              reportGeneratorNote,
		HTMLReport:             htmlReport,
		TextReport:             textReport,
		Result:                 refined,
		SkillAnalysisProfile:   base.profile,
		RuleSetProfile:         base.ruleProfile,
		RuleExplanations:       refined.RuleExplanations,
		AnalysisTrace:          base.trace,
		RiskCalibration:        reviewreport.RiskCalibrationSummary(riskCalibration),
		IntentAnalysis:         base.intentSummary,
		ObfuscationEvidence:    refined.ObfuscationEvidence,
		RuleEvaluationRecords:  base.evalLogs,
		DecisionLabel:          localizeAdmission(refined.Summary.Admission),
		RiskLevelLabel:         localizeRiskLevel(refined.Summary.RiskLevel),
		HighRisk:               refined.Summary.HighRisk,
		MediumRisk:             refined.Summary.MediumRisk,
		LowRisk:                refined.Summary.LowRisk,
		RiskScore:              refined.Summary.RiskScore,
		Exploitability:         refined.Summary.Exploitability,
		BusinessImpact:         refined.Summary.BusinessImpact,
		RemediationSuggestions: buildDynamicSuggestions(findings, refined),
		Coverage:               coverage,
		MITRESummary:           buildMITRESummary(refined.StructuredFindings),
	})
}

func buildMITRESummary(findings []review.StructuredFinding) map[string]interface{} {
	if len(findings) == 0 {
		return map[string]interface{}{"count": 0, "techniques": []string{}}
	}
	all := make([]string, 0, len(findings)*2)
	byFinding := make([]map[string]interface{}, 0, len(findings))
	for _, finding := range findings {
		techniques := uniqueNonEmptyStrings(finding.MITRETechniques)
		if len(techniques) == 0 {
			continue
		}
		all = append(all, techniques...)
		byFinding = append(byFinding, map[string]interface{}{
			"id":         finding.ID,
			"title":      finding.Title,
			"rule_id":    finding.RuleID,
			"techniques": techniques,
		})
	}
	unique := uniqueNonEmptyStrings(all)
	return map[string]interface{}{
		"count":      len(unique),
		"techniques": unique,
		"findings":   byFinding,
	}
}

func parsePermissions(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func synthesizeIntentFindings(diffs []review.IntentDiff) []plugins.Finding {
	out := make([]plugins.Finding, 0, len(diffs))
	for _, d := range diffs {
		severity := "中风险"
		if isHighRiskIntentDiff(d.Type) {
			severity = "高风险"
		}
		out = append(out, plugins.Finding{
			PluginName:  "IntentEngine",
			RuleID:      "V7-006",
			Severity:    severity,
			Title:       "技能声明与实际行为一致性",
			Description: d.Description,
			Location:    "行为一致性分析",
			CodeSnippet: "一致性证据: " + d.Description,
		})
	}
	return out
}

func isHighRiskIntentDiff(diffType string) bool {
	switch strings.TrimSpace(diffType) {
	case "unexpected_exec", "unexpected_data_collection", "unexpected_external_dependency", "unsafe_declaration_prompt":
		return true
	default:
		return false
	}
}

func synthesizeTIFindings(items []review.TIReputation) []plugins.Finding {
	out := make([]plugins.Finding, 0)
	for _, it := range items {
		rep := strings.ToLower(strings.TrimSpace(it.Reputation))
		if rep == "internal" || rep == "trusted" || rep == "benign" || rep == "unknown" {
			continue
		}
		title := "敏感数据外发与隐蔽通道"
		severity := "高风险"
		if isCryptoPolicyTIReason(it.Reason) || isCryptoPolicyTIReason(it.Target) {
			title = "公司策略禁止的加密资产或预测市场目标"
			severity = "中风险"
		}
		if rep == "policy" {
			title = "公司策略禁止的加密资产或预测市场目标"
			severity = "中风险"
		}
		out = append(out, plugins.Finding{
			PluginName:  "ThreatIntel",
			RuleID:      "V7-003",
			Severity:    severity,
			Title:       title,
			Description: it.Reason,
			Location:    it.Target,
			CodeSnippet: "目标证据: " + defaultIfEmpty(it.Target, "未知目标") + "\n判定依据: " + defaultIfEmpty(it.Reason, "无"),
		})
	}
	return out
}

func isCryptoPolicyTIReason(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	return strings.Contains(lower, "加密资产") || strings.Contains(lower, "预测市场") || strings.Contains(lower, "polymarket") || strings.Contains(lower, "usdc")
}

func threatIntelSemantics(rep string) string {
	switch strings.ToLower(strings.TrimSpace(rep)) {
	case "malicious", "high-risk", "suspicious":
		return "threat"
	case "policy":
		return "policy"
	case "internal":
		return "internal"
	case "trusted", "benign":
		return "benign"
	default:
		return "unknown"
	}
}

func reputationForFinding(finding review.StructuredFinding, refined review.Result) string {
	for _, item := range refined.TIReputations {
		if strings.TrimSpace(item.Target) == "" {
			continue
		}
		if strings.Contains(strings.ToLower(strings.Join(finding.Evidence, " ")), strings.ToLower(strings.TrimSpace(item.Target))) {
			return item.Reputation
		}
		if strings.EqualFold(strings.TrimSpace(finding.Title), "公司策略禁止的加密资产或预测市场目标") && threatIntelSemantics(item.Reputation) == "policy" {
			return item.Reputation
		}
	}
	return ""
}

func synthesizeEvasionFindings(evasion review.EvasionAssessment) []plugins.Finding {
	out := make([]plugins.Finding, 0)
	if !evasion.Detected {
		return out
	}
	for _, sig := range evasion.Signals {
		out = append(out, plugins.Finding{
			PluginName:  "EvasionGuard",
			RuleID:      "V7-008",
			Severity:    "高风险",
			Title:       "沙箱逃逸与提权风险",
			Description: sig,
			Location:    "差分执行与行为审计",
			CodeSnippet: "逃逸信号: " + sig,
		})
	}
	return out
}

func synthesizeBehaviorFindings(behavior review.BehaviorProfile) []plugins.Finding {
	out := make([]plugins.Finding, 0, 8)
	add := func(ruleID, severity, title string, count int, location string) {
		if count == 0 {
			return
		}
		desc := fmt.Sprintf("检测到 %d 条行为证据，请结合证据链进行人工复核与修复闭环。", count)
		out = append(out, plugins.Finding{
			PluginName:  "BehaviorGuard",
			RuleID:      ruleID,
			Severity:    severity,
			Title:       title,
			Description: desc,
			Location:    location,
			CodeSnippet: "行为证据摘要: " + desc,
		})
	}

	add("V7-001", "高风险", "恶意代码与破坏性行为", len(behavior.BehaviorChains)+len(behavior.PersistenceIOCs)+len(behavior.DefenseEvasionIOCs)+len(behavior.LateralMoveIOCs)+len(behavior.C2BeaconIOCs)+len(behavior.SequenceAlerts), "行为证据采集")
	add("V7-003", "高风险", "敏感数据外发与隐蔽通道", len(behavior.OutboundIOCs)+len(behavior.CollectionIOCs), "行为证据采集")
	add("V7-008", "高风险", "沙箱逃逸与提权风险", len(behavior.PrivEscIOCs)+len(behavior.EvasionSignals), "行为证据采集")
	add("V7-009", "高风险", "自更新与远程下载执行", len(behavior.DownloadIOCs)+len(behavior.ExecuteIOCs), "行为证据采集")
	add("V7-016", "中风险", "凭据缓存与跨任务隔离", len(behavior.CredentialIOCs), "行为证据采集")

	return out
}

func synthesizeV5CoverageFindings(v5 v5CoverageSummary) []plugins.Finding {
	out := make([]plugins.Finding, 0)
	if v5.AutoTotal == 0 || len(v5.AutoUncovered) == 0 {
		return out
	}
	desc := "未覆盖项: " + strings.Join(v5.AutoUncovered, "；")
	out = append(out, plugins.Finding{
		PluginName:  "V7Coverage",
		RuleID:      "V7-AUTO-COVERAGE",
		Severity:    "高风险",
		Title:       "V7 可自动评估项覆盖不足",
		Description: desc,
		Location:    "评估规则配置",
		CodeSnippet: desc,
	})
	return out
}

func buildStructuredFindings(findings []plugins.Finding, refined review.Result, sourceRoot string, sourceFiles []evaluator.SourceFile) []review.StructuredFinding {
	sourceIndex := buildSourceContextIndex(sourceRoot, sourceFiles)
	obfuscationChainsByCategory := buildObfuscationFindingChainsByCategory(refined.ObfuscationEvidence)
	groups := make(map[string][]plugins.Finding)
	order := make([]string, 0, len(findings))
	concreteRuleIDs := concreteFindingRuleIDs(findings)
	for _, finding := range findings {
		if shouldSkipStructuredFinding(finding, concreteRuleIDs) {
			continue
		}
		key := structuredFindingGroupKey(finding)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], finding)
	}

	out := make([]review.StructuredFinding, 0, len(order))
	for i, key := range order {
		items := groups[key]
		first := items[0]
		category := structuredFindingCategory(first)
		confidence, basis := structuredFindingCalibration(category, items, refined)
		out = append(out, review.StructuredFinding{
			ID:                  fmt.Sprintf("SF-%03d", i+1),
			RuleID:              first.RuleID,
			Title:               first.Title,
			Severity:            first.Severity,
			Category:            category,
			Confidence:          confidence,
			AttackPath:          structuredAttackPath(category, first, refined),
			MITRETechniques:     mitreTechniquesForFinding(first.RuleID, category),
			Evidence:            appendObfuscationEvidence(structuredFindingEvidence(items, sourceIndex), items, category, refined.ObfuscationEvidence),
			ChainSummaries:      structuredFindingChainSummaries(category, refined.Behavior, obfuscationChainsByCategory[category]),
			Chains:              structuredFindingChains(category, refined.Behavior, obfuscationChainsByCategory[category]),
			CalibrationBasis:    basis,
			FalsePositiveChecks: falsePositiveChecks(category, first, refined),
			ReviewGuidance:      structuredReviewGuidance(category, first.Severity),
			Source:              defaultIfEmpty(first.PluginName, "规则/行为综合分析"),
			DeduplicatedCount:   len(items),
		})
	}
	return out
}

func mitreTechniquesForFinding(ruleID, category string) []string {
	ruleID = strings.TrimSpace(ruleID)
	category = strings.TrimSpace(category)
	ruleToTechniques := map[string][]string{
		"V7-001": {"TA0002 Execution", "T1059 Command and Scripting Interpreter"},
		"V7-002": {"TA0003 Persistence", "T1546 Event Triggered Execution"},
		"V7-003": {"TA0011 Command and Control", "T1071 Application Layer Protocol"},
		"V7-004": {"TA0006 Credential Access", "T1552 Unsecured Credentials"},
		"V7-008": {"TA0004 Privilege Escalation", "T1068 Exploitation for Privilege Escalation"},
		"V7-009": {"TA0002 Execution", "T1105 Ingress Tool Transfer"},
	}
	categoryToTechniques := map[string][]string{
		"恶意代码":          {"TA0002 Execution", "T1059 Command and Scripting Interpreter"},
		"后门与条件触发":       {"TA0003 Persistence", "T1546 Event Triggered Execution"},
		"外联与情报":         {"TA0011 Command and Control", "T1071 Application Layer Protocol"},
		"凭据访问":          {"TA0006 Credential Access", "T1552 Unsecured Credentials"},
		"沙箱逃逸与提权":       {"TA0004 Privilege Escalation", "T1068 Exploitation for Privilege Escalation"},
		"下载执行":          {"TA0002 Execution", "T1105 Ingress Tool Transfer"},
		"命令执行":          {"TA0002 Execution", "T1059 Command and Scripting Interpreter"},
		"敏感数据外发与隐蔽通道": {"TA0011 Command and Control", "T1071 Application Layer Protocol"},
	}

	if items, ok := ruleToTechniques[ruleID]; ok {
		return uniqueNonEmptyStrings(items)
	}
	return uniqueNonEmptyStrings(categoryToTechniques[category])
}

func structuredFindingGroupKey(finding plugins.Finding) string {
	title := strings.TrimSpace(finding.Title)
	severity := strings.TrimSpace(finding.Severity)
	ruleID := strings.TrimSpace(finding.RuleID)
	if title == "许可证验证配置缺陷" {
		return strings.Join([]string{"license-config", severity, title}, "\x00")
	}
	return strings.Join([]string{ruleID, severity, title}, "\x00")
}

func concreteFindingRuleIDs(findings []plugins.Finding) map[string]struct{} {
	ruleIDs := make(map[string]struct{})
	for _, finding := range findings {
		if strings.EqualFold(strings.TrimSpace(finding.PluginName), "BehaviorGuard") {
			continue
		}
		if !isConcreteFinding(finding) {
			continue
		}
		ruleID := strings.TrimSpace(finding.RuleID)
		if ruleID == "" {
			continue
		}
		ruleIDs[ruleID] = struct{}{}
	}
	return ruleIDs
}

func shouldSkipStructuredFinding(finding plugins.Finding, concreteRuleIDs map[string]struct{}) bool {
	if !strings.EqualFold(strings.TrimSpace(finding.PluginName), "BehaviorGuard") {
		return false
	}
	if !isBehaviorSummaryFinding(finding) {
		return false
	}
	_, exists := concreteRuleIDs[strings.TrimSpace(finding.RuleID)]
	return exists
}

func isBehaviorSummaryFinding(finding plugins.Finding) bool {
	return strings.TrimSpace(finding.Location) == "行为证据采集" && strings.Contains(strings.TrimSpace(finding.CodeSnippet), "行为证据摘要:")
}

func isConcreteFinding(finding plugins.Finding) bool {
	location := strings.TrimSpace(finding.Location)
	if location != "" && location != "未提供定位" && location != "行为证据采集" && strings.Contains(location, ":") {
		return true
	}
	code := strings.TrimSpace(finding.CodeSnippet)
	if code != "" && !strings.HasPrefix(code, "行为证据摘要:") && !strings.HasPrefix(code, "一致性证据:") && !strings.HasPrefix(code, "目标证据:") && strings.Contains(code, "\n") {
		return true
	}
	return false
}

func buildVulnerabilityBlocks(findings []review.StructuredFinding) []review.VulnerabilityBlock {
	return reviewreport.BuildVulnerabilityBlocks(findings)
}

func buildFalsePositiveReviews(findings []review.StructuredFinding, refined review.Result) []review.FalsePositiveReview {
	reviews := make([]review.FalsePositiveReview, 0, len(findings))
	for _, finding := range findings {
		reviewItem := review.FalsePositiveReview{
			FindingID:          finding.ID,
			Exploitability:     exploitabilityForFinding(finding, refined),
			Impact:             impactForFinding(finding),
			EvidenceStrength:   evidenceStrengthForFinding(finding, refined),
			ReachabilityChecks: reachabilityChecksForFinding(finding, refined),
			ExclusionChecks:    exclusionChecksForFinding(finding, refined),
			RequiredFollowUp:   followUpForFinding(finding, refined),
		}
		reviewItem.Verdict = falsePositiveVerdict(reviewItem, finding)
		reviews = append(reviews, reviewItem)
	}
	return reviews
}

func buildDetectionChainComparison(base baseScanOutput, refined review.Result) []review.DetectionChainComparison {
	return []review.DetectionChainComparison{
		{
			Area:             "执行策略与降级控制",
			CurrentStatus:    "语义模型、LLM 和沙箱均作为关键能力；任一关键能力不可用时扫描直接失败，不静默降级。",
			BaselineApproach: "参考基线通常强调阶段化执行，但对关键能力失败后的产品化提示不一定做强约束。",
			Winner:           "当前链路更适合上线前质量门禁",
			Gap:              "仍需把关键能力失败原因与恢复建议进一步结构化，便于 UI 和 API 精准提示。",
			Optimization:     "保留不降级策略，并继续把 preflight、sandbox、LLM、semantic 的失败原因纳入审计事件流。",
			Evidence:         []string{fmt.Sprintf("preflight trace:%d", len(base.trace)), fmt.Sprintf("audit events:%d", len(refined.AuditEvents))},
		},
		{
			Area:             "深度审计与多 Agent 推理",
			CurrentStatus:    "当前链路以规则、语义、LLM 意图、沙箱和威胁情报聚合为主，并已生成 Agent 任务包与确定性 reviewer 裁决。",
			BaselineApproach: "参考基线通常会把深度审计任务拆成多阶段任务包，并用独立复核提示提升覆盖。",
			Winner:           "参考基线领先",
			Gap:              "已有确定性 reviewer，但还缺少真实 LLM reviewer 的语义二次审查。",
			Optimization:     "下一步将 ReviewAgentTask 交给 LLM reviewer 执行，并用确定性 reviewer 作为保底校验。",
			Evidence:         []string{fmt.Sprintf("review agent tasks:%d", len(refined.ReviewAgentTasks)), fmt.Sprintf("review verdicts:%d", len(refined.ReviewAgentVerdicts)), "已落地结构化风险、规则解释卡和零误报复核清单作为 Agent 输入"},
		},
		{
			Area:             "规则元数据与 Prompt 模板",
			CurrentStatus:    "已从 rules_v7.yaml 自动生成规则解释卡，但规则文件本身尚未原生承载 detection/exclusion/verification/output prompt。",
			BaselineApproach: "参考基线会把说明、检测条件、排除条件、验证要求和提示模板沉淀到同一规则元数据中。",
			Winner:           "参考基线领先",
			Gap:              "当前规则解释多为代码派生，长期应沉淀到 YAML 规则元数据。",
			Optimization:     "将 RuleExplanation 反向推动 rules_v7.yaml schema 扩展，支持原生 metadata 与 prompt_template。",
			Evidence:         []string{fmt.Sprintf("rule explanations:%d", len(refined.RuleExplanations))},
		},
		{
			Area:             "行为验证与能力一致性",
			CurrentStatus:    "当前链路已有沙箱、静态/LLM/沙箱交叉校验、能力一致性矩阵和探针告警。",
			BaselineApproach: "参考基线重视阶段化分析，但不一定直接输出面向 Skill 声明与权限的一致性矩阵。",
			Winner:           "当前链路更贴合 Skill 安全审查",
			Gap:              "沙箱仍可能因入口未触发、动态拼接、条件执行而漏检。",
			Optimization:     "继续扩展沙箱探针和行为触发策略，并将未触发行为作为能力矩阵缺口展示。",
			Evidence:         []string{fmt.Sprintf("capability matrix:%d", len(refined.CapabilityMatrix)), fmt.Sprintf("probe warnings:%d", len(refined.Behavior.ProbeWarnings))},
		},
		{
			Area:             "漏洞结构化与误报复核",
			CurrentStatus:    "已支持 StructuredFinding、<vuln> 漏洞块、FalsePositiveReview 和逐项修复建议。",
			BaselineApproach: "参考基线通常提供结构化风险块与零误报复核模板，便于二次消费。",
			Winner:           "能力接近，仍可继续增强",
			Gap:              "还缺少自动二次复核执行器来消费这些结构化块并产出最终差异。",
			Optimization:     "下一步可增加 vuln block round-trip 校验和 LLM reviewer，对每个 <vuln> 块执行独立复核。",
			Evidence:         []string{fmt.Sprintf("structured findings:%d", len(refined.StructuredFindings)), fmt.Sprintf("false-positive reviews:%d", len(refined.FalsePositiveReviews))},
		},
		{
			Area:             "可观测性与审计回放",
			CurrentStatus:    "已新增结构化审计事件流，覆盖 trace、pipeline、结果生成和沙箱探针告警。",
			BaselineApproach: "参考基线通常会把计划、状态、工具调用和错误事件拆开记录，便于完整回放。",
			Winner:           "能力接近，仍可继续增强",
			Gap:              "当前事件流还没有覆盖所有具体工具输入输出，也没有事件级耗时。",
			Optimization:     "后续为每个检测函数、LLM 调用、沙箱动作补充 toolUsed/actionLog 事件和耗时字段。",
			Evidence:         []string{fmt.Sprintf("audit events:%d", len(refined.AuditEvents))},
		},
	}
}

func buildDetectionComparisonOptimizationNotes(items []review.DetectionChainComparison) []review.OptimizationNote {
	notes := make([]review.OptimizationNote, 0, 3)
	for _, item := range items {
		if !strings.Contains(item.Winner, "参考基线领先") && !strings.Contains(item.Winner, "继续增强") {
			continue
		}
		notes = append(notes, review.OptimizationNote{
			Change:  "检测链路差距: " + item.Area,
			Reason:  item.Gap,
			Benefit: item.Optimization,
		})
		if len(notes) == 3 {
			break
		}
	}
	return notes
}

func buildReviewAgentTasks(refined review.Result) []review.ReviewAgentTask {
	rules := map[string]review.RuleExplanation{}
	for _, rule := range refined.RuleExplanations {
		rules[rule.RuleID] = rule
	}
	fpReviews := map[string]review.FalsePositiveReview{}
	for _, fp := range refined.FalsePositiveReviews {
		fpReviews[fp.FindingID] = fp
	}
	vulnBlocks := map[string]string{}
	for _, block := range refined.VulnerabilityBlocks {
		vulnBlocks[block.ID] = block.Content
	}
	tasks := make([]review.ReviewAgentTask, 0, len(refined.StructuredFindings))
	for _, finding := range refined.StructuredFindings {
		rule := rules[finding.RuleID]
		fp := fpReviews[finding.ID]
		prompt := buildReviewAgentPrompt(finding, rule, fp, vulnBlocks[finding.ID])
		tasks = append(tasks, review.ReviewAgentTask{
			FindingID: finding.ID,
			AgentRole: "vuln-reviewer",
			Objective: "以零误报标准复核结构化风险是否具备真实攻击路径、影响和证据闭环。",
			Inputs: []string{
				"structured_finding:" + finding.ID,
				"finding_chains:" + finding.ID,
				"rule_explanation:" + defaultIfEmpty(rule.RuleID, finding.RuleID),
				"false_positive_review:" + defaultIfEmpty(fp.FindingID, finding.ID),
				"vulnerability_block:" + finding.ID,
			},
			StrictStandards: []string{
				"没有具体文件、代码片段或行为证据时，不得确认真实风险。",
				"README、注释、测试或示例路径只能作为上下文，不能单独作为误报结论；必须确认其是否进入发布或运行链路。",
				"必须确认入口可达性、攻击路径、权限边界和真实影响。",
				"正常授权能力、白名单限制、固定参数安全调用不得误报为漏洞。",
			},
			Prompt: prompt,
			ExpectedOutputs: []string{
				"verdict: confirmed | likely_false_positive | needs_manual_review",
				"reason: 说明裁决依据",
				"missing_evidence: 缺失的关键证据",
				"fix: 若确认风险，给出一一对应修复建议",
			},
			BlockingCriteria: []string{
				"确认存在高危命令执行、凭据泄露、隐蔽外联、持久化、提权或反分析链路。",
				"确认声明与行为严重不一致且会影响用户授权判断。",
				"确认沙箱、静态、LLM 或威胁情报多源证据互相印证。",
			},
		})
	}
	return tasks
}

func executeDeterministicReviewAgent(refined review.Result) []review.ReviewAgentVerdict {
	verdicts, _ := executeDeterministicReviewAgentWithStats(refined)
	return verdicts
}

func executeDeterministicReviewAgentWithStats(refined review.Result) ([]review.ReviewAgentVerdict, review.ReviewAgentExecutionStats) {
	stats := review.ReviewAgentExecutionStats{Reviewer: "deterministic-vuln-reviewer", TaskCount: len(refined.ReviewAgentTasks)}
	if len(refined.ReviewAgentTasks) == 0 {
		return nil, stats
	}
	startedAt := time.Now()
	findingByID := map[string]review.StructuredFinding{}
	for _, finding := range refined.StructuredFindings {
		findingByID[finding.ID] = finding
	}
	fpByID := map[string]review.FalsePositiveReview{}
	for _, fp := range refined.FalsePositiveReviews {
		fpByID[fp.FindingID] = fp
	}
	verdicts := make([]review.ReviewAgentVerdict, len(refined.ReviewAgentTasks))
	workerCount := reviewAgentWorkerCount(len(refined.ReviewAgentTasks))
	stats.WorkerCount = workerCount
	stats.MaxConcurrency = workerCount
	var wg sync.WaitGroup
	jobs := make(chan int)
	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				task := refined.ReviewAgentTasks[idx]
				finding := findingByID[task.FindingID]
				fp := fpByID[task.FindingID]
				verdicts[idx] = deterministicVerdictForTask(task, finding, fp, refined)
			}
		}()
	}
	for idx := range refined.ReviewAgentTasks {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	stats.DurationMs = time.Since(startedAt).Milliseconds()
	return verdicts, stats
}

func executeLLMReviewAgent(ctx context.Context, client llm.Client, refined review.Result) ([]review.ReviewAgentVerdict, error) {
	verdicts, _, err := executeLLMReviewAgentWithStats(ctx, client, refined)
	return verdicts, err
}

func executeLLMReviewAgentWithStats(ctx context.Context, client llm.Client, refined review.Result) ([]review.ReviewAgentVerdict, review.ReviewAgentExecutionStats, error) {
	stats := review.ReviewAgentExecutionStats{Reviewer: "llm-vuln-reviewer", TaskCount: len(refined.ReviewAgentTasks)}
	if client == nil {
		stats.Failed = true
		stats.ErrorMessage = "LLM reviewer 客户端不可用"
		return nil, stats, fmt.Errorf("LLM reviewer 客户端不可用")
	}
	if len(refined.ReviewAgentTasks) == 0 {
		return nil, stats, nil
	}
	startedAt := time.Now()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	verdicts := make([]review.ReviewAgentVerdict, len(refined.ReviewAgentTasks))
	workerCount := reviewAgentWorkerCount(len(refined.ReviewAgentTasks))
	stats.WorkerCount = workerCount
	jobs := make(chan int)
	errCh := make(chan error, 1)
	var once sync.Once
	var wg sync.WaitGroup
	var activeWorkers int32
	var maxConcurrency int32
	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if ctx.Err() != nil {
					return
				}
				current := atomic.AddInt32(&activeWorkers, 1)
				for {
					seen := atomic.LoadInt32(&maxConcurrency)
					if current <= seen || atomic.CompareAndSwapInt32(&maxConcurrency, seen, current) {
						break
					}
				}
				task := refined.ReviewAgentTasks[idx]
				analysis, err := client.AnalyzeCode(ctx, "漏洞二次复核 "+task.FindingID, task.Objective, task.Prompt)
				atomic.AddInt32(&activeWorkers, -1)
				if err != nil {
					once.Do(func() {
						errCh <- fmt.Errorf("%s: %w", task.FindingID, err)
						cancel()
					})
					return
				}
				verdicts[idx] = llmAnalysisToReviewVerdict(task, analysis)
			}
		}()
	}
	for idx := range refined.ReviewAgentTasks {
		if ctx.Err() != nil {
			break
		}
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	stats.DurationMs = time.Since(startedAt).Milliseconds()
	stats.MaxConcurrency = int(maxConcurrency)
	select {
	case err := <-errCh:
		stats.Failed = true
		stats.ErrorMessage = err.Error()
		return nil, stats, err
	default:
		return verdicts, stats, nil
	}
}

func reviewAgentWorkerCount(taskCount int) int {
	if taskCount <= 1 {
		return taskCount
	}
	if taskCount > 4 {
		return 4
	}
	return taskCount
}

func llmAnalysisToReviewVerdict(task review.ReviewAgentTask, analysis *llm.AnalysisResult) review.ReviewAgentVerdict {
	if analysis == nil {
		return review.ReviewAgentVerdict{FindingID: task.FindingID, Verdict: "needs_manual_review", Confidence: "低", Reason: "LLM reviewer 未返回有效分析。", MissingEvidence: []string{"缺少 LLM reviewer 输出"}, Reviewer: "llm-vuln-reviewer", StandardsApplied: task.StrictStandards}
	}
	riskLevel := strings.ToLower(strings.TrimSpace(analysis.IntentRiskLevel))
	highestRisk := highestLLMRiskSeverity(analysis.Risks)
	verdict := "needs_manual_review"
	confidence := "中"
	reason := strings.TrimSpace(analysis.IntentMismatch)
	if reason == "" {
		reason = strings.TrimSpace(analysis.ActualBehavior)
	}
	if reason == "" {
		reason = "LLM reviewer 已执行，但未给出详细原因。"
	}
	missing := append([]string{}, analysis.ConsistencyEvidence...)
	if highestRisk == "high" || riskLevel == "high" || riskLevel == "medium" {
		verdict = "confirmed"
		confidence = "高"
	} else if len(analysis.Risks) == 0 && (riskLevel == "none" || riskLevel == "low" || analysis.IntentConsistency >= 80) {
		verdict = "likely_false_positive"
		confidence = "中高"
		if len(missing) == 0 {
			missing = append(missing, "LLM reviewer 未发现足够风险证据")
		}
	}
	fix := "按 LLM reviewer 输出和规则解释卡修复或补证。"
	if len(analysis.Risks) > 0 && strings.TrimSpace(analysis.Risks[0].Description) != "" {
		fix = analysis.Risks[0].Description
	}
	return review.ReviewAgentVerdict{
		FindingID:        task.FindingID,
		Verdict:          verdict,
		Confidence:       confidence,
		Reason:           reason,
		MissingEvidence:  uniqueStrings(missing),
		Fix:              fix,
		Reviewer:         "llm-vuln-reviewer",
		StandardsApplied: task.StrictStandards,
	}
}

func highestLLMRiskSeverity(risks []llm.RiskItem) string {
	highest := ""
	for _, risk := range risks {
		severity := strings.ToLower(strings.TrimSpace(risk.Severity))
		if severity == "high" || severity == "高风险" {
			return "high"
		}
		if severity == "medium" || severity == "中风险" {
			highest = "medium"
		} else if highest == "" && severity != "" {
			highest = severity
		}
	}
	return highest
}

func mergeReviewAgentVerdicts(deterministic, llmVerdicts []review.ReviewAgentVerdict) []review.ReviewAgentVerdict {
	out := make([]review.ReviewAgentVerdict, 0, len(llmVerdicts)+len(deterministic))
	out = append(out, llmVerdicts...)
	out = append(out, deterministic...)
	return out
}

func deterministicVerdictForTask(task review.ReviewAgentTask, finding review.StructuredFinding, fp review.FalsePositiveReview, refined review.Result) review.ReviewAgentVerdict {
	missing := make([]string, 0, 4)
	hasRelevantBehavior := hasRelevantBehaviorSupport(finding.Category, refined.Behavior)
	tiSemantic := threatIntelSemantics(reputationForFinding(finding, refined))
	docOnly := isLikelyDocumentationOnlyFinding(finding)
	internalOnly := isLikelyInternalDevelopmentFinding(finding)
	standards := []string{
		"入口可达性",
		"证据完整性",
		"排除条件",
		"真实影响",
	}
	if len(finding.Evidence) == 0 {
		missing = append(missing, "缺少具体证据定位或代码片段")
	}
	if strings.TrimSpace(finding.AttackPath) == "" {
		missing = append(missing, "缺少攻击路径说明")
	}
	if tiSemantic != "policy" && !strings.Contains(fp.EvidenceStrength, "强") && !hasRelevantBehavior {
		missing = append(missing, "缺少多源行为证据或高危时序印证")
	}
	if len(fp.ReachabilityChecks) == 0 {
		missing = append(missing, "缺少可达性检查结论")
	}
	if docOnly && !hasThreatLikeFindingSignals(finding) {
		missing = append(missing, "缺少文档/示例内容进入真实发布或执行链路的证据")
	}
	if internalOnly && !hasThreatLikeFindingSignals(finding) {
		missing = append(missing, "缺少本地开发目标会扩展到真实外联或生产环境的证据")
	}

	verdict := "needs_manual_review"
	confidence := "中"
	reason := "证据存在但仍需人工确认入口可达性、影响和排除条件。"
	if (docOnly || internalOnly) && !hasThreatLikeFindingSignals(finding) && !hasRelevantBehavior {
		verdict = "likely_false_positive"
		confidence = "中高"
		reason = "当前主要是文档示例或本地开发证据，且缺少真实发布链路或高危行为支撑，按零误报标准先归为疑似误报。"
	} else if strings.Contains(fp.Verdict, "疑似误报") && len(missing) > 0 && !strings.Contains(fp.EvidenceStrength, "强") && !hasRelevantBehavior {
		verdict = "likely_false_positive"
		confidence = "中高"
		reason = "现有证据不足且已出现排除线索，按零误报标准先标记为疑似误报，仍需补充发布路径与运行链路结论。"
	} else if tiSemantic == "policy" && len(finding.Evidence) > 0 {
		verdict = "confirmed"
		confidence = "中高"
		reason = "该发现属于明确的准入策略命中，主要依据目标信誉语义和策略证据确认，不要求恶意行为链闭环。"
	} else if len(finding.Evidence) > 0 && len(finding.CalibrationBasis) > 0 && hasRelevantBehavior && !docOnly && !internalOnly {
		verdict = "confirmed"
		confidence = "中高"
		reason = "已存在具体定位、校准依据和相关行为支撑，虽然仍建议补充完整调用链，但已满足确认风险的最低证据要求。"
	} else if len(missing) == 0 && (strings.Contains(fp.Verdict, "倾向真实风险") || strings.Contains(fp.EvidenceStrength, "强") || finding.Confidence == "高") {
		verdict = "confirmed"
		confidence = "高"
		reason = "结构化发现、复核清单和行为/校准证据形成闭环，满足确认风险的最低标准。"
	} else if len(missing) >= 3 {
		confidence = "低"
		reason = "关键证据缺失较多，必须补充证据后才能确认或排除。"
	}

	return review.ReviewAgentVerdict{
		FindingID:        task.FindingID,
		Verdict:          verdict,
		Confidence:       confidence,
		Reason:           reason,
		MissingEvidence:  uniqueStrings(missing),
		Fix:              defaultIfEmpty(finding.ReviewGuidance, "按规则解释卡和复核清单补齐修复建议。"),
		Reviewer:         "deterministic-vuln-reviewer",
		StandardsApplied: standards,
	}
}

func buildReviewAgentPrompt(finding review.StructuredFinding, rule review.RuleExplanation, fp review.FalsePositiveReview, vulnBlock string) string {
	sections := []string{
		"你是严格的漏洞复核 Agent。目标是降低误报，而不是扩大风险范围。",
		"## 结构化风险\n" + formatStructuredFindingForPrompt(finding),
	}
	if strings.TrimSpace(vulnBlock) != "" {
		sections = append(sections, "## <vuln> 结构化漏洞块\n"+vulnBlock)
	}
	if rule.RuleID != "" {
		sections = append(sections, "## 规则解释卡\n检测条件: "+strings.Join(rule.DetectionCriteria, "；")+"\n排除条件: "+strings.Join(rule.ExclusionConditions, "；")+"\n验证要求: "+strings.Join(rule.VerificationRequirements, "；")+"\n输出要求: "+strings.Join(rule.OutputRequirements, "；"))
	}
	if fp.FindingID != "" {
		sections = append(sections, "## 当前零误报复核\n结论: "+fp.Verdict+"\n可利用性: "+fp.Exploitability+"\n影响: "+fp.Impact+"\n证据强度: "+fp.EvidenceStrength+"\n排除检查: "+strings.Join(fp.ExclusionChecks, "；"))
	}
	sections = append(sections, "## 输出要求\n只输出 JSON: {\"verdict\":\"confirmed|likely_false_positive|needs_manual_review\",\"reason\":\"...\",\"missing_evidence\":[\"...\"],\"fix\":\"...\"}。证据不足时必须选择 needs_manual_review 或 likely_false_positive。")
	return strings.Join(sections, "\n\n")
}

func limitReviewAgentTasks(items []review.ReviewAgentTask, max int) []review.ReviewAgentTask {
	if len(items) <= max {
		return items
	}
	return items[:max]
}

func formatStructuredFindingForPrompt(finding review.StructuredFinding) string {
	return reviewreport.FormatStructuredFindingForPrompt(finding)
}

func renderFindingChainsForPrompt(items []review.FindingChain) string {
	return reviewreport.RenderFindingChains(items)
}

func exploitabilityForFinding(finding review.StructuredFinding, refined review.Result) string {
	if threatIntelSemantics(reputationForFinding(finding, refined)) == "policy" {
		return "中等: 该项主要体现准入/合规策略风险，而非恶意攻击链成立。"
	}
	if hasRelevantBehaviorSupport(finding.Category, refined.Behavior) {
		return "较高: 存在行为链或高危时序证据，可支持攻击路径复核。"
	}
	if finding.Confidence == "高" {
		return "中高: 结构化证据置信度较高，但仍需确认入口可达性。"
	}
	return "待复核: 当前主要由规则命中支撑，需要补充入口、参数和运行路径证据。"
}

func impactForFinding(finding review.StructuredFinding) string {
	switch finding.Category {
	case "命令执行":
		return "可能导致任意命令执行、供应链污染或本地环境破坏。"
	case "外联与情报":
		return "可能导致敏感数据外发、远程控制通道或不受控第三方通信。"
	case "凭据访问":
		return "可能导致 token、密钥或认证文件泄露，并扩大到后续外联链路。"
	case "持久化":
		return "可能导致技能在用户不知情情况下保留自启动或长期驻留能力。"
	case "反分析/逃逸":
		return "可能导致沙箱结果低估真实风险，需要差分执行复测。"
	case "声明与行为差异":
		return "可能导致用户基于错误声明授权危险能力。"
	default:
		return "影响取决于入口可达性、权限范围和证据链完整性。"
	}
}

func evidenceStrengthForFinding(finding review.StructuredFinding, refined review.Result) string {
	score := 0
	tiSemantic := threatIntelSemantics(reputationForFinding(finding, refined))
	if len(finding.Evidence) > 0 {
		score++
	}
	if len(finding.CalibrationBasis) > 0 {
		score++
	}
	if finding.DeduplicatedCount > 1 {
		score++
	}
	if hasRelevantBehaviorSupport(finding.Category, refined.Behavior) {
		score += 2
	}
	if hasHighSignalSequenceAlert(finding.Category, refined.Behavior) {
		score++
	}
	if tiSemantic == "policy" {
		score++
	}
	if isLikelyDocumentationOnlyFinding(finding) {
		score--
	}
	switch {
	case score >= 4:
		return "强: 多源证据或行为链可互相印证。"
	case score >= 2:
		return "中: 有定位或校准依据，但仍需补充入口可达性。"
	default:
		return "弱: 证据不足，应优先人工复核并补充运行链路。"
	}
}

type evidenceTier string

const (
	evidenceTierStrong   evidenceTier = "strong"
	evidenceTierModerate evidenceTier = "moderate"
	evidenceTierWeak     evidenceTier = "weak"
)

func evidenceTierForFinding(finding review.StructuredFinding, verdict review.ReviewAgentVerdict, refined review.Result) evidenceTier {
	strength := evidenceStrengthForFinding(finding, refined)
	if strings.Contains(strength, "强") {
		if verdict.Verdict == "likely_false_positive" && isLikelyDocumentationOnlyFinding(finding) {
			return evidenceTierModerate
		}
		return evidenceTierStrong
	}
	if strings.Contains(strength, "中") {
		if finding.Confidence == "高" && hasRelevantBehaviorSupport(finding.Category, refined.Behavior) {
			return evidenceTierStrong
		}
		return evidenceTierModerate
	}
	return evidenceTierWeak
}

func hasHighSignalSequenceAlert(category string, behavior review.BehaviorProfile) bool {
	for _, alert := range relevantSequenceAlerts(category, behavior) {
		lower := strings.ToLower(strings.TrimSpace(alert))
		if strings.Contains(lower, "下载") || strings.Contains(lower, "execute") || strings.Contains(lower, "外联") || strings.Contains(lower, "凭据") {
			return true
		}
	}
	return false
}

func isLikelyDocumentationOnlyFinding(finding review.StructuredFinding) bool {
	if len(finding.Evidence) == 0 {
		return false
	}
	docHits := 0
	for _, item := range finding.Evidence {
		lower := strings.ToLower(strings.TrimSpace(item))
		if strings.Contains(lower, "readme") || strings.Contains(lower, "skill.md") || strings.Contains(lower, "docs/") || strings.Contains(lower, "examples/") || strings.Contains(lower, "testdata/") || strings.Contains(lower, "示例") || strings.Contains(lower, "文档") {
			docHits++
		}
	}
	return docHits > 0 && docHits == len(finding.Evidence)
}

func isLikelyInternalDevelopmentFinding(finding review.StructuredFinding) bool {
	if len(finding.Evidence) == 0 {
		return false
	}
	internalHits := 0
	for _, item := range finding.Evidence {
		lower := strings.ToLower(strings.TrimSpace(item))
		if strings.Contains(lower, "localhost") || strings.Contains(lower, "127.0.0.1") || strings.Contains(lower, "0.0.0.0") || strings.Contains(lower, "::1") {
			internalHits++
		}
	}
	return internalHits > 0 && internalHits == len(finding.Evidence)
}

func hasThreatLikeFindingSignals(finding review.StructuredFinding) bool {
	joined := strings.ToLower(strings.Join(append(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), finding.ChainSummaries...), " "))
	threatSignals := []string{"命令执行", "下载后执行", "隐蔽通道", "凭据", "c2", "提权", "持久化", "外发", "exfil", "shell", "dropper", "subprocess", "os.system", "exec.command"}
	for _, signal := range threatSignals {
		if strings.Contains(joined, signal) {
			return true
		}
	}
	return false
}

func reachabilityChecksForFinding(finding review.StructuredFinding, refined review.Result) []string {
	checks := []string{
		"确认风险代码所在文件是否属于技能发布包和主执行路径。",
		"确认用户输入、配置或模型输出是否能到达该风险点。",
	}
	if hasRelevantBehaviorSupport(finding.Category, refined.Behavior) {
		checks = append(checks, "沙箱已记录与当前风险相关的行为链或时序，可优先沿该链路回溯入口。")
	} else {
		checks = append(checks, "沙箱未记录对应时序时，不应直接视为无风险；需检查条件触发和动态拼接。")
	}
	if finding.Category == "声明与行为差异" {
		checks = append(checks, "将 SKILL.md、manifest、权限声明和源码行为放在同一链路中复核。")
	}
	return checks
}

func exclusionChecksForFinding(finding review.StructuredFinding, refined review.Result) []string {
	checks := append([]string{}, finding.FalsePositiveChecks...)
	checks = append(checks, "若证据位于文档、注释、测试或示例文件，需继续确认其是否会被打包、引用、解析或动态加载，不能仅凭路径名排除。")
	for _, rule := range refined.RuleExplanations {
		if rule.RuleID == finding.RuleID {
			checks = append(checks, limitList(rule.ExclusionConditions, 3)...)
			break
		}
	}
	return uniqueStrings(limitList(checks, 6))
}

func followUpForFinding(finding review.StructuredFinding, refined review.Result) []string {
	followUp := []string{
		"补充最小复现路径: 入口 -> 参数/配置 -> 风险点 -> 影响。",
		"复核文档、注释、测试或示例中的相关内容是否会被实际引用、打包、解析或动态加载。",
	}
	if finding.Confidence != "高" {
		followUp = append(followUp, "当前置信度不是高，建议补充沙箱触发样例或源码调用链。")
	}
	if len(refined.Behavior.ProbeWarnings) > 0 {
		followUp = append(followUp, "存在沙箱探针告警，需确认未触发是否由条件执行、动态拼接或探针覆盖不足导致。")
	}
	return followUp
}

func falsePositiveVerdict(item review.FalsePositiveReview, finding review.StructuredFinding) string {
	joined := strings.Join(append(append(item.ReachabilityChecks, item.ExclusionChecks...), item.RequiredFollowUp...), " ")
	if isLikelyInternalDevelopmentFinding(finding) && !hasThreatLikeFindingSignals(finding) {
		return "疑似误报: 当前证据主要指向本地开发或环回调用，除非能证明会进入真实发布链路，否则不应按恶意外联处理。"
	}
	if strings.Contains(item.EvidenceStrength, "强") && strings.Contains(item.Exploitability, "较高") && !isLikelyDocumentationOnlyFinding(finding) {
		return "倾向真实风险: 建议优先修复并复扫。"
	}
	hasConfirmedExclusion := strings.Contains(joined, "已确认") && (strings.Contains(joined, "不会进入发布包") || strings.Contains(joined, "不会被动态加载") || strings.Contains(joined, "不会被引用"))
	if (strings.Contains(item.EvidenceStrength, "弱") || isLikelyDocumentationOnlyFinding(finding)) && hasConfirmedExclusion {
		return "疑似误报: 已有排除线索，但仍建议保留证据并复核发布路径。"
	}
	if isLikelyDocumentationOnlyFinding(finding) && !hasThreatLikeFindingSignals(finding) {
		return "疑似误报: 当前证据主要来自文档、注释或示例内容，若无真实调用链与发布路径支撑，不应直接按漏洞确认。"
	}
	return "待人工复核: 证据可疑但仍需确认可达性、影响和排除条件。"
}

func structuredFindingCalibration(category string, items []plugins.Finding, refined review.Result) (string, []string) {
	basis := make([]string, 0, 6)
	confidenceScore := 1
	if len(items) > 1 {
		confidenceScore++
		basis = append(basis, fmt.Sprintf("同类证据命中 %d 次，已合并展示", len(items)))
	}
	if chains := relevantBehaviorChains(category, refined.Behavior); len(chains) > 0 {
		confidenceScore += 2
		basis = append(basis, "存在与当前风险相关的高风险行为链，静态发现与运行行为可相互印证")
	}
	if alerts := relevantSequenceAlerts(category, refined.Behavior); len(alerts) > 0 {
		confidenceScore += 2
		basis = append(basis, "存在与当前风险相关的高危时序告警，可支持攻击路径成立性复核")
	}
	if category == "外联与情报" && len(refined.TIReputations) > 0 {
		confidenceScore++
		basis = append(basis, "存在外联目标信誉信息，可用于区分普通网络访问与可疑目标")
	}
	if category == "声明与行为差异" && len(refined.IntentDiffs) > 0 {
		confidenceScore++
		basis = append(basis, "存在声明与实际行为差异，需结合权限声明复核")
	}
	if category == "反分析/逃逸" && refined.Evasion.Detected {
		confidenceScore += 2
		basis = append(basis, "差分执行或逃逸信号已触发，需优先复测")
	}
	if len(basis) == 0 {
		basis = append(basis, "当前主要由规则命中和证据片段支撑，需人工验证入口可达性")
	}
	switch {
	case confidenceScore >= 4:
		return "高", basis
	case confidenceScore >= 2:
		return "中", basis
	default:
		return "待复核", basis
	}
}

func structuredFindingEvidence(items []plugins.Finding, sourceIndex map[string][]string) []string {
	return reviewreport.StructuredFindingEvidence(items, sourceIndex, 6)
}

func structuredFindingChainSummaries(category string, behavior review.BehaviorProfile, obfuscationChains []review.FindingChain) []string {
	out := make([]string, 0, 4)
	for _, item := range relevantBehaviorChains(category, behavior) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, "行为链: "+item)
	}
	for _, item := range relevantSequenceAlerts(category, behavior) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, "时序告警: "+item)
	}
	for _, chain := range obfuscationChains {
		summary := strings.TrimSpace(chain.Summary)
		if summary == "" {
			continue
		}
		out = append(out, "混淆传播: "+summary)
	}
	return uniqueStrings(out)
}

func structuredFindingChains(category string, behavior review.BehaviorProfile, obfuscationChains []review.FindingChain) []review.FindingChain {
	out := make([]review.FindingChain, 0, 4+len(obfuscationChains))
	for _, item := range relevantBehaviorChains(category, behavior) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		source := item
		path := ""
		if pipe := strings.Index(item, "|"); pipe > 0 {
			source = strings.TrimSpace(item[:pipe])
		}
		path = filepath.ToSlash(strings.TrimSpace(chainSourcePath(source)))
		out = append(out, review.FindingChain{Kind: "behavior_chain", Summary: item, Source: source, Path: path})
	}
	for _, item := range relevantSequenceAlerts(category, behavior) {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, review.FindingChain{Kind: "sequence_alert", Summary: item})
	}
	out = append(out, obfuscationChains...)
	return dedupeFindingChains(out)
}

func buildObfuscationFindingChainsByCategory(items []review.ObfuscationEvidence) map[string][]review.FindingChain {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string][]review.FindingChain)
	for _, item := range items {
		for _, category := range []string{"命令执行", "外联与情报", "凭据访问", "反分析/逃逸"} {
			for _, chain := range obfuscationFindingChains(category, item) {
				out[category] = append(out[category], chain)
			}
		}
	}
	for category, chains := range out {
		out[category] = dedupeFindingChains(chains)
	}
	return out
}

func obfuscationFindingChains(category string, item review.ObfuscationEvidence) []review.FindingChain {
	signals := filterRelevantDataFlowSignals(category, item.DataFlowSignals)
	if len(signals) == 0 {
		return nil
	}
	pathLabel := filepath.ToSlash(strings.TrimSpace(item.Path))
	decodedPreview := summarizeDecodedPreview(item.DecodedText)
	out := make([]review.FindingChain, 0, len(signals))
	for _, signal := range signals {
		signal = strings.TrimSpace(signal)
		if signal == "" {
			continue
		}
		summary := renderDataFlowNarrative(pathLabel, decodedPreview, []string{signal})
		if summary == "" {
			summary = signal
		}
		out = append(out, review.FindingChain{
			Kind:    dataFlowSignalKind(signal),
			Summary: summary,
			Source:  signal,
			Path:    pathLabel,
		})
	}
	return out
}

func dataFlowSignalKind(signal string) string {
	signal = strings.TrimSpace(signal)
	switch {
	case strings.Contains(signal, "命令构造链"):
		return "obfuscation_command_flow"
	case strings.Contains(signal, "网络链"):
		return "obfuscation_network_flow"
	case strings.Contains(signal, "执行链"):
		return "obfuscation_exec_flow"
	default:
		return "obfuscation_flow"
	}
}

func chainSourcePath(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	if p, _, ok := parseSourceLocation(source); ok {
		return p
	}
	if idx := strings.Index(source, ":"); idx > 0 {
		return strings.TrimSpace(source[:idx])
	}
	return source
}

func dedupeFindingChains(items []review.FindingChain) []review.FindingChain {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]review.FindingChain, 0, len(items))
	for _, item := range items {
		key := strings.TrimSpace(item.Kind) + "\x00" + strings.TrimSpace(item.Summary) + "\x00" + strings.TrimSpace(item.Source) + "\x00" + strings.TrimSpace(item.Path)
		if key == "\x00\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func renderFindingChainsForVulnBlock(items []review.FindingChain) string {
	return reviewreport.RenderFindingChains(items)
}

func appendObfuscationEvidence(existing []string, items []plugins.Finding, category string, obfuscation []review.ObfuscationEvidence) []string {
	if len(items) == 0 || len(obfuscation) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing))
	out := append([]string{}, existing...)
	for _, item := range items {
		path, _, ok := parseSourceLocation(item.Location)
		if !ok {
			continue
		}
		for _, entry := range matchingObfuscationEvidence(path, category, obfuscation) {
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			out = append(out, entry)
		}
	}
	return out
}

func matchingObfuscationEvidence(path string, category string, items []review.ObfuscationEvidence) []string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	base := strings.TrimSpace(filepath.Base(path))
	if path == "" && base == "" {
		return nil
	}
	out := make([]string, 0, 2)
	for _, item := range items {
		candidate := filepath.ToSlash(strings.TrimSpace(item.Path))
		candidateBase := strings.TrimSpace(filepath.Base(candidate))
		if candidate == "" {
			continue
		}
		if candidate != path && candidateBase != base {
			continue
		}
		filtered := filterRelevantDataFlowSignals(category, item.DataFlowSignals)
		item.DataFlowSignals = filtered
		if line := renderObfuscationEvidenceLine(item); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func filterRelevantDataFlowSignals(category string, signals []string) []string {
	if len(signals) == 0 {
		return nil
	}
	relevant := make([]string, 0, len(signals))
	for _, signal := range signals {
		signal = strings.TrimSpace(signal)
		if signal == "" {
			continue
		}
		if isRelevantDataFlowSignal(category, signal) {
			relevant = append(relevant, signal)
		}
	}
	return uniqueStrings(relevant)
}

func isRelevantDataFlowSignal(category, signal string) bool {
	signal = strings.TrimSpace(signal)
	switch category {
	case "命令执行":
		return strings.Contains(signal, "执行链") || strings.Contains(signal, "命令构造链")
	case "外联与情报":
		return strings.Contains(signal, "网络链")
	case "凭据访问":
		return strings.Contains(signal, "网络链") || strings.Contains(signal, "执行链")
	case "反分析/逃逸":
		return strings.Contains(signal, "执行链")
	default:
		return true
	}
}

func renderObfuscationEvidenceLine(item review.ObfuscationEvidence) string {
	parts := make([]string, 0, 4)
	pathLabel := defaultIfEmpty(strings.TrimSpace(item.Path), "unknown")
	decodedPreview := summarizeDecodedPreview(item.DecodedText)
	if v := strings.TrimSpace(item.Summary); v != "" {
		parts = append(parts, "摘要: "+v)
	}
	if v := strings.TrimSpace(item.Technique); v != "" {
		parts = append(parts, "方式: "+v)
	}
	if v := strings.TrimSpace(item.DecodedText); v != "" {
		parts = append(parts, "还原: "+v)
	}
	if len(item.DataFlowSignals) > 0 {
		parts = append(parts, "结论: "+renderDataFlowNarrative(pathLabel, decodedPreview, item.DataFlowSignals))
	}
	if len(parts) == 0 {
		return ""
	}
	return "混淆解析证据 / " + pathLabel + " / " + strings.Join(parts, "；")
}

func renderDataFlowNarrative(pathLabel, decodedPreview string, signals []string) string {
	if len(signals) == 0 {
		return ""
	}
	clauses := make([]string, 0, len(signals))
	prefix := "文件 " + pathLabel
	if decodedPreview != "" {
		prefix += " 中恢复出的内容“" + decodedPreview + "”"
	} else {
		prefix += " 中恢复出的内容"
	}
	for _, signal := range signals {
		signal = strings.TrimSpace(signal)
		switch {
		case strings.Contains(signal, "解码变量疑似流向执行链"):
			clauses = append(clauses, prefix+"经变量传播后进入执行入口")
		case strings.Contains(signal, "解码变量疑似流向网络链"):
			clauses = append(clauses, prefix+"经变量传播后进入网络请求入口")
		case strings.Contains(signal, "解码变量疑似流向命令构造链"):
			clauses = append(clauses, prefix+"经变量传播后参与命令构造")
		case strings.Contains(signal, "解码结果疑似流向执行链"):
			clauses = append(clauses, prefix+"与执行入口同时出现")
		case strings.Contains(signal, "解码结果疑似流向网络链"):
			clauses = append(clauses, prefix+"与网络请求入口同时出现")
		case strings.Contains(signal, "解码结果疑似流向命令构造链"):
			clauses = append(clauses, prefix+"与命令构造片段同时出现")
		default:
			clauses = append(clauses, signal)
		}
	}
	clauses = uniqueStrings(clauses)
	if len(clauses) == 0 {
		return ""
	}
	return strings.Join(clauses, "；")
}

func summarizeDecodedPreview(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	runes := []rune(text)
	if len(runes) > 48 {
		return string(runes[:48]) + "..."
	}
	return text
}

func buildSourceContextIndex(root string, files []evaluator.SourceFile) map[string][]string {
	return reviewreport.BuildSourceContextIndex(root, files, displayRelPath)
}

type codeEvidenceWindow struct {
	path     string
	start    int
	end      int
	hitLines map[int]bool
	lines    map[int]string
}

func newCodeEvidenceWindow(item plugins.Finding, sourceIndex map[string][]string) (codeEvidenceWindow, bool) {
	path, line, ok := parseSourceLocation(item.Location)
	if !ok {
		return codeEvidenceWindow{}, false
	}
	if window, ok := buildWindowFromSourceIndex(path, line, sourceIndex); ok {
		return window, true
	}
	lines := normalizeCodeSnippetLines(item.CodeSnippet)
	if len(lines) == 0 {
		return codeEvidenceWindow{}, false
	}
	window := codeEvidenceWindow{
		path:     path,
		start:    line,
		end:      line + len(lines) - 1,
		hitLines: map[int]bool{line: true},
		lines:    make(map[int]string, len(lines)),
	}
	for idx, snippetLine := range lines {
		window.lines[line+idx] = snippetLine
	}
	return window, true
}

func buildWindowFromSourceIndex(path string, hitLine int, sourceIndex map[string][]string) (codeEvidenceWindow, bool) {
	if len(sourceIndex) == 0 {
		return codeEvidenceWindow{}, false
	}
	lines, ok := sourceIndex[filepath.ToSlash(strings.TrimSpace(path))]
	if !ok || hitLine <= 0 || hitLine > len(lines) {
		return codeEvidenceWindow{}, false
	}
	start := hitLine - 3
	if start < 1 {
		start = 1
	}
	end := hitLine + 3
	if end > len(lines) {
		end = len(lines)
	}
	window := codeEvidenceWindow{
		path:     filepath.ToSlash(strings.TrimSpace(path)),
		start:    start,
		end:      end,
		hitLines: map[int]bool{hitLine: true},
		lines:    make(map[int]string, end-start+1),
	}
	for lineNo := start; lineNo <= end; lineNo++ {
		window.lines[lineNo] = lines[lineNo-1]
	}
	return window, true
}

func parseSourceLocation(location string) (string, int, bool) {
	return reviewreport.ParseSourceLocation(location)
}

func normalizeCodeSnippetLines(snippet string) []string {
	snippet = strings.ReplaceAll(snippet, "\r\n", "\n")
	rawLines := strings.Split(snippet, "\n")
	for len(rawLines) > 0 && strings.TrimSpace(rawLines[0]) == "" {
		rawLines = rawLines[1:]
	}
	for len(rawLines) > 0 && strings.TrimSpace(rawLines[len(rawLines)-1]) == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}
	if len(rawLines) == 0 {
		return nil
	}
	return rawLines
}

func mergeCodeEvidenceWindows(windows []codeEvidenceWindow) []codeEvidenceWindow {
	if len(windows) == 0 {
		return nil
	}
	sorted := append([]codeEvidenceWindow(nil), windows...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].path == sorted[j].path {
			if sorted[i].start == sorted[j].start {
				return sorted[i].end < sorted[j].end
			}
			return sorted[i].start < sorted[j].start
		}
		return sorted[i].path < sorted[j].path
	})
	merged := []codeEvidenceWindow{sorted[0]}
	for _, current := range sorted[1:] {
		last := &merged[len(merged)-1]
		if last.path == current.path && current.start <= last.end+1 {
			mergeIntoCodeEvidenceWindow(last, current)
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func mergeIntoCodeEvidenceWindow(dst *codeEvidenceWindow, src codeEvidenceWindow) {
	if src.start < dst.start {
		dst.start = src.start
	}
	if src.end > dst.end {
		dst.end = src.end
	}
	for line, value := range src.lines {
		if _, exists := dst.lines[line]; !exists {
			dst.lines[line] = value
		}
	}
	for line := range src.hitLines {
		dst.hitLines[line] = true
	}
}

func renderMergedCodeEvidence(window codeEvidenceWindow) string {
	lineNumbers := make([]int, 0, len(window.lines))
	for line := range window.lines {
		lineNumbers = append(lineNumbers, line)
	}
	sort.Ints(lineNumbers)
	var b strings.Builder
	b.WriteString(window.path)
	b.WriteString(":")
	b.WriteString(strconv.Itoa(window.start))
	if window.end > window.start {
		b.WriteString("-")
		b.WriteString(strconv.Itoa(window.end))
	}
	for _, line := range lineNumbers {
		marker := "  "
		if window.hitLines[line] {
			marker = "> "
		}
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s%4d | %s", marker, line, window.lines[line]))
	}
	return b.String()
}

func structuredFindingCategory(f plugins.Finding) string {
	text := strings.ToLower(strings.Join([]string{f.RuleID, f.Title, f.Description}, " "))
	switch {
	case strings.Contains(text, "凭据") || strings.Contains(text, "credential") || strings.Contains(text, "token") || strings.Contains(text, "secret"):
		return "凭据访问"
	case strings.Contains(text, "外联") || strings.Contains(text, "外发") || strings.Contains(text, "隐蔽通道") || strings.Contains(text, "network") || strings.Contains(text, "http") || strings.Contains(text, "c2") || strings.Contains(text, "情报"):
		return "外联与情报"
	case strings.Contains(text, "执行") || strings.Contains(text, "command") || strings.Contains(text, "shell") || strings.Contains(text, "命令"):
		return "命令执行"
	case strings.Contains(text, "持久化") || strings.Contains(text, "persistence") || strings.Contains(text, "cron"):
		return "持久化"
	case strings.Contains(text, "提权") || strings.Contains(text, "privilege") || strings.Contains(text, "sudo"):
		return "提权"
	case strings.Contains(text, "逃逸") || strings.Contains(text, "规避") || strings.Contains(text, "evasion") || strings.Contains(text, "sandbox"):
		return "反分析/逃逸"
	case strings.Contains(text, "声明") || strings.Contains(text, "意图") || strings.Contains(text, "一致"):
		return "声明与行为差异"
	case strings.Contains(text, "覆盖") || strings.Contains(text, "coverage"):
		return "规则覆盖"
	default:
		return "静态规则发现"
	}
}

func hasRelevantBehaviorSupport(category string, behavior review.BehaviorProfile) bool {
	return len(relevantBehaviorChains(category, behavior)) > 0 || len(relevantSequenceAlerts(category, behavior)) > 0
}

func relevantBehaviorChains(category string, behavior review.BehaviorProfile) []string {
	keys := relevantBehaviorCategories(category)
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(behavior.BehaviorChains))
	for _, chain := range behavior.BehaviorChains {
		if behaviorChainMatchesAnyCategory(chain, keys) {
			out = append(out, chain)
		}
	}
	return uniqueStrings(out)
}

func relevantSequenceAlerts(category string, behavior review.BehaviorProfile) []string {
	allowed := relevantSequenceAlertLabels(category)
	if len(allowed) == 0 {
		return nil
	}
	allowSet := make(map[string]struct{}, len(allowed))
	for _, item := range allowed {
		allowSet[item] = struct{}{}
	}
	out := make([]string, 0, len(behavior.SequenceAlerts))
	for _, alert := range behavior.SequenceAlerts {
		if _, ok := allowSet[strings.TrimSpace(alert)]; ok {
			out = append(out, alert)
		}
	}
	return uniqueStrings(out)
}

func relevantBehaviorCategories(category string) []string {
	switch category {
	case "命令执行":
		return []string{"执行"}
	case "外联与情报":
		return []string{"外联", "C2信标", "收集打包", "凭据访问", "横向移动"}
	case "凭据访问":
		return []string{"凭据访问", "外联", "收集打包"}
	case "持久化":
		return []string{"持久化"}
	case "提权":
		return []string{"提权"}
	case "反分析/逃逸":
		return []string{"防御规避", "执行"}
	default:
		return nil
	}
}

func relevantSequenceAlertLabels(category string) []string {
	switch category {
	case "命令执行":
		return []string{"命中下载后执行时序", "命中防御规避后执行时序", "命中横向移动联动控制时序"}
	case "外联与情报":
		return []string{"命中收集后外联时序", "命中凭据访问后外联时序", "命中横向移动联动控制时序"}
	case "凭据访问":
		return []string{"命中凭据访问后外联时序"}
	case "反分析/逃逸":
		return []string{"命中防御规避后执行时序"}
	default:
		return nil
	}
}

func behaviorChainMatchesAnyCategory(chain string, categories []string) bool {
	for _, category := range categories {
		if behaviorChainHasPositiveCount(chain, category) {
			return true
		}
	}
	return false
}

func behaviorChainHasPositiveCount(chain string, category string) bool {
	needle := category + "="
	idx := strings.Index(chain, needle)
	if idx < 0 {
		return false
	}
	start := idx + len(needle)
	end := start
	for end < len(chain) && chain[end] >= '0' && chain[end] <= '9' {
		end++
	}
	if end == start {
		return false
	}
	count, err := strconv.Atoi(chain[start:end])
	if err != nil {
		return false
	}
	return count > 0
}

func structuredAttackPath(category string, f plugins.Finding, refined review.Result) string {
	if chains := relevantBehaviorChains(category, refined.Behavior); len(chains) > 0 {
		return strings.Join(limitList(chains, 2), "；")
	}
	if alerts := relevantSequenceAlerts(category, refined.Behavior); len(alerts) > 0 {
		return strings.Join(limitList(alerts, 2), "；")
	}
	switch category {
	case "命令执行":
		return "源码或运行时证据显示技能可能调用 shell、解释器或系统命令，需要确认入口参数是否可控。"
	case "凭据访问":
		return "技能存在访问 token、密钥、环境变量或认证文件的证据，需要确认是否为声明用途必要行为。"
	case "外联与情报":
		return "技能存在网络访问或可疑目标信誉证据，需要确认请求目标、数据内容和授权范围。"
	case "声明与行为差异":
		return "技能声明与实际行为存在偏差，需要将声明、权限和源码行为放在同一证据链中复核。"
	default:
		return defaultIfEmpty(f.Description, "当前发现依赖规则命中和证据片段，需要结合上下文复核可达性与真实影响。")
	}
}

func falsePositiveChecks(category string, f plugins.Finding, refined review.Result) []string {
	checks := []string{
		"确认证据是否位于真实运行路径；即使位于 README、注释、测试或示例文件，也要继续检查是否会被实际引用、打包、解析或动态加载。",
		"确认触发位置是否可由技能入口到达，且不依赖不可用配置或未启用功能。",
	}
	switch category {
	case "命令执行":
		checks = append(checks, "确认命令参数是否固定、是否经过白名单校验，以及是否允许用户输入拼接。")
	case "外联与情报":
		checks = append(checks, "确认外联域名是否为声明服务、是否传输敏感数据，以及威胁情报结果是否来自真实 IoC。")
	case "凭据访问":
		checks = append(checks, "确认读取凭据是否为用户显式授权，并检查是否存在后续外联或落地链路。")
	case "声明与行为差异":
		checks = append(checks, "确认 SKILL.md、manifest 和权限声明是否遗漏实际能力，必要时补充声明后复扫。")
	}
	if len(refined.EvidenceInventory) == 0 {
		checks = append(checks, "当前发现缺少归一化证据目录支撑，应回溯原始规则记录和源码上下文。")
	}
	return checks
}

func structuredReviewGuidance(category, severity string) string {
	if severity == "高风险" {
		return "优先复核攻击路径是否成立；若成立，应先修复或移除相关能力，再进行全量复扫。"
	}
	switch category {
	case "规则覆盖":
		return "补齐自动化覆盖或记录人工复核结论，避免规则盲区影响最终判断。"
	case "声明与行为差异":
		return "同步修正技能声明、权限说明和实际实现，确保用户能基于透明能力做判断。"
	default:
		return "结合证据片段、行为时序和业务用途复核，确认是否为必要能力或可收敛实现。"
	}
}

func findingsText(findings []plugins.Finding) string {
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, f.RuleID, f.Title, f.Description, f.CodeSnippet)
	}
	return strings.Join(parts, " ")
}

func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(text, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func capabilityStatus(declared, staticDetected, llmDetected, sandboxDetected bool) (string, string) {
	observed := staticDetected || llmDetected || sandboxDetected
	switch {
	case declared && observed && sandboxDetected:
		return "已声明且多源验证", ""
	case declared && observed:
		return "已声明但沙箱未验证", "沙箱未检出对应行为，需检查入口触发、动态拼接、环境条件或探针覆盖"
	case !declared && observed && sandboxDetected:
		return "未声明但沙箱检出", "能力未在声明或权限中清晰披露，存在隐瞒能力风险"
	case !declared && observed:
		return "未声明但静态/LLM 检出", "能力未声明且缺少运行时验证，需要人工确认是否为真实可达行为"
	case declared:
		return "已声明但未检出", "声明中提及能力，但当前静态/LLM/沙箱未形成有效证据"
	default:
		return "未观察到", ""
	}
}

func capabilityEvidence(capability string, sandboxEvidence []string, findings []plugins.Finding, base baseScanOutput, refined review.Result) []string {
	evidence := make([]string, 0, 6)
	if len(sandboxEvidence) > 0 {
		evidence = append(evidence, "沙箱证据: "+strings.Join(sandboxEvidence, "；"))
	}
	for _, f := range findings {
		cat := structuredFindingCategory(f)
		if (capability == "外联/网络访问" && cat == "外联与情报") || (capability == "命令执行" && cat == "命令执行") || (capability == "文件读写/落地" && cat == "文件读写/落地") || (capability == "凭据访问" && cat == "凭据访问") || (capability == "持久化" && cat == "持久化") || (capability == "提权/沙箱逃逸" && cat == "反分析/逃逸") || (capability == "数据收集/打包" && cat == "数据收集/打包") {
			evidence = append(evidence, "规则证据: "+f.RuleID+" "+f.Title)
			break
		}
	}
	if base.intentSummary.Available && len(base.intentSummary.ActualCapabilities) > 0 {
		evidence = append(evidence, "LLM 实际能力: "+strings.Join(base.intentSummary.ActualCapabilities, "；"))
	}
	if capability == "外联/网络访问" && len(refined.TIReputations) > 0 {
		targets := make([]string, 0, len(refined.TIReputations))
		for _, rep := range refined.TIReputations {
			targets = append(targets, rep.Target+" -> "+localizeReputation(rep.Reputation))
		}
		evidence = append(evidence, "情报证据: "+strings.Join(targets, "；"))
	}
	return evidence
}

func buildDynamicSuggestions(findings []plugins.Finding, refined review.Result) []string {
	return reviewreport.BuildDynamicSuggestions(findings, refined)
}

func remediationForHTMLFinding(f plugins.Finding) string {
	return reviewreport.RemediationForHTMLFinding(f)
}

func sortFindingsBySeverity(findings []plugins.Finding) []plugins.Finding {
	return reviewreport.SortFindingsBySeverity(findings)
}

func sortFindingsByReview(findings []plugins.Finding, refined review.Result) []plugins.Finding {
	out := append([]plugins.Finding(nil), findings...)
	if len(refined.StructuredFindings) == 0 || len(refined.ReviewAgentVerdicts) == 0 {
		return sortFindingsBySeverity(out)
	}
	structuredByKey := structuredFindingByCompositeKey(refined.StructuredFindings)
	verdicts := preferredVerdictsByFinding(refined.ReviewAgentVerdicts)
	sort.SliceStable(out, func(i, j int) bool {
		left := reviewSortKeyForFinding(out[i], structuredByKey, verdicts)
		right := reviewSortKeyForFinding(out[j], structuredByKey, verdicts)
		if left.reviewRank != right.reviewRank {
			return left.reviewRank < right.reviewRank
		}
		if left.severityRank != right.severityRank {
			return left.severityRank < right.severityRank
		}
		return left.ruleID < right.ruleID
	})
	return out
}

func sortStructuredFindingsByReview(findings []review.StructuredFinding, refined review.Result) []review.StructuredFinding {
	out := append([]review.StructuredFinding(nil), findings...)
	if len(refined.ReviewAgentVerdicts) == 0 {
		sort.SliceStable(out, func(i, j int) bool {
			return severityRank(out[i].Severity) < severityRank(out[j].Severity)
		})
		return out
	}
	verdicts := preferredVerdictsByFinding(refined.ReviewAgentVerdicts)
	sort.SliceStable(out, func(i, j int) bool {
		left := reviewSortKeyForStructuredFinding(out[i], verdicts)
		right := reviewSortKeyForStructuredFinding(out[j], verdicts)
		if left.reviewRank != right.reviewRank {
			return left.reviewRank < right.reviewRank
		}
		if left.severityRank != right.severityRank {
			return left.severityRank < right.severityRank
		}
		return left.id < right.id
	})
	return out
}

type reviewFindingSortKey struct {
	reviewRank   int
	severityRank int
	ruleID       string
	id           string
}

func reviewSortKeyForFinding(finding plugins.Finding, structuredByKey map[string]review.StructuredFinding, verdicts map[string]review.ReviewAgentVerdict) reviewFindingSortKey {
	structured, ok := structuredByKey[findingCompositeKey(finding.RuleID, finding.Severity, finding.Title)]
	if !ok {
		return reviewFindingSortKey{reviewRank: reviewVerdictRank(""), severityRank: severityRank(finding.Severity), ruleID: finding.RuleID}
	}
	verdict := verdicts[structured.ID]
	return reviewFindingSortKey{reviewRank: reviewVerdictRank(verdict.Verdict), severityRank: severityRank(structured.Severity), ruleID: structured.RuleID, id: structured.ID}
}

func reviewSortKeyForStructuredFinding(finding review.StructuredFinding, verdicts map[string]review.ReviewAgentVerdict) reviewFindingSortKey {
	verdict := verdicts[finding.ID]
	return reviewFindingSortKey{reviewRank: reviewVerdictRank(verdict.Verdict), severityRank: severityRank(finding.Severity), ruleID: finding.RuleID, id: finding.ID}
}

func structuredFindingByCompositeKey(findings []review.StructuredFinding) map[string]review.StructuredFinding {
	out := make(map[string]review.StructuredFinding, len(findings))
	for _, finding := range findings {
		out[findingCompositeKey(finding.RuleID, finding.Severity, finding.Title)] = finding
	}
	return out
}

func findingCompositeKey(ruleID, severity, title string) string {
	return strings.Join([]string{ruleID, severity, title}, "\x00")
}

func reviewVerdictRank(verdict string) int {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed":
		return 0
	case "needs_manual_review":
		return 1
	case "likely_false_positive":
		return 3
	default:
		return 2
	}
}

func severityRank(severity string) int {
	switch localizeSeverity(severity) {
	case "高风险":
		return 0
	case "中风险":
		return 1
	case "低风险":
		return 2
	default:
		return 3
	}
}

func finalReviewSummaryForFinding(finding plugins.Finding, refined review.Result) string {
	structured, ok := structuredFindingByCompositeKey(refined.StructuredFindings)[findingCompositeKey(finding.RuleID, finding.Severity, finding.Title)]
	if !ok {
		return "无匹配结构化发现"
	}
	return finalReviewSummaryForStructuredFinding(structured.ID, refined)
}

func finalReviewSummaryForStructuredFinding(findingID string, refined review.Result) string {
	verdict, ok := preferredVerdictsByFinding(refined.ReviewAgentVerdicts)[findingID]
	if !ok || strings.TrimSpace(verdict.Verdict) == "" {
		return "未生成最终裁决"
	}
	return localizeReviewVerdict(verdict.Verdict) + " / " + localizeReviewerLabel(defaultIfEmpty(verdict.Reviewer, "unknown-reviewer")) + " / 置信度: " + defaultIfEmpty(verdict.Confidence, "未标注")
}

func localizeReviewerLabel(reviewer string) string {
	reviewer = strings.TrimSpace(reviewer)
	if reviewer == "" {
		return "未知复核器"
	}
	parts := strings.Split(reviewer, "+")
	labels := make([]string, 0, len(parts))
	for _, part := range parts {
		switch strings.TrimSpace(part) {
		case "deterministic-vuln-reviewer":
			labels = append(labels, "规则复核器")
		case "llm-vuln-reviewer":
			labels = append(labels, "语义复核器")
		default:
			labels = append(labels, strings.TrimSpace(part))
		}
	}
	return strings.Join(labels, "+")
}

func localizeReviewVerdict(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed":
		return "确认风险"
	case "needs_manual_review":
		return "需人工复核"
	case "likely_false_positive":
		return "疑似误报"
	default:
		return defaultIfEmpty(verdict, "未裁决")
	}
}

func defaultIfEmpty(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}

func localizeAdmission(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "userdecisionrequired", "user_decision_required":
		return "待用户基于证据判断"
	case "pass":
		return "系统建议通过，仍需用户确认"
	case "review":
		return "需人工复核"
	case "block":
		return "需完成修复并复测"
	default:
		if strings.TrimSpace(v) == "" {
			return "未给出结论"
		}
		return v
	}
}

func localizeSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "high", "high risk", "critical", "严重", "严重风险", "高", "高风险":
		return "高风险"
	case "medium", "medium risk", "中", "中风险":
		return "中风险"
	case "low", "low risk", "低", "低风险":
		return "低风险"
	default:
		if strings.TrimSpace(v) == "" {
			return "低风险"
		}
		return v
	}
}

func localizeFindings(findings []plugins.Finding) []plugins.Finding {
	localized := make([]plugins.Finding, 0, len(findings))
	for _, f := range findings {
		item := f
		item.Severity = localizeSeverity(f.Severity)
		item.Title = localizeFindingText(f.Title, "检测到潜在风险")
		item.Description = localizeFindingText(f.Description, "检测到可疑行为，请结合规则与关键代码片段复核。")
		if strings.TrimSpace(item.Location) == "" {
			item.Location = "未提供定位"
		}
		localized = append(localized, item)
	}
	return localized
}

func localizeFindingText(text, fallback string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return fallback
	}
	if containsChinese(text) {
		return text
	}

	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "backdoor"):
		return "检测到后门触发或隐藏执行风险"
	case strings.Contains(lower, "hardcoded") || strings.Contains(lower, "credential"):
		return "检测到硬编码凭据或敏感信息访问风险"
	case strings.Contains(lower, "download"):
		return "检测到可疑下载行为风险"
	case strings.Contains(lower, "execute") || strings.Contains(lower, "command"):
		return "检测到可疑执行链路风险"
	case strings.Contains(lower, "outbound") || strings.Contains(lower, "network") || strings.Contains(lower, "c2") || strings.Contains(lower, "beacon"):
		return "检测到可疑外联或远程控制风险"
	case strings.Contains(lower, "persistence"):
		return "检测到可疑持久化风险"
	case strings.Contains(lower, "privilege") || strings.Contains(lower, "privesc"):
		return "检测到提权相关风险"
	case strings.Contains(lower, "evasion") || strings.Contains(lower, "sandbox") || strings.Contains(lower, "vm"):
		return "检测到反分析或规避检测风险"
	case strings.Contains(lower, "lateral"):
		return "检测到横向移动风险"
	case strings.Contains(lower, "collection"):
		return "检测到敏感数据收集风险"
	case strings.Contains(lower, "suspicious") || strings.Contains(lower, "malicious"):
		return "检测到可疑恶意行为风险"
	default:
		return fallback
	}
}

func containsChinese(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func localizeRiskLevel(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "low":
		return "低风险"
	case "medium":
		return "中风险"
	case "high":
		return "高风险"
	case "critical":
		return "严重风险"
	default:
		if strings.TrimSpace(v) == "" {
			return "未评估"
		}
		return v
	}
}

func localizeReputation(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "trusted":
		return "可信"
	case "internal":
		return "内网或本地目标"
	case "suspicious":
		return "可疑"
	case "unknown":
		return "未知"
	default:
		if strings.TrimSpace(v) == "" {
			return "未知"
		}
		return v
	}
}

func buildBehaviorSummary(behavior review.BehaviorProfile) string {
	parts := make([]string, 0, 4)
	if len(behavior.NetworkTargets) > 0 {
		parts = append(parts, fmt.Sprintf("外联目标 %d 个（证据: %s）", len(behavior.NetworkTargets), sampleTarget(behavior.NetworkTargets)))
	}
	if len(behavior.FileTargets) > 0 {
		parts = append(parts, fmt.Sprintf("文件操作 %d 个（证据: %s）", len(behavior.FileTargets), sampleTarget(behavior.FileTargets)))
	}
	if len(behavior.ExecTargets) > 0 {
		parts = append(parts, fmt.Sprintf("命令执行 %d 个（证据: %s）", len(behavior.ExecTargets), sampleTarget(behavior.ExecTargets)))
	}
	if len(behavior.BehaviorChains) > 0 {
		parts = append(parts, fmt.Sprintf("高风险链路 %d 条", len(behavior.BehaviorChains)))
	}
	if len(parts) == 0 {
		return "未检测到明显运行时行为证据"
	}
	return strings.Join(parts, "；")
}

func buildObfuscationEvidence(files []evaluator.SourceFile) []review.ObfuscationEvidence {
	out := make([]review.ObfuscationEvidence, 0)
	for _, file := range files {
		pre := strings.TrimSpace(file.PreprocessedContent)
		if pre == "" {
			continue
		}
		relPath := filepath.ToSlash(strings.TrimSpace(file.Path))
		ev := review.ObfuscationEvidence{
			Path:            relPath,
			DataFlowSignals: evaluator.ExtractDataFlowSignals(file.Content, file.PreprocessedContent),
		}
		for _, line := range strings.Split(pre, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "technique: "):
				ev.Technique = strings.TrimSpace(strings.TrimPrefix(line, "technique: "))
			case strings.HasPrefix(line, "confidence: "):
				ev.Confidence = strings.TrimSpace(strings.TrimPrefix(line, "confidence: "))
			case strings.HasPrefix(line, "summary: "):
				ev.Summary = strings.TrimSpace(strings.TrimPrefix(line, "summary: "))
			case strings.HasPrefix(line, "decoded: "):
				ev.DecodedText = strings.TrimSpace(strings.TrimPrefix(line, "decoded: "))
			case strings.HasPrefix(line, "benign: "):
				ev.BenignIndicators = splitPipeList(strings.TrimSpace(strings.TrimPrefix(line, "benign: ")))
			case strings.HasPrefix(line, "risk: "):
				ev.RiskIndicators = splitPipeList(strings.TrimSpace(strings.TrimPrefix(line, "risk: ")))
			}
		}
		if ev.Summary == "" && ev.DecodedText == "" && ev.Technique == "" {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func splitPipeList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, "|")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func sampleTarget(items []string) string {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		r := []rune(item)
		if len(r) > 40 {
			return string(r[:40]) + "..."
		}
		return item
	}
	return "无"
}

func buildHTMLReport(fileName, declaredDescription string, findings []plugins.Finding, base baseScanOutput, refined review.Result, evalLogs []ruleEvaluationLog) string {
	var b strings.Builder
	riskCalibration := buildRiskCalibrationSummary(findings, base, refined)
	b.WriteString("<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\"><title>技能审查报告</title>")
	b.WriteString(renderReportStyles())
	if false {
		b.WriteString("<style>:root{color-scheme:light;--bg:#f3f6fb;--card:#ffffff;--ink:#142033;--muted:#5f6b7a;--line:#d8e0ec;--blue:#2156d1;--blue-soft:#e8f0ff;--red:#b42318;--amber:#b54708;--green:#067647;}*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:linear-gradient(180deg,#eef4ff 0,#f7f9fc 220px,#f3f6fb 100%);color:var(--ink)}main{max-width:1380px;margin:0 auto;padding:28px 24px 64px}h1{margin:0 0 10px;font-size:32px}h2{margin:0 0 14px;font-size:22px}p{line-height:1.6}.hero{background:linear-gradient(135deg,#17388f 0,#2156d1 52%,#4c7dff 100%);color:#fff;border-radius:20px;padding:28px;box-shadow:0 18px 50px rgba(33,86,209,.22)}.hero p{margin:6px 0 0}.hero-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin-top:18px}.hero-stat{background:rgba(255,255,255,.14);border:1px solid rgba(255,255,255,.18);border-radius:14px;padding:14px}.hero-stat strong{display:block;font-size:13px;font-weight:600;opacity:.9}.hero-stat span{display:block;font-size:24px;font-weight:700;margin-top:4px}.nav{display:flex;flex-wrap:wrap;gap:10px;margin:18px 0 4px}.nav a{text-decoration:none;color:var(--blue);background:var(--blue-soft);border:1px solid #cddcff;padding:8px 12px;border-radius:999px;font-size:13px;font-weight:600}.card{background:var(--card);border:1px solid rgba(20,32,51,.07);border-radius:18px;padding:18px 20px;margin:14px 0;box-shadow:0 10px 28px rgba(17,24,39,.06)}.section-head{display:flex;justify-content:space-between;gap:12px;align-items:flex-start;margin-bottom:12px}.section-head .hint{max-width:65%}.grid-two{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.pill{display:inline-block;padding:4px 10px;border-radius:999px;font-size:12px;font-weight:700;background:#eef2ff;color:#344054;border:1px solid #d7def5}.risk-high{color:var(--red);font-weight:700}.risk-medium{color:var(--amber);font-weight:700}.risk-low{color:var(--green);font-weight:700}table{width:100%;border-collapse:separate;border-spacing:0;font-size:14px}th,td{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}th{background:#f8fbff;color:#334155;font-weight:700;position:sticky;top:0}tr:last-child td{border-bottom:none}.code-box{background:#0f172a;color:#e2e8f0;padding:12px 14px;border-radius:12px;white-space:pre-wrap;word-break:break-word;font-family:Consolas,Menlo,monospace;font-size:12px;line-height:1.55}.hint{color:var(--muted);font-size:12px;line-height:1.5}details{border:1px solid var(--line);border-radius:12px;padding:10px 12px;background:#fbfcff;margin:10px 0}details summary{cursor:pointer;color:var(--blue);font-weight:600}.mini-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:12px;margin-top:12px}.mini-card{border:1px solid var(--line);border-radius:14px;padding:12px;background:#fbfcff}.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:14px}.muted{color:var(--muted)}@media (max-width:1024px){.hero-grid,.mini-grid,.grid-two{grid-template-columns:1fr 1fr}}@media (max-width:720px){main{padding:18px 14px 40px}.hero-grid,.mini-grid,.grid-two{grid-template-columns:1fr}.section-head{display:block}.section-head .hint{max-width:none}}</style></head><body><main>")
		b.WriteString(renderReportSupplementalStyles())
	}
	b.WriteString("<h1>技能安全审查报告</h1>")
	b.WriteString("<section class=\"hero\"><p class=\"pill\">" + html.EscapeString(reportGeneratorNote) + "</p><p>系统只提供声明、行为、意图、权限和证据链分析，不替用户最终判断是否可以使用。</p>")
	b.WriteString("<p class=\"hint\" style=\"color:rgba(255,255,255,.84);margin:8px 0 0\">评分与分值字段仅作辅助参考，优先以证据链、风险条目和复核结论作出处置判断。</p>")
	b.WriteString("<p class=\"hint\" style=\"color:rgba(255,255,255,.84);margin:8px 0 0\">生成时间: " + html.EscapeString(time.Now().Format("2006-01-02 15:04:05")) + "</p>")
	if strings.TrimSpace(declaredDescription) != "" {
		b.WriteString("<p class=\"hint\" style=\"color:rgba(255,255,255,.84);margin:8px 0 0\"><strong>提交声明:</strong> " + html.EscapeString(declaredDescription) + "</p>")
	}
	b.WriteString("<div class=\"hero-grid\">")
	b.WriteString("<div class=\"hero-stat\"><strong>文件</strong><span>" + html.EscapeString(fileName) + "</span></div>")
	b.WriteString("<div class=\"hero-stat\"><strong>处置建议</strong><span>" + html.EscapeString(localizeAdmission(refined.Summary.Admission)) + "</span><p class=\"hint\" style=\"color:rgba(255,255,255,.78);margin:6px 0 0\">基于证据链给出的建议，不代替人工审批</p></div>")
	b.WriteString("<div class=\"hero-stat\"><strong>风险等级</strong><span>" + html.EscapeString(localizeRiskLevel(refined.Summary.RiskLevel)) + "</span></div>")
	b.WriteString(fmt.Sprintf("<div class=\"hero-stat\"><strong>风险汇总</strong><span>%d / %d / %d</span><p class=\"hint\" style=\"color:rgba(255,255,255,.78);margin:6px 0 0\">高风险 / 中风险 / 低风险</p></div>", refined.Summary.HighRisk, refined.Summary.MediumRisk, refined.Summary.LowRisk))
	b.WriteString("</div></section>")
	b.WriteString("<nav class=\"nav\"><a href=\"#verification-summary\">验证结论摘要</a><a href=\"#analysis-profile\">技能画像</a><a href=\"#structured-findings\">风险综合研判</a><a href=\"#mitre-summary\">MITRE 映射</a><a href=\"#appendix\">附录与完整性</a></nav>")

	b.WriteString(renderVerificationSummaryCard(refined))

	b.WriteString("<div id=\"analysis-profile\" class=\"card\"><div class=\"section-head\"><h2>技能分析画像</h2><span class=\"hint\">声明、依赖、权限与源码能力信号统一汇总。</span></div>")
	b.WriteString("<p><strong>分析模式:</strong> " + html.EscapeString(defaultIfEmpty(base.profile.AnalysisMode, "全链路分析")) + "</p>")
	b.WriteString(renderIntentList("声明来源", base.profile.DeclarationSources))
	b.WriteString(renderIntentList("纳入分析的源码/声明文件", base.profile.SourceFiles))
	b.WriteString(renderIntentList("依赖清单", base.profile.Dependencies))
	b.WriteString(renderIntentList("用户声明权限", base.profile.Permissions))
	b.WriteString(renderIntentList("语言/文件类型分布", base.profile.LanguageSummary))
	b.WriteString(renderIntentList("源码能力信号", base.profile.CapabilitySignals))
	b.WriteString(fmt.Sprintf("<p class=\"hint\">纳入分析文件 %d 个，声明来源 %d 个，依赖 %d 个。</p>", base.profile.SourceFileCount, base.profile.DeclarationCount, base.profile.DependencyCount))
	if len(refined.ObfuscationEvidence) > 0 {
		items := make([]string, 0, len(refined.ObfuscationEvidence))
		for _, ev := range refined.ObfuscationEvidence {
			parts := []string{ev.Path}
			if strings.TrimSpace(ev.Technique) != "" {
				parts = append(parts, "技术="+ev.Technique)
			}
			if strings.TrimSpace(ev.Confidence) != "" {
				parts = append(parts, "置信度="+ev.Confidence)
			}
			if strings.TrimSpace(ev.Summary) != "" {
				parts = append(parts, "摘要="+ev.Summary)
			}
			if len(ev.DataFlowSignals) > 0 {
				parts = append(parts, "数据流="+strings.Join(ev.DataFlowSignals, "、"))
			}
			items = append(items, strings.Join(parts, "；"))
		}
		b.WriteString(renderIntentList("混淆解析证据", items))
	}
	b.WriteString("</div>")

	_ = riskCalibration

	b.WriteString(renderStructuredFindingsSection(refined))
	b.WriteString(renderMITRESummarySection(refined.StructuredFindings))

	b.WriteString(renderAppendixSection(base, evalLogs))

	// “汇总修复建议”与综合研判重复，已移除并以每条风险内的一一对应建议为准。

	b.WriteString("</body></html>")
	return b.String()
}

func renderMITRESummarySection(findings []review.StructuredFinding) string {
	var b strings.Builder
	summary := buildMITRESummary(findings)
	b.WriteString("<div id=\"mitre-summary\" class=\"card\"><div class=\"section-head\"><h2>MITRE ATT&CK 映射</h2><span class=\"hint\">按风险项汇总战术/技术映射，用于安全复盘与处置协同。</span></div>")
	count, _ := summary["count"].(int)
	techniques, _ := summary["techniques"].([]string)
	if count == 0 || len(techniques) == 0 {
		b.WriteString("<p class=\"muted\">当前未形成可用的 MITRE 映射。</p></div>")
		return b.String()
	}
	b.WriteString("<p><strong>映射数量:</strong> " + strconv.Itoa(count) + "</p>")
	b.WriteString(renderHTMLLabeledList("技术条目", techniques, 0, "未映射"))
	if byFinding, ok := summary["findings"].([]map[string]interface{}); ok && len(byFinding) > 0 {
		b.WriteString("<div class=\"table-wrap\"><table><tr><th>风险项</th><th>规则</th><th>映射技术</th></tr>")
		for _, item := range byFinding {
			id, _ := item["id"].(string)
			title, _ := item["title"].(string)
			ruleID, _ := item["rule_id"].(string)
			rows := interfaceToStringSlice(item["techniques"])
			b.WriteString("<tr><td>" + html.EscapeString(defaultIfEmpty(id, "-")) + " / " + html.EscapeString(defaultIfEmpty(title, "-")) + "</td><td>" + html.EscapeString(defaultIfEmpty(ruleID, "-")) + "</td><td>" + html.EscapeString(strings.Join(rows, "；")) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	b.WriteString("</div>")
	return b.String()
}

func interfaceToStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	if items, ok := v.([]string); ok {
		return items
	}
	if generic, ok := v.([]interface{}); ok {
		out := make([]string, 0, len(generic))
		for _, item := range generic {
			s, ok := item.(string)
			if !ok {
				continue
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}

func renderPDFReport(htmlPath, docxPath, pdfPath string) (pdfRenderTrace, error) {
	htmlTrace, err := renderPDFFromHTML(htmlPath, pdfPath)
	if err == nil {
		htmlTrace.Engine = defaultIfEmpty(strings.TrimSpace(htmlTrace.Engine), "html")
		return htmlTrace, nil
	}

	docxTrace, fallbackErr := renderPDFFromDocx(docxPath, pdfPath)
	docxTrace.UsedFallback = true
	if fallbackErr == nil {
		docxTrace.Engine = defaultIfEmpty(strings.TrimSpace(docxTrace.Engine), "docx")
		docxTrace.Error = "html_failed: " + err.Error()
		return docxTrace, nil
	}
	t := pdfRenderTrace{
		Engine:       "none",
		UsedFallback: true,
		Error:        fmt.Sprintf("html=%v; docx=%v", err, fallbackErr),
	}
	return t, fmt.Errorf("HTML 转 PDF 失败后 DOCX 回退也失败: html=%v; docx=%v", err, fallbackErr)
}

func renderPDFFromHTML(htmlPath, pdfPath string) (pdfRenderTrace, error) {
	trace := pdfRenderTrace{Engine: "html"}
	effectiveHTMLPath, fontFile, cleanup, err := prepareHTMLForPDF(htmlPath)
	trace.FontFile = fontFile
	if err != nil {
		trace.Error = err.Error()
		return trace, err
	}
	defer cleanup()
	htmlAbs, err := filepath.Abs(effectiveHTMLPath)
	if err != nil {
		trace.Error = err.Error()
		return trace, err
	}
	pdfAbs, err := filepath.Abs(pdfPath)
	if err != nil {
		trace.Error = err.Error()
		return trace, err
	}
	browsers := []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "microsoft-edge"}
	var bin string
	for _, candidate := range browsers {
		if _, err := exec.LookPath(candidate); err == nil {
			bin = candidate
			break
		}
	}
	if bin == "" {
		err := errors.New("未找到可用于 HTML 转 PDF 的浏览器引擎")
		trace.Error = err.Error()
		return trace, err
	}
	trace.Engine = "html:" + bin
	htmlURL := (&url.URL{Scheme: "file", Path: htmlAbs}).String()
	cmd := exec.Command(bin,
		"--headless",
		"--disable-gpu",
		"--allow-file-access-from-files",
		"--no-pdf-header-footer",
		"--run-all-compositor-stages-before-draw",
		"--print-to-pdf="+pdfAbs,
		htmlURL,
	)
	cmd.Env = append(os.Environ(), "LANG=zh_CN.UTF-8", "LC_ALL=zh_CN.UTF-8")
	output, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%s HTML 转 PDF 失败: %v, output: %s", bin, err, strings.TrimSpace(string(output)))
		trace.Error = err.Error()
		return trace, err
	}
	if _, statErr := os.Stat(pdfAbs); statErr != nil {
		err = fmt.Errorf("HTML 转 PDF 后未找到产物: %s", pdfAbs)
		trace.Error = err.Error()
		return trace, err
	}
	return trace, nil
}

func prepareHTMLForPDF(htmlPath string) (string, string, func(), error) {
	fontFile := resolvePDFCJKFontFile()
	if fontFile == "" {
		return htmlPath, "", func() {}, nil
	}
	fontAbs, err := filepath.Abs(fontFile)
	if err != nil {
		return "", "", nil, fmt.Errorf("解析 REVIEW_REPORT_CJK_FONT_FILE 失败: %w", err)
	}
	fontData, err := os.ReadFile(fontAbs)
	if err != nil {
		return "", "", nil, fmt.Errorf("读取中文字体文件失败: %w", err)
	}
	mimeType, formatHint := fontMimeAndFormat(fontAbs)
	if mimeType == "" || formatHint == "" {
		return "", "", nil, fmt.Errorf("不支持的字体格式: %s", fontAbs)
	}
	htmlData, err := os.ReadFile(htmlPath)
	if err != nil {
		return "", "", nil, err
	}
	encodedFont := base64.StdEncoding.EncodeToString(fontData)
	embeddedCSS := renderEmbeddedPDFFontCSS(mimeType, formatHint, encodedFont)
	html := string(htmlData)
	if strings.Contains(strings.ToLower(html), "</head>") {
		html = strings.Replace(html, "</head>", embeddedCSS+"</head>", 1)
	} else {
		html = embeddedCSS + html
	}
	tmpFile, err := os.CreateTemp("", "skill-scanner-pdf-*.html")
	if err != nil {
		return "", "", nil, err
	}
	if _, err := tmpFile.WriteString(html); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", "", nil, err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", "", nil, err
	}
	cleanup := func() {
		_ = os.Remove(tmpFile.Name())
	}
	return tmpFile.Name(), fontAbs, cleanup, nil
}

func fontMimeAndFormat(fontPath string) (string, string) {
	switch strings.ToLower(filepath.Ext(fontPath)) {
	case ".ttf":
		return "font/ttf", "truetype"
	case ".otf":
		return "font/otf", "opentype"
	case ".woff":
		return "font/woff", "woff"
	case ".woff2":
		return "font/woff2", "woff2"
	default:
		return "", ""
	}
}

func resolvePDFCJKFontFile() string {
	for _, candidate := range expandFontCandidates(config.PDFCJKFontCandidates()) {
		mimeType, formatHint := fontMimeAndFormat(candidate)
		if mimeType == "" || formatHint == "" {
			continue
		}
		return candidate
	}
	return ""
}

func resolvePDFCJKFontDir() string {
	for _, candidate := range expandFontCandidates(config.PDFCJKFontCandidates()) {
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Dir(candidate)
		}
	}
	return ""
}

func expandFontCandidates(items []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(items)*3)
	appendIfExists := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		if _, err := os.Stat(p); err != nil {
			return
		}
		seen[p] = struct{}{}
		result = append(result, p)
	}
	wd, _ := os.Getwd()
	exeDir := ""
	if exePath, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exePath)
	}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if filepath.IsAbs(item) {
			appendIfExists(item)
			continue
		}
		appendIfExists(item)
		if wd != "" {
			appendIfExists(filepath.Join(wd, item))
		}
		if exeDir != "" {
			appendIfExists(filepath.Join(exeDir, item))
		}
	}
	return result
}

func renderPDFFromDocx(docxPath, pdfPath string) (pdfRenderTrace, error) {
	trace := pdfRenderTrace{Engine: "docx"}
	docxAbs, err := filepath.Abs(docxPath)
	if err != nil {
		trace.Error = err.Error()
		return trace, err
	}
	pdfAbs, err := filepath.Abs(pdfPath)
	if err != nil {
		trace.Error = err.Error()
		return trace, err
	}
	outDir := filepath.Dir(pdfAbs)

	bin := ""
	if _, err := exec.LookPath("soffice"); err == nil {
		bin = "soffice"
	} else if _, err := exec.LookPath("libreoffice"); err == nil {
		bin = "libreoffice"
	} else {
		err := errors.New("未找到 soffice/libreoffice")
		trace.Error = err.Error()
		return trace, err
	}
	trace.Engine = "docx:" + bin

	cmd := exec.Command(bin, "--headless", "--convert-to", "pdf", "--outdir", outDir, docxAbs)
	env := append(os.Environ(), "LANG=zh_CN.UTF-8", "LC_ALL=zh_CN.UTF-8")
	if fontDir := strings.TrimSpace(resolvePDFCJKFontDir()); fontDir != "" {
		trace.FontDir = fontDir
		env = append(env,
			"SAL_FONTPATH="+fontDir,
			"GDFONTPATH="+fontDir,
		)
	}
	trace.FontFile = resolvePDFCJKFontFile()
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%s 转换失败: %v, output: %s", bin, err, strings.TrimSpace(string(output)))
		trace.Error = err.Error()
		return trace, err
	}

	generated := strings.TrimSuffix(docxAbs, filepath.Ext(docxAbs)) + ".pdf"
	if _, statErr := os.Stat(generated); statErr != nil {
		err = fmt.Errorf("未找到转换产物: %s", generated)
		trace.Error = err.Error()
		return trace, err
	}
	if generated != pdfAbs {
		data, readErr := os.ReadFile(generated)
		if readErr != nil {
			trace.Error = readErr.Error()
			return trace, readErr
		}
		if writeErr := os.WriteFile(pdfAbs, data, 0600); writeErr != nil {
			trace.Error = writeErr.Error()
			return trace, writeErr
		}
	}
	return trace, nil
}

func describeTargetIntent(target string, behavior review.BehaviorProfile) string {
	hasDownloadCmd := false
	for _, execTarget := range behavior.ExecTargets {
		l := strings.ToLower(execTarget)
		if strings.Contains(l, "curl") || strings.Contains(l, "wget") || strings.Contains(l, "invoke-webrequest") {
			hasDownloadCmd = true
			break
		}
	}

	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || strings.TrimSpace(u.Host) == "" {
		if hasDownloadCmd {
			return "检测到下载命令，请关联该目标审计下载后执行链路。"
		}
		return "未识别为标准 URL，建议结合代码上下文复核。"
	}

	host := strings.ToLower(strings.TrimSpace(u.Host))
	p := strings.ToLower(u.Path)

	if host == "github.com" {
		if strings.Contains(p, "/releases/download/") || strings.HasSuffix(p, ".zip") || strings.HasSuffix(p, ".tar.gz") || strings.HasSuffix(p, ".tgz") {
			if hasDownloadCmd {
				return "命中 GitHub 下载型链接，且存在下载命令，需重点审计下载文件的落地与执行行为。"
			}
			return "命中 GitHub 下载型链接，当前未直接观察到下载命令，请继续核查是否有间接下载。"
		}
		return "更偏向代码仓库展示链接，平台可信不等于仓库内容可信。"
	}

	if host == "raw.githubusercontent.com" {
		if hasDownloadCmd {
			return "命中 Raw 直链并存在下载命令，建议审计文件完整性校验与后续执行路径。"
		}
		return "命中 Raw 直链，可能用于直接下发脚本或配置，建议审计后续使用方式。"
	}

	if hasDownloadCmd {
		return "检测到下载命令，需审计该目标对应文件的下载、落地和执行流程。"
	}
	return "未发现显式下载行为，可结合业务语义继续确认访问必要性。"
}

func renderEvidenceSection(title string, items []string) string {
	if len(items) == 0 {
		return "<p><strong>" + html.EscapeString(title) + ":</strong> 未检出。</p>"
	}
	var b strings.Builder
	b.WriteString("<p><strong>" + html.EscapeString(title) + ":</strong></p><ul>")
	for i := 0; i < len(items); i++ {
		b.WriteString("<li>" + html.EscapeString(items[i]) + "</li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func renderFindingDigestIntegratedCard(findings []plugins.Finding, refined review.Result) string {
	orderedFindings := sortFindingsByReview(findings, refined)
	return reviewreport.RenderFindingDigestIntegratedCard(findings, orderedFindings, reviewreport.FindingDigestRenderOptions{
		FinalReviewSummary: func(f plugins.Finding) string {
			return finalReviewSummaryForFinding(f, refined)
		},
	})
}

func normalizeEvidenceBody(text string) string {
	text = strings.ReplaceAll(text, "；", "；\n")
	text = strings.ReplaceAll(text, ";", ";\n")
	for strings.Contains(text, "\n\n") {
		text = strings.ReplaceAll(text, "\n\n", "\n")
	}
	return text
}

func renderSourceBadgeStrip(items []string) string {
	return reviewreport.RenderSourceBadgeStrip(items)
}

func structuredFindingSourceLabels(finding review.StructuredFinding, finalReview string, reviewDepth int) []string {
	return reviewreport.StructuredFindingSourceLabels(finding, finalReview, reviewDepth)
}

func capabilitySourceLabels(item review.CapabilityConsistency, finalReview string, reviewDepth int) []string {
	return reviewreport.CapabilitySourceLabels(item, finalReview, reviewDepth)
}

func reviewVerdictCountByFinding(items []review.ReviewAgentVerdict) map[string]int {
	return reviewreport.ReviewVerdictCountByFinding(items)
}

func sourcePillClass(item string) string {
	return reviewreport.SourcePillClass(item)
}

func splitCodeEvidenceLabelAndBody(item string) (string, string) {
	return reviewreport.SplitCodeEvidenceLabelAndBody(item)
}

func inferEvidenceLabel(item string) string {
	return reviewreport.InferEvidenceLabel(item)
}

func looksLikeSourceLocator(line string) bool {
	return reviewreport.LooksLikeSourceLocator(line)
}

func shortenEvidenceLabel(line string) string {
	return reviewreport.ShortenEvidenceLabel(line)
}

func severityClassSuffix(severity string) string {
	return reviewreport.SeverityClassSuffix(severity)
}

func ruleExplanationByID(items []review.RuleExplanation) map[string]review.RuleExplanation {
	return reviewreport.RuleExplanationByID(items)
}

func falsePositiveReviewByID(items []review.FalsePositiveReview) map[string]review.FalsePositiveReview {
	return reviewreport.FalsePositiveReviewByID(items)
}

func reviewVerdictsByFinding(items []review.ReviewAgentVerdict) map[string][]review.ReviewAgentVerdict {
	out := make(map[string][]review.ReviewAgentVerdict, len(items))
	for _, item := range items {
		out[item.FindingID] = append(out[item.FindingID], item)
	}
	return out
}

func structuredFindingTitleByID(items []review.StructuredFinding) map[string]string {
	out := make(map[string]string, len(items))
	for _, item := range items {
		out[item.ID] = item.Title
	}
	return out
}

func capabilityItemsForFinding(finding review.StructuredFinding, items []review.CapabilityConsistency) []review.CapabilityConsistency {
	return reviewreport.CapabilityItemsForFinding(finding, items)
}

func unmatchedCapabilityItems(items []review.CapabilityConsistency, findings []review.StructuredFinding) []review.CapabilityConsistency {
	out := make([]review.CapabilityConsistency, 0)
	for _, item := range items {
		matched := false
		for _, finding := range findings {
			if capabilityMatchesFinding(item.Capability, finding) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, item)
		}
	}
	return out
}

func capabilityEvidenceForFinding(finding review.StructuredFinding, matrix []review.CapabilityConsistency, inventory []review.EvidenceInventory, behavior review.BehaviorProfile) []string {
	return reviewreport.CapabilityEvidenceForFinding(finding, matrix, inventory, behavior)
}

func capabilityPrimaryEvidenceForFinding(finding review.StructuredFinding, item review.CapabilityConsistency, inventory []review.EvidenceInventory, behavior review.BehaviorProfile) string {
	return reviewreport.CapabilityPrimaryEvidenceForFinding(finding, item, inventory, behavior)
}

func unmatchedEvidenceInventory(items []review.EvidenceInventory, matrix []review.CapabilityConsistency) []review.EvidenceInventory {
	out := make([]review.EvidenceInventory, 0)
	for _, item := range items {
		matched := false
		for _, capability := range matrix {
			if inventoryMatchesCapability(capability.Capability, item.Category) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, item)
		}
	}
	return out
}

func inventoryMatchesCapability(capability, category string) bool {
	return reviewreport.InventoryMatchesCapability(capability, category)
}

func capabilityMatchesFinding(capability string, finding review.StructuredFinding) bool {
	return reviewreport.CapabilityMatchesFinding(capability, finding)
}

func uniqueNonEmptyStrings(items []string) []string {
	return reviewreport.UniqueNonEmptyStrings(items)
}

func yesNo(v bool) string {
	if v {
		return "是"
	}
	return "否"
}

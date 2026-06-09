package handler

import (
	"strings"
	"testing"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestBuildHTMLReportContainsSequenceSections(t *testing.T) {
	base := baseScanOutput{evaluatedRules: 10, totalRules: 10, coverageNote: "已完成当前规则集全量检测（仅覆盖系统已配置规则）"}
	base.cacheStats = incrementalCacheStats{Enabled: true, Candidate: 10, Hit: 6, Miss: 4, CacheFilePath: "/tmp/demo/.scan-cache.json"}
	base.profile = skillAnalysisProfile{
		DeclarationSources: []string{"SKILL.md"},
		SourceFiles:        []string{"SKILL.md", "scripts/run.py"},
		Dependencies:       []string{"requests==2.31.0"},
		Permissions:        []string{"network"},
		AnalysisMode:       "语义模型 + LLM 意图分析 + 沙箱行为分析 + 规则集全链路评估",
		SourceFileCount:    2,
		DeclarationCount:   1,
		DependencyCount:    1,
		LanguageSummary:    []string{"markdown:1", "python:1"},
		CapabilitySignals:  []string{"网络访问"},
	}
	base.trace = []analysisTraceEvent{{Stage: "semantic_evaluation", Status: "completed", Message: "规则集和语义模型检测完成"}}
	base.ruleProfile = ruleSetProfile{
		Version:         "7.0",
		Total:           2,
		ByLayer:         []string{"P0:1", "P1:1"},
		BySeverity:      []string{"高风险:1", "中风险:1"},
		ByDetectionType: []string{"function:1", "pattern:1"},
		BlockedRules:    []string{"V7-001 恶意代码与破坏性行为"},
		ReviewRules:     []string{"V7-015 工具响应投毒与间接提示注入"},
		Reason:          "规则画像原因",
		Benefit:         "规则画像好处",
	}
	refined := review.Result{
		Behavior: review.BehaviorProfile{
			SandboxSource:     "container-probe",
			SandboxVerdict:    "suspicious",
			SandboxScore:      6,
			SandboxDurationMs: 1234,
			SandboxFallback:   false,
			BehaviorTimelines: []string{"sample.go | 时序: 下载(L10,x1) -> 执行(L20,x1) -> 外联(L25,x1)"},
			SequenceAlerts:    []string{"命中下载后执行时序"},
		},
		TIReputations: []review.TIReputation{{
			Target:     "https://c2.example.test",
			Reputation: "suspicious",
			Confidence: 0.91,
			Source:     "misp",
			ThreatType: "ioc-match",
			Reason:     "命中测试情报",
		}},
		Summary:           review.ScoreSummary{Admission: "UserDecisionRequired", RiskLevel: "medium", MediumRisk: 1},
		Pipeline:          []review.PipelineStage{{Name: "sandbox_execute", Purpose: "采集行为", Status: "completed", Output: "完成", Benefit: "更清晰"}},
		EvidenceInventory: []review.EvidenceInventory{{Category: "行为时序", Count: 1, Meaning: "还原行为顺序", Examples: []string{"sample"}}},
		OptimizationNotes: []review.OptimizationNote{{Change: "阶段化 Pipeline", Reason: "原链路不透明", Benefit: "过程可解释"}},
		StructuredFindings: []review.StructuredFinding{{
			ID:                  "SF-001",
			RuleID:              "V7-001",
			Title:               "恶意代码与破坏性行为",
			Severity:            "高风险",
			Category:            "命令执行",
			Confidence:          "高",
			AttackPath:          "下载后执行",
			Evidence:            []string{"requests.post(url, data)"},
			CalibrationBasis:    []string{"存在高危时序告警"},
			FalsePositiveChecks: []string{"确认相关脚本不会进入发布包或动态加载链路"},
			ReviewGuidance:      "优先复核攻击路径",
			Source:              "BehaviorGuard",
			DeduplicatedCount:   2,
		}},
		VulnerabilityBlocks: []review.VulnerabilityBlock{{ID: "SF-001", Format: "structured-vuln-block", Content: "<vuln>\n  <title>恶意代码与破坏性行为</title>\n</vuln>"}},
		RuleExplanations: []review.RuleExplanation{{
			RuleID:                   "V7-001",
			Name:                     "恶意代码与破坏性行为",
			Severity:                 "高风险",
			DetectionType:            "function",
			Action:                   "block",
			Triggered:                true,
			DetectionCriteria:        []string{"检测方式: function"},
			ExclusionConditions:      []string{"仅在确认相关脚本不会进入发布包或动态加载链路时，才可降为观察项。"},
			VerificationRequirements: []string{"确认入口可达并存在真实执行链路"},
			OutputRequirements:       []string{"输出具体文件路径"},
			PromptTemplateSummary:    "必须先检查排除条件",
			RemediationFocus:         "限制下载落地与后续执行",
		}},
		FalsePositiveReviews: []review.FalsePositiveReview{{
			FindingID:          "SF-001",
			Verdict:            "倾向真实风险: 建议优先修复并复扫。",
			Exploitability:     "较高: 存在行为链或高危时序证据。",
			Impact:             "可能导致任意命令执行。",
			EvidenceStrength:   "强: 多源证据可互相印证。",
			ReachabilityChecks: []string{"确认风险代码所在文件是否属于技能发布包和主执行路径。"},
			ExclusionChecks:    []string{"确认相关脚本不会进入发布包或动态加载链路"},
			RequiredFollowUp:   []string{"补充最小复现路径"},
		}},
		DetectionComparison: []review.DetectionChainComparison{{
			Area:             "深度审计与多 Agent 推理",
			CurrentStatus:    "当前链路以规则、语义、LLM 意图、沙箱和威胁情报聚合为主。",
			BaselineApproach: "参考基线通常会把深度审计任务拆成多阶段任务包，并用独立复核提示提升覆盖。",
			Winner:           "参考基线领先",
			Gap:              "缺少独立复核 Agent。",
			Optimization:     "增加二次 LLM 复核阶段。",
			Evidence:         []string{"structured findings:1"},
		}},
		ReviewAgentTasks: []review.ReviewAgentTask{{
			FindingID:        "SF-001",
			AgentRole:        "vuln-reviewer",
			Objective:        "以零误报标准复核结构化风险。",
			Inputs:           []string{"structured_finding:SF-001"},
			StrictStandards:  []string{"没有具体证据时不得确认真实风险。"},
			Prompt:           "你是严格的漏洞复核 Agent。",
			ExpectedOutputs:  []string{"verdict"},
			BlockingCriteria: []string{"确认存在高危命令执行。"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:        "SF-001",
			Verdict:          "confirmed",
			Confidence:       "高",
			Reason:           "证据闭环",
			Fix:              "优先复核攻击路径",
			Reviewer:         "deterministic-vuln-reviewer",
			StandardsApplied: []string{"入口可达性"},
		}, {
			FindingID:        "SF-001",
			Verdict:          "confirmed",
			Confidence:       "高",
			Reason:           "LLM 二次复核同样确认存在真实风险",
			Fix:              "按复核结论收敛高危路径",
			Reviewer:         "llm-vuln-reviewer",
			StandardsApplied: []string{"多源证据交叉验证"},
		}},
		CapabilityMatrix: []review.CapabilityConsistency{{
			Capability:      "外联/网络访问",
			Declared:        true,
			StaticDetected:  true,
			LLMDetected:     true,
			SandboxDetected: false,
			Status:          "已声明但沙箱未验证",
			RiskImpact:      "可能产生数据外发",
			Gap:             "沙箱未检出对应行为",
			NextStep:        "核验目标白名单",
			Evidence:        []string{"规则证据: V7-003"},
		}},
		AuditEvents: []review.AuditEvent{{Type: "statusUpdate", StepID: "pipeline-01", Status: "completed", Brief: "沙箱执行完成", ToolName: "sandbox", Timestamp: "2026-04-29T00:00:00Z"}},
	}

	base.intentSummary = intentReportSummary{
		Available:      true,
		DeclaredIntent: "LLM 判断该技能用于生成代码安全审查摘要。",
		ActualBehavior: "LLM 判断该技能读取代码并输出风险说明。",
	}
	rawDeclaration := "这是技能声明原文，不应在一致性章节直接展示"
	findings := []plugins.Finding{{RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Description: "检测到外联", Location: "scripts/run.py:12", CodeSnippet: "requests.post(url, data)"}}
	html := buildHTMLReport("demo.zip", rawDeclaration, findings, base, refined, nil)

	checks := []string{
		"技能分析画像", "评分与分值字段仅作辅助参考", "处置建议", "不代替人工审批", "验证结论摘要", "仍需人工验证", "已完成验证",
		"提交声明", rawDeclaration, "生成时间", "风险与能力综合研判", "href=\"#behavior-combination\"", "单技能行为组合分析", "TL;DR:",
		"判定门槛:", "来源: 审计/沙箱/LLM", "结论与建议", "情报与配置信号", "误报检查", "校准依据", "下载后执行", "输出要求",
		"<pre class=\"code-box\">requests.post(url, data)</pre>", "href=\"#appendix\"", "附录与完整性", "评估完整性证明", "评估项检测记录（全量）", "规则评估覆盖统计",
		"增量缓存", "缓存命中率", "排除条件", "可达性检查", "倾向真实风险", "对应修复建议", "语言/文件类型分布", "源码能力信号",
	}
	for _, want := range checks {
		if !strings.Contains(html, want) {
			t.Fatalf("expected html report contains %q", want)
		}
	}
	if !(strings.Contains(html, "链路已验证") || strings.Contains(html, "链路待验证") || strings.Contains(html, "未发现可验证联动链路")) {
		t.Fatal("expected tldr contains verification state")
	}
	if !((strings.Contains(html, "验证状态") && strings.Contains(html, "风险定位") && strings.Contains(html, "关键代码")) || strings.Contains(html, "当前未推断出高置信度行为组合链路")) {
		t.Fatal("expected behavior-combination section contains verification columns or empty-state")
	}
	if !(strings.Contains(html, "链路标题") || strings.Contains(html, "当前未推断出高置信度行为组合链路")) {
		t.Fatal("expected behavior-combination section contains chain table or empty-state message")
	}

	hiddenChecks := []string{
		"阻断规则", "请查看 JSON 报告", "能力与证据总览", "补充证据（同风险）", "相关能力与证据", "规则体系画像", "结构化分析追踪", "结构化审计事件流",
		"阶段化分析 Pipeline", "优化说明（原因与收益）", "链路观察与后续优化", "检测链路对比与优化项", "下一步:", "可复核漏洞块", "SF-001 / structured-vuln-block",
		"规则解释卡", "零误报复核清单", "<h2>风险发现</h2>", "<h2>声明与行为一致性</h2>", "<h2>IoC 与情报信誉</h2>", "<h2>行为证据采集",
		"<h2>反逃逸与差分执行分析</h2>", "AI-Infra-Guard", "Based on Tencent", "二次复核任务与裁决（已并入综合研判）", "汇总修复建议",
	}
	for _, hidden := range hiddenChecks {
		if strings.Contains(html, hidden) {
			t.Fatalf("expected html report hides %q", hidden)
		}
	}
}

func TestBuildHTMLReportUsesNormalizedRiskLevelAndDecisionInHero(t *testing.T) {
	refined := review.Result{
		Summary: review.ScoreSummary{Admission: "pass", RiskLevel: "low", HighRisk: 4, MediumRisk: 0, LowRisk: 0},
		StructuredFindings: []review.StructuredFinding{
			{ID: "SF-001", RuleID: "V7-005", Title: "许可证本地默认服务需复核", Severity: "高风险", Category: "授权与许可证校验", Confidence: "中", Evidence: []string{"scripts/polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")"}},
			{ID: "SF-002", RuleID: "V7-021", Title: "仪表板未鉴权暴露", Severity: "高风险", Category: "暴露面与未鉴权服务", Confidence: "高", Evidence: []string{"scripts/dashboard.py:88 app.run(host=\"127.0.0.1\", port=8080)"}},
			{ID: "SF-003", RuleID: "V7-004", Title: "私钥明文存储风险", Severity: "高风险", Category: "凭据暴露", Confidence: "高", Evidence: []string{"scripts/polymarket.py:188 requests.post(webhook, json={'private_key': wallet_private_key})"}},
			{ID: "SF-004", RuleID: "V7-022", Title: "Python 系统包安装风险", Severity: "高风险", Category: "环境与构建风险", Confidence: "中", Evidence: []string{"scripts/bootstrap.sh:12 pip3 install -r requirements.txt --break-system-packages"}},
		},
	}
	htmlReport := buildHTMLReport("polymarket-sniper-bot-standalone-1.0.1.zip", "", nil, baseScanOutput{}, refined, nil)
	for _, want := range []string{"<strong>处置建议</strong><span>待用户基于证据判断（优先补 source/sink）</span>", "<strong>风险等级</strong><span>高风险</span>", "<strong>风险汇总</strong><span>1 / 0 / 3</span>"} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected hero contains %q, got %s", want, htmlReport)
		}
	}
	for _, want := range []string{"闭环摘要:", "待复核项主要缺少"} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected hero closure narrative contains %q, got %s", want, htmlReport)
		}
	}
}

func TestBuildHTMLReportPolymarketMixedScenarioIncludesSecondaryContextAndReviewSignals(t *testing.T) {
	refined := review.Result{
		Summary: review.ScoreSummary{Admission: "pass", RiskLevel: "low", HighRisk: 5, MediumRisk: 0, LowRisk: 0},
		StructuredFindings: []review.StructuredFinding{
			{
				ID:                "SF-001",
				RuleID:            "V7-005",
				Title:             "许可证本地默认服务需复核",
				Severity:          "高风险",
				Category:          "授权与许可证校验",
				Confidence:        "中",
				Evidence:          []string{"scripts/polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")"},
				CalibrationBasis:  []string{"本地 fallback 仅用于开发态，生成期已降为低风险。"},
				SecurityVerdict:   "review",
				Source:            "static-rule",
				DeduplicatedCount: 1,
			},
			{
				ID:                "SF-002",
				RuleID:            "V7-021",
				Title:             "仪表板未鉴权暴露",
				Severity:          "高风险",
				Category:          "暴露面与未鉴权服务",
				Confidence:        "中",
				Evidence:          []string{"scripts/dashboard.py:88 app.run(host=\"127.0.0.1\", port=8080)"},
				CalibrationBasis:  []string{"本地 loopback dashboard，生成期已降为低风险。"},
				SecurityVerdict:   "review",
				Source:            "static-rule",
				DeduplicatedCount: 1,
			},
			{
				ID:                "SF-003",
				RuleID:            "V7-004",
				Title:             "私钥明文存储风险",
				Severity:          "高风险",
				Category:          "凭据暴露",
				Confidence:        "高",
				Evidence:          []string{"scripts/polymarket.py:188 requests.post(webhook, json={'private_key': wallet_private_key})"},
				CalibrationBasis:  []string{"凭据进入真实外联执行链。"},
				SecurityVerdict:   "confirmed",
				Source:            "static-rule",
				DeduplicatedCount: 1,
			},
			{
				ID:                "SF-004",
				RuleID:            "V7-022",
				Title:             "Python 系统包安装风险",
				Severity:          "高风险",
				Category:          "环境与构建风险",
				Confidence:        "中",
				Evidence:          []string{"scripts/bootstrap.sh:12 pip3 install -r requirements.txt --break-system-packages"},
				CalibrationBasis:  []string{"宿主环境安装系统包，保留中风险。"},
				SecurityVerdict:   "review",
				Source:            "static-rule",
				DeduplicatedCount: 1,
			},
			{
				ID:                "SF-005",
				RuleID:            "V7-003",
				Title:             "敏感数据外发与隐蔽通道",
				Severity:          "高风险",
				Category:          "外联与情报",
				Confidence:        "待复核",
				Evidence:          []string{"examples/demo_agent.py:12 requests.post(webhook, json={'content': msg})"},
				CalibrationBasis:  []string{"当前证据主要位于文档、示例、测试或开发态上下文，优先按低优先级线索处理并保留人工复核。"},
				FalsePositiveChecks: []string{"确认该示例文件不会进入发布包或被动态加载。"},
				SecurityVerdict:   "review",
				Source:            "llm-review",
				DeduplicatedCount: 1,
			},
		},
		FalsePositiveReviews: []review.FalsePositiveReview{{
			FindingID:          "SF-005",
			Verdict:            "待人工复核: 当前证据仍需确认是否进入真实发布链路。",
			EvidenceStrength:   "弱: 证据主要来自示例目录。",
			ReachabilityChecks: []string{"当前证据主要位于文档、示例或测试上下文，需优先确认该文件是否会进入发布包、运行镜像或动态加载链路。"},
			ExclusionChecks:    []string{"确认该示例文件不会进入发布包或被动态加载。"},
			RequiredFollowUp:   []string{"补充发布物清单或构建产物证明，确认文档、示例或测试内容不会进入真实运行链路。"},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-003", Verdict: "confirmed", Confidence: "高", Reviewer: "deterministic-vuln-reviewer"}, {FindingID: "SF-005", Verdict: "needs_manual_review", Confidence: "中", Reviewer: "deterministic-vuln-reviewer"}},
	}

	htmlReport := buildHTMLReport("polymarket-sniper-bot-standalone-1.0.1.zip", "", nil, baseScanOutput{}, refined, nil)
	for _, want := range []string{
		"<strong>风险汇总</strong><span>1 / 0 / 4</span>",
		"闭环解释:",
		"展开低优先级文档与交付提示（1 条）",
		"安全结论: 需人工复核",
		"当前证据主要位于文档、示例、测试或开发态上下文，优先按低优先级线索处理并保留人工复核。",
		"待人工复核: 当前证据仍需确认是否进入真实发布链路。",
	} {
		if !strings.Contains(htmlReport, want) {
			t.Fatalf("expected polymarket mixed html contains %q, got %s", want, htmlReport)
		}
	}
	if !strings.Contains(htmlReport, "SF-005 / 敏感数据外发与隐蔽通道") {
		t.Fatalf("expected secondary documentation finding rendered, got %s", htmlReport)
	}
}

func TestBuildVulnerabilityBlocksEscapesStructuredFindings(t *testing.T) {
	blocks := buildVulnerabilityBlocks([]review.StructuredFinding{{
		ID:                  "SF-001",
		RuleID:              "V7-003",
		Title:               "外联 <script>",
		Severity:            "高风险",
		Category:            "外联与情报",
		Confidence:          "高",
		AttackPath:          "向 https://example.com?a=1&b=2 外发",
		Evidence:            []string{"requests.post(url, data)"},
		ChainSummaries:      []string{"行为链: scripts/run.py:10-12 | 外联=1, 凭据访问=1", "时序告警: 命中凭据访问后外联时序"},
		CalibrationBasis:    []string{"存在外联证据"},
		FalsePositiveChecks: []string{"确认该内容不会进入发布包、运行镜像或动态加载链路"},
		ReviewGuidance:      "收敛到白名单",
		Source:              "Static",
	}})

	if len(blocks) != 1 {
		t.Fatalf("expected one vulnerability block, got %+v", blocks)
	}
	content := blocks[0].Content
	for _, want := range []string{"<vuln>", "<risk_type>外联与情报</risk_type>", "<chain_summaries>行为链: scripts/run.py:10-12 | 外联=1, 凭据访问=1；时序告警: 命中凭据访问后外联时序</chain_summaries>", "&lt;script&gt;", "&amp;b=2", "<fix>收敛到白名单</fix>"} {
		if !strings.Contains(content, want) {
			t.Fatalf("expected block contains %q, got %s", want, content)
		}
	}
}

func TestBuildHTMLReportIncludesSupplyChainSummaryForOSVFindings(t *testing.T) {
	refined := review.Result{
		Summary: review.ScoreSummary{Admission: "UserDecisionRequired", RiskLevel: "high", HighRisk: 1},
		StructuredFindings: []review.StructuredFinding{{
			ID:                "SF-OSV-001",
			RuleID:            "V7-010-OSV",
			Title:             "依赖漏洞与供应链风险",
			Severity:          "高风险",
			Category:          "环境与构建风险",
			Confidence:        "高",
			AttackPath:        "已知漏洞依赖进入发布链路",
			Evidence:          []string{"OSV 证据: dependency=requests version=2.19.0 vuln=GHSA-test-1234"},
			CalibrationBasis:  []string{"OSV 命中高危依赖漏洞"},
			ReviewGuidance:    "升级依赖版本并复扫",
			Source:            "SecurityEngine",
			DeduplicatedCount: 1,
		}},
	}
	html := buildHTMLReport("demo.zip", "", nil, baseScanOutput{}, refined, nil)
	for _, want := range []string{"依赖漏洞与供应链摘要", "命中项数:", "requests", "GHSA-test-1234", "OSV 证据:"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected html report contains %q, got %s", want, html)
		}
	}
}

func TestBuildHTMLReportIncludesSandboxRetrySummary(t *testing.T) {
	refined := review.Result{
		Behavior: review.BehaviorProfile{
			ProbeWarnings: []string{"检测到下载与执行信号但未形成时序告警"},
			Differentials: []review.DifferentialProbe{{Scenario: "vm-profile", Triggered: true, Summary: "VM 场景下出现额外执行信号"}},
		},
		Pipeline: []review.PipelineStage{{
			Name:   "sandbox_retry",
			Status: "completed",
			Input:  "检测到下载与执行信号但未形成时序告警",
			Output: "自动复测完成，新增 IoC 2 个，探针告警 1 条",
		}},
	}
	html := buildHTMLReport("demo.zip", "", nil, baseScanOutput{}, refined, nil)
	for _, want := range []string{"沙箱自动复测摘要", "复测状态:", "已完成", "自动复测完成，新增 IoC 2 个", "检测到下载与执行信号但未形成时序告警", "VM 场景下出现额外执行信号"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected html report contains %q, got %s", want, html)
		}
	}
}

func TestBuildHTMLReportIncludesTraceMetadataSummary(t *testing.T) {
	base := baseScanOutput{
		taskID:    "task-trace-001",
		requestID: "rid-trace-001",
		trace: []analysisTraceEvent{
			{Stage: "queued", Status: "completed", Message: "扫描任务已入队并完成技能声明解析"},
			{Stage: "behavior_review", Status: "completed", Message: "沙箱行为、差分执行和威胁情报复核完成"},
		},
	}
	html := buildHTMLReport("demo.zip", "", nil, base, review.Result{}, nil)
	for _, want := range []string{"追踪元信息摘要", "任务 ID:", "task-trace-001", "请求 ID:", "rid-trace-001", "queued / 已完成 / 扫描任务已入队并完成技能声明解析", "behavior_review / 已完成 / 沙箱行为、差分执行和威胁情报复核完成"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected html report contains %q, got %s", want, html)
		}
	}
}

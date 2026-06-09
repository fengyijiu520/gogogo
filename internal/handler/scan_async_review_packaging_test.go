package handler

import (
	"slices"
	"strings"
	"testing"

	"skill-scanner/internal/config"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestBuildFalsePositiveReviewsRequiresReachabilityEvidenceForFalsePositive(t *testing.T) {
	findings := []review.StructuredFinding{
		{ID: "SF-001", RuleID: "V7-009", Title: "命令执行", Severity: "高风险", Category: "命令执行", Confidence: "高", AttackPath: "下载后执行", Evidence: []string{"scripts/run.py:10"}, CalibrationBasis: []string{"存在高危时序告警"}, FalsePositiveChecks: []string{"确认相关脚本不会进入发布包或动态加载链路"}, DeduplicatedCount: 2},
		{ID: "SF-002", RuleID: "V7-003", Title: "外联示例", Severity: "中风险", Category: "外联与情报", Confidence: "待复核", AttackPath: "example request", Evidence: []string{"examples/demo.py:5"}, FalsePositiveChecks: []string{"确认该示例文件不会进入发布包或被动态加载"}},
	}
	refined := review.Result{
		Behavior:         review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}},
		RuleExplanations: []review.RuleExplanation{{RuleID: "V7-003", ExclusionConditions: []string{"仅在确认不会传输敏感数据且不存在重定向或动态改写时，才按普通请求处理。"}}},
	}
	reviews := buildFalsePositiveReviews(findings, refined)

	if len(reviews) != 2 {
		t.Fatalf("expected two false-positive reviews, got %+v", reviews)
	}
	if !strings.Contains(reviews[0].Verdict, "倾向真实风险") || !strings.Contains(reviews[0].EvidenceStrength, "强") {
		t.Fatalf("expected real risk review for first finding, got %+v", reviews[0])
	}
	if !strings.Contains(reviews[1].Verdict, "疑似误报") || !strings.Contains(strings.Join(reviews[1].ExclusionChecks, "\n"), "普通请求") {
		t.Fatalf("expected second finding to downgrade with exclusion checks, got %+v", reviews[1])
	}
}

func TestBuildFalsePositiveReviewsDowngradesInternalDevelopmentTargets(t *testing.T) {
	findings := []review.StructuredFinding{{
		ID:       "SF-001",
		RuleID:   "V7-003",
		Title:    "本地开发外联",
		Severity: "中风险",
		Category: "外联与情报",
		Evidence: []string{"config/dev.yaml:8 callback=http://localhost:3000/api"},
	}}
	reviews := buildFalsePositiveReviews(findings, review.Result{})
	if len(reviews) != 1 {
		t.Fatalf("expected one review, got %+v", reviews)
	}
	if !strings.Contains(reviews[0].Verdict, "疑似误报") {
		t.Fatalf("expected localhost-only finding downgraded, got %+v", reviews[0])
	}
}

func TestBuildDetectionChainComparisonHighlightsRemainingGaps(t *testing.T) {
	base := baseScanOutput{trace: []analysisTraceEvent{{Stage: "preflight", Status: "completed"}}}
	refined := review.Result{
		StructuredFindings:   []review.StructuredFinding{{ID: "SF-001"}},
		FalsePositiveReviews: []review.FalsePositiveReview{{FindingID: "SF-001"}},
		RuleExplanations:     []review.RuleExplanation{{RuleID: "V7-001"}},
		CapabilityMatrix:     []review.CapabilityConsistency{{Capability: "命令执行"}},
		AuditEvents:          []review.AuditEvent{{Type: "statusUpdate"}},
		Behavior:             review.BehaviorProfile{ProbeWarnings: []string{"沙箱未触发"}},
	}
	items := buildDetectionChainComparison(base, refined)

	if len(items) < 5 {
		t.Fatalf("expected multiple comparison items, got %+v", items)
	}
	joined := ""
	for _, item := range items {
		joined += item.Area + " " + item.Winner + " " + item.Optimization + "\n"
	}
	for _, want := range []string{"参考基线领先", "当前链路更贴合 Skill 安全审查", "LLM reviewer", "rules_access.yaml schema 扩展"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected comparison contains %q, got %+v", want, items)
		}
	}
	notes := buildDetectionComparisonOptimizationNotes(items)
	if len(notes) == 0 || !strings.Contains(notes[0].Change, "检测链路差距") || notes[0].Reason == "" || notes[0].Benefit == "" {
		t.Fatalf("expected comparison gaps converted to optimization notes, got %+v", notes)
	}
}

func TestBuildRuleExplanationsAddsCriteriaAndTriggeredStatus(t *testing.T) {
	cfg := &config.Config{Version: "7.0", Rules: []config.Rule{{
		ID:       "V7-003",
		Name:     "敏感数据外发与隐蔽通道",
		Severity: "高风险",
		Detection: config.Detection{
			Type:     "function",
			Function: "detectDataExfiltration",
		},
		OnFail: config.OnFail{Action: "block", Reason: "检测到敏感数据外发或隐蔽通道"},
		Review: config.Review{
			PromptTemplate:           "只在存在真实外发路径时报告。",
			DetectionCriteria:        []string{"必须存在外联调用和敏感数据源"},
			ExclusionConditions:      []string{"排除 localhost 开发请求"},
			VerificationRequirements: []string{"确认请求目标和传输字段"},
			OutputRequirements:       []string{"输出完整攻击路径"},
			RemediationFocus:         "强制外联白名单",
		},
	}}}
	explanations := buildRuleExplanations(cfg)
	marked := markTriggeredRuleExplanations(explanations, []plugins.Finding{{RuleID: "V7-003"}})

	if len(marked) != 1 || !marked[0].Triggered {
		t.Fatalf("expected triggered rule explanation, got %+v", marked)
	}
	joined := strings.Join(append(append(marked[0].DetectionCriteria, marked[0].ExclusionConditions...), marked[0].VerificationRequirements...), "\n")
	for _, want := range []string{"必须存在外联调用", "detectDataExfiltration", "排除 localhost", "确认请求目标", "确认目标域名"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected rule explanation contains %q, got %+v", want, marked[0])
		}
	}
	if marked[0].PromptTemplateSummary != "只在存在真实外发路径时报告。" || marked[0].RemediationFocus != "强制外联白名单" {
		t.Fatalf("expected prompt summary and remediation focus, got %+v", marked[0])
	}
}

func TestBuildReviewAgentTasksPackagesVulnReviewPrompt(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:                   "SF-001",
			RuleID:               "V7-009",
			Title:                "命令执行",
			Severity:             "高风险",
			Category:             "命令执行",
			Confidence:           "高",
			AttackPath:           "下载后执行",
			Evidence:             []string{"scripts/run.py:10"},
			BehaviorEvidenceRefs: []string{"sandbox: http_probe status=200"},
			Closure:              review.FindingClosure{Source: true, Sink: true, RuntimeSupport: true},
			ChainSummaries:       []string{"时序告警: 命中下载后执行时序"},
			Chains:               []review.FindingChain{{Kind: "sequence_alert", Summary: "命中下载后执行时序"}, {Kind: "behavior_chain", Summary: "scripts/run.py:10-12 | 下载=1, 执行=1", Source: "scripts/run.py:10-12"}},
			FalsePositiveChecks:  []string{"确认相关脚本不会进入发布包或动态加载链路"},
		}},
		RuleExplanations:     []review.RuleExplanation{{RuleID: "V7-009", DetectionCriteria: []string{"命令拼接"}, ExclusionConditions: []string{"固定参数不报"}, VerificationRequirements: []string{"确认入口可达"}, OutputRequirements: []string{"输出 JSON"}}},
		FalsePositiveReviews: []review.FalsePositiveReview{{FindingID: "SF-001", Verdict: "倾向真实风险", EvidenceStrength: "强", ExclusionChecks: []string{"确认相关脚本不会进入发布包或动态加载链路"}}},
		VulnerabilityBlocks:  []review.VulnerabilityBlock{{ID: "SF-001", Content: "<vuln><title>命令执行</title></vuln>"}},
	}
	tasks := buildReviewAgentTasks(refined)

	if len(tasks) != 1 {
		t.Fatalf("expected one review agent task, got %+v", tasks)
	}
	task := tasks[0]
	if task.StageContext == nil {
		t.Fatal("expected structured stage context")
	}
	joined := task.AgentRole + task.Objective + task.Prompt + strings.Join(task.ExpectedOutputs, "\n") + strings.Join(task.Inputs, "\n")
	for _, want := range []string{"vuln-reviewer", "零误报", "<UNTRUSTED_STAGE_CONTEXT", "固定参数不报", "confirmed|likely_false_positive|needs_manual_review", "finding_chains:SF-001", "sequence_alert: 命中下载后执行时序", "behavior_chain: scripts/run.py:10-12 | 下载=1, 执行=1 [source=scripts/run.py:10-12]"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected review agent task contains %q, got %+v", want, task)
		}
	}
	if slices.Contains(task.Inputs, "vulnerability_block:SF-001") {
		t.Fatalf("expected minimal review inputs without vulnerability block handle, got %+v", task.Inputs)
	}
	if len(task.StageContext.Finding.EvidenceRefs) != 1 || task.StageContext.Finding.EvidenceRefs[0] != "scripts/run.py:10" {
		t.Fatalf("expected filtered evidence refs, got %+v", task.StageContext.Finding.EvidenceRefs)
	}
	if len(task.StageContext.Finding.CodeEvidenceRefs) != 1 || task.StageContext.Finding.CodeEvidenceRefs[0] != "scripts/run.py:10" {
		t.Fatalf("expected code evidence refs classified, got %+v", task.StageContext.Finding)
	}
	if len(task.StageContext.Finding.RuntimeObservations) == 0 || !strings.Contains(task.StageContext.Finding.RuntimeObservations[0], "http_probe") {
		t.Fatalf("expected runtime observations retained, got %+v", task.StageContext.Finding.RuntimeObservations)
	}
	if len(task.StageContext.Finding.ClosureEvidence) == 0 || !strings.Contains(strings.Join(task.StageContext.Finding.ClosureEvidence, "\n"), "behavior_chain") {
		t.Fatalf("expected closure evidence retained, got %+v", task.StageContext.Finding.ClosureEvidence)
	}
	if task.StageContext.InputBudget.RawEvidenceCount == 0 || task.StageContext.InputBudget.RetainedEvidenceCount == 0 || task.StageContext.InputBudget.MaxEvidenceRefs != 8 {
		t.Fatalf("expected input budget metadata, got %+v", task.StageContext.InputBudget)
	}
	if got := task.StageContext.Rule.DetectionCriteria; len(got) != 1 || got[0] != "命令拼接" {
		t.Fatalf("expected compact rule detection criteria, got %+v", got)
	}
	if got := task.StageContext.FalsePositive.ExclusionChecks; len(got) != 1 || got[0] != "确认相关脚本不会进入发布包或动态加载链路" {
		t.Fatalf("expected compact false-positive exclusion checks, got %+v", got)
	}
}

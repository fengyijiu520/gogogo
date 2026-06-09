package handler

import (
	"strings"
	"testing"

	combinationservice "skill-scanner/internal/combination"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestApplyBehaviorCombinationVerificationPolicyDowngradesWithoutSandboxProof(t *testing.T) {
	analysis := combinationservice.SingleSkillBehaviorAnalysis{
		Conclusion: combinationservice.Conclusion{
			RiskLevel:      "high",
			RiskLabel:      "高风险",
			Recommendation: "old",
		},
		InferredChains: []combinationservice.InferredChain{{Title: "潜在远程指令执行链", Level: "high"}},
	}
	got := applyBehaviorCombinationVerificationPolicy(analysis, review.Result{Behavior: review.BehaviorProfile{}})
	if got.Conclusion.RiskLevel != "medium" {
		t.Fatalf("expected risk level downgraded to medium, got %q", got.Conclusion.RiskLevel)
	}
	if !strings.Contains(got.Conclusion.Recommendation, "尚缺少确定性验证闭环") {
		t.Fatalf("expected downgraded recommendation mention deterministic verification gap, got %q", got.Conclusion.Recommendation)
	}
}

func TestApplyBehaviorCombinationVerificationPolicyDowngradesHighWhenNoInferredChains(t *testing.T) {
	analysis := combinationservice.SingleSkillBehaviorAnalysis{
		Conclusion: combinationservice.Conclusion{
			RiskLevel:      "high",
			RiskLabel:      "高风险",
			Recommendation: "old",
		},
		InferredChains: nil,
	}
	got := applyBehaviorCombinationVerificationPolicy(analysis, review.Result{Behavior: review.BehaviorProfile{}})
	if got.Conclusion.RiskLevel != "medium" {
		t.Fatalf("expected high risk downgraded to medium when no inferred chains, got %q", got.Conclusion.RiskLevel)
	}
	if !strings.Contains(got.Conclusion.Recommendation, "未推断出高置信度行为组合链路") {
		t.Fatalf("expected recommendation explain missing high-confidence chains, got %q", got.Conclusion.Recommendation)
	}
}

func TestApplyBehaviorCombinationVerificationPolicyPromotesHighWhenAuditSandboxLLMAllSupport(t *testing.T) {
	analysis := combinationservice.SingleSkillBehaviorAnalysis{
		Conclusion:     combinationservice.Conclusion{RiskLevel: "medium", RiskLabel: "中风险", Recommendation: "old"},
		InferredChains: []combinationservice.InferredChain{{Title: "潜在远程指令执行链", Level: "high"}},
	}
	refined := review.Result{
		Behavior: review.BehaviorProfile{
			BehaviorChains: []string{"scripts/run.py:18-20 | 执行=1"},
			ExecuteIOCs:    []string{"scripts/run.py:20 os.system(cmd)"},
		},
		StructuredFindings:  []review.StructuredFinding{{ID: "SF-001", Title: "命令执行", Category: "命令执行", AttackPath: "scripts/run.py:20 | shell 执行"}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "confirmed", Reviewer: "llm-vuln-reviewer"}},
	}
	got := applyBehaviorCombinationVerificationPolicy(analysis, refined)
	if got.Conclusion.RiskLevel != "high" {
		t.Fatalf("expected promoted high risk when audit+sandbox+llm support chain, got %q", got.Conclusion.RiskLevel)
	}
	if !strings.Contains(got.Conclusion.Recommendation, "已形成确定性组合链路") {
		t.Fatalf("expected deterministic-chain recommendation, got %q", got.Conclusion.Recommendation)
	}
}

func TestApplyBehaviorCombinationVerificationPolicyKeepsMediumWhenOnlyPartialSources(t *testing.T) {
	analysis := combinationservice.SingleSkillBehaviorAnalysis{
		Conclusion:     combinationservice.Conclusion{RiskLevel: "high", RiskLabel: "高风险", Recommendation: "old"},
		InferredChains: []combinationservice.InferredChain{{Title: "潜在外联回传链", Level: "high"}},
	}
	refined := review.Result{
		Behavior: review.BehaviorProfile{
			BehaviorChains: []string{"scripts/run.py:12-14 | 外联=1"},
		},
		StructuredFindings:  []review.StructuredFinding{{ID: "SF-001", Title: "外联回传", Category: "外联与情报", AttackPath: "scripts/run.py:12 | requests.post"}},
		ReviewAgentVerdicts: nil,
	}
	got := applyBehaviorCombinationVerificationPolicy(analysis, refined)
	if got.Conclusion.RiskLevel != "medium" {
		t.Fatalf("expected medium when only partial verification sources exist, got %q", got.Conclusion.RiskLevel)
	}
	if !strings.Contains(got.Conclusion.Recommendation, "部分验证") {
		t.Fatalf("expected partial verification recommendation, got %q", got.Conclusion.Recommendation)
	}
}

func TestBehaviorChainVerificationThresholdsNormalizeOrder(t *testing.T) {
	t.Setenv("SKILL_SCANNER_BEHAVIOR_CHAIN_VERIFY_HIGH_THRESHOLD", "2")
	t.Setenv("SKILL_SCANNER_BEHAVIOR_CHAIN_VERIFY_MEDIUM_THRESHOLD", "3")
	high, medium := behaviorChainVerificationThresholds()
	if high != 2 {
		t.Fatalf("expected high threshold 2, got %d", high)
	}
	if medium != 2 {
		t.Fatalf("expected medium threshold normalized to 2, got %d", medium)
	}
}

func TestBuildAuditEventsCombinesTracePipelineAndWarnings(t *testing.T) {
	base := baseScanOutput{trace: []analysisTraceEvent{{Stage: "preflight", Status: "completed", Message: "自检通过"}}}
	refined := review.Result{
		Pipeline:           []review.PipelineStage{{Name: "sandbox_execute", Purpose: "执行沙箱", Status: "completed", Output: "完成", Benefit: "可解释"}},
		StructuredFindings: []review.StructuredFinding{{ID: "SF-001"}},
		CapabilityMatrix:   []review.CapabilityConsistency{{Capability: "外联/网络访问"}},
		EvidenceInventory:  []review.EvidenceInventory{{Category: "外联行为", Count: 1}},
		ReviewAgentStats:   []review.ReviewAgentExecutionStats{{Reviewer: "llm-vuln-reviewer", TaskCount: 3, WorkerCount: 3, MaxConcurrency: 2, DurationMs: 41}},
		Behavior:           review.BehaviorProfile{ProbeWarnings: []string{"静态发现外联但沙箱未检出"}},
	}
	events := buildAuditEvents(base, refined)

	if len(events) < 5 {
		t.Fatalf("expected multiple audit events, got %+v", events)
	}
	joined := ""
	for _, event := range events {
		joined += event.Type + " " + event.Brief + " " + event.Detail + "\n"
	}
	for _, want := range []string{"statusUpdate", "newPlanStep", "resultUpdate", "静态发现外联但沙箱未检出", "二次复核执行统计", "并发峰值 2"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected audit event %q in %+v", want, events)
		}
	}
}

func TestBuildCapabilityMatrixExposesSandboxGap(t *testing.T) {
	base := baseScanOutput{
		profile: skillAnalysisProfile{Permissions: []string{"network"}},
		intentSummary: intentReportSummary{
			Available:          true,
			ActualCapabilities: []string{"外联上传数据"},
		},
	}
	findings := []plugins.Finding{{RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Description: "发现外联", CodeSnippet: "fetch(url)"}}
	matrix := buildCapabilityMatrix(findings, base, review.Result{})

	found := false
	for _, item := range matrix {
		if item.Capability == "外联/网络访问" {
			found = true
			if item.Status != "已声明但沙箱未验证" || item.Gap == "" || !item.StaticDetected || !item.LLMDetected {
				t.Fatalf("unexpected external capability row: %+v", item)
			}
		}
	}
	if !found {
		t.Fatalf("expected external capability row, got %+v", matrix)
	}
}

func TestCapabilityMatchesFindingDoesNotMixPeerRiskCategories(t *testing.T) {
	if !capabilityMatchesFinding("外联/网络访问", review.StructuredFinding{Category: "外联与情报"}) {
		t.Fatalf("expected outbound capability to match outbound finding")
	}
	if capabilityMatchesFinding("命令执行", review.StructuredFinding{Category: "外联与情报", Title: "敏感数据外发与隐蔽通道", AttackPath: "外联上传", Evidence: []string{"requests.post(url, data)"}}) {
		t.Fatalf("expected command execution not to match outbound finding")
	}
}

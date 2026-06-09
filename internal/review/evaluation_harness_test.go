package review

import "testing"

func TestRunEvaluationHarnessPassesCuratedFixtures(t *testing.T) {
	result := RunEvaluationHarness("prompt-v1", "schema-v1", "model-a", []EvaluationFixture{
		{ID: "benign-docs", Label: "benign"},
		{
			ID:    "malicious-command",
			Label: "malicious",
			Findings: []StructuredFinding{{
				ID:         "SF-001",
				Title:      "命令执行",
				Category:   "命令执行",
				Severity:   "高风险",
				Confidence: "高",
				Evidence:   []string{"scripts/run.py:10 os.system(cmd)"},
			}},
			ExpectedFindings: []ExpectedEvaluationFinding{{Category: "命令执行", Severity: "高风险", EvidencePattern: "os.system"}},
		},
		{
			ID:    "prompt-injection",
			Label: "malicious",
			Findings: []StructuredFinding{{
				ID:         "SF-PI",
				Title:      "Prompt 注入",
				Category:   "Prompt 注入",
				Severity:   "高风险",
				Confidence: "高",
				Evidence:   []string{"SKILL.md:3 ignore previous instructions"},
			}},
			ExpectedFindings: []ExpectedEvaluationFinding{{Category: "Prompt 注入", Severity: "高风险", EvidencePattern: "ignore previous instructions"}},
		},
	})

	if result.PassRate != 1 || result.FalsePositiveCount != 0 || result.FalseNegativeCount != 0 || result.SchemaFailureCount != 0 || result.UnsupportedClaimCount != 0 {
		t.Fatalf("expected all fixtures pass, got %+v", result)
	}
}

func TestRunEvaluationHarnessCatchesFalsePositiveFalseNegativeAndSchemaFailure(t *testing.T) {
	result := RunEvaluationHarness("prompt-v2", "schema-v2", "model-b", []EvaluationFixture{
		{
			ID:    "benign-fp",
			Label: "benign",
			Findings: []StructuredFinding{{
				ID:         "SF-FP",
				Title:      "示例外联",
				Category:   "外联与情报",
				Severity:   "中风险",
				Confidence: "高",
				Evidence:   []string{"README.md example curl"},
			}},
		},
		{
			ID:               "malicious-fn",
			Label:            "malicious",
			ExpectedFindings: []ExpectedEvaluationFinding{{Category: "凭据访问", Severity: "高风险", EvidencePattern: ".netrc"}},
		},
		{
			ID:    "schema-bad",
			Label: "concern",
			Findings: []StructuredFinding{{
				ID:       "SF-BAD",
				Title:    "缺字段",
				Severity: "中风险",
			}},
		},
		{
			ID:    "unsupported",
			Label: "concern",
			Findings: []StructuredFinding{{
				ID:         "SF-UNSUPPORTED",
				Title:      "无证据风险",
				Category:   "命令执行",
				Severity:   "高风险",
				AttackPath: "声称存在命令执行",
			}},
		},
	})

	if result.PassRate >= 1 {
		t.Fatalf("expected failed fixtures, got %+v", result)
	}
	if result.FalsePositiveCount != 1 || result.FalseNegativeCount != 1 || result.SchemaFailureCount != 1 || result.UnsupportedClaimCount != 1 {
		t.Fatalf("expected quality gate counters, got %+v", result)
	}
}

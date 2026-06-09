package evaluator

import (
	"strings"
	"testing"
)

type batchResultExpectation struct {
	blocked           bool
	ruleID            string
	titleContains     string
	descriptionContains string
	forbidTitle       string
}

func assertBatchEvaluationResult(t *testing.T, result *EvaluationResult, want batchResultExpectation) {
	t.Helper()
	isHighRisk := result.RiskLevel == "high"
	if isHighRisk != want.blocked {
		t.Fatalf("expected blocked=%v (risk=%s), got %v details=%+v", want.blocked, result.RiskLevel, isHighRisk, result.FindingDetails)
	}
	if want.ruleID == "" && want.titleContains == "" && want.forbidTitle == "" {
		return
	}
	matched := want.ruleID == ""
	for _, detail := range result.FindingDetails {
		if want.ruleID != "" && detail.RuleID != want.ruleID {
			continue
		}
		if want.titleContains != "" && !strings.Contains(detail.Title, want.titleContains) {
			continue
		}
		if want.descriptionContains != "" && !strings.Contains(detail.Description, want.descriptionContains) {
			continue
		}
		matched = true
	}
	if !matched {
		t.Fatalf("expected matching detail, got %+v", result.FindingDetails)
	}
	if want.forbidTitle != "" {
		for _, detail := range result.FindingDetails {
			if strings.Contains(detail.Title, want.forbidTitle) {
				t.Fatalf("expected title %q absent, got %+v", want.forbidTitle, detail)
			}
		}
	}
}

func assertBatchDataCollectionFinding(t *testing.T, score float64, ruleWeight float64, details []FindingDetail, wantFinding bool, wantText string) {
	t.Helper()
	if wantFinding {
		if len(details) == 0 || score >= ruleWeight {
			t.Fatalf("expected collection finding, score=%.2f details=%+v", score, details)
		}
		if wantText == "" {
			return
		}
		for _, detail := range details {
			if strings.Contains(detail.Description, wantText) || strings.Contains(detail.CodeSnippet, wantText) {
				return
			}
		}
		t.Fatalf("expected any detail contains %q, got %+v", wantText, details)
	}
	if len(details) != 0 || score != ruleWeight {
		t.Fatalf("expected no data collection finding, score=%.2f details=%+v", score, details)
	}
}

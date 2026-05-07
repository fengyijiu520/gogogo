package handler

import (
	"testing"

	"skill-scanner/internal/config"
	"skill-scanner/internal/evaluator"
)

func TestConvertResultToFindingsUsesConcreteRuleTitleForP0Reason(t *testing.T) {
	cfg := &config.Config{Rules: []config.Rule{{
		ID:   "P1-025",
		Name: "资源耗尽与级联失败防护",
		OnFail: config.OnFail{
			Reason: "资源耗尽与级联失败防护 无补偿且未通过",
		},
	}}}

	result := &evaluator.EvaluationResult{
		P0Blocked: true,
		P0Reasons: []string{"资源耗尽与级联失败防护 无补偿且未通过"},
	}

	findings := convertResultToFindings(result, cfg)
	if len(findings) == 0 {
		t.Fatalf("expected finding generated")
	}
	if findings[0].Title != "资源耗尽与级联失败防护" {
		t.Fatalf("expected concrete rule title, got %s", findings[0].Title)
	}
	if findings[0].RuleID != "P1-025" {
		t.Fatalf("expected mapped rule id, got %s", findings[0].RuleID)
	}
}

package handler

import (
	"testing"

	"skill-scanner/internal/config"
	"skill-scanner/internal/evaluator"
)

func TestConvertResultToFindingsPreservesOSVMetadata(t *testing.T) {
	result := &evaluator.EvaluationResult{
		FindingDetails: []evaluator.FindingDetail{{
			RuleID:      "V7-010-OSV",
			Severity:    "高风险",
			Title:       "依赖漏洞与供应链风险",
			Description: "依赖 `requests`@`2.19.0` 命中 OSV 漏洞 `GHSA-test-1234`：remote code execution",
			Location:    "依赖: requests@2.19.0",
			CodeSnippet: "OSV 证据: dependency=requests version=2.19.0 vuln=GHSA-test-1234",
		}},
	}

	findings := convertResultToFindings(result, &config.Config{})
	if len(findings) != 1 {
		t.Fatalf("expected single finding, got %+v", findings)
	}
	if findings[0].RuleID != "V7-010-OSV" || findings[0].Title != "依赖漏洞与供应链风险" {
		t.Fatalf("expected osv metadata retained, got %+v", findings[0])
	}
	if findings[0].CodeSnippet != "OSV 证据: dependency=requests version=2.19.0 vuln=GHSA-test-1234" {
		t.Fatalf("expected osv evidence snippet retained, got %+v", findings[0])
	}
}

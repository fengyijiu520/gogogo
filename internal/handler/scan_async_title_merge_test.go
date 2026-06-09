package handler

import (
	"strings"
	"testing"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestBuildStructuredFindingsDeduplicatesPolicyBlacklistAcrossLLMAndStaticTitles(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "LLM", RuleID: "SF-004", Severity: "中风险", Title: "LLM检测: 命中黑名单目标（域名/IP）", Description: "命中策略", Location: "README.md:5"},
		{PluginName: "Static", RuleID: "SF-011", Severity: "中风险", Title: "命中黑名单目标（域名/IP）", Description: "命中策略", Location: "docs/guide.md:9"},
	}

	structured := buildStructuredFindings(findings, review.Result{}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected LLM/static policy blacklist findings deduplicated into one structured finding, got %+v", structured)
	}
	if structured[0].DeduplicatedCount != 2 {
		t.Fatalf("expected merged policy blacklist finding count 2, got %+v", structured[0])
	}
	if structured[0].Title != "命中黑名单目标（域名/IP）" {
		t.Fatalf("expected normalized policy blacklist title retained, got %+v", structured[0])
	}
	joinedEvidence := strings.Join(structured[0].Evidence, "\n")
	if !strings.Contains(joinedEvidence, "README.md:5") || !strings.Contains(joinedEvidence, "docs/guide.md:9") {
		t.Fatalf("expected both source locations retained as evidence, got %+v", structured[0])
	}
}

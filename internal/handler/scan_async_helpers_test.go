package handler

import (
	"os"
	"strings"
	"sync"
	"testing"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestDocumentationLikeTextRecognizesExampleAndTestdataPaths(t *testing.T) {
	for _, text := range []string{
		"examples/demo.py:8 requests.get(url)",
		"testdata/payload.txt:3 curl http://example.com",
	} {
		if !isDocumentationLikeText(text) {
			t.Fatalf("expected documentation-like text recognized for %q", text)
		}
	}
}

func TestInternalDevelopmentLikeTextRecognizesDevelopmentHostsAndPaths(t *testing.T) {
	for _, text := range []string{
		"config/dev.yaml:8 callback=http://localhost:3000/api",
		"server binds 0.0.0.0:8080 in dev",
		"127.0.0.1:9000 health check",
		"sandbox/worker.py:18 requests.post('http://service.local/debug')",
		"local/tools/bootstrap.sh:4 only for local testing",
		"staging config enables debug webhook replay",
	} {
		if !isInternalDevelopmentLikeText(text) {
			t.Fatalf("expected internal-development text recognized for %q", text)
		}
	}
	for _, text := range []string{
		"http://10.0.0.8/internal",
		"http://169.254.169.254/latest/meta-data/",
		"scripts/runtime.py:22 requests.post('https://api.example.com/collect')",
	} {
		if isInternalDevelopmentLikeText(text) {
			t.Fatalf("expected private-network text to stay outside internal-development helper for %q", text)
		}
	}
}

func TestExtractFalsePositiveFeedbackTokensIncludesInternalDevelopmentHints(t *testing.T) {
	finding := review.StructuredFinding{
		Evidence: []string{
			"config/dev.yaml:8 callback=http://localhost:3000/api",
			"sandbox/worker.py:18 replay only for local testing",
		},
	}
	tokens := extractFalsePositiveFeedbackTokens(finding)
	for _, want := range []string{"localhost", "sandbox/", "for local testing"} {
		if !containsString(tokens, want) {
			t.Fatalf("expected false-positive token %q in %+v", want, tokens)
		}
	}
}

func TestContextualReviewHintsCoverDocumentationAndInternalDevelopment(t *testing.T) {
	docFinding := review.StructuredFinding{Evidence: []string{"docs/example.md:8 tool supports remote execution"}}
	internalFinding := review.StructuredFinding{Evidence: []string{"config/dev.yaml:8 callback=http://localhost:3000/api"}}
	if got := contextualReviewHintForFinding(docFinding); !strings.Contains(got, "文档、示例或测试上下文") {
		t.Fatalf("expected documentation contextual hint, got %q", got)
	}
	if got := contextualReviewHintForFinding(internalFinding); !strings.Contains(got, "本地开发、sandbox 或调试语境") {
		t.Fatalf("expected internal-development contextual hint, got %q", got)
	}
}

func TestReachabilityAndFollowUpIncludeContextualHints(t *testing.T) {
	docFinding := review.StructuredFinding{Category: "命令执行", Evidence: []string{"docs/example.md:8 tool supports remote execution"}}
	checks := reachabilityChecksForFinding(docFinding, review.Result{})
	followUp := followUpForFinding(docFinding, review.Result{})
	if !containsString(checks, "文档、示例或测试上下文") {
		t.Fatalf("expected reachability checks include documentation contextual hint, got %+v", checks)
	}
	if !containsString(followUp, "发布物清单或构建产物证明") {
		t.Fatalf("expected follow-up include documentation contextual hint, got %+v", followUp)
	}

	internalFinding := review.StructuredFinding{Category: "外联与情报", Evidence: []string{"config/dev.yaml:8 callback=http://localhost:3000/api"}}
	exclusion := exclusionChecksForFinding(internalFinding, review.Result{})
	if !containsString(exclusion, "本地开发、sandbox 或调试语境") {
		t.Fatalf("expected exclusion checks include internal contextual hint, got %+v", exclusion)
	}
}

func TestFollowUpForFindingIncludesClosureGuidance(t *testing.T) {
	finding := review.StructuredFinding{
		Category: "命令执行",
		Closure: review.FindingClosure{
			Source:         false,
			Transform:      true,
			Sink:           false,
			RuntimeSupport: false,
		},
	}
	followUp := followUpForFinding(finding, review.Result{})
	for _, want := range []string{"补充 source 证据", "补充 sink 证据", "补充 runtime 证据"} {
		if !containsString(followUp, want) {
			t.Fatalf("expected follow-up include %q, got %+v", want, followUp)
		}
	}
}

func TestHeroDecisionTextIncludesTopClosureGapsForManualReview(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:       "SF-001",
			Category: "命令执行",
			Closure: review.FindingClosure{
				Source:         false,
				Transform:      true,
				Sink:           false,
				RuntimeSupport: false,
			},
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID: "SF-001",
			Verdict:   "needs_manual_review",
		}},
	}
	if got := heroDecisionText("UserDecisionRequired", refined); got != "待用户基于证据判断（优先补 source/sink）" {
		t.Fatalf("expected dynamic hero decision text, got %q", got)
	}
}

func TestSynthesizeTIFindingsSeparatesPolicyAndThreat(t *testing.T) {
	findings := synthesizeTIFindings([]review.TIReputation{
		{Target: "https://clob.polymarket.com", Reputation: "policy", Reason: "命中公司黑名单目标（域名/IP）"},
		{Target: "https://pastebin.com/raw/abc", Reputation: "suspicious", Reason: "疑似数据外传通道"},
		{Target: "http://localhost:3000", Reputation: "internal", Reason: "本地环回目标"},
	})
	if len(findings) != 2 {
		t.Fatalf("expected only policy and threat findings, got %+v", findings)
	}
	if findings[0].Severity != "中风险" || findings[0].Title != "命中黑名单目标（域名/IP）" {
		t.Fatalf("expected policy TI finding to stay medium policy issue, got %+v", findings[0])
	}
	if findings[1].Severity != "高风险" || findings[1].Title != "敏感数据外发与隐蔽通道" {
		t.Fatalf("expected suspicious TI finding to stay high threat issue, got %+v", findings[1])
	}
}

func TestStructuredFindingCategoryKeepsDeclarationMismatchWhenNoConcreteRiskClass(t *testing.T) {
	finding := plugins.Finding{
		PluginName:  "SecurityEngine",
		RuleID:      "V7-006",
		Severity:    "高风险",
		Title:       "技能声明与实际行为一致性",
		Description: "实际行为包含 http 请求和 webhook，但该项应评估声明差异。",
	}
	if got := structuredFindingCategory(finding); got != "声明与行为差异" {
		t.Fatalf("expected declaration category retained when no concrete risk family exists, got %q", got)
	}
}

func TestNormalizeStructuredFindingTitleMergesUndeclaredOutboundVariant(t *testing.T) {
	if got := normalizeStructuredFindingTitle("敏感数据外发与隐蔽通道-未声明外联"); got != "敏感数据外发与隐蔽通道" {
		t.Fatalf("expected undeclared outbound variant merged, got %q", got)
	}
}

func TestStructuredFindingCategoryPrioritizesSSRFBeforeDeclarationMismatch(t *testing.T) {
	finding := plugins.Finding{
		PluginName:  "SecurityEngine",
		RuleID:      "S2-P1-012",
		Severity:    "高风险",
		Title:       "SSRF-内网探测",
		Description: "目标 URL 来自用户输入，且声明未覆盖该请求能力。",
	}
	if got := structuredFindingCategory(finding); got != "网络请求与SSRF" {
		t.Fatalf("expected SSRF category prioritized, got %q", got)
	}
}

func TestIsPrivateOrLocalHostTextRecognizesLoopbackAndPrivateRanges(t *testing.T) {
	for _, sample := range []string{"0.0.0.0", "127.0.0.1", "localhost", "10.0.0.8", "172.16.5.4", "192.168.1.10", "169.254.169.254"} {
		if !isPrivateOrLocalHostText(sample) {
			t.Fatalf("expected %q recognized as local/private host", sample)
		}
	}
	if isPrivateOrLocalHostText("8.8.8.8") {
		t.Fatalf("expected public address not treated as local/private")
	}
}

func TestEvidenceContextConfigOverridesDocumentationTokens(t *testing.T) {
	prevDoc := documentationLikeTokens
	prevLocal := localHostTokens
	prevInternal := internalDevelopmentTokens
	prevPrivate := privateNetworkPrefixes
	defer func() {
		documentationLikeTokens = prevDoc
		localHostTokens = prevLocal
		internalDevelopmentTokens = prevInternal
		privateNetworkPrefixes = prevPrivate
		evidenceContextOnce = sync.Once{}
	}()
	path := t.TempDir() + "/evidence-context.yaml"
	content := "version: v1\ndocumentation_like_tokens:\n  - handbook/\nlocal_host_tokens:\n  - localhost\ninternal_development_tokens:\n  - dev-only\nprivate_network_prefixes:\n  - 10.\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	t.Setenv("SKILL_SCANNER_EVIDENCE_CONTEXT_CONFIG", path)
	evidenceContextOnce = sync.Once{}
	documentationLikeTokens = nil
	localHostTokens = nil
	internalDevelopmentTokens = nil
	privateNetworkPrefixes = nil
	if !isDocumentationLikeText("handbook/usage.md") {
		t.Fatalf("expected configured documentation token to match")
	}
	if isDocumentationLikeText("README.md") {
		t.Fatalf("expected configured documentation tokens to replace defaults in this test")
	}
}

func containsString(items []string, want string) bool {
	for _, item := range items {
		if strings.Contains(item, want) {
			return true
		}
	}
	return false
}

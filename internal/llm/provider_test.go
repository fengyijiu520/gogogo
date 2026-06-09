package llm

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"skill-scanner/internal/config"
)

type fakeCompleteClient struct {
	content string
}

func (f fakeCompleteClient) Complete(context.Context, string, string) (string, error) {
	return f.content, nil
}

func (f fakeCompleteClient) AnalyzeCode(ctx context.Context, name, description, codeSummary string) (*AnalysisResult, error) {
	return analyzeCodeWithClient(ctx, f, name, description, codeSummary)
}

func (f fakeCompleteClient) AnalyzeObfuscatedContent(ctx context.Context, name, content string) (*ObfuscationAnalysisResult, error) {
	return analyzeObfuscatedContentWithClient(ctx, f, name, content)
}

func TestNewProtocolClientSupportsOpenAIAndAnthropic(t *testing.T) {
	openAIClient, err := NewProtocolClient(ProviderConfig{Protocol: "openai", Name: "OpenAI", BaseURL: "https://api.example.com/v1", Model: "gpt-test", APIKey: "secret"})
	if err != nil {
		t.Fatalf("expected openai client: %v", err)
	}
	if _, ok := openAIClient.(*openAICompatibleClient); !ok {
		t.Fatalf("expected openai-compatible client, got %T", openAIClient)
	}

	anthropicClient, err := NewProtocolClient(ProviderConfig{Protocol: "anthropic", Name: "Claude", BaseURL: "https://api.anthropic.com/v1", Model: "claude-test", APIKey: "secret"})
	if err != nil {
		t.Fatalf("expected anthropic client: %v", err)
	}
	if _, ok := anthropicClient.(*anthropicCompatibleClient); !ok {
		t.Fatalf("expected anthropic-compatible client, got %T", anthropicClient)
	}
}

func TestProviderURLRejectsPrivateHosts(t *testing.T) {
	if _, err := NewProtocolClient(ProviderConfig{Protocol: "openai", Name: "local", BaseURL: "https://localhost/v1", Model: "demo", APIKey: "secret"}); err == nil {
		t.Fatal("expected localhost rejection")
	}
	if _, err := NewProtocolClient(ProviderConfig{Protocol: "anthropic", Name: "private", BaseURL: "https://10.0.0.1/v1", Model: "demo", APIKey: "secret"}); err == nil {
		t.Fatal("expected private ip rejection")
	}
}

func TestLLMRequestTimeoutDefaultAllowsLongerAnalysis(t *testing.T) {
	if got := config.LLMRequestTimeoutSecs(); got < 120 {
		t.Fatalf("expected default llm timeout to support longer analysis, got %d", got)
	}
}

func TestAnalyzeCodeAcceptsFloatRiskScore(t *testing.T) {
	client := fakeCompleteClient{content: `{
		"stated_intent":"deploy helper",
		"actual_behavior":"updates deployment docs",
		"intent_consistency":95,
		"risks":[{
			"title":"broad deployment access",
			"severity":"high",
			"status":"confirmed",
			"risk_score":7.5,
			"description":"deployment steps can expose credentials",
			"evidence":"DEPLOYMENT.md references token setup",
			"evidence_refs":["DEPLOYMENT.md:12"]
		}]
	}`}

	result, err := client.AnalyzeCode(context.Background(), "demo", "", "")
	if err != nil {
		t.Fatalf("expected float risk score to parse: %v", err)
	}
	if len(result.Risks) != 1 {
		t.Fatalf("expected one risk, got %d", len(result.Risks))
	}
	if result.Risks[0].RiskScore != 8 {
		t.Fatalf("expected rounded risk score 8, got %d", result.Risks[0].RiskScore)
	}
	if got := result.Risks[0].EvidenceRefs; len(got) != 1 || got[0] != "DEPLOYMENT.md:12" {
		t.Fatalf("expected evidence refs to parse, got %#v", got)
	}
}

func TestAnalyzeCodeExtractsBalancedJSONObject(t *testing.T) {
	client := fakeCompleteClient{content: "Here is the result:\n```json\n{\"stated_intent\":\"scan {docs}\",\"actual_behavior\":\"safe\",\"intent_consistency\":\"100\",\"risks\":[]}\n```\nTrailing {not json}"}

	result, err := client.AnalyzeCode(context.Background(), "demo", "", "")
	if err != nil {
		t.Fatalf("expected fenced json to parse: %v", err)
	}
	if result.StatedIntent != "scan {docs}" {
		t.Fatalf("expected quoted braces to remain in stated intent, got %q", result.StatedIntent)
	}
	if result.IntentConsistency != 100 {
		t.Fatalf("expected string intent consistency to normalize, got %d", result.IntentConsistency)
	}
}

func TestRiskItemUnmarshalAcceptsFloatAndStringFields(t *testing.T) {
	var payload struct {
		Risks []RiskItem `json:"risks"`
	}
	data := []byte(`{"risks":[{"title":123,"severity":"高风险","risk_score":"7.5","evidence_refs":"file.go:10","description":true}]}`)
	if err := json.Unmarshal(data, &payload); err != nil {
		t.Fatalf("expected risk item to unmarshal with normalized fields: %v", err)
	}
	if len(payload.Risks) != 1 {
		t.Fatalf("expected one risk, got %d", len(payload.Risks))
	}
	if payload.Risks[0].RiskScore != 8 {
		t.Fatalf("expected rounded risk score, got %d", payload.Risks[0].RiskScore)
	}
	if payload.Risks[0].Title != "123" || payload.Risks[0].Description != "true" {
		t.Fatalf("expected scalar fields to normalize, got %+v", payload.Risks[0])
	}
	if got := payload.Risks[0].EvidenceRefs; len(got) != 1 || got[0] != "file.go:10" {
		t.Fatalf("expected single evidence ref to normalize, got %#v", got)
	}
}

func TestAnalyzeObfuscatedContentNormalizesLooseSchema(t *testing.T) {
	client := fakeCompleteClient{content: `{"likely_obfuscated":"yes","technique":123,"summary":true,"benign_indicators":"test fixture","risk_indicators":["eval"]}`}

	result, err := client.AnalyzeObfuscatedContent(context.Background(), "demo", "")
	if err != nil {
		t.Fatalf("expected loose obfuscation response to parse: %v", err)
	}
	if !result.LikelyObfuscated || result.Technique != "123" || result.Summary != "true" {
		t.Fatalf("expected loose fields to normalize, got %+v", result)
	}
	if got := result.BenignIndicators; len(got) != 1 || got[0] != "test fixture" {
		t.Fatalf("expected benign indicators to normalize, got %#v", got)
	}
}

func TestOpenAICompleteReturnsHTTPStatusForNonJSONErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
	}))
	defer server.Close()

	client := &openAICompatibleClient{name: "test-openai", baseURL: server.URL, model: "demo", apiKey: "secret"}
	_, err := client.Complete(context.Background(), "system", "user")
	if err == nil {
		t.Fatal("expected non-json upstream error")
	}
	if !strings.Contains(err.Error(), "HTTP 状态异常: 502") || !strings.Contains(err.Error(), "upstream unavailable") {
		t.Fatalf("expected status and response body in error, got %v", err)
	}
}

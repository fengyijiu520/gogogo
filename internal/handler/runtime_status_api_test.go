package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

func TestRuntimeStatusAPIReturnsStructuredStatus(t *testing.T) {
	store := newHandlerTestStore(t)
	if err := store.SaveLLMProvider(storage.LLMProviderConfig{
		ID:       "deepseek",
		Name:     "DeepSeek",
		Protocol: "openai",
		BaseURL:  "https://api.example.com/v1",
		Model:    "deepseek-chat",
		Enabled:  true,
		APIKey:   "provider-secret",
	}); err != nil {
		t.Fatalf("save llm provider: %v", err)
	}
	if err := store.SaveUserLLMConfig("admin", &models.LLMConfig{Enabled: true, Provider: "deepseek"}); err != nil {
		t.Fatalf("save user llm config: %v", err)
	}

	prevReady := runtimeCheckReady
	prevResult := runtimeCheckResult
	runtimeCheckReady = true
	runtimeCheckResult = runtimeCheckReport{
		CheckedAt: time.Unix(1700000000, 0),
		Components: []componentCheck{
			{Name: "Rules", Enabled: true, Required: true, Ready: true, Message: "规则正常"},
			{Name: "Sandbox", Enabled: true, Required: false, Ready: false, Message: "sandbox runtime 缺失"},
		},
	}
	t.Cleanup(func() {
		runtimeCheckReady = prevReady
		runtimeCheckResult = prevResult
	})

	req := newAuthenticatedRequest(t, http.MethodGet, "/api/runtime/status", "admin")
	rec := httptest.NewRecorder()

	RuntimeStatusAPI(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp runtimeStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !resp.Ready {
		t.Fatal("expected overall runtime status ready")
	}
	wantCheckedText := time.Unix(1700000000, 0).In(time.Local).Format("2006-01-02 15:04:05")
	if resp.CheckedAtText != wantCheckedText {
		t.Fatalf("expected checked_at_text %s, got %q", wantCheckedText, resp.CheckedAtText)
	}
	if len(resp.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(resp.Components))
	}
	if resp.Components[1].DisplayName != "沙箱" {
		t.Fatalf("expected localized component name, got %q", resp.Components[1].DisplayName)
	}
	if resp.Components[1].Action.Href != "/runtime-help#sandbox" {
		t.Fatalf("expected sandbox action points runtime help, got %+v", resp.Components[1].Action)
	}
	if !resp.UserLLM.Ready {
		t.Fatal("expected user llm ready")
	}
	if resp.UserLLM.Action.Href != "" {
		t.Fatalf("expected ready user llm has no action, got %+v", resp.UserLLM.Action)
	}
	if !resp.ScanPreview.Ready {
		t.Fatal("expected scan preflight ready with optional warning only")
	}
	if len(resp.ScanPreview.Warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d", len(resp.ScanPreview.Warnings))
	}
}

func TestRuntimeStatusAPIReportsMissingUserLLMAsFailure(t *testing.T) {
	store := newHandlerTestStore(t)

	prevReady := runtimeCheckReady
	prevResult := runtimeCheckResult
	runtimeCheckReady = true
	runtimeCheckResult = runtimeCheckReport{
		CheckedAt: time.Unix(1700000100, 0),
		Components: []componentCheck{{Name: "Rules", Enabled: true, Required: true, Ready: true, Message: "规则正常"}},
	}
	t.Cleanup(func() {
		runtimeCheckReady = prevReady
		runtimeCheckResult = prevResult
	})

	req := newAuthenticatedRequest(t, http.MethodGet, "/api/runtime/status", "admin")
	rec := httptest.NewRecorder()

	RuntimeStatusAPI(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp runtimeStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if resp.UserLLM.Ready {
		t.Fatal("expected user llm not ready")
	}
	if resp.UserLLM.Action.Href != "/personal" {
		t.Fatalf("expected missing llm action to point personal page, got %+v", resp.UserLLM.Action)
	}
	if resp.ScanPreview.Ready {
		t.Fatal("expected scan preflight blocked by missing llm config")
	}
	if len(resp.ScanPreview.Failures) == 0 {
		t.Fatal("expected scan preflight failures")
	}
	if resp.Ready {
		t.Fatal("expected overall runtime status not ready")
	}
}

func TestBuildScanPreflightErrorResponsePrefersUserLLMAction(t *testing.T) {
	store := newHandlerTestStore(t)
	prevReady := runtimeCheckReady
	prevResult := runtimeCheckResult
	runtimeCheckReady = true
	runtimeCheckResult = runtimeCheckReport{
		CheckedAt: time.Unix(1700000100, 0),
		Components: []componentCheck{{Name: "Rules", Enabled: true, Required: true, Ready: true, Message: "规则正常"}},
	}
	t.Cleanup(func() {
		runtimeCheckReady = prevReady
		runtimeCheckResult = prevResult
	})

	validation := validateScanPreflight(store, "admin")
	if validation.Err == nil {
		t.Fatal("expected preflight error")
	}
	title, suggestion, action := BuildScanPreflightErrorResponse(store, "admin", validation.Assessment, validation.Err)
	if title != "当前账号未配置 LLM API Key" {
		t.Fatalf("expected llm title, got %q", title)
	}
	if suggestion == "" {
		t.Fatal("expected non-empty suggestion")
	}
	if action.Href != "/personal" {
		t.Fatalf("expected personal action, got %+v", action)
	}
}

func TestBuildScanPreflightErrorResponseUsesComponentAction(t *testing.T) {
	store := newHandlerTestStore(t)
	if err := store.SaveLLMProvider(storage.LLMProviderConfig{ID: "deepseek", Name: "DeepSeek", Protocol: "openai", BaseURL: "https://api.example.com/v1", Model: "deepseek-chat", Enabled: true, APIKey: "provider-secret"}); err != nil {
		t.Fatalf("save llm provider: %v", err)
	}
	if err := store.SaveUserLLMConfig("admin", &models.LLMConfig{Enabled: true, Provider: "deepseek"}); err != nil {
		t.Fatalf("save user llm config: %v", err)
	}
	prevReady := runtimeCheckReady
	prevResult := runtimeCheckResult
	runtimeCheckReady = true
	runtimeCheckResult = runtimeCheckReport{
		CheckedAt: time.Unix(1700000100, 0),
		Components: []componentCheck{{Name: "Sandbox", Enabled: true, Required: true, Ready: false, Message: "sandbox runtime 缺失"}},
	}
	t.Cleanup(func() {
		runtimeCheckReady = prevReady
		runtimeCheckResult = prevResult
	})

	validation := validateScanPreflight(store, "admin")
	if validation.Err == nil {
		t.Fatal("expected preflight error")
	}
	title, suggestion, action := BuildScanPreflightErrorResponse(store, "admin", validation.Assessment, validation.Err)
	if title != "扫描前置自检未通过" {
		t.Fatalf("expected generic title, got %q", title)
	}
	if suggestion != "请先完成运行环境修复，再重新提交扫描。" {
		t.Fatalf("expected runtime-help suggestion, got %q", suggestion)
	}
	if action.Href != "/runtime-help#sandbox" {
		t.Fatalf("expected sandbox anchor action, got %+v", action)
	}
}

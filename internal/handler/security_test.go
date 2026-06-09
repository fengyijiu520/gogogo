package handler

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"skill-scanner/internal/llm"
	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

func TestWithTrustedOriginRejectsCrossSitePost(t *testing.T) {
	h := withTrustedOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/scan", nil)
	req.Host = "scanner.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestWithTrustedOriginAllowsSameOriginPost(t *testing.T) {
	h := withTrustedOrigin(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodPost, "/scan", nil)
	req.Host = "scanner.example.com"
	req.Header.Set("Origin", "https://scanner.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rec.Code)
	}
}

func TestWithSecurityHeadersSetsDefaults(t *testing.T) {
	h := withSecurityHeaders(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/reports", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if got := rec.Header().Get("Content-Security-Policy"); got != appContentSecurityPolicy {
		t.Fatalf("expected app csp, got %q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("expected nosniff, got %q", got)
	}
	if got := rec.Header().Get("X-Frame-Options"); got != "DENY" {
		t.Fatalf("expected frame deny, got %q", got)
	}
}

func TestRenderMissingTemplateReturnsInternalServerError(t *testing.T) {
	rec := httptest.NewRecorder()
	render(rec, "missing-template", map[string]interface{}{})
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
}

func TestDecodeStrictJSONBodyRejectsUnknownFields(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/user/llm", strings.NewReader(`{"provider":"deepseek","unexpected":true}`))
	rec := httptest.NewRecorder()
	var body struct {
		Provider string `json:"provider"`
	}
	if err := decodeStrictJSONBody(rec, req, &body, 1024); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func TestSetSessionCookieMarksSecureForHTTPS(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	req.TLS = &tls.ConnectionState{}
	setSessionCookie(rec, req, "demo-session")
	res := rec.Result()
	cookies := res.Cookies()
	if len(cookies) != 1 || !cookies[0].Secure {
		t.Fatalf("expected secure cookie on https, got %+v", cookies)
	}
}

func TestValidateUploadedFilesRejectsOversizedFile(t *testing.T) {
	files := []*multipart.FileHeader{{Filename: "demo.txt", Size: maxSingleUploadFileBytes + 1}}
	if err := validateUploadedFiles(files); err == nil {
		t.Fatal("expected oversized file rejection")
	}
}

func TestLimitMultipartBodyRejectsOversizedBody(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/scan", bytes.NewReader(make([]byte, maxMultipartBodyBytes+1)))
	rec := httptest.NewRecorder()
	limitMultipartBody(rec, req)
	data := make([]byte, maxMultipartBodyBytes+1)
	if _, err := req.Body.Read(data); err == nil {
		t.Fatal("expected oversized multipart body read to fail")
	}
}

func TestValidateUserLLMRequestRejectsInvalidProvider(t *testing.T) {
	store := newTestStoreForLLMValidation(t)
	if err := validateUserLLMRequest(store, "unknown", true, "", false); err == nil {
		t.Fatal("expected invalid provider rejection")
	}
}

func TestValidateUserLLMRequestAcceptsConfiguredProvider(t *testing.T) {
	store := newTestStoreForLLMValidation(t)
	store.ForceSetLLMConfigForTest(&storage.LLMConfig{Providers: []storage.LLMProviderConfig{{ID: "demo", Name: "Demo", Protocol: "openai", BaseURL: "https://api.example.com/chat/completions", Model: "demo-model", APIKey: "secret", Enabled: true}}})
	if err := validateUserLLMRequest(store, "demo", true, "", false); err != nil {
		t.Fatalf("expected configured provider, got %v", err)
	}
}

func TestValidateUserLLMRequestRejectsProviderWithoutAPIKey(t *testing.T) {
	store := newTestStoreForLLMValidation(t)
	store.ForceSetLLMConfigForTest(&storage.LLMConfig{Providers: []storage.LLMProviderConfig{{ID: "demo", Name: "Demo", Protocol: "openai", BaseURL: "https://api.example.com/chat/completions", Model: "demo-model", Enabled: true}}})
	if err := validateUserLLMRequest(store, "demo", true, "", false); err == nil {
		t.Fatal("expected provider without api key rejection")
	}
}

func TestValidateUserLLMRequestAcceptsPersonalAPIKey(t *testing.T) {
	store := newTestStoreForLLMValidation(t)
	store.ForceSetLLMConfigForTest(&storage.LLMConfig{Providers: []storage.LLMProviderConfig{{ID: "demo", Name: "Demo", Protocol: "openai", BaseURL: "https://api.example.com/chat/completions", Model: "demo-model", Enabled: true}}})
	if err := validateUserLLMRequest(store, "demo", true, "personal-key", false); err != nil {
		t.Fatalf("expected personal api key to satisfy validation, got %v", err)
	}
}

func TestResolveUserLLMProviderConfigPrefersPersonalAPIKey(t *testing.T) {
	store := newTestStoreForLLMValidation(t)
	store.ForceSetLLMConfigForTest(&storage.LLMConfig{Providers: []storage.LLMProviderConfig{{ID: "demo", Name: "Demo", Protocol: "openai", BaseURL: "https://api.example.com/chat/completions", Model: "demo-model", APIKey: "system-key", Enabled: true}}})
	provider, ok := resolveUserLLMProviderConfig(store, &models.LLMConfig{Enabled: true, Provider: "demo", APIKey: "personal-key"})
	if !ok {
		t.Fatal("expected provider config")
	}
	if provider.APIKey != "personal-key" {
		t.Fatalf("expected personal api key, got %q", provider.APIKey)
	}
}

func TestGetUserLLMConfigListsEnabledDeepSeekPreset(t *testing.T) {
	store := newTestStoreForLLMValidation(t)
	req := httptest.NewRequest(http.MethodGet, "/api/user/llm", nil)
	sessionID := generateSessionID("admin")
	sessionStore.Store(sessionID, &Session{Username: "admin", CreatedAt: time.Now()})
	t.Cleanup(func() { sessionStore.Delete(sessionID) })
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID, Path: "/"})
	rec := httptest.NewRecorder()

	GetUserLLMConfig(store)(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var resp struct {
		Providers []storage.LLMProviderConfig `json:"providers"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	found := false
	for _, provider := range resp.Providers {
		if provider.ID == llm.DeepSeekProviderConfig.Provider {
			found = true
			if provider.Model != llm.DeepSeekModel {
				t.Fatalf("expected model %q, got %q", llm.DeepSeekModel, provider.Model)
			}
		}
	}
	if !found {
		t.Fatalf("expected deepseek provider in user llm config, got %+v", resp.Providers)
	}
}

func newTestStoreForLLMValidation(t *testing.T) *storage.Store {
	t.Helper()
	t.Setenv("SKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD", "test-password-12345")
	store, err := storage.NewStore(filepath.Join(t.TempDir(), "data"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestValidateRuleProfileRequestRejectsTooManyCustomRules(t *testing.T) {
	rules := make([]models.CustomRuleConfig, maxCustomRuleCount+1)
	for i := range rules {
		rules[i] = models.CustomRuleConfig{Name: "rule", Severity: "高风险", Patterns: []string{"abc"}}
	}
	profile := &models.RuleProfile{Name: "demo", CustomRules: rules}
	if err := validateRuleProfileRequest(profile); err == nil {
		t.Fatal("expected too many custom rules rejection")
	}
}

func TestParseCustomRulesAppliesSafetyLimits(t *testing.T) {
	raw, err := json.Marshal([]map[string]interface{}{{
		"name":     strings.Repeat("a", 200),
		"severity": "high",
		"patterns": []string{"ok"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if out := parseCustomRules(string(raw)); len(out) != 0 {
		t.Fatalf("expected invalid oversized rule name to be dropped, got %+v", out)
	}
}

package handler

import (
	"crypto/tls"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"skill-scanner/internal/models"
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

func TestValidateUserLLMRequestRejectsInvalidProvider(t *testing.T) {
	if err := validateUserLLMRequest("unknown", "key", "", true, false); err == nil {
		t.Fatal("expected invalid provider rejection")
	}
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

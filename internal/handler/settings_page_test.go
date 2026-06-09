package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSettingsPageShowsRuntimeStatusPanel(t *testing.T) {
	store := newTestStore(t)
	prevReady := runtimeCheckReady
	prevResult := runtimeCheckResult
	runtimeCheckReady = true
	runtimeCheckResult = runtimeCheckReport{
		CheckedAt: time.Unix(1700000300, 0),
		Components: []componentCheck{
			{Name: "Rules", Enabled: true, Required: true, Ready: true, Message: "规则正常"},
			{Name: "Semantic", Enabled: true, Required: true, Ready: false, Message: "语义引擎未就绪"},
		},
	}
	t.Cleanup(func() {
		runtimeCheckReady = prevReady
		runtimeCheckResult = prevResult
	})

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/settings?tab=users", "admin")
	settingsPage(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	wantTime := time.Unix(1700000300, 0).In(time.Local).Format("2006-01-02 15:04:05")
	for _, want := range []string{"运行时检查", "当前账号 LLM", "语义引擎未就绪", "当前账号未配置 LLM API Key", "最近检查", wantTime} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected settings page contains %q, got %q", want, body)
		}
	}
	if !strings.Contains(body, "href=\"/personal\"") {
		t.Fatalf("expected settings page exposes llm fix entry, got %q", body)
	}
}

package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestScanPageSetsNoStoreHeaders(t *testing.T) {
	store := newTestStore(t)
	prevReady := runtimeCheckReady
	prevResult := runtimeCheckResult
	runtimeCheckReady = true
	runtimeCheckResult = runtimeCheckReport{
		CheckedAt: time.Unix(1700000200, 0),
		Components: []componentCheck{
			{Name: "Rules", Enabled: true, Required: true, Ready: true, Message: "规则正常"},
			{Name: "Sandbox", Enabled: true, Required: true, Ready: false, Message: "sandbox runtime 缺失"},
		},
	}
	t.Cleanup(func() {
		runtimeCheckReady = prevReady
		runtimeCheckResult = prevResult
	})

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/scan", "admin")
	scan(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control no-store, got %q", got)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/admission/skills") || !strings.Contains(body, "/combination/overview") {
		t.Fatalf("expected scan page exposes admission and combination entry, got %q", body)
	}
	if !strings.Contains(body, "运行时检查") || !strings.Contains(body, "当前账号 LLM") {
		t.Fatalf("expected scan page shows runtime status panel, got %q", body)
	}
	wantCheckedTime := time.Unix(1700000200, 0).In(time.Local).Format("2006-01-02 15:04:05")
	if !strings.Contains(body, "最近检查") || !strings.Contains(body, wantCheckedTime) {
		t.Fatalf("expected scan page shows runtime checked time %s, got %q", wantCheckedTime, body)
	}
	if !strings.Contains(body, "sandbox runtime 缺失") || !strings.Contains(body, "当前账号未配置 LLM API Key") {
		t.Fatalf("expected scan page shows runtime blocking details, got %q", body)
	}
	if !strings.Contains(body, "href=\"/personal\"") {
		t.Fatalf("expected scan page exposes llm fix entry, got %q", body)
	}
	if !strings.Contains(body, "taskErrorPanel") || !strings.Contains(body, "taskErrorAction") {
		t.Fatalf("expected scan page includes inline preflight error panel, got %q", body)
	}
}

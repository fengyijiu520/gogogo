package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRuntimeHelpPageRendersSections(t *testing.T) {
	store := newTestStore(t)
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/runtime-help", "admin")
	runtimeHelp(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{"id=\"sandbox\"", "id=\"semantic\"", "/personal", "/settings?tab=llm", "docker info", "models/bge-large-zh-v1.5", "/usr/local/lib/libonnxruntime.so"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected runtime help page contains %q, got %q", want, body)
		}
	}
}

package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestScanPageSetsNoStoreHeaders(t *testing.T) {
	store := newTestStore(t)
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
}

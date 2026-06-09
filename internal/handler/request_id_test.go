package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"skill-scanner/internal/logx"
)

func TestWithRequestIDGenerateWhenMissing(t *testing.T) {
	var gotRID string
	h := withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(logx.RequestIDContextKey).(string); ok {
			gotRID = v
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/scan", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", rr.Code)
	}
	if gotRID == "" {
		t.Fatal("expected request id in context")
	}
	if rr.Header().Get(requestIDHeader) == "" {
		t.Fatal("expected response header request id")
	}
	if rr.Header().Get(requestIDHeader) != gotRID {
		t.Fatalf("header/context request id mismatch: header=%q context=%q", rr.Header().Get(requestIDHeader), gotRID)
	}
}

func TestWithRequestIDKeepIncomingHeader(t *testing.T) {
	const incoming = "rid-from-client"
	var gotRID string
	h := withRequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if v, ok := r.Context().Value(logx.RequestIDContextKey).(string); ok {
			gotRID = v
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	req := httptest.NewRequest(http.MethodGet, "/scan", nil)
	req.Header.Set(requestIDHeader, incoming)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if gotRID != incoming {
		t.Fatalf("expected context request id %q, got %q", incoming, gotRID)
	}
	if rr.Header().Get(requestIDHeader) != incoming {
		t.Fatalf("expected response header request id %q, got %q", incoming, rr.Header().Get(requestIDHeader))
	}
}

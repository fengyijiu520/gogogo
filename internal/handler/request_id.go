package handler

import (
	"context"
	"net/http"
	"strings"

	"skill-scanner/internal/logx"
	platformid "skill-scanner/internal/platform/id"
)

const requestIDHeader = "X-Request-Id"

func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := strings.TrimSpace(r.Header.Get(requestIDHeader))
		if requestID == "" {
			generated, err := platformid.GenerateHexID(8)
			if err != nil {
				generated = "rid-fallback"
			}
			requestID = generated
		}
		ctx := context.WithValue(r.Context(), logx.RequestIDContextKey, requestID)
		w.Header().Set(requestIDHeader, requestID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

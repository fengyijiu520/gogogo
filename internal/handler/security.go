package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const appContentSecurityPolicy = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
const reportContentSecurityPolicy = "sandbox; default-src 'none'; style-src 'unsafe-inline'; img-src data:; connect-src 'none'; font-src 'none'; media-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"

const maxJSONBodyBytes int64 = 1 << 20

func withSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Cross-Origin-Opener-Policy", "same-origin")
		if strings.TrimSpace(w.Header().Get("Content-Security-Policy")) == "" {
			w.Header().Set("Content-Security-Policy", appContentSecurityPolicy)
		}
		next.ServeHTTP(w, r)
	})
}

func withTrustedOrigin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requiresTrustedOrigin(r.Method) && !hasTrustedOrigin(r) {
			http.Error(w, "跨站请求已被拒绝", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func requiresTrustedOrigin(method string) bool {
	switch method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		return true
	default:
		return false
	}
}

func hasTrustedOrigin(r *http.Request) bool {
	requestHost := normalizedHost(r.Host)
	if requestHost == "" {
		return false
	}
	if origin := strings.TrimSpace(r.Header.Get("Origin")); origin != "" {
		return sameHost(origin, requestHost)
	}
	if referer := strings.TrimSpace(r.Header.Get("Referer")); referer != "" {
		return sameHost(referer, requestHost)
	}
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))) {
	case "same-origin", "same-site", "none":
		return true
	default:
		return false
	}
}

func sameHost(raw, expected string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return false
	}
	return normalizedHost(parsed.Host) == expected
}

func normalizedHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	return host
}

func requestIsSecure(r *http.Request) bool {
	if r != nil && r.TLS != nil {
		return true
	}
	if r == nil {
		return false
	}
	proto := strings.ToLower(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")))
	return proto == "https"
}

func decodeStrictJSONBody(w http.ResponseWriter, r *http.Request, dst interface{}, maxBytes int64) error {
	if maxBytes <= 0 {
		maxBytes = maxJSONBodyBytes
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fmt.Errorf("request body must contain a single JSON object")
	}
	return nil
}

func sanitizeDownloadFilename(baseName, fallback string) string {
	name := strings.TrimSpace(baseName)
	if name == "" {
		name = fallback
	}
	replacer := strings.NewReplacer("\r", "_", "\n", "_", "\t", "_", "\"", "_", ";", "_", "/", "_", "\\", "_")
	name = replacer.Replace(name)
	name = strings.Trim(name, " .")
	if name == "" {
		return fallback
	}
	return name
}

func requireMethods(w http.ResponseWriter, r *http.Request, methods ...string) bool {
	for _, method := range methods {
		if r.Method == method {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(methods, ", "))
	http.Error(w, "请求方法不被允许", http.StatusMethodNotAllowed)
	return false
}

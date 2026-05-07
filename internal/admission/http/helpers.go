package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
)

const maxJSONBodyBytes int64 = 1 << 20

func writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
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

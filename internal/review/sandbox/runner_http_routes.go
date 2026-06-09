package sandbox

import (
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func extractNextStyleRoutes(source string) map[string][]string {
	out := make(map[string][]string)
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?m)export\s+(?:async\s+)?function\s+(GET|POST|PUT|PATCH|DELETE)\s*\(`),
		regexp.MustCompile(`(?m)export\s+const\s+(GET|POST|PUT|PATCH|DELETE)\s*=`),
		regexp.MustCompile(`(?m)export\s+(?:async\s+)?function\s+(load|actions)\s*\(`),
		regexp.MustCompile(`(?m)export\s+const\s+(load|actions)\s*=`),
	} {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) >= 2 {
				for _, method := range routeMethodsForExportedHandler(match[1]) {
					out["/"] = appendHTTPMethod(out["/"], method)
				}
			}
		}
	}
	return normalizeRouteMethods(out)
}

func routeMethodsForExportedHandler(name string) []string {
	switch strings.ToUpper(strings.TrimSpace(name)) {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		return []string{strings.ToUpper(strings.TrimSpace(name))}
	case "LOAD":
		return []string{"GET"}
	case "ACTIONS":
		return []string{"POST"}
	default:
		return nil
	}
}

func routePathFromFile(relPath string) string {
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	if relPath == "" {
		return ""
	}
	parts := strings.Split(relPath, "/")
	segments := make([]string, 0, len(parts))
	for i, part := range parts {
		name := strings.TrimSuffix(part, filepath.Ext(part))
		if i == len(parts)-1 && name == "" {
			name = strings.TrimSpace(part)
		}
		name = normalizeFileRouteSegment(name)
		if name == "" || name == "index" || name == "route" || name == "server" || strings.HasPrefix(name, "+") {
			continue
		}
		segments = append(segments, name)
	}
	if len(segments) == 0 {
		return "/"
	}
	return normalizeRoutePath("/" + strings.Join(segments, "/"))
}

func normalizeFileRouteSegment(segment string) string {
	segment = strings.TrimSpace(segment)
	if segment == "" {
		return ""
	}
	if strings.HasPrefix(segment, "[") && strings.HasSuffix(segment, "]") {
		return sampleRouteParamValue(strings.Trim(segment, "[]"))
	}
	return segment
}

func defaultHTTPProbePaths(paths []string) []string {
	ordered := prioritizeHTTPProbePaths(uniqueStrings(paths))
	fallbacks := []string{"/", "/health", "/healthz", "/ready", "/readyz", "/live", "/livez", "/status", "/metrics", "/ping", "/api/health", "/api/status", "/api/v1/health", "/webhook", "/callback"}
	for _, fallback := range fallbacks {
		if !stringSliceContains(ordered, fallback) {
			ordered = append(ordered, fallback)
		}
	}
	return limitHTTPProbePaths(prioritizeHTTPProbePaths(ordered), 24)
}

func prioritizeHTTPProbePaths(paths []string) []string {
	paths = uniqueStrings(paths)
	sort.SliceStable(paths, func(i, j int) bool {
		left := scoreHTTPProbePath(paths[i])
		right := scoreHTTPProbePath(paths[j])
		if left != right {
			return left > right
		}
		return len(paths[i]) < len(paths[j])
	})
	return paths
}

func scoreHTTPProbePath(path string) int {
	lower := strings.ToLower(strings.TrimSpace(path))
	score := 0
	if strings.Contains(lower, "?") {
		score += 70
	}
	for _, token := range []string{"health", "ready", "status", "ping", "live"} {
		if strings.Contains(lower, token) {
			score += 60
			break
		}
	}
	for _, token := range []string{"scan", "analyze", "check", "webhook", "callback", "submit", "ingest", "upload", "notify"} {
		if strings.Contains(lower, token) {
			score += 50
			break
		}
	}
	if lower == "/" {
		score += 10
	}
	if strings.HasPrefix(lower, "/api/") {
		score += 8
	}
	return score
}

func limitHTTPProbePaths(paths []string, max int) []string {
	if max <= 0 || len(paths) <= max {
		return append([]string{}, paths...)
	}
	return append([]string{}, paths[:max]...)
}

func extractNamedRoutePrefixes(source string, patterns ...*regexp.Regexp) map[string]string {
	out := make(map[string]string)
	for _, pattern := range patterns {
		if pattern == nil {
			continue
		}
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 3 {
				continue
			}
			var name, prefix string
			if strings.Contains(pattern.String(), `app\.use`) {
				prefix = normalizeRoutePath(match[1])
				name = strings.TrimSpace(match[2])
			} else {
				name = strings.TrimSpace(match[1])
				prefix = normalizeRoutePath(match[2])
			}
			if name == "" || prefix == "" {
				continue
			}
			out[name] = prefix
		}
	}
	return out
}

func normalizeRoutePath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	raw = normalizeDynamicRoutePath(raw)
	if !strings.HasPrefix(raw, "/") {
		raw = "/" + raw
	}
	raw = strings.TrimRight(raw, "/")
	if raw == "" {
		return "/"
	}
	return raw
}

func normalizeDynamicRoutePath(raw string) string {
	raw = regexp.MustCompile(`<(?:[^:<>/]+:)?[^<>/]+>`).ReplaceAllStringFunc(raw, func(token string) string {
		name := strings.Trim(token, "<>")
		if idx := strings.LastIndex(name, ":"); idx >= 0 {
			name = name[idx+1:]
		}
		return sampleRouteParamValue(name)
	})
	raw = regexp.MustCompile(`\{[^{}:/]+\}`).ReplaceAllStringFunc(raw, func(token string) string {
		return sampleRouteParamValue(strings.Trim(token, "{}"))
	})
	raw = regexp.MustCompile(`:([A-Za-z_][A-Za-z0-9_]*)`).ReplaceAllStringFunc(raw, func(token string) string {
		return sampleRouteParamValue(strings.TrimPrefix(token, ":"))
	})
	return raw
}

func sampleRouteParamValue(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.Contains(lower, "id"):
		return "1"
	case strings.Contains(lower, "page") || strings.Contains(lower, "limit") || strings.Contains(lower, "count"):
		return "1"
	case strings.Contains(lower, "uuid"):
		return "00000000-0000-0000-0000-000000000000"
	case strings.Contains(lower, "slug"):
		return "sample"
	case strings.Contains(lower, "name") || strings.Contains(lower, "user"):
		return "sample"
	default:
		return "sample"
	}
}

func joinRoutePaths(prefix string, route string) string {
	prefix = normalizeRoutePath(prefix)
	route = normalizeRoutePath(route)
	if prefix == "" {
		return route
	}
	if route == "" || route == "/" {
		return prefix
	}
	if prefix == "/" {
		return route
	}
	return strings.TrimRight(prefix, "/") + route
}

func sanitizeQueryParamName(raw string) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func expandRoutesWithQueryParams(routes []string, params []string) []string {
	routes = uniqueStrings(routes)
	params = uniqueStrings(params)
	if len(routes) == 0 || len(params) == 0 {
		return routes
	}
	out := append([]string{}, routes...)
	query := buildSampleQuery(params)
	if query == "" {
		return out
	}
	for _, route := range routes {
		if strings.Contains(route, "?") {
			continue
		}
		out = append(out, route+"?"+query)
	}
	return uniqueStrings(out)
}

func expandRouteMethodsWithQueryParams(routeMethods map[string][]string, params []string) map[string][]string {
	out := cloneStringSliceMap(routeMethods)
	query := buildSampleQuery(uniqueStrings(params))
	if query == "" {
		return out
	}
	for route, methods := range routeMethods {
		if strings.Contains(route, "?") {
			continue
		}
		out[route+"?"+query] = append([]string{}, methods...)
	}
	return out
}

func buildSampleQuery(params []string) string {
	parts := make([]string, 0, len(params))
	for _, param := range params {
		param = sanitizeQueryParamName(param)
		if param == "" {
			continue
		}
		parts = append(parts, param+"="+sampleQueryParamValue(param))
		if len(parts) >= 4 {
			break
		}
	}
	return strings.Join(parts, "&")
}

func sampleQueryParamValue(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))
	switch {
	case strings.Contains(lower, "url") || strings.Contains(lower, "target") || strings.Contains(lower, "callback"):
		return "http%3A%2F%2Fexample.com"
	case strings.Contains(lower, "id") || strings.Contains(lower, "page") || strings.Contains(lower, "limit"):
		return "1"
	case strings.Contains(lower, "file"):
		return "sample.txt"
	default:
		return "sample"
	}
}

func appendHTTPMethod(methods []string, method string) []string {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" || method == "ALL" {
		return methods
	}
	switch method {
	case "GET", "POST", "PUT", "PATCH", "DELETE":
		if !stringSliceContains(methods, method) {
			methods = append(methods, method)
		}
	}
	return methods
}

func normalizeRouteMethods(in map[string][]string) map[string][]string {
	out := make(map[string][]string, len(in))
	for path, methods := range in {
		path = normalizeRoutePath(path)
		if path == "" {
			continue
		}
		for _, method := range methods {
			out[path] = appendHTTPMethod(out[path], method)
		}
	}
	return out
}

func cloneStringSliceMap(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for key, values := range in {
		out[key] = append([]string{}, values...)
	}
	return out
}

func mergeStringSliceMap(dst map[string][]string, src map[string][]string) {
	if dst == nil || len(src) == 0 {
		return
	}
	for key, values := range src {
		for _, value := range values {
			dst[key] = appendHTTPMethod(dst[key], value)
		}
	}
}

func defaultHTTPProbePorts(ports []int) []int {
	ordered := limitIntSlice(uniqueInts(ports), 4)
	for _, fallback := range []int{8000, 8080, 5000, 3000} {
		if !intSliceContains(ordered, fallback) {
			ordered = append(ordered, fallback)
		}
	}
	return limitIntSlice(ordered, maxHTTPProbePorts)
}

func firstHTTPProbePort(ports []int) int {
	ports = defaultHTTPProbePorts(ports)
	if len(ports) == 0 {
		return 8000
	}
	return ports[0]
}

func buildHTTPProbeEnv(ports []int) map[string]string {
	port := strconv.Itoa(firstHTTPProbePort(ports))
	return map[string]string{
		"SERVER_MODE":      "1",
		"HTTP_PROBE":       "1",
		"PYTHONUNBUFFERED": "1",
		"PORT":             port,
		"FLASK_RUN_HOST":   "0.0.0.0",
		"FLASK_RUN_PORT":   port,
	}
}

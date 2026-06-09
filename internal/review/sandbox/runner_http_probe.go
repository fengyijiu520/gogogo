package sandbox

import "strings"

type httpProbeAttempt struct {
	Method      string `json:"method"`
	ContentType string `json:"content_type,omitempty"`
	Body        string `json:"body,omitempty"`
}

const maxHTTPProbeAttempts = 8
const maxHTTPProbePorts = 6
const maxHTTPProbeRequests = 80

type semanticHTTPPayload struct {
	JSON string
	Form string
}

func buildHTTPProbeAttempts(paths []string, methods []string) []httpProbeAttempt {
	hasMutationHint := false
	for _, path := range paths {
		lower := strings.ToLower(strings.TrimSpace(path))
		if lower == "" {
			continue
		}
		for _, token := range []string{"/webhook", "/hook", "/callback", "/submit", "/ingest", "/upload", "/notify", "/report"} {
			if strings.Contains(lower, token) {
				hasMutationHint = true
				break
			}
		}
		if hasMutationHint {
			break
		}
	}
	attempts := make([]httpProbeAttempt, 0, 3)
	orderedMethods := prioritizeHTTPProbeMethods(methods, hasMutationHint)
	if len(orderedMethods) > 0 {
		for _, method := range orderedMethods {
			attempts = appendHTTPProbeMethodAttempts(attempts, method, paths)
		}
		return limitHTTPProbeAttempts(uniqueHTTPProbeAttempts(attempts), maxHTTPProbeAttempts)
	}
	if hasMutationHint {
		attempts = append(appendHTTPProbeMethodAttempts(attempts, "POST", paths), httpProbeAttempt{Method: "GET"})
		return limitHTTPProbeAttempts(uniqueHTTPProbeAttempts(attempts), maxHTTPProbeAttempts)
	}
	attempts = append(attempts,
		httpProbeAttempt{Method: "GET"},
		httpProbeAttempt{Method: "POST", ContentType: "application/json", Body: `{"sandbox":true,"source":"skill-scanner"}`},
		httpProbeAttempt{Method: "POST", ContentType: "application/x-www-form-urlencoded", Body: "sandbox=true&source=skill-scanner"},
	)
	return limitHTTPProbeAttempts(uniqueHTTPProbeAttempts(attempts), maxHTTPProbeAttempts)
}

func buildHTTPProbeAttemptsByPath(paths []string, methods []string, routeMethods map[string][]string) map[string][]httpProbeAttempt {
	paths = defaultHTTPProbePaths(paths)
	out := make(map[string][]httpProbeAttempt)
	for _, path := range paths {
		pathMethods := routeMethods[normalizeRoutePath(path)]
		if len(pathMethods) == 0 {
			pathMethods = methods
		}
		attempts := buildHTTPProbeAttempts([]string{path}, pathMethods)
		if len(attempts) > 0 {
			out[path] = attempts
		}
	}
	return out
}

func prioritizeHTTPProbeMethods(methods []string, hasMutationHint bool) []string {
	normalized := make([]string, 0, len(methods)+1)
	for _, method := range methods {
		normalized = appendHTTPMethod(normalized, method)
	}
	if hasMutationHint {
		normalized = appendHTTPMethod(normalized, "POST")
		normalized = appendHTTPMethod(normalized, "GET")
	}
	if len(normalized) == 0 {
		return nil
	}
	priority := []string{"POST", "PUT", "PATCH", "DELETE", "GET"}
	ordered := make([]string, 0, len(normalized))
	for _, method := range priority {
		if stringSliceContains(normalized, method) {
			ordered = append(ordered, method)
		}
	}
	return ordered
}

func appendHTTPProbeMethodAttempts(attempts []httpProbeAttempt, method string, paths []string) []httpProbeAttempt {
	method = strings.ToUpper(strings.TrimSpace(method))
	switch method {
	case "POST", "PUT", "PATCH", "DELETE":
		for _, body := range buildSemanticHTTPPayloads(paths) {
			attempts = append(attempts, httpProbeAttempt{Method: method, ContentType: "application/json", Body: body.JSON})
			attempts = append(attempts, httpProbeAttempt{Method: method, ContentType: "application/x-www-form-urlencoded", Body: body.Form})
		}
		attempts = append(attempts,
			httpProbeAttempt{Method: method, ContentType: "application/json", Body: `{"sandbox":true,"source":"skill-scanner"}`},
			httpProbeAttempt{Method: method, ContentType: "application/x-www-form-urlencoded", Body: "sandbox=true&source=skill-scanner"},
		)
	case "GET":
		attempts = append(attempts, httpProbeAttempt{Method: "GET"})
	}
	return attempts
}

func uniqueHTTPProbeAttempts(items []httpProbeAttempt) []httpProbeAttempt {
	seen := make(map[string]struct{}, len(items))
	out := make([]httpProbeAttempt, 0, len(items))
	for _, item := range items {
		item.Method = strings.ToUpper(strings.TrimSpace(item.Method))
		item.ContentType = strings.TrimSpace(item.ContentType)
		item.Body = strings.TrimSpace(item.Body)
		if item.Method == "" {
			continue
		}
		key := item.Method + "\x00" + item.ContentType + "\x00" + item.Body
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func limitHTTPProbeAttempts(items []httpProbeAttempt, limit int) []httpProbeAttempt {
	if limit <= 0 || len(items) <= limit {
		return items
	}
	return append([]httpProbeAttempt{}, items[:limit]...)
}

func buildSemanticHTTPPayloads(paths []string) []semanticHTTPPayload {
	payloads := make([]semanticHTTPPayload, 0, 4)
	for _, path := range paths {
		lower := strings.ToLower(strings.TrimSpace(path))
		switch {
		case strings.Contains(lower, "scan") || strings.Contains(lower, "analyze") || strings.Contains(lower, "check"):
			payloads = append(payloads, semanticHTTPPayload{JSON: `{"url":"http://example.com","target":"http://example.com","sandbox":true}`, Form: "url=http%3A%2F%2Fexample.com&target=http%3A%2F%2Fexample.com&sandbox=true"})
		case strings.Contains(lower, "webhook") || strings.Contains(lower, "hook") || strings.Contains(lower, "callback") || strings.Contains(lower, "notify"):
			payloads = append(payloads, semanticHTTPPayload{JSON: `{"event":"sandbox.test","callback":"http://example.com/callback","sandbox":true}`, Form: "event=sandbox.test&callback=http%3A%2F%2Fexample.com%2Fcallback&sandbox=true"})
		case strings.Contains(lower, "upload") || strings.Contains(lower, "submit") || strings.Contains(lower, "ingest"):
			payloads = append(payloads, semanticHTTPPayload{JSON: `{"filename":"sample.txt","content":"sandbox","sandbox":true}`, Form: "filename=sample.txt&content=sandbox&sandbox=true"})
		}
	}
	return uniqueSemanticHTTPPayloads(payloads)
}

func uniqueSemanticHTTPPayloads(items []semanticHTTPPayload) []semanticHTTPPayload {
	seen := make(map[string]struct{}, len(items))
	out := make([]semanticHTTPPayload, 0, len(items))
	for _, item := range items {
		key := item.JSON + "\x00" + item.Form
		if strings.TrimSpace(item.JSON) == "" || strings.TrimSpace(item.Form) == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

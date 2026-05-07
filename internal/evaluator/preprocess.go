package evaluator

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"skill-scanner/internal/llm"
)

var (
	base64TokenPattern = regexp.MustCompile(`(?i)(?:[A-Za-z0-9+/]{20,}={0,2})`)
	hexTokenPattern    = regexp.MustCompile(`(?i)\b(?:[0-9a-f]{24,})\b`)
	concatLiteralRe    = regexp.MustCompile(`(?s)(["'][^"']{4,}["']\s*(?:\+\s*["'][^"']{1,}["']\s*){1,})`)
	joinLiteralRe      = regexp.MustCompile(`(?s)\[((?:\s*["'][^"']+["']\s*,?){2,})\s*\]\.join\(\s*["']?([^"')]*)["']?\s*\)`)
	fromCharCodeRe     = regexp.MustCompile(`(?i)string\.fromcharcode\(([^)]{4,})\)`)
	templateLiteralRe  = regexp.MustCompile("(?s)`([^`]{12,})`")
	assignLiteralRe    = regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*(["'][^"']{4,}["'])`)
	assignJoinRe       = regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*(\[((?:\s*["'][^"']+["']\s*,?){2,})\s*\]\.join\(\s*["']?([^"')]*)["']?\s*\))`)
	assignTemplateRe   = regexp.MustCompile("(?m)(?:const|let|var)\\s+([A-Za-z_][\\w]*)\\s*=\\s*(`[^`]{8,}`)")
	assignAliasRe      = regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*([A-Za-z_][\w]*)\s*$`)
	assignConcatRe     = regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*([^\n;]+(?:\+[^\n;]+)+)`) 
	assignWrapperRe    = regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*(.+?)\s*$`)
	assignCallRe       = regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][\w]*)\s*=\s*([A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)*\([^\n;]*\))`)
	templateRefRe      = regexp.MustCompile(`\$\{\s*([A-Za-z_][\w]*)\s*\}`)
	concatTokenRe      = regexp.MustCompile(`(["'][^"']*["']|[A-Za-z_][\w]*)`)
)

func BuildPreprocessedContent(content string) string {
	sections := collectDecodedSections(content)
	if len(sections) == 0 {
		return ""
	}
	return "\n[preprocessed-decoded]\n" + strings.Join(sections, "\n")
}

func BuildPreprocessedContentWithLLM(ctx context.Context, client llm.Client, name, content string) string {
	base := BuildPreprocessedContent(content)
	if client == nil || !ShouldUseLLMForObfuscation(content, base) {
		return base
	}
	analysis, err := client.AnalyzeObfuscatedContent(ctx, name, trimObfuscationInput(content, base))
	if err != nil || analysis == nil || !analysis.LikelyObfuscated {
		return base
	}
	sections := make([]string, 0, 2)
	if strings.TrimSpace(base) != "" {
		sections = append(sections, strings.TrimSpace(base))
	}
	sections = append(sections, formatLLMObfuscationSection(analysis))
	return strings.Join(sections, "\n\n")
}

func BuildSourceFile(ctx context.Context, client llm.Client, path, content, language string) SourceFile {
	return SourceFile{
		Path:                path,
		Content:             content,
		PreprocessedContent: BuildPreprocessedContentWithLLM(ctx, client, filepath.Base(path), content),
		Language:            language,
	}
}

func ShouldUseLLMForObfuscation(content, preprocessed string) bool {
	if strings.TrimSpace(preprocessed) != "" {
		return true
	}
	if estimateTextEntropy(content) >= 5.2 {
		return true
	}
	return len(longEncodedTokens(content)) > 0
}

func collectDecodedSections(content string) []string {
	seen := make(map[string]struct{})
	var sections []string
	for _, merged := range mergeStringLiteralConcats(content) {
		for _, entry := range decodeCandidateLayers(merged) {
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			sections = append(sections, entry)
		}
	}

	for _, joined := range mergeJoinStringLiterals(content) {
		for _, entry := range decodeCandidateLayers(joined) {
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			sections = append(sections, entry)
		}
	}

	for _, decoded := range decodeFromCharCodeCalls(content) {
		if _, exists := seen[decoded]; exists {
			continue
		}
		seen[decoded] = struct{}{}
		sections = append(sections, decoded)
		for _, entry := range decodeCandidateLayers(strings.TrimSpace(strings.TrimPrefix(decoded, "charcode[1]: "))) {
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			sections = append(sections, entry)
		}
	}

	for _, rendered := range extractTemplateLiterals(content) {
		if _, exists := seen[rendered]; exists {
			continue
		}
		seen[rendered] = struct{}{}
		sections = append(sections, rendered)
		for _, entry := range decodeCandidateLayers(strings.TrimSpace(strings.TrimPrefix(rendered, "template[1]: "))) {
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			sections = append(sections, entry)
		}
	}

	for _, rendered := range resolveVariableLiteralCandidates(content) {
		if _, exists := seen[rendered]; exists {
			continue
		}
		seen[rendered] = struct{}{}
		sections = append(sections, rendered)
		for _, entry := range decodeCandidateLayers(strings.TrimSpace(strings.TrimPrefix(rendered, "variable[1]: "))) {
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			sections = append(sections, entry)
		}
	}

	for _, token := range base64TokenPattern.FindAllString(content, -1) {
		for _, entry := range decodeCandidateLayers(token) {
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			sections = append(sections, entry)
		}
	}

	for _, token := range hexTokenPattern.FindAllString(content, -1) {
		for _, entry := range decodeCandidateLayers(token) {
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			sections = append(sections, entry)
		}
	}
	for _, token := range longEncodedTokens(content) {
		for _, entry := range decodeCandidateLayers(token) {
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			sections = append(sections, entry)
		}
	}

	sort.Strings(sections)
	return sections
}

func mergeStringLiteralConcats(content string) []string {
	matches := concatLiteralRe.FindAllString(content, -1)
	if len(matches) == 0 {
		return nil
	}
	merged := make([]string, 0, len(matches))
	for _, match := range matches {
		parts := regexp.MustCompile(`["']([^"']+)["']`).FindAllStringSubmatch(match, -1)
		if len(parts) < 2 {
			continue
		}
		var b strings.Builder
		for _, part := range parts {
			b.WriteString(part[1])
		}
		if b.Len() >= 16 {
			merged = append(merged, b.String())
		}
	}
	return merged
}

func mergeJoinStringLiterals(content string) []string {
	matches := joinLiteralRe.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil
	}
	merged := make([]string, 0, len(matches))
	for _, match := range matches {
		parts := regexp.MustCompile(`['"]([^'"]+)['"]`).FindAllStringSubmatch(match[1], -1)
		if len(parts) < 2 {
			continue
		}
		sep := match[2]
		items := make([]string, 0, len(parts))
		for _, part := range parts {
			items = append(items, part[1])
		}
		joined := strings.Join(items, sep)
		if len(joined) >= 16 {
			merged = append(merged, joined)
		}
	}
	return merged
}

func decodeFromCharCodeCalls(content string) []string {
	matches := fromCharCodeRe.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil
	}
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, match := range matches {
		raw := strings.TrimSpace(match[1])
		if raw == "" {
			continue
		}
		segments := strings.Split(raw, ",")
		runes := make([]rune, 0, len(segments))
		valid := true
		for _, segment := range segments {
			segment = strings.TrimSpace(segment)
			if segment == "" {
				valid = false
				break
			}
			value, ok := parseCharCodeValue(segment)
			if !ok {
				valid = false
				break
			}
			runes = append(runes, rune(value))
		}
		if !valid || len(runes) < 8 {
			continue
		}
		decoded := strings.TrimSpace(string(runes))
		if !looksDecodedInteresting(decoded) {
			continue
		}
		entry := "charcode[1]: " + strings.ReplaceAll(decoded, "\x00", "")
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	return out
}

func extractTemplateLiterals(content string) []string {
	matches := templateLiteralRe.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return nil
	}
	vars := collectAssignedStringLiterals(content)
	out := make([]string, 0, len(matches))
	seen := map[string]struct{}{}
	for _, match := range matches {
		decoded := strings.TrimSpace(renderTemplateWithVars(match[1], vars))
		if decoded == "" || !looksDecodedInteresting(decoded) {
			continue
		}
		entry := "template[1]: " + strings.ReplaceAll(decoded, "\x00", "")
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	return out
}

func resolveVariableLiteralCandidates(content string) []string {
	vars := collectAssignedStringLiterals(content)
	if len(vars) == 0 {
		return nil
	}
	out := make([]string, 0, len(vars))
	seen := map[string]struct{}{}
	for _, value := range vars {
		if len(value) < 8 || !looksDecodedInteresting(value) {
			continue
		}
		entry := "variable[1]: " + strings.ReplaceAll(strings.TrimSpace(value), "\x00", "")
		if _, exists := seen[entry]; exists {
			continue
		}
		seen[entry] = struct{}{}
		out = append(out, entry)
	}
	return out
}

func collectAssignedStringLiterals(content string) map[string]string {
	vars := map[string]string{}
	for _, match := range assignLiteralRe.FindAllStringSubmatch(content, -1) {
		vars[match[1]] = strings.Trim(match[2], `"'`)
	}
	for _, match := range assignJoinRe.FindAllStringSubmatch(content, -1) {
		parts := regexp.MustCompile(`['"]([^'"]+)['"]`).FindAllStringSubmatch(match[2], -1)
		items := make([]string, 0, len(parts))
		for _, part := range parts {
			items = append(items, part[1])
		}
		vars[match[1]] = strings.Join(items, match[3])
	}
	for _, match := range assignTemplateRe.FindAllStringSubmatch(content, -1) {
		vars[match[1]] = strings.Trim(match[2], "`")
	}
	for range 4 {
		changed := false
		for _, match := range assignConcatRe.FindAllStringSubmatch(content, -1) {
			resolved, ok := resolveSimpleConcatExpression(match[2], vars)
			if ok && resolved != "" && vars[match[1]] != resolved {
				vars[match[1]] = resolved
				changed = true
			}
		}
		for _, match := range assignTemplateRe.FindAllStringSubmatch(content, -1) {
			rendered := renderTemplateWithVars(strings.Trim(match[2], "`"), vars)
			if rendered != vars[match[1]] {
				vars[match[1]] = rendered
				changed = true
			}
		}
		for _, match := range assignAliasRe.FindAllStringSubmatch(content, -1) {
			if value, ok := vars[match[2]]; ok && value != "" && vars[match[1]] != value {
				vars[match[1]] = value
				changed = true
			}
		}
		for _, match := range assignWrapperRe.FindAllStringSubmatch(content, -1) {
			if value, ok := resolvePassThroughWrapperExpression(match[2], vars); ok && value != "" && vars[match[1]] != value {
				vars[match[1]] = value
				changed = true
			}
		}
		for _, match := range assignCallRe.FindAllStringSubmatch(content, -1) {
			if value, ok := resolvePassThroughWrapperExpression(match[2], vars); ok && value != "" && vars[match[1]] != value {
				vars[match[1]] = value
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return vars
}

func isPassThroughWrapper(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "trimspace", "trim", "trimprefix", "trimsuffix", "tolower", "toupper", "sanitize", "clean", "strip", "replaceall", "replace", "join", "format", "sprintf", "abs", "resolve", "normalize", "base", "basename", "dir", "dirname":
		return true
	default:
		return false
	}
}

func resolvePassThroughWrapperExpression(expr string, vars map[string]string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || len(vars) == 0 {
		return "", false
	}
	for depth := 0; depth < 4; depth++ {
		name, inner, ok := splitWrapperCall(expr)
		if !ok || !isPassThroughWrapper(name) {
			break
		}
		expr = inner
	}
	expr = strings.TrimSpace(expr)
	if value, ok := vars[expr]; ok && value != "" {
		return value, true
	}
	return "", false
}

func splitWrapperCall(expr string) (string, string, bool) {
	open := strings.Index(expr, "(")
	close := strings.LastIndex(expr, ")")
	if open <= 0 || close <= open || close != len(expr)-1 {
		return "", "", false
	}
	name := strings.TrimSpace(expr[:open])
	if dot := strings.LastIndex(name, "."); dot >= 0 {
		name = name[dot+1:]
	}
	inner := normalizeWrapperArguments(strings.TrimSpace(expr[open+1:close]), name)
	if name == "" || inner == "" {
		return "", "", false
	}
	return name, inner, true
}

func normalizeWrapperArguments(args string, name string) string {
	args = strings.TrimSpace(args)
	if args == "" {
		return ""
	}
	parts := splitCallArguments(args)
	if len(parts) == 0 {
		return ""
	}
	name = strings.ToLower(strings.TrimSpace(name))
	switch name {
	case "replace", "replaceall", "trim", "trimprefix", "trimsuffix", "join":
		return parts[0]
	case "format", "sprintf":
		if len(parts) >= 2 {
			return parts[1]
		}
		return ""
	default:
		if len(parts) == 1 {
			return parts[0]
		}
		return ""
	}
}

func splitCallArguments(args string) []string {
	args = strings.TrimSpace(args)
	if args == "" {
		return nil
	}
	parts := make([]string, 0, 4)
	start := 0
	depth := 0
	quote := byte(0)
	for i := 0; i < len(args); i++ {
		ch := args[i]
		if quote != 0 {
			if ch == quote && (i == 0 || args[i-1] != '\\') {
				quote = 0
			}
			continue
		}
		switch ch {
		case '\'', '"', '`':
			quote = ch
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case ',':
			if depth == 0 {
				part := strings.TrimSpace(args[start:i])
				if part != "" {
					parts = append(parts, part)
				}
				start = i + 1
			}
		}
	}
	if tail := strings.TrimSpace(args[start:]); tail != "" {
		parts = append(parts, tail)
	}
	return parts
}

func resolveSimpleConcatExpression(expr string, vars map[string]string) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || !strings.Contains(expr, "+") {
		return "", false
	}
	tokens := concatTokenRe.FindAllString(expr, -1)
	if len(tokens) < 2 {
		return "", false
	}
	var b strings.Builder
	matched := 0
	for _, token := range tokens {
		token = strings.TrimSpace(token)
		switch {
		case len(token) >= 2 && ((strings.HasPrefix(token, "\"") && strings.HasSuffix(token, "\"")) || (strings.HasPrefix(token, "'") && strings.HasSuffix(token, "'"))):
			b.WriteString(strings.Trim(token, `"'`))
			matched++
		case vars[token] != "":
			b.WriteString(vars[token])
			matched++
		default:
			return "", false
		}
	}
	if matched < 2 || b.Len() < 8 {
		return "", false
	}
	return b.String(), true
}

func renderTemplateWithVars(template string, vars map[string]string) string {
	if template == "" || len(vars) == 0 {
		return template
	}
	return templateRefRe.ReplaceAllStringFunc(template, func(expr string) string {
		parts := templateRefRe.FindStringSubmatch(expr)
		if len(parts) != 2 {
			return expr
		}
		if value, ok := vars[parts[1]]; ok && value != "" {
			return value
		}
		return expr
	})
}

func parseCharCodeValue(raw string) (int64, bool) {
	raw = strings.TrimSpace(strings.TrimSuffix(raw, ")"))
	if raw == "" {
		return 0, false
	}
	base := 10
	if strings.HasPrefix(strings.ToLower(raw), "0x") {
		base = 16
		raw = raw[2:]
	}
	value, err := strconv.ParseInt(raw, base, 32)
	if err != nil || value < 0 || value > 0x10ffff {
		return 0, false
	}
	return value, true
}

func decodeCandidateLayers(token string) []string {
	seen := map[string]struct{}{}
	out := []string{}
	current := strings.TrimSpace(token)
	for depth := 0; depth < 3 && current != ""; depth++ {
		if decoded, ok := decodeBase64CandidateRelaxed(current); ok {
			entry := fmt.Sprintf("base64[%d]: %s", depth+1, decoded)
			if _, exists := seen[entry]; !exists {
				seen[entry] = struct{}{}
				if depth > 0 || looksDecodedInteresting(decoded) {
					out = append(out, entry)
				}
			}
			current = decoded
			continue
		}
		if decoded, ok := decodeHexCandidateRelaxed(current); ok {
			entry := fmt.Sprintf("hex[%d]: %s", depth+1, decoded)
			if _, exists := seen[entry]; !exists {
				seen[entry] = struct{}{}
				if depth > 0 || looksDecodedInteresting(decoded) {
					out = append(out, entry)
				}
			}
			current = decoded
			continue
		}
		break
	}
	return out
}

func decodeBase64CandidateRelaxed(token string) (string, bool) {
	if len(token)%4 != 0 {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", false
	}
	return normalizeDecodedCandidateRelaxed(decoded)
}

func decodeHexCandidateRelaxed(token string) (string, bool) {
	if len(token)%2 != 0 {
		return "", false
	}
	decoded, err := hex.DecodeString(token)
	if err != nil {
		return "", false
	}
	return normalizeDecodedCandidateRelaxed(decoded)
}

func normalizeDecodedCandidateRelaxed(decoded []byte) (string, bool) {
	if len(decoded) < 8 || !utf8.Valid(decoded) {
		return "", false
	}
	text := strings.TrimSpace(string(decoded))
	if len(text) < 8 || len(text) > 400 {
		return "", false
	}
	printable := 0
	for _, r := range text {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			printable++
		}
	}
	if printable*100/len([]rune(text)) < 85 {
		return "", false
	}
	return strings.ReplaceAll(text, "\x00", ""), true
}

func decodeBase64Candidate(token string) (string, bool) {
	if len(token)%4 != 0 {
		return "", false
	}
	decoded, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return "", false
	}
	return normalizeDecodedCandidate(decoded)
}

func decodeHexCandidate(token string) (string, bool) {
	if len(token)%2 != 0 {
		return "", false
	}
	decoded, err := hex.DecodeString(token)
	if err != nil {
		return "", false
	}
	return normalizeDecodedCandidate(decoded)
}

func normalizeDecodedCandidate(decoded []byte) (string, bool) {
	if len(decoded) < 8 || !utf8.Valid(decoded) {
		return "", false
	}
	text := strings.TrimSpace(string(decoded))
	if len(text) < 8 || len(text) > 400 {
		return "", false
	}
	printable := 0
	for _, r := range text {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r < 127) {
			printable++
		}
	}
	if printable*100/len([]rune(text)) < 85 {
		return "", false
	}
	if !looksDecodedInteresting(text) {
		return "", false
	}
	return strings.ReplaceAll(text, "\x00", ""), true
}

func looksDecodedInteresting(text string) bool {
	lower := strings.ToLower(text)
	keywords := []string{
		"http", "https", "fetch", "exec", "eval", "system", "bash", "sh ", "cmd",
		"token", "secret", "password", "api", "curl", "wget", "socket", "process.env",
	}
	for _, keyword := range keywords {
		if strings.Contains(lower, keyword) {
			return true
		}
	}
	return strings.ContainsAny(text, "/\\(){}[]:=;.")
}

func trimObfuscationInput(content, preprocessed string) string {
	content = strings.TrimSpace(content)
	if len(content) > 2400 {
		content = content[:2400]
	}
	preprocessed = strings.TrimSpace(preprocessed)
	if len(preprocessed) > 1600 {
		preprocessed = preprocessed[:1600]
	}
	if preprocessed == "" {
		return content
	}
	return content + "\n\n" + preprocessed
}

func formatLLMObfuscationSection(result *llm.ObfuscationAnalysisResult) string {
	parts := []string{"[llm-obfuscation-analysis]"}
	if result.Technique != "" {
		parts = append(parts, "technique: "+result.Technique)
	}
	if result.Confidence != "" {
		parts = append(parts, "confidence: "+result.Confidence)
	}
	if result.Summary != "" {
		parts = append(parts, "summary: "+result.Summary)
	}
	if result.DecodedText != "" {
		parts = append(parts, "decoded: "+result.DecodedText)
	}
	if len(result.BenignIndicators) > 0 {
		parts = append(parts, "benign: "+strings.Join(result.BenignIndicators, " | "))
	}
	if len(result.RiskIndicators) > 0 {
		parts = append(parts, "risk: "+strings.Join(result.RiskIndicators, " | "))
	}
	return strings.Join(parts, "\n")
}

func estimateTextEntropy(content string) float64 {
	if content == "" {
		return 0
	}
	counts := map[rune]int{}
	total := 0
	for _, r := range content {
		counts[r]++
		total++
	}
	entropy := 0.0
	for _, count := range counts {
		p := float64(count) / float64(total)
		entropy -= p * math.Log2(p)
	}
	return entropy
}

func longEncodedTokens(content string) []string {
	var tokens []string
	for _, token := range base64TokenPattern.FindAllString(content, -1) {
		if len(token) >= 48 {
			tokens = append(tokens, token)
		}
	}
	for _, token := range hexTokenPattern.FindAllString(content, -1) {
		if len(token) >= 48 {
			tokens = append(tokens, token)
		}
	}
	return tokens
}

func ExtractDataFlowSignals(content, preprocessed string) []string {
	joined := strings.ToLower(strings.TrimSpace(content + "\n" + preprocessed))
	if joined == "" {
		return nil
	}
	signals := make([]string, 0, 4)
	decodedMarkers := []string{"decoded:", "base64[", "hex[", "charcode[", "template[", "variable["}
	hasDecodedSignal := false
	for _, marker := range decodedMarkers {
		if strings.Contains(joined, marker) {
			hasDecodedSignal = true
			break
		}
	}
	decodedVars := decodedVariableNames(content)
	flowVars := propagateDecodedVariableNames(content, decodedVars)
	if hasDecodedSignal && hasVariableFlowToSink(content, decodedVars, executionSinkPattern()) {
		signals = append(signals, "解码变量疑似流向执行链")
	}
	if hasDecodedSignal && hasVariableFlowToSink(content, flowVars, executionSinkPattern()) {
		signals = append(signals, "解码变量经多跳传播后疑似流向执行链")
	}
	if hasDecodedSignal && hasVariableFlowToSink(content, decodedVars, networkSinkPattern()) {
		signals = append(signals, "解码变量疑似流向网络链")
	}
	if hasDecodedSignal && hasVariableFlowToSink(content, flowVars, networkSinkPattern()) {
		signals = append(signals, "解码变量经多跳传播后疑似流向网络链")
	}
	if hasDecodedSignal && hasVariableFlowToSink(content, decodedVars, commandSinkPattern()) {
		signals = append(signals, "解码变量疑似流向命令构造链")
	}
	if hasDecodedSignal && hasVariableFlowToSink(content, flowVars, commandSinkPattern()) {
		signals = append(signals, "解码变量经多跳传播后疑似流向命令构造链")
	}
	if hasDecodedSignal &&
		(strings.Contains(joined, "exec") || strings.Contains(joined, "eval") || strings.Contains(joined, "subprocess") || strings.Contains(joined, "os.system")) {
		signals = append(signals, "解码结果疑似流向执行链")
	}
	if hasDecodedSignal &&
		(strings.Contains(joined, "http") || strings.Contains(joined, "fetch") || strings.Contains(joined, "axios") || strings.Contains(joined, "requests.")) {
		signals = append(signals, "解码结果疑似流向网络链")
	}
	if hasDecodedSignal &&
		(strings.Contains(joined, "bash") || strings.Contains(joined, "curl") || strings.Contains(joined, "wget") || strings.Contains(joined, "cmd")) {
		signals = append(signals, "解码结果疑似流向命令构造链")
	}
	return uniqueSortedStrings(signals)
}

func decodedVariableNames(content string) []string {
	vars := collectAssignedStringLiterals(content)
	if len(vars) == 0 {
		return nil
	}
	out := make([]string, 0, len(vars))
	for name, value := range vars {
		trimmed := strings.TrimSpace(value)
		if trimmed == "" {
			continue
		}
		if len(decodeCandidateLayers(trimmed)) > 0 || looksDecodedInteresting(trimmed) {
			out = append(out, name)
		}
	}
	return uniqueSortedStrings(out)
}

func propagateDecodedVariableNames(content string, seeds []string) []string {
	if len(seeds) == 0 {
		return nil
	}
	known := make(map[string]struct{}, len(seeds))
	for _, item := range seeds {
		item = strings.TrimSpace(item)
		if item != "" {
			known[item] = struct{}{}
		}
	}
	for depth := 0; depth < 4; depth++ {
		changed := false
		for _, match := range assignAliasRe.FindAllStringSubmatch(content, -1) {
			if _, ok := known[strings.TrimSpace(match[2])]; ok {
				if _, exists := known[strings.TrimSpace(match[1])]; !exists {
					known[strings.TrimSpace(match[1])] = struct{}{}
					changed = true
				}
			}
		}
		for _, match := range assignConcatRe.FindAllStringSubmatch(content, -1) {
			expr := strings.TrimSpace(match[2])
			for name := range known {
				if strings.Contains(expr, name) {
					if _, exists := known[strings.TrimSpace(match[1])]; !exists {
						known[strings.TrimSpace(match[1])] = struct{}{}
						changed = true
					}
					break
				}
			}
		}
		for _, match := range assignCallRe.FindAllStringSubmatch(content, -1) {
			expr := strings.TrimSpace(match[2])
			for name := range known {
				if strings.Contains(expr, name) {
					if _, exists := known[strings.TrimSpace(match[1])]; !exists {
						known[strings.TrimSpace(match[1])] = struct{}{}
						changed = true
					}
					break
				}
			}
		}
		for _, match := range assignTemplateRe.FindAllStringSubmatch(content, -1) {
			templateBody := strings.Trim(match[2], "`")
			for name := range known {
				if strings.Contains(templateBody, "${"+name+"}") {
					if _, exists := known[strings.TrimSpace(match[1])]; !exists {
						known[strings.TrimSpace(match[1])] = struct{}{}
						changed = true
					}
					break
				}
			}
		}
		for _, match := range assignWrapperRe.FindAllStringSubmatch(content, -1) {
			expr := strings.TrimSpace(match[2])
			resolvedExpr, ok := resolveDecodedFlowWrapperExpression(expr, known)
			if ok && resolvedExpr != "" {
				if _, exists := known[strings.TrimSpace(match[1])]; !exists {
					known[strings.TrimSpace(match[1])] = struct{}{}
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}
	out := make([]string, 0, len(known))
	for name := range known {
		out = append(out, name)
	}
	return uniqueSortedStrings(out)
}

func resolveDecodedFlowWrapperExpression(expr string, known map[string]struct{}) (string, bool) {
	expr = strings.TrimSpace(expr)
	if expr == "" || len(known) == 0 {
		return "", false
	}
	for depth := 0; depth < 4; depth++ {
		name, inner, ok := splitWrapperCall(expr)
		if !ok || !isPassThroughWrapper(name) {
			break
		}
		expr = inner
	}
	expr = strings.TrimSpace(expr)
	if _, ok := known[expr]; ok {
		return expr, true
	}
	return "", false
}

func hasVariableFlowToSink(content string, vars []string, sink *regexp.Regexp) bool {
	if len(vars) == 0 || sink == nil {
		return false
	}
	for _, name := range vars {
		pattern := regexp.MustCompile(`(?is)` + regexp.QuoteMeta(name) + `.{0,160}` + sink.String() + `|` + sink.String() + `.{0,160}` + regexp.QuoteMeta(name))
		if pattern.MatchString(content) {
			return true
		}
	}
	return false
}

func executionSinkPattern() *regexp.Regexp {
	return regexp.MustCompile(`(?i)(eval\(|exec\(|subprocess\.(run|popen|call)|os\.system\(|exec\.command\(|child_process\.(exec|spawn)|runtime\.getruntime\(\)\.exec)`)
}

func networkSinkPattern() *regexp.Regexp {
	return regexp.MustCompile(`(?i)(fetch\(|axios\.(get|post|put|delete|request)\(|requests\.(get|post|put|delete|request)\(|http\.(get|post|newrequest)\(|urllib\.request\.(urlopen|request)|client\.do\(|curl\s+[^#\n]*https?://|wget\s+[^#\n]*https?://)`)
}

func commandSinkPattern() *regexp.Regexp {
	return regexp.MustCompile(`(?i)(bash\s+-c|sh\s+-c|cmd(?:\.exe)?\s+/c|powershell(?:\.exe)?\s+-|start-process\s+|processstartinfo|exec\.command\([^\n)]*("bash"|"sh"|"cmd"|"cmd\.exe"|"powershell"|"powershell\.exe")|curl\s+[^#\n]*\||wget\s+[^#\n]*\|)`)
}

func uniqueSortedStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, exists := seen[item]; exists {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

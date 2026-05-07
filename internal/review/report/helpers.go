package report

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func ResolveSkillDescription(formDescription, scanPath string) string {
	if strings.TrimSpace(formDescription) != "" {
		return strings.TrimSpace(formDescription)
	}
	if desc := ExtractSkillDeclaration(scanPath); desc != "" {
		return desc
	}
	return ""
}

func ExtractSkillDeclaration(scanPath string) string {
	type candidate struct {
		path     string
		priority int
	}
	var candidates []candidate
	_ = filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.ToLower(filepath.Ext(path)) != ".md" {
			return nil
		}
		base := strings.ToLower(filepath.Base(path))
		priority := 3
		switch base {
		case "skill.md":
			priority = 0
		case "readme.md":
			priority = 1
		case "description.md", "manifest.md":
			priority = 2
		}
		candidates = append(candidates, candidate{path: path, priority: priority})
		return nil
	})
	if len(candidates) == 0 {
		return ""
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority < candidates[j].priority
		}
		return candidates[i].path < candidates[j].path
	})
	parts := make([]string, 0, 3)
	for _, c := range candidates {
		if len(parts) >= 3 {
			break
		}
		data, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(data))
		if text == "" {
			continue
		}
		if len(text) > 4000 {
			text = text[:4000]
		}
		parts = append(parts, fmt.Sprintf("%s:\n%s", filepath.Base(c.path), text))
	}
	return strings.Join(parts, "\n\n")
}

func BuildSourceContextIndex(root string, files []evaluator.SourceFile, displayRelPath func(root, path string) string) map[string][]string {
	if len(files) == 0 {
		return nil
	}
	index := make(map[string][]string, len(files)*2)
	for _, file := range files {
		lines := strings.Split(strings.ReplaceAll(file.Content, "\r\n", "\n"), "\n")
		fullPath := normalizeEvidencePath(file.Path)
		if fullPath != "" {
			index[fullPath] = lines
		}
		relPath := normalizeEvidencePath(displayRelPath(root, file.Path))
		if relPath != "" {
			index[relPath] = lines
		}
	}
	return index
}

func StructuredFindingEvidence(items []plugins.Finding, sourceIndex map[string][]string, limit int) []string {
	evidence := make([]string, 0, len(items)*2)
	seen := map[string]bool{}
	codeWindows := make([]codeEvidenceWindow, 0, len(items))
	add := func(value string) {
		value = strings.TrimSpace(value)
		key := evidenceDedupKey(value)
		if value == "" || key == "" || seen[key] {
			return
		}
		seen[key] = true
		evidence = append(evidence, value)
	}
	for _, item := range items {
		if window, ok := newCodeEvidenceWindow(item, sourceIndex); ok {
			codeWindows = append(codeWindows, window)
			continue
		}
		if strings.TrimSpace(item.Location) != "" {
			add("位置: " + item.Location)
		}
		if strings.TrimSpace(item.CodeSnippet) != "" {
			add("片段: " + item.CodeSnippet)
		} else {
			add("说明: " + item.Description)
		}
	}
	for _, block := range mergeCodeEvidenceWindows(codeWindows) {
		add(renderMergedCodeEvidence(block))
	}
	if limit > 0 && len(evidence) > limit {
		return append([]string{}, evidence[:limit]...)
	}
	return evidence
}

func ParseSourceLocation(location string) (string, int, bool) {
	location = strings.TrimSpace(location)
	location = strings.TrimSpace(strings.TrimPrefix(location, "[sandbox-runtime]"))
	if idx := strings.Index(location, "|"); idx >= 0 {
		location = strings.TrimSpace(location[:idx])
	}
	if location == "" {
		return "", 0, false
	}
	lastColon := strings.LastIndex(location, ":")
	if lastColon <= 0 || lastColon == len(location)-1 {
		return "", 0, false
	}
	lineText := strings.TrimSpace(location[lastColon+1:])
	lineNumber, err := strconv.Atoi(lineText)
	if err != nil || lineNumber <= 0 {
		return "", 0, false
	}
	path := strings.TrimSpace(location[:lastColon])
	if path == "" {
		return "", 0, false
	}
	return normalizeEvidencePath(path), lineNumber, true
}

func SourcePillClass(item string) string {
	switch strings.TrimSpace(item) {
	case "静态基线":
		return "pill-static"
	case "动态行为":
		return "pill-dynamic"
	case "规则静态", "语义静态", "LLM静态":
		return "pill-static"
	case "沙箱动态", "情报关联":
		return "pill-dynamic"
	case "已验证", "二次验证":
		return "pill-verified"
	case "复核疑似误报":
		return "pill-fp"
	case "待验证", "需人工复核":
		return "pill-review"
	default:
		return ""
	}
}

func SplitCodeEvidenceLabelAndBody(item string) (string, string) {
	item = strings.TrimSpace(item)
	if item == "" {
		return "代码证据", ""
	}
	lines := strings.Split(item, "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if LooksLikeSourceLocator(line) {
			body := strings.TrimSpace(strings.Join(lines[idx+1:], "\n"))
			if body == "" {
				body = item
			}
			return "代码证据 / " + ShortenEvidenceLabel(line), body
		}
		break
	}
	return "代码证据", item
}

func InferEvidenceLabel(item string) string {
	label, _ := SplitCodeEvidenceLabelAndBody(item)
	return label
}

func LooksLikeSourceLocator(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "/") || strings.Contains(lower, "\\") {
		return true
	}
	if strings.Contains(lower, ":") && (strings.Contains(lower, ".go") || strings.Contains(lower, ".js") || strings.Contains(lower, ".ts") || strings.Contains(lower, ".py") || strings.Contains(lower, ".yaml") || strings.Contains(lower, ".yml") || strings.Contains(lower, ".json") || strings.Contains(lower, ".md")) {
		return true
	}
	return false
}

func ShortenEvidenceLabel(line string) string {
	return strings.TrimSpace(line)
}

func RenderSourceBadgeStrip(items []string) string {
	cleaned := uniqueNonEmptyStrings(items)
	if len(cleaned) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("<div class=\"source-strip\">")
	for _, item := range cleaned {
		b.WriteString("<span class=\"pill " + html.EscapeString(SourcePillClass(item)) + "\">" + html.EscapeString(item) + "</span>")
	}
	b.WriteString("</div>")
	return b.String()
}

func BuildVulnerabilityBlocks(findings []review.StructuredFinding) []review.VulnerabilityBlock {
	blocks := make([]review.VulnerabilityBlock, 0, len(findings))
	for _, finding := range findings {
		var b strings.Builder
		b.WriteString("<vuln>\n")
		writeVulnTag(&b, "id", finding.ID)
		writeVulnTag(&b, "title", finding.Title)
		writeVulnTag(&b, "desc", finding.AttackPath)
		writeVulnTag(&b, "risk_type", finding.Category)
		writeVulnTag(&b, "level", finding.Severity)
		writeVulnTag(&b, "confidence", defaultIfEmpty(strings.TrimSpace(finding.Confidence), "待复核"))
		writeVulnTag(&b, "rule_id", finding.RuleID)
		writeVulnTag(&b, "source", finding.Source)
		writeVulnTag(&b, "evidence", strings.Join(finding.Evidence, "；"))
		writeVulnTag(&b, "chain_summaries", strings.Join(finding.ChainSummaries, "；"))
		writeVulnTag(&b, "chains", RenderFindingChains(finding.Chains))
		writeVulnTag(&b, "calibration_basis", strings.Join(finding.CalibrationBasis, "；"))
		writeVulnTag(&b, "false_positive_checks", strings.Join(finding.FalsePositiveChecks, "；"))
		writeVulnTag(&b, "fix", finding.ReviewGuidance)
		b.WriteString("</vuln>")
		blocks = append(blocks, review.VulnerabilityBlock{ID: finding.ID, Format: "structured-vuln-block", Content: b.String()})
	}
	return blocks
}

func FormatStructuredFindingForPrompt(finding review.StructuredFinding) string {
	lines := []string{
		"ID: " + finding.ID,
		"Rule: " + finding.RuleID + " " + finding.Title,
		"Severity: " + finding.Severity,
		"Category: " + finding.Category,
		"Confidence: " + finding.Confidence,
		"AttackPath: " + finding.AttackPath,
		"Evidence: " + strings.Join(finding.Evidence, "；"),
		"ChainSummaries: " + strings.Join(finding.ChainSummaries, "；"),
		"Calibration: " + strings.Join(finding.CalibrationBasis, "；"),
		"FalsePositiveChecks: " + strings.Join(finding.FalsePositiveChecks, "；"),
	}
	if renderedChains := RenderFindingChains(finding.Chains); renderedChains != "" {
		lines = append(lines, "Chains: "+renderedChains)
	}
	return strings.Join(lines, "\n")
}

func RenderFindingChains(items []review.FindingChain) string {
	if len(items) == 0 {
		return ""
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		summary := strings.TrimSpace(item.Summary)
		if summary == "" {
			continue
		}
		part := strings.TrimSpace(item.Kind) + ": " + summary
		if source := strings.TrimSpace(item.Source); source != "" {
			part += " [source=" + source + "]"
		}
		if path := strings.TrimSpace(item.Path); path != "" {
			part += " [path=" + path + "]"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "；")
}

func writeVulnTag(b *strings.Builder, tag, value string) {
	b.WriteString("  <")
	b.WriteString(tag)
	b.WriteString(">")
	b.WriteString(escapeVulnBlockValue(value))
	b.WriteString("</")
	b.WriteString(tag)
	b.WriteString(">\n")
}

func escapeVulnBlockValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	return value
}


type codeEvidenceWindow struct {
	path     string
	start    int
	end      int
	hitLines map[int]bool
	lines    map[int]string
}

func newCodeEvidenceWindow(item plugins.Finding, sourceIndex map[string][]string) (codeEvidenceWindow, bool) {
	path, line, ok := ParseSourceLocation(item.Location)
	if !ok {
		return codeEvidenceWindow{}, false
	}
	if window, ok := buildWindowFromSourceIndex(path, line, sourceIndex); ok {
		return window, true
	}
	lines := normalizeCodeSnippetLines(item.CodeSnippet)
	if len(lines) == 0 {
		return codeEvidenceWindow{}, false
	}
	window := codeEvidenceWindow{
		path:     normalizeEvidencePath(path),
		start:    line,
		end:      line + len(lines) - 1,
		hitLines: map[int]bool{line: true},
		lines:    make(map[int]string, len(lines)),
	}
	for idx, snippetLine := range lines {
		window.lines[line+idx] = snippetLine
	}
	return window, true
}

func buildWindowFromSourceIndex(path string, hitLine int, sourceIndex map[string][]string) (codeEvidenceWindow, bool) {
	if len(sourceIndex) == 0 {
		return codeEvidenceWindow{}, false
	}
	path = normalizeEvidencePath(path)
	lines, ok := sourceIndex[path]
	if !ok || hitLine <= 0 || hitLine > len(lines) {
		return codeEvidenceWindow{}, false
	}
	start := hitLine - 3
	if start < 1 {
		start = 1
	}
	end := hitLine + 3
	if end > len(lines) {
		end = len(lines)
	}
	window := codeEvidenceWindow{
		path:     path,
		start:    start,
		end:      end,
		hitLines: map[int]bool{hitLine: true},
		lines:    make(map[int]string, end-start+1),
	}
	for lineNo := start; lineNo <= end; lineNo++ {
		window.lines[lineNo] = lines[lineNo-1]
	}
	return window, true
}

func normalizeCodeSnippetLines(snippet string) []string {
	snippet = strings.ReplaceAll(snippet, "\r\n", "\n")
	rawLines := strings.Split(snippet, "\n")
	for len(rawLines) > 0 && strings.TrimSpace(rawLines[0]) == "" {
		rawLines = rawLines[1:]
	}
	for len(rawLines) > 0 && strings.TrimSpace(rawLines[len(rawLines)-1]) == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}
	if len(rawLines) == 0 {
		return nil
	}
	return rawLines
}

func mergeCodeEvidenceWindows(windows []codeEvidenceWindow) []codeEvidenceWindow {
	if len(windows) == 0 {
		return nil
	}
	sorted := append([]codeEvidenceWindow(nil), windows...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].path == sorted[j].path {
			if sorted[i].start == sorted[j].start {
				return sorted[i].end < sorted[j].end
			}
			return sorted[i].start < sorted[j].start
		}
		return sorted[i].path < sorted[j].path
	})
	merged := []codeEvidenceWindow{sorted[0]}
	for _, current := range sorted[1:] {
		last := &merged[len(merged)-1]
		if last.path == current.path && current.start <= last.end+1 {
			mergeIntoCodeEvidenceWindow(last, current)
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func mergeIntoCodeEvidenceWindow(dst *codeEvidenceWindow, src codeEvidenceWindow) {
	if src.start < dst.start {
		dst.start = src.start
	}
	if src.end > dst.end {
		dst.end = src.end
	}
	for line, value := range src.lines {
		if _, exists := dst.lines[line]; !exists {
			dst.lines[line] = value
		}
	}
	for line := range src.hitLines {
		dst.hitLines[line] = true
	}
}

func renderMergedCodeEvidence(window codeEvidenceWindow) string {
	lineNumbers := make([]int, 0, len(window.lines))
	for line := range window.lines {
		lineNumbers = append(lineNumbers, line)
	}
	sort.Ints(lineNumbers)
	var b strings.Builder
	b.WriteString(window.path)
	b.WriteString(":")
	b.WriteString(strconv.Itoa(window.start))
	if window.end > window.start {
		b.WriteString("-")
		b.WriteString(strconv.Itoa(window.end))
	}
	for _, line := range lineNumbers {
		marker := "  "
		if window.hitLines[line] {
			marker = "> "
		}
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s%4d | %s", marker, line, window.lines[line]))
	}
	return b.String()
}

func normalizeEvidencePath(path string) string {
	path = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(path), "[sandbox-runtime]"))
	if path == "" {
		return ""
	}
	if idx := strings.Index(path, "|"); idx >= 0 {
		path = strings.TrimSpace(path[:idx])
	}
	if matched := regexp.MustCompile(`^(.+?):\d+(?:-\d+)?$`).FindStringSubmatch(path); len(matched) == 2 {
		path = matched[1]
	}
	return filepath.ToSlash(strings.TrimSpace(path))
}

func evidenceDedupKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	label, body := SplitCodeEvidenceLabelAndBody(value)
	label = strings.TrimSpace(label)
	body = strings.TrimSpace(body)
	if label == "代码证据" && body != "" {
		return value
	}
	path := ""
	if idx := strings.Index(label, "/"); idx >= 0 {
		path = normalizeEvidencePath(strings.TrimSpace(label[idx+1:]))
	}
	if path == "" {
		firstLine := strings.TrimSpace(strings.Split(value, "\n")[0])
		path = normalizeEvidencePath(firstLine)
	}
	body = strings.Join(strings.Fields(body), " ")
	if path != "" && body != "" {
		return path + "\x00" + body
	}
	return value
}

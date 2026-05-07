package handler

import (
	"fmt"
	"html"
	"strconv"
	"strings"

	"skill-scanner/internal/review"
)

func renderDifferentialTable(items []review.DifferentialProbe) string {
	if len(items) == 0 {
		return "<p class=\"muted\">未检出。</p>"
	}
	var b strings.Builder
	b.WriteString("<div class=\"table-wrap\"><table><tr><th>执行画像</th><th>是否触发差异</th><th>指标</th><th>说明</th></tr>")
	for _, item := range items {
		triggered := "否"
		if item.Triggered {
			triggered = "是"
		}
		b.WriteString("<tr><td>" + html.EscapeString(item.Scenario) + "</td><td>" + triggered + "</td><td>" + html.EscapeString(strings.Join(item.Indicators, "；")) + "</td><td>" + html.EscapeString(item.Summary) + "</td></tr>")
	}
	b.WriteString("</table></div>")
	return b.String()
}

func renderParagraphText(text string) string {
	parts := splitReadableParagraphs(text)
	if len(parts) == 0 {
		return "<p class=\"muted\">未提供说明</p>"
	}
	var b strings.Builder
	for _, part := range parts {
		b.WriteString("<p>" + html.EscapeString(part) + "</p>")
	}
	return b.String()
}

func splitReadableParagraphs(text string) []string {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	rawBlocks := strings.Split(text, "\n")
	parts := make([]string, 0, len(rawBlocks))
	for _, block := range rawBlocks {
		block = strings.TrimSpace(block)
		if block == "" {
			continue
		}
		if len([]rune(block)) > 80 && strings.Contains(block, "。") {
			for _, item := range strings.Split(block, "。") {
				item = strings.TrimSpace(item)
				if item != "" {
					parts = append(parts, item)
				}
			}
			continue
		}
		if strings.Contains(block, "；") {
			for _, item := range strings.Split(block, "；") {
				item = strings.TrimSpace(item)
				if item != "" {
					parts = append(parts, item)
				}
			}
			continue
		}
		if strings.Contains(block, ";") {
			for _, item := range strings.Split(block, ";") {
				item = strings.TrimSpace(item)
				if item != "" {
					parts = append(parts, item)
				}
			}
			continue
		}
		parts = append(parts, block)
	}
	return parts
}

func looksLikeCode(text string) bool {
	text = strings.TrimSpace(text)
	if text == "" {
		return false
	}
	if strings.Contains(text, "\n") {
		return true
	}
	markers := []string{"()", "=>", "{", "}", "[", "]", "requests.", "fetch(", "curl ", "http://", "https://", "os.", "exec", "subprocess", ";", "="}
	for _, marker := range markers {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func renderHTMLList(items []string, max int, empty string) string {
	cleaned := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			cleaned = append(cleaned, item)
		}
	}
	if len(cleaned) == 0 {
		return "<p class=\"muted\">" + html.EscapeString(empty) + "</p>"
	}
	if max > 0 && len(cleaned) > max {
		cleaned = cleaned[:max]
	}
	var b strings.Builder
	b.WriteString("<ul class=\"compact-list\">")
	for _, item := range cleaned {
		b.WriteString("<li>" + html.EscapeString(item) + "</li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func renderHTMLLabeledList(title string, items []string, max int, empty string) string {
	return "<div><strong>" + html.EscapeString(title) + ":</strong>" + renderHTMLList(items, max, empty) + "</div>"
}

func renderHTMLEvidenceList(title string, items []string, empty string) string {
	cleaned := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			cleaned = append(cleaned, item)
		}
	}
	if len(cleaned) == 0 {
		return "<div><strong>" + html.EscapeString(title) + ":</strong><p class=\"muted\">" + html.EscapeString(empty) + "</p></div>"
	}
	var b strings.Builder
	b.WriteString("<div><strong>" + html.EscapeString(title) + ":</strong><div class=\"stack\">")
	for _, item := range cleaned {
		if looksLikeCode(item) {
			b.WriteString(renderHTMLCodeEvidence(item))
			continue
		}
		b.WriteString(renderParagraphText(normalizeEvidenceBody(item)))
	}
	b.WriteString("</div></div>")
	return b.String()
}

func renderHTMLCodeEvidence(item string) string {
	label, body := splitCodeEvidenceLabelAndBody(item)
	return "<div class=\"code-evidence\"><div class=\"code-label\">" + html.EscapeString(label) + "</div><pre class=\"code-box\">" + html.EscapeString(body) + "</pre></div>"
}

func renderHTMLInventoryEvidenceList(title string, items []string, empty string) string {
	cleaned := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			cleaned = append(cleaned, item)
		}
	}
	if len(cleaned) == 0 {
		return "<div><strong>" + html.EscapeString(title) + ":</strong><p class=\"muted\">" + html.EscapeString(empty) + "</p></div>"
	}
	var b strings.Builder
	b.WriteString("<div><strong>" + html.EscapeString(title) + ":</strong><div class=\"stack\">")
	for _, item := range cleaned {
		if looksLikeInventoryCountLine(item) {
			b.WriteString(renderParagraphText(item))
			continue
		}
		if meaning, ok := trimInventoryPrefixedLine(item, "意义:"); ok {
			b.WriteString("<div class=\"code-evidence\"><div class=\"code-label\">意义</div><p class=\"code-box\">" + html.EscapeString(meaning) + "</p></div>")
			continue
		}
		if evidence, ok := trimInventoryPrefixedLine(item, "证据:"); ok {
			if strings.TrimSpace(evidence) == "" {
				continue
			}
			if looksLikeCode(evidence) || looksLikeSourceLocator(evidence) {
				b.WriteString(renderInventoryCodeEvidence(evidence))
			} else {
				b.WriteString("<div class=\"code-evidence\"><div class=\"code-label\">证据说明</div><p class=\"code-box\">" + html.EscapeString(evidence) + "</p></div>")
			}
			continue
		}
		if context, ok := trimInventoryPrefixedLine(item, "上下文证据:"); ok {
			if strings.TrimSpace(context) == "" {
				continue
			}
			b.WriteString(renderHTMLCodeEvidence(context))
			continue
		}
		if looksLikeCode(item) || looksLikeSourceLocator(item) {
			b.WriteString(renderHTMLCodeEvidence(item))
		} else {
			b.WriteString(renderParagraphText(item))
		}
	}
	b.WriteString("</div></div>")
	return b.String()
}

func renderInventoryCodeEvidence(evidence string) string {
	evidence = strings.TrimSpace(evidence)
	if evidence == "" {
		return ""
	}
	parts := strings.SplitN(evidence, " | ", 2)
	locator := strings.TrimSpace(parts[0])
	body := evidence
	if len(parts) == 2 {
		if strings.TrimSpace(parts[1]) == "" {
			return ""
		}
		if path, lineNo, ok := parseSourceLocation(locator); ok {
			label := "代码证据 / " + shortenEvidenceLabel(path+":"+strconv.Itoa(lineNo))
			body = fmt.Sprintf("> %4d | %s", lineNo, strings.TrimSpace(parts[1]))
			return "<div class=\"code-evidence\"><div class=\"code-label\">" + html.EscapeString(label) + "</div><pre class=\"code-box\">" + html.EscapeString(body) + "</pre></div>"
		}
	}
	return "<div class=\"code-evidence\"><div class=\"code-label\">代码证据</div><pre class=\"code-box\">" + html.EscapeString(body) + "</pre></div>"
}

func trimInventoryPrefixedLine(item, prefix string) (string, bool) {
	item = strings.TrimSpace(item)
	if !strings.HasPrefix(item, prefix) {
		return "", false
	}
	trimmed := strings.TrimSpace(strings.TrimPrefix(item, prefix))
	if trimmed == "" {
		return "", false
	}
	return trimmed, true
}

func looksLikeInventoryCountLine(item string) bool {
	item = strings.TrimSpace(item)
	if item == "" {
		return false
	}
	idx := strings.LastIndex(item, ":")
	if idx <= 0 || idx >= len(item)-1 {
		return false
	}
	right := strings.TrimSpace(item[idx+1:])
	if !strings.HasSuffix(right, "条") {
		return false
	}
	n := strings.TrimSpace(strings.TrimSuffix(right, "条"))
	if n == "" {
		return false
	}
	for _, ch := range n {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

func renderIntentList(title string, items []string) string {
	if len(items) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("<p><strong>" + html.EscapeString(title) + ":</strong></p><ul>")
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			b.WriteString("<li>" + html.EscapeString(item) + "</li>")
		}
	}
	b.WriteString("</ul>")
	return b.String()
}

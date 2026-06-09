package handler

import (
	"html"
	"strconv"
	"strings"

	"skill-scanner/internal/review"
)

func renderRemediationVerificationSection(result review.RemediationVerificationResult) string {
	if remediationVerificationEmpty(result) {
		return ""
	}
	var b strings.Builder
	b.WriteString("<div id=\"remediation-verification\" class=\"card\"><div class=\"section-head\"><h2>修复验证</h2><span class=\"hint\">对比历史风险与当前扫描结果，展示已解决、仍打开、回归和相关新增风险。</span></div>")
	b.WriteString("<div class=\"grid-two\">")
	b.WriteString(renderRemediationVerificationBucket("已解决", result.ResolvedFindingIDs, result.VerificationNotes, "pill-verified"))
	b.WriteString(renderRemediationVerificationBucket("仍打开", result.OpenFindingIDs, result.VerificationNotes, "pill-review"))
	b.WriteString(renderRemediationVerificationBucket("回归", result.RegressedFindingIDs, result.VerificationNotes, "pill-static"))
	b.WriteString(renderRemediationVerificationBucket("相关新增", result.NewRelatedFindingIDs, result.VerificationNotes, "pill-dynamic"))
	b.WriteString("</div></div>")
	return b.String()
}

func renderRemediationVerificationBucket(title string, ids []string, notes map[string]string, pillClass string) string {
	var b strings.Builder
	b.WriteString("<div class=\"finding-section\"><h3>" + html.EscapeString(title) + " <span class=\"pill " + html.EscapeString(pillClass) + "\">" + strconv.Itoa(len(ids)) + "</span></h3>")
	if len(ids) == 0 {
		b.WriteString("<p class=\"hint\">暂无记录。</p></div>")
		return b.String()
	}
	b.WriteString("<ul>")
	for _, id := range ids {
		b.WriteString("<li><strong>" + html.EscapeString(id) + "</strong>")
		if note := strings.TrimSpace(notes[id]); note != "" {
			b.WriteString("<br><span class=\"hint\">" + html.EscapeString(note) + "</span>")
		}
		b.WriteString("</li>")
	}
	b.WriteString("</ul></div>")
	return b.String()
}

func remediationVerificationEmpty(result review.RemediationVerificationResult) bool {
	return len(result.ResolvedFindingIDs) == 0 && len(result.OpenFindingIDs) == 0 && len(result.RegressedFindingIDs) == 0 && len(result.NewRelatedFindingIDs) == 0
}

func buildMITRESummary(findings []review.StructuredFinding) map[string]interface{} {
	if len(findings) == 0 {
		return map[string]interface{}{"count": 0, "techniques": []string{}}
	}
	all := make([]string, 0, len(findings)*2)
	byFinding := make([]map[string]interface{}, 0, len(findings))
	for _, finding := range findings {
		techniques := uniqueNonEmptyStrings(finding.MITRETechniques)
		if len(techniques) == 0 {
			continue
		}
		all = append(all, techniques...)
		byFinding = append(byFinding, map[string]interface{}{
			"id":         finding.ID,
			"title":      finding.Title,
			"rule_id":    displayRuleNameWithFallback(finding.RuleID, finding.Title),
			"techniques": techniques,
		})
	}
	unique := uniqueNonEmptyStrings(all)
	return map[string]interface{}{
		"count":      len(unique),
		"techniques": unique,
		"findings":   byFinding,
	}
}

func renderMITRESummarySection(findings []review.StructuredFinding) string {
	var b strings.Builder
	summary := buildMITRESummary(findings)
	b.WriteString("<div id=\"mitre-summary\" class=\"card\"><div class=\"section-head\"><h2>MITRE ATT&CK 映射</h2><span class=\"hint\">按风险项汇总战术/技术映射，用于安全复盘与处置协同。</span></div>")
	count, _ := summary["count"].(int)
	techniques, _ := summary["techniques"].([]string)
	if count == 0 || len(techniques) == 0 {
		b.WriteString("<p class=\"muted\">当前未形成可用的 MITRE 映射。</p></div>")
		return b.String()
	}
	b.WriteString("<p><strong>映射数量:</strong> " + strconv.Itoa(count) + "</p>")
	b.WriteString(renderHTMLLabeledList("技术条目", techniques, 0, "未映射"))
	if byFinding, ok := summary["findings"].([]map[string]interface{}); ok && len(byFinding) > 0 {
		b.WriteString("<div class=\"table-wrap\"><table><tr><th>风险项</th><th>规则</th><th>映射技术</th></tr>")
		for _, item := range byFinding {
			id, _ := item["id"].(string)
			title, _ := item["title"].(string)
			ruleID, _ := item["rule_id"].(string)
			rows := interfaceToStringSlice(item["techniques"])
			b.WriteString("<tr><td>" + html.EscapeString(defaultIfEmpty(id, "-")) + " / " + html.EscapeString(defaultIfEmpty(title, "-")) + "</td><td>" + html.EscapeString(defaultIfEmpty(ruleID, "-")) + "</td><td>" + html.EscapeString(strings.Join(rows, "；")) + "</td></tr>")
		}
		b.WriteString("</table></div>")
	}
	b.WriteString("</div>")
	return b.String()
}

func interfaceToStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}
	if items, ok := v.([]string); ok {
		return items
	}
	if generic, ok := v.([]interface{}); ok {
		out := make([]string, 0, len(generic))
		for _, item := range generic {
			s, ok := item.(string)
			if !ok {
				continue
			}
			out = append(out, s)
		}
		return out
	}
	return nil
}

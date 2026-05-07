package handler

import (
	"fmt"
	"html"
	"strings"

	"skill-scanner/internal/review"
)

func renderVerificationSummaryCard(refined review.Result) string {
	needVerify := make([]string, 0)
	noNeedVerify := make([]string, 0)
	verdictByFinding := preferredVerdictsByFinding(refined.ReviewAgentVerdicts)
	for _, finding := range sortStructuredFindingsByReview(refined.StructuredFindings, refined) {
		verdict, ok := verdictByFinding[finding.ID]
		if !ok || strings.TrimSpace(verdict.Verdict) == "" {
			needVerify = append(needVerify, finding.ID+" / "+finding.Title+"：尚未形成明确复核结论，仍需人工验证入口可达性、真实影响和排除条件。")
			continue
		}
		reviewDone := localizeReviewVerdict(verdict.Verdict)
		reviewSource := localizeReviewerLabel(defaultIfEmpty(verdict.Reviewer, "unknown-reviewer"))
		if strings.EqualFold(strings.TrimSpace(verdict.Verdict), "confirmed") || strings.EqualFold(strings.TrimSpace(verdict.Verdict), "likely_false_positive") {
			noNeedVerify = append(noNeedVerify, finding.ID+" / "+finding.Title+"：已完成复核（"+reviewDone+"，复核来源："+reviewSource+"），规则与证据已形成一致结论。")
			continue
		}
		needVerify = append(needVerify, finding.ID+" / "+finding.Title+"：已完成初步复核（复核来源："+reviewSource+"），当前结论为“"+reviewDone+"”，仍需人工验证关键证据闭环。")
	}
	var b strings.Builder
	b.WriteString("<div id=\"verification-summary\" class=\"card\"><div class=\"section-head\"><h2>验证结论摘要</h2><span class=\"hint\">先给出哪些需要再次验证、哪些已无需再次验证，并说明原因。</span></div>")
	b.WriteString(renderHTMLLabeledList("仍需人工验证", needVerify, 0, "当前未识别到仍需人工验证的风险项。"))
	b.WriteString(renderHTMLLabeledList("已完成验证", noNeedVerify, 0, "当前暂无可直接判定为已完成验证的风险项。"))
	b.WriteString("</div>")
	return b.String()
}

func renderAppendixSection(base baseScanOutput, evalLogs []ruleEvaluationLog) string {
	var b strings.Builder
	b.WriteString("<div id=\"appendix\" class=\"card appendix-card\"><div class=\"section-head\"><h2>附录与完整性</h2><span class=\"hint\">保留评估完整性与全量检测记录，便于审计追踪；评分字段仅作辅助参考。</span></div><div class=\"appendix-stack\">")
	b.WriteString("<p class=\"muted\">快速阅读建议：优先查看高风险与中风险条目，再按需展开全量检测记录。</p>")
	b.WriteString("<details class=\"appendix-details\"><summary>评估完整性证明</summary><div class=\"appendix-body\">")
	b.WriteString(fmt.Sprintf("<p>已评估规则: %d / %d（未评估: %d）</p>", base.evaluatedRules, base.totalRules, len(base.uncheckedRules)))
	b.WriteString("<p>说明: " + html.EscapeString(defaultIfEmpty(base.coverageNote, "无")) + "</p>")
	if base.cacheStats.Enabled {
		hitRate := incrementalCacheHitRate(base.cacheStats)
		b.WriteString(fmt.Sprintf("<p><strong>增量缓存:</strong> 候选文件 %d，命中 %d，未命中 %d</p>", base.cacheStats.Candidate, base.cacheStats.Hit, base.cacheStats.Miss))
		b.WriteString(fmt.Sprintf("<p><strong>缓存命中率:</strong> %.1f%%</p>", hitRate))
		b.WriteString("<div class=\"table-wrap\"><table><tr><th>模式</th><th>候选文件</th><th>命中</th><th>未命中</th><th>命中率</th></tr>")
		b.WriteString(fmt.Sprintf("<tr><td>增量</td><td>%d</td><td>%d</td><td>%d</td><td>%.1f%%</td></tr>", base.cacheStats.Candidate, base.cacheStats.Hit, base.cacheStats.Miss, hitRate))
		b.WriteString("</table></div>")
		if strings.TrimSpace(base.cacheStats.CacheFilePath) != "" {
			b.WriteString("<p><strong>缓存文件:</strong> " + html.EscapeString(base.cacheStats.CacheFilePath) + "</p>")
		}
	} else {
		b.WriteString("<p><strong>增量缓存:</strong> 已关闭（本次全量重建源码分析缓存）</p>")
	}
	if len(base.uncheckedRules) > 0 {
		b.WriteString("<p><strong>未评估规则ID:</strong> " + html.EscapeString(strings.Join(base.uncheckedRules, ", ")) + "</p>")
	}
	b.WriteString("</div></details>")

	b.WriteString("<details class=\"appendix-details\"><summary>评估项检测记录（全量）</summary><div class=\"appendix-body\"><div class=\"table-wrap\"><table><tr><th>规则</th><th>分层</th><th>检测过程</th><th>检测结果</th><th>风险标记</th></tr>")
	for _, log := range sortRuleLogs(evalLogs) {
		riskClass := "risk-low"
		switch log.RiskLabel {
		case "高风险":
			riskClass = "risk-high"
		case "中风险":
			riskClass = "risk-medium"
		}
		resultText := log.DetectionResult
		if len(log.EvidenceLocations) > 0 {
			resultText += " 关键位置: " + strings.Join(log.EvidenceLocations, "；")
		}
		b.WriteString("<tr><td>" + html.EscapeString(log.RuleID+" "+log.RuleName) + "</td><td>" + html.EscapeString(log.Layer) + "</td><td>" + html.EscapeString(log.DetectionProcess) + "</td><td>" + html.EscapeString(resultText) + "</td><td class=\"" + riskClass + "\">" + html.EscapeString(log.RiskLabel) + "</td></tr>")
	}
	b.WriteString("</table></div></div></details>")

	b.WriteString("<details class=\"appendix-details\"><summary>V7 评估项覆盖分类</summary><div class=\"appendix-body\">")
	b.WriteString(fmt.Sprintf("<p>可自动评估项覆盖: %d / %d</p>", base.v5Coverage.AutoCovered, base.v5Coverage.AutoTotal))
	b.WriteString(fmt.Sprintf("<p>需人工评估项: %d</p>", base.v5Coverage.ManualTotal))
	b.WriteString("<p>分类说明: " + html.EscapeString(defaultIfEmpty(base.v5Coverage.Note, "未加载 V7 分类矩阵")) + "</p>")
	if len(base.v5Coverage.AutoUncovered) > 0 {
		b.WriteString("<p><strong>未覆盖自动项:</strong> " + html.EscapeString(strings.Join(base.v5Coverage.AutoUncovered, "；")) + "</p>")
	}
	if len(base.v5Coverage.ManualCandidates) > 0 {
		b.WriteString("<p><strong>人工评估候选(节选):</strong> " + html.EscapeString(strings.Join(base.v5Coverage.ManualCandidates, "；")) + "</p>")
	}
	b.WriteString("</div></details>")
	b.WriteString("</div></div>")
	return b.String()
}

func sortRuleLogs(logs []ruleEvaluationLog) []ruleEvaluationLog {
	out := make([]ruleEvaluationLog, 0, len(logs))
	appendByRisk := func(risk string) {
		for _, log := range logs {
			if strings.TrimSpace(log.RiskLabel) == risk {
				out = append(out, log)
			}
		}
	}
	appendByRisk("高风险")
	appendByRisk("中风险")
	appendByRisk("低风险")
	appendByRisk("无风险")
	appendByRisk("未评估")
	if len(out) == len(logs) {
		return out
	}
	for _, log := range logs {
		risk := strings.TrimSpace(log.RiskLabel)
		if risk != "高风险" && risk != "中风险" && risk != "低风险" && risk != "无风险" && risk != "未评估" {
			out = append(out, log)
		}
	}
	return out
}

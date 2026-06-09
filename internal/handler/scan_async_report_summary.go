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
	observeOnly := make([]string, 0)
	policyActions := make([]string, 0)
	ctx := newReviewedFindingContext(refined)
	confirmedCount, policyCount, fpCount, manualCount, total := ctx.reviewVerdictCoverage()
	declaredCaps, actualCaps := summarizedIntentCapabilities(refined)
	httpFailureReasonCounts := httpProbeFailureReasonCountsFromResult(refined)
	for _, finding := range sortStructuredFindingsByReview(refined.StructuredFindings, refined) {
		verdict := ctx.finalVerdict(finding.ID)
		closureGaps := closureGapLabels(finding)
		gapText := ""
		if len(closureGaps) > 0 {
			gapText = " 当前缺少 " + strings.Join(closureGaps, " / ") + "。"
		}
		guidance := ""
		if items := limitList(closureGuidanceForFinding(finding), 2); len(items) > 0 {
			guidance = " 建议优先：" + strings.Join(items, "；")
		}
		if strings.TrimSpace(verdict.Verdict) == "" {
			needVerify = append(needVerify, finding.ID+" / "+finding.Title+"：尚未形成明确复核结论，仍需人工验证入口可达性、真实影响和排除条件。"+gapText+guidance)
			continue
		}
		reviewDone := localizeReviewVerdict(verdict.Verdict)
		reviewSource := localizeReviewerLabel(defaultIfEmpty(verdict.Reviewer, "unknown-reviewer"))
		if strings.EqualFold(strings.TrimSpace(verdict.Verdict), "policy") {
			policyActions = append(policyActions, finding.ID+" / "+finding.Title+"：已完成策略复核（"+reviewDone+"，复核来源："+reviewSource+"），建议按准入策略拦截、替换目标或补充白名单依据。")
			continue
		}
		if strings.TrimSpace(finding.ApplicabilityVerdict) == "not_applicable" && !strings.EqualFold(strings.TrimSpace(verdict.Verdict), "confirmed") {
			observeOnly = append(observeOnly, finding.ID+" / "+finding.Title+"：当前规则前提未满足，已转为观察项；优先补源码调用链、运行链路或真实入口证据，再决定是否升级。"+gapText+guidance)
			continue
		}
		if strings.EqualFold(strings.TrimSpace(verdict.Verdict), "confirmed") || strings.EqualFold(strings.TrimSpace(verdict.Verdict), "likely_false_positive") {
			noNeedVerify = append(noNeedVerify, finding.ID+" / "+finding.Title+"：已完成复核（"+reviewDone+"，复核来源："+reviewSource+"），规则与证据已形成一致结论。")
			continue
		}
		needVerify = append(needVerify, finding.ID+" / "+finding.Title+"：已完成初步复核（复核来源："+reviewSource+"），当前结论为“"+reviewDone+"”，仍需人工验证关键证据闭环。"+gapText+guidance)
	}
	var b strings.Builder
	b.WriteString("<div id=\"verification-summary\" class=\"card\"><div class=\"section-head\"><h2>验证结论摘要</h2><span class=\"hint\">先给出哪些需要再次验证、哪些已无需再次验证，并说明原因。</span></div>")
	b.WriteString(fmt.Sprintf("<p><strong>自动复核覆盖率:</strong> %d/%d（已确认 %d，策略风险 %d，疑似误报 %d，待人工复核 %d）</p>", confirmedCount+policyCount+fpCount, total, confirmedCount, policyCount, fpCount, manualCount))
	b.WriteString(renderHTMLLabeledList("总体声明能力", declaredCaps, 0, "未提取到总体声明能力。"))
	b.WriteString(renderHTMLLabeledList("总体实现/观测能力", actualCaps, 0, "未提取到总体实现或观测能力。"))
	b.WriteString(renderHTMLLabeledList("HTTP 失败根因聚合", httpFailureReasonCounts, 0, "当前无可聚合的 HTTP 探针失败根因。"))
	b.WriteString(renderHTMLLabeledList("待人工复核原因分桶", ctx.manualReviewBuckets(), 0, "当前没有待人工复核项。"))
	b.WriteString(renderHTMLLabeledList("闭环缺口概览", closureGapOverview(refined), 0, "当前没有需要补齐的闭环缺口。"))
	b.WriteString(renderHTMLLabeledList("策略处置项", policyActions, 0, "当前没有策略处置项。"))
	b.WriteString(renderHTMLLabeledList("观察项", observeOnly, 0, "当前没有仅需观察的低优先级项。"))
	b.WriteString(renderHTMLLabeledList("仍需人工验证", needVerify, 0, "当前未识别到仍需人工验证的风险项。"))
	b.WriteString(renderHTMLLabeledList("已完成验证", noNeedVerify, 0, "当前暂无可直接判定为已完成验证的风险项。"))
	b.WriteString("</div>")
	return b.String()
}

func closureGapOverview(refined review.Result) []string {
	summary := buildClosureSummary(refined)
	items := make([]string, 0, 5)
	confirmed, _ := summary["confirmed_count"].(int)
	closed, _ := summary["closed_count"].(int)
	total, _ := summary["total_count"].(int)
	closureRate, _ := summary["closure_rate"].(float64)
	missingSource, _ := summary["missing_source_count"].(int)
	missingTransform, _ := summary["missing_transform_count"].(int)
	missingSink, _ := summary["missing_sink_count"].(int)
	missingRuntime, _ := summary["missing_runtime_count"].(int)
	topGaps, _ := summary["top_gaps"].([]string)
	topGapDetails, _ := summary["top_gap_details"].([]string)
	items = append(items, fmt.Sprintf("已形成确认闭环 %d 条", confirmed))
	items = append(items, fmt.Sprintf("证据链完整率 %.1f%%（%d/%d）", closureRate, closed, total))
	items = append(items, fmt.Sprintf("缺少 source %d 条", missingSource))
	items = append(items, fmt.Sprintf("缺少 transform %d 条", missingTransform))
	items = append(items, fmt.Sprintf("缺少 sink %d 条", missingSink))
	items = append(items, fmt.Sprintf("缺少 runtime %d 条", missingRuntime))
	items = append(items, topGaps...)
	items = append(items, topGapDetails...)
	return items
}

func summarizedIntentCapabilities(refined review.Result) ([]string, []string) {
	declared := make([]string, 0)
	actual := make([]string, 0)
	for _, item := range refined.CapabilityMatrix {
		capability := strings.TrimSpace(item.Capability)
		if capability == "" {
			continue
		}
		if item.Declared {
			declared = append(declared, capability)
		}
		if item.StaticDetected || item.LLMDetected || item.SandboxDetected || item.TIObserved {
			actual = append(actual, capability)
		}
	}
	for _, finding := range refined.StructuredFindings {
		if finding.Category != "声明与行为差异" {
			continue
		}
		for _, item := range finding.Evidence {
			line := strings.TrimSpace(item)
			if strings.HasPrefix(line, "声明能力:") {
				declared = append(declared, splitCapabilitySummary(strings.TrimSpace(strings.TrimPrefix(line, "声明能力:")))...)
			}
			if strings.HasPrefix(line, "实际能力:") {
				actual = append(actual, splitCapabilitySummary(strings.TrimSpace(strings.TrimPrefix(line, "实际能力:")))...)
			}
		}
	}
	return uniqueNonEmptyStrings(declared), uniqueNonEmptyStrings(actual)
}

func splitCapabilitySummary(text string) []string {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}
	parts := strings.FieldsFunc(text, func(r rune) bool {
		return r == '；' || r == ';' || r == '、' || r == ',' || r == '，'
	})
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func reviewVerdictCoverage(refined review.Result) (confirmed int, policy int, fp int, manual int, total int) {
	return newReviewedFindingContext(refined).reviewVerdictCoverage()
}

func manualReviewBuckets(refined review.Result) []string {
	return newReviewedFindingContext(refined).manualReviewBuckets()
}

func renderAppendixSection(base baseScanOutput, evalLogs []ruleEvaluationLog, integrity reportIntegritySummary) string {
	var b strings.Builder
	b.WriteString("<div id=\"appendix\" class=\"card appendix-card\"><div class=\"section-head\"><h2>附录与完整性</h2><span class=\"hint\">保留评估完整性与全量检测记录，便于审计追踪；评分字段仅作辅助参考。</span></div><div class=\"appendix-stack\">")
	b.WriteString("<p class=\"muted\">快速阅读建议：优先查看高风险与中风险条目，再按需展开全量检测记录。</p>")
	b.WriteString("<details class=\"appendix-details\"><summary>报告一致性预检</summary><div class=\"appendix-body\">")
	b.WriteString("<p><strong>状态:</strong> " + html.EscapeString(defaultIfEmpty(strings.TrimSpace(integrity.Status), "未执行")) + "</p>")
	b.WriteString(renderHTMLLabeledList("自动修正", integrity.AutoFixes, 0, "无"))
	b.WriteString(renderHTMLLabeledList("待关注项", integrity.Issues, 0, "无"))
	b.WriteString(renderHTMLLabeledList("未映射样例", integrity.MappingGaps, 0, "无"))
	b.WriteString("</div></details>")
	b.WriteString("<details class=\"appendix-details\"><summary>评估完整性证明</summary><div class=\"appendix-body\">")
	b.WriteString(fmt.Sprintf("<p>已评估规则: %d / %d（未评估: %d）</p>", base.evaluatedRules, base.totalRules, len(base.uncheckedRules)))
	b.WriteString("<p>说明: " + html.EscapeString(defaultIfEmpty(base.coverageNote, "无")) + "</p>")
	if base.cacheStats.Enabled {
		hitRate := incrementalCacheHitRate(base.cacheStats)
		b.WriteString(fmt.Sprintf("<p><strong>增量缓存:</strong> 候选文件 %d，命中 %d，未命中 %d</p>", base.cacheStats.Candidate, base.cacheStats.Hit, base.cacheStats.Miss))
		b.WriteString(fmt.Sprintf("<p><strong>缓存命中率:</strong> %.1f%%</p>", hitRate))
		b.WriteString("<div class=\"table-wrap\"><table><tr><th>模式</th><th>候选文件</th><th>命中</th><th>未命中</th><th>内容复用</th><th>派生信号复用</th><th>缺失</th><th>失效</th><th>读错误</th><th>命中率</th><th>缓存条目</th><th>版本</th></tr>")
		b.WriteString(fmt.Sprintf("<tr><td>增量</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%d</td><td>%.1f%%</td><td>%d</td><td>%s</td></tr>", base.cacheStats.Candidate, base.cacheStats.Hit, base.cacheStats.Miss, base.cacheStats.ContentReused, base.cacheStats.DerivedReused, base.cacheStats.Missing, base.cacheStats.Stale, base.cacheStats.ReadErrors, hitRate, base.cacheStats.CacheEntries, html.EscapeString(defaultIfEmpty(base.cacheStats.CacheVersion, "unknown"))))
		b.WriteString("</table></div>")
		if strings.TrimSpace(base.cacheStats.CacheFilePath) != "" {
			b.WriteString("<p><strong>缓存文件:</strong> " + html.EscapeString(sanitizeReportText(base.cacheStats.CacheFilePath, "")) + "</p>")
		}
		if strings.TrimSpace(base.cacheStats.LoadWarning) != "" {
			b.WriteString("<p><strong>缓存加载诊断:</strong> " + html.EscapeString(base.cacheStats.LoadWarning) + "</p>")
		}
		if strings.TrimSpace(base.cacheStats.SaveWarning) != "" {
			b.WriteString("<p><strong>缓存保存诊断:</strong> " + html.EscapeString(base.cacheStats.SaveWarning) + "</p>")
		}
	} else {
		b.WriteString("<p><strong>增量缓存:</strong> 已关闭（本次全量重建源码分析缓存）</p>")
		if strings.TrimSpace(base.cacheStats.DisabledReason) != "" {
			b.WriteString("<p><strong>关闭原因:</strong> " + html.EscapeString(base.cacheStats.DisabledReason) + "</p>")
		}
	}
	if len(base.uncheckedRules) > 0 {
		names := make([]string, 0, len(base.uncheckedRules))
		for _, item := range base.uncheckedRules {
			names = append(names, displayRuleName(item))
		}
		b.WriteString("<p><strong>未评估规则:</strong> " + html.EscapeString(strings.Join(names, "，")) + "</p>")
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
		b.WriteString("<tr><td>" + html.EscapeString(displayRuleNameWithFallback(log.RuleID, log.RuleName)) + "</td><td>" + html.EscapeString(log.Layer) + "</td><td>" + html.EscapeString(log.DetectionProcess) + "</td><td>" + html.EscapeString(resultText) + "</td><td class=\"" + riskClass + "\">" + html.EscapeString(log.RiskLabel) + "</td></tr>")
	}
	b.WriteString("</table></div></div></details>")

	b.WriteString("<details class=\"appendix-details\"><summary>规则评估覆盖统计</summary><div class=\"appendix-body\">")
	b.WriteString(fmt.Sprintf("<p>可自动评估项覆盖: %d / %d（%.1f%%）</p>", base.ruleCoverage.AutoCovered, base.ruleCoverage.AutoTotal, ruleCoverageRate(base.ruleCoverage.AutoCovered, base.ruleCoverage.AutoTotal)))
	b.WriteString("<p>覆盖说明: " + html.EscapeString(defaultIfEmpty(base.ruleCoverage.Note, "未生成覆盖说明")) + "</p>")
	if len(base.ruleCoverage.AutoUncovered) > 0 {
		b.WriteString("<p><strong>未覆盖自动项样例:</strong> " + html.EscapeString(strings.Join(limitList(base.ruleCoverage.AutoUncovered, 8), "；")) + "</p>")
	}
	if len(base.ruleCoverage.ManualCandidates) > 0 {
		b.WriteString("<p><strong>人工复核候选样例:</strong> " + html.EscapeString(strings.Join(limitList(base.ruleCoverage.ManualCandidates, 8), "；")) + "</p>")
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

package handler

import (
	"fmt"
	"html"
	"slices"
	"strconv"
	"strings"

	"skill-scanner/internal/review"
)

func hasIntegratedIntentSummary(base baseScanOutput, refined review.Result) bool {
	return base.intentSummary.Available || len(refined.IntentDiffs) > 0 || strings.TrimSpace(base.intentSummary.UnavailableReason) != ""
}

func renderIntentIntegratedCard(base baseScanOutput, refined review.Result) string {
	consistency := "一致"
	if len(refined.IntentDiffs) > 0 {
		consistency = "不一致"
	}
	var b strings.Builder
	b.WriteString("<details class=\"finding-card\"><summary><div class=\"finding-summary-main\"><p><strong>补充声明与行为一致性</strong></p><p class=\"muted\">原独立一致性区块已并入综合研判，避免与结构化风险重复陈述。</p></div><div class=\"finding-summary-side\"><p><strong>状态</strong></p><p>" + html.EscapeString(consistency) + "</p></div></summary><div class=\"finding-layout\"><div class=\"finding-section\"><h3>一致性摘要</h3>")
	if base.intentSummary.Available {
		b.WriteString(renderParagraphText("LLM 总结的声明意图: " + defaultIfEmpty(base.intentSummary.DeclaredIntent, "未生成")))
		b.WriteString(renderParagraphText("LLM 总结的实际行为: " + defaultIfEmpty(base.intentSummary.ActualBehavior, buildBehaviorSummary(refined.Behavior))))
		b.WriteString(renderParagraphText("一致性风险等级: " + defaultIfEmpty(base.intentSummary.IntentRiskLevel, "无风险")))
		if strings.TrimSpace(base.intentSummary.IntentMismatch) != "" {
			b.WriteString(renderParagraphText("不一致说明: " + base.intentSummary.IntentMismatch))
		}
	} else {
		b.WriteString(renderParagraphText(defaultIfEmpty(base.intentSummary.UnavailableReason, "LLM 未启用或本次未返回有效声明意图分析。")))
		b.WriteString(renderParagraphText("行为摘要: " + buildBehaviorSummary(refined.Behavior)))
	}
	b.WriteString("</div><div class=\"finding-section\"><h3>一致性证据</h3>")
	b.WriteString(renderHTMLLabeledList("声明允许能力", base.intentSummary.DeclaredCapabilities, 0, "未生成"))
	b.WriteString(renderHTMLLabeledList("实际使用能力", base.intentSummary.ActualCapabilities, 0, "未生成"))
	b.WriteString(renderHTMLLabeledList("一致性证据", base.intentSummary.ConsistencyEvidence, 0, "未生成"))
	if len(refined.IntentDiffs) == 0 {
		b.WriteString("<p class=\"muted\">未发现明显偏离。</p>")
	} else {
		diffs := make([]string, 0, len(refined.IntentDiffs))
		for _, diff := range refined.IntentDiffs {
			diffs = append(diffs, diff.Description)
		}
		b.WriteString(renderHTMLLabeledList("不一致项", diffs, 0, "未生成"))
	}
	b.WriteString("</div></div></details>")
	return b.String()
}

func hasIntegratedBehaviorSummary(refined review.Result) bool {
	behavior := refined.Behavior
	return len(behavior.DownloadIOCs)+len(behavior.DropIOCs)+len(behavior.ExecuteIOCs)+len(behavior.OutboundIOCs)+len(behavior.PersistenceIOCs)+len(behavior.PrivEscIOCs)+len(behavior.CredentialIOCs)+len(behavior.DefenseEvasionIOCs)+len(behavior.LateralMoveIOCs)+len(behavior.CollectionIOCs)+len(behavior.C2BeaconIOCs)+len(behavior.BehaviorChains)+len(behavior.BehaviorTimelines)+len(behavior.SequenceAlerts)+len(behavior.ProbeWarnings) > 0
}

func renderBehaviorIntegratedCard(refined review.Result) string {
	behavior := refined.Behavior
	var b strings.Builder
	b.WriteString("<details class=\"finding-card\"><summary><div class=\"finding-summary-main\"><p><strong>补充行为与时序证据</strong></p><p class=\"muted\">原行为证据采集区块已吸纳到综合研判，这里先展示高风险链路摘要，原始探针证据收进下级折叠。</p></div><div class=\"finding-summary-side\"><p><strong>证据类目</strong></p><p>" + strconv.Itoa(countBehaviorEvidenceCategories(behavior)) + "</p></div></summary><div class=\"finding-layout\"><div class=\"finding-section\"><h3>高风险链路与时序</h3>")
	b.WriteString(renderParagraphText("沙箱执行摘要: source=" + defaultIfEmpty(behavior.SandboxSource, "unknown") + "；verdict=" + defaultIfEmpty(behavior.SandboxVerdict, "unknown") + "；score=" + strconv.Itoa(behavior.SandboxScore) + "；duration=" + strconv.FormatInt(behavior.SandboxDurationMs, 10) + "ms；fallback=" + boolText(behavior.SandboxFallback)))
	b.WriteString(renderHTMLLabeledList("高风险链路摘要", behavior.BehaviorChains, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("行为时序链路", behavior.BehaviorTimelines, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("时序告警", behavior.SequenceAlerts, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("沙箱探针告警", behavior.ProbeWarnings, 0, "未检出"))
	b.WriteString("</div><div class=\"finding-section\"><h3>原始行为证据</h3><details class=\"mini-card\"><summary>展开原始行为证据</summary>")
	b.WriteString(renderHTMLLabeledList("下载证据", behavior.DownloadIOCs, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("落地证据", behavior.DropIOCs, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("执行证据", behavior.ExecuteIOCs, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("外联证据", behavior.OutboundIOCs, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("持久化证据", behavior.PersistenceIOCs, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("提权证据", behavior.PrivEscIOCs, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("凭据访问证据", behavior.CredentialIOCs, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("防御规避证据", behavior.DefenseEvasionIOCs, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("横向移动证据", behavior.LateralMoveIOCs, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("收集打包证据", behavior.CollectionIOCs, 0, "未检出"))
	b.WriteString(renderHTMLLabeledList("C2 信标证据", behavior.C2BeaconIOCs, 0, "未检出"))
	b.WriteString("</details></div></div></details>")
	return b.String()
}

func hasIntegratedTISection(refined review.Result) bool {
	return len(refined.TIReputations) > 0
}

func renderTIIntegratedCard(refined review.Result) string {
	var b strings.Builder
	b.WriteString("<details class=\"finding-card\"><summary><div class=\"finding-summary-main\"><p><strong>补充外联目标与情报信誉</strong></p><p class=\"muted\">原情报信誉区块已并入综合研判，这里保留目标与信誉摘要，完整目标表下沉到折叠层。</p></div><div class=\"finding-summary-side\"><p><strong>目标数</strong></p><p>" + strconv.Itoa(len(refined.TIReputations)) + "</p></div></summary><div class=\"finding-layout\"><div class=\"finding-section wide-list\" style=\"grid-column:1/-1\"><h3>目标与信誉</h3><p class=\"muted\">用于补充外联目标画像，避免在每条风险卡中重复铺开完整目标表。</p><details class=\"mini-card\"><summary>展开目标与信誉明细</summary><div class=\"table-wrap\"><table><tr><th>目标</th><th>信誉</th><th>置信度</th><th>情报来源</th><th>威胁类型</th><th>说明</th><th>行为研判</th></tr>")
	for _, item := range refined.TIReputations {
		b.WriteString("<tr><td>" + html.EscapeString(item.Target) + "</td><td>" + html.EscapeString(localizeReputation(item.Reputation)) + "</td><td>" + fmt.Sprintf("%.2f", item.Confidence) + "</td><td>" + html.EscapeString(defaultIfEmpty(item.Source, "unknown")) + "</td><td>" + html.EscapeString(defaultIfEmpty(item.ThreatType, "n/a")) + "</td><td>" + html.EscapeString(item.Reason) + "</td><td>" + html.EscapeString(describeTargetIntent(item.Target, refined.Behavior)) + "</td></tr>")
	}
	b.WriteString("</table></div></details></div></div></details>")
	return b.String()
}

func hasIntegratedEvasionSection(refined review.Result) bool {
	return refined.Evasion.Detected || len(refined.Evasion.Signals) > 0 || len(refined.Evasion.Differentials) > 0
}

func renderEvasionIntegratedCard(refined review.Result) string {
	status := "未检出"
	if refined.Evasion.Detected {
		status = "已检出"
	}
	var b strings.Builder
	b.WriteString("<details class=\"finding-card\"><summary><div class=\"finding-summary-main\"><p><strong>补充反逃逸与差分执行分析</strong></p><p class=\"muted\">原独立逃逸分析区块已并入综合研判，这里先保留结论与命中信号，差分画像表继续折叠。</p></div><div class=\"finding-summary-side\"><p><strong>状态</strong></p><p>" + html.EscapeString(status) + "</p></div></summary><div class=\"finding-layout\"><div class=\"finding-section\"><h3>逃逸信号</h3>")
	if refined.Evasion.Detected {
		b.WriteString(renderParagraphText("风险结论: 检测到逃逸相关信号，需修复后复测。"))
	}
	b.WriteString(renderHTMLLabeledList("命中信号", refined.Evasion.Signals, 0, "未检出"))
	b.WriteString(renderParagraphText("修复建议: " + defaultIfEmpty(refined.Evasion.Recommendation, "未生成")))
	b.WriteString("</div><div class=\"finding-section\"><h3>差分执行画像</h3><details class=\"mini-card\"><summary>展开差分执行画像</summary>")
	b.WriteString(renderDifferentialTable(refined.Evasion.Differentials))
	b.WriteString("</details></div></div></details>")
	return b.String()
}

func renderReviewWorkflowIntegratedCard(refined review.Result) string {
	var b strings.Builder
	b.WriteString("<details class=\"finding-card review-card\"><summary><div class=\"finding-summary-main\"><p><strong>二次复核任务与裁决（已并入综合研判）</strong></p><p class=\"muted\">仅保留复核任务、标准和最终裁决，不重复风险正文。</p></div><div class=\"finding-summary-side\"><p><strong>任务数</strong></p><p>" + strconv.Itoa(len(refined.ReviewAgentTasks)) + "</p></div></summary><div class=\"finding-layout\"><div class=\"finding-section\"><p class=\"hint\">最终裁决采用保守合成：多 reviewer 结论一致时沿用原结论，存在冲突时回退为需人工复核。</p>")
	ctx := newReviewedFindingContext(refined)
	for _, task := range refined.ReviewAgentTasks {
		label := task.FindingID + " / " + defaultIfEmpty(ctx.structuredFindingTitle(task.FindingID), task.AgentRole)
		b.WriteString("<details class=\"review-task\"><summary>" + html.EscapeString(label) + "</summary>")
		b.WriteString("<p><strong>目标:</strong> " + html.EscapeString(task.Objective) + "</p>")
		if summary := renderReviewStageContextSummary(task); summary != "" {
			b.WriteString("<p><strong>阶段上下文:</strong> " + html.EscapeString(summary) + "</p>")
		}
		if counts := renderReviewStageEvidenceCounts(task); counts != "" {
			b.WriteString("<p><strong>证据计数:</strong> " + html.EscapeString(counts) + "</p>")
		}
		b.WriteString(renderIntentList("输入", task.Inputs))
		b.WriteString(renderIntentList("严格标准", task.StrictStandards))
		b.WriteString(renderIntentList("期望输出", task.ExpectedOutputs))
		b.WriteString(renderIntentList("重点判定条件", task.BlockingCriteria))
		if final := ctx.finalVerdict(task.FindingID); strings.TrimSpace(final.Verdict) != "" {
			b.WriteString("<p><strong>最终裁决:</strong> " + html.EscapeString(localizeReviewVerdict(final.Verdict)) + " / " + html.EscapeString(final.Reviewer) + " / 置信度: " + html.EscapeString(final.Confidence) + "</p>")
			b.WriteString("<p><strong>最终原因:</strong> " + html.EscapeString(final.Reason) + "</p>")
		}
		if fallback := renderReviewFallbackSignals(task, refined); fallback != "" {
			b.WriteString(fallback)
		}
		for _, verdict := range ctx.verdictsForFinding(task.FindingID) {
			selected := "未采用"
			if current := ctx.finalVerdict(verdict.FindingID); strings.TrimSpace(current.Verdict) != "" && current.Reviewer == verdict.Reviewer && current.Verdict == verdict.Verdict {
				selected = "已采用"
			}
			b.WriteString("<div class=\"mini-card\"><p><strong>Reviewer:</strong> " + html.EscapeString(verdict.Reviewer) + "</p><p><strong>裁决:</strong> " + html.EscapeString(localizeReviewVerdict(verdict.Verdict)) + "；<strong>置信度:</strong> " + html.EscapeString(verdict.Confidence) + "；<strong>最终采用:</strong> " + selected + "</p><p><strong>原因:</strong> " + html.EscapeString(verdict.Reason) + "</p>" + renderHTMLLabeledList("缺失证据", verdict.MissingEvidence, 4, "无") + renderReviewToolTrace(verdict.ToolTrace) + "<p><strong>修复建议:</strong> " + html.EscapeString(verdict.Fix) + "</p></div>")
		}
		b.WriteString("<details class=\"mini-card\"><summary>任务原文</summary><pre class=\"code-box\">" + html.EscapeString(task.Prompt) + "</pre></details></details>")
	}
	b.WriteString("</div></div></details>")
	return b.String()
}

func renderReviewTraceIntegratedCard(refined review.Result) string {
	if refined.ReviewTrace == nil || len(refined.ReviewTrace.Entries) == 0 {
		return ""
	}
	finished := reviewTraceFinishedCount(refined.ReviewTrace)
	ctx := newReviewedFindingContext(refined)
	var b strings.Builder
	b.WriteString("<details id=\"review-trace\" class=\"finding-card review-card\"><summary><div class=\"finding-summary-main\"><p><strong>LLM 复核轨迹回放</strong></p><p class=\"muted\">展示各复核任务的执行状态、失败分类、工具轨迹和最近裁决，用于历史排障与审计追溯。</p></div><div class=\"finding-summary-side\"><p><strong>进度</strong></p><p>" + strconv.Itoa(finished) + "/" + strconv.Itoa(refined.ReviewTrace.Total) + "</p></div></summary><div class=\"finding-layout\"><div class=\"finding-section wide-list\" style=\"grid-column:1/-1\">")
	b.WriteString(renderReviewTraceSummary(refined.ReviewTrace))
	for _, entry := range sortedReviewTraceEntries(refined.ReviewTrace.Entries) {
		b.WriteString(renderReviewTraceEntryCard(entry, ctx))
	}
	b.WriteString("</div></div></details>")
	return b.String()
}

func renderReviewStageContextSummary(task review.ReviewAgentTask) string {
	if task.StageContext == nil {
		return ""
	}
	parts := make([]string, 0, 5)
	finding := task.StageContext.Finding
	if strings.TrimSpace(finding.Category) != "" {
		parts = append(parts, "分类="+strings.TrimSpace(finding.Category))
	}
	if strings.TrimSpace(finding.Severity) != "" {
		parts = append(parts, "级别="+strings.TrimSpace(finding.Severity))
	}
	if strings.TrimSpace(finding.Status) != "" {
		parts = append(parts, "状态="+strings.TrimSpace(finding.Status))
	}
	if strings.TrimSpace(finding.PrimaryLocation) != "" {
		parts = append(parts, "关键位置="+strings.TrimSpace(finding.PrimaryLocation))
	}
	if strings.TrimSpace(finding.ExplanationSummary) != "" {
		parts = append(parts, "摘要="+strings.TrimSpace(finding.ExplanationSummary))
	}
	return strings.Join(parts, " | ")
}

func renderReviewStageEvidenceCounts(task review.ReviewAgentTask) string {
	if task.StageContext == nil {
		return ""
	}
	finding := task.StageContext.Finding
	parts := make([]string, 0, 4)
	if len(finding.CodeEvidenceRefs) > 0 {
		parts = append(parts, "代码证据="+strconv.Itoa(len(finding.CodeEvidenceRefs)))
	}
	if len(finding.BehaviorEvidenceRefs) > 0 {
		parts = append(parts, "行为证据="+strconv.Itoa(len(finding.BehaviorEvidenceRefs)))
	}
	if len(finding.ContextEvidenceRefs) > 0 {
		parts = append(parts, "上下文证据="+strconv.Itoa(len(finding.ContextEvidenceRefs)))
	}
	if len(finding.EvidenceRefs) > 0 {
		parts = append(parts, "总证据="+strconv.Itoa(len(finding.EvidenceRefs)))
	}
	return strings.Join(parts, " | ")
}

func renderReviewToolTrace(items []review.ToolTraceEntry) string {
	if len(items) == 0 {
		return ""
	}
	lines := make([]string, 0, len(items))
	for _, item := range items {
		line := "iter " + strconv.Itoa(item.Iteration) + " / " + item.ToolName + " / " + localizeReviewToolStatus(item.Status)
		if strings.TrimSpace(item.Summary) != "" {
			line += " / " + item.Summary
		}
		lines = append(lines, line)
	}
	return renderHTMLLabeledList("LLM 工具轨迹", lines, 6, "无")
}

func renderReviewFallbackSignals(task review.ReviewAgentTask, refined review.Result) string {
	traceEntry, ok := reviewTraceEntryByFinding(refined.ReviewTrace, task.FindingID)
	if !ok {
		return ""
	}
	items := make([]string, 0, 3)
	if traceEntry.Status == "failed" {
		items = append(items, "LLM 单项复核状态: "+localizeReviewProgressStatus(traceEntry.Status))
	}
	if strings.TrimSpace(traceEntry.FailureLabel) != "" {
		items = append(items, "失败分类: "+traceEntry.FailureLabel)
	}
	if detail := reviewFailureDetail(traceEntry); detail != "" {
		items = append(items, "回退原因: "+detail)
	}
	if traceEntry.DurationMs > 0 {
		items = append(items, "最近一次耗时: "+strconv.FormatInt(traceEntry.DurationMs, 10)+"ms")
	}
	if len(items) == 0 {
		return ""
	}
	return renderHTMLLabeledList("复核回退与异常", items, 4, "无")
}

func reviewFailureDetail(entry review.ReviewTraceEntry) string {
	switch strings.TrimSpace(entry.FailureKind) {
	case "balance_exhausted":
		return "LLM 账户余额不足，当前项已回退为需人工复核，并按规则复核结果继续生成报告"
	case "request_canceled":
		return "LLM 请求被取消，当前项已回退为需人工复核，并按规则复核结果继续生成报告"
	case "timeout":
		return "LLM 复核超时，已按规则复核结果继续生成报告"
	case "iteration_limit":
		return "LLM 工具迭代达到上限，已回退为需人工复核"
	case "tool_rejected":
		return "LLM 请求了受限工具，工具调用被拒绝，已按规则复核结果继续生成报告"
	case "invalid_response":
		return "LLM 返回结果不符合预期格式，已按规则复核结果继续生成报告"
	case "execution_error":
		return "LLM 复核执行失败，已按规则复核结果继续生成报告"
	default:
		return ""
	}
}

func localizeReviewFailureShortLabel(kind, label string) string {
	switch strings.TrimSpace(kind) {
	case "balance_exhausted":
		return "余额不足"
	case "request_canceled":
		return "请求取消"
	case "timeout":
		return "超时"
	case "invalid_response":
		return "无效响应"
	case "tool_rejected":
		return "工具拒绝"
	case "iteration_limit":
		return "迭代上限"
	case "execution_error":
		return "执行失败"
	default:
		if strings.TrimSpace(label) != "" {
			return strings.TrimSpace(label)
		}
		return "失败"
	}
}

func renderReviewTraceSummary(trace *review.ReviewTrace) string {
	if trace == nil {
		return ""
	}
	items := reviewTraceSummaryItems(trace)
	return renderHTMLLabeledList("轨迹摘要", items, 8, "无")
}

func reviewTraceSummaryText(trace *review.ReviewTrace) string {
	items := reviewTraceSummaryItems(trace)
	if len(items) == 0 {
		return ""
	}
	return strings.Join(items, " | ")
}

func reviewTraceSummaryItems(trace *review.ReviewTrace) []string {
	if trace == nil {
		return nil
	}
	stats := summarizeReviewTrace(trace)
	finished := reviewTraceFinishedCount(trace)
	items := []string{
		"总任务数: " + strconv.Itoa(trace.Total),
		"已完成: " + strconv.Itoa(finished),
		"成功: " + strconv.Itoa(stats.successCount),
		"失败: " + strconv.Itoa(stats.failedCount),
	}
	if stats.timeoutCount > 0 {
		items = append(items, "超时: "+strconv.Itoa(stats.timeoutCount))
	}
	if stats.balanceExhaustedCount > 0 {
		items = append(items, "余额不足: "+strconv.Itoa(stats.balanceExhaustedCount))
	}
	if stats.requestCanceledCount > 0 {
		items = append(items, "请求取消: "+strconv.Itoa(stats.requestCanceledCount))
	}
	if stats.invalidResponseCount > 0 {
		items = append(items, "无效响应: "+strconv.Itoa(stats.invalidResponseCount))
	}
	if stats.toolRejectedCount > 0 {
		items = append(items, "工具拒绝: "+strconv.Itoa(stats.toolRejectedCount))
	}
	if stats.iterationLimitCount > 0 {
		items = append(items, "迭代上限: "+strconv.Itoa(stats.iterationLimitCount))
	}
	if stats.executionErrorCount > 0 {
		items = append(items, "执行失败: "+strconv.Itoa(stats.executionErrorCount))
	}
	if stats.avgDurationMs > 0 {
		items = append(items, "平均耗时: "+strconv.FormatInt(stats.avgDurationMs, 10)+"ms")
	}
	if strings.TrimSpace(trace.CurrentFindingTitle) != "" {
		items = append(items, "最近项: "+trace.CurrentFindingTitle)
	}
	if strings.TrimSpace(trace.LastVerdict) != "" {
		items = append(items, "最近裁决: "+localizeReviewVerdict(trace.LastVerdict))
	}
	if trace.LastDurationMs > 0 {
		items = append(items, "最近耗时: "+strconv.FormatInt(trace.LastDurationMs, 10)+"ms")
	}
	if trace.Failed && strings.TrimSpace(trace.ErrorMessage) != "" {
		items = append(items, "全局错误: "+trace.ErrorMessage)
	}
	return items
}

func reviewTraceFinishedCount(trace *review.ReviewTrace) int {
	if trace == nil {
		return 0
	}
	finished := trace.Completed
	stats := summarizeReviewTrace(trace)
	if derived := stats.successCount + stats.failedCount; derived > finished {
		finished = derived
	}
	return finished
}

type reviewTraceSummaryStats struct {
	successCount          int
	failedCount           int
	balanceExhaustedCount int
	requestCanceledCount  int
	timeoutCount          int
	invalidResponseCount  int
	toolRejectedCount     int
	iterationLimitCount   int
	executionErrorCount   int
	avgDurationMs         int64
}

func summarizeReviewTrace(trace *review.ReviewTrace) reviewTraceSummaryStats {
	stats := reviewTraceSummaryStats{}
	if trace == nil || len(trace.Entries) == 0 {
		return stats
	}
	var durationSum int64
	var durationCount int64
	for _, entry := range trace.Entries {
		switch strings.TrimSpace(entry.Status) {
		case "completed":
			stats.successCount++
		case "failed":
			stats.failedCount++
		}
		switch strings.TrimSpace(entry.FailureKind) {
		case "balance_exhausted":
			stats.balanceExhaustedCount++
		case "request_canceled":
			stats.requestCanceledCount++
		case "timeout":
			stats.timeoutCount++
		case "invalid_response":
			stats.invalidResponseCount++
		case "tool_rejected":
			stats.toolRejectedCount++
		case "iteration_limit":
			stats.iterationLimitCount++
		case "execution_error":
			stats.executionErrorCount++
		}
		if entry.DurationMs > 0 {
			durationSum += entry.DurationMs
			durationCount++
		}
	}
	if durationCount > 0 {
		stats.avgDurationMs = durationSum / durationCount
	}
	return stats
}

func renderReviewTraceEntryCard(entry review.ReviewTraceEntry, ctx reviewedFindingContext) string {
	items := make([]string, 0, 9)
	items = append(items, "状态: "+localizeReviewProgressStatus(entry.Status))
	if strings.TrimSpace(entry.Verdict) != "" {
		items = append(items, "轨迹裁决: "+localizeReviewVerdict(entry.Verdict))
	}
	if strings.TrimSpace(entry.Confidence) != "" {
		items = append(items, "轨迹置信度: "+entry.Confidence)
	}
	if strings.TrimSpace(entry.Reviewer) != "" {
		items = append(items, "轨迹 Reviewer: "+entry.Reviewer)
	}
	if final := ctx.finalVerdict(entry.FindingID); strings.TrimSpace(final.Verdict) != "" {
		items = append(items, "最终采用裁决: "+localizeReviewVerdict(final.Verdict))
		selectedText := "已被后续合并结果覆盖"
		if reviewTraceMatchesFinalVerdict(entry, final) {
			selectedText = "该轨迹裁决已成为最终采用结果"
		}
		items = append(items, "采用状态: "+selectedText)
	}
	if strings.TrimSpace(entry.FailureLabel) != "" {
		items = append(items, "失败分类: "+entry.FailureLabel)
	}
	if detail := reviewFailureDetail(entry); detail != "" {
		items = append(items, "回退原因: "+detail)
	}
	if strings.TrimSpace(entry.Reason) != "" {
		items = append(items, "原始说明: "+entry.Reason)
	}
	if entry.DurationMs > 0 {
		items = append(items, "耗时: "+strconv.FormatInt(entry.DurationMs, 10)+"ms")
	}
	title := defaultIfEmpty(entry.FindingTitle, entry.FindingID)
	if entry.Status == "failed" && strings.TrimSpace(entry.FailureKind) != "" {
		title += " [" + localizeReviewFailureShortLabel(entry.FailureKind, entry.FailureLabel) + "]"
	}
	var b strings.Builder
	b.WriteString("<details class=\"review-task\"><summary>" + html.EscapeString(title) + "</summary>")
	b.WriteString(renderHTMLLabeledList("轨迹详情", items, 8, "无"))
	b.WriteString(renderHTMLLabeledList("缺失证据", entry.MissingEvidence, 6, "无"))
	b.WriteString(renderReviewToolTrace(entry.ToolTrace))
	if strings.TrimSpace(entry.Fix) != "" {
		b.WriteString(renderParagraphText("修复建议: " + entry.Fix))
	}
	b.WriteString("</details>")
	return b.String()
}

func reviewTraceMatchesFinalVerdict(entry review.ReviewTraceEntry, final review.ReviewAgentVerdict) bool {
	if strings.TrimSpace(entry.FindingID) == "" || strings.TrimSpace(final.FindingID) == "" {
		return false
	}
	if strings.TrimSpace(entry.FindingID) != strings.TrimSpace(final.FindingID) {
		return false
	}
	if normalizedReviewVerdict(entry.Verdict) != normalizedReviewVerdict(final.Verdict) {
		return false
	}
	return true
}

func sortedReviewTraceEntries(entries []review.ReviewTraceEntry) []review.ReviewTraceEntry {
	out := append([]review.ReviewTraceEntry{}, entries...)
	slices.SortStableFunc(out, func(a, b review.ReviewTraceEntry) int {
		if a.UpdatedAt == b.UpdatedAt {
			return strings.Compare(strings.TrimSpace(a.FindingID), strings.TrimSpace(b.FindingID))
		}
		if a.UpdatedAt > b.UpdatedAt {
			return -1
		}
		return 1
	})
	return out
}

func reviewTraceEntryByFinding(trace *review.ReviewTrace, findingID string) (review.ReviewTraceEntry, bool) {
	if trace == nil {
		return review.ReviewTraceEntry{}, false
	}
	for _, entry := range trace.Entries {
		if strings.TrimSpace(entry.FindingID) == strings.TrimSpace(findingID) {
			return entry, true
		}
	}
	return review.ReviewTraceEntry{}, false
}

func localizeReviewProgressStatus(status string) string {
	switch strings.TrimSpace(status) {
	case "pending":
		return "待执行"
	case "running":
		return "复核中"
	case "completed":
		return "已完成"
	case "failed":
		return "失败"
	default:
		if strings.TrimSpace(status) == "" {
			return "未知状态"
		}
		return strings.TrimSpace(status)
	}
}

func localizeReviewToolStatus(status string) string {
	switch strings.TrimSpace(status) {
	case "completed":
		return "已完成"
	case "rejected":
		return "已拒绝"
	case "failed":
		return "失败"
	case "running":
		return "执行中"
	case "pending":
		return "待执行"
	default:
		if strings.TrimSpace(status) == "" {
			return "未知状态"
		}
		return strings.TrimSpace(status)
	}
}

func boolText(v bool) string {
	if v {
		return "true"
	}
	return "false"
}

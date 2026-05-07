package handler

import (
	"fmt"
	"html"
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
	b.WriteString("<details class=\"finding-card\"><summary><div class=\"finding-summary-main\"><p><strong>补充外联目标与情报信誉</strong></p><p class=\"muted\">原情报信誉区块已并入综合研判，这里保留目标与信誉摘要，完整目标表下沉到折叠层。</p></div><div class=\"finding-summary-side\"><p><strong>目标数</strong></p><p>" + strconv.Itoa(len(refined.TIReputations)) + "</p></div></summary><div class=\"finding-layout\"><div class=\"finding-section wide-list\" style=\"grid-column:1/-1\"><h3>目标与信誉</h3><p class=\"muted\">用于补充外联目标画像，避免在每条风险卡中重复铺开完整目标表。</p><details class=\"mini-card\"><summary>展开目标与信誉明细</summary><div class=\"table-wrap\"><table><tr><th>目标</th><th>信誉</th><th>置信度</th><th>说明</th><th>行为研判</th></tr>")
	for _, item := range refined.TIReputations {
		b.WriteString("<tr><td>" + html.EscapeString(item.Target) + "</td><td>" + html.EscapeString(localizeReputation(item.Reputation)) + "</td><td>" + fmt.Sprintf("%.2f", item.Confidence) + "</td><td>" + html.EscapeString(item.Reason) + "</td><td>" + html.EscapeString(describeTargetIntent(item.Target, refined.Behavior)) + "</td></tr>")
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
	preferred := preferredVerdictsByFinding(refined.ReviewAgentVerdicts)
	verdictsByFinding := reviewVerdictsByFinding(refined.ReviewAgentVerdicts)
	titleByFinding := structuredFindingTitleByID(refined.StructuredFindings)
	for _, task := range refined.ReviewAgentTasks {
		label := task.FindingID + " / " + defaultIfEmpty(titleByFinding[task.FindingID], task.AgentRole)
		b.WriteString("<details class=\"review-task\"><summary>" + html.EscapeString(label) + "</summary>")
		b.WriteString("<p><strong>目标:</strong> " + html.EscapeString(task.Objective) + "</p>")
		b.WriteString(renderIntentList("输入", task.Inputs))
		b.WriteString(renderIntentList("严格标准", task.StrictStandards))
		b.WriteString(renderIntentList("期望输出", task.ExpectedOutputs))
		b.WriteString(renderIntentList("重点判定条件", task.BlockingCriteria))
		if final, ok := preferred[task.FindingID]; ok {
			b.WriteString("<p><strong>最终裁决:</strong> " + html.EscapeString(final.Verdict) + " / " + html.EscapeString(final.Reviewer) + " / 置信度: " + html.EscapeString(final.Confidence) + "</p>")
			b.WriteString("<p><strong>最终原因:</strong> " + html.EscapeString(final.Reason) + "</p>")
		}
		for _, verdict := range verdictsByFinding[task.FindingID] {
			selected := "否"
			if current, ok := preferred[verdict.FindingID]; ok && current.Reviewer == verdict.Reviewer && current.Verdict == verdict.Verdict {
				selected = "是"
			}
			b.WriteString("<div class=\"mini-card\"><p><strong>Reviewer:</strong> " + html.EscapeString(verdict.Reviewer) + "</p><p><strong>裁决:</strong> " + html.EscapeString(verdict.Verdict) + "；<strong>置信度:</strong> " + html.EscapeString(verdict.Confidence) + "；<strong>最终采用:</strong> " + selected + "</p><p><strong>原因:</strong> " + html.EscapeString(verdict.Reason) + "</p>" + renderHTMLLabeledList("缺失证据", verdict.MissingEvidence, 4, "无") + "<p><strong>修复建议:</strong> " + html.EscapeString(verdict.Fix) + "</p></div>")
		}
		b.WriteString("<details class=\"mini-card\"><summary>任务原文</summary><pre class=\"code-box\">" + html.EscapeString(task.Prompt) + "</pre></details></details>")
	}
	b.WriteString("</div></div></details>")
	return b.String()
}

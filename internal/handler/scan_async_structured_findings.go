package handler

import (
	"html"
	"strconv"
	"strings"

	"skill-scanner/internal/review"
)

func renderStructuredFindingsSection(refined review.Result) string {
	var b strings.Builder
	b.WriteString("<div id=\"structured-findings\" class=\"card\"><div class=\"section-head\"><h2>风险与能力综合研判</h2><span class=\"hint\">按单条风险聚合展示规则依据、能力状态、证据、误报复核与修复建议；默认折叠，展开后直接看全量内容。</span></div>")
	if len(refined.StructuredFindings) == 0 && len(refined.CapabilityMatrix) == 0 && len(refined.EvidenceInventory) == 0 {
		b.WriteString("<p>未形成综合研判结果。</p>")
		b.WriteString("</div>")
		return b.String()
	}

	ruleByID := ruleExplanationByID(refined.RuleExplanations)
	fpByID := falsePositiveReviewByID(refined.FalsePositiveReviews)
	reviewDepth := reviewVerdictCountByFinding(refined.ReviewAgentVerdicts)
	b.WriteString("<div class=\"findings-stack\">")
	for _, finding := range sortStructuredFindingsByReview(refined.StructuredFindings, refined) {
		b.WriteString(renderStructuredFindingCard(finding, refined, ruleByID, fpByID, reviewDepth))
	}
	b.WriteString("</div></div>")
	return b.String()
}

func renderStructuredFindingCard(
	finding review.StructuredFinding,
	refined review.Result,
	ruleByID map[string]review.RuleExplanation,
	fpByID map[string]review.FalsePositiveReview,
	reviewDepth map[string]int,
) string {
	var b strings.Builder
	className := "risk-low"
	if finding.Severity == "高风险" {
		className = "risk-high"
	} else if finding.Severity == "中风险" {
		className = "risk-medium"
	}
	rule := ruleByID[finding.RuleID]
	fp := fpByID[finding.ID]
	finalReview := finalReviewSummaryForStructuredFinding(finding.ID, refined)
	capabilities := capabilityItemsForFinding(finding, refined.CapabilityMatrix)
	evidenceLines := capabilityEvidenceForFinding(finding, refined.CapabilityMatrix, refined.EvidenceInventory, refined.Behavior)
	findingSources := structuredFindingSourceLabels(finding, finalReview, reviewDepth[finding.ID])

	b.WriteString("<details class=\"finding-card severity-" + severityClassSuffix(finding.Severity) + "\"><summary><div class=\"finding-summary-main\"><p><strong>" + html.EscapeString(finding.ID+" / "+finding.Title) + "</strong></p><div class=\"finding-meta\"><span class=\"" + className + "\">" + html.EscapeString(finding.Severity) + "</span><span class=\"pill\">" + html.EscapeString(finding.Category) + "</span><span class=\"muted\">来源: " + html.EscapeString(finding.Source) + "</span></div>" + renderSourceBadgeStrip(findingSources) + "<p class=\"muted\">攻击路径: " + html.EscapeString(finding.AttackPath) + "</p></div><div class=\"finding-summary-side\"><p><strong>最终复核</strong></p><p>" + html.EscapeString(finalReview) + "</p><p class=\"muted\">合并命中: " + strconv.Itoa(finding.DeduplicatedCount) + "</p></div></summary>")
	b.WriteString("<div class=\"finding-layout\"><div class=\"finding-section\"><h3>风险研判与规则依据</h3><p><strong>置信度:</strong> " + html.EscapeString(defaultIfEmpty(finding.Confidence, "待复核")) + "</p>" + renderHTMLLabeledList("来源构成", findingSources, 0, "未生成") + renderHTMLLabeledList("MITRE ATT&CK 映射", finding.MITRETechniques, 0, "未映射") + renderParagraphText("影响: "+impactForFinding(finding)) + renderHTMLLabeledList("检测条件", rule.DetectionCriteria, 0, "未生成") + renderHTMLLabeledList("排除条件", rule.ExclusionConditions, 0, "未生成") + renderHTMLLabeledList("验证要求", rule.VerificationRequirements, 0, "未生成") + renderHTMLLabeledList("输出要求", rule.OutputRequirements, 0, "未生成") + "</div>")
	b.WriteString("<div class=\"finding-section\"><h3>证据与误报复核</h3>" + renderHTMLEvidenceList("关键证据", finding.Evidence, "未提取") + renderHTMLLabeledList("校准依据", finding.CalibrationBasis, 0, "未生成") + renderHTMLLabeledList("误报检查", finding.FalsePositiveChecks, 0, "未生成") + renderHTMLLabeledList("可达性检查", fp.ReachabilityChecks, 0, "未生成") + renderHTMLLabeledList("排除复核", fp.ExclusionChecks, 0, "未生成") + renderHTMLLabeledList("后续要求", fp.RequiredFollowUp, 0, "未生成") + "</div>")
	b.WriteString("<div class=\"finding-section\"><h3>相关能力与证据</h3><div class=\"capability-strip\">")
	if len(capabilities) == 0 {
		b.WriteString("<p class=\"muted\">未匹配到直接相关的能力一致性项。</p>")
	} else {
		for _, item := range capabilities {
			primaryEvidence := defaultIfEmpty(capabilityPrimaryEvidenceForFinding(finding, item, refined.EvidenceInventory, refined.Behavior), defaultIfEmpty(strings.Join(finding.Evidence, "；"), "未提取"))
			b.WriteString("<div class=\"capability-card\"><p><strong>" + html.EscapeString(item.Capability) + "</strong></p>" + renderSourceBadgeStrip(capabilitySourceLabels(item, finalReview, reviewDepth[finding.ID])) + "<p><strong>状态:</strong> " + html.EscapeString(item.Status) + "</p><p><strong>声明/静态/LLM/沙箱/情报:</strong> " + yesNo(item.Declared) + " / " + yesNo(item.StaticDetected) + " / " + yesNo(item.LLMDetected) + " / " + yesNo(item.SandboxDetected) + " / " + yesNo(item.TIObserved) + "</p>" + renderParagraphText("对应风险影响: "+impactForFinding(finding)) + renderParagraphText("对应证据: "+primaryEvidence) + renderParagraphText("对应修复建议: "+defaultIfEmpty(finding.ReviewGuidance, defaultIfEmpty(item.NextStep, defaultIfEmpty(rule.RemediationFocus, ruleRemediationFocus(finding.Category))))) + renderParagraphText("缺口: "+defaultIfEmpty(item.Gap, "无明确缺口")) + "</div>")
		}
	}
	b.WriteString(renderHTMLInventoryEvidenceList("该风险补充证据", evidenceLines, "未汇总到补充证据目录"))
	b.WriteString("</div></div>")
	b.WriteString("<div class=\"finding-section\"><h3>修复建议与处置方向</h3>" + renderParagraphText("结构化建议: "+finding.ReviewGuidance) + renderParagraphText("复核结论: "+defaultIfEmpty(fp.Verdict, "待人工复核")) + renderParagraphText("对应修复建议: "+defaultIfEmpty(rule.RemediationFocus, ruleRemediationFocus(finding.Category))) + "</div></div></details>")
	return b.String()
}

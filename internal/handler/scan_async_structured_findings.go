package handler

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
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
	ctx := newReviewedFindingContext(refined)
	primaryFindings, secondaryFindings := splitStructuredFindingsForDisplay(sortStructuredFindingsByReview(refined.StructuredFindings, refined))
	b.WriteString("<div class=\"findings-stack\">")
	for _, finding := range primaryFindings {
		b.WriteString(renderStructuredFindingCard(finding, refined, ctx, ruleByID, fpByID, reviewDepth))
	}
	b.WriteString("</div>")
	if len(secondaryFindings) > 0 {
		b.WriteString("<details class=\"mini-card\"><summary>展开低优先级文档与交付提示（" + strconv.Itoa(len(secondaryFindings)) + " 条）</summary><div class=\"findings-stack\">")
		for _, finding := range secondaryFindings {
			b.WriteString(renderStructuredFindingCard(finding, refined, ctx, ruleByID, fpByID, reviewDepth))
		}
		b.WriteString("</div></details>")
	}
	b.WriteString("</div>")
	return b.String()
}

func splitStructuredFindingsForDisplay(findings []review.StructuredFinding) ([]review.StructuredFinding, []review.StructuredFinding) {
	primary := make([]review.StructuredFinding, 0, len(findings))
	secondary := make([]review.StructuredFinding, 0)
	for _, finding := range findings {
		if shouldRenderStructuredFindingAsSecondary(finding) {
			secondary = append(secondary, finding)
			continue
		}
		primary = append(primary, finding)
	}
	return primary, secondary
}

func shouldRenderStructuredFindingAsSecondary(finding review.StructuredFinding) bool {
	if strings.TrimSpace(finding.Title) == "声明与交付内容需人工复核" {
		return true
	}
	if strings.TrimSpace(finding.SecurityVerdict) == "confirmed" {
		return false
	}
	if !isLikelyDocumentationOnlyFinding(finding) {
		return false
	}
	category := strings.TrimSpace(finding.Category)
	switch category {
	case "外联与情报", "命令执行", "凭据访问", "凭据暴露", "声明与行为差异":
	default:
		return false
	}
	joined := strings.ToLower(strings.Join(finding.Evidence, " "))
	for _, token := range []string{"readme.md", "/docs/", "docs/", "/examples/", "examples/", "/example/", "example/", "/demo/", "demo/", "/sample/", "sample/", "/test/", "test/", "/tests/", "tests/", "/fixture/", "fixture/", "/fixtures/", "fixtures/", "/mock/", "mock/", "/mocks/", "mocks/", "示例"} {
		if strings.Contains(joined, token) {
			return true
		}
	}
	return false
}

func renderStructuredFindingCard(
	finding review.StructuredFinding,
	refined review.Result,
	ctx reviewedFindingContext,
	ruleByID map[string]review.RuleExplanation,
	fpByID map[string]review.FalsePositiveReview,
	reviewDepth map[string]int,
) string {
	var b strings.Builder
	displaySeverity := ctx.normalizedSeverity(finding)
	className := "risk-low"
	if displaySeverity == "高风险" {
		className = "risk-high"
	} else if displaySeverity == "中风险" {
		className = "risk-medium"
	}
	rule := ruleByID[finding.RuleID]
	fp := fpByID[finding.ID]
	finalVerdict := ctx.finalVerdict(finding.ID)
	finalReview := finalReviewSummaryForStructuredFinding(finding.ID, ctx)
	evidenceLines := capabilityEvidenceForFinding(finding, refined.CapabilityMatrix, refined.EvidenceInventory, refined.Behavior)
	findingSources := structuredFindingSourceLabels(finding, finalReview, reviewDepth[finding.ID])
	mainEvidence := buildMainEvidenceForFinding(finding, evidenceLines, finalReview)
	securityVerdict := defaultIfEmpty(finding.SecurityVerdict, "needs_manual_review")
	if normalizedReviewVerdict(finalVerdict.Verdict) != "" {
		securityVerdict = normalizedReviewVerdict(finalVerdict.Verdict)
	}
	declarationGroup := declarationSubtypeLabel(finding)

	b.WriteString("<details class=\"finding-card severity-" + severityClassSuffix(displaySeverity) + "\"><summary><div class=\"finding-summary-main\"><p><strong>" + html.EscapeString(finding.ID+" / "+finding.Title) + "</strong></p><div class=\"finding-meta\"><span class=\"" + className + "\">" + html.EscapeString(displaySeverity) + "</span><span class=\"pill\">" + html.EscapeString(finding.Category) + "</span>" + renderDeclarationSubtypePill(declarationGroup) + "<span class=\"muted\">来源: " + html.EscapeString(finding.Source) + "</span></div>" + renderSourceBadgeStrip(findingSources) + "<p class=\"muted\">攻击路径: " + html.EscapeString(finding.AttackPath) + "</p></div><div class=\"finding-summary-side\"><p><strong>最终复核</strong></p><p>" + html.EscapeString(finalReview) + "</p><p class=\"muted\">安全结论: " + html.EscapeString(localizeReviewVerdict(securityVerdict)) + "</p><p class=\"muted\">声明结论: " + html.EscapeString(localizeDeclarationVerdict(finding.DeclarationVerdict)) + "</p><p class=\"muted\">同链路合并: " + strconv.Itoa(finding.DeduplicatedCount) + " 条</p></div></summary>")
	b.WriteString("<div class=\"finding-layout\"><div class=\"finding-section\"><h3>风险研判与规则依据</h3><p><strong>置信度:</strong> " + html.EscapeString(defaultIfEmpty(finding.Confidence, "待复核")) + "</p>" + renderHTMLLabeledList("来源构成", findingSources, 0, "未生成") + renderHTMLLabeledList("MITRE ATT&CK 映射", finding.MITRETechniques, 0, "未映射") + renderParagraphText("影响: "+impactForFinding(finding)) + renderHTMLLabeledList("检测条件", rule.DetectionCriteria, 0, "未生成") + renderHTMLLabeledList("排除条件", rule.ExclusionConditions, 0, "未生成") + renderHTMLLabeledList("验证要求", rule.VerificationRequirements, 0, "未生成") + renderHTMLLabeledList("输出要求", rule.OutputRequirements, 0, "未生成") + "</div>")
	b.WriteString("<div class=\"finding-section\"><h3>证据与误报复核</h3>" + renderHTMLEvidenceList("关键证据", mainEvidence, "未提取"))
	b.WriteString(renderHTMLLabeledList("链路闭环", closureSummaryForFinding(finding), 0, "未生成") + renderHTMLLabeledList("规则适用性", applicabilitySummaryForFinding(finding), 0, "未生成") + renderHTMLLabeledList("校准依据", finding.CalibrationBasis, 0, "未生成") + renderHTMLLabeledList("误报检查", finding.FalsePositiveChecks, 0, "未生成") + renderHTMLLabeledList("可达性检查", fp.ReachabilityChecks, 0, "未生成") + renderHTMLLabeledList("排除复核", fp.ExclusionChecks, 0, "未生成") + renderHTMLLabeledList("后续要求", fp.RequiredFollowUp, 0, "未生成") + renderExcludedEvidenceSection(finding) + "</div>")
	b.WriteString(renderEmbeddedReviewSummaryForFinding(finding, refined, finalVerdict))
	b.WriteString("<div class=\"finding-section\"><h3>修复建议与处置方向</h3>" + renderParagraphText("结构化建议: "+finding.ReviewGuidance) + renderParagraphText("复核结论: "+defaultIfEmpty(fp.Verdict, "待人工复核")) + renderParagraphText("对应修复建议: "+defaultIfEmpty(rule.RemediationFocus, ruleRemediationFocus(finding.Category))) + "</div>")
	b.WriteString(renderBusinessFixExamples(finding))
	b.WriteString("</div></details>")
	return b.String()
}

func renderEmbeddedReviewSummaryForFinding(finding review.StructuredFinding, refined review.Result, finalVerdict review.ReviewAgentVerdict) string {
	var b strings.Builder
	b.WriteString("<div class=\"finding-section\"><h3>复核摘要</h3>")
	items := make([]string, 0, 6)
	if strings.TrimSpace(finalVerdict.Verdict) != "" {
		items = append(items, "最终裁决: "+localizeReviewVerdict(finalVerdict.Verdict))
	}
	if strings.TrimSpace(finalVerdict.Reviewer) != "" {
		items = append(items, "复核器: "+localizeReviewerLabel(finalVerdict.Reviewer))
	}
	if strings.TrimSpace(finalVerdict.Confidence) != "" {
		items = append(items, "置信度: "+finalVerdict.Confidence)
	}
	if strings.TrimSpace(finalVerdict.Reason) != "" {
		items = append(items, "最终原因: "+finalVerdict.Reason)
	}
	if entry, ok := reviewTraceEntryByFinding(refined.ReviewTrace, finding.ID); ok {
		items = append(items, "轨迹状态: "+localizeReviewProgressStatus(entry.Status))
		if strings.TrimSpace(entry.FailureLabel) != "" {
			items = append(items, "失败分类: "+entry.FailureLabel)
			items = append(items, "失败标签: "+localizeReviewFailureShortLabel(entry.FailureKind, entry.FailureLabel))
		}
		if detail := reviewFailureDetail(entry); detail != "" {
			items = append(items, "回退原因: "+detail)
		}
		if entry.DurationMs > 0 {
			items = append(items, "最近耗时: "+strconv.FormatInt(entry.DurationMs, 10)+"ms")
		}
		b.WriteString(renderHTMLLabeledList("摘要", items, 8, "无"))
		b.WriteString("<details class=\"mini-card\"><summary>展开复核轨迹</summary>")
		b.WriteString(renderReviewToolTrace(entry.ToolTrace))
		if strings.TrimSpace(entry.Reason) != "" {
			b.WriteString(renderParagraphText("轨迹说明: " + entry.Reason))
		}
		b.WriteString("</details>")
	} else {
		b.WriteString(renderHTMLLabeledList("摘要", items, 8, "无"))
	}
	b.WriteString("</div>")
	return b.String()
}

func renderDeclarationSubtypePill(label string) string {
	label = strings.TrimSpace(label)
	if label == "" {
		return ""
	}
	return "<span class=\"pill\">" + html.EscapeString(label) + "</span>"
}

func declarationSubtypeLabel(finding review.StructuredFinding) string {
	if finding.Category != "声明与行为差异" {
		return ""
	}
	joined := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), " "))
	switch {
	case strings.Contains(joined, "private_key") || strings.Contains(joined, "token") || strings.Contains(joined, "secret") || strings.Contains(joined, "凭据"):
		return "凭据处理"
	case strings.Contains(joined, "git clone") || strings.Contains(joined, "bootstrap.sh") || strings.Contains(joined, "pip install") || strings.Contains(joined, "依赖来源") || strings.Contains(joined, "供应链"):
		return "供应链引入"
	case strings.Contains(joined, "create_order") || strings.Contains(joined, "live trading") || strings.Contains(joined, "signed_order") || strings.Contains(joined, "自动交易") || strings.Contains(joined, "下单"):
		return "自动交易"
	case strings.Contains(joined, "http") || strings.Contains(joined, "webhook") || strings.Contains(joined, "localhost") || strings.Contains(joined, "license_server") || strings.Contains(joined, "网络"):
		return "网络访问"
	case strings.Contains(joined, "session") || strings.Contains(joined, "收集") || strings.Contains(joined, "data"):
		return "数据收集"
	case strings.Contains(joined, "exec") || strings.Contains(joined, "shell") || strings.Contains(joined, "subprocess") || strings.Contains(joined, "命令"):
		return "命令执行"
	default:
		return "声明差异"
	}
}

func renderBusinessFixExamples(finding review.StructuredFinding) string {
	loc := firstSourceLocationFromEvidence(finding.Evidence)
	var b strings.Builder
	b.WriteString("<div class=\"finding-section\"><h3>可直接落地的修改示例</h3>")
	b.WriteString("<p class=\"muted\">以下示例用于帮助业务和研发快速对齐修复动作，请按实际代码语境调整。</p>")
	if loc != "" {
		b.WriteString("<p><strong>建议修改位置:</strong> " + html.EscapeString(loc) + "</p>")
	}
	switch finding.Category {
	case "命令执行", "下载执行", "恶意代码":
		b.WriteString(renderCodeEvidence("示例修改（命令执行收敛）", "# before\nsubprocess.run(user_input, shell=True)\n\n# after\nallowed = {\"status\": [\"python3\", \"app.py\", \"status\"]}\ncmd = allowed.get(user_input)\nif cmd is None:\n    raise ValueError(\"unsupported command\")\nsubprocess.run(cmd, check=True)"))
	case "外联与情报", "敏感数据外发与隐蔽通道":
		b.WriteString(renderCodeEvidence("示例修改（外联白名单 + 字段最小化）", "# before\nrequests.post(target_url, json=payload)\n\n# after\nallowed_hosts = {\"gamma-api.polymarket.com\", \"clob.polymarket.com\"}\nhost = urllib.parse.urlparse(target_url).hostname\nif host not in allowed_hosts:\n    raise ValueError(\"blocked outbound target\")\nsafe_payload = {\"id\": payload.get(\"id\")}\nrequests.post(target_url, json=safe_payload, timeout=10)"))
	case "凭据访问":
		b.WriteString(renderCodeEvidence("示例修改（凭据读取隔离）", "# before\nconfig = yaml.safe_load(open(\"config.yaml\"))\nprivate_key = config[\"wallet_private_key\"]\n\n# after\nprivate_key = os.environ.get(\"WALLET_PRIVATE_KEY\")\nif not private_key:\n    raise RuntimeError(\"wallet private key is not configured\")"))
	case "授权与许可证校验":
		b.WriteString(renderCodeEvidence("示例修改（许可证失败即拒绝）", "# before\nif license_check_failed:\n    enable_live_trading()\n\n# after\nif license_check_failed:\n    raise RuntimeError(\"license validation failed\")\nenable_live_trading()"))
	case "业务自动化高风险行为":
		b.WriteString(renderCodeEvidence("示例修改（自动交易默认关闭 + 二次确认）", "# before\nif live_trading:\n    client.create_order(order_args)\n\n# after\nif not settings.live_trading_enabled:\n    raise RuntimeError(\"live trading is disabled\")\nif order_amount > settings.max_order_amount:\n    raise ValueError(\"order amount exceeds limit\")\nrequire_user_confirmation(order_args)\nclient.create_order(order_args)"))
	default:
		b.WriteString(renderCodeEvidence("示例修改（通用防护）", "# before\nprocess(user_input, target)\n\n# after\nvalidated = validate_input(user_input)\nif not is_allowed_target(target):\n    raise ValueError(\"target not allowed\")\nprocess(validated, target)"))
	}
	b.WriteString("</div>")
	return b.String()
}

func renderCodeEvidence(title, code string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		title = "示例修改"
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return ""
	}
	return "<div class=\"code-evidence\"><div class=\"code-label\">" + html.EscapeString(title) + "</div><pre class=\"code-box\">" + html.EscapeString(code) + "</pre></div>"
}

func firstSourceLocationFromEvidence(evidence []string) string {
	for _, item := range evidence {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if p, l, ok := tryParseInlineLocator(item); ok {
			return fmt.Sprintf("%s:%d", p, l)
		}
	}
	return ""
}

func buildMainEvidenceForFinding(finding review.StructuredFinding, evidenceLines []string, finalReview string) []string {
	out := make([]string, 0, len(finding.Evidence)+4)
	seen := map[string]struct{}{}
	add := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" {
			return
		}
		key := normalizeEvidenceDedupKey(line)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		out = append(out, line)
	}
	for _, item := range finding.Evidence {
		if shouldSkipMainEvidenceLine(finding, item) {
			continue
		}
		add(normalizeMainEvidenceFormat(item))
	}
	if finding.Category == "声明与行为差异" {
		for _, item := range finding.CodeEvidenceRefs {
			if shouldSkipMainEvidenceLine(finding, item) {
				continue
			}
			add(normalizeMainEvidenceFormat(item))
		}
		for _, item := range finding.ContextEvidenceRefs {
			item = strings.TrimSpace(item)
			if item == "" || strings.HasPrefix(item, "一致性证据:") {
				continue
			}
			add(normalizeMainEvidenceFormat(item))
		}
	}
	if finding.Category == "授权与许可证校验" {
		for _, item := range finding.CodeEvidenceRefs {
			line := strings.TrimSpace(item)
			if line == "" {
				continue
			}
			lower := strings.ToLower(line)
			if strings.Contains(lower, "license_server") || strings.Contains(lower, "/api/validate") || strings.Contains(lower, "verify_failed") || strings.Contains(lower, "license validation") {
				add(normalizeMainEvidenceFormat(line))
			}
		}
	}
	if finding.Category == "业务自动化高风险行为" {
		for _, item := range finding.CodeEvidenceRefs {
			line := strings.TrimSpace(item)
			if line == "" {
				continue
			}
			lower := strings.ToLower(line)
			if strings.Contains(lower, "create_order") || strings.Contains(lower, "place_order") || strings.Contains(lower, "submit") || strings.Contains(lower, "signed_order") || strings.Contains(lower, "live trading") {
				add(normalizeMainEvidenceFormat(line))
			}
		}
	}
	if finding.Category == "网络请求与SSRF" {
		for _, item := range finding.ContextEvidenceRefs {
			item = strings.TrimSpace(item)
			if strings.HasPrefix(item, "请求调用=") || strings.HasPrefix(item, "输入来源=") || strings.HasPrefix(item, "来源类型=") || strings.HasPrefix(item, "危险目标=") || strings.HasPrefix(item, "缺少校验=") {
				add(item)
			}
		}
	}
	allowCapabilityEvidence := isConfirmedReview(finalReview) || len(out) == 0
	for _, raw := range evidenceLines {
		if !allowCapabilityEvidence {
			break
		}
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "链路:") || strings.HasPrefix(line, "意义:") {
			continue
		}
		if strings.Contains(line, "条") && strings.Contains(line, ":") && !strings.HasPrefix(line, "证据:") {
			continue
		}
		if strings.HasPrefix(line, "证据:") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "证据:"))
		}
		if strings.Contains(strings.ToLower(line), ".scan-cache.json") {
			continue
		}
		if containsLocalOnlyEndpoint(line) {
			continue
		}
		add(normalizeMainEvidenceFormat(line))
	}
	return out
}

func applicabilitySummaryForFinding(finding review.StructuredFinding) []string {
	items := make([]string, 0, len(finding.ApplicabilityBasis)+1)
	if strings.TrimSpace(finding.ApplicabilityVerdict) != "" {
		label := "需人工判断"
		if strings.TrimSpace(finding.ApplicabilityVerdict) == "applicable" {
			label = "满足当前规则前提"
		}
		if strings.TrimSpace(finding.ApplicabilityVerdict) == "not_applicable" {
			label = "当前未满足规则前提"
		}
		items = append(items, "适用性结论: "+label)
	}
	items = append(items, finding.ApplicabilityBasis...)
	return uniqueStrings(items)
}

func renderExcludedEvidenceSection(finding review.StructuredFinding) string {
	if len(finding.ExcludedEvidence) == 0 {
		return ""
	}
	items := make([]string, 0, len(finding.ExcludedEvidence))
	for _, item := range finding.ExcludedEvidence {
		parts := make([]string, 0, 3)
		if strings.TrimSpace(item.Location) != "" {
			parts = append(parts, item.Location)
		}
		if strings.TrimSpace(item.Summary) != "" {
			parts = append(parts, item.Summary)
		}
		if strings.TrimSpace(item.Reason) != "" {
			parts = append(parts, "剔除原因: "+item.Reason)
		}
		joined := strings.TrimSpace(strings.Join(parts, " | "))
		if joined != "" {
			items = append(items, joined)
		}
	}
	if len(items) == 0 {
		return ""
	}
	return renderHTMLLabeledList("剔除证据", items, 0, "无")
}

func closureSummaryForFinding(finding review.StructuredFinding) []string {
	items := make([]string, 0, 4)
	items = append(items, closureStatusLine("source", finding.Closure.Source, "已识别输入源、目标来源或敏感数据入口", "仍缺少明确入口来源证据"))
	items = append(items, closureStatusLine("transform", finding.Closure.Transform, "已识别拼接、序列化、参数构造或中间处理", "仍缺少中间加工或参数构造证据"))
	items = append(items, closureStatusLine("sink", finding.Closure.Sink, "已识别请求发送、执行调用、监听暴露或落库落点", "仍缺少明确落点/sink 证据"))
	items = append(items, closureStatusLine("runtime", finding.Closure.RuntimeSupport, "已存在行为链、时序、校准或运行支撑", "仍缺少运行链路或时序支撑"))
	return items
}

func closureStatusLine(label string, ok bool, passText, failText string) string {
	if ok {
		return label + ": 已满足 - " + passText
	}
	return label + ": 待补充 - " + failText
}

func normalizeMainEvidenceFormat(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	line = sanitizeReportText(line, "")
	if line == "" || isInternalScanArtifactText(line) {
		return ""
	}
	if strings.Contains(line, "\n") {
		return line
	}
	if p, l, ok := tryParseInlineLocator(line); ok {
		code := strings.TrimSpace(strings.TrimPrefix(line, p+":"+strconv.Itoa(l)))
		if rendered, ok := renderEvidenceContextWindow(p, l, code); ok {
			return rendered
		}
		if code == "" {
			return fmt.Sprintf("%s:%d", p, l)
		}
		return fmt.Sprintf("%s:%d\n> %4d | %s", p, l, l, code)
	}
	return line
}

func shouldSkipMainEvidenceLine(finding review.StructuredFinding, line string) bool {
	line = strings.TrimSpace(line)
	if line == "" {
		return true
	}
	if finding.Category != "声明与行为差异" {
		return false
	}
	return strings.HasPrefix(line, "声明能力:") || strings.HasPrefix(line, "实际能力:") || strings.HasPrefix(line, "一致性证据:")
}

func renderEvidenceContextWindow(path string, lineNo int, inlineCode string) (string, bool) {
	path = filepath.ToSlash(strings.TrimSpace(path))
	if path == "" || lineNo <= 0 {
		return "", false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", false
	}
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	if lineNo > len(lines) {
		return "", false
	}
	start := lineNo - 4
	if start < 1 {
		start = 1
	}
	end := lineNo + 4
	if end > len(lines) {
		end = len(lines)
	}
	var b strings.Builder
	b.WriteString(path)
	b.WriteString(":")
	b.WriteString(strconv.Itoa(start))
	if end > start {
		b.WriteString("-")
		b.WriteString(strconv.Itoa(end))
	}
	for i := start; i <= end; i++ {
		marker := "  "
		if i == lineNo {
			marker = "> "
		}
		content := lines[i-1]
		if i == lineNo && strings.TrimSpace(content) == "" && strings.TrimSpace(inlineCode) != "" {
			content = inlineCode
		}
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s%4d | %s", marker, i, content))
	}
	return b.String(), true
}

func tryParseInlineLocator(line string) (string, int, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return "", 0, false
	}
	if p, l, ok := parseSourceLocation(line); ok {
		return p, l, true
	}
	cut := strings.IndexByte(line, ' ')
	if cut <= 0 {
		return "", 0, false
	}
	locator := strings.TrimSpace(line[:cut])
	return parseSourceLocation(locator)
}

func isConfirmedReview(finalReview string) bool {
	text := strings.ToLower(strings.TrimSpace(finalReview))
	return strings.Contains(text, "confirmed") || strings.Contains(text, "已确认") || strings.Contains(text, "确认风险")
}

func containsLocalOnlyEndpoint(line string) bool {
	low := strings.ToLower(line)
	return isPrivateOrLocalHostText(low)
}

func normalizeEvidenceDedupKey(line string) string {
	line = strings.ReplaceAll(line, "\r\n", "\n")
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	parts := strings.Split(line, "\n")
	if len(parts) == 0 {
		return strings.ToLower(strings.Join(strings.Fields(line), " "))
	}
	first := strings.TrimSpace(parts[0])
	if p, l, ok := parseSourceLocation(first); ok {
		return strings.ToLower(filepath.ToSlash(strings.TrimSpace(p)) + ":" + strconv.Itoa(l))
	}
	return strings.ToLower(strings.Join(strings.Fields(line), " "))
}

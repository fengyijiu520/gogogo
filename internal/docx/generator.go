package docx

import (
	"archive/zip"
	"bytes"
	"fmt"
	stdhtml "html"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

const (
	docxLatinFont = "Arial"
	docxMonoFont  = "Courier New"
)

func docxCJKFont() string {
	return docxPreferredCJKFonts()[0]
}

func docxPreferredCJKFonts() []string {
	fonts := []string{}
	if value := strings.TrimSpace(os.Getenv("REVIEW_REPORT_CJK_FONT")); value != "" {
		fonts = append(fonts, value)
	}
	fonts = append(fonts,
		"Noto Sans CJK SC",
		"Source Han Sans SC",
		"Microsoft YaHei",
		"PingFang SC",
		"Hiragino Sans GB",
		"WenQuanYi Micro Hei",
		"SimSun",
		"Arial Unicode MS",
	)
	seen := map[string]struct{}{}
	filtered := make([]string, 0, len(fonts))
	for _, font := range fonts {
		font = strings.TrimSpace(font)
		if font == "" {
			continue
		}
		if _, ok := seen[font]; ok {
			continue
		}
		seen[font] = struct{}{}
		filtered = append(filtered, font)
	}
	if len(filtered) == 0 {
		return []string{"Microsoft YaHei"}
	}
	return filtered
}

func docxRunFonts(latinFont, eastAsiaFont string) string {
	return fmt.Sprintf(`<w:rFonts w:ascii="%s" w:hAnsi="%s" w:eastAsia="%s" w:cs="%s"/>`, escapeXML(latinFont), escapeXML(latinFont), escapeXML(eastAsiaFont), escapeXML(latinFont))
}

func docxFontTableXML() string {
	fonts := []string{
		docxLatinFont,
		docxMonoFont,
	}
	fonts = append(fonts, docxPreferredCJKFonts()...)
	seen := map[string]struct{}{}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8" standalone="yes"?>`)
	b.WriteString("\n<w:fonts xmlns:w=\"http://schemas.openxmlformats.org/wordprocessingml/2006/main\">\n")
	for _, font := range fonts {
		font = strings.TrimSpace(font)
		if font == "" {
			continue
		}
		if _, ok := seen[font]; ok {
			continue
		}
		seen[font] = struct{}{}
		b.WriteString(`  <w:font w:name="` + escapeXML(font) + `"/>` + "\n")
	}
	b.WriteString(`</w:fonts>`)
	return b.String()
}

func docxStylesXML() string {
	return `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault>
      <w:rPr>
        ` + docxRunFonts(docxLatinFont, docxCJKFont()) + `
        <w:lang w:val="zh-CN" w:eastAsia="zh-CN" w:bidi="en-US"/>
      </w:rPr>
    </w:rPrDefault>
  </w:docDefaults>
</w:styles>`
}

// Generator produces .docx risk reports from plugin findings.
type Generator struct{}

type IntentSummary struct {
	Available            bool
	DeclaredIntent       string
	ActualBehavior       string
	DeclaredCapabilities []string
	ActualCapabilities   []string
	ConsistencyEvidence  []string
	IntentRiskLevel      string
	IntentMismatch       string
	UnavailableReason    string
}

type AnalysisProfile struct {
	AnalysisMode       string
	DeclarationSources []string
	SourceFiles        []string
	Dependencies       []string
	Permissions        []string
	LanguageSummary    []string
	CapabilitySignals  []string
}

// NewGenerator returns a new Generator.
func NewGenerator() *Generator {
	return &Generator{}
}

// Generate writes a .docx report to outputPath.
func (g *Generator) Generate(findings []plugins.Finding, score float64, modelInfo string, llmEnabled bool, outputPath string) error {
	return g.generateDocx(findings, score, modelInfo, llmEnabled, nil, IntentSummary{}, AnalysisProfile{}, outputPath)
}

// GenerateWithReview writes a .docx report with differential/evasion context.
func (g *Generator) GenerateWithReview(findings []plugins.Finding, score float64, modelInfo string, llmEnabled bool, result review.Result, intent IntentSummary, profile AnalysisProfile, outputPath string) error {
	return g.generateDocx(findings, score, modelInfo, llmEnabled, &result, intent, profile, outputPath)
}

// GenerateFromHTMLReport writes a .docx report derived from the HTML report body.
func (g *Generator) GenerateFromHTMLReport(title, htmlReport, outputPath string) error {
	return g.generateHTMLBasedDocx(title, TextFromHTMLReport(htmlReport), outputPath)
}

func (g *Generator) generateHTMLBasedDocx(title, textReport, outputPath string) error {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	addFile := func(name, content string) {
		w, _ := zw.Create(name)
		w.Write([]byte(content))
	}

	addFile("[Content_Types].xml", contentTypesXML)
	addFile("_rels/.rels", relsXML)
	addFile("word/_rels/document.xml.rels", docRelsXML)
	addFile("word/styles.xml", docxStylesXML())
	addFile("word/fontTable.xml", docxFontTableXML())
	addFile("word/settings.xml", settingsXML)
	addFile("word/document.xml", g.buildHTMLDerivedDocument(title, textReport))
	zw.Close()

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = buf.WriteTo(f)
	return err
}

// TextFromHTMLReport converts an HTML report into a plain-text outline while preserving headings and code blocks.
func TextFromHTMLReport(htmlReport string) string {
	text := htmlReport
	replacements := []struct {
		old string
		new string
	}{
		{"\r\n", "\n"},
		{"<br>", "\n"},
		{"<br/>", "\n"},
		{"<br />", "\n"},
	}
	for _, item := range replacements {
		text = strings.ReplaceAll(text, item.old, item.new)
	}

	blockPatterns := []struct {
		pattern string
		repl    string
	}{
		{`(?is)<script[^>]*>.*?</script>`, "\n"},
		{`(?is)<style[^>]*>.*?</style>`, "\n"},
		{`(?is)<head[^>]*>.*?</head>`, "\n"},
		{`(?is)<pre[^>]*>(.*?)</pre>`, "\n```text\n$1\n```\n"},
		{`(?is)<h1[^>]*>`, "\n# "},
		{`(?is)</h1>`, "\n"},
		{`(?is)<h2[^>]*>`, "\n## "},
		{`(?is)</h2>`, "\n"},
		{`(?is)<h3[^>]*>`, "\n### "},
		{`(?is)</h3>`, "\n"},
		{`(?is)<summary[^>]*>`, "\n### "},
		{`(?is)</summary>`, "\n"},
		{`(?is)<li[^>]*>`, "\n- "},
		{`(?is)</li>`, "\n"},
		{`(?is)<tr[^>]*>`, "\n"},
		{`(?is)</tr>`, "\n"},
		{`(?is)<t[dh][^>]*>`, " | "},
		{`(?is)</t[dh]>`, " "},
		{`(?is)<p[^>]*>`, ""},
		{`(?is)</p>`, "\n"},
		{`(?is)<div[^>]*>`, ""},
		{`(?is)</div>`, "\n"},
		{`(?is)<section[^>]*>`, ""},
		{`(?is)</section>`, "\n"},
		{`(?is)<nav[^>]*>`, ""},
		{`(?is)</nav>`, "\n"},
	}
	for _, item := range blockPatterns {
		re := regexp.MustCompile(item.pattern)
		text = re.ReplaceAllString(text, item.repl)
	}

	text = regexp.MustCompile(`(?is)<[^>]+>`).ReplaceAllString(text, "")
	text = stdhtml.UnescapeString(text)

	lines := strings.Split(text, "\n")
	normalized := make([]string, 0, len(lines))
	lastBlank := true
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			if !lastBlank {
				normalized = append(normalized, "")
			}
			lastBlank = true
			continue
		}
		trimmed = strings.Join(strings.Fields(trimmed), " ")
		normalized = append(normalized, trimmed)
		lastBlank = false
	}
	return strings.TrimSpace(strings.Join(normalized, "\n"))
}

func (g *Generator) buildHTMLDerivedDocument(title, textReport string) string {
	var b strings.Builder
	b.WriteString(docHeader)
	b.WriteString(para(defaultText(title, "技能安全审查报告"), "36", "center", true))
	b.WriteString(para(fmt.Sprintf("生成时间: %s", time.Now().Format("2006-01-02 15:04:05")), "24", "center", false))
	b.WriteString(para("说明: DOCX 由 HTML 主报告派生生成，正文内容与 HTML 报告保持一致口径。", "22", "left", false))
	b.WriteString(blankPara())

	lines := strings.Split(textReport, "\n")
	inCode := false
	codeLines := make([]string, 0, 8)
	flushCode := func() {
		if len(codeLines) == 0 {
			return
		}
		b.WriteString(codeBlockPara(strings.Join(codeLines, "\n")))
		codeLines = codeLines[:0]
	}
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "```text" || trimmed == "```" {
			if inCode {
				flushCode()
			}
			inCode = !inCode
			continue
		}
		if inCode {
			codeLines = append(codeLines, line)
			continue
		}
		if trimmed == "" {
			b.WriteString(blankPara())
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "# "):
			b.WriteString(heading(strings.TrimPrefix(trimmed, "# "), "34"))
		case strings.HasPrefix(trimmed, "## "):
			b.WriteString(heading(strings.TrimPrefix(trimmed, "## "), "30"))
		case strings.HasPrefix(trimmed, "### "):
			b.WriteString(heading(strings.TrimPrefix(trimmed, "### "), "26"))
		case strings.HasPrefix(trimmed, "- "):
			b.WriteString(para(trimmed, "22", "left", false))
		default:
			b.WriteString(para(trimmed, "22", "left", false))
		}
	}
	if inCode {
		flushCode()
	}
	b.WriteString(docFooter)
	return b.String()
}

func (g *Generator) generateDocx(findings []plugins.Finding, score float64, modelInfo string, llmEnabled bool, result *review.Result, intent IntentSummary, profile AnalysisProfile, outputPath string) error {
	buf := new(bytes.Buffer)
	zw := zip.NewWriter(buf)

	addFile := func(name, content string) {
		w, _ := zw.Create(name)
		w.Write([]byte(content))
	}

	addFile("[Content_Types].xml", contentTypesXML)
	addFile("_rels/.rels", relsXML)
	addFile("word/_rels/document.xml.rels", docRelsXML)
	addFile("word/styles.xml", docxStylesXML())
	addFile("word/fontTable.xml", docxFontTableXML())
	addFile("word/settings.xml", settingsXML)
	addFile("word/document.xml", g.buildDocument(findings, score, modelInfo, llmEnabled, result, intent, profile))
	zw.Close()

	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = buf.WriteTo(f)
	return err
}

func (g *Generator) buildDocument(findings []plugins.Finding, score float64, modelInfo string, llmEnabled bool, result *review.Result, intent IntentSummary, profile AnalysisProfile) string {
	_ = score
	var b strings.Builder

	high, medium, low := partition(findings)
	groupedHigh := groupByRuleID(high)
	groupedMedium := groupByRuleID(medium)
	groupedLow := groupByRuleID(low)
	totalRiskCategories := len(groupedHigh) + len(groupedMedium) + len(groupedLow)

	b.WriteString(docHeader)
	b.WriteString(para("技能安全审查报告", "36", "center", true))
	b.WriteString(para(fmt.Sprintf("生成时间: %s", time.Now().Format("2006-01-02 15:04:05")), "24", "center", false))
	b.WriteString(para("说明: 报告中的代码片段和目标地址为技能自身内容原文引用，其余为系统中文分析结论。", "22", "left", false))
	b.WriteString(para("生成器: Skill Scanner 结构化审查流水线", "20", "left", false))

	b.WriteString(para(fmt.Sprintf("风险汇总: 高风险 %d 项，中风险 %d 项，低风险 %d 项", len(groupedHigh), len(groupedMedium), len(groupedLow)), "28", "left", false))
	b.WriteString(para("结论说明: 本报告按高风险、中风险、低风险聚合，系统只提供证据、风险标记和复核建议，最终是否使用由用户判断。", "22", "left", false))
	b.WriteString(blankPara())

	b.WriteString(para(fmt.Sprintf("总计发现: %d 项风险类别", totalRiskCategories), "28", "left", false))
	b.WriteString(para("建议按“高风险 -> 中风险 -> 低风险”顺序复核和修复，每轮修复后执行全量复扫。", "22", "left", false))
	b.WriteString(blankPara())

	b.WriteString(intentSummarySection(intent))
	b.WriteString(blankPara())
	b.WriteString(analysisProfileSection(profile))
	b.WriteString(blankPara())

	if len(findings) == 0 {
		b.WriteString(heading("未发现风险", "28"))
		b.WriteString(para("扫描范围内未检测到敏感信息泄露或危险函数调用。", "24", "left", false))
	} else {
		if len(high) > 0 {
			b.WriteString(heading(fmt.Sprintf("高风险 (%d项)", len(groupedHigh)), "32"))
			for _, items := range groupedHigh {
				first := items[0]
				b.WriteString(ruleHeading(first.RuleID, first.Title, "FF0000", "32"))
				for _, item := range items {
					b.WriteString(findingDetailPara(item))
				}
				b.WriteString(blankPara())
			}
		}

		if len(medium) > 0 {
			b.WriteString(heading(fmt.Sprintf("中风险 (%d项)", len(groupedMedium)), "28"))
			for _, items := range groupedMedium {
				first := items[0]
				b.WriteString(ruleHeading(first.RuleID, first.Title, "FFA500", "28"))
				for _, item := range items {
					b.WriteString(findingDetailPara(item))
				}
				b.WriteString(blankPara())
			}
		}

		if len(low) > 0 {
			b.WriteString(heading(fmt.Sprintf("低风险 (%d项)", len(groupedLow)), "24"))
			for _, items := range groupedLow {
				first := items[0]
				b.WriteString(ruleHeading(first.RuleID, first.Title, "008000", "24"))
				for _, item := range items {
					b.WriteString(findingDetailPara(item))
				}
				b.WriteString(blankPara())
			}
		}
	}

	if result != nil {
		b.WriteString(blankPara())
		b.WriteString(auditEventsSection(result.AuditEvents))
		b.WriteString(blankPara())
		b.WriteString(pipelineSection(result.Pipeline))
		b.WriteString(blankPara())
		b.WriteString(evidenceInventorySection(result.EvidenceInventory))
		b.WriteString(blankPara())
		b.WriteString(capabilityMatrixSection(result.CapabilityMatrix))
		b.WriteString(blankPara())
		b.WriteString(structuredFindingsSection(result.StructuredFindings, result.ReviewAgentVerdicts))
		b.WriteString(blankPara())
		b.WriteString(falsePositiveReviewsSection(result.FalsePositiveReviews))
		b.WriteString(blankPara())
		b.WriteString(detectionComparisonSection(result.DetectionComparison))
		b.WriteString(blankPara())
		b.WriteString(reviewAgentTasksSection(result.ReviewAgentTasks))
		b.WriteString(blankPara())
		b.WriteString(reviewAgentVerdictsSection(result.ReviewAgentVerdicts))
		b.WriteString(blankPara())
		b.WriteString(vulnerabilityBlocksSection(result.VulnerabilityBlocks))
		b.WriteString(blankPara())
		b.WriteString(ruleExplanationsSection(result.RuleExplanations))
		b.WriteString(blankPara())
		b.WriteString(optimizationNotesSection(result.OptimizationNotes))

		b.WriteString(blankPara())
		b.WriteString(heading("行为证据采集（下载 / 落地 / 执行 / 外联 / 持久化 / 提权 / 凭据访问 / 防御规避 / 横向移动 / 收集打包 / C2信标）", "28"))
		b.WriteString(para("以下证据来自隔离执行探针与代码行为提取，建议按证据链逐项复核。", "22", "left", false))
		b.WriteString(behaviorEvidencePara("下载证据", result.Behavior.DownloadIOCs))
		b.WriteString(behaviorEvidencePara("落地证据", result.Behavior.DropIOCs))
		b.WriteString(behaviorEvidencePara("执行证据", result.Behavior.ExecuteIOCs))
		b.WriteString(behaviorEvidencePara("外联证据", result.Behavior.OutboundIOCs))
		b.WriteString(behaviorEvidencePara("持久化证据", result.Behavior.PersistenceIOCs))
		b.WriteString(behaviorEvidencePara("提权证据", result.Behavior.PrivEscIOCs))
		b.WriteString(behaviorEvidencePara("凭据访问证据", result.Behavior.CredentialIOCs))
		b.WriteString(behaviorEvidencePara("防御规避证据", result.Behavior.DefenseEvasionIOCs))
		b.WriteString(behaviorEvidencePara("横向移动证据", result.Behavior.LateralMoveIOCs))
		b.WriteString(behaviorEvidencePara("收集打包证据", result.Behavior.CollectionIOCs))
		b.WriteString(behaviorEvidencePara("C2 信标证据", result.Behavior.C2BeaconIOCs))
		b.WriteString(behaviorEvidencePara("高风险链路摘要", result.Behavior.BehaviorChains))
		b.WriteString(behaviorEvidencePara("行为时序链路", result.Behavior.BehaviorTimelines))
		b.WriteString(behaviorEvidencePara("时序告警", result.Behavior.SequenceAlerts))
		b.WriteString(behaviorEvidencePara("沙箱探针告警", result.Behavior.ProbeWarnings))

		b.WriteString(blankPara())
		b.WriteString(heading("反逃逸与差分执行分析", "28"))
		if !result.Evasion.Detected {
			b.WriteString(para("未发现明确的反沙箱或反虚拟机逃逸迹象。", "24", "left", false))
		} else {
			b.WriteString(para("风险结论: 检测到反分析/反虚拟机相关信号，需修复后复测。", "24", "left", false))
			if len(result.Evasion.Signals) > 0 {
				b.WriteString(para("命中信号:", "24", "left", true))
				for _, s := range result.Evasion.Signals {
					b.WriteString(para("- "+s, "22", "left", false))
				}
			}
			if strings.TrimSpace(result.Evasion.Recommendation) != "" {
				b.WriteString(para("修复建议: "+result.Evasion.Recommendation, "24", "left", false))
			}
		}

		if len(result.Evasion.Differentials) > 0 {
			b.WriteString(para("差分执行结果:", "24", "left", true))
			for _, d := range result.Evasion.Differentials {
				triggered := "否"
				if d.Triggered {
					triggered = "是"
				}
				b.WriteString(para(fmt.Sprintf("- 执行画像: %s | 触发差异: %s", d.Scenario, triggered), "22", "left", false))
				if len(d.Indicators) > 0 {
					b.WriteString(para("  指标: "+strings.Join(d.Indicators, "；"), "20", "left", false))
				}
				if strings.TrimSpace(d.Summary) != "" {
					b.WriteString(para("  说明: "+d.Summary, "20", "left", false))
				}
			}
		}
	}

	b.WriteString(blankPara())
	b.WriteString(heading("检测引擎说明", "28"))

	engineDesc := "• 语义相似度检测: " + modelInfo + "\n"
	engineDesc += "• 恶意模式匹配: 正则检测危险命令、后门、数据外发等\n"
	engineDesc += "• 静态代码分析: Go / JavaScript / TypeScript 危险调用检测\n"
	engineDesc += "• 依赖漏洞分析: 基于依赖版本与已知漏洞库比对\n"
	if llmEnabled {
		engineDesc += "• LLM 深度分析: 已启用，40项规则内用于辅助复核与降低误报，规则外新增风险才标记为 LLM"
	} else {
		engineDesc += "• LLM 深度分析: 未启用（可在个人中心完成配置后启用）"
	}
	b.WriteString(para(engineDesc, "24", "left", false))

	b.WriteString(docFooter)

	return b.String()
}

func partition(findings []plugins.Finding) (high, medium, low []plugins.Finding) {
	for _, f := range findings {
		switch f.Severity {
		case "高风险":
			high = append(high, f)
		case "中风险":
			medium = append(medium, f)
		default:
			low = append(low, f)
		}
	}
	return
}

func para(text, size, align string, bold bool) string {
	alignAttr := map[string]string{
		"center": `<w:jc w:val="center"/>`,
		"right":  `<w:jc w:val="right"/>`,
	}[align]
	if alignAttr == "" {
		alignAttr = `<w:jc w:val="left"/>`
	}

	boldAttr := ""
	if bold {
		boldAttr = `<w:b/>`
	}

	// 转义 XML 特殊字符
	text = escapeXML(text)

	return fmt.Sprintf(
		`<w:p><w:pPr>%s<w:sz w:val="%s"/></w:pPr><w:r>%s<w:rPr>%s<w:sz w:val="%s"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		alignAttr, size, boldAttr, docxRunFonts(docxLatinFont, docxCJKFont()), size, text,
	)
}

func heading(text, size string) string {
	text = escapeXML(text)
	return fmt.Sprintf(
		`<w:p><w:pPr><w:pStyle w:val="Heading2"/><w:sz w:val="%s"/></w:pPr><w:r><w:rPr><w:b/>%s<w:sz w:val="%s"/></w:rPr><w:t xml:space="preserve">%s</w:t></w:r></w:p>`,
		size, docxRunFonts(docxLatinFont, docxCJKFont()), size, text,
	)
}

func findingPara(f plugins.Finding, color string) string {
	var b strings.Builder

	b.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="28"/></w:pPr><w:r><w:rPr><w:b/><w:color w:val="%s"/>%s<w:sz w:val="28"/></w:rPr><w:t xml:space="preserve">[%s] %s</w:t></w:r></w:p>`,
		color, docxRunFonts(docxLatinFont, docxCJKFont()), f.RuleID, escapeXML(f.Title),
	))
	b.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="24"/><w:ind w:left="400"/></w:pPr><w:r><w:rPr>%s<w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">描述: %s</w:t></w:r></w:p>`,
		docxRunFonts(docxLatinFont, docxCJKFont()), escapeXML(f.Description),
	))
	b.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="24"/><w:ind w:left="400"/></w:pPr><w:r><w:rPr>%s<w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">位置: %s</w:t></w:r></w:p>`,
		docxRunFonts(docxLatinFont, docxCJKFont()), escapeXML(f.Location),
	))

	// 输出代码片段
	if f.CodeSnippet != "" {
		b.WriteString(codeBlockPara(f.CodeSnippet))
	}

	b.WriteString(blankPara())
	return b.String()
}

func blankPara() string {
	return `<w:p/>`
}

// codeBlockPara 生成一个带背景色的代码块段落（类似终端输出）
func codeBlockPara(code string) string {
	code = escapeXML(code)
	lines := strings.Split(code, "\n")
	var b strings.Builder
	for _, line := range lines {
		b.WriteString(`<w:p>`)
		b.WriteString(`<w:pPr>`)
		b.WriteString(`<w:shd w:val="clear" w:color="auto" w:fill="F5F5F5"/>`)
		b.WriteString(`<w:spacing w:before="0" w:after="0"/>`)
		b.WriteString(`<w:ind w:left="400"/>`)
		b.WriteString(`</w:pPr>`)
		b.WriteString(`<w:r>`)
		b.WriteString(`<w:rPr>`)
		b.WriteString(docxRunFonts(docxMonoFont, docxCJKFont()))
		b.WriteString(`<w:sz w:val="20"/>`)
		b.WriteString(`</w:rPr>`)
		b.WriteString(`<w:t xml:space="preserve">` + line + `</w:t>`)
		b.WriteString(`</w:r>`)
		b.WriteString(`</w:p>`)
	}
	return b.String()
}

func behaviorEvidencePara(title string, items []string) string {
	if len(items) == 0 {
		return para(title+": 未检出。", "22", "left", false)
	}
	var b strings.Builder
	b.WriteString(para(title+":", "22", "left", true))
	max := len(items)
	if max > 12 {
		max = 12
	}
	for i := 0; i < max; i++ {
		b.WriteString(para("- "+items[i], "20", "left", false))
	}
	if len(items) > max {
		b.WriteString(para(fmt.Sprintf("- ... 其余 %d 条请查看 JSON 报告。", len(items)-max), "20", "left", false))
	}
	return b.String()
}

func intentSummarySection(intent IntentSummary) string {
	var b strings.Builder
	b.WriteString(heading("声明与行为一致性", "28"))
	b.WriteString(para("本节展示 LLM 对技能声明进行语义理解后形成的声明意图摘要，不直接复述原始声明文本。", "22", "left", false))
	if !intent.Available {
		b.WriteString(para(defaultText(intent.UnavailableReason, "LLM 未启用或本次未返回有效声明意图分析。"), "22", "left", false))
		return b.String()
	}
	b.WriteString(para("LLM 总结的声明意图: "+defaultText(intent.DeclaredIntent, "未生成"), "22", "left", false))
	b.WriteString(para("LLM 总结的实际行为: "+defaultText(intent.ActualBehavior, "未生成"), "22", "left", false))
	b.WriteString(para("一致性风险等级: "+defaultText(intent.IntentRiskLevel, "无风险"), "22", "left", false))
	if strings.TrimSpace(intent.IntentMismatch) != "" {
		b.WriteString(para("不一致说明: "+intent.IntentMismatch, "22", "left", false))
	}
	if len(intent.DeclaredCapabilities) > 0 {
		b.WriteString(para("声明允许能力: "+strings.Join(intent.DeclaredCapabilities, "；"), "22", "left", false))
	}
	if len(intent.ActualCapabilities) > 0 {
		b.WriteString(para("实际使用能力: "+strings.Join(intent.ActualCapabilities, "；"), "22", "left", false))
	}
	if len(intent.ConsistencyEvidence) > 0 {
		b.WriteString(para("一致性证据: "+strings.Join(intent.ConsistencyEvidence, "；"), "22", "left", false))
	}
	return b.String()
}

func analysisProfileSection(profile AnalysisProfile) string {
	var b strings.Builder
	b.WriteString(heading("技能分析画像", "28"))
	b.WriteString(para("分析模式: "+defaultText(profile.AnalysisMode, "全链路分析"), "22", "left", false))
	if len(profile.DeclarationSources) > 0 {
		b.WriteString(para("声明来源: "+strings.Join(profile.DeclarationSources, "；"), "22", "left", false))
	}
	if len(profile.SourceFiles) > 0 {
		b.WriteString(para("纳入分析文件: "+joinLimited(profile.SourceFiles, 12), "22", "left", false))
	}
	if len(profile.LanguageSummary) > 0 {
		b.WriteString(para("语言/文件类型分布: "+strings.Join(profile.LanguageSummary, "；"), "22", "left", false))
	}
	if len(profile.Dependencies) > 0 {
		b.WriteString(para("依赖清单: "+joinLimited(profile.Dependencies, 12), "22", "left", false))
	}
	if len(profile.Permissions) > 0 {
		b.WriteString(para("用户声明权限: "+strings.Join(profile.Permissions, "；"), "22", "left", false))
	}
	if len(profile.CapabilitySignals) > 0 {
		b.WriteString(para("源码能力信号: "+strings.Join(profile.CapabilitySignals, "；"), "22", "left", false))
	}
	return b.String()
}

func pipelineSection(stages []review.PipelineStage) string {
	var b strings.Builder
	b.WriteString(heading("阶段化分析 Pipeline", "28"))
	if len(stages) == 0 {
		b.WriteString(para("未记录阶段化 Pipeline。", "22", "left", false))
		return b.String()
	}
	for _, stage := range stages {
		line := fmt.Sprintf("- %s [%s]: %s", stage.Name, stage.Status, stage.Purpose)
		if strings.TrimSpace(stage.Output) != "" {
			line += "；输出: " + stage.Output
		}
		if strings.TrimSpace(stage.Benefit) != "" {
			line += "；收益: " + stage.Benefit
		}
		b.WriteString(para(line, "20", "left", false))
	}
	return b.String()
}

func auditEventsSection(events []review.AuditEvent) string {
	var b strings.Builder
	b.WriteString(heading("结构化审计事件流", "28"))
	b.WriteString(para("本节将扫描过程组织为可回放的阶段、工具、状态和结果事件。", "22", "left", false))
	if len(events) == 0 {
		b.WriteString(para("未记录审计事件流。", "22", "left", false))
		return b.String()
	}
	for _, event := range events {
		line := fmt.Sprintf("- [%s] %s %s: %s", event.Type, defaultText(event.Status, "-"), defaultText(event.ToolName, event.StepID), event.Brief)
		if strings.TrimSpace(event.Detail) != "" {
			line += "；详情: " + event.Detail
		}
		b.WriteString(para(line, "20", "left", false))
	}
	return b.String()
}

func evidenceInventorySection(items []review.EvidenceInventory) string {
	var b strings.Builder
	b.WriteString(heading("证据目录", "28"))
	if len(items) == 0 {
		b.WriteString(para("未形成额外证据目录。", "22", "left", false))
		return b.String()
	}
	for _, item := range items {
		line := fmt.Sprintf("- %s: %d 条；意义: %s", item.Category, item.Count, item.Meaning)
		if len(item.Examples) > 0 {
			line += "；证据: " + strings.Join(item.Examples, "；")
		}
		b.WriteString(para(line, "20", "left", false))
	}
	return b.String()
}

func capabilityMatrixSection(items []review.CapabilityConsistency) string {
	var b strings.Builder
	b.WriteString(heading("能力一致性矩阵", "28"))
	b.WriteString(para("本节按能力聚合声明、静态规则、LLM 意图、沙箱行为和威胁情报，用于判断每类能力是已验证、未声明、未触发还是存在探针盲区。", "22", "left", false))
	if len(items) == 0 {
		b.WriteString(para("未形成能力一致性矩阵。", "22", "left", false))
		return b.String()
	}
	for _, item := range items {
		line := fmt.Sprintf("- %s: 状态=%s；声明=%s；静态=%s；LLM=%s；沙箱=%s；情报=%s", item.Capability, item.Status, yesNoText(item.Declared), yesNoText(item.StaticDetected), yesNoText(item.LLMDetected), yesNoText(item.SandboxDetected), yesNoText(item.TIObserved))
		b.WriteString(para(line, "20", "left", true))
		b.WriteString(para("  影响: "+item.RiskImpact, "20", "left", false))
		if strings.TrimSpace(item.Gap) != "" {
			b.WriteString(para("  缺口: "+item.Gap, "20", "left", false))
		}
		b.WriteString(para("  下一步: "+item.NextStep, "20", "left", false))
		if len(item.Evidence) > 0 {
			b.WriteString(para("  证据: "+joinLimited(item.Evidence, 4), "20", "left", false))
		}
	}
	return b.String()
}

func yesNoText(v bool) string {
	if v {
		return "是"
	}
	return "否"
}

func preferredDocxVerdictsByFinding(verdicts []review.ReviewAgentVerdict) map[string]review.ReviewAgentVerdict {
	grouped := make(map[string][]review.ReviewAgentVerdict, len(verdicts))
	for _, verdict := range verdicts {
		if strings.TrimSpace(verdict.FindingID) == "" {
			continue
		}
		grouped[verdict.FindingID] = append(grouped[verdict.FindingID], verdict)
	}
	out := make(map[string]review.ReviewAgentVerdict, len(grouped))
	for findingID, items := range grouped {
		out[findingID] = synthesizeDocxVerdict(items)
	}
	return out
}

func synthesizeDocxVerdict(items []review.ReviewAgentVerdict) review.ReviewAgentVerdict {
	if len(items) == 0 {
		return review.ReviewAgentVerdict{}
	}
	byVerdict := map[string][]review.ReviewAgentVerdict{}
	for _, item := range items {
		key := normalizedDocxVerdict(item.Verdict)
		if key == "" {
			key = "needs_manual_review"
		}
		byVerdict[key] = append(byVerdict[key], item)
	}
	if len(byVerdict) == 1 {
		for _, sameVerdicts := range byVerdict {
			return strongestDocxVerdict(sameVerdicts)
		}
	}
	merged := strongestDocxVerdict(items)
	merged.Verdict = "needs_manual_review"
	merged.Confidence = "低"
	merged.Reviewer = joinDocxReviewers(items)
	merged.Reason = "复核结论存在分歧，已回退为需人工复核。"
	merged.MissingEvidence = docxUniqueStrings(append(merged.MissingEvidence, collectDocxMissingEvidence(items)...))
	merged.StandardsApplied = docxUniqueStrings(collectDocxStandards(items))
	if strings.TrimSpace(merged.Fix) == "" {
		merged.Fix = "请补充可达性、运行链路和真实影响证据后再判断。"
	} else {
		merged.Fix = merged.Fix + "；请补充可达性、运行链路和真实影响证据后再判断。"
	}
	return merged
}

func strongestDocxVerdict(items []review.ReviewAgentVerdict) review.ReviewAgentVerdict {
	best := items[0]
	for _, item := range items[1:] {
		if docxConfidencePriority(item.Confidence) > docxConfidencePriority(best.Confidence) {
			best = item
			continue
		}
		if docxConfidencePriority(item.Confidence) == docxConfidencePriority(best.Confidence) && docxReviewerPriority(item.Reviewer) > docxReviewerPriority(best.Reviewer) {
			best = item
		}
	}
	return best
}

func docxReviewerPriority(reviewer string) int {
	reviewer = strings.ToLower(strings.TrimSpace(reviewer))
	if strings.Contains(reviewer, "deterministic") {
		return 2
	}
	if strings.Contains(reviewer, "llm") {
		return 1
	}
	return 0
}

func docxConfidencePriority(confidence string) int {
	switch strings.TrimSpace(confidence) {
	case "高":
		return 4
	case "中高":
		return 3
	case "中":
		return 2
	case "中低":
		return 1
	case "低":
		return 0
	default:
		return -1
	}
}

func normalizedDocxVerdict(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed", "needs_manual_review", "likely_false_positive":
		return strings.ToLower(strings.TrimSpace(verdict))
	default:
		return ""
	}
}

func collectDocxMissingEvidence(items []review.ReviewAgentVerdict) []string {
	out := make([]string, 0, len(items)*2)
	for _, item := range items {
		out = append(out, item.MissingEvidence...)
	}
	return out
}

func collectDocxStandards(items []review.ReviewAgentVerdict) []string {
	out := make([]string, 0, len(items)*2)
	for _, item := range items {
		out = append(out, item.StandardsApplied...)
	}
	return out
}

func joinDocxReviewers(items []review.ReviewAgentVerdict) string {
	reviewers := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		reviewer := strings.TrimSpace(item.Reviewer)
		if reviewer == "" || seen[reviewer] {
			continue
		}
		seen[reviewer] = true
		reviewers = append(reviewers, reviewer)
	}
	if len(reviewers) == 0 {
		return "multi-review"
	}
	sort.Strings(reviewers)
	return strings.Join(reviewers, "+")
}

func docxUniqueStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func sortStructuredFindingsForDocx(items []review.StructuredFinding, verdicts map[string]review.ReviewAgentVerdict) []review.StructuredFinding {
	out := append([]review.StructuredFinding(nil), items...)
	sort.SliceStable(out, func(i, j int) bool {
		leftVerdict := verdicts[out[i].ID]
		rightVerdict := verdicts[out[j].ID]
		if docxVerdictRank(leftVerdict.Verdict) != docxVerdictRank(rightVerdict.Verdict) {
			return docxVerdictRank(leftVerdict.Verdict) < docxVerdictRank(rightVerdict.Verdict)
		}
		if docxSeverityRank(out[i].Severity) != docxSeverityRank(out[j].Severity) {
			return docxSeverityRank(out[i].Severity) < docxSeverityRank(out[j].Severity)
		}
		return out[i].ID < out[j].ID
	})
	return out
}

func docxVerdictRank(verdict string) int {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed":
		return 0
	case "needs_manual_review":
		return 1
	case "likely_false_positive":
		return 3
	default:
		return 2
	}
}

func docxSeverityRank(severity string) int {
	switch strings.TrimSpace(severity) {
	case "高风险", "high", "critical":
		return 0
	case "中风险", "medium":
		return 1
	case "低风险", "low":
		return 2
	default:
		return 3
	}
}

func docxFinalReviewSummary(findingID string, verdicts map[string]review.ReviewAgentVerdict) string {
	verdict, ok := verdicts[findingID]
	if !ok || strings.TrimSpace(verdict.Verdict) == "" {
		return "未生成最终裁决"
	}
	return docxLocalizeVerdict(verdict.Verdict) + " / " + defaultText(verdict.Reviewer, "unknown-reviewer") + " / 置信度: " + defaultText(verdict.Confidence, "未标注")
}

func docxLocalizeVerdict(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed":
		return "确认风险"
	case "needs_manual_review":
		return "需人工复核"
	case "likely_false_positive":
		return "疑似误报"
	default:
		return defaultText(verdict, "未裁决")
	}
}

func structuredFindingsSection(items []review.StructuredFinding, verdicts []review.ReviewAgentVerdict) string {
	var b strings.Builder
	b.WriteString(heading("结构化风险发现", "28"))
	b.WriteString(para("本节将同类规则命中合并为可复核发现，并展示攻击路径、证据、误报检查、最终 reviewer 裁决和复核建议。", "22", "left", false))
	if len(items) == 0 {
		b.WriteString(para("未形成结构化风险发现。", "22", "left", false))
		return b.String()
	}
	preferred := preferredDocxVerdictsByFinding(verdicts)
	for _, item := range sortStructuredFindingsForDocx(items, preferred) {
		b.WriteString(para(fmt.Sprintf("- %s [%s] %s / %s / 置信度: %s", item.ID, item.Severity, item.Category, item.Title, defaultText(item.Confidence, "待复核")), "20", "left", true))
		b.WriteString(para("  最终复核: "+docxFinalReviewSummary(item.ID, preferred), "20", "left", false))
		b.WriteString(para("  攻击路径/影响: "+item.AttackPath, "20", "left", false))
		if len(item.Evidence) > 0 {
			b.WriteString(para("  证据: "+joinLimited(item.Evidence, 4), "20", "left", false))
		}
		if len(item.CalibrationBasis) > 0 {
			b.WriteString(para("  校准依据: "+joinLimited(item.CalibrationBasis, 4), "20", "left", false))
		}
		if len(item.FalsePositiveChecks) > 0 {
			b.WriteString(para("  误报检查: "+joinLimited(item.FalsePositiveChecks, 4), "20", "left", false))
		}
		b.WriteString(para("  复核建议: "+item.ReviewGuidance, "20", "left", false))
	}
	return b.String()
}

func vulnerabilityBlocksSection(items []review.VulnerabilityBlock) string {
	var b strings.Builder
	b.WriteString(heading("可复核漏洞块", "28"))
	b.WriteString(para("本节将结构化风险发现导出为可复制、可二次复核、可机器解析的漏洞块。", "22", "left", false))
	if len(items) == 0 {
		b.WriteString(para("未生成可复核漏洞块。", "22", "left", false))
		return b.String()
	}
	for _, item := range items {
		b.WriteString(para(item.ID+" / "+item.Format, "22", "left", true))
		for _, line := range strings.Split(item.Content, "\n") {
			b.WriteString(para(line, "18", "left", false))
		}
	}
	return b.String()
}

func falsePositiveReviewsSection(items []review.FalsePositiveReview) string {
	var b strings.Builder
	b.WriteString(heading("零误报复核清单", "28"))
	b.WriteString(para("本节按可利用性、影响、证据强度、可达性和排除条件复核每个结构化风险。", "22", "left", false))
	if len(items) == 0 {
		b.WriteString(para("未生成零误报复核清单。", "22", "left", false))
		return b.String()
	}
	for _, item := range items {
		b.WriteString(para("- "+item.FindingID+" / "+item.Verdict, "20", "left", true))
		b.WriteString(para("  可利用性: "+item.Exploitability, "20", "left", false))
		b.WriteString(para("  影响: "+item.Impact, "20", "left", false))
		b.WriteString(para("  证据强度: "+item.EvidenceStrength, "20", "left", false))
		b.WriteString(para("  可达性检查: "+joinLimited(item.ReachabilityChecks, 3), "20", "left", false))
		b.WriteString(para("  排除检查: "+joinLimited(item.ExclusionChecks, 3), "20", "left", false))
		b.WriteString(para("  后续要求: "+joinLimited(item.RequiredFollowUp, 3), "20", "left", false))
	}
	return b.String()
}

func detectionComparisonSection(items []review.DetectionChainComparison) string {
	var b strings.Builder
	b.WriteString(heading("检测链路对比与优化项", "28"))
	b.WriteString(para("本节将当前检测链路与参考基线进行逐项比较，明确哪一方更优、当前差距和下一步可执行优化项。", "22", "left", false))
	if len(items) == 0 {
		b.WriteString(para("未生成检测链路对比。", "22", "left", false))
		return b.String()
	}
	for _, item := range items {
		b.WriteString(para("- "+item.Area+" / "+item.Winner, "20", "left", true))
		b.WriteString(para("  当前链路: "+item.CurrentStatus, "20", "left", false))
		b.WriteString(para("  参考基线: "+item.BaselineApproach, "20", "left", false))
		b.WriteString(para("  差距: "+item.Gap, "20", "left", false))
		b.WriteString(para("  优化项: "+item.Optimization, "20", "left", false))
		if len(item.Evidence) > 0 {
			b.WriteString(para("  证据: "+joinLimited(item.Evidence, 4), "20", "left", false))
		}
	}
	return b.String()
}

func reviewAgentTasksSection(items []review.ReviewAgentTask) string {
	var b strings.Builder
	b.WriteString(heading("二次复核 Agent 任务包", "28"))
	b.WriteString(para("本节将结构化复核方法转化为可执行任务包，可交给 LLM reviewer 或外部审计系统消费。", "22", "left", false))
	if len(items) == 0 {
		b.WriteString(para("未生成二次复核 Agent 任务包。", "22", "left", false))
		return b.String()
	}
	max := len(items)
	if max > 4 {
		max = 4
	}
	for _, item := range items[:max] {
		b.WriteString(para("- "+item.FindingID+" / "+item.AgentRole, "20", "left", true))
		b.WriteString(para("  目标: "+item.Objective, "20", "left", false))
		b.WriteString(para("  输入: "+joinLimited(item.Inputs, 4), "20", "left", false))
		b.WriteString(para("  严格标准: "+joinLimited(item.StrictStandards, 4), "20", "left", false))
		b.WriteString(para("  期望输出: "+joinLimited(item.ExpectedOutputs, 4), "20", "left", false))
		b.WriteString(para("  重点判定条件: "+joinLimited(item.BlockingCriteria, 4), "20", "left", false))
		b.WriteString(para("  Prompt: "+item.Prompt, "18", "left", false))
	}
	if len(items) > max {
		b.WriteString(para(fmt.Sprintf("其余 %d 个任务包请查看 JSON 报告。", len(items)-max), "20", "left", false))
	}
	return b.String()
}

func reviewAgentVerdictsSection(items []review.ReviewAgentVerdict) string {
	var b strings.Builder
	b.WriteString(heading("二次复核 Agent 裁决", "28"))
	b.WriteString(para("本节展示 vuln-reviewer 对 Agent 任务包的复核裁决。最终裁决优先级: LLM reviewer > deterministic reviewer；风险排序优先级: confirmed > needs_manual_review > 无裁决 > likely_false_positive。", "22", "left", false))
	if len(items) == 0 {
		b.WriteString(para("未生成二次复核裁决。", "22", "left", false))
		return b.String()
	}
	preferred := preferredDocxVerdictsByFinding(items)
	for _, item := range items {
		selected := "否"
		if current, ok := preferred[item.FindingID]; ok && current.Reviewer == item.Reviewer && current.Verdict == item.Verdict {
			selected = "是"
		}
		b.WriteString(para("- "+item.FindingID+" / "+item.Verdict+" / 置信度: "+item.Confidence+" / 最终采用: "+selected, "20", "left", true))
		b.WriteString(para("  原因: "+item.Reason, "20", "left", false))
		if len(item.MissingEvidence) > 0 {
			b.WriteString(para("  缺失证据: "+joinLimited(item.MissingEvidence, 4), "20", "left", false))
		}
		b.WriteString(para("  修复建议: "+item.Fix, "20", "left", false))
		b.WriteString(para("  Reviewer: "+item.Reviewer, "20", "left", false))
	}
	return b.String()
}

func ruleExplanationsSection(items []review.RuleExplanation) string {
	var b strings.Builder
	b.WriteString(heading("规则解释卡", "28"))
	b.WriteString(para("本节为规则生成检测条件、排除条件、验证要求和输出要求。", "22", "left", false))
	if len(items) == 0 {
		b.WriteString(para("未生成规则解释卡。", "22", "left", false))
		return b.String()
	}
	max := len(items)
	if max > 8 {
		max = 8
	}
	for _, item := range items[:max] {
		status := "未命中"
		if item.Triggered {
			status = "已命中"
		}
		b.WriteString(para(fmt.Sprintf("- %s %s / %s / %s", item.RuleID, item.Name, item.Severity, status), "20", "left", true))
		b.WriteString(para("  检测条件: "+joinLimited(item.DetectionCriteria, 3), "20", "left", false))
		b.WriteString(para("  排除条件: "+joinLimited(item.ExclusionConditions, 3), "20", "left", false))
		b.WriteString(para("  验证要求: "+joinLimited(item.VerificationRequirements, 3), "20", "left", false))
		b.WriteString(para("  输出要求: "+joinLimited(item.OutputRequirements, 3), "20", "left", false))
		b.WriteString(para("  Prompt 摘要: "+item.PromptTemplateSummary, "20", "left", false))
		b.WriteString(para("  修复重点: "+item.RemediationFocus, "20", "left", false))
	}
	if len(items) > max {
		b.WriteString(para(fmt.Sprintf("其余 %d 条规则解释请查看 JSON 报告。", len(items)-max), "20", "left", false))
	}
	return b.String()
}

func optimizationNotesSection(notes []review.OptimizationNote) string {
	var b strings.Builder
	b.WriteString(heading("优化说明（原因与收益）", "28"))
	if len(notes) == 0 {
		b.WriteString(para("无额外优化说明。", "22", "left", false))
		return b.String()
	}
	for _, note := range notes {
		b.WriteString(para("- 改动: "+note.Change, "20", "left", true))
		b.WriteString(para("  原因: "+note.Reason, "20", "left", false))
		b.WriteString(para("  好处: "+note.Benefit, "20", "left", false))
	}
	return b.String()
}

func joinLimited(items []string, limit int) string {
	if len(items) <= limit {
		return strings.Join(items, "；")
	}
	return strings.Join(items[:limit], "；") + fmt.Sprintf("；...其余 %d 项请查看 JSON 报告", len(items)-limit)
}

func escapeXML(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

// XML templates.
const (
	contentTypesXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/fontTable.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.fontTable+xml"/>
  <Override PartName="/word/settings.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml"/>
</Types>`

	relsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>`

	docRelsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/fontTable" Target="fontTable.xml"/>
  <Relationship Id="rId3" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/settings" Target="settings.xml"/>
</Relationships>`

	settingsXML = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:themeFontLang w:val="en-US" w:eastAsia="zh-CN"/>
</w:settings>`

	docHeader = `<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
<w:body>`

	docFooter = `</w:body></w:document>`
)

// groupByRuleID 将 findings 按 RuleID 分组
func groupByRuleID(findings []plugins.Finding) map[string][]plugins.Finding {
	grouped := make(map[string][]plugins.Finding)
	for _, f := range findings {
		grouped[f.RuleID] = append(grouped[f.RuleID], f)
	}
	return grouped
}

// ruleHeading 生成规则的主标题
func ruleHeading(ruleID, title, color, size string) string {
	return fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="%s"/></w:pPr><w:r><w:rPr><w:b/><w:color w:val="%s"/>%s<w:sz w:val="%s"/></w:rPr><w:t xml:space="preserve">[%s] %s</w:t></w:r></w:p>`,
		size, color, docxRunFonts(docxLatinFont, docxCJKFont()), size, escapeXML(ruleID), escapeXML(title),
	)
}

// findingDetailPara 输出单个发现的位置和代码片段（不含标题）
func findingDetailPara(f plugins.Finding) string {
	var b strings.Builder
	desc := f.Description
	if f.RuleID == "LLM-DETECT" {
		desc = "[模型分析] " + desc
	}
	b.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="24"/><w:ind w:left="400"/></w:pPr><w:r><w:rPr><w:b/>%s<w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">问题说明: %s</w:t></w:r></w:p>`,
		docxRunFonts(docxLatinFont, docxCJKFont()), escapeXML(desc),
	))
	b.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="24"/><w:ind w:left="400"/></w:pPr><w:r><w:rPr>%s<w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">触发位置: %s</w:t></w:r></w:p>`,
		docxRunFonts(docxLatinFont, docxCJKFont()), escapeXML(defaultText(f.Location, "未提供具体位置，请结合规则名称排查")),
	))
	b.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="24"/><w:ind w:left="400"/></w:pPr><w:r><w:rPr>%s<w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">风险影响: %s</w:t></w:r></w:p>`,
		docxRunFonts(docxLatinFont, docxCJKFont()), escapeXML(riskImpactForFinding(f)),
	))
	b.WriteString(fmt.Sprintf(
		`<w:p><w:pPr><w:sz w:val="24"/><w:ind w:left="400"/></w:pPr><w:r><w:rPr>%s<w:sz w:val="24"/></w:rPr><w:t xml:space="preserve">修复建议: %s</w:t></w:r></w:p>`,
		docxRunFonts(docxLatinFont, docxCJKFont()), escapeXML(remediationForFinding(f)),
	))
	if f.CodeSnippet != "" {
		b.WriteString(codeBlockPara(f.CodeSnippet))
	}
	return b.String()
}

func defaultText(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}

func riskImpactForFinding(f plugins.Finding) string {
	s := strings.TrimSpace(f.Severity)
	switch s {
	case "高风险":
		return "该问题可能导致越权执行、敏感数据泄露或恶意指令落地，应立即修复。"
	case "中风险":
		return "该问题可能在特定条件下扩大攻击面，建议在本轮迭代中完成修复。"
	default:
		return "该问题主要影响防护完整性，建议纳入常规修复计划并复测验证。"
	}
}

func remediationForFinding(f plugins.Finding) string {
	ruleID := strings.ToUpper(strings.TrimSpace(f.RuleID))
	if ruleID == "V7-003" {
		return "将外联目标收敛到白名单并启用 TLS，补充来源校验与完整性校验后复测。"
	}
	if ruleID == "V7-006" {
		return "同步修正技能声明与实现行为，确保权限声明、代码能力和测试用例保持一致。"
	}
	if strings.HasPrefix(ruleID, "V7-00") || ruleID == "V7-010" || ruleID == "V7-011" || ruleID == "V7-012" || ruleID == "V7-013" || ruleID == "V7-014" {
		return "优先移除高危调用或增加显式权限校验，补充对应单元测试后重新扫描确认风险清零。"
	}
	if ruleID == "LLM-DETECT" {
		return "按模型提示定位具体路径，增加输入校验、最小权限控制与错误处理，再执行全量复扫。"
	}
	if strings.TrimSpace(f.Severity) == "高风险" {
		return "在问题位置补充输入校验、权限边界与异常处理，必要时下线相关能力后逐步恢复。"
	}
	return "结合规则说明修正代码与配置，修复完成后执行全量复扫并更新设计文档。"
}

package handler

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"

	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
	reviewreport "skill-scanner/internal/review/report"
)

func buildStructuredFindings(findings []plugins.Finding, refined review.Result, consolidation *llm.CrossFileConsolidation, sourceRoot string, sourceFiles []evaluator.SourceFile) []review.StructuredFinding {
	sourceIndex := buildSourceContextIndex(sourceRoot, sourceFiles)
	sanitizer := newReportSanitizer(sourceRoot)
	deliveryProfile := summarizeDeliveredFiles(sourceFiles)
	obfuscationChainsByCategory := buildObfuscationFindingChainsByCategory(refined.ObfuscationEvidence)
	linkedChainsByCategory := buildCrossEvidenceChainsByCategory(findings, refined)
	groups := make(map[string][]plugins.Finding)
	order := make([]string, 0, len(findings))
	concreteRuleIDs := concreteFindingRuleIDs(findings)
	for _, finding := range findings {
		if shouldSkipStructuredFinding(finding, concreteRuleIDs) {
			continue
		}
		key := structuredFindingGroupKey(finding)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], finding)
	}

	out := make([]review.StructuredFinding, 0, len(order))
	for i, key := range order {
		items := groups[key]
		first := representativeFinding(items)
		if shouldSkipDeliveryMismatchGroup(first, items, deliveryProfile) {
			continue
		}
		category := structuredFindingCategory(first)
		if shouldSkipWeakDependencyAdvisoryGroup(first, items) || shouldSkipPlaceholderDocumentationGroup(category, items) || shouldSkipDocumentationExampleGroup(category, items) || shouldSkipCommentOnlyGroup(category, items, sourceIndex) {
			continue
		}
		evidence := appendObfuscationEvidence(sanitizer.structuredFindingEvidence(items, sourceIndex), items, category, refined.ObfuscationEvidence)
		evidenceItems, excludedEvidence := structuredEvidenceItemsForFinding(category, items, evidence)
		applicabilityVerdict, applicabilityBasis := structuredFindingApplicability(category, items, evidenceItems)
		evidence = acceptedStructuredEvidenceLines(evidenceItems)
		if applicabilityVerdict == "not_applicable" {
			evidence = limitNonEmptyStrings(evidence, 2)
		}
		if !hasConcreteStructuredFindingEvidence(evidence) && !hasConcreteStructuredFindingLocationForCategory(category, items) {
			continue
		}
		confidence, basis := structuredFindingCalibration(category, items, refined)
		basis = uniqueStrings(append(basis, crossFileConsolidationCalibrationBasis(category, consolidation)...))
		chainSummaries := uniqueStrings(append(structuredFindingChainSummaries(category, refined.Behavior, append(obfuscationChainsByCategory[category], linkedChainsByCategory[category]...)), crossFileConsolidationChainSummaries(category, consolidation)...))
		codeEvidenceRefs, behaviorEvidenceRefs, contextEvidenceRefs := structuredFindingTypedEvidenceRefs(items, append(evidence, chainSummaries...))
		attackPath := structuredAttackPath(category, first, refined)
		out = append(out, review.StructuredFinding{
			ID:                   fmt.Sprintf("SF-%03d", i+1),
			RuleID:               publicRuleIDForOutput(first.RuleID),
			Title:                normalizeStructuredFindingTitle(first.Title),
			Severity:             normalizedStructuredFindingSeverity(first),
			Category:             category,
			SecurityVerdict:      structuredFindingSecurityVerdict(first, items, refined),
			DeclarationVerdict:   structuredFindingDeclarationVerdict(first, items),
			Confidence:           confidence,
			AttackPath:           attackPath,
			MITRETechniques:      mitreTechniquesForFinding(first.RuleID, category),
			CodeEvidenceRefs:     codeEvidenceRefs,
			BehaviorEvidenceRefs: behaviorEvidenceRefs,
			ContextEvidenceRefs:  contextEvidenceRefs,
			Evidence:             evidence,
			EvidenceItems:        evidenceItems,
			ExcludedEvidence:     excludedEvidence,
			Closure:              buildFindingClosureSummary(review.StructuredFinding{Title: normalizeStructuredFindingTitle(first.Title), Category: category, AttackPath: attackPath, Evidence: evidence, CodeEvidenceRefs: codeEvidenceRefs, BehaviorEvidenceRefs: behaviorEvidenceRefs, ContextEvidenceRefs: contextEvidenceRefs, ChainSummaries: chainSummaries, CalibrationBasis: basis}, refined).toReviewFindingClosure(),
			ChainSummaries:       chainSummaries,
			Chains:               structuredFindingChains(category, refined.Behavior, append(obfuscationChainsByCategory[category], linkedChainsByCategory[category]...)),
			ApplicabilityVerdict: applicabilityVerdict,
			ApplicabilityBasis:   applicabilityBasis,
			CalibrationBasis:     basis,
			FalsePositiveChecks:  falsePositiveChecks(category, first, refined),
			ReviewGuidance:       structuredReviewGuidance(category, first),
			Source:               mergedFindingSource(items),
			DeduplicatedCount:    len(items),
		})
	}
	return out
}

func crossFileConsolidationAppliesToCategory(category string, consolidation *llm.CrossFileConsolidation) bool {
	if consolidation == nil {
		return false
	}
	for _, item := range consolidation.RelatedCategories {
		if strings.TrimSpace(item) == strings.TrimSpace(category) {
			return true
		}
	}
	return false
}

func crossFileConsolidationAppliesToFinding(finding review.StructuredFinding, consolidation *llm.CrossFileConsolidation) bool {
	return crossFileConsolidationAppliesToCategory(finding.Category, consolidation)
}

func crossFileConsolidationCalibrationBasis(category string, consolidation *llm.CrossFileConsolidation) []string {
	if !crossFileConsolidationAppliesToCategory(category, consolidation) {
		return nil
	}
	basis := []string{}
	if text := strings.TrimSpace(consolidation.Summary); text != "" {
		basis = append(basis, text)
	}
	if len(consolidation.MissingParts) > 0 {
		basis = append(basis, "跨文件链路仍缺少 "+strings.Join(consolidation.MissingParts, "/")+" 支撑，当前结论保留补证要求。")
	}
	return basis
}

func crossFileConsolidationChainSummaries(category string, consolidation *llm.CrossFileConsolidation) []string {
	if !crossFileConsolidationAppliesToCategory(category, consolidation) {
		return nil
	}
	items := []string{}
	if text := strings.TrimSpace(consolidation.Summary); text != "" {
		items = append(items, text)
	}
	items = append(items, consolidation.Evidence...)
	return uniqueStrings(items)
}

type deliveredFileProfile struct {
	runtimeFiles  int
	pythonFiles   int
	shellFiles    int
	serviceFiles  int
	basenames     map[string]struct{}
	hasReadmeOnly bool
}

func summarizeDeliveredFiles(sourceFiles []evaluator.SourceFile) deliveredFileProfile {
	profile := deliveredFileProfile{basenames: make(map[string]struct{})}
	meaningful := 0
	for _, file := range sourceFiles {
		path := strings.TrimSpace(filepath.ToSlash(file.Path))
		if path == "" {
			continue
		}
		base := strings.ToLower(filepath.Base(path))
		profile.basenames[base] = struct{}{}
		if !isMeaningfulDeliveredFile(path) {
			continue
		}
		meaningful++
		profile.runtimeFiles++
		switch strings.ToLower(filepath.Ext(base)) {
		case ".py":
			profile.pythonFiles++
		case ".sh":
			profile.shellFiles++
		}
		if isLikelyServiceOrRuntimeFile(base) {
			profile.serviceFiles++
		}
	}
	profile.hasReadmeOnly = meaningful == 1 && hasOnlyReadme(profile.basenames)
	return profile
}

func shouldSkipDeliveryMismatchGroup(first plugins.Finding, items []plugins.Finding, profile deliveredFileProfile) bool {
	if normalizeStructuredFindingTitle(first.Title) != "声明与交付内容需人工复核" {
		return false
	}
	if profile.hasReadmeOnly {
		return false
	}
	if profile.serviceFiles >= 2 {
		return true
	}
	if profile.runtimeFiles >= 3 && (profile.pythonFiles >= 2 || profile.shellFiles >= 1) {
		return true
	}
	joined := strings.ToLower(strings.Join(append(findingTexts(items), first.Title), "\n"))
	if strings.Contains(joined, "only readme") || strings.Contains(joined, "只有 readme") {
		if profile.runtimeFiles >= 2 {
			return true
		}
	}
	if strings.Contains(joined, "only empty init file") || strings.Contains(joined, "仅包含一个空") {
		if profile.runtimeFiles >= 1 {
			return true
		}
	}
	return false
}

func findingTexts(items []plugins.Finding) []string {
	out := make([]string, 0, len(items)*3)
	for _, item := range items {
		out = append(out, item.Title, item.Description, item.CodeSnippet)
	}
	return out
}

func isMeaningfulDeliveredFile(path string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(path)))
	if base == "" {
		return false
	}
	if base == "readme.md" || base == "skill.md" || base == "deployment.md" || base == "troubleshooting.md" || base == "license" || base == "license.md" || base == "_meta.json" {
		return false
	}
	if strings.HasSuffix(base, "_test.py") || strings.HasPrefix(base, "test_") {
		return false
	}
	if strings.Contains(path, "/tests/") {
		return false
	}
	return true
}

func isLikelyServiceOrRuntimeFile(base string) bool {
	if base == "polymarket.py" || base == "dashboard.py" || base == "db.py" || base == "bootstrap.sh" || base == "agent.yaml" {
		return true
	}
	return strings.HasSuffix(base, ".py") || strings.HasSuffix(base, ".sh") || strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")
}

func hasOnlyReadme(basenames map[string]struct{}) bool {
	if len(basenames) != 1 {
		return false
	}
	_, ok := basenames["readme.md"]
	return ok
}

func representativeFinding(items []plugins.Finding) plugins.Finding {
	if len(items) == 0 {
		return plugins.Finding{}
	}
	best := items[0]
	for _, item := range items[1:] {
		if severityRank(item.Severity) < severityRank(best.Severity) {
			best = item
			continue
		}
		if severityRank(item.Severity) == severityRank(best.Severity) && concreteEvidenceWeight(item) > concreteEvidenceWeight(best) {
			best = item
		}
	}
	return best
}

func concreteEvidenceWeight(item plugins.Finding) int {
	weight := 0
	if hasConcreteStructuredFindingLocation([]plugins.Finding{item}) {
		weight += 2
	}
	if hasConcreteStructuredFindingEvidence([]string{item.CodeSnippet, item.Description}) {
		weight++
	}
	return weight
}

func hasConcreteStructuredFindingLocation(items []plugins.Finding) bool {
	return hasConcreteStructuredFindingLocationForCategory("", items)
}

func hasConcreteStructuredFindingLocationForCategory(category string, items []plugins.Finding) bool {
	for _, item := range items {
		location := strings.TrimSpace(item.Location)
		if location == "" || location == "行为证据采集" || isInternalScanArtifactPath(location) {
			continue
		}
		joined := strings.Join([]string{item.Location, item.CodeSnippet, item.Description, item.Title}, " ")
		if isPlaceholderLocatorText(joined) {
			continue
		}
		if strings.Contains(strings.ToLower(location), "倒数第二行") {
			return true
		}
		if strings.Contains(location, ":") {
			return true
		}
	}
	return false
}

func shouldSkipWeakDependencyAdvisoryGroup(first plugins.Finding, items []plugins.Finding) bool {
	title := normalizeStructuredFindingTitle(first.Title)
	if title != "依赖漏洞与供应链风险" && strings.TrimSpace(first.Title) != "依赖漏洞与恶意依赖-高危漏洞依赖" {
		return false
	}
	joined := strings.ToLower(strings.Join(findingTexts(items), " "))
	if hasConcreteDependencyVulnerabilitySignal(joined) {
		return false
	}
	return containsAny(joined, []string{"高危依赖", "依赖漏洞", "漏洞依赖", "缺少版本", "缺少 sbom", "缺少sbom", "补充依赖清单", "锁定版本", "无法完成漏洞精确比对"})
}

func hasConcreteDependencyVulnerabilitySignal(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	hasPackage := containsAny(lower, []string{"dependency=", "package=", "module=", "pkg=", "@"})
	hasVersion := containsAny(lower, []string{"version=", "版本=", "@"})
	hasVulnerabilityID := containsAny(lower, []string{"ghsa-", "cve-", "vuln=", "osv 证据", "osv:"})
	return hasPackage && hasVersion && hasVulnerabilityID
}

func shouldSkipPlaceholderDocumentationGroup(category string, items []plugins.Finding) bool {
	if strings.TrimSpace(category) == "声明与行为差异" {
		return false
	}
	for _, item := range items {
		joined := strings.Join([]string{item.Location, item.CodeSnippet, item.Description, item.Title}, " ")
		if !isPlaceholderLocatorText(joined) {
			return false
		}
	}
	return len(items) > 0
}

func shouldSkipCommentOnlyGroup(category string, items []plugins.Finding, sourceIndex map[string][]string) bool {
	if !commentOnlySkipCategory(category) {
		return false
	}
	for _, item := range items {
		if !isCommentOnlyFinding(item, sourceIndex) {
			return false
		}
	}
	return len(items) > 0
}

func commentOnlySkipCategory(category string) bool {
	switch strings.TrimSpace(category) {
	case "命令执行", "下载执行", "恶意代码", "网络请求与SSRF", "凭据访问", "凭据暴露", "外联与情报", "暴露面与未鉴权服务", "持久化", "提权", "反分析/逃逸":
		return true
	default:
		return false
	}
}

func isCommentOnlyFinding(item plugins.Finding, sourceIndex map[string][]string) bool {
	if isCommentOnlySnippet(item.CodeSnippet) {
		return true
	}
	path, line, ok := parseSourceLocation(item.Location)
	if !ok || len(sourceIndex) == 0 {
		return false
	}
	lines, ok := sourceIndex[filepath.ToSlash(strings.TrimSpace(path))]
	if !ok {
		return false
	}
	return sourceLineIsCommentOnly(lines, line)
}

func isCommentOnlySnippet(snippet string) bool {
	text := strings.TrimSpace(strings.ReplaceAll(snippet, "\r\n", "\n"))
	if text == "" {
		return false
	}
	if isWrappedCommentBlock(text) {
		return true
	}
	lines := strings.Split(text, "\n")
	commentLines := 0
	contentLines := 0
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		contentLines++
		if isLineComment(trimmed) || isWrappedCommentBlock(trimmed) {
			commentLines++
		}
	}
	return contentLines > 0 && contentLines == commentLines
}

func isWrappedCommentBlock(text string) bool {
	trimmed := strings.TrimSpace(text)
	return strings.HasPrefix(trimmed, "/*") && strings.HasSuffix(trimmed, "*/") ||
		strings.HasPrefix(trimmed, "<!--") && strings.HasSuffix(trimmed, "-->") ||
		strings.HasPrefix(trimmed, "'''") && strings.HasSuffix(trimmed, "'''") ||
		strings.HasPrefix(trimmed, `"""`) && strings.HasSuffix(trimmed, `"""`)
}

func isLineComment(trimmed string) bool {
	return strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "--")
}

func sourceLineIsCommentOnly(lines []string, line int) bool {
	if line <= 0 || line > len(lines) {
		return false
	}
	block := ""
	for idx, raw := range lines {
		currentLine := idx + 1
		trimmed := strings.TrimSpace(raw)
		if currentLine == line {
			if block != "" || isLineComment(trimmed) || startsBlockComment(trimmed) {
				return true
			}
			return false
		}
		block = updateCommentBlockState(block, trimmed)
		if currentLine >= line {
			break
		}
	}
	return false
}

func startsBlockComment(trimmed string) bool {
	return strings.HasPrefix(trimmed, "/*") || strings.HasPrefix(trimmed, "<!--") || strings.HasPrefix(trimmed, "'''") || strings.HasPrefix(trimmed, `"""`)
}

func updateCommentBlockState(block, trimmed string) string {
	if block != "" {
		if strings.Contains(trimmed, commentBlockEnd(block)) {
			return ""
		}
		return block
	}
	for _, marker := range []string{"/*", "<!--", "'''", `"""`} {
		if !strings.HasPrefix(trimmed, marker) {
			continue
		}
		end := commentBlockEnd(marker)
		rest := strings.TrimPrefix(trimmed, marker)
		if strings.Contains(rest, end) {
			return ""
		}
		return marker
	}
	return ""
}

func commentBlockEnd(block string) string {
	switch block {
	case "/*":
		return "*/"
	case "<!--":
		return "-->"
	case "'''":
		return "'''"
	case `"""`:
		return `"""`
	default:
		return ""
	}
}

func shouldSkipDocumentationExampleGroup(category string, items []plugins.Finding) bool {
	switch strings.TrimSpace(category) {
	case "命令执行", "下载执行", "恶意代码", "网络请求与SSRF", "凭据访问", "凭据暴露", "外联与情报":
		for _, item := range items {
			joined := strings.Join([]string{item.Location, item.CodeSnippet, item.Description, item.Title}, " ")
			if !isSkippableDocumentationEvidenceText(joined) {
				return false
			}
		}
		return len(items) > 0
	default:
		return false
	}
}

func isPrimaryDocumentationEvidenceText(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "skill.md") || isNonSkillDocumentationEvidenceText(lower)
}

func isNonSkillDocumentationEvidenceText(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, "readme") || strings.Contains(lower, "docs/") || strings.Contains(lower, "/docs/")
}

func isSkippableDocumentationEvidenceText(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	if isNonSkillDocumentationEvidenceText(lower) {
		return true
	}
	if strings.Contains(lower, "skill.md") {
		return isSkillExampleOrPlaceholderText(lower)
	}
	return false
}

func isPlaceholderLocatorText(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	return containsAny(lower, []string{"[slug]", "[path]", "[file]", "[filename]", "<slug>", "<path>", "{slug}", "{path}", "${slug}", "${path}"})
}

func isSkillExampleOrPlaceholderText(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" || !strings.Contains(lower, "skill.md") {
		return false
	}
	if containsAny(lower, []string{"<url>", "[slug]", "[path]", "[file]", "[filename]", "<slug>", "<path>", "{slug}", "{path}"}) {
		return true
	}
	if containsAny(lower, []string{"example.com", "example.org", "example.net"}) {
		return containsAny(lower, []string{"示例", "example", "sample", "demo", "安装教程", "usage example", "for example", "例如"})
	}
	return containsAny(lower, []string{"示例", "example", "sample", "demo", "安装教程", "usage example", "for example"}) && containsAny(lower, []string{"curl ", "wget ", "git clone", "pip install", "npm install"})
}

func hasConcreteStructuredFindingEvidence(items []string) bool {
	for _, item := range items {
		text := strings.ToLower(strings.TrimSpace(item))
		if text == "" {
			continue
		}
		if strings.HasPrefix(text, "位置: 行为证据采集") {
			continue
		}
		if strings.HasPrefix(text, "片段: 行为证据摘要:") {
			continue
		}
		if strings.Contains(text, "行为证据摘要:") && !strings.Contains(text, "关键样本") {
			continue
		}
		return true
	}
	return false
}

type reportSanitizer struct {
	trimmedRoot string
}

func newReportSanitizer(sourceRoot string) reportSanitizer {
	return reportSanitizer{
		trimmedRoot: strings.Trim(filepath.ToSlash(strings.TrimSpace(sourceRoot)), "/"),
	}
}

func sanitizeReportResult(refined review.Result, sourceRoot string) review.Result {
	sanitizer := newReportSanitizer(sourceRoot)
	for i := range refined.StructuredFindings {
		refined.StructuredFindings[i] = sanitizer.sanitizeStructuredFinding(refined.StructuredFindings[i])
	}
	for i := range refined.ReviewAgentVerdicts {
		refined.ReviewAgentVerdicts[i].MissingEvidence = sanitizer.sanitizeStringList(refined.ReviewAgentVerdicts[i].MissingEvidence)
		refined.ReviewAgentVerdicts[i].Reason = sanitizer.sanitizeText(refined.ReviewAgentVerdicts[i].Reason)
		refined.ReviewAgentVerdicts[i].Fix = sanitizer.sanitizeText(refined.ReviewAgentVerdicts[i].Fix)
	}
	for i := range refined.FalsePositiveReviews {
		refined.FalsePositiveReviews[i].ReachabilityChecks = sanitizer.sanitizeStringList(refined.FalsePositiveReviews[i].ReachabilityChecks)
		refined.FalsePositiveReviews[i].ExclusionChecks = sanitizer.sanitizeStringList(refined.FalsePositiveReviews[i].ExclusionChecks)
		refined.FalsePositiveReviews[i].RequiredFollowUp = sanitizer.sanitizeStringList(refined.FalsePositiveReviews[i].RequiredFollowUp)
	}
	return refined
}

func (s reportSanitizer) sanitizeStructuredFinding(finding review.StructuredFinding) review.StructuredFinding {
	finding.AttackPath = s.sanitizeAttackPath(finding.AttackPath)
	finding.CodeEvidenceRefs = s.sanitizeStringList(finding.CodeEvidenceRefs)
	finding.BehaviorEvidenceRefs = s.sanitizeStringList(finding.BehaviorEvidenceRefs)
	finding.ContextEvidenceRefs = s.sanitizeStringList(finding.ContextEvidenceRefs)
	finding.Evidence = s.sanitizeStringList(finding.Evidence)
	finding.ApplicabilityBasis = s.sanitizeStringList(finding.ApplicabilityBasis)
	finding.ChainSummaries = s.sanitizeStringList(finding.ChainSummaries)
	finding.CalibrationBasis = s.sanitizeStringList(finding.CalibrationBasis)
	finding.FalsePositiveChecks = s.sanitizeStringList(finding.FalsePositiveChecks)
	finding.ReviewGuidance = s.sanitizeText(finding.ReviewGuidance)
	finding.EvidenceItems = sanitizeStructuredEvidenceItems(s, finding.EvidenceItems)
	finding.ExcludedEvidence = sanitizeStructuredEvidenceItems(s, finding.ExcludedEvidence)
	outChains := make([]review.FindingChain, 0, len(finding.Chains))
	for _, chain := range finding.Chains {
		chain.Summary = s.sanitizeText(chain.Summary)
		chain.Source = s.sanitizeText(chain.Source)
		chain.Path = s.sanitizePath(chain.Path)
		if isInternalScanArtifactText(chain.Summary) || isInternalScanArtifactText(chain.Source) || isInternalScanArtifactPath(chain.Path) {
			continue
		}
		outChains = append(outChains, chain)
	}
	finding.Chains = dedupeFindingChains(outChains)
	return finding
}

func sanitizeStructuredEvidenceItems(s reportSanitizer, items []review.StructuredEvidenceItem) []review.StructuredEvidenceItem {
	out := make([]review.StructuredEvidenceItem, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		item.Location = s.sanitizePath(item.Location)
		item.Snippet = s.sanitizeText(item.Snippet)
		item.Summary = s.sanitizeText(item.Summary)
		item.Reason = s.sanitizeText(item.Reason)
		if item.Location == "" && item.Snippet == "" && item.Summary == "" {
			continue
		}
		key := normalizeEvidenceDedupKey(strings.Join([]string{item.Location, item.Snippet, item.Summary, item.SourceType, item.Status, item.Reason}, " | "))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func structuredEvidenceItemsForFinding(category string, items []plugins.Finding, evidence []string) ([]review.StructuredEvidenceItem, []review.StructuredEvidenceItem) {
	accepted := make([]review.StructuredEvidenceItem, 0, len(evidence)+len(items))
	excluded := make([]review.StructuredEvidenceItem, 0)
	for _, line := range evidence {
		item := structuredEvidenceItemFromText(category, line)
		if item.Status == "excluded" {
			excluded = append(excluded, item)
			continue
		}
		accepted = append(accepted, item)
	}
	for _, finding := range items {
		item := structuredEvidenceItemFromPluginFinding(category, finding)
		if item.Status == "excluded" {
			excluded = append(excluded, item)
			continue
		}
		accepted = append(accepted, item)
	}
	return dedupeStructuredEvidenceItems(accepted), dedupeStructuredEvidenceItems(excluded)
}

func structuredEvidenceItemFromText(category, line string) review.StructuredEvidenceItem {
	line = strings.TrimSpace(line)
	item := review.StructuredEvidenceItem{Summary: line, Status: "accepted", SourceType: "derived_evidence"}
	if p, _, ok := tryParseInlineLocator(line); ok {
		item.Location = strings.TrimSpace(p)
	}
	lower := strings.ToLower(line)
	if strings.HasPrefix(line, "混淆解析证据 /") {
		item.SourceType = "obfuscation"
		return item
	}
	switch {
	case shouldExcludeCommentEvidence(category, line):
		item.SourceType = "comment"
		item.Status = "excluded"
		item.Reason = "注释块或说明性片段不进入主证据集"
	case shouldExcludeDocumentationEvidence(category, line):
		item.SourceType = "documentation"
		item.Status = "excluded"
		item.Reason = "文档或示例证据不进入主证据集"
	case shouldExcludeInternalEvidence(category, line):
		item.SourceType = "internal"
		item.Status = "excluded"
		item.Reason = "本地开发或调试语境证据不进入主证据集"
	case strings.Contains(lower, "行为证据摘要:") && !strings.Contains(lower, "关键样本"):
		item.SourceType = "behavior_summary"
		item.Status = "excluded"
		item.Reason = "仅摘要型行为证据需要映射回具体源码后再参与判断"
	case strings.Contains(lower, ".scan-cache.json"):
		item.SourceType = "scan_artifact"
		item.Status = "excluded"
		item.Reason = "扫描内部产物不作为用户可见主证据"
	}
	return item
}

func structuredEvidenceItemFromPluginFinding(category string, finding plugins.Finding) review.StructuredEvidenceItem {
	summary := strings.TrimSpace(firstNonEmpty(finding.CodeSnippet, finding.Description, finding.Title))
	item := review.StructuredEvidenceItem{
		Location:   strings.TrimSpace(finding.Location),
		Snippet:    strings.TrimSpace(finding.CodeSnippet),
		Summary:    summary,
		SourceType: "plugin_finding",
		Status:     "accepted",
	}
	joined := strings.TrimSpace(strings.Join([]string{finding.Location, finding.CodeSnippet, finding.Description, finding.Title}, " "))
	switch {
	case shouldExcludeCommentEvidence(category, joined):
		item.Status = "excluded"
		item.Reason = "插件命中位于注释块或说明性片段"
	case shouldExcludeDocumentationEvidence(category, joined) || shouldExcludeInternalEvidence(category, joined):
		item.Status = "excluded"
		item.Reason = "插件命中位于文档、示例或内部开发语境"
	case isInternalScanArtifactPath(finding.Location):
		item.Status = "excluded"
		item.Reason = "插件命中仅指向扫描内部产物"
	case strings.TrimSpace(finding.Location) == "" && strings.TrimSpace(finding.CodeSnippet) == "" && strings.TrimSpace(finding.Description) == "":
		item.Status = "excluded"
		item.Reason = "插件命中缺少可验证证据内容"
	}
	return item
}

func shouldExcludeDocumentationEvidence(category, text string) bool {
	if strings.Contains(strings.ToLower(strings.TrimSpace(text)), "skill.md") {
		return isSkillExampleOrPlaceholderText(text)
	}
	if !isDocumentationLikeText(text) {
		return false
	}
	switch strings.TrimSpace(category) {
	case "命令执行", "下载执行", "恶意代码", "网络请求与SSRF", "凭据访问", "凭据暴露", "外联与情报", "声明与行为差异", "暴露面与未鉴权服务":
		return true
	default:
		return false
	}
}

func shouldExcludeCommentEvidence(category, text string) bool {
	return commentOnlySkipCategory(category) && isCommentOnlySnippet(text)
}

func shouldExcludeInternalEvidence(category, text string) bool {
	if !isInternalDevelopmentLikeText(text) {
		return false
	}
	switch strings.TrimSpace(category) {
	case "命令执行", "下载执行", "恶意代码", "网络请求与SSRF", "凭据访问", "凭据暴露", "外联与情报", "暴露面与未鉴权服务":
		return true
	default:
		return false
	}
}

func dedupeStructuredEvidenceItems(items []review.StructuredEvidenceItem) []review.StructuredEvidenceItem {
	out := make([]review.StructuredEvidenceItem, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		key := normalizeEvidenceDedupKey(strings.Join([]string{item.Location, item.Snippet, item.Summary, item.SourceType, item.Status, item.Reason}, " | "))
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func acceptedStructuredEvidenceLines(items []review.StructuredEvidenceItem) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.Status) == "excluded" {
			continue
		}
		line := strings.TrimSpace(item.Summary)
		if line == "" {
			line = strings.TrimSpace(item.Snippet)
		}
		if line == "" {
			line = strings.TrimSpace(item.Location)
		}
		if line == "" {
			continue
		}
		out = append(out, line)
	}
	return uniqueStrings(out)
}

func structuredFindingApplicability(category string, items []plugins.Finding, evidenceItems []review.StructuredEvidenceItem) (string, []string) {
	joined := strings.ToLower(strings.Join(findingTexts(items), " \n "))
	accepted := 0
	for _, item := range evidenceItems {
		if strings.TrimSpace(item.Status) != "excluded" {
			accepted++
		}
	}
	basis := make([]string, 0, 4)
	switch category {
	case "命令执行", "下载执行", "恶意代码":
		hasExec := containsAny(joined, []string{"os.system", "subprocess", "exec(", "bash ", "shell", "requests.get", "wget ", "curl "})
		if hasExec && accepted > 0 {
			return "applicable", []string{"存在可执行或下载执行相关调用，且保留了可验证源码证据。"}
		}
		basis = append(basis, "缺少可执行 sink 或下载执行链上的保留证据。")
	case "网络请求与SSRF":
		hasRequest := containsAny(joined, []string{"requests.get", "requests.post", "httpx", "urllib", "请求调用="})
		hasSource := containsAny(joined, []string{"来源类型=user_input", "输入来源=", "target_url", "url 参数"})
		if hasRequest && hasSource && accepted > 0 {
			return "applicable", []string{"存在请求调用和输入来源双证据，符合 SSRF 复核前提。"}
		}
		basis = append(basis, "缺少请求调用、输入来源或保留证据，暂不满足 SSRF 适用前提。")
	case "凭据访问", "凭据暴露":
		hasSecret := containsAny(joined, []string{"private_key", "token", "secret", "passphrase", "credential"})
		if hasSecret && accepted > 0 {
			return "applicable", []string{"存在凭据对象和可验证证据，符合凭据类规则前提。"}
		}
		basis = append(basis, "缺少真实凭据对象或保留证据，当前只适合作为观察项。")
	case "暴露面与未鉴权服务":
		hasService := containsAny(joined, []string{"app.run", "listen", "0.0.0.0", "127.0.0.1", "flask", "dashboard"})
		if hasService && accepted > 0 {
			return "applicable", []string{"存在监听/服务暴露信号，且保留了可验证证据。"}
		}
		basis = append(basis, "缺少监听入口或暴露证据，未满足服务暴露类规则前提。")
	default:
		if accepted > 0 {
			return "applicable", []string{"至少保留了一条可验证证据。"}
		}
		basis = append(basis, "当前仅剩文档、示例、调试或摘要型证据，未形成可验证主证据。")
	}
	return "not_applicable", basis
}

func firstNonEmpty(items ...string) string {
	for _, item := range items {
		if strings.TrimSpace(item) != "" {
			return item
		}
	}
	return ""
}

func (s reportSanitizer) sanitizeStringList(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		cleaned := s.sanitizeText(item)
		if cleaned == "" || isInternalScanArtifactText(cleaned) {
			continue
		}
		key := normalizeEvidenceDedupKey(cleaned)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, cleaned)
	}
	return out
}

func (s reportSanitizer) sanitizeAttackPath(text string) string {
	parts := strings.Split(text, "；")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = s.sanitizeText(part)
		if part == "" || isInternalScanArtifactText(part) {
			continue
		}
		out = append(out, part)
	}
	if len(out) == 0 {
		return "当前发现依赖规则命中和证据片段，需要结合源码上下文复核可达性与真实影响。"
	}
	return strings.Join(uniqueStrings(out), "；")
}

func sanitizeReportText(text, sourceRoot string) string {
	return newReportSanitizer(sourceRoot).sanitizeText(text)
}

func (s reportSanitizer) sanitizeText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	text = strings.ReplaceAll(text, "\\", "/")
	if s.trimmedRoot != "" {
		text = strings.ReplaceAll(text, "/"+s.trimmedRoot+"/", "")
		text = strings.ReplaceAll(text, s.trimmedRoot+"/", "")
	}
	segments := strings.Split(text, "/")
	for i, segment := range segments {
		if isLikelyTaskID(segment) && i+1 < len(segments) {
			text = strings.Join(segments[i+1:], "/")
			break
		}
	}
	return strings.TrimSpace(text)
}

func (s reportSanitizer) sanitizePath(pathValue string) string {
	cleaned := s.sanitizeText(pathValue)
	if isInternalScanArtifactPath(cleaned) {
		return ""
	}
	return cleaned
}

func isLikelyTaskID(segment string) bool {
	segment = strings.TrimSpace(segment)
	if len(segment) < 24 {
		return false
	}
	for _, r := range segment {
		if (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F') || (r >= '0' && r <= '9') {
			continue
		}
		return false
	}
	return true
}

func isInternalScanArtifactText(text string) bool {
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	return strings.Contains(lower, ".scan-cache.json") || strings.Contains(lower, "[sandbox-runtime] .scan-cache.json")
}

func isInternalScanArtifactPath(pathValue string) bool {
	lower := strings.ToLower(strings.TrimSpace(pathValue))
	return lower == ".scan-cache.json" || strings.HasSuffix(lower, "/.scan-cache.json") || strings.Contains(lower, ".scan-cache.json:")
}

func (s reportSanitizer) structuredFindingEvidence(items []plugins.Finding, sourceIndex map[string][]string) []string {
	evidence := s.sanitizeStringList(reviewreport.StructuredFindingEvidence(items, sourceIndex, 6))
	return reorderStructuredFindingEvidence(items, evidence)
}

func structuredFindingEvidence(items []plugins.Finding, sourceIndex map[string][]string) []string {
	return newReportSanitizer("").structuredFindingEvidence(items, sourceIndex)
}

func reorderStructuredFindingEvidence(items []plugins.Finding, evidence []string) []string {
	if len(evidence) < 2 || len(items) == 0 {
		return evidence
	}
	category := structuredFindingCategory(representativeFinding(items))
	sorted := append([]string{}, evidence...)
	sort.SliceStable(sorted, func(i, j int) bool {
		left := structuredEvidencePriority(category, sorted[i])
		right := structuredEvidencePriority(category, sorted[j])
		if left != right {
			return left > right
		}
		return len(sorted[i]) < len(sorted[j])
	})
	return sorted
}

func structuredEvidencePriority(category, evidence string) int {
	lower := strings.ToLower(strings.TrimSpace(evidence))
	if lower == "" {
		return 0
	}
	score := 0
	label, _ := reviewreport.SplitCodeEvidenceLabelAndBody(evidence)
	labelPath := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(label), "代码证据 /"))
	if strings.Contains(evidence, "\n>") {
		score += 2
	}
	if p, _, ok := tryParseInlineLocator(evidence); ok && strings.TrimSpace(p) != "" {
		score += 3
	}
	if reviewreport.IsDocumentationEvidencePath(labelPath) {
		score -= 3
	}
	switch category {
	case "授权与许可证校验":
		if strings.Contains(lower, "verify_failed") || strings.Contains(lower, "license validation") || strings.Contains(lower, "/api/validate") {
			score += 10
		}
		if strings.Contains(lower, "license_server") || strings.Contains(lower, "pro_license_key") || strings.Contains(lower, "localhost:8080") {
			score += 6
		}
		if strings.Contains(lower, "gamma_api") || strings.Contains(lower, "/markets") {
			score -= 4
		}
	case "业务自动化高风险行为":
		if strings.Contains(lower, "create_order") || strings.Contains(lower, "place_order") || strings.Contains(lower, "signed_order") || strings.Contains(lower, "submit") {
			score += 10
		}
		if strings.Contains(lower, "wallet_private_key") || strings.Contains(lower, "live trading") || strings.Contains(lower, "real funds") {
			score += 6
		}
		if strings.Contains(lower, "gamma_api") || strings.Contains(lower, "/markets") || strings.Contains(lower, "clob_api") {
			score -= 4
		}
	}
	return score
}

func structuredFindingTypedEvidenceRefs(items []plugins.Finding, fallbackEvidence []string) ([]string, []string, []string) {
	codeRefs := make([]string, 0, len(items))
	behaviorRefs := make([]string, 0, len(items))
	contextRefs := make([]string, 0, len(items))
	for _, item := range items {
		evidenceText, ok := typedEvidenceRefFromFinding(item)
		if !ok {
			for _, signal := range structuredSignalEvidenceRefsFromFinding(item) {
				codeRefs, behaviorRefs, contextRefs = appendTypedEvidenceRef(codeRefs, behaviorRefs, contextRefs, signal)
			}
			continue
		}
		codeRefs, behaviorRefs, contextRefs = appendTypedEvidenceRef(codeRefs, behaviorRefs, contextRefs, evidenceText)
		for _, signal := range structuredSignalEvidenceRefsFromFinding(item) {
			codeRefs, behaviorRefs, contextRefs = appendTypedEvidenceRef(codeRefs, behaviorRefs, contextRefs, signal)
		}
	}
	codeRefs = uniqueTypedEvidenceStrings(codeRefs)
	behaviorRefs = uniqueTypedEvidenceStrings(behaviorRefs)
	contextRefs = uniqueTypedEvidenceStrings(contextRefs)
	fallbackCodeRefs, fallbackBehaviorRefs, fallbackContextRefs := classifyFindingEvidenceRefs(fallbackEvidence)
	codeRefs = uniqueTypedEvidenceStrings(append(codeRefs, fallbackCodeRefs...))
	behaviorRefs = uniqueTypedEvidenceStrings(append(behaviorRefs, fallbackBehaviorRefs...))
	contextRefs = uniqueTypedEvidenceStrings(append(contextRefs, fallbackContextRefs...))
	if len(codeRefs) > 0 || len(behaviorRefs) > 0 || len(contextRefs) > 0 {
		return codeRefs, behaviorRefs, contextRefs
	}
	return nil, nil, nil
}

func typedEvidenceRefFromFinding(item plugins.Finding) (string, bool) {
	location := strings.TrimSpace(item.Location)
	snippet := strings.TrimSpace(item.CodeSnippet)
	description := strings.TrimSpace(item.Description)
	if isBehaviorSummaryFinding(item) {
		return behaviorSummaryEvidenceRef(snippet)
	}
	if isDocumentationContextFinding(item, location) {
		text := contextEvidenceRef(location, snippet, description)
		return text, strings.TrimSpace(text) != ""
	}
	if isConcreteFinding(item) {
		text := inlineCodeEvidenceRef(location, snippet)
		return text, strings.TrimSpace(text) != ""
	}
	return "", false
}

func structuredSignalEvidenceRefsFromFinding(item plugins.Finding) []string {
	desc := strings.TrimSpace(item.Description)
	if desc == "" {
		return nil
	}
	refs := make([]string, 0, 8)
	for _, prefix := range []string{"请求调用=", "执行调用=", "订单调用=", "授权调用=", "授权服务=", "输入来源=", "配置来源=", "来源类型=", "危险目标=", "目标服务=", "敏感字段=", "数据字段=", "缺少校验=", "授权结果=", "runtime=", "沙箱=", "探针="} {
		if value := extractStructuredSignal(desc, prefix); value != "" {
			refs = append(refs, prefix+value)
		}
	}
	return refs
}

func extractStructuredSignal(text, prefix string) string {
	idx := strings.Index(text, prefix)
	if idx < 0 {
		return ""
	}
	segment := text[idx+len(prefix):]
	for _, sep := range []string{"；", ";", "。", "\n"} {
		if cut := strings.Index(segment, sep); cut >= 0 {
			segment = segment[:cut]
			break
		}
	}
	return strings.TrimSpace(segment)
}

func behaviorSummaryEvidenceRef(snippet string) (string, bool) {
	text := strings.TrimSpace(snippet)
	if !strings.Contains(text, "关键样本") {
		return "", false
	}
	return text, true
}

func isDocumentationContextFinding(item plugins.Finding, location string) bool {
	pluginName := strings.TrimSpace(item.PluginName)
	return strings.EqualFold(pluginName, "LLM") || isDocumentationLikeText(location)
}

func firstNonEmptyLine(text string) string {
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func mergedFindingSource(items []plugins.Finding) string {
	labels := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		name := strings.TrimSpace(item.PluginName)
		if name == "" {
			name = "规则/行为综合分析"
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		labels = append(labels, name)
	}
	if len(labels) == 0 {
		return "规则/行为综合分析"
	}
	return strings.Join(labels, "+")
}

func structuredFindingSecurityVerdict(first plugins.Finding, items []plugins.Finding, refined review.Result) string {
	category := structuredFindingCategory(first)
	title := normalizeStructuredFindingTitle(first.Title)
	text := strings.ToLower(strings.Join([]string{first.Title, first.Description, first.Location, first.CodeSnippet}, " "))
	finding := review.StructuredFinding{
		RuleID:            publicRuleIDForOutput(first.RuleID),
		Title:             title,
		Severity:          normalizedStructuredFindingSeverity(first),
		Category:          category,
		AttackPath:        structuredAttackPath(category, first, refined),
		Evidence:          structuredFindingEvidence(items, nil),
		CalibrationBasis:  structuredFindingCalibrationBasisOnly(category, items, refined),
		Source:            mergedFindingSource(items),
		DeduplicatedCount: len(items),
	}
	if isDocumentationOrInternalContextText(text) {
		return "review"
	}
	if isDirectlyConfirmedFinding(finding, refined) {
		return "confirmed"
	}
	if threatIntelSemantics(reputationForFinding(finding, refined)) == "policy" {
		return "policy"
	}
	if isLikelyDocumentationOnlyFinding(finding) || isLikelyInternalDevelopmentFinding(finding) {
		return "review"
	}
	return "review"
}

func normalizedStructuredFindingSeverity(finding plugins.Finding) string {
	severity := localizeSeverity(finding.Severity)
	if fixed, ok := calibratedStructuredFindingSeverity(finding); ok {
		severity = fixed
	}
	if severityRank(severity) > severityRank(minimumSeverityForFinding(finding)) {
		return minimumSeverityForFinding(finding)
	}
	return severity
}

func minimumSeverityForFinding(finding plugins.Finding) string {
	switch normalizeStructuredFindingTitle(finding.Title) {
	case "Python 系统包安装风险":
		if text := strings.ToLower(strings.Join([]string{finding.Title, finding.Description, finding.Location, finding.CodeSnippet}, " ")); containsAny(text, []string{"dockerfile", "container", "image build", "镜像构建", "容器构建", "builder stage", "构建阶段", "ci image"}) {
			return "低风险"
		}
		if text := strings.ToLower(strings.Join([]string{finding.Title, finding.Description, finding.Location, finding.CodeSnippet}, " ")); isLocalBootstrapPythonSystemPackageText(text) {
			return "低风险"
		}
		return "中风险"
	case "仪表板未鉴权暴露":
		return "低风险"
	default:
		return "低风险"
	}
}

func calibratedStructuredFindingSeverity(finding plugins.Finding) (string, bool) {
	title := normalizeStructuredFindingTitle(finding.Title)
	text := strings.ToLower(strings.Join([]string{finding.Title, finding.Description, finding.Location, finding.CodeSnippet}, " "))
	switch title {
	case "许可证本地默认服务需复核", "授权绕过风险 - 许可证校验逻辑不闭环":
		if containsAny(text, []string{"verify_failed", "fail open", "fail-open", "return true", "continue on failure", "校验失败后继续", "失败分支放行"}) {
			return "高风险", true
		}
		if strings.Contains(text, "license_server") || strings.Contains(text, "/api/validate") || strings.Contains(text, "localhost:8080") {
			if containsAny(text, []string{"127.0.0.1", "localhost", "本地", "dev", "development", "fallback"}) {
				return "低风险", true
			}
			return "中风险", true
		}
		return "中风险", true
	case "Python 系统包安装风险":
		if strings.Contains(text, "curl ") || strings.Contains(text, "wget ") || strings.Contains(text, "| sh") || strings.Contains(text, "| bash") || strings.Contains(text, "git clone") || strings.Contains(text, "远程脚本") || strings.Contains(text, "供应链") {
			return "高风险", true
		}
		if isLocalBootstrapPythonSystemPackageText(text) {
			return "低风险", true
		}
		if containsAny(text, []string{"dockerfile", "container", "image build", "镜像构建", "容器构建", "builder stage", "构建阶段", "ci image"}) {
			return "低风险", true
		}
		return "中风险", true
	case "仪表板未鉴权暴露":
		if containsAny(text, []string{"0.0.0.0", "公网", "public network", "publicly accessible", "listen all interfaces", "监听所有网络接口"}) {
			return "高风险", true
		}
		if containsAny(text, []string{"127.0.0.1", "localhost", "本地", "loopback", "dev", "development"}) {
			return "低风险", true
		}
		return "中风险", true
	case "自动交易资金风险需复核":
		if containsAny(text, []string{"create_order", "signed_order", "place_order", "submit_order"}) {
			if containsAny(text, []string{"live trading", "real funds", "真实交易", "真实资金", "自动下单"}) {
				return "高风险", true
			}
			return "中风险", true
		}
		if containsAny(text, []string{"market query", "gamma_api", "/markets", "行情查询", "市场查询"}) {
			return "低风险", true
		}
		return "中风险", true
	case "命中黑名单目标（域名/IP）", "敏感数据外发与隐蔽通道", "外联回传", "已声明外联回传", "用户可控外联目标":
		if isDocumentationOrInternalContextText(text) {
			return "低风险", true
		}
		if strings.Contains(text, "命中黑名单目标") || strings.Contains(text, "policy blacklist") || strings.Contains(text, "策略黑名单") {
			return "中风险", true
		}
		if containsAny(text, []string{"api_key", "oem_api_key", "token", "secret", "authorization", "cookie"}) {
			return "高风险", true
		}
		if strings.Contains(text, "requests.post(target") || strings.Contains(text, "upload target") || strings.Contains(text, "用户可控外联目标") || strings.Contains(text, "allowlist") {
			return "高风险", true
		}
		if strings.Contains(text, "固定售后平台") || strings.Contains(text, "已声明外联回传") || strings.Contains(text, "after-sales.example.com") {
			return "低风险", true
		}
		return "中风险", true
	case "技能声明与实际行为一致性", "网络访问需复核", "凭据处理需复核", "命令执行需复核", "数据收集需复核", "自动交易需复核":
		if isDocumentationOrInternalContextText(text) {
			return "低风险", true
		}
		if containsAny(text, []string{"create_order", "signed_order", "live trading", "wallet_private_key", "token", "secret", "subprocess", "os.system", "exec("}) {
			return "高风险", true
		}
		if containsAny(text, []string{"license_server", "localhost", "http", "webhook", "network", "网络访问", "数据库", "sqlite"}) {
			return "中风险", true
		}
		return "低风险", true
	case "凭据暴露", "明文私钥配置风险", "明文凭据配置风险", "私钥明文存储风险", "敏感凭证暴露而无功能收益":
		if isDocumentationOrInternalContextText(text) {
			return "低风险", true
		}
		if containsAny(text, []string{"wallet_private_key", "private key", "token", "secret"}) && containsAny(text, []string{"requests.post", "webhook", "create_order", "signed_order", "real funds", "外发"}) {
			return "高风险", true
		}
		if containsAny(text, []string{"localhost", "127.0.0.1", "dev", "development", "placeholder", "empty", "示例", "sample"}) {
			return "低风险", true
		}
		return "中风险", true
	case "SSRF-内网探测", "ssrf-内网探测":
		if isDocumentationOrInternalContextText(text) {
			return "低风险", true
		}
		if containsAny(text, []string{"metadata.google", "169.254.169.254", "危险目标=metadata.google", "危险目标=10.", "危险目标=192.168.", "危险目标=172.", "危险目标=169.254."}) && containsAny(text, []string{"target_url", "来源类型=user_input", "输入来源="}) && containsAny(text, []string{"missing-guard", "缺少校验"}) {
			return "高风险", true
		}
		if containsAny(text, []string{"target_url", "来源类型=user_input", "输入来源="}) && containsAny(text, []string{"missing-guard", "缺少校验"}) {
			return "中风险", true
		}
		if containsAny(text, []string{"localhost", "127.0.0.1", "dev", "development", "allowlist", "白名单"}) {
			return "低风险", true
		}
		return "中风险", true
	case "命令执行", "远程下载执行", "下载执行", "恶意代码", "恶意代码与破坏性行为":
		if isDocumentationOrInternalContextText(text) {
			return "低风险", true
		}
		return "", false
	default:
		return "", false
	}
}

func isDocumentationOrInternalContextText(text string) bool {
	return isDocumentationLikeText(text) || isInternalDevelopmentLikeText(text)
}

func structuredFindingDeclarationVerdict(first plugins.Finding, items []plugins.Finding) string {
	title := strings.ToLower(normalizeStructuredFindingTitle(first.Title))
	desc := strings.ToLower(strings.TrimSpace(first.Description))
	joined := title + " " + desc
	if strings.Contains(joined, "未声明") || strings.Contains(joined, "声明不完整") || strings.Contains(joined, "声明外") || strings.Contains(joined, "一致性") {
		if strings.Contains(joined, "已声明") || strings.Contains(joined, "声明一致") {
			return "partially_declared"
		}
		return "undeclared"
	}
	for _, item := range items {
		text := strings.ToLower(strings.TrimSpace(item.Description + " " + item.Title))
		if strings.Contains(text, "未声明") || strings.Contains(text, "声明外") {
			return "undeclared"
		}
	}
	return "declared"
}

func structuredFindingCalibrationBasisOnly(category string, items []plugins.Finding, refined review.Result) []string {
	_, basis := structuredFindingCalibration(category, items, refined)
	return basis
}

func mitreTechniquesForFinding(ruleID, category string) []string {
	ruleID = publicRuleIDForOutput(ruleID)
	ruleID = strings.TrimSpace(ruleID)
	category = strings.TrimSpace(category)
	ruleToTechniques := map[string][]string{
		"S2-P0-001": {"TA0002 Execution", "T1059 Command and Scripting Interpreter"},
		"S2-P0-006": {"TA0011 Command and Control", "T1071 Application Layer Protocol"},
		"S2-P0-008": {"TA0006 Credential Access", "T1552 Unsecured Credentials"},
		"S2-P0-010": {"TA0004 Privilege Escalation", "T1068 Exploitation for Privilege Escalation"},
		"S2-P0-012": {"TA0002 Execution", "T1105 Ingress Tool Transfer"},
	}
	categoryToTechniques := map[string][]string{
		"恶意代码":        {"TA0002 Execution", "T1059 Command and Scripting Interpreter"},
		"后门与条件触发":     {"TA0003 Persistence", "T1546 Event Triggered Execution"},
		"外联与情报":       {"TA0011 Command and Control", "T1071 Application Layer Protocol"},
		"网络请求与SSRF":   {"TA0011 Command and Control", "T1090 Proxy"},
		"凭据访问":        {"TA0006 Credential Access", "T1552 Unsecured Credentials"},
		"沙箱逃逸与提权":     {"TA0004 Privilege Escalation", "T1068 Exploitation for Privilege Escalation"},
		"下载执行":        {"TA0002 Execution", "T1105 Ingress Tool Transfer"},
		"命令执行":        {"TA0002 Execution", "T1059 Command and Scripting Interpreter"},
		"敏感数据外发与隐蔽通道": {"TA0011 Command and Control", "T1071 Application Layer Protocol"},
		"授权与许可证校验":    {},
	}

	if items, ok := ruleToTechniques[ruleID]; ok {
		return uniqueNonEmptyStrings(items)
	}
	return uniqueNonEmptyStrings(categoryToTechniques[category])
}

package handler

import (
	"path/filepath"
	"strings"

	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
	reviewreport "skill-scanner/internal/review/report"
)

func buildCrossEvidenceChainsByCategory(findings []plugins.Finding, refined review.Result) map[string][]review.FindingChain {
	out := map[string][]review.FindingChain{}
	staticText := normalizedJoinedText(extractStaticEvidenceSnippets(findings))
	sandboxText := normalizedJoinedText(collectCrossEvidenceSandboxSignals(refined.Behavior))
	llmText := normalizedJoinedText(collectConfirmedLLMFindingTexts(refined))

	if mentionsAny(staticText, "download", "fetch", "wget", "curl", "拉取", "下载") && mentionsAny(sandboxText, "exec", "execute", "subprocess", "运行", "执行") {
		appendCrossEvidenceChain(out, []string{"下载执行", "命令执行", "恶意代码"}, buildCrossEvidenceChain("跨证据关联: 静态发现下载行为，沙箱发现执行行为，形成下载后执行链", "download->execute", llmText))
	}

	if mentionsAny(staticText, "credential", "token", ".env", "/etc/shadow", "凭据", "密钥") && mentionsAny(sandboxText, "http", "upload", "post", "outbound", "外联", "外发") {
		appendCrossEvidenceChain(out, []string{"外联与情报", "敏感数据外发与隐蔽通道", "凭据访问"}, buildCrossEvidenceChain("跨证据关联: 静态发现凭据/敏感读取，沙箱发现外联发送，形成敏感数据外发链", "sensitive_read->outbound", llmText))
	}

	for category, chains := range out {
		out[category] = dedupeFindingChains(chains)
	}
	return out
}

func normalizedJoinedText(items []string) string {
	return strings.ToLower(strings.Join(items, " \n "))
}

func collectCrossEvidenceSandboxSignals(behavior review.BehaviorProfile) []string {
	out := make([]string, 0, len(behavior.DownloadIOCs)+len(behavior.ExecuteIOCs)+len(behavior.OutboundIOCs)+len(behavior.CredentialIOCs))
	out = append(out, behavior.DownloadIOCs...)
	out = append(out, behavior.ExecuteIOCs...)
	out = append(out, behavior.OutboundIOCs...)
	out = append(out, behavior.CredentialIOCs...)
	return out
}

func buildCrossEvidenceChain(summary, path, llmText string) review.FindingChain {
	chain := review.FindingChain{Kind: "evidence_link", Summary: summary, Source: "static+sandbox+llm", Path: path}
	if mentionsAny(llmText, "confirmed", "确认", "真实风险") {
		chain.Summary += "（LLM 复核已确认）"
	}
	return chain
}

func appendCrossEvidenceChain(out map[string][]review.FindingChain, categories []string, chain review.FindingChain) {
	for _, category := range categories {
		out[category] = append(out[category], chain)
	}
}

func extractStaticEvidenceSnippets(findings []plugins.Finding) []string {
	out := make([]string, 0, len(findings)*2)
	for _, finding := range findings {
		plugin := strings.ToLower(strings.TrimSpace(finding.PluginName))
		if plugin == "behaviorguard" || plugin == "threatintel" {
			continue
		}
		if text := strings.TrimSpace(finding.Description); text != "" {
			out = append(out, text)
		}
		if text := strings.TrimSpace(finding.CodeSnippet); text != "" {
			out = append(out, text)
		}
	}
	return out
}

func collectConfirmedLLMFindingTexts(refined review.Result) []string {
	ctx := newReviewedFindingContext(refined)
	out := make([]string, 0, len(refined.StructuredFindings))
	for _, finding := range refined.StructuredFindings {
		v := ctx.finalVerdict(finding.ID)
		if normalizedReviewVerdict(v.Verdict) != "confirmed" {
			continue
		}
		out = append(out, finding.Title, finding.Category, finding.AttackPath, v.Reason)
	}
	return out
}

func mentionsAny(text string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(text, strings.ToLower(strings.TrimSpace(kw))) {
			return true
		}
	}
	return false
}

func buildObfuscationFindingChainsByCategory(items []review.ObfuscationEvidence) map[string][]review.FindingChain {
	if len(items) == 0 {
		return nil
	}
	out := make(map[string][]review.FindingChain)
	for _, item := range items {
		for _, category := range []string{"命令执行", "外联与情报", "凭据访问", "反分析/逃逸"} {
			for _, chain := range obfuscationFindingChains(category, item) {
				out[category] = append(out[category], chain)
			}
		}
	}
	for category, chains := range out {
		out[category] = dedupeFindingChains(chains)
	}
	return out
}

func obfuscationFindingChains(category string, item review.ObfuscationEvidence) []review.FindingChain {
	signals := filterRelevantDataFlowSignals(category, item.DataFlowSignals)
	if len(signals) == 0 {
		return nil
	}
	pathLabel := filepath.ToSlash(strings.TrimSpace(item.Path))
	decodedPreview := summarizeDecodedPreview(item.DecodedText)
	out := make([]review.FindingChain, 0, len(signals))
	for _, signal := range signals {
		signal = strings.TrimSpace(signal)
		if signal == "" {
			continue
		}
		summary := renderDataFlowNarrative(pathLabel, decodedPreview, []string{signal})
		if summary == "" {
			summary = signal
		}
		out = append(out, review.FindingChain{
			Kind:    dataFlowSignalKind(signal),
			Summary: summary,
			Source:  signal,
			Path:    pathLabel,
		})
	}
	return out
}

func dataFlowSignalKind(signal string) string {
	signal = strings.TrimSpace(signal)
	switch {
	case strings.Contains(signal, "命令构造链"):
		return "obfuscation_command_flow"
	case strings.Contains(signal, "网络链"):
		return "obfuscation_network_flow"
	case strings.Contains(signal, "执行链"):
		return "obfuscation_exec_flow"
	default:
		return "obfuscation_flow"
	}
}

func chainSourcePath(source string) string {
	source = strings.TrimSpace(source)
	if source == "" {
		return ""
	}
	if p, _, ok := parseSourceLocation(source); ok {
		return p
	}
	if idx := strings.Index(source, ":"); idx > 0 {
		return strings.TrimSpace(source[:idx])
	}
	return source
}

func dedupeFindingChains(items []review.FindingChain) []review.FindingChain {
	if len(items) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]review.FindingChain, 0, len(items))
	for _, item := range items {
		key := strings.TrimSpace(item.Kind) + "\x00" + strings.TrimSpace(item.Summary) + "\x00" + strings.TrimSpace(item.Source) + "\x00" + strings.TrimSpace(item.Path)
		if key == "\x00\x00" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func renderFindingChainsForVulnBlock(items []review.FindingChain) string {
	return reviewreport.RenderFindingChains(items)
}

func appendObfuscationEvidence(existing []string, items []plugins.Finding, category string, obfuscation []review.ObfuscationEvidence) []string {
	if len(items) == 0 || len(obfuscation) == 0 {
		return existing
	}
	seen := make(map[string]struct{}, len(existing))
	out := append([]string{}, existing...)
	for _, item := range items {
		path, _, ok := parseSourceLocation(item.Location)
		if !ok {
			continue
		}
		for _, entry := range matchingObfuscationEvidence(path, category, obfuscation) {
			if _, exists := seen[entry]; exists {
				continue
			}
			seen[entry] = struct{}{}
			out = append(out, entry)
		}
	}
	return out
}

func matchingObfuscationEvidence(path string, category string, items []review.ObfuscationEvidence) []string {
	path = filepath.ToSlash(strings.TrimSpace(path))
	base := strings.TrimSpace(filepath.Base(path))
	if path == "" && base == "" {
		return nil
	}
	out := make([]string, 0, 2)
	for _, item := range items {
		candidate := filepath.ToSlash(strings.TrimSpace(item.Path))
		candidateBase := strings.TrimSpace(filepath.Base(candidate))
		if candidate == "" {
			continue
		}
		if candidate != path && candidateBase != base {
			continue
		}
		filtered := filterRelevantDataFlowSignals(category, item.DataFlowSignals)
		item.DataFlowSignals = filtered
		if line := renderObfuscationEvidenceLine(item); line != "" {
			out = append(out, line)
		}
	}
	return out
}

func filterRelevantDataFlowSignals(category string, signals []string) []string {
	if len(signals) == 0 {
		return nil
	}
	relevant := make([]string, 0, len(signals))
	for _, signal := range signals {
		signal = strings.TrimSpace(signal)
		if signal == "" {
			continue
		}
		if isRelevantDataFlowSignal(category, signal) {
			relevant = append(relevant, signal)
		}
	}
	return uniqueStrings(relevant)
}

func isRelevantDataFlowSignal(category, signal string) bool {
	signal = strings.TrimSpace(signal)
	switch category {
	case "命令执行":
		return strings.Contains(signal, "执行链") || strings.Contains(signal, "命令构造链")
	case "外联与情报":
		return strings.Contains(signal, "网络链")
	case "凭据访问":
		return strings.Contains(signal, "网络链") || strings.Contains(signal, "执行链")
	case "反分析/逃逸":
		return strings.Contains(signal, "执行链")
	default:
		return true
	}
}

func renderObfuscationEvidenceLine(item review.ObfuscationEvidence) string {
	parts := make([]string, 0, 4)
	pathLabel := defaultIfEmpty(strings.TrimSpace(item.Path), "unknown")
	decodedPreview := summarizeDecodedPreview(item.DecodedText)
	if v := strings.TrimSpace(item.Summary); v != "" {
		parts = append(parts, "摘要: "+v)
	}
	if v := strings.TrimSpace(item.Technique); v != "" {
		parts = append(parts, "方式: "+v)
	}
	if v := strings.TrimSpace(item.DecodedText); v != "" {
		parts = append(parts, "还原: "+v)
	}
	if len(item.DataFlowSignals) > 0 {
		parts = append(parts, "结论: "+renderDataFlowNarrative(pathLabel, decodedPreview, item.DataFlowSignals))
	}
	if len(parts) == 0 {
		return ""
	}
	return "混淆解析证据 / " + pathLabel + " / " + strings.Join(parts, "；")
}

func renderDataFlowNarrative(pathLabel, decodedPreview string, signals []string) string {
	if len(signals) == 0 {
		return ""
	}
	clauses := make([]string, 0, len(signals))
	prefix := "文件 " + pathLabel
	if decodedPreview != "" {
		prefix += " 中恢复出的内容“" + decodedPreview + "”"
	} else {
		prefix += " 中恢复出的内容"
	}
	for _, signal := range signals {
		signal = strings.TrimSpace(signal)
		switch {
		case strings.Contains(signal, "解码变量疑似流向执行链"):
			clauses = append(clauses, prefix+"经变量传播后进入执行入口")
		case strings.Contains(signal, "解码变量疑似流向网络链"):
			clauses = append(clauses, prefix+"经变量传播后进入网络请求入口")
		case strings.Contains(signal, "解码变量疑似流向命令构造链"):
			clauses = append(clauses, prefix+"经变量传播后参与命令构造")
		case strings.Contains(signal, "解码结果疑似流向执行链"):
			clauses = append(clauses, prefix+"与执行入口同时出现")
		case strings.Contains(signal, "解码结果疑似流向网络链"):
			clauses = append(clauses, prefix+"与网络请求入口同时出现")
		case strings.Contains(signal, "解码结果疑似流向命令构造链"):
			clauses = append(clauses, prefix+"与命令构造片段同时出现")
		default:
			clauses = append(clauses, signal)
		}
	}
	clauses = uniqueStrings(clauses)
	if len(clauses) == 0 {
		return ""
	}
	return strings.Join(clauses, "；")
}

func summarizeDecodedPreview(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	runes := []rune(text)
	if len(runes) > 48 {
		return string(runes[:48]) + "..."
	}
	return text
}

func buildSourceContextIndex(root string, files []evaluator.SourceFile) map[string][]string {
	return reviewreport.BuildSourceContextIndex(root, files, displayRelPath)
}

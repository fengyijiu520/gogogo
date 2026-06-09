package report

import (
	"fmt"
	"html"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func ResolveSkillDescription(formDescription, scanPath string) string {
	if strings.TrimSpace(formDescription) != "" {
		return strings.TrimSpace(formDescription)
	}
	if desc := ExtractSkillDeclaration(scanPath); desc != "" {
		return desc
	}
	return ""
}

func ExtractSkillDeclaration(scanPath string) string {
	type candidate struct {
		path     string
		priority int
	}
	var candidates []candidate
	_ = filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || strings.ToLower(filepath.Ext(path)) != ".md" {
			return nil
		}
		base := strings.ToLower(filepath.Base(path))
		priority := 3
		switch base {
		case "skill.md":
			priority = 0
		case "readme.md":
			priority = 1
		case "description.md", "manifest.md":
			priority = 2
		}
		candidates = append(candidates, candidate{path: path, priority: priority})
		return nil
	})
	if len(candidates) == 0 {
		return ""
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].priority != candidates[j].priority {
			return candidates[i].priority < candidates[j].priority
		}
		return candidates[i].path < candidates[j].path
	})
	parts := make([]string, 0, 3)
	for _, c := range candidates {
		if len(parts) >= 3 {
			break
		}
		data, err := os.ReadFile(c.path)
		if err != nil {
			continue
		}
		text := strings.TrimSpace(string(data))
		if text == "" {
			continue
		}
		if len(text) > 4000 {
			text = text[:4000]
		}
		parts = append(parts, fmt.Sprintf("%s:\n%s", filepath.Base(c.path), text))
	}
	return strings.Join(parts, "\n\n")
}

func BuildSourceContextIndex(root string, files []evaluator.SourceFile, displayRelPath func(root, path string) string) map[string][]string {
	if len(files) == 0 {
		return nil
	}
	index := make(map[string][]string, len(files)*2)
	for _, file := range files {
		lines := strings.Split(strings.ReplaceAll(file.Content, "\r\n", "\n"), "\n")
		fullPath := normalizeEvidencePath(file.Path)
		if fullPath != "" {
			index[fullPath] = lines
		}
		relPath := normalizeEvidencePath(displayRelPath(root, file.Path))
		if relPath != "" {
			index[relPath] = lines
		}
	}
	return index
}

func StructuredFindingEvidence(items []plugins.Finding, sourceIndex map[string][]string, limit int) []string {
	strategy := selectEvidenceStrategy(items)
	codeEvidence := make([]string, 0, len(items)*2)
	documentationEvidence := make([]string, 0, len(items))
	miscEvidence := make([]string, 0, len(items)*2)
	seen := map[string]bool{}
	codeWindows := make([]codeEvidenceWindow, 0, len(items))
	behaviorAnchors := map[string]codeEvidenceWindow{}
	add := func(target *[]string, value string) {
		value = strings.TrimSpace(value)
		key := evidenceDedupKey(value)
		if value == "" || key == "" || seen[key] {
			return
		}
		seen[key] = true
		*target = append(*target, value)
	}
	for _, item := range items {
		if strategyBehaviorLike(strategy) {
			for _, anchor := range buildBehaviorSourceAnchors(item, sourceIndex, strategy) {
				key := anchor.path + ":" + strconv.Itoa(anchor.start) + ":" + strconv.Itoa(anchor.end)
				if existing, ok := behaviorAnchors[key]; ok {
					mergeIntoCodeEvidenceWindow(&existing, anchor)
					behaviorAnchors[key] = existing
					continue
				}
				behaviorAnchors[key] = anchor
			}
		}
		if window, ok := newCodeEvidenceWindow(item, sourceIndex); ok {
			codeWindows = append(codeWindows, window)
			continue
		}
		if strings.TrimSpace(item.Location) != "" {
			if isDocumentationEvidencePath(item.Location) {
				add(&documentationEvidence, "位置: "+item.Location)
			} else {
				add(&miscEvidence, "位置: "+item.Location)
			}
		}
		if strings.TrimSpace(item.CodeSnippet) != "" {
			if isDocumentationEvidencePath(item.Location) {
				add(&documentationEvidence, "片段: "+item.CodeSnippet)
			} else {
				add(&miscEvidence, "片段: "+item.CodeSnippet)
			}
		} else {
			if isDocumentationEvidencePath(item.Location) {
				add(&documentationEvidence, "说明: "+item.Description)
			} else {
				add(&miscEvidence, "说明: "+item.Description)
			}
		}
	}
	for _, anchor := range behaviorAnchors {
		codeWindows = append(codeWindows, anchor)
	}
	for _, block := range mergeCodeEvidenceWindows(expandCodeEvidenceWindows(codeWindows, sourceIndex)) {
		if isDocumentationEvidencePath(block.path) {
			add(&documentationEvidence, renderMergedCodeEvidence(block))
		} else {
			add(&codeEvidence, renderMergedCodeEvidence(block))
		}
	}
	evidence := append([]string{}, codeEvidence...)
	evidence = append(evidence, rankMiscEvidence(miscEvidence)...)
	evidence = append(evidence, rankMiscEvidence(documentationEvidence)...)
	filtered := filterEvidenceByStrategy(evidence, strategy)
	if len(filtered) > 0 {
		evidence = rankEvidenceByStrategy(filtered, strategy)
	} else {
		evidence = rankEvidenceByStrategy(evidence, strategy)
	}
	if limit > 0 && len(evidence) > limit {
		return append([]string{}, evidence[:limit]...)
	}
	return evidence
}

type evidenceStrategy string

var evidencePathLineSuffixRe = regexp.MustCompile(`^(.+?):\d+(?:-\d+)?$`)

const (
	evidenceStrategyDefault         evidenceStrategy = "default"
	evidenceStrategyLicense         evidenceStrategy = "license"
	evidenceStrategyOutbound        evidenceStrategy = "outbound"
	evidenceStrategyDownloadExecute evidenceStrategy = "download-execute"
	evidenceStrategyExecute         evidenceStrategy = "execute"
	evidenceStrategyCredential      evidenceStrategy = "credential"
	evidenceStrategyPersistence     evidenceStrategy = "persistence"
	evidenceStrategyPrivilege       evidenceStrategy = "privilege"
	evidenceStrategyEvasion         evidenceStrategy = "evasion"
	evidenceStrategyCollection      evidenceStrategy = "collection"
	evidenceStrategyFileIO          evidenceStrategy = "file-io"
)

func selectEvidenceStrategy(items []plugins.Finding) evidenceStrategy {
	textParts := make([]string, 0, len(items)*3)
	titleParts := make([]string, 0, len(items)*2)
	for _, item := range items {
		textParts = append(textParts, item.RuleID, item.Title, item.Description)
		titleParts = append(titleParts, item.RuleID, item.Title)
	}
	titleText := strings.ToLower(strings.Join(titleParts, " "))
	text := strings.ToLower(strings.Join(textParts, " "))
	switch {
	case containsAny(titleText, "许可证验证配置缺陷", "授权绕过风险 - 许可证校验逻辑不闭环", "license", "licence", "许可证", "授权校验"):
		return evidenceStrategyLicense
	case containsAny(titleText, "敏感数据外发与隐蔽通道", "外联与情报", "未声明外联", "外发", "outbound", "exfiltration"):
		return evidenceStrategyOutbound
	case containsAny(titleText, "下载执行", "自更新与远程下载执行", "远程下载执行", "download", "ingress tool transfer"):
		return evidenceStrategyDownloadExecute
	case containsAny(titleText, "命令执行", "exec", "subprocess", "shell", "command"):
		return evidenceStrategyExecute
	case containsAny(titleText, "凭据访问", "credential", "token", "secret", "密钥", "口令"):
		return evidenceStrategyCredential
	case containsAny(titleText, "持久化", "persistence", "cron", "自启动", "启动项"):
		return evidenceStrategyPersistence
	case containsAny(titleText, "提权", "privilege", "privesc", "sudo", "setuid"):
		return evidenceStrategyPrivilege
	case containsAny(titleText, "沙箱逃逸", "反分析", "防御规避", "evasion", "sandbox", "anti-analysis"):
		return evidenceStrategyEvasion
	case containsAny(titleText, "数据收集", "收集打包", "collection", "archive", "dump"):
		return evidenceStrategyCollection
	case containsAny(titleText, "文件读写", "文件落地", "落地", "drop", "write file"):
		return evidenceStrategyFileIO
	case containsAny(text, "许可证验证配置缺陷", "授权绕过风险 - 许可证校验逻辑不闭环", "license", "licence", "许可证", "授权校验"):
		return evidenceStrategyLicense
	case containsAny(text, "敏感数据外发与隐蔽通道", "外联与情报", "未声明外联", "外发", "outbound", "exfiltration"):
		return evidenceStrategyOutbound
	case containsAny(text, "下载执行", "自更新与远程下载执行", "远程下载执行", "download", "ingress tool transfer"):
		return evidenceStrategyDownloadExecute
	case containsAny(text, "命令执行", "exec", "subprocess", "shell", "command"):
		return evidenceStrategyExecute
	case containsAny(text, "凭据访问", "credential", "token", "secret", "密钥", "口令"):
		return evidenceStrategyCredential
	case containsAny(text, "持久化", "persistence", "cron", "自启动", "启动项"):
		return evidenceStrategyPersistence
	case containsAny(text, "提权", "privilege", "privesc", "sudo", "setuid"):
		return evidenceStrategyPrivilege
	case containsAny(text, "沙箱逃逸", "反分析", "防御规避", "evasion", "sandbox", "anti-analysis"):
		return evidenceStrategyEvasion
	case containsAny(text, "数据收集", "收集打包", "collection", "archive", "dump"):
		return evidenceStrategyCollection
	case containsAny(text, "文件读写", "文件落地", "落地", "drop", "write file"):
		return evidenceStrategyFileIO
	default:
		return evidenceStrategyDefault
	}
}

func strategyBehaviorLike(strategy evidenceStrategy) bool {
	switch strategy {
	case evidenceStrategyOutbound, evidenceStrategyDownloadExecute, evidenceStrategyExecute, evidenceStrategyCredential, evidenceStrategyPersistence, evidenceStrategyPrivilege, evidenceStrategyEvasion, evidenceStrategyCollection, evidenceStrategyFileIO:
		return true
	default:
		return false
	}
}

func filterEvidenceByStrategy(evidence []string, strategy evidenceStrategy) []string {
	if strategy == evidenceStrategyDefault || len(evidence) == 0 {
		return evidence
	}
	filtered := make([]string, 0, len(evidence))
	for _, item := range evidence {
		text := strings.ToLower(strings.TrimSpace(item))
		switch strategy {
		case evidenceStrategyLicense:
			if containsAny(text,
				"license", "licence", "许可证", "授权", "license_server", "pro_license_key", "validate_pro_license",
				"localhost:8080", "/api/validate", "verify_failed", "fail open", "bypass", "绕过",
			) {
				filtered = append(filtered, item)
			}
		case evidenceStrategyOutbound:
			if containsAny(text,
				"requests.get", "requests.post", "fetch(", "axios", "http://", "https://", "webhook", "post(", "get(",
				"gamma-api", "clob", "外联", "外发", "行为证据摘要", "c2信标",
			) && !containsAny(text,
				"balanceof", "decimals().call", "usdc balance", "heartbeat", "failed to fetch usdc balance",
				"license_server", "pro_license_key", "validate_pro_license", "/api/validate",
			) {
				filtered = append(filtered, item)
			}
		case evidenceStrategyDownloadExecute:
			if containsAny(text,
				"curl", "wget", "download", "requests.get", "fetch(", "git clone", "pip install", "npm install",
				"exec(", "exec.command", "subprocess", "os.system", "bash", "sh ", "python3", "行为证据摘要", "下载后执行", "远程下载执行",
			) {
				filtered = append(filtered, item)
			}
		case evidenceStrategyExecute:
			if containsAny(text,
				"exec(", "exec.command", "subprocess", "os.system", "shell", "sh -c", "bash -c", "行为证据摘要", "下载后执行", "执行",
			) {
				filtered = append(filtered, item)
			}
		case evidenceStrategyCredential:
			if containsAny(text,
				"token", "secret", "password", "private_key", "api_secret", "passphrase", ".env", ".netrc", "credential", "api key", "密钥", "凭据", "行为证据摘要",
			) {
				filtered = append(filtered, item)
			}
		case evidenceStrategyPersistence:
			if containsAny(text,
				"cron", "crontab", "systemd", "systemctl", "launchctl", "startup", "autorun", "@reboot", "持久化", "自启动", "行为证据摘要",
			) {
				filtered = append(filtered, item)
			}
		case evidenceStrategyPrivilege:
			if containsAny(text,
				"sudo", "setuid", "setgid", "chmod 4777", "chmod +s", "privilege", "privesc", "提权", "docker.sock", "行为证据摘要",
			) {
				filtered = append(filtered, item)
			}
		case evidenceStrategyEvasion:
			if containsAny(text,
				"sandbox", "vm", "virtualbox", "vmware", "debugger", "sleep", "evasion", "anti-analysis", "防御规避", "反分析", "沙箱逃逸", "行为证据摘要",
			) {
				filtered = append(filtered, item)
			}
		case evidenceStrategyCollection:
			if containsAny(text,
				"zip", "tar", "archive", "shutil.make_archive", "os.walk", "glob", "dump", "collect", "收集", "打包", "行为证据摘要",
			) {
				filtered = append(filtered, item)
			}
		case evidenceStrategyFileIO:
			if containsAny(text,
				"open(", ".write(", "writefile", "os.write", "shutil.copy", "tempfile", "落地", "写入", "文件", "行为证据摘要",
			) {
				filtered = append(filtered, item)
			}
		}
	}
	return filtered
}

func buildBehaviorSourceAnchors(item plugins.Finding, sourceIndex map[string][]string, strategy evidenceStrategy) []codeEvidenceWindow {
	if len(sourceIndex) == 0 || !isBehaviorSummaryItem(item) {
		return nil
	}
	keywords := behaviorAnchorKeywords(item, strategy)
	if len(keywords) == 0 {
		return nil
	}
	paths := preferredSourceIndexPaths(sourceIndex)
	codeAnchors := make([]codeEvidenceWindow, 0, 4)
	docAnchors := make([]codeEvidenceWindow, 0, 2)
	for _, path := range paths {
		lines := sourceIndex[path]
		if len(lines) == 0 || strings.EqualFold(filepath.Base(path), ".scan-cache.json") {
			continue
		}
		for lineNo, line := range lines {
			if !containsAny(strings.ToLower(line), keywords...) {
				continue
			}
			if evidenceLineExcludedByStrategy(line, strategy) {
				continue
			}
			if window, ok := buildWindowFromSourceIndex(path, lineNo+1, sourceIndex); ok {
				if isDocumentationEvidencePath(path) {
					docAnchors = append(docAnchors, window)
				} else {
					codeAnchors = append(codeAnchors, window)
				}
			}
		}
	}
	if len(codeAnchors) > 0 {
		return mergeCodeEvidenceWindows(codeAnchors)
	}
	return mergeCodeEvidenceWindows(docAnchors)
}

func evidenceLineExcludedByStrategy(line string, strategy evidenceStrategy) bool {
	text := strings.ToLower(strings.TrimSpace(line))
	switch strategy {
	case evidenceStrategyOutbound:
		return containsAny(text,
			"balanceof", "decimals().call", "usdc balance", "failed to fetch usdc balance",
			"license_server", "pro_license_key", "validate_pro_license", "/api/validate",
		)
	default:
		return false
	}
}

func IsDocumentationEvidencePath(path string) bool {
	path = strings.TrimSpace(path)
	if matched := evidencePathLineSuffixRe.FindStringSubmatch(path); len(matched) == 2 {
		path = matched[1]
	}
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".md", ".markdown", ".rst", ".txt", ".html", ".htm":
		return true
	default:
		return false
	}
}

func isDocumentationEvidencePath(path string) bool {
	return IsDocumentationEvidencePath(path)
}

func preferredSourceIndexPaths(sourceIndex map[string][]string) []string {
	if len(sourceIndex) == 0 {
		return nil
	}
	paths := make([]string, 0, len(sourceIndex))
	for path := range sourceIndex {
		if strings.TrimSpace(path) == "" {
			continue
		}
		paths = append(paths, path)
	}
	sort.Slice(paths, func(i, j int) bool {
		absI := filepath.IsAbs(paths[i])
		absJ := filepath.IsAbs(paths[j])
		if absI != absJ {
			return !absI
		}
		if len(paths[i]) != len(paths[j]) {
			return len(paths[i]) < len(paths[j])
		}
		return paths[i] < paths[j]
	})
	seen := make(map[string]struct{}, len(paths))
	filtered := make([]string, 0, len(paths))
	for _, path := range paths {
		norm := normalizeEvidencePath(path)
		if _, ok := seen[norm]; ok {
			continue
		}
		seen[norm] = struct{}{}
		filtered = append(filtered, path)
	}
	return filtered
}

func isBehaviorSummaryItem(item plugins.Finding) bool {
	plugin := strings.EqualFold(strings.TrimSpace(item.PluginName), "BehaviorGuard")
	location := strings.Contains(strings.ToLower(strings.TrimSpace(item.Location)), ".scan-cache.json")
	summary := strings.Contains(strings.TrimSpace(item.CodeSnippet), "行为证据摘要:")
	return plugin || location || summary
}

func behaviorAnchorKeywords(item plugins.Finding, strategy evidenceStrategy) []string {
	base := strings.ToLower(strings.Join([]string{item.RuleID, item.Title, item.Description, item.CodeSnippet}, " "))
	keywords := []string{}
	add := func(values ...string) {
		for _, value := range values {
			value = strings.ToLower(strings.TrimSpace(value))
			if value == "" || containsAny(strings.Join(keywords, "\n"), value) {
				continue
			}
			keywords = append(keywords, value)
		}
	}
	switch strategy {
	case evidenceStrategyOutbound:
		add("requests.post", "requests.get", "fetch(", "axios", "webhook", "upload", "post(", "get(")
	case evidenceStrategyDownloadExecute:
		add("curl", "wget", "download", "requests.get", "fetch(", "git clone", "pip install", "npm install", "subprocess", "os.system", "exec(")
	case evidenceStrategyExecute:
		add("exec.command", "subprocess", "os.system", "shell", "sh -c", "bash -c", "spawn(", "popen(")
	case evidenceStrategyCredential:
		add("token", "secret", "password", "private_key", "api_secret", "passphrase", ".env", ".netrc", "api_key", "apikey", "credential")
	case evidenceStrategyPersistence:
		add("cron", "crontab", "systemd", "systemctl", "launchctl", "startup", "autorun", "@reboot")
	case evidenceStrategyPrivilege:
		add("sudo", "setuid", "setgid", "chmod 4777", "chmod +s", "privilege", "docker.sock")
	case evidenceStrategyEvasion:
		add("sandbox", "virtualbox", "vmware", "debugger", "sleep", "evasion", "anti-analysis")
	case evidenceStrategyCollection:
		add("zip", "tar", "archive", "shutil.make_archive", "os.walk", "glob", "dump", "collect")
	case evidenceStrategyFileIO:
		add("open(", ".write(", "writefile", "os.write", "shutil.copy", "tempfile")
	}
	if containsAny(base, "下载后执行", "download") {
		add("curl", "wget", "download", "fetch(")
	}
	if containsAny(base, "外联", "外发", "post", "outbound") {
		add("requests.post", "webhook")
	}
	if containsAny(base, "凭据", "密钥", "credential", "token") {
		add("token", "secret", "password", "private_key", "api_secret", "passphrase", ".env", ".netrc")
	}
	return keywords
}

func containsAny(text string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(text, strings.ToLower(strings.TrimSpace(kw))) {
			return true
		}
	}
	return false
}

func ParseSourceLocation(location string) (string, int, bool) {
	location = strings.TrimSpace(location)
	location = strings.TrimSpace(strings.TrimPrefix(location, "[sandbox-runtime]"))
	if idx := strings.Index(location, "|"); idx >= 0 {
		location = strings.TrimSpace(location[:idx])
	}
	if location == "" {
		return "", 0, false
	}
	lastColon := strings.LastIndex(location, ":")
	if lastColon <= 0 || lastColon == len(location)-1 {
		return "", 0, false
	}
	lineText := strings.TrimSpace(location[lastColon+1:])
	lineNumber, err := strconv.Atoi(lineText)
	if err != nil || lineNumber <= 0 {
		return "", 0, false
	}
	path := strings.TrimSpace(location[:lastColon])
	if path == "" {
		return "", 0, false
	}
	return normalizeEvidencePath(path), lineNumber, true
}

func SourcePillClass(item string) string {
	switch strings.TrimSpace(item) {
	case "静态基线":
		return "pill-static"
	case "动态行为":
		return "pill-dynamic"
	case "规则静态", "语义静态", "LLM静态":
		return "pill-static"
	case "沙箱动态", "情报关联":
		return "pill-dynamic"
	case "已验证", "二次验证":
		return "pill-verified"
	case "复核疑似误报":
		return "pill-fp"
	case "待验证", "需人工复核":
		return "pill-review"
	default:
		return ""
	}
}

func SplitCodeEvidenceLabelAndBody(item string) (string, string) {
	item = strings.TrimSpace(item)
	if item == "" {
		return "代码证据", ""
	}
	lines := strings.Split(item, "\n")
	for idx, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if LooksLikeSourceLocator(line) {
			body := strings.TrimSpace(strings.Join(lines[idx+1:], "\n"))
			if body == "" {
				body = item
			}
			return "代码证据 / " + ShortenEvidenceLabel(line), body
		}
		break
	}
	return "代码证据", item
}

func InferEvidenceLabel(item string) string {
	label, _ := SplitCodeEvidenceLabelAndBody(item)
	return label
}

func LooksLikeSourceLocator(line string) bool {
	lower := strings.ToLower(strings.TrimSpace(line))
	if lower == "" {
		return false
	}
	if strings.Contains(lower, "/") || strings.Contains(lower, "\\") {
		return true
	}
	if strings.Contains(lower, ":") && (strings.Contains(lower, ".go") || strings.Contains(lower, ".js") || strings.Contains(lower, ".ts") || strings.Contains(lower, ".py") || strings.Contains(lower, ".yaml") || strings.Contains(lower, ".yml") || strings.Contains(lower, ".json") || strings.Contains(lower, ".md")) {
		return true
	}
	return false
}

func ShortenEvidenceLabel(line string) string {
	return strings.TrimSpace(line)
}

func RenderSourceBadgeStrip(items []string) string {
	cleaned := uniqueNonEmptyStrings(items)
	if len(cleaned) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("<div class=\"source-strip\">")
	for _, item := range cleaned {
		b.WriteString("<span class=\"pill " + html.EscapeString(SourcePillClass(item)) + "\">" + html.EscapeString(item) + "</span>")
	}
	b.WriteString("</div>")
	return b.String()
}

func BuildVulnerabilityBlocks(findings []review.StructuredFinding) []review.VulnerabilityBlock {
	blocks := make([]review.VulnerabilityBlock, 0, len(findings))
	for _, finding := range findings {
		var b strings.Builder
		b.WriteString("<vuln>\n")
		writeVulnTag(&b, "id", finding.ID)
		writeVulnTag(&b, "title", finding.Title)
		writeVulnTag(&b, "desc", finding.AttackPath)
		writeVulnTag(&b, "risk_type", finding.Category)
		writeVulnTag(&b, "level", finding.Severity)
		writeVulnTag(&b, "confidence", defaultIfEmpty(strings.TrimSpace(finding.Confidence), "待复核"))
		writeVulnTag(&b, "rule_id", finding.RuleID)
		writeVulnTag(&b, "source", finding.Source)
		writeVulnTag(&b, "evidence", strings.Join(finding.Evidence, "；"))
		writeVulnTag(&b, "chain_summaries", strings.Join(finding.ChainSummaries, "；"))
		writeVulnTag(&b, "chains", RenderFindingChains(finding.Chains))
		writeVulnTag(&b, "calibration_basis", strings.Join(finding.CalibrationBasis, "；"))
		writeVulnTag(&b, "false_positive_checks", strings.Join(finding.FalsePositiveChecks, "；"))
		writeVulnTag(&b, "fix", finding.ReviewGuidance)
		b.WriteString("</vuln>")
		blocks = append(blocks, review.VulnerabilityBlock{ID: finding.ID, Format: "structured-vuln-block", Content: b.String()})
	}
	return blocks
}

func FormatStructuredFindingForPrompt(finding review.StructuredFinding) string {
	lines := []string{
		"ID: " + finding.ID,
		"Rule: " + finding.RuleID + " " + finding.Title,
		"Severity: " + finding.Severity,
		"Category: " + finding.Category,
		"Confidence: " + finding.Confidence,
		"AttackPath: " + finding.AttackPath,
		"Evidence: " + strings.Join(finding.Evidence, "；"),
		"ChainSummaries: " + strings.Join(finding.ChainSummaries, "；"),
		"Calibration: " + strings.Join(finding.CalibrationBasis, "；"),
		"FalsePositiveChecks: " + strings.Join(finding.FalsePositiveChecks, "；"),
	}
	if renderedChains := RenderFindingChains(finding.Chains); renderedChains != "" {
		lines = append(lines, "Chains: "+renderedChains)
	}
	return strings.Join(lines, "\n")
}

func RenderFindingChains(items []review.FindingChain) string {
	if len(items) == 0 {
		return ""
	}
	parts := make([]string, 0, len(items))
	for _, item := range items {
		summary := strings.TrimSpace(item.Summary)
		if summary == "" {
			continue
		}
		part := strings.TrimSpace(item.Kind) + ": " + summary
		if source := strings.TrimSpace(item.Source); source != "" {
			part += " [source=" + source + "]"
		}
		if path := strings.TrimSpace(item.Path); path != "" {
			part += " [path=" + path + "]"
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, "；")
}

func writeVulnTag(b *strings.Builder, tag, value string) {
	b.WriteString("  <")
	b.WriteString(tag)
	b.WriteString(">")
	b.WriteString(escapeVulnBlockValue(value))
	b.WriteString("</")
	b.WriteString(tag)
	b.WriteString(">\n")
}

func escapeVulnBlockValue(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(value, "&", "&amp;")
	value = strings.ReplaceAll(value, "<", "&lt;")
	value = strings.ReplaceAll(value, ">", "&gt;")
	return value
}

type codeEvidenceWindow struct {
	path     string
	start    int
	end      int
	hitLines map[int]bool
	lines    map[int]string
}

func newCodeEvidenceWindow(item plugins.Finding, sourceIndex map[string][]string) (codeEvidenceWindow, bool) {
	path, line, ok := ParseSourceLocation(item.Location)
	if !ok {
		return codeEvidenceWindow{}, false
	}
	if window, ok := buildWindowFromSourceIndex(path, line, sourceIndex); ok {
		return window, true
	}
	lines := normalizeCodeSnippetLines(item.CodeSnippet)
	if len(lines) == 0 {
		return codeEvidenceWindow{}, false
	}
	window := codeEvidenceWindow{
		path:     normalizeEvidencePath(path),
		start:    line,
		end:      line + len(lines) - 1,
		hitLines: map[int]bool{line: true},
		lines:    make(map[int]string, len(lines)),
	}
	for idx, snippetLine := range lines {
		window.lines[line+idx] = snippetLine
	}
	return window, true
}

func buildWindowFromSourceIndex(path string, hitLine int, sourceIndex map[string][]string) (codeEvidenceWindow, bool) {
	if len(sourceIndex) == 0 {
		return codeEvidenceWindow{}, false
	}
	path = normalizeEvidencePath(path)
	lines, ok := sourceIndex[path]
	if !ok || hitLine <= 0 || hitLine > len(lines) {
		return codeEvidenceWindow{}, false
	}
	start := hitLine - 3
	if start < 1 {
		start = 1
	}
	end := hitLine + 3
	if end > len(lines) {
		end = len(lines)
	}
	window := codeEvidenceWindow{
		path:     path,
		start:    start,
		end:      end,
		hitLines: map[int]bool{hitLine: true},
		lines:    make(map[int]string, end-start+1),
	}
	for lineNo := start; lineNo <= end; lineNo++ {
		window.lines[lineNo] = lines[lineNo-1]
	}
	return window, true
}

func expandCodeEvidenceWindows(windows []codeEvidenceWindow, sourceIndex map[string][]string) []codeEvidenceWindow {
	if len(windows) == 0 || len(sourceIndex) == 0 {
		return windows
	}
	grouped := make(map[string][]codeEvidenceWindow)
	for _, window := range windows {
		grouped[window.path] = append(grouped[window.path], window)
	}
	expanded := make([]codeEvidenceWindow, 0, len(windows))
	for path, group := range grouped {
		lines := sourceIndex[path]
		if len(lines) == 0 {
			expanded = append(expanded, group...)
			continue
		}
		hitSet := map[int]bool{}
		for _, window := range group {
			for line := range window.hitLines {
				hitSet[line] = true
			}
		}
		changed := true
		for changed {
			changed = false
			currentHits := make([]int, 0, len(hitSet))
			for line := range hitSet {
				currentHits = append(currentHits, line)
			}
			for _, hit := range currentHits {
				start := hit - 3
				if start < 1 {
					start = 1
				}
				end := hit + 3
				if end > len(lines) {
					end = len(lines)
				}
				for _, window := range group {
					for line := range window.hitLines {
						if line >= start && line <= end && !hitSet[line] {
							hitSet[line] = true
							changed = true
						}
					}
				}
			}
		}
		allHits := make([]int, 0, len(hitSet))
		for line := range hitSet {
			allHits = append(allHits, line)
		}
		sort.Ints(allHits)
		if len(allHits) == 0 {
			expanded = append(expanded, group...)
			continue
		}
		start := allHits[0] - 3
		if start < 1 {
			start = 1
		}
		end := allHits[len(allHits)-1] + 3
		if end > len(lines) {
			end = len(lines)
		}
		window := codeEvidenceWindow{
			path:     path,
			start:    start,
			end:      end,
			hitLines: hitSet,
			lines:    make(map[int]string, end-start+1),
		}
		for lineNo := start; lineNo <= end; lineNo++ {
			window.lines[lineNo] = lines[lineNo-1]
		}
		expanded = append(expanded, window)
	}
	return expanded
}

func normalizeCodeSnippetLines(snippet string) []string {
	snippet = strings.ReplaceAll(snippet, "\r\n", "\n")
	rawLines := strings.Split(snippet, "\n")
	for len(rawLines) > 0 && strings.TrimSpace(rawLines[0]) == "" {
		rawLines = rawLines[1:]
	}
	for len(rawLines) > 0 && strings.TrimSpace(rawLines[len(rawLines)-1]) == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}
	if len(rawLines) == 0 {
		return nil
	}
	return rawLines
}

func mergeCodeEvidenceWindows(windows []codeEvidenceWindow) []codeEvidenceWindow {
	if len(windows) == 0 {
		return nil
	}
	sorted := append([]codeEvidenceWindow(nil), windows...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].path == sorted[j].path {
			if sorted[i].start == sorted[j].start {
				return sorted[i].end < sorted[j].end
			}
			return sorted[i].start < sorted[j].start
		}
		return sorted[i].path < sorted[j].path
	})
	merged := []codeEvidenceWindow{sorted[0]}
	for _, current := range sorted[1:] {
		last := &merged[len(merged)-1]
		if last.path == current.path && current.start <= last.end+1 {
			mergeIntoCodeEvidenceWindow(last, current)
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func mergeIntoCodeEvidenceWindow(dst *codeEvidenceWindow, src codeEvidenceWindow) {
	if src.start < dst.start {
		dst.start = src.start
	}
	if src.end > dst.end {
		dst.end = src.end
	}
	for line, value := range src.lines {
		if _, exists := dst.lines[line]; !exists {
			dst.lines[line] = value
		}
	}
	for line := range src.hitLines {
		dst.hitLines[line] = true
	}
}

func renderMergedCodeEvidence(window codeEvidenceWindow) string {
	lineNumbers := make([]int, 0, len(window.lines))
	for line := range window.lines {
		lineNumbers = append(lineNumbers, line)
	}
	sort.Ints(lineNumbers)
	var b strings.Builder
	b.WriteString(window.path)
	b.WriteString(":")
	b.WriteString(strconv.Itoa(window.start))
	if window.end > window.start {
		b.WriteString("-")
		b.WriteString(strconv.Itoa(window.end))
	}
	for _, line := range lineNumbers {
		marker := "  "
		if window.hitLines[line] && strings.TrimSpace(window.lines[line]) != "" {
			marker = "> "
		}
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s%4d | %s", marker, line, window.lines[line]))
	}
	return b.String()
}

func normalizeEvidencePath(path string) string {
	path = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(path), "[sandbox-runtime]"))
	if path == "" {
		return ""
	}
	if idx := strings.Index(path, "|"); idx >= 0 {
		path = strings.TrimSpace(path[:idx])
	}
	if matched := evidencePathLineSuffixRe.FindStringSubmatch(path); len(matched) == 2 {
		path = matched[1]
	}
	return filepath.ToSlash(strings.TrimSpace(path))
}

func evidenceDedupKey(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	label, body := SplitCodeEvidenceLabelAndBody(value)
	label = strings.TrimSpace(label)
	body = strings.TrimSpace(body)
	if label == "代码证据" && body != "" {
		return value
	}
	path := ""
	if idx := strings.Index(label, "/"); idx >= 0 {
		path = normalizeEvidencePath(strings.TrimSpace(label[idx+1:]))
	}
	if path == "" {
		firstLine := strings.TrimSpace(strings.Split(value, "\n")[0])
		path = normalizeEvidencePath(firstLine)
	}
	body = strings.Join(strings.Fields(body), " ")
	if path != "" && body != "" {
		return path + "\x00" + body
	}
	return value
}

func evidenceRank(value string) int {
	trimmed := strings.TrimSpace(value)
	label, body := SplitCodeEvidenceLabelAndBody(trimmed)
	joined := strings.ToLower(strings.TrimSpace(label + " " + body))
	labelPath := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(label), "代码证据 /"))
	switch {
	case strings.HasPrefix(strings.TrimSpace(label), "代码证据 /") && isDocumentationEvidencePath(labelPath) && !strings.Contains(joined, ".scan-cache.json"):
		return 1
	case strings.HasPrefix(strings.TrimSpace(label), "代码证据 /") && !strings.Contains(joined, ".scan-cache.json"):
		return 0
	case strings.HasPrefix(strings.TrimSpace(label), "代码证据 /"):
		return 2
	case strings.Contains(joined, "行为证据摘要") || strings.Contains(joined, ".scan-cache.json"):
		return 3
	case strings.HasPrefix(trimmed, "位置: ") || strings.HasPrefix(trimmed, "片段: ") || strings.HasPrefix(trimmed, "说明: "):
		return 2
	default:
		return 2
	}
}

func evidenceStrategyBoost(value string, strategy evidenceStrategy) int {
	text := strings.ToLower(strings.TrimSpace(value))
	switch strategy {
	case evidenceStrategyLicense:
		if containsAny(text, "validate_pro_license", "/api/validate", "verify_failed", "fail open", "bypass", "pro_license_key") {
			return -2
		}
		if containsAny(text, "license_server", "license", "licence", "许可证", "授权") {
			return -1
		}
	case evidenceStrategyOutbound:
		if strings.Contains(text, ".scan-cache.json") || strings.Contains(text, "行为证据摘要") {
			return 2
		}
		if containsAny(text, "requests.post", "requests.get", "fetch(", "axios", "http://", "https://", "webhook") {
			return -1
		}
	case evidenceStrategyDownloadExecute:
		if strings.Contains(text, ".scan-cache.json") || strings.Contains(text, "行为证据摘要") {
			return 2
		}
		if containsAny(text, "curl", "wget", "download", "requests.get", "fetch(", "git clone", "subprocess", "os.system", "exec(") {
			return -1
		}
	case evidenceStrategyExecute:
		if strings.Contains(text, ".scan-cache.json") || strings.Contains(text, "行为证据摘要") {
			return 2
		}
		if containsAny(text, "exec.command", "subprocess", "os.system", "shell", "sh -c", "bash -c") {
			return -1
		}
	case evidenceStrategyCredential:
		if strings.Contains(text, ".scan-cache.json") || strings.Contains(text, "行为证据摘要") {
			return 2
		}
		if containsAny(text, "token", "secret", "password", "private_key", "api_secret", "passphrase", ".env", ".netrc", "credential") {
			return -1
		}
	case evidenceStrategyPersistence:
		if strings.Contains(text, ".scan-cache.json") || strings.Contains(text, "行为证据摘要") {
			return 2
		}
		if containsAny(text, "cron", "crontab", "systemd", "systemctl", "startup", "autorun", "@reboot") {
			return -1
		}
	case evidenceStrategyPrivilege:
		if strings.Contains(text, ".scan-cache.json") || strings.Contains(text, "行为证据摘要") {
			return 2
		}
		if containsAny(text, "sudo", "setuid", "setgid", "chmod 4777", "chmod +s", "privilege", "docker.sock") {
			return -1
		}
	case evidenceStrategyEvasion:
		if strings.Contains(text, ".scan-cache.json") || strings.Contains(text, "行为证据摘要") {
			return 2
		}
		if containsAny(text, "sandbox", "virtualbox", "vmware", "debugger", "sleep", "evasion", "anti-analysis") {
			return -1
		}
	case evidenceStrategyCollection:
		if strings.Contains(text, ".scan-cache.json") || strings.Contains(text, "行为证据摘要") {
			return 2
		}
		if containsAny(text, "zip", "tar", "archive", "shutil.make_archive", "os.walk", "glob", "dump", "collect") {
			return -1
		}
	case evidenceStrategyFileIO:
		if strings.Contains(text, ".scan-cache.json") || strings.Contains(text, "行为证据摘要") {
			return 2
		}
		if containsAny(text, "open(", ".write(", "writefile", "os.write", "shutil.copy", "tempfile") {
			return -1
		}
	}
	return 0
}

func rankEvidence(items []string) []string {
	if len(items) <= 1 {
		return items
	}
	ranked := append([]string(nil), items...)
	sort.SliceStable(ranked, func(i, j int) bool {
		ri := evidenceRank(ranked[i])
		rj := evidenceRank(ranked[j])
		if ri != rj {
			return ri < rj
		}
		return ranked[i] < ranked[j]
	})
	return ranked
}

func rankEvidenceByStrategy(items []string, strategy evidenceStrategy) []string {
	if len(items) <= 1 {
		return items
	}
	ranked := append([]string(nil), items...)
	sort.SliceStable(ranked, func(i, j int) bool {
		ri := evidenceRank(ranked[i]) + evidenceStrategyBoost(ranked[i], strategy)
		rj := evidenceRank(ranked[j]) + evidenceStrategyBoost(ranked[j], strategy)
		if ri != rj {
			return ri < rj
		}
		return ranked[i] < ranked[j]
	})
	return ranked
}

func rankMiscEvidence(items []string) []string {
	return rankEvidence(items)
}

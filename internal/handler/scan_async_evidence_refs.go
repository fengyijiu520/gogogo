package handler

import (
	"os"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
	"skill-scanner/internal/config"
)

var defaultDocumentationLikeTokens = []string{"readme", "skill.md", "docs/", "examples/", "example/", "demo/", "sample/", "testdata/", "test/", "tests/", "fixture/", "fixtures/", "mock/", "mocks/", "示例", "文档"}
var defaultLocalHostTokens = []string{"localhost", "127.0.0.1", "0.0.0.0", "::1"}
var defaultInternalDevelopmentTokens = []string{"/dev/", "dev/", "/sandbox/", "sandbox/", "/local/", "local/", "staging", "debug", "development", "dev environment", "local-only", "for local testing"}
var defaultPrivateNetworkPrefixes = []string{"10.", "192.168.", "169.254.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.", "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.", "172.28.", "172.29.", "172.30.", "172.31."}

type evidenceContextConfig struct {
	DocumentationLikeTokens []string `yaml:"documentation_like_tokens"`
	LocalHostTokens         []string `yaml:"local_host_tokens"`
	InternalDevelopmentTokens []string `yaml:"internal_development_tokens"`
	PrivateNetworkPrefixes  []string `yaml:"private_network_prefixes"`
}

var evidenceContextOnce sync.Once
var documentationLikeTokens []string
var localHostTokens []string
var internalDevelopmentTokens []string
var privateNetworkPrefixes []string

func loadEvidenceContextConfig() {
	documentationLikeTokens = append([]string(nil), defaultDocumentationLikeTokens...)
	localHostTokens = append([]string(nil), defaultLocalHostTokens...)
	internalDevelopmentTokens = append([]string(nil), defaultInternalDevelopmentTokens...)
	privateNetworkPrefixes = append([]string(nil), defaultPrivateNetworkPrefixes...)
	data, err := os.ReadFile(config.EvidenceContextConfigPath())
	if err != nil || len(data) == 0 {
		return
	}
	var cfg evidenceContextConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return
	}
	if tokens := normalizeEvidenceTokens(cfg.DocumentationLikeTokens); len(tokens) > 0 {
		documentationLikeTokens = tokens
	}
	if tokens := normalizeEvidenceTokens(cfg.LocalHostTokens); len(tokens) > 0 {
		localHostTokens = tokens
	}
	if tokens := normalizeEvidenceTokens(cfg.InternalDevelopmentTokens); len(tokens) > 0 {
		internalDevelopmentTokens = tokens
	}
	if tokens := normalizeEvidenceTokens(cfg.PrivateNetworkPrefixes); len(tokens) > 0 {
		privateNetworkPrefixes = tokens
	}
}

func ensureEvidenceContextConfig() {
	evidenceContextOnce.Do(loadEvidenceContextConfig)
}

func normalizeEvidenceTokens(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.ToLower(strings.TrimSpace(item))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func classifyEvidenceRefText(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return ""
	}
	switch {
	case isBehaviorEvidenceRef(trimmed):
		return "behavior"
	case isCodeEvidenceRef(trimmed):
		return "code"
	default:
		return "context"
	}
}

func appendTypedEvidenceRef(codeRefs, behaviorRefs, contextRefs []string, text string) ([]string, []string, []string) {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return codeRefs, behaviorRefs, contextRefs
	}
	switch classifyEvidenceRefText(trimmed) {
	case "behavior":
		behaviorRefs = append(behaviorRefs, trimmed)
	case "code":
		codeRefs = append(codeRefs, trimmed)
	default:
		contextRefs = append(contextRefs, trimmed)
	}
	return codeRefs, behaviorRefs, contextRefs
}

func contextEvidenceRef(location, snippet, description string) string {
	if text := strings.TrimSpace(location); text != "" {
		return text
	}
	if text := firstNonEmptyLine(snippet); text != "" {
		return text
	}
	return firstNonEmptyLine(description)
}

func inlineCodeEvidenceRef(location, snippet string) string {
	return strings.TrimSpace(strings.TrimSpace(location) + " " + strings.TrimSpace(firstNonEmptyLine(snippet)))
}

func isDocumentationLikeText(text string) bool {
	ensureEvidenceContextConfig()
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	// 如果包含代码证据特征（文件路径+行号、代码片段等），不算纯文档
	if hasCodeEvidenceCharacteristics(lower) {
		return false
	}
	for _, token := range documentationLikeTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

// hasCodeEvidenceCharacteristics 检查文本是否包含代码证据特征
func hasCodeEvidenceCharacteristics(text string) bool {
	// 文件路径+行号模式（如 cleanup.sh:20, main.py:15-20）
	if regexp.MustCompile(`\w+\.\w+:\d+`).MatchString(text) {
		return true
	}
	// 代码片段特征
	codeIndicators := []string{
		"curl ", "wget ", "bash ", "sh ", "python ", "node ",
		"subprocess", "os.system", "exec(", "eval(",
		"import ", "require(", "from ", "def ", "func ",
		"if ", "for ", "while ", "return ",
		"http://", "https://", "ftp://",
		"chmod", "chown", "rm -", "mv ", "cp ",
		"encrypt", "decrypt", "base64",
		"password", "token", "secret", "key",
	}
	for _, indicator := range codeIndicators {
		if strings.Contains(text, indicator) {
			return true
		}
	}
	return false
}

func isPrivateOrLocalHostText(text string) bool {
	ensureEvidenceContextConfig()
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	for _, token := range localHostTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	for _, prefix := range privateNetworkPrefixes {
		if strings.Contains(lower, prefix) {
			return true
		}
	}
	return false
}

func isInternalDevelopmentLikeText(text string) bool {
	ensureEvidenceContextConfig()
	lower := strings.ToLower(strings.TrimSpace(text))
	if lower == "" {
		return false
	}
	// 如果包含代码证据特征，不算纯本地开发
	if hasCodeEvidenceCharacteristics(lower) {
		return false
	}
	for _, token := range internalDevelopmentTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	for _, token := range localHostTokens {
		if strings.Contains(lower, token) {
			return true
		}
	}
	return false
}

func uniqueTypedEvidenceStrings(items []string) []string {
	out := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		text := strings.TrimSpace(item)
		if text == "" {
			continue
		}
		key := normalizeEvidenceDedupKey(text)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, text)
	}
	return out
}

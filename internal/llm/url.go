package llm

import (
	"fmt"
	"net"
	"net/url"
	"strings"
)

func normalizeChatCompletionsURL(raw string) (string, error) {
	return normalizeProviderURL(raw, "/chat/completions")
}

func normalizeAnthropicMessagesURL(raw string) (string, error) {
	return normalizeProviderURL(raw, "/messages")
}

func normalizeProviderURL(raw, suffix string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", fmt.Errorf("llm base url is required")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("llm url is invalid")
	}
	if parsed.Scheme != "https" {
		return "", fmt.Errorf("llm url must use https")
	}
	if err := validatePublicLLMHost(parsed.Hostname()); err != nil {
		return "", err
	}
	path := strings.TrimRight(parsed.Path, "/")
	// 如果已经以 suffix 结尾，直接使用
	if strings.HasSuffix(path, suffix) {
		parsed.Path = path
		return parsed.String(), nil
	}
	// 尝试直接拼接
	parsed.Path = path + suffix
	return parsed.String(), nil
}

// normalizeProviderURLWithFallback 返回多个候选 URL，用于测试连通性时逐个尝试。
// 有些 API 提供商在标准路径前多了 /v1 或其他前缀，需要尝试多种拼接方式。
func normalizeProviderURLWithFallback(raw, suffix string) []string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return nil
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return nil
	}
	if parsed.Scheme != "https" {
		return nil
	}
	if err := validatePublicLLMHost(parsed.Hostname()); err != nil {
		return nil
	}
	path := strings.TrimRight(parsed.Path, "/")

	var candidates []string
	// 已经以 suffix 结尾
	if strings.HasSuffix(path, suffix) {
		parsed.Path = path
		return []string{parsed.String()}
	}
	// 直接拼接
	p1 := *parsed
	p1.Path = path + suffix
	candidates = append(candidates, p1.String())
	// 在 suffix 前插入 /v1（适配 /anthropic/v1/messages 等非标准路径）
	if !strings.Contains(path, "/v1") {
		p2 := *parsed
		p2.Path = path + "/v1" + suffix
		candidates = append(candidates, p2.String())
	}
	return candidates
}

func normalizeProtocol(protocol string) string {
	protocol = strings.TrimSpace(strings.ToLower(protocol))
	if protocol == "" {
		return "openai"
	}
	return protocol
}

func validatePublicLLMHost(host string) error {
	host = strings.TrimSpace(strings.TrimSuffix(host, "."))
	if host == "" {
		return fmt.Errorf("llm url host is required")
	}
	lowerHost := strings.ToLower(host)
	if lowerHost == "localhost" || strings.HasSuffix(lowerHost, ".localhost") {
		return fmt.Errorf("llm url host is not allowed")
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("llm url host is not allowed")
		}
		return nil
	}
	if !strings.Contains(host, ".") {
		return fmt.Errorf("llm url host must be a public domain")
	}
	return nil
}

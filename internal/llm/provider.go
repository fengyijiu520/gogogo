package llm

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"
)

type ProviderConfig struct {
	Provider string
	Name     string
	Protocol string
	BaseURL  string
	Model    string
	APIKey   string
}

const DeepSeekModel = "deepseek-v4-pro"

var DeepSeekProviderConfig = ProviderConfig{
	Provider: "deepseek",
	Name:     "DeepSeek",
	Protocol: "openai",
	BaseURL:  "https://api.deepseek.com/chat/completions",
	Model:    DeepSeekModel,
}

type ProviderFactory func(ProviderConfig) (Client, error)

var providerRegistry = struct {
	sync.RWMutex
	factories map[string]ProviderFactory
}{factories: map[string]ProviderFactory{}}

func RegisterProvider(name string, factory ProviderFactory) {
	name = strings.TrimSpace(strings.ToLower(name))
	if name == "" || factory == nil {
		return
	}
	providerRegistry.Lock()
	defer providerRegistry.Unlock()
	providerRegistry.factories[name] = factory
}

func NewClient(cfg ProviderConfig) (Client, error) {
	if strings.TrimSpace(cfg.BaseURL) != "" {
		return NewProtocolClient(cfg)
	}
	provider := strings.TrimSpace(strings.ToLower(cfg.Provider))
	if provider == "" {
		return nil, fmt.Errorf("llm provider is required")
	}
	providerRegistry.RLock()
	factory := providerRegistry.factories[provider]
	providerRegistry.RUnlock()
	if factory == nil {
		return nil, fmt.Errorf("unsupported llm provider: %s", provider)
	}
	return factory(cfg)
}

func NewProtocolClient(cfg ProviderConfig) (Client, error) {
	switch normalizeProtocol(cfg.Protocol) {
	case "anthropic":
		return NewAnthropicCompatibleClient(cfg)
	case "openai":
		return NewOpenAICompatibleClient(cfg)
	default:
		return nil, fmt.Errorf("unsupported llm protocol: %s", cfg.Protocol)
	}
}

// TestProvider 测试 LLM 提供商连通性。如果标准 URL 失败，会自动尝试 fallback 拼接。
// 成功时 cfg.BaseURL 会被修正为实际可用的 URL。
func TestProvider(ctx context.Context, cfg *ProviderConfig) error {
	// 先用标准方式构建客户端
	client, err := NewProtocolClient(*cfg)
	if err == nil {
		testCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		defer cancel()
		_, err = client.Complete(testCtx, "你是连通性测试助手。", "只回复一个 JSON 对象：{\"ok\":true}。")
		if err == nil {
			return nil
		}
	}
	// 标准 URL 失败，尝试 fallback 拼接（适配 /v1/messages 等非标准路径）
	suffix := "/chat/completions"
	if normalizeProtocol(cfg.Protocol) == "anthropic" {
		suffix = "/messages"
	}
	candidates := normalizeProviderURLWithFallback(cfg.BaseURL, suffix)
	for _, candidateURL := range candidates {
		if candidateURL == cfg.BaseURL {
			continue // 已经试过了
		}
		fallbackCfg := *cfg
		fallbackCfg.BaseURL = candidateURL
		client, err = NewProtocolClient(fallbackCfg)
		if err != nil {
			continue
		}
		testCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
		_, err = client.Complete(testCtx, "你是连通性测试助手。", "只回复一个 JSON 对象：{\"ok\":true}。")
		cancel()
		if err == nil {
			cfg.BaseURL = candidateURL
			return nil
		}
	}
	return fmt.Errorf("所有 URL 拼接方式均失败，最后错误: %w", err)
}

func defaultText(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

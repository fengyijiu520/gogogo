package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"skill-scanner/internal/config"
)

type anthropicCompatibleClient struct {
	name    string
	baseURL string
	model   string
	apiKey  string
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
	} `json:"error"`
}

func NewAnthropicCompatibleClient(cfg ProviderConfig) (Client, error) {
	baseURL, err := normalizeAnthropicMessagesURL(cfg.BaseURL)
	if err != nil {
		return nil, err
	}
	model := strings.TrimSpace(cfg.Model)
	if model == "" {
		model = strings.TrimSpace(cfg.Name)
	}
	if model == "" {
		return nil, fmt.Errorf("llm model is required")
	}
	apiKey := strings.TrimSpace(cfg.APIKey)
	if apiKey == "" {
		return nil, fmt.Errorf("llm api key is required")
	}
	name := strings.TrimSpace(cfg.Name)
	if name == "" {
		name = strings.TrimSpace(cfg.Provider)
	}
	return &anthropicCompatibleClient{name: name, baseURL: baseURL, model: model, apiKey: apiKey}, nil
}

func (c *anthropicCompatibleClient) AnalyzeCode(ctx context.Context, name, description, codeSummary string) (*AnalysisResult, error) {
	return analyzeCodeWithClient(ctx, c, name, description, codeSummary)
}

func (c *anthropicCompatibleClient) AnalyzeObfuscatedContent(ctx context.Context, name, content string) (*ObfuscationAnalysisResult, error) {
	return analyzeObfuscatedContentWithClient(ctx, c, name, content)
}

func (c *anthropicCompatibleClient) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := anthropicRequest{Model: c.model, MaxTokens: 4096, System: systemPrompt, Messages: []anthropicMessage{{Role: "user", Content: userPrompt}}}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("序列化请求失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", c.apiKey)
	req.Header.Set("Anthropic-Version", "2023-06-01")
	resp, err := (&http.Client{Timeout: time.Duration(config.LLMRequestTimeoutSecs()) * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("调用 %s API 失败: %w", defaultText(c.name, "LLM"), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("读取 %s 响应失败: %w", defaultText(c.name, "LLM"), err)
	}
	var result anthropicResponse
	if err := json.Unmarshal(body, &result); err != nil {
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return "", fmt.Errorf("%s API HTTP 状态异常: %d: %s", defaultText(c.name, "LLM"), resp.StatusCode, strings.TrimSpace(string(body)))
		}
		return "", fmt.Errorf("解析响应失败: %w", err)
	}
	if result.Error.Message != "" {
		return "", fmt.Errorf("%s API 错误: %s", defaultText(c.name, "LLM"), result.Error.Message)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("%s API HTTP 状态异常: %d", defaultText(c.name, "LLM"), resp.StatusCode)
	}
	for _, block := range result.Content {
		if strings.TrimSpace(block.Text) != "" {
			return block.Text, nil
		}
	}
	return "", fmt.Errorf("%s API 返回空结果", defaultText(c.name, "LLM"))
}

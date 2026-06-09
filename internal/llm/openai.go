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

type openAICompatibleClient struct {
	name    string
	baseURL string
	model   string
	apiKey  string
}

type chatRequest struct {
	Model       string        `json:"model"`
	Messages    []chatMessage `json:"messages"`
	Temperature float64       `json:"temperature"`
}

type chatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    any    `json:"code"`
	} `json:"error"`
}

func NewOpenAICompatibleClient(cfg ProviderConfig) (Client, error) {
	baseURL, err := normalizeChatCompletionsURL(cfg.BaseURL)
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
	return &openAICompatibleClient{name: name, baseURL: baseURL, model: model, apiKey: apiKey}, nil
}

func (c *openAICompatibleClient) AnalyzeCode(ctx context.Context, name, description, codeSummary string) (*AnalysisResult, error) {
	return analyzeCodeWithClient(ctx, c, name, description, codeSummary)
}

func (c *openAICompatibleClient) AnalyzeObfuscatedContent(ctx context.Context, name, content string) (*ObfuscationAnalysisResult, error) {
	return analyzeObfuscatedContentWithClient(ctx, c, name, content)
}

func (c *openAICompatibleClient) Test(ctx context.Context) error {
	_, err := c.Complete(ctx, "你是连通性测试助手。", "只回复 ok。")
	return err
}

func (c *openAICompatibleClient) Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error) {
	reqBody := chatRequest{Model: c.model, Messages: []chatMessage{{Role: "system", Content: systemPrompt}, {Role: "user", Content: userPrompt}}, Temperature: 0.1}
	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("序列化请求失败: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := (&http.Client{Timeout: time.Duration(config.LLMRequestTimeoutSecs()) * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("调用 %s API 失败: %w", defaultText(c.name, "LLM"), err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", fmt.Errorf("读取 %s 响应失败: %w", defaultText(c.name, "LLM"), err)
	}
	var result chatResponse
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
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("%s API 返回空结果", defaultText(c.name, "LLM"))
	}
	return result.Choices[0].Message.Content, nil
}

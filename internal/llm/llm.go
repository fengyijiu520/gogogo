package llm

import (
	"context"
	"regexp"
)

// Client LLM 客户端接口
type Client interface {
	AnalyzeCode(ctx context.Context, name, description, codeSummary string) (*AnalysisResult, error)
	AnalyzeObfuscatedContent(ctx context.Context, name, content string) (*ObfuscationAnalysisResult, error)
}

// AnalysisResult LLM 分析结果
type AnalysisResult struct {
	StatedIntent         string     `json:"stated_intent"`
	ActualBehavior       string     `json:"actual_behavior"`
	IntentConsistency    int        `json:"intent_consistency"`
	IntentRiskLevel      string     `json:"intent_risk_level,omitempty"`
	IntentMismatch       string     `json:"intent_mismatch,omitempty"`
	DeclaredCapabilities []string   `json:"declared_capabilities,omitempty"`
	ActualCapabilities   []string   `json:"actual_capabilities,omitempty"`
	ConsistencyEvidence  []string   `json:"consistency_evidence,omitempty"`
	Risks                []RiskItem `json:"risks"`
}

// RiskItem 风险项
type RiskItem struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
}

type ObfuscationAnalysisResult struct {
	LikelyObfuscated bool     `json:"likely_obfuscated"`
	Technique        string   `json:"technique,omitempty"`
	Summary          string   `json:"summary,omitempty"`
	DecodedText      string   `json:"decoded_text,omitempty"`
	Confidence       string   `json:"confidence,omitempty"`
	BenignIndicators []string `json:"benign_indicators,omitempty"`
	RiskIndicators   []string `json:"risk_indicators,omitempty"`
}

var jsonRegex = regexp.MustCompile(`(?s)\{.*\}`)

// extractJSON 从 LLM 回复中提取 JSON 内容
func extractJSON(s string) string {
	match := jsonRegex.FindString(s)
	if match != "" {
		return match
	}
	return s
}

// NewDeepSeekClient 创建 DeepSeek 客户端
func NewDeepSeekClient(apiKey string) Client {
	return &deepseekClient{apiKey: apiKey}
}

// NewMiniMaxClient 创建 MiniMax 客户端
func NewMiniMaxClient(groupID, apiKey string) Client {
	return &minimaxClient{groupID: groupID, apiKey: apiKey}
}

package llm

import (
	"context"
)

// Client LLM 客户端接口
type Client interface {
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
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
	CrossFileConsolidation *CrossFileConsolidation `json:"cross_file_consolidation,omitempty"`
	Risks                []RiskItem `json:"risks"`
}

type CrossFileConsolidation struct {
	Summary           string   `json:"summary,omitempty"`
	Evidence          []string `json:"evidence,omitempty"`
	RelatedCategories []string `json:"related_categories,omitempty"`
	MissingParts      []string `json:"missing_parts,omitempty"`
	HasSource         bool     `json:"has_source,omitempty"`
	HasTransform      bool     `json:"has_transform,omitempty"`
	HasSink           bool     `json:"has_sink,omitempty"`
	HasRuntime        bool     `json:"has_runtime,omitempty"`
}

// RiskItem 风险项
type RiskItem struct {
	Title              string   `json:"title"`
	Severity           string   `json:"severity"`
	Status             string   `json:"status,omitempty"`
	Confidence         string   `json:"confidence,omitempty"`
	Exploitability     string   `json:"exploitability,omitempty"`
	RiskScore          int      `json:"risk_score,omitempty"`
	Description        string   `json:"description"`
	Evidence           string   `json:"evidence"`
	EvidenceRefs       []string `json:"evidence_refs,omitempty"`
	KeyCodeLocation    string   `json:"key_code_location,omitempty"`
	Remediation        string   `json:"remediation,omitempty"`
	VerificationStep   string   `json:"verification_step,omitempty"`
	RemediationQuality string   `json:"remediation_quality,omitempty"`
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

// extractJSON 从 LLM 回复中提取 JSON 内容
func extractJSON(s string) string {
	return ExtractJSON(s)
}

// ExtractJSON 从 LLM 回复中提取第一个平衡 JSON 对象。
func ExtractJSON(s string) string {
	start := -1
	depth := 0
	inString := false
	escaped := false
	for i, r := range s {
		if start >= 0 {
			if escaped {
				escaped = false
				continue
			}
			if r == '\\' && inString {
				escaped = true
				continue
			}
			if r == '"' {
				inString = !inString
				continue
			}
			if inString {
				continue
			}
		}
		if r == '{' && !inString {
			if start < 0 {
				start = i
			}
			depth++
			continue
		}
		if r == '}' && start >= 0 && !inString {
			depth--
			if depth == 0 {
				return s[start : i+1]
			}
		}
	}
	return s
}

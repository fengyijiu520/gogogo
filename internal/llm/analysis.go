package llm

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
)

func analyzeCodeWithClient(ctx context.Context, client Client, name, description, codeSummary string) (*AnalysisResult, error) {
	systemPrompt, userPrompt := buildCodeAnalysisPrompts(name, description, codeSummary)
	content, err := client.Complete(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}
	analysisResult, err := parseAnalysisResult(content)
	if err != nil {
		return nil, fmt.Errorf("解析 LLM 响应失败: %w", err)
	}
	return analysisResult, nil
}

func analyzeObfuscatedContentWithClient(ctx context.Context, client Client, name, content string) (*ObfuscationAnalysisResult, error) {
	systemPrompt, userPrompt := buildObfuscationAnalysisPrompts(name, content)
	response, err := client.Complete(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, err
	}
	analysisResult, err := parseObfuscationAnalysisResult(response)
	if err != nil {
		return nil, fmt.Errorf("解析 LLM 响应失败: %w", err)
	}
	return analysisResult, nil
}

func parseAnalysisResult(content string) (*AnalysisResult, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(extractJSON(content)), &raw); err != nil {
		return nil, err
	}
	result := &AnalysisResult{
		StatedIntent:         stringValue(raw["stated_intent"]),
		ActualBehavior:       stringValue(raw["actual_behavior"]),
		IntentConsistency:    intValue(raw["intent_consistency"]),
		IntentRiskLevel:      stringValue(raw["intent_risk_level"]),
		IntentMismatch:       stringValue(raw["intent_mismatch"]),
		DeclaredCapabilities: stringSliceValue(raw["declared_capabilities"]),
		ActualCapabilities:   stringSliceValue(raw["actual_capabilities"]),
		ConsistencyEvidence:  stringSliceValue(raw["consistency_evidence"]),
	}
	if risks, ok := raw["risks"].([]any); ok {
		result.Risks = make([]RiskItem, 0, len(risks))
		for _, item := range risks {
			riskMap, ok := item.(map[string]any)
			if !ok {
				continue
			}
			result.Risks = append(result.Risks, RiskItem{
				Title:              stringValue(riskMap["title"]),
				Severity:           stringValue(riskMap["severity"]),
				Status:             stringValue(riskMap["status"]),
				Confidence:         stringValue(riskMap["confidence"]),
				Exploitability:     stringValue(riskMap["exploitability"]),
				RiskScore:          intValue(riskMap["risk_score"]),
				Description:        stringValue(riskMap["description"]),
				Evidence:           stringValue(riskMap["evidence"]),
				EvidenceRefs:       stringSliceValue(riskMap["evidence_refs"]),
				KeyCodeLocation:    stringValue(riskMap["key_code_location"]),
				Remediation:        stringValue(riskMap["remediation"]),
				VerificationStep:   stringValue(riskMap["verification_step"]),
				RemediationQuality: stringValue(riskMap["remediation_quality"]),
			})
		}
	}
	return result, nil
}

func parseObfuscationAnalysisResult(content string) (*ObfuscationAnalysisResult, error) {
	var raw map[string]any
	if err := json.Unmarshal([]byte(extractJSON(content)), &raw); err != nil {
		return nil, err
	}
	return &ObfuscationAnalysisResult{
		LikelyObfuscated: boolValue(raw["likely_obfuscated"]),
		Technique:        stringValue(raw["technique"]),
		Summary:          stringValue(raw["summary"]),
		DecodedText:      stringValue(raw["decoded_text"]),
		Confidence:       stringValue(raw["confidence"]),
		BenignIndicators: stringSliceValue(raw["benign_indicators"]),
		RiskIndicators:   stringSliceValue(raw["risk_indicators"]),
	}, nil
}

func (r *RiskItem) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = RiskItem{
		Title:              stringValue(raw["title"]),
		Severity:           stringValue(raw["severity"]),
		Status:             stringValue(raw["status"]),
		Confidence:         stringValue(raw["confidence"]),
		Exploitability:     stringValue(raw["exploitability"]),
		RiskScore:          intValue(raw["risk_score"]),
		Description:        stringValue(raw["description"]),
		Evidence:           stringValue(raw["evidence"]),
		EvidenceRefs:       stringSliceValue(raw["evidence_refs"]),
		KeyCodeLocation:    stringValue(raw["key_code_location"]),
		Remediation:        stringValue(raw["remediation"]),
		VerificationStep:   stringValue(raw["verification_step"]),
		RemediationQuality: stringValue(raw["remediation_quality"]),
	}
	return nil
}

func (r *AnalysisResult) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = AnalysisResult{
		StatedIntent:         stringValue(raw["stated_intent"]),
		ActualBehavior:       stringValue(raw["actual_behavior"]),
		IntentConsistency:    intValue(raw["intent_consistency"]),
		IntentRiskLevel:      stringValue(raw["intent_risk_level"]),
		IntentMismatch:       stringValue(raw["intent_mismatch"]),
		DeclaredCapabilities: stringSliceValue(raw["declared_capabilities"]),
		ActualCapabilities:   stringSliceValue(raw["actual_capabilities"]),
		ConsistencyEvidence:  stringSliceValue(raw["consistency_evidence"]),
	}
	if risks, ok := raw["risks"].([]any); ok {
		r.Risks = make([]RiskItem, 0, len(risks))
		for _, item := range risks {
			data, err := json.Marshal(item)
			if err != nil {
				continue
			}
			var risk RiskItem
			if err := json.Unmarshal(data, &risk); err == nil {
				r.Risks = append(r.Risks, risk)
			}
		}
	}
	return nil
}

func (r *ObfuscationAnalysisResult) UnmarshalJSON(data []byte) error {
	var raw map[string]any
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*r = ObfuscationAnalysisResult{
		LikelyObfuscated: boolValue(raw["likely_obfuscated"]),
		Technique:        stringValue(raw["technique"]),
		Summary:          stringValue(raw["summary"]),
		DecodedText:      stringValue(raw["decoded_text"]),
		Confidence:       stringValue(raw["confidence"]),
		BenignIndicators: stringSliceValue(raw["benign_indicators"]),
		RiskIndicators:   stringSliceValue(raw["risk_indicators"]),
	}
	return nil
}

func stringValue(value any) string {
	switch v := value.(type) {
	case string:
		return strings.TrimSpace(v)
	case json.Number:
		return v.String()
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}

func boolValue(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "yes", "1", "是", "有", "likely":
			return true
		}
	case float64:
		return v != 0
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return i != 0
		}
	}
	return false
}

func intValue(value any) int {
	switch v := value.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(math.Round(v))
	case json.Number:
		if i, err := v.Int64(); err == nil {
			return int(i)
		}
		if f, err := v.Float64(); err == nil {
			return int(math.Round(f))
		}
	case string:
		v = strings.TrimSpace(v)
		if i, err := strconv.Atoi(v); err == nil {
			return i
		}
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			return int(math.Round(f))
		}
	}
	return 0
}

func stringSliceValue(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if text := stringValue(item); text != "" {
				out = append(out, text)
			}
		}
		return out
	case string:
		if strings.TrimSpace(v) == "" {
			return nil
		}
		return []string{strings.TrimSpace(v)}
	default:
		return nil
	}
}

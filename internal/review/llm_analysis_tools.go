package review

import (
	"encoding/json"
	"fmt"
	"strings"
)

type LLMAnalysisTool interface {
	Name() string
	SafetyClass() string
	Run(ctx LLMStageContext, args map[string]string) (ToolObservation, error)
}

type ToolObservation struct {
	ToolName     string   `json:"tool_name"`
	Status       string   `json:"status"`
	Summary      string   `json:"summary"`
	EvidenceRefs []string `json:"evidence_refs,omitempty"`
	Items        []string `json:"items,omitempty"`
}

type ToolRegistry struct {
	tools map[string]LLMAnalysisTool
}

func NewToolRegistry(tools ...LLMAnalysisTool) ToolRegistry {
	registry := ToolRegistry{tools: map[string]LLMAnalysisTool{}}
	for _, tool := range tools {
		if tool == nil {
			continue
		}
		name := strings.TrimSpace(tool.Name())
		if name == "" {
			continue
		}
		registry.tools[name] = tool
	}
	return registry
}

func DefaultReadOnlyToolRegistry() ToolRegistry {
	return NewToolRegistry(LocateRiskyCodeTool{}, SummarizeEvidenceTool{})
}

func (r ToolRegistry) Dispatch(ctx LLMStageContext, toolName string, args map[string]string) (string, error) {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return "", fmt.Errorf("tool name is required")
	}
	tool := r.tools[toolName]
	if tool == nil {
		return "", fmt.Errorf("unregistered llm analysis tool: %s", toolName)
	}
	if tool.SafetyClass() != "read-only" {
		return "", fmt.Errorf("llm analysis tool is not allowed: %s", toolName)
	}
	if err := validateToolArgs(args); err != nil {
		return "", err
	}
	observation, err := tool.Run(ctx, args)
	if err != nil {
		return "", err
	}
	observation.ToolName = tool.Name()
	if strings.TrimSpace(observation.Status) == "" {
		observation.Status = "completed"
	}
	return WrapToolObservation(observation)
}

type LocateRiskyCodeTool struct{}

func (LocateRiskyCodeTool) Name() string { return "locateRiskyCode" }

func (LocateRiskyCodeTool) SafetyClass() string { return "read-only" }

func (LocateRiskyCodeTool) Run(ctx LLMStageContext, args map[string]string) (ToolObservation, error) {
	pattern := strings.ToLower(strings.TrimSpace(args["pattern"]))
	primaryEvidence := preferredToolEvidenceRefs(ctx.Finding)
	items := make([]string, 0, len(primaryEvidence)+len(ctx.Finding.ChainSummaries))
	for _, item := range primaryEvidence {
		if pattern == "" || strings.Contains(strings.ToLower(item), pattern) {
			items = append(items, item)
		}
	}
	for _, item := range ctx.Finding.ChainSummaries {
		if pattern == "" || strings.Contains(strings.ToLower(item), pattern) {
			items = append(items, item)
		}
	}
	return ToolObservation{Summary: "返回归一化 finding 中匹配的代码或链路证据。", EvidenceRefs: append([]string{}, primaryEvidence...), Items: items}, nil
}

type SummarizeEvidenceTool struct{}

func (SummarizeEvidenceTool) Name() string { return "summarizeEvidence" }

func (SummarizeEvidenceTool) SafetyClass() string { return "read-only" }

func (SummarizeEvidenceTool) Run(ctx LLMStageContext, args map[string]string) (ToolObservation, error) {
	items := []string{
		"finding=" + ctx.Finding.ID,
		"category=" + ctx.Finding.Category,
		"severity=" + ctx.Finding.Severity,
		"confidence=" + ctx.Finding.Confidence,
		"code_evidence_count=" + fmt.Sprintf("%d", len(ctx.Finding.CodeEvidenceRefs)),
		"behavior_evidence_count=" + fmt.Sprintf("%d", len(ctx.Finding.BehaviorEvidenceRefs)),
		"context_evidence_count=" + fmt.Sprintf("%d", len(ctx.Finding.ContextEvidenceRefs)),
	}
	if ctx.Rule.RuleID != "" {
		items = append(items, "rule="+ctx.Rule.RuleID)
	}
	if ctx.FalsePositive.Verdict != "" {
		items = append(items, "false_positive_review="+ctx.FalsePositive.Verdict)
	}
	return ToolObservation{Summary: "返回二审上下文的证据摘要。", EvidenceRefs: append([]string{}, preferredToolEvidenceRefs(ctx.Finding)...), Items: items}, nil
}

func preferredToolEvidenceRefs(finding NormalizedFinding) []string {
	for _, refs := range [][]string{finding.CodeEvidenceRefs, finding.BehaviorEvidenceRefs, finding.ContextEvidenceRefs, finding.EvidenceRefs} {
		if len(refs) > 0 {
			return append([]string{}, refs...)
		}
	}
	return nil
}

func validateToolArgs(args map[string]string) error {
	for key, value := range args {
		key = strings.TrimSpace(key)
		if key == "" {
			return fmt.Errorf("tool argument key is required")
		}
		if len(key) > 64 {
			return fmt.Errorf("tool argument key is too long")
		}
		if len(value) > 2048 {
			return fmt.Errorf("tool argument value is too long")
		}
	}
	return nil
}

func WrapToolObservation(observation ToolObservation) (string, error) {
	data, err := json.MarshalIndent(observation, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal tool observation: %w", err)
	}
	return "<TOOL_OBSERVATION trust_level=\"trusted-system-output\">\n" + string(data) + "\n</TOOL_OBSERVATION>", nil
}

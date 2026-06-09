package review

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"skill-scanner/internal/llm"
)

type LLMCompleter interface {
	Complete(ctx context.Context, systemPrompt, userPrompt string) (string, error)
}

type LLMAnalysisLoopConfig struct {
	MaxIterations int
	SystemPrompt  string
	UserPrompt    string
	Tools         ToolRegistry
}

type LLMAnalysisLoopResult struct {
	FinalResponse string           `json:"final_response,omitempty"`
	ToolTrace     []ToolTraceEntry `json:"tool_trace,omitempty"`
	LimitReached  bool             `json:"limit_reached,omitempty"`
	Warnings      []string         `json:"warnings,omitempty"`
}

type ToolTraceEntry struct {
	Iteration int    `json:"iteration"`
	ToolName  string `json:"tool_name"`
	Status    string `json:"status"`
	Summary   string `json:"summary"`
}

type llmToolAction struct {
	Tool string            `json:"tool"`
	Args map[string]string `json:"args,omitempty"`
}

func RunBoundedLLMAnalysisLoop(ctx context.Context, client LLMCompleter, stage LLMStageContext, cfg LLMAnalysisLoopConfig) (LLMAnalysisLoopResult, error) {
	if client == nil {
		return LLMAnalysisLoopResult{}, fmt.Errorf("llm client is required")
	}
	maxIterations := cfg.MaxIterations
	if maxIterations <= 0 {
		maxIterations = 3
	}
	registry := cfg.Tools
	if registry.tools == nil {
		registry = DefaultReadOnlyToolRegistry()
	}
	systemPrompt := strings.TrimSpace(cfg.SystemPrompt)
	if systemPrompt == "" {
		systemPrompt = "你是受控的 skill 安全分析 Agent。只能输出 JSON，工具调用必须使用 {\"tool\":\"工具名\",\"args\":{}}。"
	}
	history := strings.TrimSpace(cfg.UserPrompt)
	if history == "" {
		history = buildReviewAgentPromptFromContextForLoop(stage)
	}
	result := LLMAnalysisLoopResult{}
	for iteration := 1; iteration <= maxIterations; iteration++ {
		response, err := client.Complete(ctx, systemPrompt, history)
		if err != nil {
			return result, err
		}
		if action, ok := parseLLMToolAction(response); ok {
			observation, dispatchErr := registry.Dispatch(stage, action.Tool, action.Args)
			status := "completed"
			summary := "工具调用完成"
			if dispatchErr != nil {
				status = "rejected"
				summary = dispatchErr.Error()
				observation = "<TOOL_OBSERVATION trust_level=\"trusted-system-output\">\n{\"status\":\"rejected\",\"summary\":" + jsonString(summary) + "}\n</TOOL_OBSERVATION>"
			}
			result.ToolTrace = append(result.ToolTrace, ToolTraceEntry{Iteration: iteration, ToolName: action.Tool, Status: status, Summary: summary})
			history += "\n\n" + observation
			continue
		}
		result.FinalResponse = response
		return result, nil
	}
	result.LimitReached = true
	result.Warnings = append(result.Warnings, "LLM analysis loop reached iteration limit")
	return result, nil
}

func parseLLMToolAction(response string) (llmToolAction, bool) {
	var action llmToolAction
	text := strings.TrimSpace(response)
	if text == "" {
		return action, false
	}
	text = llm.ExtractJSON(text)
	if err := json.Unmarshal([]byte(text), &action); err != nil {
		return llmToolAction{}, false
	}
	return action, strings.TrimSpace(action.Tool) != ""
}

func jsonString(value string) string {
	data, err := json.Marshal(value)
	if err != nil {
		return "\"\""
	}
	return string(data)
}

func buildReviewAgentPromptFromContextForLoop(stage LLMStageContext) string {
	data, err := json.MarshalIndent(stage, "", "  ")
	if err != nil {
		data = []byte(`{"error":"failed to marshal stage context"}`)
	}
	return "<UNTRUSTED_STAGE_CONTEXT>\n" + string(data) + "\n</UNTRUSTED_STAGE_CONTEXT>"
}

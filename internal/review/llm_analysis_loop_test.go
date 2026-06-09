package review

import (
	"context"
	"strings"
	"testing"
)

type scriptedCompleter struct {
	responses []string
	calls     int
	lastUser  string
}

func (s *scriptedCompleter) Complete(_ context.Context, _, userPrompt string) (string, error) {
	s.lastUser = userPrompt
	if s.calls >= len(s.responses) {
		return `{"verdict":"needs_manual_review"}`, nil
	}
	response := s.responses[s.calls]
	s.calls++
	return response, nil
}

func TestRunBoundedLLMAnalysisLoopDispatchesToolAndReturnsFinalResponse(t *testing.T) {
	client := &scriptedCompleter{responses: []string{
		`{"tool":"locateRiskyCode","args":{"pattern":"os.system"}}`,
		`{"verdict":"confirmed","reason":"证据充分"}`,
	}}
	stage := LLMStageContext{Finding: NormalizedFinding{ID: "SF-001", CodeEvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}}}

	result, err := RunBoundedLLMAnalysisLoop(context.Background(), client, stage, LLMAnalysisLoopConfig{MaxIterations: 3})
	if err != nil {
		t.Fatalf("run loop: %v", err)
	}
	if result.FinalResponse == "" || result.LimitReached {
		t.Fatalf("expected final response before limit, got %+v", result)
	}
	if len(result.ToolTrace) != 1 || result.ToolTrace[0].Status != "completed" || result.ToolTrace[0].ToolName != "locateRiskyCode" {
		t.Fatalf("expected completed tool trace, got %+v", result.ToolTrace)
	}
	if !strings.Contains(client.lastUser, "<TOOL_OBSERVATION") || !strings.Contains(client.lastUser, "os.system") {
		t.Fatalf("expected bounded tool observation in next prompt, got %s", client.lastUser)
	}
}

func TestRunBoundedLLMAnalysisLoopRejectsToolAndStopsAtLimit(t *testing.T) {
	client := &scriptedCompleter{responses: []string{
		`{"tool":"runShell","args":{"cmd":"whoami"}}`,
		`{"tool":"runShell","args":{"cmd":"id"}}`,
	}}

	result, err := RunBoundedLLMAnalysisLoop(context.Background(), client, LLMStageContext{}, LLMAnalysisLoopConfig{MaxIterations: 2})
	if err != nil {
		t.Fatalf("run loop: %v", err)
	}
	if !result.LimitReached || len(result.Warnings) == 0 {
		t.Fatalf("expected iteration limit warning, got %+v", result)
	}
	if len(result.ToolTrace) != 2 || result.ToolTrace[0].Status != "rejected" || result.ToolTrace[1].Status != "rejected" {
		t.Fatalf("expected rejected tool trace, got %+v", result.ToolTrace)
	}
	if !strings.Contains(client.lastUser, "TOOL_OBSERVATION") || !strings.Contains(client.lastUser, "rejected") {
		t.Fatalf("expected rejected observation boundary, got %s", client.lastUser)
	}
}

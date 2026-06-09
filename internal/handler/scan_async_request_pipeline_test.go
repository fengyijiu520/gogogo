package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"skill-scanner/internal/config"
	"skill-scanner/internal/evaluator"
)

func TestLoadEffectiveScanConfigFallsBackAndFiltersRules(t *testing.T) {
	t.Setenv("SKILL_SCANNER_RULES_PATH", filepath.Join(t.TempDir(), "missing-rules.yaml"))
	cfg := loadEffectiveScanConfig([]string{"V7-001"}, nil)
	if cfg == nil {
		t.Fatal("expected fallback config")
	}
	if len(cfg.Rules) == 0 {
		t.Fatal("expected fallback rules loaded")
	}
	for _, rule := range cfg.Rules {
		if rule.ID != "S2-P0-001" {
			t.Fatalf("expected selected rules filtered to S2-P0-001, got %s", rule.ID)
		}
	}
}

func TestEnsureBaseScanPrerequisitesReportsEmbedderError(t *testing.T) {
	originalEmbedder := globalEmbedder
	originalErr := embedderInitError
	globalEmbedder = nil
	embedderInitError = os.ErrNotExist
	t.Cleanup(func() {
		globalEmbedder = originalEmbedder
		embedderInitError = originalErr
	})
	err := ensureBaseScanPrerequisites()
	if err == nil || !strings.Contains(err.Error(), "语义引擎不可用") || !strings.Contains(err.Error(), os.ErrNotExist.Error()) {
		t.Fatalf("expected prerequisite error with embedder detail, got %v", err)
	}
}

func TestApplyBaseScanEvaluationResultCopiesEvaluationFields(t *testing.T) {
	base := baseScanOutput{}
	cfg := &config.Config{Rules: []config.Rule{{ID: "V7-001", Name: "恶意代码与破坏性行为", Severity: "高风险", Layer: "P0", Detection: config.Detection{Type: "function", Function: "detectExec"}, OnFail: config.OnFail{Action: "block", Reason: "risk"}}}}
	result := &evaluator.EvaluationResult{
		Score:               42,
		RiskLevel:           "high",
		IntentAnalysisError: "llm timeout",
		ItemScores:          map[string]float64{"V7-001": 0.9},
		DetectionErrors:     []evaluator.DetectionError{{RuleID: "V7-001", Kind: "degraded", Message: "slow", Severity: "warning"}},
		FindingDetails:      []evaluator.FindingDetail{{RuleID: "V7-001", Title: "exec", Severity: "高风险", Location: "main.py:1", CodeSnippet: "os.system('x')"}},
	}

	applyBaseScanEvaluationResult(&base, cfg, result)

	if base.score != 42 {
		t.Fatalf("expected score=42, got %+v", base)
	}
	if len(base.detectionErrors) != 1 || base.detectionErrors[0].RuleID != "V7-001" {
		t.Fatalf("expected detection errors copied, got %+v", base.detectionErrors)
	}
	if len(base.findings) == 0 || len(base.evalLogs) == 0 {
		t.Fatalf("expected findings and eval logs built, got findings=%+v logs=%+v", base.findings, base.evalLogs)
	}
	if base.intentSummary.Available || !strings.Contains(base.intentSummary.UnavailableReason, "llm timeout") {
		t.Fatalf("expected intent summary error carried, got %+v", base.intentSummary)
	}
	if base.evaluatedRules != 1 || len(base.uncheckedRules) != 0 {
		t.Fatalf("expected evaluated rule accounting updated, got evaluated=%d unchecked=%+v", base.evaluatedRules, base.uncheckedRules)
	}
	if len(base.trace) < 2 {
		t.Fatalf("expected trace entries appended, got %+v", base.trace)
	}
}

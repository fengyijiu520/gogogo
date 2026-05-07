package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadRulesV7Config(t *testing.T) {
	cfg, err := Load("../../config/rules_v7.yaml")
	if err != nil {
		t.Fatalf("load V7 rules config: %v", err)
	}
	if cfg.Version != "7.0" {
		t.Fatalf("expected version 7.0, got %q", cfg.Version)
	}
	if len(cfg.Rules) != 30 {
		t.Fatalf("expected 30 V7 rules, got %d", len(cfg.Rules))
	}
	for _, rule := range cfg.Rules {
		if !strings.HasPrefix(rule.ID, "V7-") {
			t.Fatalf("expected V7 rule id, got %q", rule.ID)
		}
		if rule.Severity == "" {
			t.Fatalf("expected V7 rule %s has severity", rule.ID)
		}
		if rule.Layer == "" {
			t.Fatalf("expected V7 rule %s mapped to internal layer", rule.ID)
		}
	}
}

func TestRulesV7HighRiskRulesContainReviewMetadata(t *testing.T) {
	cfg, err := Load("../../config/rules_v7.yaml")
	if err != nil {
		t.Fatalf("load V7 rules config: %v", err)
	}

	reviewed := 0
	for _, rule := range cfg.Rules {
		if rule.Severity != "高风险" {
			continue
		}
		reviewed++
		if rule.Review.PromptTemplate == "" {
			t.Fatalf("expected high-risk rule %s has prompt_template", rule.ID)
		}
		if len(rule.Review.DetectionCriteria) == 0 || len(rule.Review.ExclusionConditions) == 0 || len(rule.Review.VerificationRequirements) == 0 || len(rule.Review.OutputRequirements) == 0 {
			t.Fatalf("expected high-risk rule %s has complete review metadata, got %+v", rule.ID, rule.Review)
		}
		if rule.Review.RemediationFocus == "" {
			t.Fatalf("expected high-risk rule %s has remediation_focus", rule.ID)
		}
	}
	if reviewed != 14 {
		t.Fatalf("expected 14 high-risk rules with review metadata, got %d", reviewed)
	}
}

func TestRulesV7ConfigContainsNoScoreFields(t *testing.T) {
	data, err := os.ReadFile("../../config/rules_v7.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, forbidden := range []string{"weight:", "score_deduction:", "default_deduction:", "threshold:", "threshold_low:", "threshold_high:"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("V7 rules config should not contain score field %q", forbidden)
		}
	}
}

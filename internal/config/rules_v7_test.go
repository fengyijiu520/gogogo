package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadRulesAccessConfig(t *testing.T) {
	cfg, err := Load("../../config/rules_access.yaml")
	if err != nil {
		t.Fatalf("load access rules config: %v", err)
	}
	if cfg.Version == "" {
		t.Fatalf("expected version to be set")
	}
	if len(cfg.Rules) == 0 {
		t.Fatalf("expected non-empty access rules, got %d rules from %d groups", len(cfg.Rules), len(cfg.RuleGroups))
	}
	for _, rule := range cfg.Rules {
		if !strings.HasPrefix(rule.ID, "S2-") {
			t.Fatalf("expected S2 rule id, got %q", rule.ID)
		}
		if strings.TrimSpace(rule.Name) == "" {
			t.Fatalf("expected access rule %s has name", rule.ID)
		}
		if rule.Layer == "" {
			t.Fatalf("expected access rule %s mapped to internal layer", rule.ID)
		}
	}
}

func TestRulesAccessContainsP0AndP1(t *testing.T) {
	cfg, err := Load("../../config/rules_access.yaml")
	if err != nil {
		t.Fatalf("load access rules config: %v", err)
	}

	hasP0 := false
	hasP1 := false
	for _, rule := range cfg.Rules {
		switch strings.TrimSpace(rule.Layer) {
		case "P0":
			hasP0 = true
		case "P1":
			hasP1 = true
		}
	}
	if !hasP0 || !hasP1 {
		t.Fatalf("expected access rules contain both P0 and P1 layers, got P0=%v P1=%v", hasP0, hasP1)
	}
}

func TestRulesAccessConfigContainsDetectionFields(t *testing.T) {
	data, err := os.ReadFile("../../config/rules_access.yaml")
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, required := range []string{"detection_target:", "risk_personal:"} {
		if !strings.Contains(text, required) {
			t.Fatalf("access rules config should contain field %q", required)
		}
	}
}

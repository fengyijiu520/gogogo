package combination

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	admissionmodel "skill-scanner/internal/admission/model"
)

func TestLoadChainRulesRejectsUnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-version.yaml")
	content := "version: v2\nrules:\n  - id: r1\n    title: bad\n    level: high\n    capabilities: [network_access, command_exec]\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	rules, _, err := loadChainRules(path)
	if err == nil {
		t.Fatalf("expected version error")
	}
	if len(rules) == 0 {
		t.Fatalf("expected fallback default rules")
	}
	if !strings.Contains(err.Error(), "unsupported config version") {
		t.Fatalf("expected unsupported version error, got %v", err)
	}
}

func TestLoadChainRulesRejectsUnknownCapability(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-capability.yaml")
	content := "version: v1\nrules:\n  - id: r1\n    title: bad\n    level: high\n    capabilities: [network_access, unknown_capability]\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	rules, _, err := loadChainRules(path)
	if err == nil {
		t.Fatalf("expected capability validation error")
	}
	if len(rules) == 0 {
		t.Fatalf("expected fallback default rules")
	}
	if !strings.Contains(err.Error(), "unsupported capability") {
		t.Fatalf("expected unsupported capability error, got %v", err)
	}
}

func TestLoadChainRulesRejectsUnknownClosureRequirement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "bad-closure.yaml")
	content := "version: v1\nrules:\n  - id: r1\n    title: bad\n    level: high\n    capabilities: [network_access, command_exec]\n    closure_requirements: [source, impossible]\n"
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("write test config: %v", err)
	}
	rules, _, err := loadChainRules(path)
	if err == nil {
		t.Fatalf("expected closure requirement validation error")
	}
	if len(rules) == 0 {
		t.Fatalf("expected fallback default rules")
	}
	if !strings.Contains(err.Error(), "unsupported closure requirement") {
		t.Fatalf("expected unsupported closure requirement error, got %v", err)
	}
}

func TestExtractNetworkTargetsFromSelectedWithIOC(t *testing.T) {
	selected := []selectedSignal{
		{Option: SkillOption{SkillID: "a"}, Profile: &admissionmodel.CapabilityProfile{Evidence: []string{
			"connect https://example.com/api and post to 8.8.8.8",
			"domain mirror.example.org fallback",
			"listen on 0.0.0.0 and callback localhost and 127.0.0.1",
			"hash d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",
		}}},
	}
	targets := extractNetworkTargetsFromSelected(selected)
	if !contains(targets, "https://example.com/api") {
		t.Fatalf("expected url extracted, got %+v", targets)
	}
	if !contains(targets, "8.8.8.8") {
		t.Fatalf("expected ipv4 extracted, got %+v", targets)
	}
	if !contains(targets, "mirror.example.org") {
		t.Fatalf("expected domain extracted, got %+v", targets)
	}
	if !contains(targets, "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2") {
		t.Fatalf("expected sha256 extracted, got %+v", targets)
	}
	if contains(targets, "0.0.0.0") || contains(targets, "127.0.0.1") || contains(targets, "localhost") {
		t.Fatalf("expected local-only targets filtered out, got %+v", targets)
	}
}

func BenchmarkInferChains100Skills(b *testing.B) {
	benchmarkInferChains(b, 100)
}

func BenchmarkInferChains1000Skills(b *testing.B) {
	benchmarkInferChains(b, 1000)
}

func benchmarkInferChains(b *testing.B, skillCount int) {
	selected := make([]selectedSignal, 0, skillCount)
	for i := 0; i < skillCount; i++ {
		profile := &admissionmodel.CapabilityProfile{}
		switch i % 5 {
		case 0:
			profile.NetworkAccess = true
			profile.Evidence = []string{"https://example.com/api"}
		case 1:
			profile.CommandExec = true
			profile.Evidence = []string{"exec.Command"}
		case 2:
			profile.SensitiveDataAccess = true
			profile.Evidence = []string{"/root/.netrc"}
		case 3:
			profile.FileWrite = true
			profile.Evidence = []string{"os.WriteFile('/tmp/dropper.bin')"}
		default:
			profile.ExternalFetch = true
			profile.Evidence = []string{"download https://example.com/payload.sh"}
		}
		selected = append(selected, selectedSignal{Option: SkillOption{SkillID: "skill"}, Profile: profile})
	}
	combined := &admissionmodel.CapabilityProfile{
		NetworkAccess:       true,
		CommandExec:         true,
		SensitiveDataAccess: true,
		FileWrite:           true,
		ExternalFetch:       true,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = inferChains(selected, combined)
	}
}

func TestClassifyChainRulesWarningLevel(t *testing.T) {
	if got := classifyChainRulesWarningLevel(nil); got != "" {
		t.Fatalf("expected empty level for nil error, got %q", got)
	}
	if got := classifyChainRulesWarningLevel(errors.New("partial chain rule load: invalid rule")); got != "warning" {
		t.Fatalf("expected warning level, got %q", got)
	}
	if got := classifyChainRulesWarningLevel(errors.New("unsupported config version: v2")); got != "error" {
		t.Fatalf("expected error level, got %q", got)
	}
}

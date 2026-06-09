package config

import "testing"

func TestRuntimeThresholdDefaults(t *testing.T) {
	t.Setenv("REVIEW_EVASION_DELAY_THRESHOLD_SECS", "")
	t.Setenv("SKILL_SCANNER_MAX_ACTIVE_TASKS_PER_USER", "")
	t.Setenv("SKILL_SCANNER_MAX_ACTIVE_TASKS_GLOBAL", "")
	t.Setenv("SKILL_SCANNER_SIMILARITY_LOW", "")
	t.Setenv("SKILL_SCANNER_SIMILARITY_HIGH", "")
	t.Setenv("SKILL_SCANNER_BEHAVIOR_CHAIN_VERIFY_HIGH_THRESHOLD", "")
	t.Setenv("SKILL_SCANNER_BEHAVIOR_CHAIN_VERIFY_MEDIUM_THRESHOLD", "")
	t.Setenv("SKILL_SCANNER_SEMANTIC_CHAIN_MIN_SKILLS", "")
	t.Setenv("SKILL_SCANNER_SEMANTIC_CHAIN_MIN_PHASES", "")
	t.Setenv("SKILL_SCANNER_SEMANTIC_CHAIN_MIN_EVIDENCE", "")

	if got := EvasionDelayThresholdSecs(); got != 300 {
		t.Fatalf("expected default evasion delay 300, got %d", got)
	}
	if got := MaxActiveTasksPerUser(); got != 2 {
		t.Fatalf("expected default per-user active tasks 2, got %d", got)
	}
	if got := MaxActiveTasksGlobal(); got != 6 {
		t.Fatalf("expected default global active tasks 6, got %d", got)
	}
	if got := SimilarityThresholdLow(); got != 0.5 {
		t.Fatalf("expected default similarity low 0.5, got %v", got)
	}
	if got := SimilarityThresholdHigh(); got != 0.75 {
		t.Fatalf("expected default similarity high 0.75, got %v", got)
	}
	if got := BehaviorChainVerifyHighThreshold(); got != 3 {
		t.Fatalf("expected default chain verify high threshold 3, got %d", got)
	}
	if got := BehaviorChainVerifyMediumThreshold(); got != 2 {
		t.Fatalf("expected default chain verify medium threshold 2, got %d", got)
	}
	if got := SemanticChainMinSkills(); got != 3 {
		t.Fatalf("expected default semantic min skills 3, got %d", got)
	}
	if got := SemanticChainMinPhases(); got != 3 {
		t.Fatalf("expected default semantic min phases 3, got %d", got)
	}
	if got := SemanticChainMinEvidence(); got != 2 {
		t.Fatalf("expected default semantic min evidence 2, got %d", got)
	}
}

func TestRuntimeThresholdOverrides(t *testing.T) {
	t.Setenv("REVIEW_EVASION_DELAY_THRESHOLD_SECS", "180")
	t.Setenv("SKILL_SCANNER_MAX_ACTIVE_TASKS_PER_USER", "3")
	t.Setenv("SKILL_SCANNER_MAX_ACTIVE_TASKS_GLOBAL", "9")
	t.Setenv("SKILL_SCANNER_SIMILARITY_LOW", "0.42")
	t.Setenv("SKILL_SCANNER_SIMILARITY_HIGH", "0.81")
	t.Setenv("SKILL_SCANNER_BEHAVIOR_CHAIN_VERIFY_HIGH_THRESHOLD", "2")
	t.Setenv("SKILL_SCANNER_BEHAVIOR_CHAIN_VERIFY_MEDIUM_THRESHOLD", "1")
	t.Setenv("SKILL_SCANNER_SEMANTIC_CHAIN_MIN_SKILLS", "4")
	t.Setenv("SKILL_SCANNER_SEMANTIC_CHAIN_MIN_PHASES", "2")
	t.Setenv("SKILL_SCANNER_SEMANTIC_CHAIN_MIN_EVIDENCE", "5")

	if got := EvasionDelayThresholdSecs(); got != 180 {
		t.Fatalf("expected overridden evasion delay 180, got %d", got)
	}
	if got := MaxActiveTasksPerUser(); got != 3 {
		t.Fatalf("expected overridden per-user active tasks 3, got %d", got)
	}
	if got := MaxActiveTasksGlobal(); got != 9 {
		t.Fatalf("expected overridden global active tasks 9, got %d", got)
	}
	if got := SimilarityThresholdLow(); got != 0.42 {
		t.Fatalf("expected overridden similarity low 0.42, got %v", got)
	}
	if got := SimilarityThresholdHigh(); got != 0.81 {
		t.Fatalf("expected overridden similarity high 0.81, got %v", got)
	}
	if got := BehaviorChainVerifyHighThreshold(); got != 2 {
		t.Fatalf("expected overridden chain verify high threshold 2, got %d", got)
	}
	if got := BehaviorChainVerifyMediumThreshold(); got != 1 {
		t.Fatalf("expected overridden chain verify medium threshold 1, got %d", got)
	}
	if got := SemanticChainMinSkills(); got != 4 {
		t.Fatalf("expected overridden semantic min skills 4, got %d", got)
	}
	if got := SemanticChainMinPhases(); got != 2 {
		t.Fatalf("expected overridden semantic min phases 2, got %d", got)
	}
	if got := SemanticChainMinEvidence(); got != 5 {
		t.Fatalf("expected overridden semantic min evidence 5, got %d", got)
	}
}

func TestPluginEnvDefaultsEmpty(t *testing.T) {
	t.Setenv("SKILL_SCANNER_ENABLED_PLUGINS", "")
	t.Setenv("SKILL_SCANNER_DISABLED_PLUGINS", "")

	if got := EnabledPlugins(); got != nil {
		t.Fatalf("expected nil enabled plugins by default, got %v", got)
	}
	if got := DisabledPlugins(); got != nil {
		t.Fatalf("expected nil disabled plugins by default, got %v", got)
	}
}

func TestPluginEnvParsesCSVAndNormalizes(t *testing.T) {
	t.Setenv("SKILL_SCANNER_ENABLED_PLUGINS", " secret, dangerous,SECRET ,, skill-audit ")
	t.Setenv("SKILL_SCANNER_DISABLED_PLUGINS", "dangerous, unknown ")

	enabled := EnabledPlugins()
	if len(enabled) != 3 {
		t.Fatalf("expected 3 unique enabled plugins, got %v", enabled)
	}
	if enabled[0] != "secret" || enabled[1] != "dangerous" || enabled[2] != "skill-audit" {
		t.Fatalf("unexpected enabled plugins order/content: %v", enabled)
	}

	disabled := DisabledPlugins()
	if len(disabled) != 2 {
		t.Fatalf("expected 2 disabled plugins, got %v", disabled)
	}
	if disabled[0] != "dangerous" || disabled[1] != "unknown" {
		t.Fatalf("unexpected disabled plugins order/content: %v", disabled)
	}
}

func TestPluginsConfigPathDefaultAndOverride(t *testing.T) {
	t.Setenv("SKILL_SCANNER_PLUGINS_CONFIG", "")
	if got := PluginsConfigPath(); got != "config/plugins.json" {
		t.Fatalf("expected default plugins config path, got %q", got)
	}
	t.Setenv("SKILL_SCANNER_PLUGINS_CONFIG", "custom/plugins-runtime.json")
	if got := PluginsConfigPath(); got != "custom/plugins-runtime.json" {
		t.Fatalf("expected overridden plugins config path, got %q", got)
	}
}

func TestEvidenceContextConfigPathDefaultAndOverride(t *testing.T) {
	t.Setenv("SKILL_SCANNER_EVIDENCE_CONTEXT_CONFIG", "")
	if got := EvidenceContextConfigPath(); got != "config/evidence_context.yaml" {
		t.Fatalf("expected default evidence context config path, got %q", got)
	}
	t.Setenv("SKILL_SCANNER_EVIDENCE_CONTEXT_CONFIG", "custom/evidence-context.yaml")
	if got := EvidenceContextConfigPath(); got != "custom/evidence-context.yaml" {
		t.Fatalf("expected overridden evidence context config path, got %q", got)
	}
}

func TestIncrementalScanCacheEnabledDefaultAndOverride(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "")
	if !IncrementalScanCacheEnabled() {
		t.Fatal("expected incremental scan cache enabled by default")
	}
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "false")
	if IncrementalScanCacheEnabled() {
		t.Fatal("expected incremental scan cache disabled when env=false")
	}
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", "true")
	if !IncrementalScanCacheEnabled() {
		t.Fatal("expected incremental scan cache enabled when env=true")
	}
}

func TestIncrementalScanCacheMaxEntriesDefaultAndOverride(t *testing.T) {
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE_MAX_ENTRIES", "")
	if got := IncrementalScanCacheMaxEntries(); got != 2000 {
		t.Fatalf("expected default cache max entries 2000, got %d", got)
	}
	t.Setenv("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE_MAX_ENTRIES", "120")
	if got := IncrementalScanCacheMaxEntries(); got != 120 {
		t.Fatalf("expected overridden cache max entries 120, got %d", got)
	}
}

func TestEvaluatorCacheConfigDefaultAndOverride(t *testing.T) {
	t.Setenv("SKILL_SCANNER_EVALUATOR_CACHE_MAX_ENTRIES", "")
	t.Setenv("SKILL_SCANNER_EVALUATOR_CACHE_TTL_SECS", "")
	if got := EvaluatorCacheMaxEntries(); got != 10000 {
		t.Fatalf("expected default evaluator cache max entries 10000, got %d", got)
	}
	if got := EvaluatorCacheTTLSecs(); got != 86400 {
		t.Fatalf("expected default evaluator cache ttl seconds 86400, got %d", got)
	}

	t.Setenv("SKILL_SCANNER_EVALUATOR_CACHE_MAX_ENTRIES", "2048")
	t.Setenv("SKILL_SCANNER_EVALUATOR_CACHE_TTL_SECS", "7200")
	if got := EvaluatorCacheMaxEntries(); got != 2048 {
		t.Fatalf("expected overridden evaluator cache max entries 2048, got %d", got)
	}
	if got := EvaluatorCacheTTLSecs(); got != 7200 {
		t.Fatalf("expected overridden evaluator cache ttl seconds 7200, got %d", got)
	}
}

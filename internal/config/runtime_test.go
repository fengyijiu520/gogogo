package config

import "testing"

func TestRuntimeThresholdDefaults(t *testing.T) {
	t.Setenv("REVIEW_EVASION_DELAY_THRESHOLD_SECS", "")
	t.Setenv("SKILL_SCANNER_MAX_ACTIVE_TASKS_PER_USER", "")
	t.Setenv("SKILL_SCANNER_MAX_ACTIVE_TASKS_GLOBAL", "")
	t.Setenv("SKILL_SCANNER_SIMILARITY_LOW", "")
	t.Setenv("SKILL_SCANNER_SIMILARITY_HIGH", "")

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
}

func TestRuntimeThresholdOverrides(t *testing.T) {
	t.Setenv("REVIEW_EVASION_DELAY_THRESHOLD_SECS", "180")
	t.Setenv("SKILL_SCANNER_MAX_ACTIVE_TASKS_PER_USER", "3")
	t.Setenv("SKILL_SCANNER_MAX_ACTIVE_TASKS_GLOBAL", "9")
	t.Setenv("SKILL_SCANNER_SIMILARITY_LOW", "0.42")
	t.Setenv("SKILL_SCANNER_SIMILARITY_HIGH", "0.81")

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

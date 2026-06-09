package plugins

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestLoadRuntimeConfigAndResolveFilters(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "plugins.json")
	content := `{"enabled":["secret","dangerous","secret"],"disabled":["skill-audit"]}`
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadRuntimeConfig(path)
	if err != nil {
		t.Fatalf("load runtime config: %v", err)
	}
	enabled, disabled := ResolvePluginFilters([]string{"legacy"}, []string{"old"}, cfg)
	if !reflect.DeepEqual(enabled, []string{"secret", "dangerous"}) {
		t.Fatalf("unexpected enabled filters: %v", enabled)
	}
	if !reflect.DeepEqual(disabled, []string{"skill-audit"}) {
		t.Fatalf("unexpected disabled filters: %v", disabled)
	}
}

func TestLoadRuntimeConfigMissingFile(t *testing.T) {
	cfg, err := LoadRuntimeConfig(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("missing file should not fail: %v", err)
	}
	if len(cfg.Enabled) != 0 || len(cfg.Disabled) != 0 {
		t.Fatalf("expected empty config for missing file, got %+v", cfg)
	}
}

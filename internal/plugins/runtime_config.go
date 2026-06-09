package plugins

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
)

type RuntimeConfig struct {
	Enabled []string `json:"enabled"`
	Disabled []string `json:"disabled"`
}

func LoadRuntimeConfig(path string) (RuntimeConfig, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return RuntimeConfig{}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return RuntimeConfig{}, nil
		}
		return RuntimeConfig{}, err
	}
	var cfg RuntimeConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return RuntimeConfig{}, err
	}
	cfg.Enabled = normalizePluginIDs(cfg.Enabled)
	cfg.Disabled = normalizePluginIDs(cfg.Disabled)
	return cfg, nil
}

func ResolvePluginFilters(envEnabled, envDisabled []string, runtime RuntimeConfig) (enabled, disabled []string) {
	enabled = normalizePluginIDs(envEnabled)
	disabled = normalizePluginIDs(envDisabled)
	if len(runtime.Enabled) > 0 {
		enabled = runtime.Enabled
	}
	if len(runtime.Disabled) > 0 {
		disabled = runtime.Disabled
	}
	return enabled, disabled
}

func normalizePluginIDs(ids []string) []string {
	if len(ids) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		n := normalizePluginID(id)
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"strings"

	"skill-scanner/internal/config"
	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

type ruleCatalogItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Layer    string `json:"layer"`
}

type differentialConfig struct {
	Enabled            bool `json:"enabled"`
	DelayThresholdSecs int  `json:"delay_threshold_secs"`
}

type rulePreset struct {
	Key                 string   `json:"key"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	SelectedRuleIDs     []string `json:"selected_rule_ids"`
	DifferentialEnabled bool     `json:"differential_enabled"`
	DelayThresholdSecs  int      `json:"delay_threshold_secs"`
}

func rulesCatalog(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		cfg, err := config.Load(config.RulesConfigPath())
		if err != nil {
			cfg = getDefaultConfig()
		}

		items := make([]ruleCatalogItem, 0, len(cfg.Rules))
		ruleIDsBySeverity := map[string][]string{"高风险": {}, "中风险": {}, "低风险": {}}
		for _, rule := range cfg.Rules {
			items = append(items, ruleCatalogItem{
				ID:       rule.ID,
				Name:     rule.Name,
				Severity: rule.Severity,
				Layer:    rule.Layer,
			})
			severity := strings.TrimSpace(rule.Severity)
			if _, ok := ruleIDsBySeverity[severity]; ok {
				ruleIDsBySeverity[severity] = append(ruleIDsBySeverity[severity], rule.ID)
			}
		}

		diffDefaults := differentialConfig{
			Enabled:            readDifferentialEnabled(),
			DelayThresholdSecs: readDelayThresholdSec(),
		}

		profiles := store.ListUserRuleProfiles(sess.Username)
		presets := []rulePreset{
			{
				Key:                 "default-all",
				Name:                "默认全量基线",
				Description:         "启用全部 V7 整改规则",
				SelectedRuleIDs:     collectRuleIDs(cfg),
				DifferentialEnabled: diffDefaults.Enabled,
				DelayThresholdSecs:  diffDefaults.DelayThresholdSecs,
			},
			{
				Key:                 "strict-admission",
				Name:                "深度整改审查",
				Description:         "全量规则 + 环境差分画像，适用于上线前完整整改审查",
				SelectedRuleIDs:     collectRuleIDs(cfg),
				DifferentialEnabled: true,
				DelayThresholdSecs:  diffDefaults.DelayThresholdSecs,
			},
			{
				Key:                 "fast-review",
				Name:                "快速审查",
				Description:         "启用高风险和中风险规则，适用于开发阶段快速回归",
				SelectedRuleIDs:     append(append([]string{}, ruleIDsBySeverity["高风险"]...), ruleIDsBySeverity["中风险"]...),
				DifferentialEnabled: true,
				DelayThresholdSecs:  diffDefaults.DelayThresholdSecs,
			},
			{
				Key:                 "high-risk-gate",
				Name:                "高风险优先排查",
				Description:         "仅启用高风险规则，适用于紧急预筛和优先整改",
				SelectedRuleIDs:     append([]string{}, ruleIDsBySeverity["高风险"]...),
				DifferentialEnabled: true,
				DelayThresholdSecs:  diffDefaults.DelayThresholdSecs,
			},
		}

		profilePayload := make([]models.RuleProfile, 0, len(profiles))
		for _, p := range profiles {
			profilePayload = append(profilePayload, p)
		}

		resp := map[string]interface{}{
			"rules":          items,
			"differential":   diffDefaults,
			"presets":        presets,
			"saved_profiles": profilePayload,
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func readDifferentialEnabled() bool {
	raw := strings.ToLower(strings.TrimSpace(os.Getenv("REVIEW_DIFF_ENABLED")))
	if raw == "" {
		raw = strings.ToLower(strings.TrimSpace(os.Getenv("REVIEW_DIFF_SCENARIOS")))
	}
	return raw != "false" && raw != "0" && raw != "off" && raw != "disabled"
}

func readDelayThresholdSec() int {
	return config.EvasionDelayThresholdSecs()
}

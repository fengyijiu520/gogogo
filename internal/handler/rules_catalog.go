package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
	"skill-scanner/internal/config"
	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

type ruleCatalogItem struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Layer    string `json:"layer"`
	Scenario string `json:"scenario"`
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

type approvalRulesConfig struct {
	Rules []approvalRuleItem `yaml:"rules"`
}

type approvalRuleItem struct {
	ID    string   `yaml:"id"`
	Title string   `yaml:"title"`
	Level string   `yaml:"level"`
	Caps  []string `yaml:"capabilities"`
}

type dedupResult struct {
	Items               []ruleCatalogItem
	Scenario2RuleIDs    []string
	Scenario3RuleIDs    []string
	RuleIDsBySeverity   map[string][]string
	DuplicateMappings   map[string]string
	DuplicateScenario3  []string
	RawScenario2Count   int
	RawScenario3Count   int
	DedupScenario3Count int
}

func rulesCatalog(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		catalog := buildCatalogRules()
		items := catalog.Items
		scenario2RuleIDs := catalog.Scenario2RuleIDs
		scenario3RuleIDs := catalog.Scenario3RuleIDs
		ruleIDsBySeverity := catalog.RuleIDsBySeverity
		sort.SliceStable(items, func(i, j int) bool {
			si := catalogSeverityRank(items[i].Severity)
			sj := catalogSeverityRank(items[j].Severity)
			if si != sj {
				return si < sj
			}
			return strings.TrimSpace(items[i].ID) < strings.TrimSpace(items[j].ID)
		})

		sort.Strings(scenario2RuleIDs)
		sort.Strings(scenario3RuleIDs)

		diffDefaults := differentialConfig{
			Enabled:            readDifferentialEnabled(),
			DelayThresholdSecs: readDelayThresholdSec(),
		}

		profiles := store.ListUserRuleProfiles(sess.Username)
		presets := []rulePreset{
			{
				Key:                 "scenario2-default",
				Name:                "默认规则（场景二）",
				Description:         "默认只启用场景二规则，适用于常规技能扫描",
				SelectedRuleIDs:     scenario2RuleIDs,
				DifferentialEnabled: diffDefaults.Enabled,
				DelayThresholdSecs:  diffDefaults.DelayThresholdSecs,
			},
			{
				Key:                 "all-rules",
				Name:                "全量规则（场景二+场景三）",
				Description:         "同时启用场景二与场景三规则，适用于完整风险排查",
				SelectedRuleIDs:     append(append([]string{}, scenario2RuleIDs...), scenario3RuleIDs...),
				DifferentialEnabled: diffDefaults.Enabled,
				DelayThresholdSecs:  diffDefaults.DelayThresholdSecs,
			},
			{
				Key:                 "scenario3-combination",
				Name:                "组合分析（场景三）",
				Description:         "默认仅启用场景三规则，聚焦跨技能组合风险",
				SelectedRuleIDs:     scenario3RuleIDs,
				DifferentialEnabled: true,
				DelayThresholdSecs:  diffDefaults.DelayThresholdSecs,
			},
			{
				Key:                 "fast-review",
				Name:                "快速审查",
				Description:         "启用高风险和中风险规则，覆盖场景二与场景三的重点项",
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
			"dedup": map[string]interface{}{
				"duplicate_mappings":    catalog.DuplicateMappings,
				"duplicate_scenario3":   catalog.DuplicateScenario3,
				"raw_scenario2_count":   catalog.RawScenario2Count,
				"raw_scenario3_count":   catalog.RawScenario3Count,
				"dedup_scenario3_count": catalog.DedupScenario3Count,
			},
			"stats": map[string]int{
				"total":       len(items),
				"scenario2":   len(scenario2RuleIDs),
				"scenario3":   len(scenario3RuleIDs),
				"high_risk":   len(ruleIDsBySeverity["高风险"]),
				"medium_risk": len(ruleIDsBySeverity["中风险"]),
				"low_risk":    len(ruleIDsBySeverity["低风险"]),
			},
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}
}

func rulesValidate() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cfg, err := config.Load(config.RulesConfigPath())
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]interface{}{
				"ok":    false,
				"error": "规则配置加载失败: " + err.Error(),
			})
			return
		}

		type invalidPattern struct {
			RuleID   string `json:"rule_id"`
			RuleName string `json:"rule_name"`
			Pattern  string `json:"pattern"`
			Error    string `json:"error"`
		}
		type invalidRule struct {
			RuleID string `json:"rule_id"`
			Error  string `json:"error"`
		}

		invalids := make([]invalidPattern, 0)
		invalidRules := make([]invalidRule, 0)
		checkedPatterns := 0
		for _, rule := range cfg.Rules {
			if strings.TrimSpace(rule.ID) == "" {
				invalidRules = append(invalidRules, invalidRule{RuleID: "", Error: "缺少规则 ID"})
			}
			if strings.TrimSpace(rule.Name) == "" {
				invalidRules = append(invalidRules, invalidRule{RuleID: strings.TrimSpace(rule.ID), Error: "缺少规则名称"})
			}
			dt := strings.TrimSpace(rule.Detection.Type)
			if dt == "" {
				invalidRules = append(invalidRules, invalidRule{RuleID: strings.TrimSpace(rule.ID), Error: "缺少 detection.type"})
				continue
			}
			if dt != "pattern" && dt != "function" && dt != "semantic" {
				invalidRules = append(invalidRules, invalidRule{RuleID: strings.TrimSpace(rule.ID), Error: "detection.type 非法: " + dt})
			}
			if strings.TrimSpace(rule.Detection.Type) != "pattern" {
				continue
			}
			for _, pat := range rule.Detection.Patterns {
				if strings.TrimSpace(pat) == "" {
					continue
				}
				checkedPatterns++
				if _, compileErr := regexp.Compile(pat); compileErr != nil {
					invalids = append(invalids, invalidPattern{
						RuleID:   strings.TrimSpace(rule.ID),
						RuleName: strings.TrimSpace(rule.Name),
						Pattern:  pat,
						Error:    compileErr.Error(),
					})
				}
			}
		}

		approvalRules, approvalErr := loadApprovalRules()
		approvalInvalidRules := make([]invalidRule, 0)
		if approvalErr == nil {
			for _, rule := range approvalRules {
				if strings.TrimSpace(rule.ID) == "" {
					approvalInvalidRules = append(approvalInvalidRules, invalidRule{RuleID: "", Error: "场景三规则缺少 ID"})
				}
				if strings.TrimSpace(rule.Title) == "" {
					approvalInvalidRules = append(approvalInvalidRules, invalidRule{RuleID: strings.TrimSpace(rule.ID), Error: "场景三规则缺少 title"})
				}
				lv := strings.ToLower(strings.TrimSpace(rule.Level))
				if lv != "high" && lv != "medium" && lv != "low" && lv != "p0" && lv != "p1" && lv != "p2" {
					approvalInvalidRules = append(approvalInvalidRules, invalidRule{RuleID: strings.TrimSpace(rule.ID), Error: "场景三规则 level 非法: " + strings.TrimSpace(rule.Level)})
				}
				if len(rule.Caps) == 0 {
					approvalInvalidRules = append(approvalInvalidRules, invalidRule{RuleID: strings.TrimSpace(rule.ID), Error: "场景三规则缺少 capabilities"})
				}
			}
		}

		sendJSON(w, http.StatusOK, map[string]interface{}{
			"ok":               len(invalids) == 0 && len(invalidRules) == 0 && len(approvalInvalidRules) == 0 && approvalErr == nil,
			"checked_rules":    len(cfg.Rules),
			"checked_patterns": checkedPatterns,
			"invalid_count":    len(invalids),
			"invalid_patterns": invalids,
			"invalid_rules":    invalidRules,
			"scenario3_checked_rules": func() int {
				if approvalErr != nil {
					return 0
				}
				return len(approvalRules)
			}(),
			"scenario3_load_error": func() string {
				if approvalErr != nil {
					return approvalErr.Error()
				}
				return ""
			}(),
			"scenario3_invalid_rules": approvalInvalidRules,
		})
	}
}

func buildCatalogRules() dedupResult {
	admissionCfg, err := config.Load(config.RulesConfigPath())
	if err != nil {
		admissionCfg = getDefaultConfig()
	}
	combinationRules, combinationErr := loadApprovalRules()

	items := make([]ruleCatalogItem, 0, len(admissionCfg.Rules)+len(combinationRules))
	ruleIDsBySeverity := map[string][]string{"高风险": {}, "中风险": {}, "低风险": {}}
	scenario2RuleIDs := make([]string, 0, len(admissionCfg.Rules))
	scenario3RuleIDs := make([]string, 0, len(combinationRules))
	nameToScenario2ID := make(map[string]string, len(admissionCfg.Rules))
	duplicateMappings := make(map[string]string)
	duplicateScenario3 := make([]string, 0)

	for _, rule := range admissionCfg.Rules {
		ruleID := strings.TrimSpace(rule.ID)
		ruleName := strings.TrimSpace(rule.Name)
		items = append(items, ruleCatalogItem{
			ID:       ruleID,
			Name:     ruleName,
			Severity: rule.Severity,
			Layer:    rule.Layer,
			Scenario: "场景二",
		})
		scenario2RuleIDs = append(scenario2RuleIDs, ruleID)
		if key := normalizeRuleTitle(ruleName); key != "" {
			if _, exists := nameToScenario2ID[key]; !exists {
				nameToScenario2ID[key] = ruleID
			}
		}
		severity := strings.TrimSpace(rule.Severity)
		if _, ok := ruleIDsBySeverity[severity]; ok {
			ruleIDsBySeverity[severity] = append(ruleIDsBySeverity[severity], ruleID)
		}
	}

	if combinationErr == nil {
		for _, rule := range combinationRules {
			ruleID := strings.TrimSpace(rule.ID)
			ruleTitle := strings.TrimSpace(rule.Title)
			if mappedID, duplicated := nameToScenario2ID[normalizeRuleTitle(ruleTitle)]; duplicated {
				duplicateMappings[ruleID] = mappedID
				duplicateScenario3 = append(duplicateScenario3, ruleID)
				if mappedID != "" {
					scenario3RuleIDs = append(scenario3RuleIDs, mappedID)
				}
				continue
			}
			severity := normalizeCombinationSeverity(rule.Level)
			items = append(items, ruleCatalogItem{
				ID:       ruleID,
				Name:     ruleTitle,
				Severity: severity,
				Layer:    layerFromSeverity(severity),
				Scenario: "场景三",
			})
			if ruleID != "" {
				scenario3RuleIDs = append(scenario3RuleIDs, ruleID)
				if _, ok := ruleIDsBySeverity[severity]; ok {
					ruleIDsBySeverity[severity] = append(ruleIDsBySeverity[severity], ruleID)
				}
			}
		}
	}

	sort.Strings(scenario2RuleIDs)
	sort.Strings(scenario3RuleIDs)
	sort.Strings(duplicateScenario3)
	scenario3RuleIDs = uniqueRuleIDs(scenario3RuleIDs)
	return dedupResult{
		Items:               items,
		Scenario2RuleIDs:    scenario2RuleIDs,
		Scenario3RuleIDs:    scenario3RuleIDs,
		RuleIDsBySeverity:   ruleIDsBySeverity,
		DuplicateMappings:   duplicateMappings,
		DuplicateScenario3:  duplicateScenario3,
		RawScenario2Count:   len(admissionCfg.Rules),
		RawScenario3Count:   len(combinationRules),
		DedupScenario3Count: len(combinationRules) - len(duplicateScenario3),
	}
}

func normalizeRuleTitle(title string) string {
	t := strings.TrimSpace(title)
	t = strings.ReplaceAll(t, "（", "(")
	t = strings.ReplaceAll(t, "）", ")")
	t = strings.ReplaceAll(t, "：", ":")
	t = strings.ReplaceAll(t, "，", ",")
	return strings.ToLower(strings.Join(strings.Fields(t), ""))
}

func uniqueRuleIDs(ids []string) []string {
	seen := make(map[string]bool, len(ids))
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	sort.Strings(out)
	return out
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

func normalizeCombinationSeverity(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high", "p0":
		return "高风险"
	case "medium", "p1":
		return "中风险"
	case "low", "p2":
		return "低风险"
	default:
		return "中风险"
	}
}

func layerFromSeverity(severity string) string {
	switch strings.TrimSpace(severity) {
	case "高风险":
		return "P0"
	case "中风险":
		return "P1"
	case "低风险":
		return "P2"
	default:
		return "P1"
	}
}

func loadApprovalRules() ([]approvalRuleItem, error) {
	candidates := []string{
		"config/rules_approval.yaml",
		filepath.Join("..", "..", "config", "rules_approval.yaml"),
	}
	var data []byte
	var err error
	for _, path := range candidates {
		data, err = os.ReadFile(path)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}
	var cfg approvalRulesConfig
	if unmarshalErr := yaml.Unmarshal(data, &cfg); unmarshalErr != nil {
		return nil, unmarshalErr
	}
	return cfg.Rules, nil
}

func catalogSeverityRank(severity string) int {
	switch strings.TrimSpace(severity) {
	case "高风险":
		return 0
	case "中风险":
		return 1
	case "低风险":
		return 2
	default:
		return 3
	}
}

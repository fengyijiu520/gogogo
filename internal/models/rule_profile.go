package models

type RuleProfile struct {
	Name                  string             `json:"name"`
	SelectedRuleIDs       []string           `json:"selected_rule_ids"`
	CustomRules           []CustomRuleConfig `json:"custom_rules,omitempty"`
	DifferentialEnabled   bool               `json:"differential_enabled"`
	DifferentialScenarios []string           `json:"differential_scenarios,omitempty"`
	EvasionDelayThreshold int                `json:"evasion_delay_threshold_secs"`
	CreatedAt             int64              `json:"created_at"`
	UpdatedAt             int64              `json:"updated_at"`
}

type CustomRuleConfig struct {
	ID       string   `json:"id,omitempty"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Layer    string   `json:"layer,omitempty"`
	Patterns []string `json:"patterns"`
	Reason   string   `json:"reason,omitempty"`
}

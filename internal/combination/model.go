package combination

import admissionmodel "skill-scanner/internal/admission/model"

type RunRecord struct {
	RunID          string      `json:"run_id"`
	SelectionKey   string      `json:"selection_key"`
	SelectionFingerprint string `json:"selection_fingerprint,omitempty"`
	SelectedSkills []string    `json:"selected_skills"`
	Overview       RunOverview `json:"overview"`
	CreatedAt      int64       `json:"created_at"`
	UpdatedAt      int64       `json:"updated_at"`
}

type RunOverview struct {
	RiskLevel      string        `json:"risk_level"`
	RiskLabel      string        `json:"risk_label"`
	ClosureNarrative string      `json:"closure_narrative,omitempty"`
	Recommendation string        `json:"recommendation,omitempty"`
	CombinedProfile *admissionmodel.CapabilityProfile `json:"combined_profile,omitempty"`
	RuleConfigWarning string     `json:"rule_config_warning,omitempty"`
	RuleConfigWarnLevel string   `json:"rule_config_warn_level,omitempty"`
	RuleConfigVersion string     `json:"rule_config_version,omitempty"`
	RuleConfigRevision string    `json:"rule_config_revision,omitempty"`
	RuleContentHash string       `json:"rule_content_hash,omitempty"`
	RuleSourcePath string        `json:"rule_source_path,omitempty"`
	Capabilities   []string      `json:"capabilities"`
	CombinedTags   []string      `json:"combined_tags"`
	TITargetCount  int           `json:"ti_target_count,omitempty"`
	TIThreatCount  int           `json:"ti_threat_count,omitempty"`
	TISuspiciousCount int        `json:"ti_suspicious_count,omitempty"`
	TIAdjustmentScore float64    `json:"ti_adjustment_score,omitempty"`
	CombinedRisks  []StoredRisk  `json:"combined_risks"`
	InferredChains []StoredChain `json:"inferred_chains"`
	SemanticChains []StoredChain `json:"semantic_chains,omitempty"`
}

type StoredRisk struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Level        string            `json:"level"`
	Category     string            `json:"category"`
	Description  string            `json:"description"`
	Mitigation   string            `json:"mitigation"`
	SourceSkills []RiskSourceSkill `json:"source_skills"`
}

type StoredChain struct {
	ID              string            `json:"id"`
	Title           string            `json:"title"`
	Level           string            `json:"level"`
	Summary         string            `json:"summary"`
	Recommendation  string            `json:"recommendation"`
	ClosureRequirements []string      `json:"closure_requirements,omitempty"`
	Evidence        []string          `json:"evidence"`
	AttackPath      []string          `json:"attack_path,omitempty"`
	MITRETechniques []string          `json:"mitre_techniques,omitempty"`
	SourceSkills    []RiskSourceSkill `json:"source_skills"`
}

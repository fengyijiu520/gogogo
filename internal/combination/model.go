package combination

type RunRecord struct {
	RunID          string      `json:"run_id"`
	SelectionKey   string      `json:"selection_key"`
	SelectedSkills []string    `json:"selected_skills"`
	Overview       RunOverview `json:"overview"`
	CreatedAt      int64       `json:"created_at"`
	UpdatedAt      int64       `json:"updated_at"`
}

type RunOverview struct {
	RiskLevel      string        `json:"risk_level"`
	RiskLabel      string        `json:"risk_label"`
	Capabilities   []string      `json:"capabilities"`
	CombinedTags   []string      `json:"combined_tags"`
	CombinedRisks  []StoredRisk  `json:"combined_risks"`
	InferredChains []StoredChain `json:"inferred_chains"`
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
	Evidence        []string          `json:"evidence"`
	AttackPath      []string          `json:"attack_path,omitempty"`
	MITRETechniques []string          `json:"mitre_techniques,omitempty"`
	SourceSkills    []RiskSourceSkill `json:"source_skills"`
}

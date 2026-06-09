package review

type LLMStagePurpose string

const (
	LLMStageSecondReview LLMStagePurpose = "second-review"
)

type LLMStageContext struct {
	Purpose         LLMStagePurpose        `json:"purpose"`
	StageID         string                 `json:"stage_id"`
	Finding         NormalizedFinding      `json:"finding"`
	Rule            NormalizedRule         `json:"rule,omitempty"`
	FalsePositive   NormalizedFPReview     `json:"false_positive,omitempty"`
	Vulnerability   NormalizedEvidenceItem `json:"vulnerability,omitempty"`
	InputBudget     NormalizedInputBudget  `json:"input_budget,omitempty"`
	StrictStandards []string               `json:"strict_standards,omitempty"`
	Limitations     []string               `json:"limitations,omitempty"`
}

type NormalizedFinding struct {
	ID                    string   `json:"id"`
	Title                 string   `json:"title"`
	Category              string   `json:"category"`
	Severity              string   `json:"severity"`
	Status                string   `json:"status"`
	Confidence            string   `json:"confidence"`
	CodeEvidenceRefs      []string `json:"code_evidence_refs,omitempty"`
	BehaviorEvidenceRefs  []string `json:"behavior_evidence_refs,omitempty"`
	ContextEvidenceRefs   []string `json:"context_evidence_refs,omitempty"`
	EvidenceRefs          []string `json:"evidence_refs,omitempty"`
	EvidenceAliases       []string `json:"evidence_aliases,omitempty"`
	PrimaryLocation       string   `json:"primary_location,omitempty"`
	ExplanationSummary    string   `json:"explanation_summary"`
	ImpactScope           string   `json:"impact_scope,omitempty"`
	RemediationSummary    string   `json:"remediation_summary,omitempty"`
	SourceStage           string   `json:"source_stage"`
	ChainSummaries        []string `json:"chain_summaries,omitempty"`
	CalibrationBasis      []string `json:"calibration_basis,omitempty"`
	FalsePositiveChecks   []string `json:"false_positive_checks,omitempty"`
	ReachabilityChecks    []string `json:"reachability_checks,omitempty"`
	FollowUpHints         []string `json:"follow_up_hints,omitempty"`
	RefutationHints       []string `json:"refutation_hints,omitempty"`
	ExclusionHints        []string `json:"exclusion_hints,omitempty"`
	ClosureSummary        []string `json:"closure_summary,omitempty"`
	ClosureEvidence       []string `json:"closure_evidence,omitempty"`
	MissingClosureParts   []string `json:"missing_closure_parts,omitempty"`
	RuntimeObservations   []string `json:"runtime_observations,omitempty"`
	CrossFileSummary      string   `json:"cross_file_summary,omitempty"`
	CrossFileCategories   []string `json:"cross_file_categories,omitempty"`
	CrossFileMissingParts []string `json:"cross_file_missing_parts,omitempty"`
}

type NormalizedInputBudget struct {
	RawEvidenceCount      int `json:"raw_evidence_count,omitempty"`
	RetainedEvidenceCount int `json:"retained_evidence_count,omitempty"`
	CodeEvidenceCount     int `json:"code_evidence_count,omitempty"`
	BehaviorEvidenceCount int `json:"behavior_evidence_count,omitempty"`
	ContextEvidenceCount  int `json:"context_evidence_count,omitempty"`
	PriorityEvidenceCount int `json:"priority_evidence_count,omitempty"`
	DroppedEvidenceCount  int `json:"dropped_evidence_count,omitempty"`
	AliasCount            int `json:"alias_count,omitempty"`
	MaxEvidenceRefs       int `json:"max_evidence_refs,omitempty"`
}

type NormalizedRule struct {
	RuleID                   string   `json:"rule_id,omitempty"`
	Name                     string   `json:"name,omitempty"`
	Severity                 string   `json:"severity,omitempty"`
	DetectionCriteria        []string `json:"detection_criteria,omitempty"`
	ExclusionConditions      []string `json:"exclusion_conditions,omitempty"`
	VerificationRequirements []string `json:"verification_requirements,omitempty"`
	OutputRequirements       []string `json:"output_requirements,omitempty"`
	RemediationFocus         string   `json:"remediation_focus,omitempty"`
}

type NormalizedFPReview struct {
	FindingID          string   `json:"finding_id,omitempty"`
	Verdict            string   `json:"verdict,omitempty"`
	Exploitability     string   `json:"exploitability,omitempty"`
	Impact             string   `json:"impact,omitempty"`
	EvidenceStrength   string   `json:"evidence_strength,omitempty"`
	ReachabilityChecks []string `json:"reachability_checks,omitempty"`
	ExclusionChecks    []string `json:"exclusion_checks,omitempty"`
	RequiredFollowUp   []string `json:"required_follow_up,omitempty"`
}

type NormalizedEvidenceItem struct {
	ID         string `json:"id,omitempty"`
	Source     string `json:"source,omitempty"`
	TrustLevel string `json:"trust_level,omitempty"`
	Summary    string `json:"summary,omitempty"`
	Snippet    string `json:"snippet,omitempty"`
}

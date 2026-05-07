package review

import "skill-scanner/internal/plugins"

type Phase string

const (
	PhaseQueued  Phase = "queued"
	PhaseP0      Phase = "running:p0"
	PhaseP1      Phase = "running:p1"
	PhaseP2      Phase = "running:p2"
	PhaseScoring Phase = "scoring"
	PhaseDone    Phase = "completed"
	PhaseFailed  Phase = "failed"
)

type FindingEvidence struct {
	RuleID      string   `json:"rule_id"`
	Title       string   `json:"title"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Evidence    []string `json:"evidence"`
}

type BehaviorProfile struct {
	NetworkTargets     []string            `json:"network_targets"`
	FileTargets        []string            `json:"file_targets"`
	ExecTargets        []string            `json:"exec_targets"`
	DownloadIOCs       []string            `json:"download_iocs,omitempty"`
	DropIOCs           []string            `json:"drop_iocs,omitempty"`
	ExecuteIOCs        []string            `json:"execute_iocs,omitempty"`
	OutboundIOCs       []string            `json:"outbound_iocs,omitempty"`
	PersistenceIOCs    []string            `json:"persistence_iocs,omitempty"`
	PrivEscIOCs        []string            `json:"priv_esc_iocs,omitempty"`
	CredentialIOCs     []string            `json:"credential_iocs,omitempty"`
	DefenseEvasionIOCs []string            `json:"defense_evasion_iocs,omitempty"`
	LateralMoveIOCs    []string            `json:"lateral_move_iocs,omitempty"`
	CollectionIOCs     []string            `json:"collection_iocs,omitempty"`
	C2BeaconIOCs       []string            `json:"c2_beacon_iocs,omitempty"`
	BehaviorChains     []string            `json:"behavior_chains,omitempty"`
	BehaviorTimelines  []string            `json:"behavior_timelines,omitempty"`
	SequenceAlerts     []string            `json:"sequence_alerts,omitempty"`
	ProbeWarnings      []string            `json:"probe_warnings,omitempty"`
	EvasionSignals     []string            `json:"evasion_signals,omitempty"`
	Differentials      []DifferentialProbe `json:"differentials,omitempty"`
}

type DifferentialProbe struct {
	Scenario   string   `json:"scenario"`
	Triggered  bool     `json:"triggered"`
	Indicators []string `json:"indicators,omitempty"`
	Summary    string   `json:"summary"`
}

type EvasionAssessment struct {
	Detected       bool                `json:"detected"`
	Severity       string              `json:"severity"`
	Signals        []string            `json:"signals,omitempty"`
	Differentials  []DifferentialProbe `json:"differentials,omitempty"`
	Recommendation string              `json:"recommendation,omitempty"`
}

type IntentDiff struct {
	Type        string  `json:"type"`
	Description string  `json:"description"`
	Penalty     float64 `json:"penalty"`
}

type TIReputation struct {
	Target     string  `json:"target"`
	Reputation string  `json:"reputation"`
	Confidence float64 `json:"confidence"`
	Reason     string  `json:"reason"`
}

type ScoreSummary struct {
	BaseScore      float64 `json:"base_score"`
	P1Deduction    float64 `json:"p1_deduction"`
	ICS            float64 `json:"ics"`
	TIAdjustment   float64 `json:"ti_adjustment"`
	TrustScore     float64 `json:"trust_score"`
	RiskScore      float64 `json:"risk_score,omitempty"`
	Exploitability float64 `json:"exploitability,omitempty"`
	BusinessImpact float64 `json:"business_impact,omitempty"`
	HighRisk       int     `json:"high_risk"`
	MediumRisk     int     `json:"medium_risk"`
	LowRisk        int     `json:"low_risk"`
	RiskLevel      string  `json:"risk_level"`
	Admission      string  `json:"admission"`
	VetoTriggered  bool    `json:"veto_triggered"`
	VetoReason     string  `json:"veto_reason,omitempty"`
}

type PipelineStage struct {
	Name       string `json:"name"`
	Purpose    string `json:"purpose"`
	Status     string `json:"status"`
	Input      string `json:"input,omitempty"`
	Output     string `json:"output,omitempty"`
	Benefit    string `json:"benefit,omitempty"`
	MethodNote string `json:"method_note,omitempty"`
}

type EvidenceInventory struct {
	Category string   `json:"category"`
	Count    int      `json:"count"`
	Examples []string `json:"examples,omitempty"`
	Meaning  string   `json:"meaning"`
}

type OptimizationNote struct {
	Change  string `json:"change"`
	Reason  string `json:"reason"`
	Benefit string `json:"benefit"`
}

type FindingChain struct {
	Kind    string `json:"kind"`
	Summary string `json:"summary"`
	Source  string `json:"source,omitempty"`
	Path    string `json:"path,omitempty"`
}

type StructuredFinding struct {
	ID                  string         `json:"id"`
	RuleID              string         `json:"rule_id"`
	Title               string         `json:"title"`
	Severity            string         `json:"severity"`
	Category            string         `json:"category"`
	Confidence          string         `json:"confidence"`
	AttackPath          string         `json:"attack_path"`
	MITRETechniques     []string       `json:"mitre_techniques,omitempty"`
	Evidence            []string       `json:"evidence"`
	ChainSummaries      []string       `json:"chain_summaries,omitempty"`
	Chains              []FindingChain `json:"chains,omitempty"`
	CalibrationBasis    []string       `json:"calibration_basis"`
	FalsePositiveChecks []string       `json:"false_positive_checks"`
	ReviewGuidance      string         `json:"review_guidance"`
	Source              string         `json:"source"`
	DeduplicatedCount   int            `json:"deduplicated_count"`
}

type VulnerabilityBlock struct {
	ID      string `json:"id"`
	Format  string `json:"format"`
	Content string `json:"content"`
}

type RuleExplanation struct {
	RuleID                   string   `json:"rule_id"`
	Name                     string   `json:"name"`
	Severity                 string   `json:"severity"`
	DetectionType            string   `json:"detection_type"`
	Action                   string   `json:"action"`
	Triggered                bool     `json:"triggered"`
	DetectionCriteria        []string `json:"detection_criteria"`
	ExclusionConditions      []string `json:"exclusion_conditions"`
	VerificationRequirements []string `json:"verification_requirements"`
	OutputRequirements       []string `json:"output_requirements"`
	PromptTemplateSummary    string   `json:"prompt_template_summary"`
	RemediationFocus         string   `json:"remediation_focus"`
}

type FalsePositiveReview struct {
	FindingID          string   `json:"finding_id"`
	Verdict            string   `json:"verdict"`
	Exploitability     string   `json:"exploitability"`
	Impact             string   `json:"impact"`
	EvidenceStrength   string   `json:"evidence_strength"`
	ReachabilityChecks []string `json:"reachability_checks"`
	ExclusionChecks    []string `json:"exclusion_checks"`
	RequiredFollowUp   []string `json:"required_follow_up"`
}

type DetectionChainComparison struct {
	Area             string   `json:"area"`
	CurrentStatus    string   `json:"current_status"`
	BaselineApproach string   `json:"baseline_approach"`
	Winner           string   `json:"winner"`
	Gap              string   `json:"gap"`
	Optimization     string   `json:"optimization"`
	Evidence         []string `json:"evidence,omitempty"`
}

type ReviewAgentTask struct {
	FindingID        string   `json:"finding_id"`
	AgentRole        string   `json:"agent_role"`
	Objective        string   `json:"objective"`
	Inputs           []string `json:"inputs"`
	StrictStandards  []string `json:"strict_standards"`
	Prompt           string   `json:"prompt"`
	ExpectedOutputs  []string `json:"expected_outputs"`
	BlockingCriteria []string `json:"blocking_criteria"`
}

type ReviewAgentVerdict struct {
	FindingID        string   `json:"finding_id"`
	Verdict          string   `json:"verdict"`
	Confidence       string   `json:"confidence"`
	Reason           string   `json:"reason"`
	MissingEvidence  []string `json:"missing_evidence,omitempty"`
	Fix              string   `json:"fix,omitempty"`
	Reviewer         string   `json:"reviewer"`
	StandardsApplied []string `json:"standards_applied,omitempty"`
}

type CapabilityConsistency struct {
	Capability      string   `json:"capability"`
	Declared        bool     `json:"declared"`
	StaticDetected  bool     `json:"static_detected"`
	LLMDetected     bool     `json:"llm_detected"`
	SandboxDetected bool     `json:"sandbox_detected"`
	TIObserved      bool     `json:"ti_observed"`
	Status          string   `json:"status"`
	RiskImpact      string   `json:"risk_impact"`
	Evidence        []string `json:"evidence,omitempty"`
	Gap             string   `json:"gap,omitempty"`
	NextStep        string   `json:"next_step"`
}

type ObfuscationEvidence struct {
	Path             string   `json:"path"`
	Technique        string   `json:"technique,omitempty"`
	Confidence       string   `json:"confidence,omitempty"`
	Summary          string   `json:"summary,omitempty"`
	DecodedText      string   `json:"decoded_text,omitempty"`
	BenignIndicators []string `json:"benign_indicators,omitempty"`
	RiskIndicators   []string `json:"risk_indicators,omitempty"`
	DataFlowSignals  []string `json:"data_flow_signals,omitempty"`
}

type AuditEvent struct {
	Type      string `json:"type"`
	StepID    string `json:"step_id"`
	Title     string `json:"title,omitempty"`
	Status    string `json:"status,omitempty"`
	Brief     string `json:"brief"`
	Detail    string `json:"detail,omitempty"`
	ToolName  string `json:"tool_name,omitempty"`
	Timestamp string `json:"timestamp"`
}

type ReviewAgentExecutionStats struct {
	Reviewer       string `json:"reviewer"`
	TaskCount      int    `json:"task_count"`
	WorkerCount    int    `json:"worker_count"`
	MaxConcurrency int    `json:"max_concurrency"`
	DurationMs     int64  `json:"duration_ms"`
	Failed         bool   `json:"failed,omitempty"`
	ErrorMessage   string `json:"error_message,omitempty"`
}

type Result struct {
	Findings             []plugins.Finding           `json:"findings"`
	Behavior             BehaviorProfile             `json:"behavior"`
	IntentDiffs          []IntentDiff                `json:"intent_diffs"`
	TIReputations        []TIReputation              `json:"ti_reputations"`
	Evasion              EvasionAssessment           `json:"evasion"`
	Summary              ScoreSummary                `json:"summary"`
	RuleEvidence         []FindingEvidence           `json:"rule_evidence"`
	Pipeline             []PipelineStage             `json:"pipeline,omitempty"`
	EvidenceInventory    []EvidenceInventory         `json:"evidence_inventory,omitempty"`
	OptimizationNotes    []OptimizationNote          `json:"optimization_notes,omitempty"`
	StructuredFindings   []StructuredFinding         `json:"structured_findings,omitempty"`
	VulnerabilityBlocks  []VulnerabilityBlock        `json:"vulnerability_blocks,omitempty"`
	RuleExplanations     []RuleExplanation           `json:"rule_explanations,omitempty"`
	FalsePositiveReviews []FalsePositiveReview       `json:"false_positive_reviews,omitempty"`
	DetectionComparison  []DetectionChainComparison  `json:"detection_chain_comparison,omitempty"`
	ReviewAgentTasks     []ReviewAgentTask           `json:"review_agent_tasks,omitempty"`
	ReviewAgentVerdicts  []ReviewAgentVerdict        `json:"review_agent_verdicts,omitempty"`
	ReviewAgentStats     []ReviewAgentExecutionStats `json:"review_agent_stats,omitempty"`
	CapabilityMatrix     []CapabilityConsistency     `json:"capability_matrix,omitempty"`
	ObfuscationEvidence  []ObfuscationEvidence       `json:"obfuscation_evidence,omitempty"`
	AuditEvents          []AuditEvent                `json:"audit_events,omitempty"`
}

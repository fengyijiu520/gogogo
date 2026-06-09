package review

import (
	"skill-scanner/internal/llm"
	"skill-scanner/internal/plugins"
)

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
	ExecutionScenarios []string            `json:"execution_scenarios,omitempty"`
	ScenarioExecutions []ScenarioExecution `json:"scenario_executions,omitempty"`
	SandboxSource      string              `json:"sandbox_source,omitempty"`
	SandboxVerdict     string              `json:"sandbox_verdict,omitempty"`
	SandboxScore       int                 `json:"sandbox_score,omitempty"`
	SandboxDurationMs  int64               `json:"sandbox_duration_ms,omitempty"`
	SandboxFallback    bool                `json:"sandbox_fallback,omitempty"`
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

	// zeroclaw 沙箱详细数据
	ZeroclawDNSQueries     []string `json:"zeroclaw_dns_queries,omitempty"`
	ZeroclawTCPConnections []string `json:"zeroclaw_tcp_connections,omitempty"`
	ZeroclawHTTPRequests   []string `json:"zeroclaw_http_requests,omitempty"`
	ZeroclawProcessTree    string   `json:"zeroclaw_process_tree,omitempty"`
	ZeroclawCommands       []string `json:"zeroclaw_commands,omitempty"`
	ZeroclawFileOps        []string `json:"zeroclaw_file_ops,omitempty"`
	ZeroclawDeclaredCaps   []string `json:"zeroclaw_declared_caps,omitempty"`
	ZeroclawObservedCaps   []string `json:"zeroclaw_observed_caps,omitempty"`
	ZeroclawConsistency    string   `json:"zeroclaw_consistency,omitempty"`
}

type ScenarioExecution struct {
	Name            string              `json:"name"`
	Command         string              `json:"command,omitempty"`
	ExitCode        int                 `json:"exit_code,omitempty"`
	HTTPPorts       []int               `json:"http_ports,omitempty"`
	HTTPPaths       []string            `json:"http_paths,omitempty"`
	HTTPPathMethods map[string][]string `json:"http_path_methods,omitempty"`
	HTTPMethod      string              `json:"http_method,omitempty"`
	HTTPPort        int                 `json:"http_port,omitempty"`
	HTTPPath        string              `json:"http_path,omitempty"`
	HTTPStatusCode  int                 `json:"http_status_code,omitempty"`
	Output          []string            `json:"output,omitempty"`
	InputFiles      []string            `json:"input_files,omitempty"`
	EnvKeys         []string            `json:"env_keys,omitempty"`
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
	Source     string  `json:"source,omitempty"`
	ThreatType string  `json:"threat_type,omitempty"`
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

type StructuredEvidenceItem struct {
	Location   string `json:"location,omitempty"`
	Snippet    string `json:"snippet,omitempty"`
	Summary    string `json:"summary,omitempty"`
	SourceType string `json:"source_type,omitempty"`
	Status     string `json:"status,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

type FindingClosure struct {
	Source         bool `json:"source"`
	Transform      bool `json:"transform"`
	Sink           bool `json:"sink"`
	RuntimeSupport bool `json:"runtime_support"`
}

type StructuredFinding struct {
	ID                   string                   `json:"id"`
	RuleID               string                   `json:"rule_id"`
	Title                string                   `json:"title"`
	Severity             string                   `json:"severity"`
	Category             string                   `json:"category"`
	SecurityVerdict      string                   `json:"security_verdict,omitempty"`
	DeclarationVerdict   string                   `json:"declaration_verdict,omitempty"`
	Confidence           string                   `json:"confidence"`
	AttackPath           string                   `json:"attack_path"`
	MITRETechniques      []string                 `json:"mitre_techniques,omitempty"`
	CodeEvidenceRefs     []string                 `json:"code_evidence_refs,omitempty"`
	BehaviorEvidenceRefs []string                 `json:"behavior_evidence_refs,omitempty"`
	ContextEvidenceRefs  []string                 `json:"context_evidence_refs,omitempty"`
	Evidence             []string                 `json:"evidence"`
	EvidenceItems        []StructuredEvidenceItem `json:"evidence_items,omitempty"`
	ExcludedEvidence     []StructuredEvidenceItem `json:"excluded_evidence,omitempty"`
	Closure              FindingClosure           `json:"closure,omitempty"`
	ChainSummaries       []string                 `json:"chain_summaries,omitempty"`
	Chains               []FindingChain           `json:"chains,omitempty"`
	ApplicabilityVerdict string                   `json:"applicability_verdict,omitempty"`
	ApplicabilityBasis   []string                 `json:"applicability_basis,omitempty"`
	CalibrationBasis     []string                 `json:"calibration_basis"`
	FalsePositiveChecks  []string                 `json:"false_positive_checks"`
	ReviewGuidance       string                   `json:"review_guidance"`
	Source               string                   `json:"source"`
	DeduplicatedCount    int                      `json:"deduplicated_count"`
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
	FindingID        string           `json:"finding_id"`
	AgentRole        string           `json:"agent_role"`
	Objective        string           `json:"objective"`
	Inputs           []string         `json:"inputs"`
	StrictStandards  []string         `json:"strict_standards"`
	Prompt           string           `json:"prompt"`
	StageContext     *LLMStageContext `json:"stage_context,omitempty"`
	ExpectedOutputs  []string         `json:"expected_outputs"`
	BlockingCriteria []string         `json:"blocking_criteria"`
}

type ReviewAgentVerdict struct {
	FindingID        string           `json:"finding_id"`
	Verdict          string           `json:"verdict"`
	Confidence       string           `json:"confidence"`
	Reason           string           `json:"reason"`
	MissingEvidence  []string         `json:"missing_evidence,omitempty"`
	Fix              string           `json:"fix,omitempty"`
	Reviewer         string           `json:"reviewer"`
	StandardsApplied []string         `json:"standards_applied,omitempty"`
	ToolTrace        []ToolTraceEntry `json:"tool_trace,omitempty"`
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

type ReviewTrace struct {
	Total               int                `json:"total"`
	Completed           int                `json:"completed"`
	CurrentFindingID    string             `json:"current_finding_id,omitempty"`
	CurrentFindingTitle string             `json:"current_finding_title,omitempty"`
	CurrentObjective    string             `json:"current_objective,omitempty"`
	CurrentSummary      string             `json:"current_summary,omitempty"`
	LastVerdict         string             `json:"last_verdict,omitempty"`
	LastReason          string             `json:"last_reason,omitempty"`
	LastDurationMs      int64              `json:"last_duration_ms,omitempty"`
	Failed              bool               `json:"failed,omitempty"`
	ErrorMessage        string             `json:"error_message,omitempty"`
	Entries             []ReviewTraceEntry `json:"entries,omitempty"`
}

type ReviewTraceEntry struct {
	FindingID        string           `json:"finding_id"`
	FindingTitle     string           `json:"finding_title,omitempty"`
	Objective        string           `json:"objective,omitempty"`
	PromptSummary    string           `json:"prompt_summary,omitempty"`
	InputDigest      []string         `json:"input_digest,omitempty"`
	StandardsApplied []string         `json:"standards_applied,omitempty"`
	Status           string           `json:"status"`
	FailureKind      string           `json:"failure_kind,omitempty"`
	FailureLabel     string           `json:"failure_label,omitempty"`
	Verdict          string           `json:"verdict,omitempty"`
	Confidence       string           `json:"confidence,omitempty"`
	Reviewer         string           `json:"reviewer,omitempty"`
	Reason           string           `json:"reason,omitempty"`
	MissingEvidence  []string         `json:"missing_evidence,omitempty"`
	Fix              string           `json:"fix,omitempty"`
	DurationMs       int64            `json:"duration_ms,omitempty"`
	ToolTrace        []ToolTraceEntry `json:"tool_trace,omitempty"`
	UpdatedAt        int64            `json:"updated_at"`
}

type Result struct {
	Findings                []plugins.Finding             `json:"findings"`
	Behavior                BehaviorProfile               `json:"behavior"`
	CrossFileConsolidation  *llm.CrossFileConsolidation   `json:"cross_file_consolidation,omitempty"`
	IntentDiffs             []IntentDiff                  `json:"intent_diffs"`
	TIReputations           []TIReputation                `json:"ti_reputations"`
	Evasion                 EvasionAssessment             `json:"evasion"`
	Summary                 ScoreSummary                  `json:"summary"`
	RuleEvidence            []FindingEvidence             `json:"rule_evidence"`
	Pipeline                []PipelineStage               `json:"pipeline,omitempty"`
	EvidenceInventory       []EvidenceInventory           `json:"evidence_inventory,omitempty"`
	OptimizationNotes       []OptimizationNote            `json:"optimization_notes,omitempty"`
	StructuredFindings      []StructuredFinding           `json:"structured_findings,omitempty"`
	VulnerabilityBlocks     []VulnerabilityBlock          `json:"vulnerability_blocks,omitempty"`
	RuleExplanations        []RuleExplanation             `json:"rule_explanations,omitempty"`
	FalsePositiveReviews    []FalsePositiveReview         `json:"false_positive_reviews,omitempty"`
	DetectionComparison     []DetectionChainComparison    `json:"detection_chain_comparison,omitempty"`
	ReviewAgentTasks        []ReviewAgentTask             `json:"review_agent_tasks,omitempty"`
	ReviewAgentVerdicts     []ReviewAgentVerdict          `json:"review_agent_verdicts,omitempty"`
	ReviewAgentStats        []ReviewAgentExecutionStats   `json:"review_agent_stats,omitempty"`
	ReviewTrace             *ReviewTrace                  `json:"review_trace,omitempty"`
	RemediationVerification RemediationVerificationResult `json:"remediation_verification,omitempty"`
	CapabilityMatrix        []CapabilityConsistency       `json:"capability_matrix,omitempty"`
	ObfuscationEvidence     []ObfuscationEvidence         `json:"obfuscation_evidence,omitempty"`
	AuditEvents             []AuditEvent                  `json:"audit_events,omitempty"`
}

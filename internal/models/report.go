package models

// Report represents a scan report stored in the system.
type Report struct {
	ID        string `json:"id"`
	TaskID    string `json:"task_id,omitempty"`
	Status    string `json:"status,omitempty"`
	Username  string `json:"username"`
	Team      string `json:"team"` // team of the user who created the report
	FileName  string `json:"file_name"`
	FilePath  string `json:"file_path"`
	HTMLPath  string `json:"html_path,omitempty"`
	JSONPath  string `json:"json_path,omitempty"`
	PDFPath   string `json:"pdf_path,omitempty"`
	PDFError  string `json:"pdf_error,omitempty"`
	CreatedAt int64  `json:"created_at"`
	// 旧的兼容字段
	FindingCount int  `json:"finding_count"`
	HighRisk     int  `json:"high_risk"`
	MediumRisk   int  `json:"medium_risk"`
	LowRisk      int  `json:"low_risk"`
	NoRisk       bool `json:"no_risk"`
	// 新的审查引擎字段
	Score            float64            `json:"score"`
	RiskLevel        string             `json:"risk_level"` // low, medium, high, critical
	Decision         string             `json:"decision,omitempty"`
	TrustScore       float64            `json:"trust_score,omitempty"`
	RiskScore        float64            `json:"risk_score,omitempty"`
	Exploitability   float64            `json:"exploitability,omitempty"`
	BusinessImpact   float64            `json:"business_impact,omitempty"`
	ICS              float64            `json:"ics,omitempty"`
	P0Blocked        bool               `json:"p0_blocked"`
	P0Reasons        []string           `json:"p0_reasons"`
	RuleTotal        int                `json:"rule_total,omitempty"`
	RuleEvaluated    int                `json:"rule_evaluated,omitempty"`
	RuleUnchecked    int                `json:"rule_unchecked,omitempty"`
	RuleUncheckedIDs []string           `json:"rule_unchecked_ids,omitempty"`
	CoverageNote     string             `json:"coverage_note,omitempty"`
	ItemScores       map[string]float64 `json:"item_scores"`
}

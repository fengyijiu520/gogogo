package report

type RiskCalibrationSummary struct {
	Policy             string   `json:"policy"`
	RiskLevel          string   `json:"risk_level"`
	Decision           string   `json:"decision"`
	UserActionRequired bool     `json:"user_action_required"`
	Basis              []string `json:"basis"`
	ConfidenceNotes    []string `json:"confidence_notes"`
}

type RiskCalibrationInput struct {
	RiskLevel             string
	Decision              string
	HighRisk              int
	MediumRisk            int
	LowRisk               int
	IntentDiffCount       int
	BehaviorCategoryCount int
	EvasionDetected       bool
	P0Detected            bool
	P0Reasons             []string
	FindingCount          int
	EvaluatedRules        int
	TotalRules            int
	UncheckedRules        []string
	IntentSummaryReady    bool
}

func BuildRiskCalibrationSummary(in RiskCalibrationInput) RiskCalibrationSummary {
	summary := RiskCalibrationSummary{
		Policy:             "系统按证据强度、风险级别、意图差异、行为证据和覆盖完整性校准风险；评分字段仅作辅助参考，不替用户做放行或拒绝判断，最终由用户基于证据决定如何整改和使用。",
		RiskLevel:          in.RiskLevel,
		Decision:           in.Decision,
		UserActionRequired: true,
	}
	summary.Basis = append(summary.Basis, buildRiskCountLine(in.HighRisk, in.MediumRisk, in.LowRisk))
	if in.IntentDiffCount > 0 {
		summary.Basis = append(summary.Basis, buildIntentDiffLine(in.IntentDiffCount))
	}
	if in.BehaviorCategoryCount > 0 {
		summary.Basis = append(summary.Basis, buildBehaviorCategoryLine(in.BehaviorCategoryCount))
	}
	if in.EvasionDetected {
		summary.Basis = append(summary.Basis, "检测到反沙箱或反虚拟机逃逸信号")
	}
	if in.P0Detected && len(in.P0Reasons) > 0 {
		summary.Basis = append(summary.Basis, buildP0ReasonLine(in.P0Reasons))
	}
	if in.FindingCount == 0 {
		summary.Basis = append(summary.Basis, "未产生结构化风险发现，但仍需用户结合业务授权和运行环境复核")
	}
	summary.ConfidenceNotes = append(summary.ConfidenceNotes, buildCoverageLine(in.EvaluatedRules, in.TotalRules))
	if len(in.UncheckedRules) > 0 {
		summary.ConfidenceNotes = append(summary.ConfidenceNotes, buildUncheckedRulesLine(in.UncheckedRules))
	} else {
		summary.ConfidenceNotes = append(summary.ConfidenceNotes, "当前已完成已配置规则集评估")
	}
	if in.IntentSummaryReady {
		summary.ConfidenceNotes = append(summary.ConfidenceNotes, "LLM 意图分析已参与校准")
	}
	summary.ConfidenceNotes = append(summary.ConfidenceNotes, "评分与分值字段仅作辅助参考，不单独决定最终风险结论。")
	return summary
}

type JSONReportPayloadInput struct {
	Generator              string
	HTMLReport             string
	TextReport             string
	Result                 any
	SkillAnalysisProfile   any
	RuleSetProfile         any
	RuleExplanations       any
	AnalysisTrace          any
	RiskCalibration        RiskCalibrationSummary
	IntentAnalysis         any
	RuleEvaluationRecords  any
	ObfuscationEvidence    any
	DecisionLabel          string
	RiskLevelLabel         string
	HighRisk               int
	MediumRisk             int
	LowRisk                int
	RiskScore              float64
	Exploitability         float64
	BusinessImpact         float64
	RemediationSuggestions []string
	Coverage               map[string]interface{}
	MITRESummary           map[string]interface{}
}

func BuildJSONReportPayload(in JSONReportPayloadInput) map[string]interface{} {
	return map[string]interface{}{
		"generator": in.Generator,
		"primary_report": map[string]interface{}{
			"source_format": "html",
			"html":          in.HTMLReport,
			"text":          in.TextReport,
		},
		"result":                  in.Result,
		"skill_analysis_profile":  in.SkillAnalysisProfile,
		"rule_set_profile":        in.RuleSetProfile,
		"rule_explanations":       in.RuleExplanations,
		"analysis_trace":          in.AnalysisTrace,
		"risk_calibration":        in.RiskCalibration,
		"intent_analysis_cn":      in.IntentAnalysis,
		"obfuscation_evidence":    in.ObfuscationEvidence,
		"rule_evaluation_records": in.RuleEvaluationRecords,
		"summary_cn": map[string]interface{}{
			"decision":        in.DecisionLabel,
			"risk_level":      in.RiskLevelLabel,
			"high_risk":       in.HighRisk,
			"medium_risk":     in.MediumRisk,
			"low_risk":        in.LowRisk,
			"risk_score":      in.RiskScore,
			"exploitability":  in.Exploitability,
			"business_impact": in.BusinessImpact,
		},
		"audience_views": map[string]interface{}{
			"developer": map[string]interface{}{
				"focus":   "代码定位、修复优先级、可执行改动",
				"summary": "优先修复高风险规则命中与可利用链路，逐条补齐边界校验、权限控制与回归测试。",
			},
			"security": map[string]interface{}{
				"focus":   "攻击路径、可利用性、证据闭环",
				"summary": "关注结构化风险的攻击路径和证据强度，确认是否达到阻断条件并保留审计追溯。",
			},
			"management": map[string]interface{}{
				"focus":   "风险趋势、处置状态、发布决策",
				"summary": "根据风险等级与处置进度决定发布窗口，要求高风险清零或形成书面例外审批。",
			},
		},
		"remediation_suggestions": in.RemediationSuggestions,
		"coverage":                in.Coverage,
		"mitre_summary":           in.MITRESummary,
	}
}

func buildRiskCountLine(high, medium, low int) string {
	return "风险发现汇总: 高风险 " + itoa(high) + " 项，中风险 " + itoa(medium) + " 项，低风险 " + itoa(low) + " 项"
}

func buildIntentDiffLine(count int) string {
	return "声明与行为差异: " + itoa(count) + " 项"
}

func buildBehaviorCategoryLine(count int) string {
	return "行为证据类别: " + itoa(count) + " 类"
}

func buildP0ReasonLine(reasons []string) string {
	joined := ""
	for i, reason := range reasons {
		if i > 0 {
			joined += "；"
		}
		joined += reason
	}
	return "存在 P0 高优先级风险原因: " + joined
}

func buildCoverageLine(evaluated, total int) string {
	return "规则评估覆盖: " + itoa(evaluated) + "/" + itoa(total)
}

func buildUncheckedRulesLine(items []string) string {
	joined := ""
	for i, item := range items {
		if i > 0 {
			joined += "，"
		}
		joined += item
	}
	return "存在未评估规则，需补齐后复扫: " + joined
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	negative := v < 0
	if negative {
		v = -v
	}
	buf := [20]byte{}
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	if negative {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

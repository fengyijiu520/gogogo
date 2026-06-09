package scoring

import "skill-scanner/internal/review"

type Engine struct{}

func NewEngine() *Engine {
	return &Engine{}
}

func (e *Engine) Compute(baseScore float64, p1Deduction float64, ics float64, tiAdjustment float64, veto bool, vetoReason string) review.ScoreSummary {
	summary := review.ScoreSummary{
		BaseScore:     baseScore,
		P1Deduction:   p1Deduction,
		ICS:           ics,
		TIAdjustment:  tiAdjustment,
		VetoTriggered: veto,
		VetoReason:    vetoReason,
	}

	trust := (baseScore - p1Deduction) * 0.6
	trust += ics * 0.3
	trust += (100 + tiAdjustment) * 0.1

	// 对高风险命中不做直接阻断，统一折算为最低信任分
	if veto {
		trust = 0
	}

	if trust > 100 {
		trust = 100
	}
	if trust < 0 {
		trust = 0
	}

	summary.TrustScore = trust
	summary.Exploitability = deriveExploitabilityScore(veto, p1Deduction, ics)
	summary.BusinessImpact = deriveBusinessImpactScore(baseScore, tiAdjustment)
	summary.RiskScore = deriveRiskScore(summary.Exploitability, summary.BusinessImpact)
	if veto {
		summary.RiskLevel = "high"
		summary.Admission = "Block"
		return summary
	}
	switch {
	case summary.RiskScore >= 8.5:
		summary.RiskLevel = "critical"
		summary.Admission = "Block"
	case summary.RiskScore >= 7.0:
		summary.RiskLevel = "high"
		summary.Admission = "Block"
	case summary.RiskScore >= 4.0:
		summary.RiskLevel = "medium"
		summary.Admission = "Review"
	case trust >= 85:
		summary.RiskLevel = "low"
		summary.Admission = "Pass"
	default:
		summary.RiskLevel = "low"
		summary.Admission = "Pass"
	}

	return summary
}

func (e *Engine) ComputeByRisk(high, medium, low int, veto bool, vetoReason string) review.ScoreSummary {
	summary := review.ScoreSummary{
		HighRisk:      high,
		MediumRisk:    medium,
		LowRisk:       low,
		VetoTriggered: veto,
		VetoReason:    vetoReason,
	}
	summary.Exploitability = deriveExploitabilityFromCounts(high, medium)
	summary.BusinessImpact = deriveBusinessImpactFromCounts(high, medium, low)
	summary.RiskScore = deriveRiskScore(summary.Exploitability, summary.BusinessImpact)
	if veto && high == 0 {
		high = 1
		summary.HighRisk = 1
	}
	switch {
	case summary.RiskScore >= 8.5:
		summary.RiskLevel = "critical"
		summary.Admission = "Block"
	case high > 0:
		summary.RiskLevel = "high"
		summary.Admission = "Block"
	case medium > 0:
		summary.RiskLevel = "medium"
		summary.Admission = "Review"
	default:
		summary.RiskLevel = "low"
		summary.Admission = "Pass"
	}
	return summary
}

func deriveExploitabilityScore(veto bool, p1Deduction float64, ics float64) float64 {
	base := 2.0
	if veto {
		base += 4.0
	}
	base += minMax(p1Deduction/20.0, 0, 2.5)
	base += minMax(ics/100.0*1.5, 0, 1.5)
	return minMax(base, 0, 10)
}

func deriveBusinessImpactScore(baseScore float64, tiAdjustment float64) float64 {
	impact := 1.5
	impact += minMax((100-baseScore)/20.0, 0, 3.0)
	if tiAdjustment < 0 {
		impact += minMax((-tiAdjustment)/20.0, 0, 2.0)
	}
	return minMax(impact, 0, 10)
}

func deriveExploitabilityFromCounts(high, medium int) float64 {
	return minMax(float64(high)*3.0+float64(medium)*1.2+1.0, 0, 10)
}

func deriveBusinessImpactFromCounts(high, medium, low int) float64 {
	return minMax(float64(high)*2.5+float64(medium)*1.0+float64(low)*0.2+1.0, 0, 10)
}

func deriveRiskScore(exploitability float64, businessImpact float64) float64 {
	return minMax(exploitability*0.6+businessImpact*0.4, 0, 10)
}

func minMax(v float64, minV float64, maxV float64) float64 {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

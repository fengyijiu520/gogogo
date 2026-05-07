package scoring

import "testing"

func TestComputeKeepsLowTrustAsReviewWithoutVeto(t *testing.T) {
	summary := NewEngine().Compute(10, 30, 20, -50, false, "")
	if summary.RiskLevel != "medium" || summary.Admission != "Review" {
		t.Fatalf("expected low trust without veto to remain review, got %+v", summary)
	}
}

func TestComputeVetoStillBlocks(t *testing.T) {
	summary := NewEngine().Compute(90, 0, 90, 0, true, "critical chain")
	if summary.RiskLevel != "high" || summary.Admission != "Block" || !summary.VetoTriggered {
		t.Fatalf("expected veto to block, got %+v", summary)
	}
}

func TestComputeRegressionSamples(t *testing.T) {
	tests := []struct {
		name          string
		baseScore     float64
		p1Deduction   float64
		ics           float64
		tiAdjustment  float64
		veto          bool
		wantRiskLevel string
		wantAdmission string
	}{
		{name: "高信任低风险", baseScore: 95, p1Deduction: 0, ics: 95, tiAdjustment: 0, veto: false, wantRiskLevel: "low", wantAdmission: "Pass"},
		{name: "低信任但无 veto 仅复核", baseScore: 10, p1Deduction: 30, ics: 20, tiAdjustment: -50, veto: false, wantRiskLevel: "medium", wantAdmission: "Review"},
		{name: "存在 veto 直接阻断", baseScore: 90, p1Deduction: 0, ics: 90, tiAdjustment: 0, veto: true, wantRiskLevel: "high", wantAdmission: "Block"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			summary := NewEngine().Compute(tc.baseScore, tc.p1Deduction, tc.ics, tc.tiAdjustment, tc.veto, "sample")
			if summary.RiskLevel != tc.wantRiskLevel || summary.Admission != tc.wantAdmission {
				t.Fatalf("expected %s/%s, got %+v", tc.wantRiskLevel, tc.wantAdmission, summary)
			}
		})
	}
}

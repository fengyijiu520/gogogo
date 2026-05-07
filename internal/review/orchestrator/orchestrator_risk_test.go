package orchestrator

import (
	"testing"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestDeriveCalibratedRiskCountsUsesStrongSignals(t *testing.T) {
	findings := []plugins.Finding{{Severity: "中风险"}}
	diffs := []review.IntentDiff{{Type: "unexpected_exec", Description: "声明未提及执行"}}
	reputations := []review.TIReputation{{Target: "example.test", Reputation: "suspicious"}}
	behavior := review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}}
	high, medium, low := deriveCalibratedRiskCounts(findings, diffs, reputations, behavior, review.EvasionAssessment{}, true, false)
	if high < 2 || medium < 1 || low != 0 {
		t.Fatalf("expected strong signals to raise calibrated counts, got %d/%d/%d", high, medium, low)
	}
}

func TestDeriveCalibratedRiskCountsDoesNotEscalateWeakSignalsToHigh(t *testing.T) {
	findings := []plugins.Finding{{Severity: "低风险"}}
	behavior := review.BehaviorProfile{ProbeWarnings: []string{"静态发现外联但沙箱未检出"}}
	high, medium, low := deriveCalibratedRiskCounts(findings, nil, nil, behavior, review.EvasionAssessment{}, false, false)
	if high != 0 || medium != 0 || low != 1 {
		t.Fatalf("expected weak warnings alone not to escalate, got %d/%d/%d", high, medium, low)
	}
}

func TestHasSuspiciousReputation(t *testing.T) {
	if !hasSuspiciousReputation([]review.TIReputation{{Reputation: "suspicious"}}) {
		t.Fatal("expected suspicious reputation to be detected")
	}
	if hasSuspiciousReputation([]review.TIReputation{{Reputation: "policy"}}) {
		t.Fatal("expected policy reputation not to be treated as threat signal")
	}
	if hasSuspiciousReputation([]review.TIReputation{{Reputation: "internal"}}) {
		t.Fatal("expected internal reputation not to be treated as threat signal")
	}
	if hasSuspiciousReputation([]review.TIReputation{{Reputation: "benign"}}) {
		t.Fatal("expected benign reputation not to be detected")
	}
}

func TestDeriveCalibratedRiskCountsRegressionSamples(t *testing.T) {
	tests := []struct {
		name         string
		findings     []plugins.Finding
		diffs        []review.IntentDiff
		reputations  []review.TIReputation
		behavior     review.BehaviorProfile
		evasion      review.EvasionAssessment
		malicious    bool
		behaviorVeto bool
		wantHigh     int
		wantMedium   int
		wantLow      int
	}{
		{
			name:       "弱探针告警不升级",
			findings:   []plugins.Finding{{Severity: "低风险"}},
			behavior:   review.BehaviorProfile{ProbeWarnings: []string{"静态发现外联但沙箱未检出"}},
			wantHigh:   0,
			wantMedium: 0,
			wantLow:    1,
		},
		{
			name:        "可疑信誉升为中风险辅助信号",
			findings:    []plugins.Finding{{Severity: "低风险"}},
			reputations: []review.TIReputation{{Reputation: "suspicious"}},
			wantHigh:    0,
			wantMedium:  1,
			wantLow:     1,
		},
		{
			name:        "策略信誉不按恶意情报升级",
			findings:    []plugins.Finding{{Severity: "低风险"}},
			reputations: []review.TIReputation{{Reputation: "policy"}},
			wantHigh:    0,
			wantMedium:  0,
			wantLow:     1,
		},
		{
			name:       "逃逸与恶意信号抬升高风险",
			findings:   []plugins.Finding{{Severity: "中风险"}},
			behavior:   review.BehaviorProfile{SequenceAlerts: []string{"命中防御规避后执行时序"}},
			evasion:    review.EvasionAssessment{Detected: true},
			malicious:  true,
			wantHigh:   1,
			wantMedium: 2,
			wantLow:    0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			high, medium, low := deriveCalibratedRiskCounts(tc.findings, tc.diffs, tc.reputations, tc.behavior, tc.evasion, tc.malicious, tc.behaviorVeto)
			if high != tc.wantHigh || medium != tc.wantMedium || low != tc.wantLow {
				t.Fatalf("expected %d/%d/%d, got %d/%d/%d", tc.wantHigh, tc.wantMedium, tc.wantLow, high, medium, low)
			}
		})
	}
}

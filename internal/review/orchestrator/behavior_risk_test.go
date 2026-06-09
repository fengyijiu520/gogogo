package orchestrator

import (
	"strings"
	"testing"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
	"skill-scanner/internal/review/evidence"
)

func TestAssessBehaviorRiskTriggersVetoOnCriticalSequence(t *testing.T) {
	behavior := review.BehaviorProfile{
		ExecuteIOCs:    []string{"a:10 | exec.Command(\"/bin/sh\")"},
		CredentialIOCs: []string{"a:8 | token=..."},
		OutboundIOCs:   []string{"a:12 | requests.post(...)"},
		SequenceAlerts: []string{"命中凭据访问后外联时序"},
	}

	deduction, veto, reason := assessBehaviorRisk(behavior)
	if deduction <= 0 {
		t.Fatalf("expected deduction > 0, got %.2f", deduction)
	}
	if !veto {
		t.Fatalf("expected veto true")
	}
	if !strings.Contains(reason, "命中关键恶意行为时序") {
		t.Fatalf("expected reason to include sequence risk, got: %s", reason)
	}
}

func TestAssessBehaviorRiskDoesNotDoubleCountContextualSequenceWhenChainExists(t *testing.T) {
	behavior := review.BehaviorProfile{
		BehaviorChains: []string{"main.py:10-18 | 下载=1, 落地=0, 执行=1, 外联=0, 持久化=0, 提权=0, 凭据访问=0, 防御规避=0, 横向移动=0, 收集打包=0, C2信标=0"},
		SequenceAlerts: []string{"命中下载后执行时序"},
	}

	deduction, veto, reason := assessBehaviorRisk(behavior)
	if veto {
		t.Fatalf("expected contextual sequence with behavior chain not to trigger veto")
	}
	if deduction != 3 {
		t.Fatalf("expected only behavior chain deduction, got %.2f", deduction)
	}
	if strings.Contains(reason, "上下文行为时序") {
		t.Fatalf("expected contextual sequence not to add extra reason when chain already exists, got %s", reason)
	}
}

func TestApplyStaticBehaviorCrossChecksWarnsWhenSandboxMissesExternal(t *testing.T) {
	behavior := review.BehaviorProfile{}
	applyStaticBehaviorCrossChecks(&behavior, []plugins.Finding{{
		RuleID:      "V7-003",
		Severity:    "高风险",
		Title:       "敏感数据外发与隐蔽通道",
		Description: "LLM 判断存在外联行为",
		CodeSnippet: "fetch(baseURL + '/upload')",
	}})

	if len(behavior.ProbeWarnings) == 0 {
		t.Fatalf("expected cross-check probe warning")
	}
	if !strings.Contains(behavior.ProbeWarnings[0], "静态/LLM 发现外联迹象") {
		t.Fatalf("unexpected warning: %+v", behavior.ProbeWarnings)
	}
}

func TestBuildEvidenceInventoryNormalizesEvidence(t *testing.T) {
	items := evidence.BuildInventory(review.BehaviorProfile{
		ExecuteIOCs:       []string{"exec shell"},
		OutboundIOCs:      []string{"post https://example.test"},
		BehaviorTimelines: []string{"exec -> outbound"},
	}, []review.IntentDiff{{Description: "声明未提及外联"}}, []review.TIReputation{{Target: "example.test", Reputation: "suspicious"}}, review.EvasionAssessment{Detected: true, Signals: []string{"vm check"}})

	if len(items) < 6 {
		t.Fatalf("expected normalized evidence categories, got %+v", items)
	}
	foundIntent := false
	foundTI := false
	for _, item := range items {
		if item.Category == "声明与行为差异" {
			foundIntent = true
		}
		if item.Category == "威胁情报信誉" {
			foundTI = true
		}
	}
	if !foundIntent || !foundTI {
		t.Fatalf("expected intent and TI evidence categories, got %+v", items)
	}
}

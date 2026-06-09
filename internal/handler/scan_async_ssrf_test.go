package handler

import (
	"testing"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestIsDirectlyConfirmedFindingConfirmsStrongSSRFEvidence(t *testing.T) {
	finding := review.StructuredFinding{
		RuleID:           "S2-P1-012",
		Title:            "SSRF-内网探测",
		Severity:         "高风险",
		Category:         "网络请求与SSRF",
		AttackPath:       "target_url 来自用户输入并进入 requests.get，可访问 metadata 和内网地址",
		Evidence:         []string{"client.py:88 requests.get(target_url)", "client.py:87 target_url = user_input"},
		CalibrationBasis: []string{"存在真实请求和可控目标"},
	}
	if !isDirectlyConfirmedFinding(finding, review.Result{}) {
		t.Fatalf("expected strong ssrf evidence directly confirmed, got false")
	}
}

func TestDeterministicVerdictDirectlyConfirmsStrongSSRFRisk(t *testing.T) {
	finding := review.StructuredFinding{
		ID:               "SF-SSRF-001",
		RuleID:           "S2-P1-012",
		Title:            "SSRF-内网探测",
		Severity:         "高风险",
		Category:         "网络请求与SSRF",
		Confidence:       "高",
		AttackPath:       "target_url 来自用户输入并进入 requests.get，可访问 metadata 和内网地址",
		Evidence:         []string{"client.py:88 requests.get(target_url)", "client.py:87 target_url = user_input"},
		CalibrationBasis: []string{"存在真实请求和可控目标"},
		ReviewGuidance:   "增加 host 白名单和协议限制。",
	}
	fp := review.FalsePositiveReview{FindingID: "SF-SSRF-001", EvidenceStrength: "中: 有定位或校准依据，但仍需补充入口可达性。"}
	verdict := deterministicVerdictForTask(review.ReviewAgentTask{FindingID: "SF-SSRF-001"}, finding, fp, review.Result{})
	if verdict.Verdict != "confirmed" {
		t.Fatalf("expected deterministic verdict confirmed, got %+v", verdict)
	}
}

func TestBuildStructuredFindingsMergesUndeclaredOutboundWithOutboundRisk(t *testing.T) {
	findings := []plugins.Finding{
		{PluginName: "SecurityEngine", RuleID: "V7-006", Severity: "高风险", Title: "敏感数据外发与隐蔽通道-未声明外联", Description: "检测到 webhook 未声明", Location: "polymarket.py:59", CodeSnippet: `requests.post(webhook, json={"content": msg})`},
		{PluginName: "BehaviorGuard", RuleID: "V7-003", Severity: "高风险", Title: "敏感数据外发与隐蔽通道", Description: "检测到外联行为", Location: "polymarket.py:59", CodeSnippet: `requests.post(webhook, json={"content": msg})`},
	}
	structured := buildStructuredFindings(findings, review.Result{}, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected undeclared outbound and outbound risk merged, got %+v", structured)
	}
	if structured[0].Title != "敏感数据外发与隐蔽通道" {
		t.Fatalf("expected normalized outbound title retained, got %+v", structured[0])
	}
	if structured[0].DeclarationVerdict != "undeclared" {
		t.Fatalf("expected declaration verdict undeclared, got %+v", structured[0])
	}
}

func TestBuildStructuredFindingKeepsDeclaredButConfirmedRisk(t *testing.T) {
	findings := []plugins.Finding{{
		PluginName:  "BehaviorGuard",
		RuleID:      "S2-P1-012",
		Severity:    "高风险",
		Title:       "SSRF-内网探测",
		Description: "技能已声明网络请求能力，但 target_url 仍由用户输入控制。",
		Location:    "client.py:88",
		CodeSnippet: `requests.get(target_url)`,
	}}
	refined := review.Result{Behavior: review.BehaviorProfile{BehaviorChains: []string{"client.py:87-88 | 外联=1"}}}
	structured := buildStructuredFindings(findings, refined, nil, "", nil)
	if len(structured) != 1 {
		t.Fatalf("expected one structured finding, got %+v", structured)
	}
	if structured[0].DeclarationVerdict != "declared" {
		t.Fatalf("expected declared verdict preserved, got %+v", structured[0])
	}
	if structured[0].SecurityVerdict != "confirmed" {
		t.Fatalf("expected security verdict confirmed, got %+v", structured[0])
	}
}

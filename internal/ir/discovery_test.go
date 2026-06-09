package ir

import (
	"fmt"
	"testing"
)

func TestRuleDiscoveryBasic(t *testing.T) {
	results := []ScanResult{
		{
			ScanID:    "scan-1",
			SkillName: "skill-a",
			Findings: []Finding{
				{RuleID: "r1", Category: "command_exec", Description: "os.system() called", Location: "a.py:5"},
				{RuleID: "r2", Category: "network_access", Description: "requests.post() called", Location: "a.py:8"},
			},
		},
		{
			ScanID:    "scan-2",
			SkillName: "skill-b",
			Findings: []Finding{
				{RuleID: "r3", Category: "command_exec", Description: "os.system() called", Location: "b.py:3"},
				{RuleID: "r4", Category: "network_access", Description: "requests.post() called", Location: "b.py:7"},
			},
		},
		{
			ScanID:    "scan-3",
			SkillName: "skill-c",
			Findings: []Finding{
				{RuleID: "r5", Category: "command_exec", Description: "os.system() called", Location: "c.py:10"},
			},
		},
	}

	engine := NewRuleDiscoveryEngine(2, 0.2)
	discovered := engine.Discover(results)

	fmt.Printf("=== 规则发现基本测试 ===\n")
	fmt.Printf("Discovered: %d rules\n", len(discovered))
	for _, r := range discovered {
		fmt.Printf("  - %s\n", FormatDiscoveredRule(r))
	}

	if len(discovered) == 0 {
		t.Error("should discover at least one rule from repeated patterns")
	}
}

func TestRuleDiscoveryWithVerdicts(t *testing.T) {
	results := []ScanResult{
		{
			ScanID: "scan-1",
			Findings: []Finding{
				{RuleID: "f1", Category: "command_exec", Description: "exec() called"},
			},
			Verdicts: []FindingVerdict{
				{FindingID: "f1", Verdict: "confirmed"},
			},
		},
		{
			ScanID: "scan-2",
			Findings: []Finding{
				{RuleID: "f2", Category: "command_exec", Description: "exec() called"},
			},
			Verdicts: []FindingVerdict{
				{FindingID: "f2", Verdict: "confirmed"},
			},
		},
		{
			ScanID: "scan-3",
			Findings: []Finding{
				{RuleID: "f3", Category: "command_exec", Description: "exec() called"},
			},
			Verdicts: []FindingVerdict{
				{FindingID: "f3", Verdict: "dismissed"},
			},
		},
	}

	engine := NewRuleDiscoveryEngine(2, 0.3)
	discovered := engine.Discover(results)

	fmt.Printf("=== 有判定的规则发现 ===\n")
	for _, r := range discovered {
		fmt.Printf("  - %s\n", FormatDiscoveredRule(r))
		fmt.Printf("    确认=%d, 驳回=%d\n", r.ConfirmedCount, r.DismissedCount)
	}
}

func TestRuleDiscoveryNoPattern(t *testing.T) {
	// 每个类别只出现一次，不应发现规则
	results := []ScanResult{
		{
			ScanID: "scan-1",
			Findings: []Finding{
				{RuleID: "r1", Category: "command_exec", Description: "os.system()"},
			},
		},
		{
			ScanID: "scan-2",
			Findings: []Finding{
				{RuleID: "r2", Category: "network_access", Description: "requests.post()"},
			},
		},
	}

	engine := NewRuleDiscoveryEngine(2, 0.3)
	discovered := engine.Discover(results)

	fmt.Printf("=== 无重复模式测试 ===\n")
	fmt.Printf("Discovered: %d (expected 0)\n", len(discovered))

	if len(discovered) > 0 {
		t.Error("should not discover rules from non-repeated patterns")
	}
}

func TestFeedbackProcessor(t *testing.T) {
	processor := NewFeedbackProcessor()

	// 初始权重应为 1.0
	w := processor.GetWeight("rule-1")
	if w != 1.0 {
		t.Errorf("expected initial weight 1.0, got %.2f", w)
	}

	// 处理确认反馈
	adjustments := processor.ProcessFeedback([]FeedbackEntry{
		{RuleID: "rule-1", Feedback: "confirmed"},
		{RuleID: "rule-1", Feedback: "confirmed"},
		{RuleID: "rule-2", Feedback: "dismissed"},
	})

	fmt.Printf("=== 反馈处理测试 ===\n")
	for _, a := range adjustments {
		fmt.Printf("  %s: %.2f → %.2f (%s)\n", a.RuleID, a.OldWeight, a.NewWeight, a.Reason)
	}

	// rule-1 应该权重提升
	w1 := processor.GetWeight("rule-1")
	if w1 <= 1.0 {
		t.Errorf("rule-1 weight should be > 1.0 after confirmation, got %.2f", w1)
	}

	// rule-2 应该权重降低
	w2 := processor.GetWeight("rule-2")
	if w2 >= 1.0 {
		t.Errorf("rule-2 weight should be < 1.0 after dismissal, got %.2f", w2)
	}
}

func TestFeedbackLoop(t *testing.T) {
	processor := NewFeedbackProcessor()

	// 模拟多次驳回
	for i := 0; i < 5; i++ {
		processor.ProcessFeedback([]FeedbackEntry{
			{RuleID: "noisy-rule", Feedback: "dismissed"},
		})
	}

	w := processor.GetWeight("noisy-rule")
	fmt.Printf("=== 反馈循环测试 ===\n")
	fmt.Printf("noisy-rule weight after 5 dismissals: %.2f\n", w)

	if w > 0.5 {
		t.Errorf("noisy-rule weight should be low after many dismissals, got %.2f", w)
	}

	// 模拟确认恢复
	for i := 0; i < 3; i++ {
		processor.ProcessFeedback([]FeedbackEntry{
			{RuleID: "noisy-rule", Feedback: "confirmed"},
		})
	}

	w2 := processor.GetWeight("noisy-rule")
	fmt.Printf("noisy-rule weight after 3 confirmations: %.2f\n", w2)

	if w2 <= w {
		t.Error("weight should increase after confirmations")
	}
}

func TestDiscoveredRulesToIRRules(t *testing.T) {
	discovered := []DiscoveredRule{
		{
			ID:              "auto-cmd-exec",
			Name:            "自动发现: os.system 模式",
			Category:        "command_exec",
			Severity:        "高风险",
			FuncNamePattern: "os.system",
		},
		{
			ID:       "auto-network",
			Name:     "自动发现: network 模式",
			Category: "network_access",
			Severity: "中风险",
		},
	}

	irRules := DiscoveredRulesToIRRules(discovered)

	fmt.Printf("=== 转换为 IR 规则 ===\n")
	for _, r := range irRules {
		fmt.Printf("  %s: type=%s\n", r.ID, r.Detection.Type)
	}

	if len(irRules) != 2 {
		t.Errorf("expected 2 IR rules, got %d", len(irRules))
	}
}

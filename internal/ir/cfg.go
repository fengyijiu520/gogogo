package ir

import (
	"fmt"
	"strings"
)

// =============================================================================
// 控制流图 (Control Flow Graph)
//
// CFG 是深层分析的基础，用于：
//   1. 识别分支条件（if/else/switch）
//   2. 识别循环结构（for/while）
//   3. 过滤不可达路径（减少误报）
//   4. 为污点分析提供路径上下文
//
// 设计：基于 AST 节点构建轻量级 CFG，不依赖完整的字节码。
// =============================================================================

// CFG 控制流图。
type CFG struct {
	// Nodes 基本块列表
	Nodes []*CFGNode `json:"nodes"`
	// Edges 控制流边
	Edges []CFGEdge `json:"edges"`
	// Entry 入口节点
	Entry *CFGNode `json:"-"`
	// Exit 出口节点
	Exit *CFGNode `json:"-"`
}

// CFGNode 基本块。
type CFGNode struct {
	// ID 唯一标识
	ID string `json:"id"`
	// Kind 节点类型
	Kind CFGNodeKind `json:"kind"`
	// StartLine 起始行号
	StartLine int `json:"start_line"`
	// EndLine 结束行号
	EndLine int `json:"end_line"`
	// Calls 块内的调用表达式
	Calls []CallExpr `json:"calls,omitempty"`
	// Assignments 块内的赋值
	Assignments []Assignment `json:"assignments,omitempty"`
	// Condition 分支条件（if/while/for 的条件表达式）
	Condition string `json:"condition,omitempty"`
	// Successors 后继节点
	Successors []*CFGNode `json:"-"`
	// Predecessors 前驱节点
	Predecessors []*CFGNode `json:"-"`
}

// CFGNodeKind 基本块类型。
type CFGNodeKind string

const (
	CFGNodeEntry     CFGNodeKind = "entry"      // 入口
	CFGNodeExit      CFGNodeKind = "exit"       // 出口
	CFGNodeNormal    CFGNodeKind = "normal"     // 普通块
	CFGNodeBranch    CFGNodeKind = "branch"     // 分支（if/else）
	CFGNodeLoop      CFGNodeKind = "loop"       // 循环（for/while）
	CFGNodeCall      CFGNodeKind = "call"       // 函数调用
	CFGNodeReturn    CFGNodeKind = "return"     // 返回
	CFGNodeTryCatch  CFGNodeKind = "try_catch"  // 异常处理
)

// CFGEdge 控制流边。
type CFGEdge struct {
	// From 源节点
	From *CFGNode `json:"-"`
	// To 目标节点
	To *CFGNode `json:"-"`
	// Kind 边类型
	Kind CFGEdgeKind `json:"kind"`
	// Condition 条件（分支边）
	Condition string `json:"condition,omitempty"`
}

// CFGEdgeKind 边类型。
type CFGEdgeKind string

const (
	CFGEdgeNormal    CFGEdgeKind = "normal"     // 顺序流
	CFGEdgeTrue      CFGEdgeKind = "true"       // 条件为真
	CFGEdgeFalse     CFGEdgeKind = "false"      // 条件为假
	CFGEdgeLoop      CFGEdgeKind = "loop"       // 循环回边
	CFGEdgeException CFGEdgeKind = "exception"  // 异常边
)

// =============================================================================
// CFG 构建器
// =============================================================================

// CFGBuilder CFG 构建器。
type CFGBuilder struct {
	nodeCounter int
	edges       []CFGEdge
}

// NewCFGBuilder 创建 CFG 构建器。
func NewCFGBuilder() *CFGBuilder {
	return &CFGBuilder{}
}

// BuildFromFunction 从函数构建 CFG。
func (b *CFGBuilder) BuildFromFunction(fn Function, file File) *CFG {
	cfg := &CFG{}

	// 创建入口和出口节点
	entry := b.newNode(CFGNodeEntry, fn.StartLine, fn.StartLine)
	exit := b.newNode(CFGNodeExit, fn.EndLine, fn.EndLine)
	cfg.Entry = entry
	cfg.Exit = exit
	cfg.Nodes = append(cfg.Nodes, entry, exit)
	cfg.Edges = []CFGEdge{} // 初始化边列表

	// 从函数体构建基本块
	bodyNodes := b.buildBody(fn, file)
	cfg.Nodes = append(cfg.Nodes, bodyNodes...)

	// 连接入口到第一个块
	if len(bodyNodes) > 0 {
		b.addEdge(entry, bodyNodes[0], CFGEdgeNormal)
	} else {
		b.addEdge(entry, exit, CFGEdgeNormal)
	}

	// 连接所有没有后继的节点到出口
	for _, node := range bodyNodes {
		if len(node.Successors) == 0 {
			b.addEdge(node, exit, CFGEdgeNormal)
		}
	}

	// 复制边到 CFG
	cfg.Edges = b.edges

	return cfg
}

// buildBody 从函数体构建基本块。
func (b *CFGBuilder) buildBody(fn Function, file File) []*CFGNode {
	var nodes []*CFGNode

	// 简化实现：将函数体分解为基本块
	// 1. 普通语句 → 一个块
	// 2. if/else → 分支节点 + 两个分支块
	// 3. for/while → 循环节点 + 循环体块
	// 4. return → 返回节点

	lines := strings.Split(file.RawContent, "\n")
	startIdx := fn.StartLine - 1
	endIdx := fn.EndLine
	if startIdx < 0 {
		startIdx = 0
	}
	if endIdx > len(lines) {
		endIdx = len(lines)
	}

	// 创建一个普通块收集连续的语句
	currentBlock := b.newNode(CFGNodeNormal, startIdx+1, startIdx+1)
	currentBlock.Calls = fn.Calls
	currentBlock.Assignments = fn.Assignments

	for i := startIdx; i < endIdx; i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}

		// 检查是否为控制流语句
		if isIfStatement(line) {
			// 保存当前块
			nodes = append(nodes, currentBlock)

			// 创建分支节点
			branchNode := b.newNode(CFGNodeBranch, i+1, i+1)
			branchNode.Condition = extractCondition(line)
			nodes = append(nodes, branchNode)

			// 创建分支结束后的合并块
			mergeBlock := b.newNode(CFGNodeNormal, i+2, i+2)

			// 连接：当前块 → 分支节点
			b.addEdge(currentBlock, branchNode, CFGEdgeNormal)
			// 分支节点 → 合并块（简化：不展开分支体）
			b.addEdge(branchNode, mergeBlock, CFGEdgeTrue)
			b.addEdge(branchNode, mergeBlock, CFGEdgeFalse)

			// 开始新块
			currentBlock = mergeBlock
			continue
		}

		if isForStatement(line) || isWhileStatement(line) {
			// 保存当前块
			nodes = append(nodes, currentBlock)

			// 创建循环节点
			loopNode := b.newNode(CFGNodeLoop, i+1, i+1)
			loopNode.Condition = extractCondition(line)
			nodes = append(nodes, loopNode)

			// 创建循环结束后的块
			afterLoop := b.newNode(CFGNodeNormal, i+2, i+2)

			// 连接：当前块 → 循环节点
			b.addEdge(currentBlock, loopNode, CFGEdgeNormal)
			// 循环节点 → 循环体（简化）
			b.addEdge(loopNode, afterLoop, CFGEdgeTrue)
			// 循环节点 → 循环后（跳出）
			b.addEdge(loopNode, afterLoop, CFGEdgeFalse)

			// 开始新块
			currentBlock = afterLoop
			continue
		}

		if isReturnStatement(line) {
			// 保存当前块
			nodes = append(nodes, currentBlock)

			// 创建返回节点
			retNode := b.newNode(CFGNodeReturn, i+1, i+1)
			nodes = append(nodes, retNode)

			// 连接：当前块 → 返回节点
			b.addEdge(currentBlock, retNode, CFGEdgeNormal)

			// 开始新块（return 后的代码不可达）
			currentBlock = b.newNode(CFGNodeNormal, i+2, i+2)
			continue
		}

		if isTryStatement(line) {
			// 保存当前块
			nodes = append(nodes, currentBlock)

			// 创建 try-catch 节点
			tryNode := b.newNode(CFGNodeTryCatch, i+1, i+1)
			nodes = append(nodes, tryNode)

			// 创建 try 结束后的块
			afterTry := b.newNode(CFGNodeNormal, i+2, i+2)

			// 连接
			b.addEdge(currentBlock, tryNode, CFGEdgeNormal)
			b.addEdge(tryNode, afterTry, CFGEdgeNormal)
			b.addEdge(tryNode, afterTry, CFGEdgeException)

			// 开始新块
			currentBlock = afterTry
			continue
		}

		// 普通语句，累积到当前块
		currentBlock.EndLine = i + 1
	}

	// 保存最后一个块
	nodes = append(nodes, currentBlock)

	return nodes
}

// newNode 创建新节点。
func (b *CFGBuilder) newNode(kind CFGNodeKind, startLine, endLine int) *CFGNode {
	b.nodeCounter++
	return &CFGNode{
		ID:        fmt.Sprintf("bb_%d", b.nodeCounter),
		Kind:      kind,
		StartLine: startLine,
		EndLine:   endLine,
	}
}

// addEdge 添加边。
func (b *CFGBuilder) addEdge(from, to *CFGNode, kind CFGEdgeKind) {
	edge := CFGEdge{
		From: from,
		To:   to,
		Kind: kind,
	}
	b.edges = append(b.edges, edge)
	from.Successors = append(from.Successors, to)
	to.Predecessors = append(to.Predecessors, from)
}

// =============================================================================
// CFG 分析
// =============================================================================

// FindReachableNodes 从入口节点查找所有可达节点。
func (cfg *CFG) FindReachableNodes() map[string]bool {
	reachable := make(map[string]bool)
	if cfg.Entry == nil {
		return reachable
	}

	queue := []*CFGNode{cfg.Entry}
	reachable[cfg.Entry.ID] = true

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		for _, succ := range node.Successors {
			if !reachable[succ.ID] {
				reachable[succ.ID] = true
				queue = append(queue, succ)
			}
		}
	}

	return reachable
}

// FindBackEdges 查找回边（循环边）。
func (cfg *CFG) FindBackEdges() []CFGEdge {
	var backEdges []CFGEdge
	visited := make(map[string]bool)
	inStack := make(map[string]bool)

	var dfs func(node *CFGNode)
	dfs = func(node *CFGNode) {
		visited[node.ID] = true
		inStack[node.ID] = true

		for _, succ := range node.Successors {
			if inStack[succ.ID] {
				// 回边
				backEdges = append(backEdges, CFGEdge{
					From: node,
					To:   succ,
					Kind: CFGEdgeLoop,
				})
			} else if !visited[succ.ID] {
				dfs(succ)
			}
		}

		inStack[node.ID] = false
	}

	if cfg.Entry != nil {
		dfs(cfg.Entry)
	}

	return backEdges
}

// IsReachable 检查从 from 到 to 是否可达。
func (cfg *CFG) IsReachable(from, to *CFGNode) bool {
	if from == nil || to == nil {
		return false
	}

	visited := make(map[string]bool)
	queue := []*CFGNode{from}
	visited[from.ID] = true

	for len(queue) > 0 {
		node := queue[0]
		queue = queue[1:]

		if node.ID == to.ID {
			return true
		}

		for _, succ := range node.Successors {
			if !visited[succ.ID] {
				visited[succ.ID] = true
				queue = append(queue, succ)
			}
		}
	}

	return false
}

// GetBranches 获取分支节点的 true/false 分支。
func (cfg *CFG) GetBranches(branchNode *CFGNode) (trueBranch, falseBranch *CFGNode) {
	for _, succ := range branchNode.Successors {
		for _, edge := range cfg.Edges {
			if edge.From == branchNode && edge.To == succ {
				if edge.Kind == CFGEdgeTrue {
					trueBranch = succ
				} else if edge.Kind == CFGEdgeFalse {
					falseBranch = succ
				}
			}
		}
	}
	// 如果没有明确的 true/false 边，返回前两个后继
	if trueBranch == nil && len(branchNode.Successors) > 0 {
		trueBranch = branchNode.Successors[0]
	}
	if falseBranch == nil && len(branchNode.Successors) > 1 {
		falseBranch = branchNode.Successors[1]
	}
	return
}

// String 返回 CFG 的文本表示。
func (cfg *CFG) String() string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("CFG: %d nodes, %d edges\n", len(cfg.Nodes), len(cfg.Edges)))
	for _, node := range cfg.Nodes {
		sb.WriteString(fmt.Sprintf("  %s [%s] L%d-%d", node.ID, node.Kind, node.StartLine, node.EndLine))
		if node.Condition != "" {
			sb.WriteString(fmt.Sprintf(" cond=%s", node.Condition))
		}
		sb.WriteString(" →")
		for _, succ := range node.Successors {
			sb.WriteString(fmt.Sprintf(" %s", succ.ID))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

// =============================================================================
// 辅助函数
// =============================================================================

func isIfStatement(line string) bool {
	return strings.HasPrefix(line, "if ") || strings.HasPrefix(line, "if(") ||
		strings.HasPrefix(line, "} else if") || strings.HasPrefix(line, "} else {")
}

func isForStatement(line string) bool {
	return strings.HasPrefix(line, "for ") || strings.HasPrefix(line, "for(")
}

func isWhileStatement(line string) bool {
	return strings.HasPrefix(line, "while ") || strings.HasPrefix(line, "while(")
}

func isReturnStatement(line string) bool {
	return strings.HasPrefix(line, "return ") || strings.HasPrefix(line, "return(") ||
		line == "return"
}

func isTryStatement(line string) bool {
	return strings.HasPrefix(line, "try") || strings.HasPrefix(line, "try {") ||
		strings.HasPrefix(line, "try:")
}

func extractCondition(line string) string {
	// 提取条件表达式（简化版）
	if idx := strings.Index(line, "("); idx >= 0 {
		if endIdx := strings.LastIndex(line, ")"); endIdx > idx {
			return line[idx+1 : endIdx]
		}
	}
	// Python 风格
	if strings.HasPrefix(line, "if ") {
		cond := strings.TrimPrefix(line, "if ")
		cond = strings.TrimSuffix(cond, ":")
		return cond
	}
	return line
}

// =============================================================================
// CFG 增强的污点分析
// =============================================================================

// CFGTaintAnalyzer CFG 增强的污点分析器。
type CFGTaintAnalyzer struct {
	base      *TaintAnalyzer
	builder   *CFGBuilder
	cfgCache  map[string]*CFG // file:path → CFG
}

// NewCFGTaintAnalyzer 创建 CFG 增强的污点分析器。
func NewCFGTaintAnalyzer(rules []TaintRule) *CFGTaintAnalyzer {
	return &CFGTaintAnalyzer{
		base:     NewTaintAnalyzer(rules),
		builder:  NewCFGBuilder(),
		cfgCache: make(map[string]*CFG),
	}
}

// AnalyzeWithCFG 使用 CFG 增强的污点分析。
func (a *CFGTaintAnalyzer) AnalyzeWithCFG(files []File) []TaintFinding {
	// 先用基础分析器
	baseFindings := a.base.Analyze(files)

	// 预构建所有函数的 CFG
	for _, file := range files {
		for _, fn := range file.Functions {
			key := file.Path + ":" + fn.Name
			if _, ok := a.cfgCache[key]; !ok {
				a.cfgCache[key] = a.builder.BuildFromFunction(fn, file)
			}
		}
	}

	// 用 CFG 过滤不可达路径
	var filtered []TaintFinding
	for _, finding := range baseFindings {
		if a.isReachableFinding(finding, files) {
			filtered = append(filtered, finding)
		}
	}

	return filtered
}

// isReachableFinding 检查发现是否在可达路径上。
// 通过 CFG 检查 finding 所在行是否从函数入口可达。
func (a *CFGTaintAnalyzer) isReachableFinding(finding TaintFinding, files []File) bool {
	if finding.Location == "" {
		return true // 无位置信息，保守保留
	}

	// 解析位置信息获取文件路径和行号
	filePath, lineNum := parseLocation(finding.Location)
	if filePath == "" || lineNum <= 0 {
		return true // 无法解析，保守保留
	}

	// 查找对应的文件和函数
	for _, file := range files {
		if !strings.HasSuffix(file.Path, filePath) && file.Path != filePath {
			continue
		}
		for _, fn := range file.Functions {
			if lineNum < fn.StartLine || lineNum > fn.EndLine {
				continue
			}
			// 找到包含此行的函数，检查 CFG 可达性
			key := file.Path + ":" + fn.Name
			cfg, ok := a.cfgCache[key]
			if !ok || cfg == nil || cfg.Entry == nil {
				return true // 无 CFG，保守保留
			}

			// 找到包含此行的基本块
			targetBlock := a.findBlockByLine(cfg, lineNum)
			if targetBlock == nil {
				return true // 找不到块，保守保留
			}

			// 检查从入口是否可达
			return cfg.IsReachable(cfg.Entry, targetBlock)
		}
	}

	return true // 找不到对应函数，保守保留
}

// findBlockByLine 在 CFG 中查找包含指定行号的基本块。
func (a *CFGTaintAnalyzer) findBlockByLine(cfg *CFG, lineNum int) *CFGNode {
	for _, node := range cfg.Nodes {
		if node.Kind == CFGNodeEntry || node.Kind == CFGNodeExit {
			continue
		}
		if lineNum >= node.StartLine && lineNum <= node.EndLine {
			return node
		}
	}
	return nil
}

// parseLocation 解析位置字符串（如 "file.py:10" 或 "file.py:10-15"）。
func parseLocation(loc string) (string, int) {
	// 格式: "file.py:10" 或 "file.py:10-15"
	idx := strings.LastIndex(loc, ":")
	if idx < 0 {
		return "", 0
	}
	filePath := loc[:idx]
	lineStr := loc[idx+1:]

	// 处理 "10-15" 格式，取起始行
	if dashIdx := strings.Index(lineStr, "-"); dashIdx >= 0 {
		lineStr = lineStr[:dashIdx]
	}

	lineNum := 0
	for _, c := range lineStr {
		if c >= '0' && c <= '9' {
			lineNum = lineNum*10 + int(c-'0')
		} else {
			break
		}
	}
	return filePath, lineNum
}

package ir

import (
	"fmt"
	"sort"
	"strings"
)

// =============================================================================
// 调用图 (Call Graph)
//
// 调用图是深层分析的基础设施，用于：
//   - 追踪函数之间的调用关系
//   - 识别危险调用链（如 main → handler → exec.Command）
//   - 过程间分析的基础
//   - 识别不可达代码
// =============================================================================

// CallGraph 表示项目的调用图。
type CallGraph struct {
	// Nodes 函数节点（key 为函数唯一标识）
	Nodes map[string]*CallNode `json:"nodes"`
	// Edges 调用边列表
	Edges []CallEdge `json:"edges"`
	// EntryPoints 入口点列表（main 函数、导出函数等）
	EntryPoints []string `json:"entry_points"`
}

// CallNode 调用图中的函数节点。
type CallNode struct {
	// ID 唯一标识（如 "file.py:func_name"）
	ID string `json:"id"`
	// Name 函数简单名称
	Name string `json:"name"`
	// QualifiedName 限定名
	QualifiedName string `json:"qualified_name"`
	// File 所在文件路径
	File string `json:"file"`
	// StartLine 起始行号
	StartLine int `json:"start_line"`
	// EndLine 结束行号
	EndLine int `json:"end_line"`
	// IsExported 是否导出
	IsExported bool `json:"is_exported"`
	// IsEntry 是否为入口点
	IsEntry bool `json:"is_entry"`
	// Calls 函数内的调用表达式
	Calls []CallExpr `json:"calls"`
	// Params 参数列表
	Params []Parameter `json:"params"`
	// Callers 调用此函数的节点 ID
	Callers []string `json:"callers"`
	// Callees 此函数调用的节点 ID
	Callees []string `json:"callees"`
	// ExternalCalls 无法解析到项目内函数的外部调用
	ExternalCalls []CallExpr `json:"external_calls"`
	// SecurityTags 安全标签（如 "has_command_exec", "has_network_access"）
	SecurityTags []string `json:"security_tags"`
}

// CallEdge 调用图中的边。
type CallEdge struct {
	// Caller 调用者节点 ID
	Caller string `json:"caller"`
	// Callee 被调用者节点 ID（或外部函数名）
	Callee string `json:"callee"`
	// CallSite 调用位置（文件:行号）
	CallSite string `json:"call_site"`
	// IsExternal 是否为外部调用
	IsExternal bool `json:"is_external"`
}

// CallChain 调用链。
type CallChain struct {
	// Nodes 从入口到当前函数的路径
	Nodes []string `json:"nodes"`
	// Length 链长度
	Length int `json:"length"`
	// HasDangerousCall 链中是否包含危险调用
	HasDangerousCall bool `json:"has_dangerous_call"`
	// DangerousCalls 链中的危险调用列表
	DangerousCalls []CallExpr `json:"dangerous_calls"`
}

// =============================================================================
// 调用图构建器
// =============================================================================

// CallGraphBuilder 调用图构建器。
type CallGraphBuilder struct {
	// funcIndex 函数索引：key 为 (file, funcName)，value 为节点 ID
	funcIndex map[string]string
}

// NewCallGraphBuilder 创建调用图构建器。
func NewCallGraphBuilder() *CallGraphBuilder {
	return &CallGraphBuilder{
		funcIndex: make(map[string]string),
	}
}

// Build 从文件列表构建调用图。
func (b *CallGraphBuilder) Build(files []File) *CallGraph {
	graph := &CallGraph{
		Nodes: make(map[string]*CallNode),
	}

	// 第一遍：注册所有函数节点
	for _, file := range files {
		b.registerFileFunctions(file, graph)
	}

	// 第二遍：解析调用关系
	for _, file := range files {
		b.resolveFileCalls(file, graph)
	}

	// 第三遍：计算安全标签和入口点
	b.computeSecurityTags(graph)
	b.identifyEntryPoints(graph)

	return graph
}

// registerFileFunctions 注册文件中的所有函数。
func (b *CallGraphBuilder) registerFileFunctions(file File, graph *CallGraph) {
	for _, fn := range file.Functions {
		nodeID := b.makeNodeID(file.Path, fn.Name)
		node := &CallNode{
			ID:            nodeID,
			Name:          fn.Name,
			QualifiedName: fn.QualifiedName,
			File:          file.Path,
			StartLine:     fn.StartLine,
			EndLine:       fn.EndLine,
			IsExported:    fn.IsExported,
			Calls:         fn.Calls,
			Params:        fn.Parameters,
		}
		graph.Nodes[nodeID] = node

		// 索引：全限定名
		indexKey := file.Path + ":" + fn.Name
		b.funcIndex[indexKey] = nodeID

		// 索引：仅函数名（用于跨文件查找）
		if _, exists := b.funcIndex[fn.Name]; !exists {
			b.funcIndex[fn.Name] = nodeID
		}
	}
}

// resolveFileCalls 解析文件中的调用关系。
func (b *CallGraphBuilder) resolveFileCalls(file File, graph *CallGraph) {
	// 收集文件中的导入，建立别名映射
	imports := b.buildImportMap(file)

	// 解析函数内的调用
	for _, fn := range file.Functions {
		callerID := b.makeNodeID(file.Path, fn.Name)
		callerNode := graph.Nodes[callerID]

		for _, call := range fn.Calls {
			calleeID := b.resolveCallee(call, file.Path, imports, graph)

			if calleeID != "" {
				// 解析到项目内函数
				edge := CallEdge{
					Caller:   callerID,
					Callee:   calleeID,
					CallSite: Location(file.Path, call.Line),
				}
				graph.Edges = append(graph.Edges, edge)

				callerNode.Callees = append(callerNode.Callees, calleeID)
				if calleeNode, ok := graph.Nodes[calleeID]; ok {
					calleeNode.Callers = append(calleeNode.Callers, callerID)
				}
			} else {
				// 外部调用
				edge := CallEdge{
					Caller:    callerID,
					Callee:    call.FuncName,
					CallSite:  Location(file.Path, call.Line),
					IsExternal: true,
				}
				graph.Edges = append(graph.Edges, edge)
				callerNode.ExternalCalls = append(callerNode.ExternalCalls, call)
			}
		}
	}
}

// buildImportMap 构建导入别名映射。
func (b *CallGraphBuilder) buildImportMap(file File) map[string]string {
	importMap := make(map[string]string)

	for _, imp := range file.Imports {
		if imp.Alias != "" {
			// import foo as bar → bar → foo
			importMap[imp.Alias] = imp.Module
		}
		// import os → os → os
		importMap[imp.Module] = imp.Module

		// from os import system → system → os.system
		for _, item := range imp.Items {
			fullName := imp.Module + "." + item
			importMap[item] = fullName
		}
	}

	return importMap
}

// resolveCallee 解析调用目标。
func (b *CallGraphBuilder) resolveCallee(call CallExpr, currentFile string, importMap map[string]string, graph *CallGraph) string {
	funcName := call.FuncName

	// 1. 尝试直接匹配（同文件内）
	directID := b.makeNodeID(currentFile, funcName)
	if _, ok := graph.Nodes[directID]; ok {
		return directID
	}

	// 2. 尝试通过导入解析
	// 例如：requests.post → requests.post（外部）
	// 但：system → os.system（通过 from os import system）
	if resolved, ok := importMap[funcName]; ok {
		// 解析后的全限定名
		resolvedID := b.funcIndex[currentFile+":"+resolved]
		if resolvedID != "" {
			if _, ok := graph.Nodes[resolvedID]; ok {
				return resolvedID
			}
		}
	}

	// 3. 尝试解析 receiver.method 形式
	if call.Receiver != "" {
		// obj.method() → 检查 method 是否在某个类中
		receiverType := importMap[call.Receiver]
		if receiverType == "" {
			receiverType = call.Receiver
		}
		qualifiedName := receiverType + "." + funcName
		if nodeID, ok := b.funcIndex[qualifiedName]; ok {
			return nodeID
		}
	}

	// 4. 尝试全局函数名匹配
	if nodeID, ok := b.funcIndex[funcName]; ok {
		return nodeID
	}

	return ""
}

// computeSecurityTags 计算函数的安全标签。
func (b *CallGraphBuilder) computeSecurityTags(graph *CallGraph) {
	for _, node := range graph.Nodes {
		tags := map[string]bool{}
		for _, call := range node.Calls {
			cat := CallCategory(ClassifyCall(call.FuncName))
			switch cat {
			case CatCommandExec:
				tags["has_command_exec"] = true
			case CatNetworkAccess:
				tags["has_network_access"] = true
			case CatFileRead:
				tags["has_file_read"] = true
			case CatFileWrite:
				tags["has_file_write"] = true
			case CatEnvAccess:
				tags["has_env_access"] = true
			case CatPrivilegeEsc:
				tags["has_privilege_escalation"] = true
			case CatUnsafe:
				tags["has_unsafe_operation"] = true
			}
		}
		node.SecurityTags = make([]string, 0, len(tags))
		for tag := range tags {
			node.SecurityTags = append(node.SecurityTags, tag)
		}
		sort.Strings(node.SecurityTags)
	}
}

// identifyEntryPoints 识别入口点。
func (b *CallGraphBuilder) identifyEntryPoints(graph *CallGraph) {
	graph.EntryPoints = nil
	for _, node := range graph.Nodes {
		// 入口点条件：
		// 1. 导出函数（公开可见）
		// 2. main 函数
		// 3. 没有调用者（可能是被外部调用的）
		isEntryPoint := node.IsExported ||
			node.Name == "main" ||
			node.Name == "handler" ||
			node.Name == "handle" ||
			strings.HasPrefix(node.Name, "handle") ||
			len(node.Callers) == 0

		if isEntryPoint {
			node.IsEntry = true
			graph.EntryPoints = append(graph.EntryPoints, node.ID)
		}
	}
	sort.Strings(graph.EntryPoints)
}

// makeNodeID 生成节点唯一标识。
func (b *CallGraphBuilder) makeNodeID(filePath, funcName string) string {
	return filePath + ":" + funcName
}

// =============================================================================
// 调用图查询
// =============================================================================

// GetNode 获取节点。
func (g *CallGraph) GetNode(id string) *CallNode {
	return g.Nodes[id]
}

// GetCallees 获取函数调用的所有目标。
func (g *CallGraph) GetCallees(nodeID string) []*CallNode {
	node := g.Nodes[nodeID]
	if node == nil {
		return nil
	}
	var callees []*CallNode
	for _, calleeID := range node.Callees {
		if callee, ok := g.Nodes[calleeID]; ok {
			callees = append(callees, callee)
		}
	}
	return callees
}

// GetCallers 获取调用此函数的所有函数。
func (g *CallGraph) GetCallers(nodeID string) []*CallNode {
	node := g.Nodes[nodeID]
	if node == nil {
		return nil
	}
	var callers []*CallNode
	for _, callerID := range node.Callers {
		if caller, ok := g.Nodes[callerID]; ok {
			callers = append(callers, caller)
		}
	}
	return callers
}

// FindDangerousPaths 查找从入口点到危险函数的所有路径。
func (g *CallGraph) FindDangerousPaths() []CallChain {
	var chains []CallChain

	// 从每个入口点开始 BFS
	for _, entryID := range g.EntryPoints {
		chains = append(chains, g.findPathsFrom(entryID, 5)...) // 最大深度 5
	}

	return chains
}

// findPathsFrom 从指定节点查找所有路径。
func (g *CallGraph) findPathsFrom(startID string, maxDepth int) []CallChain {
	var chains []CallChain
	visited := map[string]bool{}
	var dfs func(nodeID string, path []string, depth int)

	dfs = func(nodeID string, path []string, depth int) {
		if depth > maxDepth {
			return
		}
		if visited[nodeID] {
			return
		}
		visited[nodeID] = true
		defer func() { visited[nodeID] = false }()

		path = append(path, nodeID)
		node := g.Nodes[nodeID]
		if node == nil {
			return
		}

		// 检查是否有危险调用
		var dangerousCalls []CallExpr
		for _, call := range node.ExternalCalls {
			if IsDangerousCall(call.FuncName) {
				dangerousCalls = append(dangerousCalls, call)
			}
		}

		if len(dangerousCalls) > 0 {
			chains = append(chains, CallChain{
				Nodes:            append([]string(nil), path...),
				Length:           len(path),
				HasDangerousCall: true,
				DangerousCalls:   dangerousCalls,
			})
		}

		// 继续遍历被调用者
		for _, calleeID := range node.Callees {
			dfs(calleeID, path, depth+1)
		}

		// 也检查外部调用中的危险函数
		for _, call := range node.ExternalCalls {
			if IsDangerousCall(call.FuncName) && len(dangerousCalls) == 0 {
				// 已经在上面处理了
			}
		}
	}

	dfs(startID, nil, 0)
	return chains
}

// FindFunctionsByTag 查找具有指定安全标签的函数。
func (g *CallGraph) FindFunctionsByTag(tag string) []*CallNode {
	var result []*CallNode
	for _, node := range g.Nodes {
		for _, t := range node.SecurityTags {
			if t == tag {
				result = append(result, node)
				break
			}
		}
	}
	return result
}

// FindExternalCalls 查找所有外部危险调用。
func (g *CallGraph) FindExternalCalls() []CallExpr {
	var calls []CallExpr
	seen := map[string]bool{}
	for _, node := range g.Nodes {
		for _, call := range node.ExternalCalls {
			key := fmt.Sprintf("%s:%d", call.FuncName, call.Line)
			if !seen[key] {
				seen[key] = true
				calls = append(calls, call)
			}
		}
	}
	return calls
}

// Stats 返回调用图统计信息。
func (g *CallGraph) Stats() CallGraphStats {
	stats := CallGraphStats{
		NodeCount: len(g.Nodes),
		EdgeCount: len(g.Edges),
	}
	for _, node := range g.Nodes {
		if node.IsEntry {
			stats.EntryPointCount++
		}
		if len(node.Callers) == 0 {
			stats.LeafCount++
		}
		stats.ExternalCallCount += len(node.ExternalCalls)
		for _, tag := range node.SecurityTags {
			switch tag {
			case "has_command_exec":
				stats.CommandExecNodes++
			case "has_network_access":
				stats.NetworkAccessNodes++
			case "has_file_read":
				stats.FileReadNodes++
			case "has_file_write":
				stats.FileWriteNodes++
			}
		}
	}
	return stats
}

// CallGraphStats 调用图统计信息。
type CallGraphStats struct {
	NodeCount          int `json:"node_count"`
	EdgeCount          int `json:"edge_count"`
	EntryPointCount    int `json:"entry_point_count"`
	LeafCount          int `json:"leaf_count"`
	ExternalCallCount  int `json:"external_call_count"`
	CommandExecNodes   int `json:"command_exec_nodes"`
	NetworkAccessNodes int `json:"network_access_nodes"`
	FileReadNodes      int `json:"file_read_nodes"`
	FileWriteNodes     int `json:"file_write_nodes"`
}

// String 返回统计信息的文本表示。
func (s CallGraphStats) String() string {
	return fmt.Sprintf("nodes=%d edges=%d entries=%d external_calls=%d cmd_exec=%d network=%d",
		s.NodeCount, s.EdgeCount, s.EntryPointCount, s.ExternalCallCount,
		s.CommandExecNodes, s.NetworkAccessNodes)
}

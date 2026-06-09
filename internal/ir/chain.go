package ir

import (
	"fmt"
	"strings"
)

// =============================================================================
// 能力链验证器 (Chain Verifier)
//
// 将 capability_chain 从关键词匹配升级为数据流验证。
// 原有逻辑只检查"能力 A 和能力 B 是否同时存在"，
// ChainVerifier 进一步验证"A 的输出是否真的流向了 B 的输入"。
//
// 验证策略：
//   1. 基于 TaintAnalyzer 的结果，检查 source→sink 是否有真实数据流
//   2. 基于 CallGraph 的调用链，验证 source 和 sink 之间是否存在调用路径
//   3. 综合两者给出置信度评估
// =============================================================================

// ChainPattern 定义一条能力链模式。
// 例如 "file_read → file_write" 表示读取文件后写入另一文件。
type ChainPattern struct {
	// ID 链模式标识
	ID string `json:"id"`
	// Description 描述
	Description string `json:"description"`
	// SourceCategory 源端能力类别（对应 CallCategory）
	SourceCategory CallCategory `json:"source_category"`
	// SinkCategory 汇聚端能力类别
	SinkCategory CallCategory `json:"sink_category"`
	// SourceTaintKinds 匹配的污点 source 规则 ID 前缀
	SourceTaintKinds []string `json:"source_taint_kinds,omitempty"`
	// SinkTaintKinds 匹配的污点 sink 规则 ID 前缀
	SinkTaintKinds []string `json:"sink_taint_kinds,omitempty"`
	// Severity 链风险等级
	Severity string `json:"severity"`
}

// DefaultChainPatterns 返回预定义的能力链模式。
func DefaultChainPatterns() []ChainPattern {
	return []ChainPattern{
		{
			ID:             "file-read-write",
			Description:    "文件读取后写入（数据重写/扩散）",
			SourceCategory: CatFileRead,
			SinkCategory:   CatFileWrite,
			SourceTaintKinds: []string{"source-file-read"},
			SinkTaintKinds:   []string{"sink-file-write"},
			Severity:         "中风险",
		},
		{
			ID:             "credential-network",
			Description:    "凭据/敏感数据经网络外发（数据泄露）",
			SourceCategory: CatEnvAccess,
			SinkCategory:   CatNetworkAccess,
			SourceTaintKinds: []string{"source-env"},
			SinkTaintKinds:   []string{"sink-network"},
			Severity:         "高风险",
		},
		{
			ID:             "file-read-network",
			Description:    "文件读取后经网络外发（文件泄露）",
			SourceCategory: CatFileRead,
			SinkCategory:   CatNetworkAccess,
			SourceTaintKinds: []string{"source-file-read"},
			SinkTaintKinds:   []string{"sink-network"},
			Severity:         "高风险",
		},
		{
			ID:             "network-cmd-exec",
			Description:    "网络输入驱动命令执行（远程代码执行）",
			SourceCategory: CatNetworkAccess,
			SinkCategory:   CatCommandExec,
			SourceTaintKinds: []string{"source-request", "source-url"},
			SinkTaintKinds:   []string{"sink-cmd-exec", "sink-subprocess", "sink-exec"},
			Severity:         "高风险",
		},
		{
			ID:             "file-read-cmd-exec",
			Description:    "文件内容驱动命令执行（间接代码注入）",
			SourceCategory: CatFileRead,
			SinkCategory:   CatCommandExec,
			SourceTaintKinds: []string{"source-file-read"},
			SinkTaintKinds:   []string{"sink-cmd-exec", "sink-subprocess", "sink-exec"},
			Severity:         "高风险",
		},
		{
			ID:             "env-file-write",
			Description:    "环境变量/凭据写入文件（凭据落地）",
			SourceCategory: CatEnvAccess,
			SinkCategory:   CatFileWrite,
			SourceTaintKinds: []string{"source-env"},
			SinkTaintKinds:   []string{"sink-file-write"},
			Severity:         "中风险",
		},
		{
			ID:             "user-input-cmd-exec",
			Description:    "用户输入驱动命令执行（命令注入）",
			SourceCategory: CatEnvAccess, // user_input 通常也经过 env 或 request
			SinkCategory:   CatCommandExec,
			SourceTaintKinds: []string{"source-user-input", "source-request"},
			SinkTaintKinds:   []string{"sink-cmd-exec", "sink-subprocess", "sink-exec"},
			Severity:         "高风险",
		},
		{
			ID:             "crypto-network",
			Description:    "加密后经网络外发（加密隧道/隐蔽通道）",
			SourceCategory: CatCryptoOp,
			SinkCategory:   CatNetworkAccess,
			Severity:       "中风险",
		},
	}
}

// =============================================================================
// 链验证结果
// =============================================================================

// ChainVerificationResult 链验证结果。
type ChainVerificationResult struct {
	// PatternID 匹配的链模式 ID
	PatternID string `json:"pattern_id"`
	// Description 链描述
	Description string `json:"description"`
	// Verified 是否通过数据流验证
	Verified bool `json:"verified"`
	// Confidence 置信度：高/中/低/未验证
	Confidence string `json:"confidence"`
	// Severity 风险等级
	Severity string `json:"severity"`
	// Evidence 证据列表
	Evidence []ChainEvidence `json:"evidence"`
	// DataFlowPath 数据流路径（如果验证通过）
	DataFlowPath []DataFlowStep `json:"data_flow_path,omitempty"`
	// CallChainPath 调用链路径（如果通过调用图验证）
	CallChainPath []string `json:"call_chain_path,omitempty"`
	// GapDescription 未验证时的缺口描述
	GapDescription string `json:"gap_description,omitempty"`
	// SourceCalls 源端调用列表
	SourceCalls []CallExpr `json:"source_calls,omitempty"`
	// SinkCalls 汇聚端调用列表
	SinkCalls []CallExpr `json:"sink_calls,omitempty"`
}

// ChainEvidence 链验证证据。
type ChainEvidence struct {
	// Kind 证据类型：taint_flow / call_chain / co_occurrence / sandbox_behavior
	Kind string `json:"kind"`
	// Description 证据描述
	Description string `json:"description"`
	// Location 位置
	Location string `json:"location,omitempty"`
	// Strength 证据强度：强/中/弱
	Strength string `json:"strength"`
}

// =============================================================================
// 链验证器
// =============================================================================

// ChainVerifier 能力链验证器。
type ChainVerifier struct {
	patterns    []ChainPattern
	callGraph   *CallGraph
	taintFindings []TaintFinding
	files       []File
}

// NewChainVerifier 创建链验证器。
func NewChainVerifier(patterns []ChainPattern, graph *CallGraph, taintFindings []TaintFinding, files []File) *ChainVerifier {
	if len(patterns) == 0 {
		patterns = DefaultChainPatterns()
	}
	return &ChainVerifier{
		patterns:      patterns,
		callGraph:     graph,
		taintFindings: taintFindings,
		files:         files,
	}
}

// Verify 对所有链模式执行验证。
func (v *ChainVerifier) Verify() []ChainVerificationResult {
	var results []ChainVerificationResult

	for _, pattern := range v.patterns {
		result := v.verifyPattern(pattern)
		results = append(results, result)
	}

	return results
}

// verifyPattern 验证单条链模式。
func (v *ChainVerifier) verifyPattern(pattern ChainPattern) ChainVerificationResult {
	result := ChainVerificationResult{
		PatternID:   pattern.ID,
		Description: pattern.Description,
		Severity:    pattern.Severity,
		Verified:    false,
		Confidence:  "未验证",
	}

	// 策略 1：检查污点分析结果中是否有匹配的 source→sink 数据流
	taintVerified := v.checkTaintFlow(pattern, &result)

	// 策略 2：检查调用图中 source 和 sink 是否在同一调用链上
	callChainVerified := v.checkCallChain(pattern, &result)

	// 策略 3：检查 source 和 sink 是否在同一函数中共现
	coOccurrenceVerified := v.checkCoOccurrence(pattern, &result)

	// 综合判定
	if taintVerified {
		result.Verified = true
		result.Confidence = "高"
	} else if callChainVerified {
		result.Verified = true
		result.Confidence = "中"
	} else if coOccurrenceVerified {
		result.Verified = true
		result.Confidence = "低"
	} else {
		result.Verified = false
		result.Confidence = "未验证"
		result.GapDescription = v.describeGap(pattern)
	}

	return result
}

// checkTaintFlow 检查污点分析是否覆盖了此链模式。
func (v *ChainVerifier) checkTaintFlow(pattern ChainPattern, result *ChainVerificationResult) bool {
	matched := false

	for _, finding := range v.taintFindings {
		if !v.matchesPatternTaint(finding, pattern) {
			continue
		}

		// 找到了匹配的污点流
		result.Evidence = append(result.Evidence, ChainEvidence{
			Kind:        "taint_flow",
			Description: fmt.Sprintf("污点数据从 %s(%s) 流向 %s", finding.Source.VarName, finding.Source.Category, finding.Sink.Call.FuncName),
			Location:    finding.Location,
			Strength:    "强",
		})
		result.DataFlowPath = finding.DataFlow
		result.SourceCalls = append(result.SourceCalls, v.findSourceCalls(finding)...)
		result.SinkCalls = append(result.SinkCalls, finding.Sink.Call)
		matched = true
	}

	return matched
}

// matchesPatternTaint 检查污点发现是否匹配链模式。
func (v *ChainVerifier) matchesPatternTaint(finding TaintFinding, pattern ChainPattern) bool {
	// 检查 source 类别（基于 finding.Source.Category 和 SourceTaintKinds）
	sourceMatch := false
	if len(pattern.SourceTaintKinds) > 0 {
		for _, kind := range pattern.SourceTaintKinds {
			// SourceTaintKinds 匹配 source 规则 ID 前缀或 source 类别
			if strings.HasPrefix(finding.Source.Source, kind) || strings.Contains(finding.Source.Category, kind) {
				sourceMatch = true
				break
			}
		}
	} else {
		// 无特定 taint kind 约束，按类别匹配
		sourceCat := CallCategory(ClassifyCall(finding.Source.VarName))
		if sourceCat == pattern.SourceCategory || strings.Contains(finding.Source.Category, string(pattern.SourceCategory)) {
			sourceMatch = true
		}
	}

	if !sourceMatch {
		return false
	}

	// 检查 sink 类别（基于 finding.Sink.Rule.ID 和 SinkTaintKinds）
	sinkMatch := false
	if len(pattern.SinkTaintKinds) > 0 {
		for _, kind := range pattern.SinkTaintKinds {
			if strings.HasPrefix(finding.Sink.Rule.ID, kind) {
				sinkMatch = true
				break
			}
		}
	} else {
		sinkCat := CallCategory(ClassifyCall(finding.Sink.Call.FuncName))
		sinkMatch = sinkCat == pattern.SinkCategory
	}

	return sinkMatch
}

// findSourceCalls 从污点发现中查找源端调用。
func (v *ChainVerifier) findSourceCalls(finding TaintFinding) []CallExpr {
	var calls []CallExpr
	for _, file := range v.files {
		for _, call := range file.AllCallExprs() {
			if strings.Contains(call.FuncName, finding.Source.VarName) ||
				strings.Contains(finding.Source.VarName, call.FuncName) {
				calls = append(calls, call)
			}
		}
	}
	return calls
}

// checkCallChain 检查调用图中 source 和 sink 是否在同一调用链上。
func (v *ChainVerifier) checkCallChain(pattern ChainPattern, result *ChainVerificationResult) bool {
	if v.callGraph == nil {
		return false
	}

	// 找到包含 source 类别调用的函数
	sourceNodes := v.findNodesByCallCategory(pattern.SourceCategory)
	// 找到包含 sink 类别调用的函数
	sinkNodes := v.findNodesByCallCategory(pattern.SinkCategory)

	if len(sourceNodes) == 0 || len(sinkNodes) == 0 {
		return false
	}

	// 检查是否存在 source → sink 的调用路径
	for _, srcNode := range sourceNodes {
		for _, sinkNode := range sinkNodes {
			path := v.findCallPath(srcNode.ID, sinkNode.ID)
			if len(path) > 0 {
				result.Evidence = append(result.Evidence, ChainEvidence{
					Kind:        "call_chain",
					Description: fmt.Sprintf("调用链: %s", strings.Join(path, " → ")),
					Strength:    "中",
				})
				result.CallChainPath = path
				return true
			}
		}
	}

	return false
}

// findNodesByCallCategory 查找包含指定类别调用的节点。
func (v *ChainVerifier) findNodesByCallCategory(category CallCategory) []*CallNode {
	var nodes []*CallNode
	for _, node := range v.callGraph.Nodes {
		for _, call := range node.Calls {
			if CallCategory(ClassifyCall(call.FuncName)) == category {
				nodes = append(nodes, node)
				break
			}
		}
		// 也检查外部调用
		for _, call := range node.ExternalCalls {
			if CallCategory(ClassifyCall(call.FuncName)) == category {
				nodes = append(nodes, node)
				break
			}
		}
	}
	return nodes
}

// findCallPath 在调用图中查找从 src 到 sink 的路径（BFS）。
func (v *ChainVerifier) findCallPath(srcID, sinkID string) []string {
	if srcID == sinkID {
		return []string{srcID}
	}

	// BFS
	type node struct {
		id   string
		path []string
	}
	queue := []node{{id: srcID, path: []string{srcID}}}
	visited := map[string]bool{srcID: true}

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]

		if len(current.path) > 5 {
			continue // 限制深度
		}

		// 获取当前节点的被调用者
		callNode := v.callGraph.Nodes[current.id]
		if callNode == nil {
			continue
		}

		for _, calleeID := range callNode.Callees {
			if visited[calleeID] {
				continue
			}
			visited[calleeID] = true
			newPath := append(append([]string(nil), current.path...), calleeID)
			if calleeID == sinkID {
				return newPath
			}
			queue = append(queue, node{id: calleeID, path: newPath})
		}
	}

	return nil
}

// checkCoOccurrence 检查 source 和 sink 是否在同一函数中共现。
func (v *ChainVerifier) checkCoOccurrence(pattern ChainPattern, result *ChainVerificationResult) bool {
	for _, file := range v.files {
		for _, fn := range file.Functions {
			hasSource := false
			hasSink := false
			var sourceCall, sinkCall CallExpr

			for _, call := range fn.Calls {
				cat := CallCategory(ClassifyCall(call.FuncName))
				if cat == pattern.SourceCategory {
					hasSource = true
					sourceCall = call
				}
				if cat == pattern.SinkCategory {
					hasSink = true
					sinkCall = call
				}
			}

			if hasSource && hasSink {
				result.Evidence = append(result.Evidence, ChainEvidence{
					Kind:        "co_occurrence",
					Description: fmt.Sprintf("函数 %s 中同时出现 %s(%s) 和 %s(%s)", fn.Name, sourceCall.FuncName, pattern.SourceCategory, sinkCall.FuncName, pattern.SinkCategory),
					Location:    Location(file.Path, fn.StartLine),
					Strength:    "弱",
				})
				result.SourceCalls = append(result.SourceCalls, sourceCall)
				result.SinkCalls = append(result.SinkCalls, sinkCall)
				return true
			}
		}
	}

	return false
}

// describeGap 描述链验证的缺口。
func (v *ChainVerifier) describeGap(pattern ChainPattern) string {
	hasSource := false
	hasSink := false

	for _, file := range v.files {
		for _, call := range file.AllCallExprs() {
			cat := CallCategory(ClassifyCall(call.FuncName))
			if cat == pattern.SourceCategory {
				hasSource = true
			}
			if cat == pattern.SinkCategory {
				hasSink = true
			}
		}
	}

	switch {
	case !hasSource && !hasSink:
		return fmt.Sprintf("未发现 %s 和 %s 能力调用", pattern.SourceCategory, pattern.SinkCategory)
	case !hasSource:
		return fmt.Sprintf("未发现 %s 能力调用，但存在 %s 能力", pattern.SourceCategory, pattern.SinkCategory)
	case !hasSink:
		return fmt.Sprintf("未发现 %s 能力调用，但存在 %s 能力", pattern.SinkCategory, pattern.SourceCategory)
	default:
		return fmt.Sprintf("同时存在 %s 和 %s 能力调用，但未发现数据流连接", pattern.SourceCategory, pattern.SinkCategory)
	}
}

// =============================================================================
// 便捷方法
// =============================================================================

// VerifyChains 是一站式验证入口，自动构建所有依赖并执行验证。
func VerifyChains(files []File) []ChainVerificationResult {
	// 构建调用图
	builder := NewCallGraphBuilder()
	graph := builder.Build(files)

	// 执行污点分析（CFG 增强）
	cfgAnalyzer := NewCFGTaintAnalyzer(DefaultTaintRules())
	taintFindings := cfgAnalyzer.AnalyzeWithCFG(files)

	// 创建链验证器并执行验证
	verifier := NewChainVerifier(DefaultChainPatterns(), graph, taintFindings, files)
	return verifier.Verify()
}

// VerifiedChains 返回所有已验证的链。
func VerifiedChains(results []ChainVerificationResult) []ChainVerificationResult {
	var verified []ChainVerificationResult
	for _, r := range results {
		if r.Verified {
			verified = append(verified, r)
		}
	}
	return verified
}

// HighConfidenceChains 返回高置信度的链。
func HighConfidenceChains(results []ChainVerificationResult) []ChainVerificationResult {
	var high []ChainVerificationResult
	for _, r := range results {
		if r.Confidence == "高" {
			high = append(high, r)
		}
	}
	return high
}

// String 返回验证结果的文本摘要。
func (r ChainVerificationResult) String() string {
	status := "❌ 未验证"
	if r.Verified {
		status = "✅ 已验证"
	}
	return fmt.Sprintf("[%s] %s (%s, 置信度=%s)", status, r.Description, r.Severity, r.Confidence)
}

package ir

import (
	"fmt"
	"strings"
)

// =============================================================================
// Agent 自动探索 (Agent Auto Exploration)
//
// AI Agent 自动构造测试用例验证漏洞，补充 source-sink 链路证据。
//
// 能力：
//   1. 对污点分析发现，自动生成验证用例
//   2. 对链验证缺口，自动补充缺失环节的证据
//   3. 对危险调用路径，自动生成可达性分析
//
// 设计为"证据生成器"：不执行代码，只生成结构化证据描述。
// =============================================================================

// ExplorationTask 探索任务。
type ExplorationTask struct {
	// ID 任务标识
	ID string `json:"id"`
	// Kind 任务类型：verify_taint / fill_chain_gap / analyze_path / generate_poc
	Kind string `json:"kind"`
	// Description 任务描述
	Description string `json:"description"`
	// Target 目标（发现/链/路径）
	Target string `json:"target"`
	// Priority 优先级（1-10）
	Priority int `json:"priority"`
}

// ExplorationResult 探索结果。
type ExplorationResult struct {
	// TaskID 关联任务 ID
	TaskID string `json:"task_id"`
	// Status 状态：completed / partial / failed
	Status string `json:"status"`
	// Evidence 生成的证据
	Evidence []EvidenceItem `json:"evidence"`
	// SuggestedAction 建议的后续行动
	SuggestedAction string `json:"suggested_action,omitempty"`
	// GeneratedCode 生成的验证代码（PoC）
	GeneratedCode string `json:"generated_code,omitempty"`
}

// EvidenceItem 证据条目。
type EvidenceItem struct {
	// Kind 证据类型：code_snippet / data_flow / call_path / input_output
	Kind string `json:"kind"`
	// Description 证据描述
	Description string `json:"description"`
	// Location 位置
	Location string `json:"location,omitempty"`
	// Strength 证据强度：强/中/弱
	Strength string `json:"strength"`
}

// AgentExplorer Agent 自动探索器。
type AgentExplorer struct {
	files []File
	graph *CallGraph
}

// NewAgentExplorer 创建 Agent 探索器。
func NewAgentExplorer(files []File) *AgentExplorer {
	builder := NewCallGraphBuilder()
	graph := builder.Build(files)

	return &AgentExplorer{
		files: files,
		graph: graph,
	}
}

// GenerateTasks 从分析结果生成探索任务。
func (e *AgentExplorer) GenerateTasks(taintFindings []TaintFinding, chainResults []ChainVerificationResult) []ExplorationTask {
	var tasks []ExplorationTask
	taskID := 0

	// 1. 为每个污点发现生成验证任务
	for _, tf := range taintFindings {
		taskID++
		tasks = append(tasks, ExplorationTask{
			ID:          fmt.Sprintf("task-%d", taskID),
			Kind:        "verify_taint",
			Description: fmt.Sprintf("验证污点流: %s → %s", tf.Source.VarName, tf.Sink.Call.FuncName),
			Target:      tf.RuleID,
			Priority:    severityToPriority(tf.Severity),
		})
	}

	// 2. 为链验证缺口生成补充任务
	for _, cr := range chainResults {
		if !cr.Verified && cr.GapDescription != "" {
			taskID++
			tasks = append(tasks, ExplorationTask{
				ID:          fmt.Sprintf("task-%d", taskID),
				Kind:        "fill_chain_gap",
				Description: fmt.Sprintf("补充链证据: %s (缺口: %s)", cr.Description, cr.GapDescription),
				Target:      cr.PatternID,
				Priority:    7,
			})
		}
	}

	// 3. 为危险路径生成分析任务
	if e.graph != nil {
		dangerousPaths := e.graph.FindDangerousPaths()
		for _, dp := range dangerousPaths {
			taskID++
			tasks = append(tasks, ExplorationTask{
				ID:          fmt.Sprintf("task-%d", taskID),
				Kind:        "analyze_path",
				Description: fmt.Sprintf("分析危险路径: %s", strings.Join(dp.Nodes, " → ")),
				Target:      strings.Join(dp.Nodes, ","),
				Priority:    8,
			})
		}
	}

	return tasks
}

// ExecuteTask 执行探索任务。
func (e *AgentExplorer) ExecuteTask(task ExplorationTask) ExplorationResult {
	switch task.Kind {
	case "verify_taint":
		return e.verifyTaint(task)
	case "fill_chain_gap":
		return e.fillChainGap(task)
	case "analyze_path":
		return e.analyzePath(task)
	default:
		return ExplorationResult{
			TaskID: task.ID,
			Status: "failed",
			Evidence: []EvidenceItem{{
				Kind:        "error",
				Description: fmt.Sprintf("未知任务类型: %s", task.Kind),
				Strength:    "弱",
			}},
		}
	}
}

// ExecuteAll 执行所有任务。
func (e *AgentExplorer) ExecuteAll(tasks []ExplorationTask) []ExplorationResult {
	results := make([]ExplorationResult, 0, len(tasks))
	for _, task := range tasks {
		results = append(results, e.ExecuteTask(task))
	}
	return results
}

// verifyTaint 验证污点发现，生成证据。
func (e *AgentExplorer) verifyTaint(task ExplorationTask) ExplorationResult {
	result := ExplorationResult{
		TaskID: task.ID,
		Status: "partial",
	}

	// 在文件中查找相关代码
	for _, file := range e.files {
		for _, fn := range file.Functions {
			// 查找包含 source 和 sink 的函数
			hasSource := false
			hasSink := false
			var sourceLine, sinkLine int

			for _, assign := range fn.Assignments {
				if strings.Contains(assign.RHS, "getenv") || strings.Contains(assign.RHS, "environ") || strings.Contains(assign.RHS, "ReadFile") {
					hasSource = true
					sourceLine = assign.Line
				}
			}

			for _, call := range fn.Calls {
				cat := CallCategory(ClassifyCall(call.FuncName))
				if cat == CatNetworkAccess || cat == CatCommandExec || cat == CatFileWrite {
					hasSink = true
					sinkLine = call.Line
				}
			}

			if hasSource && hasSink {
				result.Status = "completed"
				result.Evidence = append(result.Evidence, EvidenceItem{
					Kind:        "data_flow",
					Description: fmt.Sprintf("函数 %s 中存在 source(line %d) → sink(line %d) 数据流", fn.Name, sourceLine, sinkLine),
					Location:    Location(file.Path, fn.StartLine),
					Strength:    "强",
				})

				// 生成 PoC
				result.GeneratedCode = generatePoC(file, fn)
				result.SuggestedAction = "建议在沙箱中执行 PoC 验证数据流可达性"
			}
		}
	}

	if len(result.Evidence) == 0 {
		result.Evidence = append(result.Evidence, EvidenceItem{
			Kind:        "code_snippet",
			Description: "未在代码中找到明确的 source-sink 对，可能需要跨文件分析",
			Strength:    "弱",
		})
	}

	return result
}

// fillChainGap 补充链验证缺口。
func (e *AgentExplorer) fillChainGap(task ExplorationTask) ExplorationResult {
	result := ExplorationResult{
		TaskID: task.ID,
		Status: "partial",
	}

	// 分析缺口
	// 从 task.Description 中提取缺口信息
	if strings.Contains(task.Description, "未发现") {
		// 缺少能力调用
		result.Evidence = append(result.Evidence, EvidenceItem{
			Kind:        "code_snippet",
			Description: "代码中缺少关键能力调用，链无法闭合",
			Strength:    "中",
		})
		result.SuggestedAction = "建议检查是否有间接调用（通过变量、回调、反射等方式）"
	} else if strings.Contains(task.Description, "数据流连接") {
		// 有能力调用但无数据流
		result.Evidence = append(result.Evidence, EvidenceItem{
			Kind:        "data_flow",
			Description: "存在能力调用但数据流未连接，可能是独立的无害操作",
			Strength:    "中",
		})
		result.SuggestedAction = "建议检查变量赋值链和函数参数传递"
	}

	return result
}

// analyzePath 分析危险调用路径。
func (e *AgentExplorer) analyzePath(task ExplorationTask) ExplorationResult {
	result := ExplorationResult{
		TaskID: task.ID,
		Status: "partial",
	}

	// 解析路径节点
	nodes := strings.Split(task.Target, ",")
	if len(nodes) < 2 {
		result.Status = "failed"
		return result
	}

	// 查找每个节点的详细信息
	for _, nodeID := range nodes {
		nodeID = strings.TrimSpace(nodeID)
		node := e.graph.GetNode(nodeID)
		if node == nil {
			continue
		}

		// 分析节点的安全标签
		for _, tag := range node.SecurityTags {
			result.Evidence = append(result.Evidence, EvidenceItem{
				Kind:        "call_path",
				Description: fmt.Sprintf("函数 %s 具有 %s 标签", node.Name, tag),
				Location:    Location(node.File, node.StartLine),
				Strength:    "中",
			})
		}

		// 分析外部调用
		for _, call := range node.ExternalCalls {
			if IsDangerousCall(call.FuncName) {
				result.Evidence = append(result.Evidence, EvidenceItem{
					Kind:        "code_snippet",
					Description: fmt.Sprintf("函数 %s 调用危险函数 %s (line %d)", node.Name, call.FuncName, call.Line),
					Location:    Location(node.File, call.Line),
					Strength:    "强",
				})
			}
		}
	}

	if len(result.Evidence) > 0 {
		result.Status = "completed"
		result.SuggestedAction = "建议验证路径可达性，检查是否有条件分支阻断执行流"
	}

	return result
}

// generatePoC 生成验证用的 PoC 代码。
func generatePoC(file File, fn Function) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# PoC for %s/%s\n", file.Path, fn.Name))
	sb.WriteString("# Auto-generated verification code\n\n")

	// 提取函数中的关键调用
	for _, call := range fn.Calls {
		cat := CallCategory(ClassifyCall(call.FuncName))
		switch cat {
		case CatNetworkAccess:
			sb.WriteString(fmt.Sprintf("# Network call: %s\n", call.FuncName))
			sb.WriteString(fmt.Sprintf("# Args: %s\n\n", strings.Join(call.Args, ", ")))
		case CatCommandExec:
			sb.WriteString(fmt.Sprintf("# Command exec: %s\n", call.FuncName))
			sb.WriteString(fmt.Sprintf("# Args: %s\n\n", strings.Join(call.Args, ", ")))
		case CatFileWrite:
			sb.WriteString(fmt.Sprintf("# File write: %s\n", call.FuncName))
			sb.WriteString(fmt.Sprintf("# Args: %s\n\n", strings.Join(call.Args, ", ")))
		}
	}

	// 提取赋值链
	for _, assign := range fn.Assignments {
		sb.WriteString(fmt.Sprintf("# %s = %s (line %d)\n", assign.VarName, assign.RHS, assign.Line))
	}

	return sb.String()
}

// severityToPriority 严重性转优先级。
func severityToPriority(severity string) int {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "高风险", "high":
		return 9
	case "中风险", "medium":
		return 6
	case "低风险", "low":
		return 3
	default:
		return 5
	}
}

// =============================================================================
// 综合分析入口
// =============================================================================

// FullAnalysis 完整的 IR + Agent 分析流程。
type FullAnalysis struct {
	// TaintFindings 污点分析发现
	TaintFindings []TaintFinding `json:"taint_findings"`
	// ChainResults 链验证结果
	ChainResults []ChainVerificationResult `json:"chain_results"`
	// SimilarityMatches 相似性匹配
	SimilarityMatches []SimilarityMatch `json:"similarity_matches"`
	// ExplorationTasks 探索任务
	ExplorationTasks []ExplorationTask `json:"exploration_tasks"`
	// ExplorationResults 探索结果
	ExplorationResults []ExplorationResult `json:"exploration_results"`
	// CallGraphStats 调用图统计
	CallGraphStats CallGraphStats `json:"call_graph_stats"`
}

// RunFullAnalysis 运行完整的 IR + Agent 分析。
func RunFullAnalysis(files []File) FullAnalysis {
	result := FullAnalysis{}

	// 1. 构建调用图
	builder := NewCallGraphBuilder()
	graph := builder.Build(files)
	result.CallGraphStats = graph.Stats()

	// 2. 污点分析（CFG 增强）
	cfgAnalyzer := NewCFGTaintAnalyzer(DefaultTaintRules())
	result.TaintFindings = cfgAnalyzer.AnalyzeWithCFG(files)

	// 3. 链验证
	chainVerifier := NewChainVerifier(DefaultChainPatterns(), graph, result.TaintFindings, files)
	result.ChainResults = chainVerifier.Verify()

	// 4. 相似性搜索
	simEngine := NewSimilarityEngine(nil, nil, 0.3)
	result.SimilarityMatches = simEngine.Search(files)

	// 5. Agent 探索
	explorer := NewAgentExplorer(files)
	result.ExplorationTasks = explorer.GenerateTasks(result.TaintFindings, result.ChainResults)
	result.ExplorationResults = explorer.ExecuteAll(result.ExplorationTasks)

	return result
}

// FormatFullAnalysis 格式化完整分析结果。
func FormatFullAnalysis(analysis FullAnalysis) string {
	var sb strings.Builder

	sb.WriteString("=== IR 完整分析报告 ===\n\n")

	// 调用图统计
	sb.WriteString(fmt.Sprintf("调用图: %s\n\n", analysis.CallGraphStats.String()))

	// 污点发现
	if len(analysis.TaintFindings) > 0 {
		sb.WriteString(fmt.Sprintf("## 污点分析: %d 条发现\n", len(analysis.TaintFindings)))
		for i, tf := range analysis.TaintFindings {
			sb.WriteString(fmt.Sprintf("  %d. [%s] %s\n", i+1, tf.Severity, tf.Description))
			sb.WriteString(fmt.Sprintf("     %s → %s\n", tf.Source.VarName, tf.Sink.Call.FuncName))
		}
		sb.WriteString("\n")
	}

	// 链验证
	verified := 0
	for _, cr := range analysis.ChainResults {
		if cr.Verified {
			verified++
		}
	}
	sb.WriteString(fmt.Sprintf("## 能力链验证: %d/%d 通过\n", verified, len(analysis.ChainResults)))
	for _, cr := range analysis.ChainResults {
		if cr.Verified {
			sb.WriteString(fmt.Sprintf("  ✅ %s (%s)\n", cr.Description, cr.Confidence))
		}
	}
	sb.WriteString("\n")

	// 相似性匹配
	if len(analysis.SimilarityMatches) > 0 {
		sb.WriteString(fmt.Sprintf("## 相似性匹配: %d 条\n", len(analysis.SimilarityMatches)))
		for _, m := range analysis.SimilarityMatches {
			sb.WriteString(fmt.Sprintf("  - %s\n", FormatSimilarityMatch(m)))
		}
		sb.WriteString("\n")
	}

	// Agent 探索
	if len(analysis.ExplorationResults) > 0 {
		completed := 0
		for _, r := range analysis.ExplorationResults {
			if r.Status == "completed" {
				completed++
			}
		}
		sb.WriteString(fmt.Sprintf("## Agent 探索: %d/%d 完成\n", completed, len(analysis.ExplorationResults)))
		for _, r := range analysis.ExplorationResults {
			sb.WriteString(fmt.Sprintf("  [%s] Task %s: %d 条证据\n", r.Status, r.TaskID, len(r.Evidence)))
			if r.SuggestedAction != "" {
				sb.WriteString(fmt.Sprintf("    建议: %s\n", r.SuggestedAction))
			}
		}
	}

	return sb.String()
}

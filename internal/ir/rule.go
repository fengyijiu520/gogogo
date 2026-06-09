package ir

import (
	"fmt"
	"strings"
)

// =============================================================================
// IR 规则 Schema (Rule Schema v2)
//
// 在现有 YAML 规则（正则匹配）之上，增加基于 IR 的结构化规则表达能力。
// 新规则支持：
//   - AST 节点匹配（函数名+参数模式，替代正则）
//   - 安全类别匹配（基于 CallCategory）
//   - 数据流约束（taint source→sink 验证）
//   - 调用链约束（call chain 路径验证）
//
// 向后兼容：
//   - 旧的 detection.type=pattern/forbid_pattern 继续工作
//   - 新增 detection.type=ir_pattern 启用 IR 分析
//   - 旧规则可自动升级为 IR 规则（正则→类别映射）
// =============================================================================

// IRRule 基于 IR 的结构化规则。
type IRRule struct {
	// ID 规则标识
	ID string `json:"id"`
	// Name 规则名称
	Name string `json:"name"`
	// Severity 严重性：high / medium / low
	Severity string `json:"severity"`
	// Layer 层级：P0 / P1 / P2
	Layer string `json:"layer"`
	// Description 描述
	Description string `json:"description"`
	// Detection 检测配置
	Detection IRDetection `json:"detection"`
	// OnFail 失败处理
	OnFail IROnFail `json:"on_fail,omitempty"`
	// Review 复核配置
	Review IRReview `json:"review,omitempty"`
}

// IRDetection IR 检测配置。
type IRDetection struct {
	// Type 检测类型：ir_call / ir_category / ir_taint_flow / ir_call_chain / ir_compound
	Type string `json:"type"`
	// Call 调用匹配（type=ir_call）
	Call *IRCallMatch `json:"call,omitempty"`
	// Category 类别匹配（type=ir_category）
	Category *IRCategoryMatch `json:"category,omitempty"`
	// TaintFlow 污点流匹配（type=ir_taint_flow）
	TaintFlow *IRTaintFlowMatch `json:"taint_flow,omitempty"`
	// CallChain 调用链匹配（type=ir_call_chain）
	CallChain *IRCallChainMatch `json:"call_chain,omitempty"`
	// Compound 复合匹配（type=ir_compound）
	Compound *IRCompoundMatch `json:"compound,omitempty"`
	// IncludeGlobs 文件 glob 白名单（所有类型通用）
	IncludeGlobs []string `json:"include_globs,omitempty"`
	// ExcludeGlobs 文件 glob 黑名单
	ExcludeGlobs []string `json:"exclude_globs,omitempty"`
	// PassIf 通过条件：no_match / match_found
	PassIf string `json:"pass_if,omitempty"`
	// Reason 检测说明
	Reason string `json:"reason,omitempty"`
}

// IRCallMatch 调用表达式匹配。
type IRCallMatch struct {
	// FuncName 函数名（contains 匹配，不区分大小写）
	FuncName string `json:"func_name,omitempty"`
	// FuncNameExact 函数名精确匹配
	FuncNameExact string `json:"func_name_exact,omitempty"`
	// FuncNamePrefix 函数名前缀匹配
	FuncNamePrefix string `json:"func_name_prefix,omitempty"`
	// ArgCount 参数数量（-1 表示不限）
	ArgCount int `json:"arg_count,omitempty"`
	// ArgContains 参数内容包含（任意参数匹配）
	ArgContains string `json:"arg_contains,omitempty"`
	// ArgIndex 特定参数索引（配合 ArgContains）
	ArgIndex int `json:"arg_index,omitempty"`
	// Receiver 接收者匹配
	Receiver string `json:"receiver,omitempty"`
	// IsDynamic 是否匹配动态调用
	IsDynamic *bool `json:"is_dynamic,omitempty"`
}

// IRCategoryMatch 安全类别匹配。
type IRCategoryMatch struct {
	// Categories 匹配的安全类别列表（OR 关系）
	Categories []string `json:"categories"`
	// MinCount 最少匹配次数（默认 1）
	MinCount int `json:"min_count,omitempty"`
}

// IRTaintFlowMatch 污点流匹配。
type IRTaintFlowMatch struct {
	// SourceCategory 源端类别
	SourceCategory string `json:"source_category,omitempty"`
	// SourceCall 源端调用匹配
	SourceCall *IRCallMatch `json:"source_call,omitempty"`
	// SinkCategory 汇聚端类别
	SinkCategory string `json:"sink_category,omitempty"`
	// SinkCall 汇聚端调用匹配
	SinkCall *IRCallMatch `json:"sink_call,omitempty"`
	// MinConfidence 最低置信度：高/中/低
	MinConfidence string `json:"min_confidence,omitempty"`
}

// IRCallChainMatch 调用链匹配。
type IRCallChainMatch struct {
	// FromCategory 起始端类别
	FromCategory string `json:"from_category,omitempty"`
	// ToCategory 终止端类别
	ToCategory string `json:"to_category,omitempty"`
	// MaxDepth 最大链深度
	MaxDepth int `json:"max_depth,omitempty"`
}

// IRCompoundMatch 复合匹配（多个条件 AND/OR）。
type IRCompoundMatch struct {
	// Operator 逻辑操作符：and / or
	Operator string `json:"operator"`
	// Conditions 子条件列表
	Conditions []IRSubCondition `json:"conditions"`
}

// IRSubCondition 子条件。
type IRSubCondition struct {
	// Kind 条件类型：call / category / taint_flow / call_chain
	Kind string `json:"kind"`
	// Call 调用匹配
	Call *IRCallMatch `json:"call,omitempty"`
	// Category 类别匹配
	Category *IRCategoryMatch `json:"category,omitempty"`
	// TaintFlow 污点流匹配
	TaintFlow *IRTaintFlowMatch `json:"taint_flow,omitempty"`
	// Negate 是否取反
	Negate bool `json:"negate,omitempty"`
}

// IROnFail 失败处理。
type IROnFail struct {
	Action string `json:"action"`
	Reason string `json:"reason,omitempty"`
}

// IRReview 复核配置。
type IRReview struct {
	PromptTemplate    string   `json:"prompt_template,omitempty"`
	DetectionCriteria []string `json:"detection_criteria,omitempty"`
}

// =============================================================================
// 规则执行结果
// =============================================================================

// IRRuleResult IR 规则执行结果。
type IRRuleResult struct {
	// RuleID 规则标识
	RuleID string `json:"rule_id"`
	// Matched 是否匹配
	Matched bool `json:"matched"`
	// Findings 发现列表
	Findings []IRFinding `json:"findings,omitempty"`
	// Score 分数影响
	Score float64 `json:"score,omitempty"`
	// Blocked 是否阻断
	Blocked bool `json:"blocked"`
	// Reason 原因
	Reason string `json:"reason,omitempty"`
}

// IRFinding IR 发现。
type IRFinding struct {
	// Kind 发现类型
	Kind string `json:"kind"`
	// Description 描述
	Description string `json:"description"`
	// Location 位置
	Location string `json:"location"`
	// Evidence 证据
	Evidence string `json:"evidence,omitempty"`
	// Confidence 置信度
	Confidence string `json:"confidence,omitempty"`
	// CallExpr 相关调用表达式
	CallExpr *CallExpr `json:"call_expr,omitempty"`
}

// =============================================================================
// IR 规则引擎
// =============================================================================

// IRRuleEngine IR 规则执行引擎。
type IRRuleEngine struct {
	files          []File
	callGraph      *CallGraph
	taintAnalyzer  *TaintAnalyzer
	taintFindings  []TaintFinding
	chainVerifier  *ChainVerifier
	chainResults   []ChainVerificationResult
}

// NewIRRuleEngine 创建 IR 规则引擎。
func NewIRRuleEngine(files []File) *IRRuleEngine {
	// 构建调用图
	builder := NewCallGraphBuilder()
	graph := builder.Build(files)

	// 执行污点分析（CFG 增强）
	baseTaintAnalyzer := NewTaintAnalyzer(DefaultTaintRules())
	cfgAnalyzer := NewCFGTaintAnalyzer(DefaultTaintRules())
	taintFindings := cfgAnalyzer.AnalyzeWithCFG(files)

	// 执行链验证
	chainVerifier := NewChainVerifier(DefaultChainPatterns(), graph, taintFindings, files)
	chainResults := chainVerifier.Verify()

	return &IRRuleEngine{
		files:         files,
		callGraph:     graph,
		taintAnalyzer: baseTaintAnalyzer,
		taintFindings: taintFindings,
		chainVerifier: chainVerifier,
		chainResults:  chainResults,
	}
}

// Evaluate 执行单条 IR 规则。
func (e *IRRuleEngine) Evaluate(rule IRRule) IRRuleResult {
	result := IRRuleResult{
		RuleID: rule.ID,
	}

	switch rule.Detection.Type {
	case "ir_call":
		result = e.evaluateCall(rule)
	case "ir_category":
		result = e.evaluateCategory(rule)
	case "ir_taint_flow":
		result = e.evaluateTaintFlow(rule)
	case "ir_call_chain":
		result = e.evaluateCallChain(rule)
	case "ir_compound":
		result = e.evaluateCompound(rule)
	default:
		result.Reason = fmt.Sprintf("未知的 IR 检测类型: %s", rule.Detection.Type)
	}

	// 应用 PassIf 逻辑
	if rule.Detection.PassIf == "no_match" {
		// 规则期望没有匹配 → 有匹配则阻断
		result.Blocked = result.Matched
	} else if rule.Detection.PassIf == "match_found" {
		// 规则期望有匹配 → 没有匹配则阻断
		result.Blocked = !result.Matched
	}

	return result
}

// EvaluateAll 执行多条 IR 规则。
func (e *IRRuleEngine) EvaluateAll(rules []IRRule) []IRRuleResult {
	results := make([]IRRuleResult, 0, len(rules))
	for _, rule := range rules {
		results = append(results, e.Evaluate(rule))
	}
	return results
}

// evaluateCall 执行调用匹配规则。
func (e *IRRuleEngine) evaluateCall(rule IRRule) IRRuleResult {
	result := IRRuleResult{RuleID: rule.ID}
	match := rule.Detection.Call
	if match == nil {
		result.Reason = "ir_call 规则缺少 call 配置"
		return result
	}

	for _, file := range e.files {
		if !e.matchFile(file.Path, rule.Detection.IncludeGlobs, rule.Detection.ExcludeGlobs) {
			continue
		}
		for _, call := range file.AllCallExprs() {
			if e.matchCallExpr(call, match) {
				result.Matched = true
				result.Findings = append(result.Findings, IRFinding{
					Kind:        "ir_call",
					Description: fmt.Sprintf("匹配到调用: %s", call.FuncName),
					Location:    Location(file.Path, call.Line),
					CallExpr:    &call,
					Confidence:  "高",
				})
			}
		}
	}

	if !result.Matched && rule.Detection.Reason != "" {
		result.Reason = rule.Detection.Reason
	}
	return result
}

// evaluateCategory 执行类别匹配规则。
func (e *IRRuleEngine) evaluateCategory(rule IRRule) IRRuleResult {
	result := IRRuleResult{RuleID: rule.ID}
	match := rule.Detection.Category
	if match == nil {
		result.Reason = "ir_category 规则缺少 category 配置"
		return result
	}

	minCount := match.MinCount
	if minCount <= 0 {
		minCount = 1
	}

	count := 0
	for _, file := range e.files {
		if !e.matchFile(file.Path, rule.Detection.IncludeGlobs, rule.Detection.ExcludeGlobs) {
			continue
		}
		for _, call := range file.AllCallExprs() {
			cat := ClassifyCall(call.FuncName)
			for _, targetCat := range match.Categories {
				if cat == targetCat {
					count++
					result.Findings = append(result.Findings, IRFinding{
						Kind:        "ir_category",
						Description: fmt.Sprintf("匹配到 %s 类别调用: %s", targetCat, call.FuncName),
						Location:    Location(file.Path, call.Line),
						CallExpr:    &call,
					})
					break
				}
			}
		}
	}

	result.Matched = count >= minCount
	return result
}

// evaluateTaintFlow 执行污点流匹配规则。
func (e *IRRuleEngine) evaluateTaintFlow(rule IRRule) IRRuleResult {
	result := IRRuleResult{RuleID: rule.ID}
	match := rule.Detection.TaintFlow
	if match == nil {
		result.Reason = "ir_taint_flow 规则缺少 taint_flow 配置"
		return result
	}

	for _, finding := range e.taintFindings {
		if !e.matchTaintFlowFinding(finding, match) {
			continue
		}
		result.Matched = true
		result.Findings = append(result.Findings, IRFinding{
			Kind:        "ir_taint_flow",
			Description: fmt.Sprintf("污点数据从 %s(%s) 流向 %s", finding.Source.VarName, finding.Source.Category, finding.Sink.Call.FuncName),
			Location:    finding.Location,
			Confidence:  finding.Confidence,
		})
	}

	// 也检查链验证结果
	for _, chainResult := range e.chainResults {
		if !chainResult.Verified {
			continue
		}
		if e.matchChainResult(chainResult, match) {
			if !result.Matched {
				result.Matched = true
			}
			result.Findings = append(result.Findings, IRFinding{
				Kind:        "ir_chain_flow",
				Description: fmt.Sprintf("能力链已验证: %s (%s)", chainResult.Description, chainResult.Confidence),
				Confidence:  chainResult.Confidence,
			})
		}
	}

	return result
}

// evaluateCallChain 执行调用链匹配规则。
func (e *IRRuleEngine) evaluateCallChain(rule IRRule) IRRuleResult {
	result := IRRuleResult{RuleID: rule.ID}
	match := rule.Detection.CallChain
	if match == nil {
		result.Reason = "ir_call_chain 规则缺少 call_chain 配置"
		return result
	}

	// 利用链验证结果
	for _, chainResult := range e.chainResults {
		if !chainResult.Verified {
			continue
		}
		if match.FromCategory != "" && match.ToCategory != "" {
			// 检查链模式是否匹配
			pattern := findChainPattern(chainResult.PatternID)
			if pattern != nil &&
				string(pattern.SourceCategory) == match.FromCategory &&
				string(pattern.SinkCategory) == match.ToCategory {
				result.Matched = true
				result.Findings = append(result.Findings, IRFinding{
					Kind:        "ir_call_chain",
					Description: fmt.Sprintf("调用链验证: %s", chainResult.Description),
					Confidence:  chainResult.Confidence,
				})
			}
		}
	}

	// 如果没有链验证结果，尝试直接在调用图中查找
	if !result.Matched && e.callGraph != nil {
		sourceNodes := e.findNodesByCategory(CallCategory(match.FromCategory))
		sinkNodes := e.findNodesByCategory(CallCategory(match.ToCategory))
		maxDepth := match.MaxDepth
		if maxDepth <= 0 {
			maxDepth = 5
		}

		for _, src := range sourceNodes {
			for _, sink := range sinkNodes {
				path := e.chainVerifier.findCallPath(src.ID, sink.ID)
				if len(path) > 0 && len(path) <= maxDepth {
					result.Matched = true
					result.Findings = append(result.Findings, IRFinding{
						Kind:        "ir_call_chain",
						Description: fmt.Sprintf("调用链: %s", strings.Join(path, " → ")),
						Confidence:  "中",
					})
				}
			}
		}
	}

	return result
}

// evaluateCompound 执行复合匹配规则。
func (e *IRRuleEngine) evaluateCompound(rule IRRule) IRRuleResult {
	result := IRRuleResult{RuleID: rule.ID}
	match := rule.Detection.Compound
	if match == nil {
		result.Reason = "ir_compound 规则缺少 compound 配置"
		return result
	}

	operator := strings.ToLower(match.Operator)
	if operator == "" {
		operator = "and"
	}

	allMatched := true
	anyMatched := false

	for _, cond := range match.Conditions {
		subMatched := e.evaluateSubCondition(cond)
		if subMatched {
			anyMatched = true
		} else {
			allMatched = false
		}
	}

	if operator == "and" {
		result.Matched = allMatched
	} else {
		result.Matched = anyMatched
	}

	return result
}

// evaluateSubCondition 评估子条件。
func (e *IRRuleEngine) evaluateSubCondition(cond IRSubCondition) bool {
	var matched bool

	switch cond.Kind {
	case "call":
		if cond.Call != nil {
			for _, file := range e.files {
				for _, call := range file.AllCallExprs() {
					if e.matchCallExpr(call, cond.Call) {
						matched = true
						break
					}
				}
				if matched {
					break
				}
			}
		}
	case "category":
		if cond.Category != nil {
			count := 0
			for _, file := range e.files {
				for _, call := range file.AllCallExprs() {
					cat := ClassifyCall(call.FuncName)
					for _, targetCat := range cond.Category.Categories {
						if cat == targetCat {
							count++
						}
					}
				}
			}
			minCount := cond.Category.MinCount
			if minCount <= 0 {
				minCount = 1
			}
			matched = count >= minCount
		}
	case "taint_flow":
		if cond.TaintFlow != nil {
			for _, finding := range e.taintFindings {
				if e.matchTaintFlowFinding(finding, cond.TaintFlow) {
					matched = true
					break
				}
			}
		}
	}

	if cond.Negate {
		matched = !matched
	}
	return matched
}

// =============================================================================
// 匹配辅助方法
// =============================================================================

// matchCallExpr 检查调用表达式是否匹配。
func (e *IRRuleEngine) matchCallExpr(call CallExpr, match *IRCallMatch) bool {
	if match.FuncName != "" {
		if !strings.Contains(strings.ToLower(call.FuncName), strings.ToLower(match.FuncName)) {
			return false
		}
	}
	if match.FuncNameExact != "" {
		if call.FuncName != match.FuncNameExact {
			return false
		}
	}
	if match.FuncNamePrefix != "" {
		if !strings.HasPrefix(call.FuncName, match.FuncNamePrefix) {
			return false
		}
	}
	if match.Receiver != "" {
		if !strings.Contains(strings.ToLower(call.Receiver), strings.ToLower(match.Receiver)) {
			return false
		}
	}
	if match.IsDynamic != nil {
		if call.IsDynamic != *match.IsDynamic {
			return false
		}
	}
	if match.ArgContains != "" {
		found := false
		for i, arg := range call.Args {
			if match.ArgIndex >= 0 && i != match.ArgIndex {
				continue
			}
			if strings.Contains(strings.ToLower(arg), strings.ToLower(match.ArgContains)) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// matchTaintFlowFinding 检查污点发现是否匹配。
func (e *IRRuleEngine) matchTaintFlowFinding(finding TaintFinding, match *IRTaintFlowMatch) bool {
	if match.SourceCategory != "" {
		if !strings.Contains(finding.Source.Category, match.SourceCategory) {
			return false
		}
	}
	if match.SinkCategory != "" {
		sinkCat := ClassifyCall(finding.Sink.Call.FuncName)
		if sinkCat != match.SinkCategory {
			return false
		}
	}
	if match.SourceCall != nil {
		// 用 source 变量名作为近似匹配
		sourceMatched := false
		for _, file := range e.files {
			for _, call := range file.AllCallExprs() {
				if strings.Contains(call.FuncName, finding.Source.VarName) || strings.Contains(finding.Source.VarName, call.FuncName) {
					if e.matchCallExpr(call, match.SourceCall) {
						sourceMatched = true
						break
					}
				}
			}
			if sourceMatched {
				break
			}
		}
		if !sourceMatched {
			return false
		}
	}
	if match.SinkCall != nil {
		if !e.matchCallExpr(finding.Sink.Call, match.SinkCall) {
			return false
		}
	}
	return true
}

// matchChainResult 检查链验证结果是否匹配。
func (e *IRRuleEngine) matchChainResult(chain ChainVerificationResult, match *IRTaintFlowMatch) bool {
	if match.SourceCategory != "" && match.SinkCategory != "" {
		pattern := findChainPattern(chain.PatternID)
		if pattern == nil {
			return false
		}
		return string(pattern.SourceCategory) == match.SourceCategory &&
			string(pattern.SinkCategory) == match.SinkCategory
	}
	return true
}

// matchFile 检查文件是否匹配 glob 规则。
func (e *IRRuleEngine) matchFile(path string, include, exclude []string) bool {
	// 简化实现：检查扩展名
	if len(include) > 0 {
		matched := false
		for _, glob := range include {
			if matchGlobSimple(path, glob) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	for _, glob := range exclude {
		if matchGlobSimple(path, glob) {
			return false
		}
	}
	return true
}

// findNodesByCategory 查找包含指定类别调用的节点。
func (e *IRRuleEngine) findNodesByCategory(category CallCategory) []*CallNode {
	var nodes []*CallNode
	for _, node := range e.callGraph.Nodes {
		for _, call := range node.Calls {
			if CallCategory(ClassifyCall(call.FuncName)) == category {
				nodes = append(nodes, node)
				break
			}
		}
		for _, call := range node.ExternalCalls {
			if CallCategory(ClassifyCall(call.FuncName)) == category {
				nodes = append(nodes, node)
				break
			}
		}
	}
	return nodes
}

// findChainPattern 查找链模式。
func findChainPattern(id string) *ChainPattern {
	for _, p := range DefaultChainPatterns() {
		if p.ID == id {
			return &p
		}
	}
	return nil
}

// matchGlobSimple 简化的 glob 匹配。
func matchGlobSimple(path, glob string) bool {
	// 处理 **/*.ext 模式
	if strings.HasPrefix(glob, "**/*.") {
		ext := strings.TrimPrefix(glob, "**/*")
		return strings.HasSuffix(strings.ToLower(path), strings.ToLower(ext))
	}
	// 处理 * 通配符
	if glob == "*" || glob == "**" {
		return true
	}
	// 精确匹配
	return path == glob
}

// =============================================================================
// 规则编译器：旧 YAML 规则 → IR 规则
// =============================================================================

// CompileYAMLRuleToIR 将旧的 YAML Detection 编译为 IR 规则。
// 实现向后兼容：旧规则自动降级为基础 IR 匹配。
func CompileYAMLRuleToIR(id, name, severity, layer string, detectionType string, patterns []string, includeGlobs []string) *IRRule {
	rule := &IRRule{
		ID:       id,
		Name:     name,
		Severity: severity,
		Layer:    layer,
		Detection: IRDetection{
			IncludeGlobs: includeGlobs,
			PassIf:       "match_found",
		},
	}

	switch detectionType {
	case "forbid_pattern":
		// forbid_pattern → ir_call 或 ir_category（如果有已知模式）
		rule.Detection.PassIf = "no_match"
		rule.Detection.Type = "ir_call"
		if compiled := compilePatternsToCallMatch(patterns); compiled != nil {
			rule.Detection.Call = compiled
		} else {
			// 无法编译为精确匹配，降级为类别匹配
			rule.Detection.Type = "ir_category"
			rule.Detection.Category = compilePatternsToCategory(patterns)
		}

	case "require_pattern":
		rule.Detection.PassIf = "match_found"
		rule.Detection.Type = "ir_call"
		if compiled := compilePatternsToCallMatch(patterns); compiled != nil {
			rule.Detection.Call = compiled
		} else {
			rule.Detection.Type = "ir_category"
			rule.Detection.Category = compilePatternsToCategory(patterns)
		}

	case "pattern":
		rule.Detection.Type = "ir_category"
		rule.Detection.Category = compilePatternsToCategory(patterns)

	default:
		// 不支持的类型，返回 nil
		return nil
	}

	return rule
}

// compilePatternsToCallMatch 将正则模式编译为调用匹配。
func compilePatternsToCallMatch(patterns []string) *IRCallMatch {
	if len(patterns) == 0 {
		return nil
	}

	// 尝试从正则中提取函数名
	for _, p := range patterns {
		// 处理常见的模式：func_name( 或 module.func_name
		cleaned := strings.TrimPrefix(p, "^")
		cleaned = strings.TrimSuffix(cleaned, "$")
		cleaned = strings.TrimSuffix(cleaned, "(")
		cleaned = strings.TrimSuffix(cleaned, "\\(")
		cleaned = strings.ReplaceAll(cleaned, "\\", "")
		cleaned = strings.ReplaceAll(cleaned, ".*", "")
		cleaned = strings.TrimSpace(cleaned)

		if cleaned != "" && !strings.Contains(cleaned, "(") && !strings.Contains(cleaned, "[") {
			// 看起来像函数名
			return &IRCallMatch{
				FuncName: cleaned,
			}
		}
	}

	return nil
}

// compilePatternsToCategory 将正则模式编译为类别匹配。
func compilePatternsToCategory(patterns []string) *IRCategoryMatch {
	categories := map[string]bool{}

	for _, p := range patterns {
		lower := strings.ToLower(p)
		switch {
		case strings.Contains(lower, "os.system") || strings.Contains(lower, "subprocess") || strings.Contains(lower, "exec") || strings.Contains(lower, "eval"):
			categories[string(CatCommandExec)] = true
		case strings.Contains(lower, "requests") || strings.Contains(lower, "http") || strings.Contains(lower, "fetch") || strings.Contains(lower, "axios"):
			categories[string(CatNetworkAccess)] = true
		case strings.Contains(lower, "readfile") || strings.Contains(lower, "open") || strings.Contains(lower, "read"):
			categories[string(CatFileRead)] = true
		case strings.Contains(lower, "writefile") || strings.Contains(lower, "write") || strings.Contains(lower, "save"):
			categories[string(CatFileWrite)] = true
		case strings.Contains(lower, "getenv") || strings.Contains(lower, "environ") || strings.Contains(lower, "process.env"):
			categories[string(CatEnvAccess)] = true
		case strings.Contains(lower, "crypto") || strings.Contains(lower, "encrypt") || strings.Contains(lower, "hash"):
			categories[string(CatCryptoOp)] = true
		}
	}

	if len(categories) == 0 {
		return nil
	}

	catList := make([]string, 0, len(categories))
	for cat := range categories {
		catList = append(catList, cat)
	}
	return &IRCategoryMatch{
		Categories: catList,
		MinCount:   1,
	}
}

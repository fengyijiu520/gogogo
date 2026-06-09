package ir

import (
	"fmt"
	"strings"
)

// =============================================================================
// 结构化模式匹配
//
// 替代正则表达式，在 AST/IR 上做结构化匹配。
// 比正则的优势：
//   - 不受代码格式/换行/注释影响
//   - 可以匹配语义结构（函数调用、赋值、导入）
//   - 支持通配符和约束条件
//   - 可以追踪数据流
// =============================================================================

// Pattern 表示一个结构化匹配模式。
type Pattern struct {
	// Kind 模式类型
	Kind PatternKind `json:"kind"`
	// Rules 匹配规则列表（AND 关系）
	Rules []MatchRule `json:"rules"`
	// Description 模式描述（用于报告）
	Description string `json:"description,omitempty"`
}

// PatternKind 模式类型。
type PatternKind string

const (
	// PatternCall 匹配调用表达式
	PatternCall PatternKind = "call"
	// PatternAssignment 匹配赋值/变量声明
	PatternAssignment PatternKind = "assignment"
	// PatternImport 匹配导入声明
	PatternImport PatternKind = "import"
	// PatternCallChain 匹配调用链（A 调用后跟 B 调用）
	PatternCallChain PatternKind = "call_chain"
	// PatternDataFlow 匹配数据流（source → sink）
	PatternDataFlow PatternKind = "data_flow"
)

// MatchRule 单条匹配规则。
type MatchRule struct {
	// Field 要匹配的字段（func_name, receiver, arg, var_name, module, ...）
	Field string `json:"field"`
	// Op 匹配操作（eq, contains, prefix, suffix, regex, any）
	Op MatchOp `json:"op"`
	// Value 匹配值
	Value string `json:"value"`
	// Negate 是否取反
	Negate bool `json:"negate,omitempty"`
}

// MatchOp 匹配操作。
type MatchOp string

const (
	OpEq       MatchOp = "eq"       // 精确匹配
	OpContains MatchOp = "contains" // 包含
	OpPrefix   MatchOp = "prefix"   // 前缀
	OpSuffix   MatchOp = "suffix"   // 后缀
	OpAny      MatchOp = "any"      // 任意值（字段存在即可）
	OpIn       MatchOp = "in"       // 在列表中（Value 用逗号分隔）
)

// MatchResult 匹配结果。
type MatchResult struct {
	// Matched 是否匹配
	Matched bool `json:"matched"`
	// Findings 匹配到的发现
	Findings []Finding `json:"findings,omitempty"`
	// MatchedNodes 匹配到的节点信息
	MatchedNodes []MatchedNode `json:"matched_nodes,omitempty"`
}

// MatchedNode 匹配到的节点。
type MatchedNode struct {
	// Kind 节点类型
	Kind string `json:"kind"`
	// Name 节点名称
	Name string `json:"name"`
	// Location 位置
	Location string `json:"location"`
	// Context 上下文（所在函数等）
	Context string `json:"context,omitempty"`
}

// =============================================================================
// 模式匹配器
// =============================================================================

// PatternMatcher 模式匹配器。
type PatternMatcher struct {
	patterns []Pattern
}

// NewPatternMatcher 创建模式匹配器。
func NewPatternMatcher(patterns []Pattern) *PatternMatcher {
	return &PatternMatcher{patterns: patterns}
}

// MatchFile 对文件执行所有模式匹配。
func (m *PatternMatcher) MatchFile(file File) []Finding {
	var findings []Finding
	for _, pattern := range m.patterns {
		result := m.matchPattern(file, pattern)
		if result.Matched {
			findings = append(findings, result.Findings...)
		}
	}
	return findings
}

// MatchFiles 对多个文件执行模式匹配。
func (m *PatternMatcher) MatchFiles(files []File) []Finding {
	var findings []Finding
	for _, file := range files {
		findings = append(findings, m.MatchFile(file)...)
	}
	return findings
}

// matchPattern 对文件执行单个模式匹配。
func (m *PatternMatcher) matchPattern(file File, pattern Pattern) MatchResult {
	switch pattern.Kind {
	case PatternCall:
		return m.matchCallPattern(file, pattern)
	case PatternAssignment:
		return m.matchAssignmentPattern(file, pattern)
	case PatternImport:
		return m.matchImportPattern(file, pattern)
	case PatternCallChain:
		return m.matchCallChainPattern(file, pattern)
	case PatternDataFlow:
		return m.matchDataFlowPattern(file, pattern)
	default:
		return MatchResult{}
	}
}

// matchCallPattern 匹配调用表达式模式。
func (m *PatternMatcher) matchCallPattern(file File, pattern Pattern) MatchResult {
	result := MatchResult{}
	allCalls := file.AllCallExprs()

	for _, call := range allCalls {
		if m.matchCall(call, pattern.Rules) {
			result.Matched = true
			finding := Finding{
				RuleID:      "PATTERN-CALL",
				Severity:    "中风险",
				Title:       pattern.Description,
				Description: fmt.Sprintf("匹配到调用: %s", call.FuncName),
				Location:    Location(file.Path, call.Line),
				CodeSnippet: fmt.Sprintf("%s(...)", call.FuncName),
				Source:      &call,
				Category:    ClassifyCall(call.FuncName),
			}
			result.Findings = append(result.Findings, finding)
			result.MatchedNodes = append(result.MatchedNodes, MatchedNode{
				Kind:     "call",
				Name:     call.FuncName,
				Location: Location(file.Path, call.Line),
				Context:  call.Context,
			})
		}
	}
	return result
}

// matchAssignmentPattern 匹配赋值模式。
func (m *PatternMatcher) matchAssignmentPattern(file File, pattern Pattern) MatchResult {
	result := MatchResult{}
	allAssignments := file.Assignments

	for _, fn := range file.Functions {
		allAssignments = append(allAssignments, fn.Assignments...)
	}

	for _, assign := range allAssignments {
		if m.matchAssignment(assign, pattern.Rules) {
			result.Matched = true
			finding := Finding{
				RuleID:      "PATTERN-ASSIGN",
				Severity:    "中风险",
				Title:       pattern.Description,
				Description: fmt.Sprintf("匹配到赋值: %s", assign.VarName),
				Location:    Location(file.Path, assign.Line),
				CodeSnippet: assign.RHS,
				Category:    "assignment",
			}
			result.Findings = append(result.Findings, finding)
		}
	}
	return result
}

// matchImportPattern 匹配导入模式。
func (m *PatternMatcher) matchImportPattern(file File, pattern Pattern) MatchResult {
	result := MatchResult{}

	for _, imp := range file.Imports {
		if m.matchImport(imp, pattern.Rules) {
			result.Matched = true
			finding := Finding{
				RuleID:      "PATTERN-IMPORT",
				Severity:    "低风险",
				Title:       pattern.Description,
				Description: fmt.Sprintf("匹配到导入: %s", imp.Module),
				Location:    Location(file.Path, imp.Line),
				CodeSnippet: imp.Module,
				Category:    "import",
			}
			result.Findings = append(result.Findings, finding)
		}
	}
	return result
}

// matchCallChainPattern 匹配调用链模式。
// 检查同一函数内是否存在规则 A 调用后跟规则 B 调用。
func (m *PatternMatcher) matchCallChainPattern(file File, pattern Pattern) MatchResult {
	result := MatchResult{}

	if len(pattern.Rules) < 2 {
		return result
	}

	ruleA := pattern.Rules[0]
	ruleB := pattern.Rules[1]

	for _, fn := range file.Functions {
		calls := fn.Calls
		for i, callA := range calls {
			if !m.matchSingleCall(callA, ruleA) {
				continue
			}
			// 检查后续是否有匹配 B 的调用
			for _, callB := range calls[i+1:] {
				if m.matchSingleCall(callB, ruleB) {
					result.Matched = true
					finding := Finding{
						RuleID:      "PATTERN-CHAIN",
						Severity:    "高风险",
						Title:       pattern.Description,
						Description: fmt.Sprintf("调用链: %s → %s", callA.FuncName, callB.FuncName),
						Location:    Location(file.Path, callA.Line),
						CodeSnippet: fmt.Sprintf("%s → %s", callA.FuncName, callB.FuncName),
						DataFlow: []DataFlowStep{
							{Kind: "source", Location: Location(file.Path, callA.Line), Description: callA.FuncName},
							{Kind: "sink", Location: Location(file.Path, callB.Line), Description: callB.FuncName},
						},
						Category: "call_chain",
					}
					result.Findings = append(result.Findings, finding)
					break
				}
			}
		}
	}
	return result
}

// matchDataFlowPattern 匹配数据流模式。
// 检查是否存在 source 变量传播到 sink 调用。
func (m *PatternMatcher) matchDataFlowPattern(file File, pattern Pattern) MatchResult {
	result := MatchResult{}

	if len(pattern.Rules) < 2 {
		return result
	}

	ruleSource := pattern.Rules[0]
	ruleSink := pattern.Rules[1]

	// 收集所有赋值，标记 source
	taintedVars := map[string]string{} // varName → source description
	allAssignments := file.Assignments
	for _, fn := range file.Functions {
		allAssignments = append(allAssignments, fn.Assignments...)
	}

	for _, assign := range allAssignments {
		if m.matchAssignment(assign, []MatchRule{ruleSource}) {
			taintedVars[assign.VarName] = assign.RHS
		}
	}

	// 检查 sink 调用是否使用了 tainted 变量
	allCalls := file.AllCallExprs()
	for _, call := range allCalls {
		if !m.matchCall(call, []MatchRule{ruleSink}) {
			continue
		}
		// 检查参数是否包含 tainted 变量
		for _, arg := range call.Args {
			arg = strings.TrimSpace(arg)
			if source, ok := taintedVars[arg]; ok {
				result.Matched = true
				finding := Finding{
					RuleID:      "PATTERN-DATAFLOW",
					Severity:    "高风险",
					Title:       pattern.Description,
					Description: fmt.Sprintf("数据流: %s → %s(%s)", source, call.FuncName, arg),
					Location:    Location(file.Path, call.Line),
					CodeSnippet: fmt.Sprintf("%s = %s → %s(%s)", arg, source, call.FuncName, arg),
					DataFlow: []DataFlowStep{
						{Kind: "source", VarName: arg, Description: source},
						{Kind: "sink", VarName: arg, Location: Location(file.Path, call.Line), Description: call.FuncName},
					},
					Category: "data_flow",
				}
				result.Findings = append(result.Findings, finding)
				break
			}
		}
	}
	return result
}

// =============================================================================
// 规则匹配
// =============================================================================

// matchCall 检查调用是否匹配所有规则。
func (m *PatternMatcher) matchCall(call CallExpr, rules []MatchRule) bool {
	for _, rule := range rules {
		if !m.matchSingleCall(call, rule) {
			return false
		}
	}
	return true
}

// matchSingleCall 检查调用是否匹配单条规则。
func (m *PatternMatcher) matchSingleCall(call CallExpr, rule MatchRule) bool {
	var matched bool
	switch rule.Field {
	case "func_name":
		matched = m.matchValue(call.FuncName, rule.Op, rule.Value)
	case "receiver":
		matched = m.matchValue(call.Receiver, rule.Op, rule.Value)
	case "context":
		matched = m.matchValue(call.Context, rule.Op, rule.Value)
	case "category":
		matched = m.matchValue(ClassifyCall(call.FuncName), rule.Op, rule.Value)
	case "arg":
		// 匹配任意参数
		matched = false
		for _, arg := range call.Args {
			if m.matchValue(arg, rule.Op, rule.Value) {
				matched = true
				break
			}
		}
	default:
		matched = false
	}
	if rule.Negate {
		matched = !matched
	}
	return matched
}

// matchAssignment 检查赋值是否匹配所有规则。
func (m *PatternMatcher) matchAssignment(assign Assignment, rules []MatchRule) bool {
	for _, rule := range rules {
		var matched bool
		switch rule.Field {
		case "var_name":
			matched = m.matchValue(assign.VarName, rule.Op, rule.Value)
		case "rhs":
			matched = m.matchValue(assign.RHS, rule.Op, rule.Value)
		case "taint_source":
			matched = m.matchValue(assign.TaintSource, rule.Op, rule.Value)
		default:
			matched = false
		}
		if rule.Negate {
			matched = !matched
		}
		if !matched {
			return false
		}
	}
	return true
}

// matchImport 检查导入是否匹配所有规则。
func (m *PatternMatcher) matchImport(imp Import, rules []MatchRule) bool {
	for _, rule := range rules {
		var matched bool
		switch rule.Field {
		case "module":
			matched = m.matchValue(imp.Module, rule.Op, rule.Value)
		case "alias":
			matched = m.matchValue(imp.Alias, rule.Op, rule.Value)
		case "item":
			matched = false
			for _, item := range imp.Items {
				if m.matchValue(item, rule.Op, rule.Value) {
					matched = true
					break
				}
			}
		default:
			matched = false
		}
		if rule.Negate {
			matched = !matched
		}
		if !matched {
			return false
		}
	}
	return true
}

// matchValue 检查值是否匹配规则。
func (m *PatternMatcher) matchValue(value string, op MatchOp, pattern string) bool {
	switch op {
	case OpEq:
		return strings.EqualFold(value, pattern)
	case OpContains:
		return strings.Contains(strings.ToLower(value), strings.ToLower(pattern))
	case OpPrefix:
		return strings.HasPrefix(strings.ToLower(value), strings.ToLower(pattern))
	case OpSuffix:
		return strings.HasSuffix(strings.ToLower(value), strings.ToLower(pattern))
	case OpAny:
		return strings.TrimSpace(value) != ""
	case OpIn:
		for _, item := range strings.Split(pattern, ",") {
			if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(item)) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

// =============================================================================
// 预定义模式工厂
// =============================================================================

// NewCallPattern 创建调用匹配模式。
func NewCallPattern(funcName string, description string) Pattern {
	return Pattern{
		Kind: PatternCall,
		Rules: []MatchRule{
			{Field: "func_name", Op: OpContains, Value: funcName},
		},
		Description: description,
	}
}

// NewCallCategoryPattern 创建按类别匹配调用的模式。
func NewCallCategoryPattern(category string, description string) Pattern {
	return Pattern{
		Kind: PatternCall,
		Rules: []MatchRule{
			{Field: "category", Op: OpEq, Value: category},
		},
		Description: description,
	}
}

// NewCallChainPattern 创建调用链模式。
func NewCallChainPattern(funcA, funcB, description string) Pattern {
	return Pattern{
		Kind: PatternCallChain,
		Rules: []MatchRule{
			{Field: "func_name", Op: OpContains, Value: funcA},
			{Field: "func_name", Op: OpContains, Value: funcB},
		},
		Description: description,
	}
}

// NewDataFlowPattern 创建数据流模式。
func NewDataFlowPattern(sourceRHS, sinkFunc, description string) Pattern {
	return Pattern{
		Kind: PatternDataFlow,
		Rules: []MatchRule{
			{Field: "rhs", Op: OpContains, Value: sourceRHS},
			{Field: "func_name", Op: OpContains, Value: sinkFunc},
		},
		Description: description,
	}
}

// NewImportPattern 创建导入匹配模式。
func NewImportPattern(module string, description string) Pattern {
	return Pattern{
		Kind: PatternImport,
		Rules: []MatchRule{
			{Field: "module", Op: OpContains, Value: module},
		},
		Description: description,
	}
}

// =============================================================================
// 常用安全模式
// =============================================================================

// DangerousCallPatterns 返回已知危险调用的模式列表。
func DangerousCallPatterns() []Pattern {
	return []Pattern{
		// 命令执行
		NewCallPattern("os.system", "检测到 os.system 命令执行"),
		NewCallPattern("subprocess", "检测到 subprocess 子进程调用"),
		NewCallPattern("exec.Command", "检测到 Go exec.Command 调用"),
		NewCallPattern("Runtime.exec", "检测到 Java Runtime.exec 调用"),
		NewCallPattern("child_process", "检测到 Node.js child_process 调用"),

		// 网络请求
		NewCallPattern("requests.post", "检测到 requests.post 外联"),
		NewCallPattern("requests.get", "检测到 requests.get 外联"),
		NewCallPattern("axios.post", "检测到 axios.post 外联"),
		NewCallPattern("http.Post", "检测到 Go http.Post 外联"),

		// 文件操作
		NewCallPattern("os.ReadFile", "检测到文件读取"),
		NewCallPattern("os.WriteFile", "检测到文件写入"),
		NewCallPattern("writeFile", "检测到文件写入"),

		// 环境变量
		NewCallPattern("os.Getenv", "检测到环境变量访问"),
		NewCallPattern("process.env", "检测到环境变量访问"),
	}
}

// DataFlowPatterns 返回数据流安全模式。
func DataFlowPatterns() []Pattern {
	return []Pattern{
		// 环境变量 → 网络请求（凭据外发）
		NewDataFlowPattern("os.getenv", "requests.post", "环境变量经网络外发"),
		NewDataFlowPattern("os.Getenv", "http.Post", "环境变量经网络外发"),
		NewDataFlowPattern("process.env", "axios.post", "环境变量经网络外发"),

		// 文件读取 → 网络请求（数据外泄）
		NewCallChainPattern("os.ReadFile", "http.Post", "文件内容经网络外发"),
		NewCallChainPattern("readFile", "requests.post", "文件内容经网络外发"),

		// 网络下载 → 命令执行（远程代码执行）
		NewCallChainPattern("requests.get", "exec", "下载后执行"),
		NewCallChainPattern("http.Get", "exec.Command", "下载后执行"),
	}
}

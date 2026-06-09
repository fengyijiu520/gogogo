package ir

import (
	"fmt"
	"strings"
)

// =============================================================================
// 污点分析 (Taint Analysis)
//
// 污点分析是安全分析的核心技术，用于追踪不可信数据从 source 到 sink 的传播。
//
// 三类规则：
//   - Source：数据来源（用户输入、环境变量、配置文件等）
//   - Sink：数据去向（网络请求、命令执行、文件写入等）
//   - Transform：数据转换（赋值、拼接、编码等）
//
// 分析流程：
//   1. 标记所有 source 变量为"受污染"
//   2. 追踪污点在赋值/参数传递中的传播
//   3. 检查 sink 调用是否使用了受污染的数据
// =============================================================================

// TaintRule 污点规则。
type TaintRule struct {
	// ID 规则标识
	ID string `json:"id"`
	// Kind 规则类型：source / sink / transform
	Kind TaintRuleKind `json:"kind"`
	// Category 安全类别
	Category string `json:"category"`
	// Description 描述
	Description string `json:"description"`
	// Severity 严重性
	Severity string `json:"severity"`
	// MatchFunc 匹配函数（用于 source/sink）
	MatchFunc TaintMatchFunc `json:"-"`
	// MatchCall 匹配调用表达式（用于 source/sink）
	MatchCall CallMatchRule `json:"match_call,omitempty"`
	// MatchAssign 匹配赋值表达式（用于 source）
	MatchAssign AssignMatchRule `json:"match_assign,omitempty"`
	// PropagationRules 污点传播规则（用于 transform）
	PropagationRules []PropagationRule `json:"propagation_rules,omitempty"`
}

// TaintRuleKind 污点规则类型。
type TaintRuleKind string

const (
	TaintSource    TaintRuleKind = "source"
	TaintSink      TaintRuleKind = "sink"
	TaintTransform TaintRuleKind = "transform"
)

// CallMatchRule 调用匹配规则。
type CallMatchRule struct {
	// FuncNamePattern 函数名模式（contains 匹配）
	FuncNamePattern string `json:"func_name_pattern"`
	// ArgIndex 哪个参数受污染（-1 表示任意参数）
	ArgIndex int `json:"arg_index"`
	// ArgPattern 参数文本模式（可选）
	ArgPattern string `json:"arg_pattern,omitempty"`
}

// AssignMatchRule 赋值匹配规则。
type AssignMatchRule struct {
	// RHSPattern 右值模式（contains 匹配）
	RHSPattern string `json:"rhs_pattern"`
}

// PropagationRule 污点传播规则。
type PropagationRule struct {
	// Trigger 触发条件
	Trigger string `json:"trigger"`
	// Description 描述
	Description string `json:"description"`
}

// TaintMatchFunc 自定义匹配函数。
type TaintMatchFunc func(call CallExpr) bool

// =============================================================================
// 污点标记
// =============================================================================

// TaintTag 污点标记。
type TaintTag struct {
	// VarName 变量名
	VarName string `json:"var_name"`
	// Source 来源规则 ID
	Source string `json:"source"`
	// Category 安全类别
	Category string `json:"category"`
	// Location 位置
	Location string `json:"location"`
	// PropagationPath 传播路径
	PropagationPath []string `json:"propagation_path,omitempty"`
}

// TaintSinkPoint 污点汇聚点。
type TaintSinkPoint struct {
	// Call 调用表达式
	Call CallExpr `json:"call"`
	// Rule 触发的规则
	Rule *TaintRule `json:"rule"`
	// TaintedArgs 受污染的参数
	TaintedArgs []TaintedArg `json:"tainted_args"`
	// Location 位置
	Location string `json:"location"`
}

// TaintedArg 受污染的参数。
type TaintedArg struct {
	// Index 参数索引
	Index int `json:"index"`
	// Text 参数文本
	Text string `json:"text"`
	// TaintSource 污点来源
	TaintSource *TaintTag `json:"taint_source"`
}

// TaintFinding 污点分析发现。
type TaintFinding struct {
	// RuleID 规则标识
	RuleID string `json:"rule_id"`
	// Severity 严重性
	Severity string `json:"severity"`
	// Title 标题
	Title string `json:"title"`
	// Description 描述
	Description string `json:"description"`
	// Category 安全类别
	Category string `json:"category"`
	// Source 污点来源
	Source *TaintTag `json:"source"`
	// Sink 污点汇聚
	Sink *TaintSinkPoint `json:"sink"`
	// DataFlow 数据流路径
	DataFlow []DataFlowStep `json:"data_flow"`
	// Location 位置
	Location string `json:"location"`
	// Confidence 置信度
	Confidence string `json:"confidence"`
}

// =============================================================================
// 污点分析器
// =============================================================================

// TaintAnalyzer 污点分析器。
type TaintAnalyzer struct {
	rules   []TaintRule
	sources map[string]*TaintRule
	sinks   map[string]*TaintRule
}

// NewTaintAnalyzer 创建污点分析器。
func NewTaintAnalyzer(rules []TaintRule) *TaintAnalyzer {
	a := &TaintAnalyzer{
		rules:   rules,
		sources: make(map[string]*TaintRule),
		sinks:   make(map[string]*TaintRule),
	}
	for i := range rules {
		switch rules[i].Kind {
		case TaintSource:
			a.sources[rules[i].ID] = &rules[i]
		case TaintSink:
			a.sinks[rules[i].ID] = &rules[i]
		}
	}
	return a
}

// Analyze 对文件执行污点分析。
func (a *TaintAnalyzer) Analyze(files []File) []TaintFinding {
	var findings []TaintFinding

	for _, file := range files {
		fileFindings := a.analyzeFile(file)
		findings = append(findings, fileFindings...)
	}

	return findings
}

// analyzeFile 对单个文件执行污点分析。
func (a *TaintAnalyzer) analyzeFile(file File) []TaintFinding {
	var findings []TaintFinding

	// 收集所有赋值（顶层 + 函数内）
	allAssignments := file.Assignments
	for _, fn := range file.Functions {
		allAssignments = append(allAssignments, fn.Assignments...)
	}

	// 第一步：标记 source
	taintTags := a.markSources(file, allAssignments)

	// 第二步：追踪传播
	taintTags = a.propagateTaint(file, allAssignments, taintTags)

	// 第三步：检查 sink
	sinks := a.checkSinks(file, taintTags)

	// 第四步：生成发现
	for _, sink := range sinks {
		finding := a.createFinding(sink, taintTags)
		findings = append(findings, finding)
	}

	return findings
}

// markSources 标记所有 source 变量。
func (a *TaintAnalyzer) markSources(file File, assignments []Assignment) map[string]*TaintTag {
	taintTags := make(map[string]*TaintTag)

	// 从赋值中标记 source
	for _, assign := range assignments {
		for _, rule := range a.rules {
			if rule.Kind != TaintSource {
				continue
			}
			if a.matchSource(assign, rule) {
				taintTags[assign.VarName] = &TaintTag{
					VarName:  assign.VarName,
					Source:   rule.ID,
					Category: rule.Category,
					Location: Location(file.Path, assign.Line),
				}
			}
		}
	}

	// 从调用中标记 source（如 os.getenv 的返回值）
	allCalls := file.AllCallExprs()
	for _, call := range allCalls {
		for _, rule := range a.rules {
			if rule.Kind != TaintSource {
				continue
			}
			if a.matchCallSource(call, rule) {
				// 查找接收此调用结果的赋值
				for _, assign := range assignments {
					if strings.Contains(assign.RHS, call.FuncName) {
						taintTags[assign.VarName] = &TaintTag{
							VarName:  assign.VarName,
							Source:   rule.ID,
							Category: rule.Category,
							Location: Location(file.Path, assign.Line),
						}
					}
				}
			}
		}
	}

	return taintTags
}

// matchSource 检查赋值是否匹配 source 规则。
func (a *TaintAnalyzer) matchSource(assign Assignment, rule TaintRule) bool {
	if rule.MatchFunc != nil {
		// 自定义匹配函数
		return false
	}
	if rule.MatchAssign.RHSPattern != "" {
		return strings.Contains(strings.ToLower(assign.RHS), strings.ToLower(rule.MatchAssign.RHSPattern))
	}
	return false
}

// matchCallSource 检查调用是否匹配 source 规则。
func (a *TaintAnalyzer) matchCallSource(call CallExpr, rule TaintRule) bool {
	if rule.MatchFunc != nil {
		return rule.MatchFunc(call)
	}
	if rule.MatchCall.FuncNamePattern != "" {
		return strings.Contains(strings.ToLower(call.FuncName), strings.ToLower(rule.MatchCall.FuncNamePattern))
	}
	return false
}

// propagateTaint 追踪污点传播。
func (a *TaintAnalyzer) propagateTaint(file File, assignments []Assignment, taintTags map[string]*TaintTag) map[string]*TaintTag {
	// 多轮传播，直到没有新标记
	changed := true
	for changed {
		changed = false
		for _, assign := range assignments {
			if _, alreadyTainted := taintTags[assign.VarName]; alreadyTainted {
				continue
			}
			// 检查右值是否引用了受污染的变量（精确词边界匹配）
			for varName, tag := range taintTags {
				if containsVarRef(assign.RHS, varName) {
					newTag := &TaintTag{
						VarName:  assign.VarName,
						Source:   tag.Source,
						Category: tag.Category,
						Location: tag.Location,
						PropagationPath: append(append([]string(nil), tag.PropagationPath...),
							fmt.Sprintf("%s → %s", varName, assign.VarName)),
					}
					taintTags[assign.VarName] = newTag
					changed = true
					break
				}
			}
		}
	}
	return taintTags
}

// checkSinks 检查所有 sink 调用是否使用了受污染的数据。
func (a *TaintAnalyzer) checkSinks(file File, taintTags map[string]*TaintTag) []TaintSinkPoint {
	var sinks []TaintSinkPoint

	// 收集所有调用
	allCalls := file.AllCallExprs()

	for _, call := range allCalls {
		for _, rule := range a.rules {
			if rule.Kind != TaintSink {
				continue
			}
			if !a.matchSink(call, rule) {
				continue
			}
			// 检查参数是否受污染
			taintedArgs := a.checkArgsTaint(call, taintTags)
			if len(taintedArgs) > 0 {
				sinks = append(sinks, TaintSinkPoint{
					Call:        call,
					Rule:        &rule,
					TaintedArgs: taintedArgs,
					Location:    Location(file.Path, call.Line),
				})
			}
		}
	}

	return sinks
}

// matchSink 检查调用是否匹配 sink 规则。
func (a *TaintAnalyzer) matchSink(call CallExpr, rule TaintRule) bool {
	if rule.MatchFunc != nil {
		return rule.MatchFunc(call)
	}
	if rule.MatchCall.FuncNamePattern != "" {
		return strings.Contains(strings.ToLower(call.FuncName), strings.ToLower(rule.MatchCall.FuncNamePattern))
	}
	return false
}

// checkArgsTaint 检查调用参数是否受污染。
func (a *TaintAnalyzer) checkArgsTaint(call CallExpr, taintTags map[string]*TaintTag) []TaintedArg {
	var taintedArgs []TaintedArg

	for i, arg := range call.Args {
		arg = strings.TrimSpace(arg)
		// 检查参数是否直接引用了受污染的变量（精确词边界匹配）
		for varName, tag := range taintTags {
			if arg == varName || containsVarRef(arg, varName) {
				taintedArgs = append(taintedArgs, TaintedArg{
					Index:       i,
					Text:        arg,
					TaintSource: tag,
				})
				break
			}
		}
	}

	return taintedArgs
}

// createFinding 从 sink 创建发现。
func (a *TaintAnalyzer) createFinding(sink TaintSinkPoint, taintTags map[string]*TaintTag) TaintFinding {
	source := sink.TaintedArgs[0].TaintSource

	dataFlow := []DataFlowStep{
		{Kind: "source", VarName: source.VarName, Location: source.Location, Description: source.Category},
	}
	if len(source.PropagationPath) > 0 {
		for _, step := range source.PropagationPath {
			dataFlow = append(dataFlow, DataFlowStep{Kind: "transform", Description: step})
		}
	}
	dataFlow = append(dataFlow, DataFlowStep{
		Kind:        "sink",
		VarName:     sink.TaintedArgs[0].Text,
		Location:    sink.Location,
		Description: sink.Call.FuncName,
	})

	return TaintFinding{
		RuleID:      sink.Rule.ID,
		Severity:    sink.Rule.Severity,
		Title:       sink.Rule.Description,
		Description: fmt.Sprintf("污点数据从 %s 传播到 %s", source.VarName, sink.Call.FuncName),
		Category:    sink.Rule.Category,
		Source:      source,
		Sink:        &sink,
		DataFlow:    dataFlow,
		Location:    sink.Location,
		Confidence:  "高",
	}
}

// =============================================================================
// 预定义污点规则
// =============================================================================

// DefaultTaintRules 返回默认的污点分析规则。
func DefaultTaintRules() []TaintRule {
	return []TaintRule{
		// ===== Source 规则 =====

		// 环境变量
		{
			ID:          "source-env",
			Kind:        TaintSource,
			Category:    "env_access",
			Description: "环境变量读取",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "os.getenv",
				ArgIndex:        -1,
			},
		},
		{
			ID:          "source-env-js",
			Kind:        TaintSource,
			Category:    "env_access",
			Description: "环境变量读取",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "process.env",
				ArgIndex:        -1,
			},
		},
		{
			ID:          "source-env-go",
			Kind:        TaintSource,
			Category:    "env_access",
			Description: "环境变量读取",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "os.Getenv",
				ArgIndex:        -1,
			},
		},

		// 用户输入
		{
			ID:          "source-user-input",
			Kind:        TaintSource,
			Category:    "user_input",
			Description: "用户输入",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "input(",
				ArgIndex:        -1,
			},
		},
		{
			ID:          "source-request-params",
			Kind:        TaintSource,
			Category:    "user_input",
			Description: "HTTP 请求参数",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "request.args",
				ArgIndex:        -1,
			},
		},
		{
			ID:          "source-request-body",
			Kind:        TaintSource,
			Category:    "user_input",
			Description: "HTTP 请求体",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "request.json",
				ArgIndex:        -1,
			},
		},
		{
			ID:          "source-url-query",
			Kind:        TaintSource,
			Category:    "user_input",
			Description: "URL 查询参数",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "URL.Query",
				ArgIndex:        -1,
			},
		},

		// 文件读取
		{
			ID:          "source-file-read",
			Kind:        TaintSource,
			Category:    "file_read",
			Description: "文件读取",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "os.ReadFile",
				ArgIndex:        -1,
			},
		},
		{
			ID:          "source-file-read-py",
			Kind:        TaintSource,
			Category:    "file_read",
			Description: "文件读取",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "open(",
				ArgIndex:        -1,
			},
		},

		// ===== Sink 规则 =====

		// 命令执行
		{
			ID:          "sink-cmd-exec",
			Kind:        TaintSink,
			Category:    "command_exec",
			Description: "污点数据进入命令执行",
			Severity:    "高风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "os.system",
				ArgIndex:        0,
			},
		},
		{
			ID:          "sink-subprocess",
			Kind:        TaintSink,
			Category:    "command_exec",
			Description: "污点数据进入子进程",
			Severity:    "高风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "subprocess",
				ArgIndex:        0,
			},
		},
		{
			ID:          "sink-exec-go",
			Kind:        TaintSink,
			Category:    "command_exec",
			Description: "污点数据进入命令执行",
			Severity:    "高风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "exec.Command",
				ArgIndex:        0,
			},
		},

		// 网络请求
		{
			ID:          "sink-network-post",
			Kind:        TaintSink,
			Category:    "network_access",
			Description: "污点数据经网络外发",
			Severity:    "高风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "requests.post",
				ArgIndex:        -1,
			},
		},
		{
			ID:          "sink-network-axios",
			Kind:        TaintSink,
			Category:    "network_access",
			Description: "污点数据经网络外发",
			Severity:    "高风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "axios.post",
				ArgIndex:        -1,
			},
		},
		{
			ID:          "sink-network-go",
			Kind:        TaintSink,
			Category:    "network_access",
			Description: "污点数据经网络外发",
			Severity:    "高风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "http.Post",
				ArgIndex:        -1,
			},
		},

		// 文件写入
		{
			ID:          "sink-file-write",
			Kind:        TaintSink,
			Category:    "file_write",
			Description: "污点数据写入文件",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "os.WriteFile",
				ArgIndex:        1,
			},
		},
		{
			ID:          "sink-file-write-py",
			Kind:        TaintSink,
			Category:    "file_write",
			Description: "污点数据写入文件",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "write(",
				ArgIndex:        0,
			},
		},

		// 日志输出
		{
			ID:          "sink-log",
			Kind:        TaintSink,
			Category:    "data_leak",
			Description: "污点数据输出到日志",
			Severity:    "中风险",
			MatchCall: CallMatchRule{
				FuncNamePattern: "logging.",
				ArgIndex:        -1,
			},
		},
	}
}

// containsVarRef 检查 text 中是否包含 varName 作为完整变量引用（词边界匹配）。
// 避免 "secret" 误匹配 "secretKey"、"my_secret" 等。
func containsVarRef(text, varName string) bool {
	if varName == "" || text == "" {
		return false
	}
	idx := 0
	for {
		pos := strings.Index(text[idx:], varName)
		if pos < 0 {
			return false
		}
		absPos := idx + pos
		// 检查前一个字符是否为标识符字符
		if absPos > 0 {
			if isIdentChar(text[absPos-1]) {
				idx = absPos + len(varName)
				continue
			}
		}
		// 检查后一个字符是否为标识符字符
		endPos := absPos + len(varName)
		if endPos < len(text) {
			if isIdentChar(text[endPos]) {
				idx = endPos
				continue
			}
		}
		return true
	}
}

package ir

import (
	"fmt"
	"strings"
)

// =============================================================================
// 过程间污点分析 (Inter-procedural Taint Analysis)
//
// 当前 TaintAnalyzer 只分析单文件内的赋值链。
// InterprocTaintAnalyzer 通过调用图追踪跨函数的污点传播：
//
//   1. 函数参数传播：caller 传入污点数据 → callee 的参数被污染
//   2. 返回值传播：callee 返回污点数据 → caller 的接收变量被污染
//   3. 跨文件传播：通过 import 解析函数调用
//
// 策略：在 TaintAnalyzer 基础上叠加，不修改原有逻辑。
// =============================================================================

// InterprocTaintAnalyzer 过程间污点分析器。
type InterprocTaintAnalyzer struct {
	rules     []TaintRule
	graph     *CallGraph
	files     []File
	base      *TaintAnalyzer
}

// NewInterprocTaintAnalyzer 创建过程间污点分析器。
func NewInterprocTaintAnalyzer(rules []TaintRule, graph *CallGraph, files []File) *InterprocTaintAnalyzer {
	return &InterprocTaintAnalyzer{
		rules: rules,
		graph: graph,
		files: files,
		base:  NewTaintAnalyzer(rules),
	}
}

// Analyze 执行过程间污点分析。
func (a *InterprocTaintAnalyzer) Analyze() []TaintFinding {
	if a.graph == nil || len(a.files) == 0 {
		return nil
	}

	// 第一步：用基础分析器获取单文件发现
	baseFindings := a.base.Analyze(a.files)

	// 第二步：构建函数签名索引
	funcIndex := a.buildFuncIndex()

	// 第三步：追踪跨函数传播
	interprocFindings := a.analyzeInterproc(funcIndex)

	// 合并去重
	return a.mergeFindings(baseFindings, interprocFindings)
}

// funcInfo 函数信息（用于过程间分析）。
type funcInfo struct {
	node      *CallNode
	file      File
	function  Function
	paramTags map[string]*TaintTag  // 参数的污点标记
	retTags   []*TaintTag           // 返回值的污点标记
}

// buildFuncIndex 构建函数索引。
func (a *InterprocTaintAnalyzer) buildFuncIndex() map[string]*funcInfo {
	index := make(map[string]*funcInfo)

	for _, file := range a.files {
		for i, fn := range file.Functions {
			nodeID := file.Path + ":" + fn.Name
			node := a.graph.GetNode(nodeID)

			info := &funcInfo{
				node:     node,
				file:     file,
				function: file.Functions[i],
			}
			index[nodeID] = info
		}
	}

	return index
}

// analyzeInterproc 执行过程间分析。
func (a *InterprocTaintAnalyzer) analyzeInterproc(funcIndex map[string]*funcInfo) []TaintFinding {
	var findings []TaintFinding

	// 对每个函数调用，检查是否形成跨函数污点流
	for _, callerFile := range a.files {
		for _, callerFn := range callerFile.Functions {
			for _, call := range callerFn.Calls {
				// 解析被调用函数
				calleeInfo := a.resolveCallee(call, callerFile, funcIndex)
				if calleeInfo == nil {
					continue
				}

				// 分析 caller→callee 参数传播
				paramFindings := a.analyzeParamPropagation(call, callerFn, callerFile, calleeInfo)
				findings = append(findings, paramFindings...)

				// 分析 callee→caller 返回值传播
				retFindings := a.analyzeReturnPropagation(call, callerFn, callerFile, calleeInfo)
				findings = append(findings, retFindings...)
			}
		}
	}

	return findings
}

// resolveCallee 解析被调用函数。
func (a *InterprocTaintAnalyzer) resolveCallee(call CallExpr, callerFile File, funcIndex map[string]*funcInfo) *funcInfo {
	// 1. 同文件直接匹配
	nodeID := callerFile.Path + ":" + call.FuncName
	if info, ok := funcIndex[nodeID]; ok {
		return info
	}

	// 2. 通过 import 解析
	for _, imp := range callerFile.Imports {
		for _, item := range imp.Items {
			if item == call.FuncName {
				// from module import func
				resolvedID := imp.Module + ":" + call.FuncName
				if info, ok := funcIndex[resolvedID]; ok {
					return info
				}
			}
		}
	}

	// 3. 全局函数名匹配
	for id, info := range funcIndex {
		if strings.HasSuffix(id, ":"+call.FuncName) {
			return info
		}
	}

	return nil
}

// analyzeParamPropagation 分析参数传播（caller→callee）。
func (a *InterprocTaintAnalyzer) analyzeParamPropagation(call CallExpr, callerFn Function, callerFile File, calleeInfo *funcInfo) []TaintFinding {
	var findings []TaintFinding

	// 获取 caller 中的污点标记
	callerTaints := a.getFileTaints(callerFile)

	// 检查调用参数是否包含污点数据
	for i, arg := range call.Args {
		arg = strings.TrimSpace(arg)
		if arg == "" {
			continue
		}

		// 检查参数是否被污染
		var taintTag *TaintTag
		for varName, tag := range callerTaints {
			if arg == varName || containsVarRef(arg, varName) {
				taintTag = tag
				break
			}
		}

		if taintTag == nil {
			continue
		}

		// 参数被污染，检查 callee 中对应的参数是否流向 sink
		if i < len(calleeInfo.function.Parameters) {
			paramName := calleeInfo.function.Parameters[i].Name
			calleeFindings := a.analyzeCalleeWithTaintedParam(calleeInfo, paramName, taintTag)
			findings = append(findings, calleeFindings...)
		}
	}

	return findings
}

// analyzeReturnPropagation 分析返回值传播（callee→caller）。
func (a *InterprocTaintAnalyzer) analyzeReturnPropagation(call CallExpr, callerFn Function, callerFile File, calleeInfo *funcInfo) []TaintFinding {
	var findings []TaintFinding

	// 检查 callee 是否有污点 source 调用
	calleeTaints := a.getFileTaints(calleeInfo.file)

	// 检查 callee 中是否有 source 调用返回污点数据
	for _, calleeCall := range calleeInfo.function.Calls {
		for _, rule := range a.rules {
			if rule.Kind != TaintSource {
				continue
			}
			if a.base.matchCallSource(calleeCall, rule) {
				// callee 的返回值可能被污染
				// 检查 caller 是否将调用结果传给 sink
				ruleCopy := rule
				callerFindings := a.checkCallerSinkFromReturn(call, callerFn, callerFile, &ruleCopy)
				findings = append(findings, callerFindings...)
			}
		}
	}

	// 检查 callee 内部的污点是否通过返回值传出
	for varName, tag := range calleeTaints {
		// 检查 callee 的返回语句是否引用了污点变量
		if a.functionReturnsTaint(calleeInfo.function, varName) {
			// 返回值被污染，检查 caller 是否将结果传给 sink
			callerFindings := a.checkCallerSinkFromReturn(call, callerFn, callerFile, tag.SourceRule())
			findings = append(findings, callerFindings...)
		}
	}

	return findings
}

// analyzeCalleeWithTaintedParam 分析 callee 中被污染参数的流向。
func (a *InterprocTaintAnalyzer) analyzeCalleeWithTaintedParam(calleeInfo *funcInfo, paramName string, callerTaint *TaintTag) []TaintFinding {
	var findings []TaintFinding

	// 在 callee 中追踪参数的传播
	taintTags := map[string]*TaintTag{
		paramName: {
			VarName:  paramName,
			Source:   callerTaint.Source,
			Category: callerTaint.Category,
			Location: callerTaint.Location,
			PropagationPath: []string{
				fmt.Sprintf("param:%s(from %s)", paramName, callerTaint.VarName),
			},
		},
	}

	// 传播
	assignments := calleeInfo.function.Assignments
	taintTags = a.base.propagulateTaint(assignments, taintTags)

	// 检查 sink
	for _, call := range calleeInfo.function.Calls {
		for _, rule := range a.rules {
			if rule.Kind != TaintSink {
				continue
			}
			if !a.base.matchSink(call, rule) {
				continue
			}
			// 检查参数是否被污染
			for i, arg := range call.Args {
				arg = strings.TrimSpace(arg)
				for varName, tag := range taintTags {
					if arg == varName || containsVarRef(arg, varName) {
						finding := TaintFinding{
							RuleID:   rule.ID,
							Severity: rule.Severity,
							Title:    rule.Description,
							Description: fmt.Sprintf("跨函数污点传播: %s → %s.%s → %s",
								callerTaint.VarName, calleeInfo.function.Name, paramName, call.FuncName),
							Category: rule.Category,
							Source:   callerTaint,
							Sink: &TaintSinkPoint{
								Call: call,
								Rule: &rule,
								TaintedArgs: []TaintedArg{{
									Index:       i,
									Text:        arg,
									TaintSource: tag,
								}},
								Location: Location(calleeInfo.file.Path, call.Line),
							},
							DataFlow: []DataFlowStep{
								{Kind: "source", VarName: callerTaint.VarName, Location: callerTaint.Location, Description: callerTaint.Category},
								{Kind: "transform", Description: fmt.Sprintf("参数传递 → %s.%s", calleeInfo.function.Name, paramName)},
							},
							Location:   Location(calleeInfo.file.Path, call.Line),
							Confidence: "中",
						}
						findings = append(findings, finding)
					}
				}
			}
		}
	}

	return findings
}

// checkCallerSinkFromReturn 检查 caller 是否将 callee 的返回值传给 sink。
func (a *InterprocTaintAnalyzer) checkCallerSinkFromReturn(call CallExpr, callerFn Function, callerFile File, sourceRule *TaintRule) []TaintFinding {
	var findings []TaintFinding

	// 查找接收返回值的赋值
	for _, assign := range callerFn.Assignments {
		if strings.Contains(assign.RHS, call.FuncName) {
			// 接收了返回值，检查是否传给 sink
			taintTag := &TaintTag{
				VarName:  assign.VarName,
				Source:   sourceRule.ID,
				Category: sourceRule.Category,
				Location: Location(callerFile.Path, assign.Line),
			}

			// 追踪传播
			taintTags := map[string]*TaintTag{assign.VarName: taintTag}
			taintTags = a.base.propagulateTaint(callerFn.Assignments, taintTags)

			// 检查 sink
			for _, sinkCall := range callerFn.Calls {
				for _, rule := range a.rules {
					if rule.Kind != TaintSink {
						continue
					}
					if !a.base.matchSink(sinkCall, rule) {
						continue
					}
					for i, arg := range sinkCall.Args {
						arg = strings.TrimSpace(arg)
						for varName, tag := range taintTags {
							if arg == varName || containsVarRef(arg, varName) {
								finding := TaintFinding{
									RuleID:   rule.ID,
									Severity: rule.Severity,
									Title:    rule.Description,
									Description: fmt.Sprintf("跨函数污点传播: %s() 返回值 → %s → %s",
										call.FuncName, assign.VarName, sinkCall.FuncName),
									Category: rule.Category,
									Source:   tag,
									Sink: &TaintSinkPoint{
										Call: sinkCall,
										Rule: &rule,
										TaintedArgs: []TaintedArg{{
											Index:       i,
											Text:        arg,
											TaintSource: tag,
										}},
										Location: Location(callerFile.Path, sinkCall.Line),
									},
									Location:   Location(callerFile.Path, sinkCall.Line),
									Confidence: "中",
								}
								findings = append(findings, finding)
							}
						}
					}
				}
			}
		}
	}

	return findings
}

// functionReturnsTaint 检查函数是否返回了污点变量。
func (a *InterprocTaintAnalyzer) functionReturnsTaint(fn Function, taintVar string) bool {
	// 简化实现：检查函数体中是否有 return 语句引用了污点变量
	// 这需要 AST 中的 return 节点，目前通过调用列表近似
	for _, call := range fn.Calls {
		if call.FuncName == "return" || strings.HasPrefix(call.FuncName, "return ") {
			for _, arg := range call.Args {
				if strings.Contains(arg, taintVar) {
					return true
				}
			}
		}
	}
	return false
}

// getFileTaints 获取文件中的所有污点标记。
func (a *InterprocTaintAnalyzer) getFileTaints(file File) map[string]*TaintTag {
	allAssignments := file.Assignments
	for _, fn := range file.Functions {
		allAssignments = append(allAssignments, fn.Assignments...)
	}
	return a.base.markSources(file, allAssignments)
}

// mergeFindings 合并去重发现。
func (a *InterprocTaintAnalyzer) mergeFindings(base, extra []TaintFinding) []TaintFinding {
	seen := make(map[string]bool)
	var result []TaintFinding

	for _, f := range base {
		key := f.RuleID + ":" + f.Location + ":" + f.Description
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}

	for _, f := range extra {
		key := f.RuleID + ":" + f.Location + ":" + f.Description
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}

	return result
}

// propagulateTaint 追踪污点传播（导出给 interproc 使用）。
func (a *TaintAnalyzer) propagulateTaint(assignments []Assignment, taintTags map[string]*TaintTag) map[string]*TaintTag {
	changed := true
	for changed {
		changed = false
		for _, assign := range assignments {
			if _, alreadyTainted := taintTags[assign.VarName]; alreadyTainted {
				continue
			}
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

// SourceRule 返回 source 规则（如果有）。
func (t *TaintTag) SourceRule() *TaintRule {
	// 返回一个临时规则用于标识
	return &TaintRule{
		ID:       t.Source,
		Kind:     TaintSource,
		Category: t.Category,
	}
}

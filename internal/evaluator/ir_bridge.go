package evaluator

import (
	"fmt"
	"path/filepath"
	"strings"

	"skill-scanner/internal/config"
	"skill-scanner/internal/ir"
	"skill-scanner/internal/logx"
)

// =============================================================================
// IR 桥接层
//
// 将 evaluator 的 Skill/SourceFile 转换为 ir.File，运行 IR 引擎，
// 再将 IR 结果转回 evaluator 的 FindingDetail。
//
// 集成策略：
//   - 新增 detection.type = "ir_pattern" 启用 IR 分析
//   - 旧规则（pattern/forbid_pattern 等）继续走原有逻辑
//   - IR 发现自动注入 FindingDetails，与原有发现合并
// =============================================================================

// skillToIRFiles 将 Skill 的源文件转换为 IR File 列表。
func skillToIRFiles(skill *Skill) []ir.File {
	var files []ir.File

	for _, sf := range skill.Files {
		lang := detectLanguage(sf.Path, sf.Language)
		parser, ok := ir.GetParser(lang)
		if !ok {
			// 不支持的语言，跳过
			logx.With("component", "ir_bridge", "file", sf.Path, "language", lang).Debug("parser not available")
			continue
		}

		content := sf.AnalysisContent()
		if strings.TrimSpace(content) == "" {
			continue
		}

		parsed, err := parser.Parse(sf.Path, content)
		if err != nil {
			logx.With("component", "ir_bridge", "file", sf.Path, "error", err.Error()).Debug("parse error")
			continue
		}

		files = append(files, *parsed)
	}

	return files
}

// detectLanguage 从文件路径和显式语言标识推断编程语言。
func detectLanguage(path, explicit string) string {
	if explicit != "" {
		return strings.ToLower(strings.TrimSpace(explicit))
	}

	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".py":
		return "python"
	case ".go":
		return "go"
	case ".js", ".jsx", ".mjs":
		return "javascript"
	case ".ts", ".tsx":
		return "typescript"
	default:
		return ""
	}
}

// executeIRPattern 执行 ir_pattern 类型规则。
// 将 Skill 文件解析为 IR，运行 IR 规则引擎，返回 FindingDetail。
func (e *Evaluator) executeIRPattern(skill *Skill, rule config.Rule) (float64, bool, string, []FindingDetail, error) {
	// 1. 转换 Skill → IR Files
	irFiles := skillToIRFiles(skill)
	if len(irFiles) == 0 {
		// 没有可解析的文件，视为通过
		return rule.Weight, false, "", nil, nil
	}

	// 2. 构建 IR 规则
	irRule := buildIRRule(rule)
	if irRule == nil {
		return rule.Weight, false, "", nil, fmt.Errorf("failed to build IR rule from config: %s", rule.ID)
	}

	// 3. 运行 IR 引擎
	engine := ir.NewIRRuleEngine(irFiles)
	result := engine.Evaluate(*irRule)

	// 4. 转换结果为 FindingDetail
	var details []FindingDetail
	for _, finding := range result.Findings {
		detail := FindingDetail{
			RuleID:      rule.ID,
			Severity:    rule.Severity,
			Title:       rule.Name,
			Description: finding.Description,
			Location:    finding.Location,
			CodeSnippet: finding.Evidence,
		}
		if finding.CallExpr != nil {
			detail.CodeSnippet = formatCallExpr(finding.CallExpr)
		}
		details = append(details, detail)
	}

	// 5. 判定结果
	if result.Blocked {
		if rule.OnFail.Action == "block" {
			return 0, true, rule.OnFail.Reason, details, nil
		}
		return 0, false, rule.OnFail.Reason, details, nil
	}

	if result.Matched && rule.Detection.PassIf == "no_match" {
		// 匹配到了禁用模式
		if rule.OnFail.Action == "block" {
			return 0, true, rule.OnFail.Reason, details, nil
		}
		return 0, false, rule.OnFail.Reason, details, nil
	}

	return rule.Weight, false, "", details, nil
}

// buildIRRule 从 config.Rule 构建 ir.IRRule。
func buildIRRule(rule config.Rule) *ir.IRRule {
	irRule := &ir.IRRule{
		ID:       rule.ID,
		Name:     rule.Name,
		Severity: rule.Severity,
		Layer:    rule.Layer,
		Detection: ir.IRDetection{
			IncludeGlobs: rule.Detection.IncludeGlobs,
			PassIf:       rule.Detection.PassIf,
			Reason:       rule.Detection.Reason,
		},
		OnFail: ir.IROnFail{
			Action: rule.OnFail.Action,
			Reason: rule.OnFail.Reason,
		},
	}

	// 解析 IR 检测配置（从 Detection 的扩展字段中提取）
	detType := parseIRDetectionType(rule.Detection)
	irRule.Detection.Type = detType

	switch detType {
	case "ir_call":
		irRule.Detection.Call = parseIRCallMatch(rule.Detection)
	case "ir_category":
		irRule.Detection.Category = parseIRCategoryMatch(rule.Detection)
	case "ir_taint_flow":
		irRule.Detection.TaintFlow = parseIRTaintFlowMatch(rule.Detection)
	case "ir_call_chain":
		irRule.Detection.CallChain = parseIRCallChainMatch(rule.Detection)
	case "ir_compound":
		irRule.Detection.Compound = parseIRCompoundMatch(rule.Detection)
	default:
		// 尝试自动推断：如果有 patterns，编译为 IR 规则
		if len(rule.Detection.Patterns) > 0 {
			compiled := ir.CompileYAMLRuleToIR(rule.ID, rule.Name, rule.Severity, rule.Layer, rule.Detection.Type, rule.Detection.Patterns, rule.Detection.IncludeGlobs)
			if compiled != nil {
				return compiled
			}
			// 编译失败，尝试直接用 ir_call 类型
			irRule.Detection.Type = "ir_call"
			irRule.Detection.Call = &ir.IRCallMatch{
				FuncName: extractFuncNameFromPatterns(rule.Detection.Patterns),
			}
			if irRule.Detection.Call.FuncName != "" {
				return irRule
			}
		}
		return nil
	}

	return irRule
}

// parseIRDetectionType 从 Detection 配置中解析 IR 检测类型。
func parseIRDetectionType(d config.Detection) string {
	// 优先使用显式类型
	if strings.HasPrefix(d.Type, "ir_") {
		return d.Type
	}

	// 从 Function 字段推断（约定：function 名以 ir_ 开头）
	if strings.HasPrefix(d.Function, "ir_") {
		return d.Function
	}

	// 从 Reason 推断
	reason := strings.ToLower(d.Reason)
	if strings.Contains(reason, "taint") || strings.Contains(reason, "数据流") || strings.Contains(reason, "污点") {
		return "ir_taint_flow"
	}
	if strings.Contains(reason, "call_chain") || strings.Contains(reason, "调用链") {
		return "ir_call_chain"
	}

	return ""
}

// parseIRCallMatch 从 Detection 配置解析调用匹配。
func parseIRCallMatch(d config.Detection) *ir.IRCallMatch {
	// 从 patterns 中提取函数名
	if len(d.Patterns) > 0 {
		for _, p := range d.Patterns {
			cleaned := strings.TrimPrefix(p, "^")
			cleaned = strings.TrimSuffix(cleaned, "$")
			cleaned = strings.TrimSuffix(cleaned, "(")
			cleaned = strings.TrimSuffix(cleaned, "\\(")
			cleaned = strings.ReplaceAll(cleaned, "\\", "")
			cleaned = strings.TrimSpace(cleaned)
			if cleaned != "" && !strings.Contains(cleaned, "(") && !strings.Contains(cleaned, "[") {
				return &ir.IRCallMatch{
					FuncName: cleaned,
				}
			}
		}
	}

	// 从 CodePatterns 中提取
	if len(d.CodePatterns) > 0 {
		for _, p := range d.CodePatterns {
			cleaned := strings.TrimPrefix(p, "^")
			cleaned = strings.TrimSuffix(cleaned, "$")
			cleaned = strings.TrimSuffix(cleaned, "(")
			cleaned = strings.ReplaceAll(cleaned, "\\", "")
			cleaned = strings.TrimSpace(cleaned)
			if cleaned != "" {
				return &ir.IRCallMatch{
					FuncName: cleaned,
				}
			}
		}
	}

	return nil
}

// parseIRCategoryMatch 从 Detection 配解析类别匹配。
func parseIRCategoryMatch(d config.Detection) *ir.IRCategoryMatch {
	// 从 patterns 推断类别
	var categories []string
	allPatterns := append(d.Patterns, d.CodePatterns...)
	for _, p := range allPatterns {
		lower := strings.ToLower(p)
		switch {
		case strings.Contains(lower, "os.system") || strings.Contains(lower, "subprocess") || strings.Contains(lower, "exec"):
			categories = appendUnique(categories, string(ir.CatCommandExec))
		case strings.Contains(lower, "requests") || strings.Contains(lower, "http") || strings.Contains(lower, "fetch"):
			categories = appendUnique(categories, string(ir.CatNetworkAccess))
		case strings.Contains(lower, "readfile") || strings.Contains(lower, "open"):
			categories = appendUnique(categories, string(ir.CatFileRead))
		case strings.Contains(lower, "writefile") || strings.Contains(lower, "write"):
			categories = appendUnique(categories, string(ir.CatFileWrite))
		case strings.Contains(lower, "getenv") || strings.Contains(lower, "environ"):
			categories = appendUnique(categories, string(ir.CatEnvAccess))
		}
	}

	if len(categories) == 0 {
		return nil
	}
	return &ir.IRCategoryMatch{
		Categories: categories,
		MinCount:   1,
	}
}

// parseIRTaintFlowMatch 从 Detection 配置解析污点流匹配。
func parseIRTaintFlowMatch(d config.Detection) *ir.IRTaintFlowMatch {
	match := &ir.IRTaintFlowMatch{}

	// 从 CodePatterns 推断 source
	for _, p := range d.CodePatterns {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "getenv") || strings.Contains(lower, "environ") {
			match.SourceCategory = string(ir.CatEnvAccess)
		}
		if strings.Contains(lower, "readfile") || strings.Contains(lower, "open") {
			match.SourceCategory = string(ir.CatFileRead)
		}
	}

	// 从 DocPatterns 推断 sink
	for _, p := range d.DocPatterns {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "http") || strings.Contains(lower, "request") || strings.Contains(lower, "网络") {
			match.SinkCategory = string(ir.CatNetworkAccess)
		}
		if strings.Contains(lower, "exec") || strings.Contains(lower, "command") || strings.Contains(lower, "执行") {
			match.SinkCategory = string(ir.CatCommandExec)
		}
	}

	if match.SourceCategory == "" && match.SinkCategory == "" {
		return nil
	}
	return match
}

// parseIRCallChainMatch 从 Detection 配置解析调用链匹配。
func parseIRCallChainMatch(d config.Detection) *ir.IRCallChainMatch {
	match := &ir.IRCallChainMatch{
		MaxDepth: 5,
	}

	for _, p := range d.CodePatterns {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "http") || strings.Contains(lower, "request") {
			match.FromCategory = string(ir.CatNetworkAccess)
		}
		if strings.Contains(lower, "readfile") || strings.Contains(lower, "open") {
			match.FromCategory = string(ir.CatFileRead)
		}
	}

	for _, p := range d.DocPatterns {
		lower := strings.ToLower(p)
		if strings.Contains(lower, "exec") || strings.Contains(lower, "command") {
			match.ToCategory = string(ir.CatCommandExec)
		}
		if strings.Contains(lower, "write") || strings.Contains(lower, "写入") {
			match.ToCategory = string(ir.CatFileWrite)
		}
	}

	if match.FromCategory == "" || match.ToCategory == "" {
		return nil
	}
	return match
}

// parseIRCompoundMatch 从 Detection 配置解析复合匹配。
func parseIRCompoundMatch(d config.Detection) *ir.IRCompoundMatch {
	// 复合匹配需要显式配置，不从旧规则推断
	return nil
}

// formatCallExpr 格式化调用表达式为可读文本。
func formatCallExpr(call *ir.CallExpr) string {
	if call == nil {
		return ""
	}
	args := strings.Join(call.Args, ", ")
	return fmt.Sprintf("%s(%s)", call.FuncName, args)
}

// appendUnique 追加不重复的字符串。
func appendUnique(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

// extractFuncNameFromPatterns 从正则模式中提取函数名。
func extractFuncNameFromPatterns(patterns []string) string {
	for _, p := range patterns {
		cleaned := strings.TrimPrefix(p, "^")
		cleaned = strings.TrimSuffix(cleaned, "$")
		cleaned = strings.TrimSuffix(cleaned, "(")
		cleaned = strings.TrimSuffix(cleaned, "\\(")
		cleaned = strings.ReplaceAll(cleaned, "\\", "")
		cleaned = strings.ReplaceAll(cleaned, ".*", "")
		cleaned = strings.TrimSpace(cleaned)
		if cleaned != "" && !strings.Contains(cleaned, "(") && !strings.Contains(cleaned, "[") && !strings.Contains(cleaned, "|") {
			return cleaned
		}
	}
	return ""
}

// RunIRAnalysis 独立运行 IR 分析（供外部调用）。
// 返回 IR 发现列表，可用于报告增强。
func RunIRAnalysis(skill *Skill) []ir.Finding {
	irFiles := skillToIRFiles(skill)
	if len(irFiles) == 0 {
		return nil
	}

	// 构建调用图
	builder := ir.NewCallGraphBuilder()
	graph := builder.Build(irFiles)

	// 执行过程间污点分析（包含基础分析）
	interprocAnalyzer := ir.NewInterprocTaintAnalyzer(ir.DefaultTaintRules(), graph, irFiles)
	taintFindings := interprocAnalyzer.Analyze()

	// 执行链验证
	chainVerifier := ir.NewChainVerifier(ir.DefaultChainPatterns(), graph, taintFindings, irFiles)
	chainResults := chainVerifier.Verify()

	// 转换为 ir.Finding
	var findings []ir.Finding

	// 污点发现 → Finding
	for _, tf := range taintFindings {
		findings = append(findings, ir.Finding{
			RuleID:      tf.RuleID,
			Severity:    tf.Severity,
			Title:       tf.Title,
			Description: tf.Description,
			Category:    tf.Category,
			Location:    tf.Location,
			DataFlow:    tf.DataFlow,
			Confidence:  tf.Confidence,
		})
	}

	// 链验证结果 → Finding
	for _, cr := range chainResults {
		if !cr.Verified {
			continue
		}
		findings = append(findings, ir.Finding{
			RuleID:      cr.PatternID,
			Severity:    cr.Severity,
			Title:       cr.Description,
			Description: fmt.Sprintf("能力链验证通过（%s）: %s", cr.Confidence, cr.Description),
			Category:    "chain_verification",
			Confidence:  cr.Confidence,
			DataFlow:    cr.DataFlowPath,
		})
	}

	return findings
}

// RunSimilaritySearch 运行代码相似性搜索（供报告增强）。
func RunSimilaritySearch(skill *Skill, embedder ir.CodeEmbedder) []ir.SimilarityMatch {
	irFiles := skillToIRFiles(skill)
	if len(irFiles) == 0 {
		return nil
	}

	engine := ir.NewSimilarityEngine(nil, embedder, 0.3)
	return engine.Search(irFiles)
}

// GetIRCallGraphStats 获取 IR 调用图统计（供报告使用）。
func GetIRCallGraphStats(skill *Skill) *ir.CallGraphStats {
	irFiles := skillToIRFiles(skill)
	if len(irFiles) == 0 {
		return nil
	}

	builder := ir.NewCallGraphBuilder()
	graph := builder.Build(irFiles)
	stats := graph.Stats()
	return &stats
}

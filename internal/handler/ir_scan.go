package handler

import (
	"fmt"
	"strings"

	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/ir"
	"skill-scanner/internal/logx"
	"skill-scanner/internal/plugins"
)

// =============================================================================
// IR 扫描集成
//
// 将 IR 分析结果注入主扫描流程的 findings 列表。
// 在 performBaseScan 完成后调用，不修改原有逻辑。
// =============================================================================

// IRScanResult IR 扫描结果。
type IRScanResult struct {
	// Findings IR 发现（转为 plugins.Finding 格式）
	Findings []plugins.Finding
	// TaintCount 污点发现数
	TaintCount int
	// ChainCount 链验证通过数
	ChainCount int
	// SimilarityCount 相似性匹配数
	SimilarityCount int
	// ExplorationCount Agent 探索任务数
	ExplorationCount int
	// Summary 摘要
	Summary string
}

// runIRAnalysis 运行 IR 分析并返回 plugins.Finding 列表。
func runIRAnalysis(skill *evaluator.Skill) IRScanResult {
	result := IRScanResult{}

	// 转换为 IR 文件
	irFiles := skillToIRFiles(skill)
	if len(irFiles) == 0 {
		result.Summary = "无可解析的源文件"
		return result
	}

	// 使用并行分析器
	analyzer := ir.NewParallelAnalyzer(4)
	analysis := analyzer.AnalyzeParallel(irFiles)

	// 过程间污点分析（补充跨函数传播）
	builder := ir.NewCallGraphBuilder()
	graph := builder.Build(irFiles)
	interprocAnalyzer := ir.NewInterprocTaintAnalyzer(ir.DefaultTaintRules(), graph, irFiles)
	interprocFindings := interprocAnalyzer.Analyze()
	// 合并：过程间发现替换基础污点发现（已包含）
	analysis.TaintFindings = interprocFindings

	result.TaintCount = len(analysis.TaintFindings)
	for _, cr := range analysis.ChainResults {
		if cr.Verified {
			result.ChainCount++
		}
	}
	result.SimilarityCount = len(analysis.SimilarityMatches)

	// Agent 探索
	explorer := ir.NewAgentExplorer(irFiles)
	explorationTasks := explorer.GenerateTasks(analysis.TaintFindings, analysis.ChainResults)
	result.ExplorationCount = len(explorationTasks)

	// 转换为 plugins.Finding
	result.Findings = append(result.Findings, taintFindingsToPlugins(analysis.TaintFindings)...)
	result.Findings = append(result.Findings, chainResultsToPlugins(analysis.ChainResults)...)
	result.Findings = append(result.Findings, similarityMatchesToPlugins(analysis.SimilarityMatches)...)

	result.Summary = buildIRScanSummary(result)

	logx.With(
		"component", "ir_scan",
		"taint", result.TaintCount,
		"chain", result.ChainCount,
		"similarity", result.SimilarityCount,
		"exploration", result.ExplorationCount,
		"findings", len(result.Findings),
	).Info("IR analysis completed")

	return result
}

// taintFindingsToPlugins 将污点发现转为 plugins.Finding。
func taintFindingsToPlugins(findings []ir.TaintFinding) []plugins.Finding {
	var result []plugins.Finding
	for _, tf := range findings {
		desc := tf.Description
		// 附加数据流信息
		if len(tf.DataFlow) > 0 {
			var flowParts []string
			for _, step := range tf.DataFlow {
				flowParts = append(flowParts, fmt.Sprintf("%s(%s)", step.VarName, step.Description))
			}
			desc += fmt.Sprintf(" [数据流: %s]", strings.Join(flowParts, " → "))
		}

		finding := plugins.Finding{
			RuleID:      tf.RuleID,
			Severity:    tf.Severity,
			Title:       tf.Title,
			Description: desc,
			Location:    tf.Location,
		}
		result = append(result, finding)
	}
	return result
}

// chainResultsToPlugins 将链验证结果转为 plugins.Finding。
func chainResultsToPlugins(results []ir.ChainVerificationResult) []plugins.Finding {
	var result []plugins.Finding
	for _, cr := range results {
		if !cr.Verified {
			continue
		}

		desc := fmt.Sprintf("能力链已通过数据流验证（置信度=%s）", cr.Confidence)
		// 附加证据
		for _, e := range cr.Evidence {
			desc += fmt.Sprintf(" [%s: %s]", e.Kind, e.Description)
		}

		finding := plugins.Finding{
			RuleID:      "ir-chain-" + cr.PatternID,
			Severity:    cr.Severity,
			Title:       fmt.Sprintf("能力链验证: %s", cr.Description),
			Description: desc,
		}
		result = append(result, finding)
	}
	return result
}

// similarityMatchesToPlugins 将相似性匹配转为 plugins.Finding。
func similarityMatchesToPlugins(matches []ir.SimilarityMatch) []plugins.Finding {
	var result []plugins.Finding
	for _, m := range matches {
		finding := plugins.Finding{
			RuleID:      "ir-sim-" + m.PatternID,
			Severity:    m.Severity,
			Title:       fmt.Sprintf("代码相似性: %s", m.PatternName),
			Description: fmt.Sprintf("代码与已知漏洞模式 %s 相似度 %.0f%%，修复建议: %s", m.PatternName, m.Similarity*100, m.Remediation),
			Location:    m.Location,
			CodeSnippet: m.MatchedCode,
		}
		result = append(result, finding)
	}
	return result
}

// skillToIRFiles 将 Skill 转为 IR 文件。
func skillToIRFiles(skill *evaluator.Skill) []ir.File {
	var files []ir.File
	for _, sf := range skill.Files {
		lang := detectLanguage(sf.Path, sf.Language)
		parser, ok := ir.GetParser(lang)
		if !ok {
			continue
		}
		content := sf.AnalysisContent()
		if strings.TrimSpace(content) == "" {
			continue
		}
		parsed, err := parser.Parse(sf.Path, content)
		if err != nil {
			continue
		}
		files = append(files, *parsed)
	}
	return files
}

// detectLanguage 检测编程语言。
func detectLanguage(path, explicit string) string {
	if explicit != "" {
		return strings.ToLower(strings.TrimSpace(explicit))
	}
	ext := strings.ToLower(path)
	if idx := strings.LastIndex(ext, "."); idx >= 0 {
		switch ext[idx:] {
		case ".py":
			return "python"
		case ".go":
			return "go"
		case ".js", ".jsx", ".mjs":
			return "javascript"
		case ".ts", ".tsx":
			return "typescript"
		}
	}
	return ""
}

// buildIRScanSummary 构建 IR 扫描摘要。
func buildIRScanSummary(result IRScanResult) string {
	var parts []string
	if result.TaintCount > 0 {
		parts = append(parts, fmt.Sprintf("污点分析 %d 条", result.TaintCount))
	}
	if result.ChainCount > 0 {
		parts = append(parts, fmt.Sprintf("能力链验证 %d 条", result.ChainCount))
	}
	if result.SimilarityCount > 0 {
		parts = append(parts, fmt.Sprintf("相似性匹配 %d 条", result.SimilarityCount))
	}
	if result.ExplorationCount > 0 {
		parts = append(parts, fmt.Sprintf("Agent 探索 %d 个任务", result.ExplorationCount))
	}
	if len(parts) == 0 {
		return "IR 分析未发现额外风险"
	}
	return "IR 分析: " + strings.Join(parts, "；")
}

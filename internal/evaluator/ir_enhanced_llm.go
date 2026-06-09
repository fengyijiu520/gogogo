package evaluator

import (
	"context"
	"fmt"
	"strings"

	"skill-scanner/internal/ir"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/logx"
)

// =============================================================================
// LLM 增强分析 (LLM-Enhanced IR Analysis)
//
// 将 IR 分析结果注入 LLM prompt，让 LLM 能够：
//   1. 验证污点分析发现（确认/驳回/补充证据）
//   2. 验证链验证结果（评估数据流可达性）
//   3. 分析调用图中的可疑路径
//   4. 生成修复建议
//
// 策略：IR 先跑确定性分析 → 将发现作为结构化上下文注入 LLM → LLM 做深度判断
// =============================================================================

// IRAnalysisContext IR 分析上下文（注入 LLM prompt）。
type IRAnalysisContext struct {
	// TaintFindings 污点分析发现
	TaintFindings []ir.TaintFinding `json:"taint_findings,omitempty"`
	// ChainResults 链验证结果
	ChainResults []ir.ChainVerificationResult `json:"chain_results,omitempty"`
	// CallGraphStats 调用图统计
	CallGraphStats *ir.CallGraphStats `json:"call_graph_stats,omitempty"`
	// SimilarityMatches 相似性匹配
	SimilarityMatches []ir.SimilarityMatch `json:"similarity_matches,omitempty"`
	// DangerousPaths 危险调用路径
	DangerousPaths []ir.CallChain `json:"dangerous_paths,omitempty"`
}

// IRLlmVerdict LLM 对 IR 发现的判定。
type IRLlmVerdict struct {
	// FindingID 发现标识
	FindingID string `json:"finding_id"`
	// Verdict 判定：confirmed / needs_review / dismissed
	Verdict string `json:"verdict"`
	// Reason 判定原因
	Reason string `json:"reason"`
	// AdditionalEvidence LLM 补充的证据
	AdditionalEvidence string `json:"additional_evidence,omitempty"`
	// Remediation 修复建议
	Remediation string `json:"remediation,omitempty"`
}

// EnhancedAnalysisResult 增强分析结果。
type EnhancedAnalysisContext struct {
	// IRContext IR 分析上下文
	IRContext IRAnalysisContext `json:"ir_context"`
	// Verdicts LLM 对 IR 发现的判定
	Verdicts []IRLlmVerdict `json:"verdicts,omitempty"`
	// EnhancedRisks LLM 基于 IR 上下文发现的额外风险
	EnhancedRisks []EnhancedRisk `json:"enhanced_risks,omitempty"`
	// Summary 综合摘要
	Summary string `json:"summary,omitempty"`
}

// EnhancedRisk 增强风险。
type EnhancedRisk struct {
	Title       string `json:"title"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Source      string `json:"source"` // "ir_taint" / "ir_chain" / "ir_similarity" / "llm_inference"
}

// RunEnhancedAnalysis 运行 IR + LLM 联合增强分析。
func RunEnhancedAnalysis(ctx context.Context, skill *Skill, llmClient llm.Client) *EnhancedAnalysisContext {
	result := &EnhancedAnalysisContext{}

	// 1. 运行 IR 分析
	irFiles := skillToIRFiles(skill)
	if len(irFiles) == 0 {
		return result
	}

	// 构建调用图
	builder := ir.NewCallGraphBuilder()
	graph := builder.Build(irFiles)

	// 污点分析
	taintAnalyzer := ir.NewTaintAnalyzer(ir.DefaultTaintRules())
	taintFindings := taintAnalyzer.Analyze(irFiles)

	// 链验证
	chainVerifier := ir.NewChainVerifier(ir.DefaultChainPatterns(), graph, taintFindings, irFiles)
	chainResults := chainVerifier.Verify()

	// 相似性搜索
	simEngine := ir.NewSimilarityEngine(nil, nil, 0.3)
	simMatches := simEngine.Search(irFiles)

	// 危险路径
	dangerousPaths := graph.FindDangerousPaths()

	// 组装 IR 上下文
	result.IRContext = IRAnalysisContext{
		TaintFindings:     taintFindings,
		ChainResults:      chainResults,
		CallGraphStats:    ptrStats(graph.Stats()),
		SimilarityMatches: simMatches,
		DangerousPaths:    dangerousPaths,
	}

	// 2. 如果有 LLM 客户端，请求 LLM 验证
	if llmClient == nil {
		result.Summary = buildIRSummary(result.IRContext)
		return result
	}

	verdicts, enhancedRisks, err := requestLLMVerification(ctx, llmClient, skill, result.IRContext)
	if err != nil {
		logx.With("component", "ir_enhanced_llm", "error", err.Error()).Warn("LLM verification failed")
		result.Summary = buildIRSummary(result.IRContext)
		return result
	}

	result.Verdicts = verdicts
	result.EnhancedRisks = enhancedRisks
	result.Summary = buildEnhancedSummary(result)

	return result
}

// requestLLMVerification 请求 LLM 验证 IR 发现。
func requestLLMVerification(ctx context.Context, llmClient llm.Client, skill *Skill, irCtx IRAnalysisContext) ([]IRLlmVerdict, []EnhancedRisk, error) {
	// 构建增强 prompt
	systemPrompt, userPrompt := buildEnhancedPrompts(skill, irCtx)

	// 调用 LLM
	response, err := llmClient.Complete(ctx, systemPrompt, userPrompt)
	if err != nil {
		return nil, nil, fmt.Errorf("LLM complete failed: %w", err)
	}

	// 解析响应
	verdicts, risks := parseEnhancedResponse(response)
	return verdicts, risks, nil
}

// buildEnhancedPrompts 构建增强分析 prompt。
func buildEnhancedPrompts(skill *Skill, irCtx IRAnalysisContext) (string, string) {
	systemPrompt := `你是一位顶级代码安全专家。你将收到 IR（中间表示）层的自动化分析结果，包括污点分析、能力链验证和代码相似性匹配。
你的任务是：
1. 验证每个 IR 发现：确认(confirmed)、需要复核(needs_review) 或 驳回(dismissed)
2. 对 confirmed 的发现提供具体修复建议
3. 如果你能从 IR 上下文中发现额外风险，补充到 enhanced_risks

判定标准：
- confirmed：IR 证据充分，数据流路径清晰，风险确认
- needs_review：IR 证据部分支持，需要更多上下文确认
- dismissed：IR 误报，数据流实际不可达或有安全防护

输出格式：JSON 对象，包含 verdicts 数组和 enhanced_risks 数组。`

	var sb strings.Builder
	sb.WriteString("技能名称：")
	sb.WriteString(skill.Name)
	sb.WriteString("\n技能描述：")
	sb.WriteString(skill.Description)
	sb.WriteString("\n\n")

	// 注入 IR 分析结果
	if len(irCtx.TaintFindings) > 0 {
		sb.WriteString("## 污点分析发现\n")
		for i, tf := range irCtx.TaintFindings {
			sb.WriteString(fmt.Sprintf("%d. [%s] %s\n", i+1, tf.Severity, tf.Description))
			sb.WriteString(fmt.Sprintf("   位置: %s\n", tf.Location))
			sb.WriteString(fmt.Sprintf("   来源: %s (%s)\n", tf.Source.VarName, tf.Source.Category))
			sb.WriteString(fmt.Sprintf("   汇聚: %s\n", tf.Sink.Call.FuncName))
			if len(tf.DataFlow) > 0 {
				sb.WriteString("   数据流: ")
				for j, step := range tf.DataFlow {
					if j > 0 {
						sb.WriteString(" → ")
					}
					sb.WriteString(fmt.Sprintf("%s(%s)", step.VarName, step.Description))
				}
				sb.WriteString("\n")
			}
		}
		sb.WriteString("\n")
	}

	if len(irCtx.ChainResults) > 0 {
		sb.WriteString("## 能力链验证结果\n")
		for i, cr := range irCtx.ChainResults {
			status := "❌ 未验证"
			if cr.Verified {
				status = "✅ 已验证"
			}
			sb.WriteString(fmt.Sprintf("%d. %s %s (置信度=%s)\n", i+1, status, cr.Description, cr.Confidence))
			for _, e := range cr.Evidence {
				sb.WriteString(fmt.Sprintf("   证据[%s]: %s\n", e.Kind, e.Description))
			}
			if cr.GapDescription != "" {
				sb.WriteString(fmt.Sprintf("   缺口: %s\n", cr.GapDescription))
			}
		}
		sb.WriteString("\n")
	}

	if len(irCtx.SimilarityMatches) > 0 {
		sb.WriteString("## 代码相似性匹配\n")
		for i, m := range irCtx.SimilarityMatches {
			sb.WriteString(fmt.Sprintf("%d. [%s] %s (相似度=%.0f%%) at %s\n", i+1, m.Severity, m.PatternName, m.Similarity*100, m.Location))
		}
		sb.WriteString("\n")
	}

	if len(irCtx.DangerousPaths) > 0 {
		sb.WriteString("## 危险调用路径\n")
		for i, dp := range irCtx.DangerousPaths {
			sb.WriteString(fmt.Sprintf("%d. %s (长度=%d)\n", i+1, strings.Join(dp.Nodes, " → "), dp.Length))
			for _, dc := range dp.DangerousCalls {
				sb.WriteString(fmt.Sprintf("   危险调用: %s at line %d\n", dc.FuncName, dc.Line))
			}
		}
		sb.WriteString("\n")
	}

	sb.WriteString("请对以上 IR 发现逐条判定，并补充你发现的额外风险。\n")

	return systemPrompt, sb.String()
}

// parseEnhancedResponse 解析 LLM 增强分析响应。
func parseEnhancedResponse(response string) ([]IRLlmVerdict, []EnhancedRisk) {
	// 提取 JSON
	jsonStr := llm.ExtractJSON(response)
	if jsonStr == "" {
		return nil, nil
	}

	// 简化解析：从文本中提取判定
	var verdicts []IRLlmVerdict
	var risks []EnhancedRisk

	// 尝试解析 verdicts
	lines := strings.Split(response, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "confirmed") || strings.Contains(line, "needs_review") || strings.Contains(line, "dismissed") {
			verdict := IRLlmVerdict{
				Verdict: "needs_review",
				Reason:  line,
			}
			if strings.Contains(line, "confirmed") {
				verdict.Verdict = "confirmed"
			} else if strings.Contains(line, "dismissed") {
				verdict.Verdict = "dismissed"
			}
			verdicts = append(verdicts, verdict)
		}
	}

	return verdicts, risks
}

// buildIRSummary 构建 IR 分析摘要。
func buildIRSummary(irCtx IRAnalysisContext) string {
	var parts []string

	if len(irCtx.TaintFindings) > 0 {
		parts = append(parts, fmt.Sprintf("污点分析发现 %d 条数据流", len(irCtx.TaintFindings)))
	}

	verifiedChains := 0
	for _, cr := range irCtx.ChainResults {
		if cr.Verified {
			verifiedChains++
		}
	}
	if verifiedChains > 0 {
		parts = append(parts, fmt.Sprintf("能力链验证通过 %d 条", verifiedChains))
	}

	if len(irCtx.SimilarityMatches) > 0 {
		parts = append(parts, fmt.Sprintf("代码相似性匹配 %d 条", len(irCtx.SimilarityMatches)))
	}

	if len(irCtx.DangerousPaths) > 0 {
		parts = append(parts, fmt.Sprintf("发现 %d 条危险调用路径", len(irCtx.DangerousPaths)))
	}

	if len(parts) == 0 {
		return "IR 分析未发现显著风险"
	}
	return "IR 分析: " + strings.Join(parts, "；")
}

// buildEnhancedSummary 构建增强分析摘要。
func buildEnhancedSummary(result *EnhancedAnalysisContext) string {
	irSummary := buildIRSummary(result.IRContext)

	confirmed := 0
	dismissed := 0
	for _, v := range result.Verdicts {
		switch v.Verdict {
		case "confirmed":
			confirmed++
		case "dismissed":
			dismissed++
		}
	}

	enhanced := ""
	if confirmed > 0 || dismissed > 0 || len(result.EnhancedRisks) > 0 {
		enhanced = fmt.Sprintf("；LLM 验证: %d 确认, %d 驳回, %d 补充风险", confirmed, dismissed, len(result.EnhancedRisks))
	}

	return irSummary + enhanced
}

// ptrStats 返回 stats 的指针。
func ptrStats(stats ir.CallGraphStats) *ir.CallGraphStats {
	return &stats
}

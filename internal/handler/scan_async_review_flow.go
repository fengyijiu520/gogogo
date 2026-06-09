package handler

import (
	"context"
	"fmt"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
	"skill-scanner/internal/storage"
)

func completeStructuredReviewFlow(store *storage.Store, taskID string, base baseScanOutput, refined review.Result) (review.Result, []plugins.Finding, error) {
	return completeStructuredReviewFlowWithContext(context.Background(), store, taskID, base, refined)
}

func completeStructuredReviewFlowWithContext(ctx context.Context, store *storage.Store, taskID string, base baseScanOutput, refined review.Result) (review.Result, []plugins.Finding, error) {
	findings := buildSupplementedFindings(base, refined)
	updateScanTaskMessage(taskID, fmt.Sprintf("执行结构化整理与 LLM 复核：生成 %d 条补充风险并构建结构化结果", len(findings)), "structured-findings")
	if err := ctx.Err(); err != nil {
		return refined, findings, err
	}

	refined = enrichRefinedResult(base, refined, findings)
	updateScanTaskMessage(taskID, fmt.Sprintf("执行结构化整理与 LLM 复核：已生成 %d 条结构化风险，待复核 %d 项", len(refined.StructuredFindings), len(refined.ReviewAgentTasks)), "review-task-build")
	if err := ctx.Err(); err != nil {
		return refined, findings, err
	}

	llmReviewErr := error(nil)
	refined, llmReviewErr = runReviewAgentsWithContext(ctx, taskID, base, refined)
	if llmReviewErr != nil {
		base.trace = append(base.trace, newAnalysisTraceEvent("llm_review", "warning", "LLM 二次复核未完整完成，已回退为规则复核结果继续生成报告", llmReviewErr.Error()))
		updateScanTaskMessageWithReviewTrace(taskID, "执行结构化整理与 LLM 复核：LLM 复核部分失败，已按规则复核结果继续汇总报告", refined.ReviewTrace)
	}

	updateScanTaskMessage(taskID, "执行结构化整理与 LLM 复核：复核完成，正在汇总风险结论", "review-complete")
	if err := ctx.Err(); err != nil {
		return refined, findings, err
	}
	applyAutomaticFalsePositiveFeedback(store, refined)
	refined = finalizeRefinedResult(base, refined, findings)
	return refined, findings, llmReviewErr
}

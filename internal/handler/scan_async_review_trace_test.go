package handler

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"skill-scanner/internal/llm"
	"skill-scanner/internal/review"
	"skill-scanner/web/templates"
)

func TestReviewLocalizationHelpers(t *testing.T) {
	if got := localizeReviewVerdict("confirmed"); got != "已确认风险" {
		t.Fatalf("expected localized confirmed verdict, got %q", got)
	}
	if got := localizeReviewVerdict("likely_false_positive"); got != "疑似误报" {
		t.Fatalf("expected localized false positive verdict, got %q", got)
	}
	if got := localizeReviewVerdict("needs_manual_review"); got != "需人工复核" {
		t.Fatalf("expected localized manual review verdict, got %q", got)
	}
	if got := localizeReviewVerdict("policy"); got != "策略风险" {
		t.Fatalf("expected localized policy verdict, got %q", got)
	}
	if got := localizeReviewProgressStatus("running"); got != "复核中" {
		t.Fatalf("expected localized running status, got %q", got)
	}
	if got := localizeReviewProgressStatus("pending"); got != "待执行" {
		t.Fatalf("expected localized pending status, got %q", got)
	}
	if got := localizeReviewToolStatus("rejected"); got != "已拒绝" {
		t.Fatalf("expected localized rejected tool status, got %q", got)
	}
	if got := localizeReviewToolStatus("completed"); got != "已完成" {
		t.Fatalf("expected localized completed tool status, got %q", got)
	}
}

func TestScanTemplateIncludesReviewTraceProgressAndFailureBadges(t *testing.T) {
	for _, want := range []string{
		"运行时检查",
		"当前账号 LLM",
		"可提交扫描",
		"存在阻塞项",
		"err.data = data || {}",
		"taskErrorSuggestion",
		"处理建议：",
		"openAgentAnalysisBtn",
		"智能体分析详情",
		"agentAnalysisSelect",
		"暂无 LLM 对话",
		"renderAgentAnalysisOptions(entries, activeEntry);",
		"buildAgentAnalysisOptionLabel(entry, i + 1)",
		"renderLLMIOPanel(activeEntry, trace);",
		"case 'balance_exhausted':",
		"return '余额不足';",
		"case 'request_canceled':",
		"return '请求取消';",
		"case 'execution_error':",
		"return '执行失败';",
		"customRuleModal",
		"smartRuleEnabled",
		"generateSmartRuleBtn",
		"/api/rules/augment",
		"renderCustomRuleTrace(",
	} {
		if !strings.Contains(templates.ScanHTML, want) {
			t.Fatalf("expected scan template contains %q", want)
		}
	}
	if !strings.Contains(templates.CommonPartialsHTML, "runtime-action") {
		t.Fatalf("expected common partials contain %q", "runtime-action")
	}
	if !strings.Contains(templates.CommonPartialsHTML, "enableRuntimeStatusAutoRefresh") {
		t.Fatalf("expected common partials contain %q", "enableRuntimeStatusAutoRefresh")
	}
	if !strings.Contains(templates.CommonPartialsHTML, "hasDirtyRuntimePageState") {
		t.Fatalf("expected common partials contain %q", "hasDirtyRuntimePageState")
	}
	if !strings.Contains(templates.CommonPartialsHTML, "replaceRuntimePanels(data)") {
		t.Fatalf("expected common partials contain %q", "replaceRuntimePanels(data)")
	}
	if !strings.Contains(templates.CommonPartialsHTML, "renderRuntimePanelHTML") {
		t.Fatalf("expected common partials contain %q", "renderRuntimePanelHTML")
	}
}

func TestExecuteLLMReviewAgentWithStatsReportsProgress(t *testing.T) {
	refined := review.Result{ReviewAgentTasks: []review.ReviewAgentTask{
		{FindingID: "SF-001", Objective: "复核命令执行", Prompt: "prompt-1", StrictStandards: []string{"零误报"}},
		{FindingID: "SF-002", Objective: "复核示例外联", Prompt: "prompt-2", StrictStandards: []string{"排除示例"}},
	}}
	client := &fakeLLMReviewClient{results: map[string]*llm.AnalysisResult{
		"漏洞二次复核 SF-001": {IntentRiskLevel: "low", IntentConsistency: 95, ConsistencyEvidence: []string{"证据不足"}},
		"漏洞二次复核 SF-002": {IntentRiskLevel: "low", IntentConsistency: 95, ConsistencyEvidence: []string{"证据不足"}},
	}}
	progressEvents := make([]string, 0, 2)
	_, _, err := executeLLMReviewAgentWithStats(context.Background(), client, refined, func(event reviewProgressEvent) {
		progressEvents = append(progressEvents, fmt.Sprintf("%s:%d/%d:%s", event.Stage, event.Done, event.Total, event.Task.FindingID))
	})
	if err != nil {
		t.Fatalf("execute llm reviewer with progress: %v", err)
	}
	if len(progressEvents) != 4 {
		t.Fatalf("expected two progress events, got %+v", progressEvents)
	}
	if !containsString(progressEvents, "started:0/2:SF-001") && !containsString(progressEvents, "started:0/2:SF-002") {
		t.Fatalf("expected started progress event recorded, got %+v", progressEvents)
	}
	if !containsString(progressEvents, "completed:2/2:SF-001") && !containsString(progressEvents, "completed:2/2:SF-002") {
		t.Fatalf("expected completion progress event recorded, got %+v", progressEvents)
	}
}

func TestExecuteLLMReviewAgentWithStatsFallsBackPerItemWithoutCancelingBatch(t *testing.T) {
	refined := review.Result{ReviewAgentTasks: []review.ReviewAgentTask{
		{FindingID: "SF-001", Objective: "复核命令执行", Prompt: "prompt-1", StrictStandards: []string{"零误报"}},
		{FindingID: "SF-002", Objective: "复核示例外联", Prompt: "prompt-2", StrictStandards: []string{"排除示例"}},
		{FindingID: "SF-003", Objective: "复核凭据访问", Prompt: "prompt-3", StrictStandards: []string{"入口可达性"}},
	}}
	client := &fakeLLMReviewClient{
		results: map[string]*llm.AnalysisResult{
			"漏洞二次复核 SF-001": {IntentRiskLevel: "high", IntentMismatch: "存在真实命令执行", Risks: []llm.RiskItem{{Severity: "high", Description: "命令拼接进入 shell", KeyCodeLocation: "scripts/run.py:10", EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, Remediation: "fix", VerificationStep: "verify", RemediationQuality: "high"}}},
			"漏洞二次复核 SF-003": {IntentRiskLevel: "low", IntentConsistency: 95, ConsistencyEvidence: []string{"示例不会进入发布包"}},
		},
		errors: map[string]error{
			"漏洞二次复核 SF-002": fmt.Errorf("DeepSeek API 错误: Insufficient Balance"),
		},
	}
	verdicts, stats, err := executeLLMReviewAgentWithStats(context.Background(), client, refined, nil)
	if err != nil {
		t.Fatalf("expected batch fallback without fatal error, got %v", err)
	}
	if len(verdicts) != 3 {
		t.Fatalf("expected three verdicts, got %+v", verdicts)
	}
	if verdicts[1].Verdict != "needs_manual_review" || !strings.Contains(verdicts[1].Reason, "账户余额不足") {
		t.Fatalf("expected failing item fallback to manual review, got %+v", verdicts[1])
	}
	if verdicts[2].FindingID != "SF-003" || verdicts[2].Verdict == "" {
		t.Fatalf("expected later task still completes, got %+v", verdicts[2])
	}
	if !stats.Failed {
		t.Fatalf("expected stats capture partial failure, got %+v", stats)
	}
	for _, want := range []string{"3/3 项复核已结束", "成功 2 项", "余额不足 1 项"} {
		if !strings.Contains(stats.ErrorMessage, want) {
			t.Fatalf("expected aggregated stats error summary contains %q, got %q", want, stats.ErrorMessage)
		}
	}
}

func TestReviewTraceLifecycleCapturesVerdictAndToolTrace(t *testing.T) {
	tasks := []review.ReviewAgentTask{{
		FindingID: "SF-001",
		Objective: "复核命令执行",
		StageContext: &review.LLMStageContext{Finding: review.NormalizedFinding{
			Title:            "命令执行",
			Category:         "远程命令执行",
			Severity:         "高风险",
			PrimaryLocation:  "scripts/run.py:10",
			CodeEvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"},
		}},
	}}
	trace := buildInitialReviewTrace(tasks)
	if trace.Total != 1 || len(trace.Entries) != 1 || trace.Entries[0].Status != "pending" {
		t.Fatalf("expected initial pending trace, got %+v", trace)
	}
	applyReviewProgressEvent(trace, reviewProgressEvent{Stage: reviewProgressStarted, Done: 0, Total: 1, Task: tasks[0]})
	if trace.CurrentFindingTitle != "命令执行" || trace.Entries[0].Status != "running" {
		t.Fatalf("expected running review trace state, got %+v", trace)
	}
	applyReviewProgressEvent(trace, reviewProgressEvent{
		Stage: reviewProgressCompleted,
		Done:  1,
		Total: 1,
		Task:  tasks[0],
		Verdict: review.ReviewAgentVerdict{
			FindingID:       "SF-001",
			Verdict:         "confirmed",
			Reviewer:        "llm-vuln-reviewer",
			Reason:          "证据充分",
			Confidence:      "高",
			MissingEvidence: []string{"缺少运行时二次验证"},
			Fix:             "补充回归测试并复扫。",
			ToolTrace: []review.ToolTraceEntry{{
				Iteration: 1,
				ToolName:  "locateRiskyCode",
				Status:    "completed",
				Summary:   "定位到关键命令执行点",
			}},
		},
		DurationMs: 1350,
	})
	if trace.Completed != 1 || trace.LastVerdict != "confirmed" || trace.LastDurationMs != 1350 {
		t.Fatalf("expected completed review trace summary, got %+v", trace)
	}
	entry := trace.Entries[0]
	if entry.Status != "completed" || entry.Verdict != "confirmed" {
		t.Fatalf("expected completed entry, got %+v", entry)
	}
	if entry.Confidence != "高" || entry.Reviewer != "llm-vuln-reviewer" || entry.Fix != "补充回归测试并复扫。" || len(entry.MissingEvidence) != 1 {
		t.Fatalf("expected verdict metadata captured, got %+v", entry)
	}
	if len(entry.ToolTrace) != 1 || entry.ToolTrace[0].ToolName != "locateRiskyCode" {
		t.Fatalf("expected tool trace recorded, got %+v", entry.ToolTrace)
	}
}

func TestReviewTraceContextSummarySanitizesAbsolutePaths(t *testing.T) {
	task := review.ReviewAgentTask{StageContext: &review.LLMStageContext{Finding: review.NormalizedFinding{
		Category:         "声明与行为差异",
		Severity:         "中风险",
		PrimaryLocation:  "/home/admini/gogogo/data/tasks/feedb95d31ff1a2d9462a0f18f859596/polymarket.py polymarket.py:50",
		CodeEvidenceRefs: []string{"polymarket.py:50"},
	}}}
	summary := reviewTraceContextSummary(task)
	if strings.Contains(summary, "/home/admini/gogogo/data/tasks/") {
		t.Fatalf("expected absolute path sanitized, got %q", summary)
	}
	if !strings.Contains(summary, "位置:polymarket.py") {
		t.Fatalf("expected basename retained, got %q", summary)
	}
}

func TestBuildJSONReportPayloadIncludesReviewTrace(t *testing.T) {
	refined := review.Result{ReviewTrace: &review.ReviewTrace{
		Total:               1,
		Completed:           1,
		CurrentFindingID:    "SF-001",
		CurrentFindingTitle: "命令执行",
		LastVerdict:         "confirmed",
		Entries: []review.ReviewTraceEntry{{
			FindingID: "SF-001",
			Status:    "completed",
			Verdict:   "confirmed",
			Reason:    "证据充分",
			ToolTrace: []review.ToolTraceEntry{{Iteration: 1, ToolName: "locateRiskyCode", Status: "completed", Summary: "工具调用完成"}},
			UpdatedAt: 1,
		}},
	}, ReviewAgentStats: []review.ReviewAgentExecutionStats{{Reviewer: "llm-vuln-reviewer", TaskCount: 1, WorkerCount: 1, MaxConcurrency: 1, DurationMs: 1200}}}
	payload := buildJSONReportPayload("<html></html>", "text", nil, baseScanOutput{}, refined)
	trace, ok := payload["review_trace"].(*review.ReviewTrace)
	if !ok || trace == nil {
		t.Fatalf("expected review_trace in payload, got %+v", payload["review_trace"])
	}
	if trace.CurrentFindingTitle != "命令执行" || len(trace.Entries) != 1 {
		t.Fatalf("expected review_trace content preserved, got %+v", trace)
	}
	stats, ok := payload["review_agent_stats"].([]review.ReviewAgentExecutionStats)
	if !ok || len(stats) != 1 || stats[0].Reviewer != "llm-vuln-reviewer" {
		t.Fatalf("expected top-level review_agent_stats in payload, got %+v", payload["review_agent_stats"])
	}
}

func TestRenderVerificationSummaryCardMovesNotApplicableFindingToObserveOnly(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:                   "SF-OBS-001",
			Title:                "命令执行",
			Category:             "命令执行",
			Closure:              review.FindingClosure{Source: false, Transform: false, Sink: true, RuntimeSupport: false},
			ApplicabilityVerdict: "not_applicable",
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:  "SF-OBS-001",
			Verdict:    "needs_manual_review",
			Reviewer:   "deterministic-vuln-reviewer",
			Confidence: "低",
		}},
	}
	html := renderVerificationSummaryCard(refined)
	if !strings.Contains(html, "观察项") || !strings.Contains(html, "当前规则前提未满足，已转为观察项") || !strings.Contains(html, "缺少 source / transform / runtime") {
		t.Fatalf("expected observe-only summary for not-applicable finding, got %s", html)
	}
	if strings.Contains(html, "仍需人工验证</strong></li><li>SF-OBS-001") {
		t.Fatalf("expected not-applicable finding excluded from need-verify list, got %s", html)
	}
}

func TestRenderReviewWorkflowIntegratedCardShowsFallbackReason(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{ID: "SF-TRACE", Title: "命令执行"}},
		ReviewAgentTasks:   []review.ReviewAgentTask{{FindingID: "SF-TRACE", AgentRole: "vuln-reviewer", Objective: "复核命令执行"}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:  "SF-TRACE",
			Verdict:    "needs_manual_review",
			Confidence: "低",
			Reason:     "规则复核兜底",
			Reviewer:   "deterministic-vuln-reviewer",
		}},
		ReviewTrace: &review.ReviewTrace{Entries: []review.ReviewTraceEntry{{
			FindingID:    "SF-TRACE",
			Status:       "failed",
			FailureKind:  "timeout",
			FailureLabel: "LLM 复核超时",
			Reason:       "context deadline exceeded",
			DurationMs:   90000,
		}}},
	}
	html := renderReviewWorkflowIntegratedCard(refined)
	for _, want := range []string{"复核回退与异常", "LLM 单项复核状态: 失败", "失败分类: LLM 复核超时", "回退原因: LLM 复核超时，已按规则复核结果继续生成报告", "最近一次耗时: 90000ms"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected fallback signal %q, got %s", want, html)
		}
	}
}

func TestClassifyReviewFailure(t *testing.T) {
	cases := []struct {
		reason string
		kind   string
		label  string
	}{
		{reason: "context deadline exceeded", kind: "timeout", label: "LLM 复核超时"},
		{reason: "DeepSeek API 错误: Insufficient Balance", kind: "balance_exhausted", label: "LLM 账户余额不足"},
		{reason: "调用 DeepSeek API 失败: context canceled", kind: "request_canceled", label: "LLM 请求被取消"},
		{reason: "LLM analysis loop reached iteration limit", kind: "iteration_limit", label: "工具迭代达到上限"},
		{reason: "tool rejected by policy", kind: "tool_rejected", label: "工具调用被拒绝"},
		{reason: "LLM reviewer 未返回有效 JSON 裁决", kind: "invalid_response", label: "模型返回无效结果"},
		{reason: "dial tcp timeout", kind: "execution_error", label: "LLM 执行失败"},
	}
	for _, tc := range cases {
		kind, label := classifyReviewFailure(tc.reason)
		if kind != tc.kind || label != tc.label {
			t.Fatalf("reason %q expected %s/%s, got %s/%s", tc.reason, tc.kind, tc.label, kind, label)
		}
	}
}

func TestBuildHTMLReportIncludesReviewTraceSection(t *testing.T) {
	refined := review.Result{ReviewTrace: &review.ReviewTrace{
		Total:               2,
		Completed:           1,
		CurrentFindingTitle: "命令执行",
		LastVerdict:         "confirmed",
		Entries: []review.ReviewTraceEntry{{
			FindingID:    "SF-001",
			FindingTitle: "命令执行",
			Status:       "completed",
			Verdict:      "confirmed",
			DurationMs:   1200,
			UpdatedAt:    2,
		}, {
			FindingID:    "SF-002",
			FindingTitle: "示例外联",
			Status:       "failed",
			FailureKind:  "timeout",
			FailureLabel: "LLM 复核超时",
			DurationMs:   2400,
			UpdatedAt:    1,
		}},
	}}
	html := buildHTMLReport("demo.zip", "", nil, baseScanOutput{}, refined, nil)
	for _, want := range []string{"#review-trace", "LLM 复核轨迹回放", "<p>2/2</p>", "轨迹摘要", "最近裁决: 已确认风险", "成功: 1", "失败: 1", "平均耗时: 1800ms", "示例外联 [超时]"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected review trace section contains %q, got %s", want, html)
		}
	}
}

func TestSummarizeReviewTrace(t *testing.T) {
	stats := summarizeReviewTrace(&review.ReviewTrace{Entries: []review.ReviewTraceEntry{
		{FindingID: "SF-001", Status: "completed", DurationMs: 1000},
		{FindingID: "SF-006", Status: "failed", FailureKind: "balance_exhausted", DurationMs: 500},
		{FindingID: "SF-007", Status: "failed", FailureKind: "request_canceled", DurationMs: 700},
		{FindingID: "SF-002", Status: "failed", FailureKind: "timeout", DurationMs: 3000},
		{FindingID: "SF-003", Status: "failed", FailureKind: "invalid_response", DurationMs: 2000},
		{FindingID: "SF-004", Status: "failed", FailureKind: "tool_rejected"},
		{FindingID: "SF-005", Status: "failed", FailureKind: "iteration_limit", DurationMs: 4000},
		{FindingID: "SF-008", Status: "failed", FailureKind: "execution_error", DurationMs: 900},
	}})
	if stats.successCount != 1 || stats.failedCount != 7 {
		t.Fatalf("unexpected success/failed stats: %+v", stats)
	}
	if stats.balanceExhaustedCount != 1 || stats.requestCanceledCount != 1 || stats.timeoutCount != 1 || stats.invalidResponseCount != 1 || stats.toolRejectedCount != 1 || stats.iterationLimitCount != 1 || stats.executionErrorCount != 1 {
		t.Fatalf("unexpected failure breakdown: %+v", stats)
	}
	if stats.avgDurationMs != 1728 {
		t.Fatalf("expected avg duration 1728ms, got %+v", stats)
	}
}

func TestRenderReviewTraceSummaryShowsExpandedFailureBreakdown(t *testing.T) {
	html := renderReviewTraceSummary(&review.ReviewTrace{
		Total:        3,
		Completed:    3,
		Failed:       true,
		ErrorMessage: "3/3 项复核已结束；成功 1 项；余额不足 1 项；请求取消 1 项",
		Entries: []review.ReviewTraceEntry{
			{FindingID: "SF-001", Status: "failed", FailureKind: "balance_exhausted", DurationMs: 400},
			{FindingID: "SF-002", Status: "failed", FailureKind: "request_canceled", DurationMs: 600},
			{FindingID: "SF-003", Status: "completed", Verdict: "confirmed", DurationMs: 1000},
		},
	})
	for _, want := range []string{"余额不足: 1", "请求取消: 1", "平均耗时: 666ms", "全局错误: 3/3 项复核已结束；成功 1 项；余额不足 1 项；请求取消 1 项"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected expanded failure breakdown %q, got %s", want, html)
		}
	}
}

func TestReviewTraceErrorSummaryAggregatesFailureBreakdown(t *testing.T) {
	trace := &review.ReviewTrace{
		Total:     5,
		Completed: 5,
		Entries: []review.ReviewTraceEntry{
			{FindingID: "SF-001", Status: "completed"},
			{FindingID: "SF-002", Status: "failed", FailureKind: "balance_exhausted"},
			{FindingID: "SF-003", Status: "failed", FailureKind: "request_canceled"},
			{FindingID: "SF-004", Status: "failed", FailureKind: "timeout"},
			{FindingID: "SF-005", Status: "failed", FailureKind: "execution_error"},
		},
	}
	got := reviewTraceErrorSummary(trace)
	for _, want := range []string{"5/5 项复核已结束", "成功 1 项", "余额不足 1 项", "请求取消 1 项", "超时 1 项", "执行失败 1 项"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected aggregated summary %q, got %q", want, got)
		}
	}
}

func TestReviewTraceStatsErrorSummaryAggregatesExecutionStats(t *testing.T) {
	got := reviewTraceStatsErrorSummary(4, 4, reviewTraceSummaryStats{
		successCount:          1,
		balanceExhaustedCount: 1,
		requestCanceledCount:  1,
		executionErrorCount:   1,
	})
	for _, want := range []string{"4/4 项复核已结束", "成功 1 项", "余额不足 1 项", "请求取消 1 项", "执行失败 1 项"} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected stats summary contains %q, got %q", want, got)
		}
	}
}

func TestReviewTraceFinishedCountPrefersDerivedCompletedEntries(t *testing.T) {
	trace := &review.ReviewTrace{
		Total:     2,
		Completed: 1,
		Entries: []review.ReviewTraceEntry{
			{FindingID: "SF-001", Status: "completed"},
			{FindingID: "SF-002", Status: "failed", FailureKind: "timeout"},
		},
	}
	if got := reviewTraceFinishedCount(trace); got != 2 {
		t.Fatalf("expected derived finished count 2, got %d", got)
	}
	if got := reviewTraceErrorSummary(trace); !strings.Contains(got, "2/2 项复核已结束") {
		t.Fatalf("expected error summary uses unified finished count, got %q", got)
	}
	html := renderReviewTraceIntegratedCard(review.Result{ReviewTrace: trace})
	if !strings.Contains(html, "<p>2/2</p>") {
		t.Fatalf("expected integrated review trace progress 2/2, got %s", html)
	}
}

func TestRenderReviewTraceIntegratedCardShowsFinalVerdictContext(t *testing.T) {
	trace := &review.ReviewTrace{Entries: []review.ReviewTraceEntry{{
		FindingID:    "SF-001",
		FindingTitle: "敏感数据外发与隐蔽通道",
		Status:       "completed",
		Verdict:      "likely_false_positive",
		Reason:       "原始轨迹判断为示例性质",
		UpdatedAt:    10,
	}}}
	html := renderReviewTraceIntegratedCard(review.Result{
		ReviewTrace: trace,
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:  "SF-001",
			Verdict:    "confirmed",
			Confidence: "高",
			Reason:     "规则复核确认存在真实执行链",
			Reviewer:   "deterministic-vuln-reviewer",
		}},
	})
	for _, want := range []string{"轨迹裁决: 疑似误报", "最终采用裁决: 已确认风险", "采用状态: 已被后续合并结果覆盖"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected integrated card contains %q, got %s", want, html)
		}
	}
}

func TestRenderReviewTraceIntegratedCardMarksSelectedTraceVerdict(t *testing.T) {
	trace := &review.ReviewTrace{Entries: []review.ReviewTraceEntry{{
		FindingID:    "SF-001",
		FindingTitle: "命令执行",
		Status:       "completed",
		Verdict:      "confirmed",
		Reason:       "轨迹与最终裁决一致",
		UpdatedAt:    20,
	}}}
	html := renderReviewTraceIntegratedCard(review.Result{
		ReviewTrace: trace,
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:  "SF-001",
			Verdict:    "confirmed",
			Confidence: "高",
			Reason:     "证据闭环",
			Reviewer:   "deterministic-vuln-reviewer",
		}},
	})
	for _, want := range []string{"轨迹裁决: 已确认风险", "最终采用裁决: 已确认风险", "采用状态: 该轨迹裁决已成为最终采用结果"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected selected trace verdict context %q, got %s", want, html)
		}
	}
}

func TestRenderReviewTraceIntegratedCardShowsExpandedTraceMetadata(t *testing.T) {
	trace := &review.ReviewTrace{Entries: []review.ReviewTraceEntry{{
		FindingID:       "SF-TRACE",
		FindingTitle:    "命令执行",
		Status:          "completed",
		Verdict:         "confirmed",
		Confidence:      "高",
		Reviewer:        "llm-vuln-reviewer",
		Reason:          "代码和行为证据闭环成立",
		MissingEvidence: []string{"缺少生产流量样本"},
		Fix:             "补充真实调用链回归验证。",
		ToolTrace:       []review.ToolTraceEntry{{Iteration: 1, ToolName: "locateRiskyCode", Status: "completed", Summary: "定位到 os.system(cmd)"}},
		UpdatedAt:       5,
	}}}
	html := renderReviewTraceIntegratedCard(review.Result{ReviewTrace: trace})
	for _, want := range []string{"轨迹置信度: 高", "轨迹 Reviewer: llm-vuln-reviewer", "缺失证据", "缺少生产流量样本", "修复建议: 补充真实调用链回归验证。", "定位到 os.system(cmd)"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected expanded trace metadata %q, got %s", want, html)
		}
	}
}

func TestRenderStructuredFindingCardEmbedsReviewSummary(t *testing.T) {
	refined := review.Result{
		StructuredFindings: []review.StructuredFinding{{
			ID:                 "SF-001",
			RuleID:             "V7-003",
			Title:              "敏感数据外发与隐蔽通道",
			Severity:           "高风险",
			Category:           "外联与情报",
			SecurityVerdict:    "confirmed",
			DeclarationVerdict: "undeclared",
			Confidence:         "高",
			AttackPath:         "webhook 请求携带运行数据外发",
			Evidence:           []string{"polymarket.py:59 requests.post(webhook, json={\"content\": msg})"},
			ReviewGuidance:     "限制目标白名单并收敛出站字段。",
			Source:             "BehaviorGuard+SecurityEngine",
			DeduplicatedCount:  2,
		}},
		ReviewAgentVerdicts: []review.ReviewAgentVerdict{{
			FindingID:  "SF-001",
			Verdict:    "needs_manual_review",
			Confidence: "低",
			Reason:     "规则复核兜底",
			Reviewer:   "deterministic-vuln-reviewer",
		}},
		ReviewTrace: &review.ReviewTrace{Entries: []review.ReviewTraceEntry{{
			FindingID:    "SF-001",
			FindingTitle: "敏感数据外发与隐蔽通道",
			Status:       "failed",
			FailureKind:  "invalid_response",
			FailureLabel: "模型返回无效结果",
			Reason:       "LLM reviewer 未返回有效 JSON 裁决",
			DurationMs:   1800,
			ToolTrace:    []review.ToolTraceEntry{{Iteration: 1, ToolName: "locateRiskyCode", Status: "completed", Summary: "定位到 webhook 外发点"}},
			UpdatedAt:    3,
		}}},
	}
	html := renderStructuredFindingsSection(refined)
	for _, want := range []string{"复核摘要", "轨迹状态: 失败", "失败分类: 模型返回无效结果", "失败标签: 无效响应", "回退原因: LLM 返回结果不符合预期格式，已按规则复核结果继续生成报告", "展开复核轨迹", "locateRiskyCode", "已完成"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected embedded review summary contains %q, got %s", want, html)
		}
	}
}

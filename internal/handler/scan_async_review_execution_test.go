package handler

import (
	"context"
	"strings"
	"testing"
	"time"

	"skill-scanner/internal/llm"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func TestExecuteLLMReviewAgentProducesVerdictsAndMergeUsesConservativeFallback(t *testing.T) {
	refined := review.Result{ReviewAgentTasks: []review.ReviewAgentTask{{FindingID: "SF-001", Objective: "复核命令执行", Prompt: "prompt-1", StrictStandards: []string{"零误报"}}, {FindingID: "SF-002", Objective: "复核示例外联", Prompt: "prompt-2", StrictStandards: []string{"排除示例"}}}}
	client := &fakeLLMReviewClient{results: map[string]*llm.AnalysisResult{
		"漏洞二次复核 SF-001": {IntentRiskLevel: "high", IntentMismatch: "存在真实命令执行", Risks: []llm.RiskItem{{Severity: "high", Description: "命令拼接进入 shell", KeyCodeLocation: "scripts/run.py:10", EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, Remediation: "在 scripts/run.py:10 移除 shell 拼接，改为固定命令 allowlist 和参数数组传递。", VerificationStep: "重新扫描 scripts/run.py:10，确认 os.system(cmd) 证据消失。", RemediationQuality: "high"}}},
		"漏洞二次复核 SF-002": {IntentRiskLevel: "low", IntentConsistency: 95, ConsistencyEvidence: []string{"已确认示例文件不会进入发布包"}},
	}}

	llmVerdicts, stats, err := executeLLMReviewAgentWithStats(context.Background(), client, refined, nil)
	if err != nil {
		t.Fatalf("execute llm reviewer: %v", err)
	}
	if len(llmVerdicts) != 2 || len(client.calls) != 2 {
		t.Fatalf("expected two llm verdicts and calls, got verdicts=%+v calls=%+v", llmVerdicts, client.calls)
	}
	if stats.Reviewer != "llm-vuln-reviewer" || stats.TaskCount != 2 || stats.WorkerCount == 0 || stats.MaxConcurrency == 0 {
		t.Fatalf("expected llm reviewer stats, got %+v", stats)
	}
	if llmVerdicts[0].Verdict != "confirmed" || llmVerdicts[0].Reviewer != "llm-vuln-reviewer" {
		t.Fatalf("expected confirmed llm verdict, got %+v", llmVerdicts[0])
	}
	if llmVerdicts[1].Verdict != "likely_false_positive" {
		t.Fatalf("expected likely false positive, got %+v", llmVerdicts[1])
	}

	merged := mergeReviewAgentVerdicts([]review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "needs_manual_review", Reviewer: "deterministic-vuln-reviewer"}}, llmVerdicts[:1])
	preferred := preferredVerdictsByFinding(merged)
	if preferred["SF-001"].Verdict != "needs_manual_review" || !strings.Contains(preferred["SF-001"].Reviewer, "deterministic-vuln-reviewer") || !strings.Contains(preferred["SF-001"].Reviewer, "llm-vuln-reviewer") {
		t.Fatalf("expected conflicting verdicts to fall back to manual review, got %+v", preferred["SF-001"])
	}
}

func TestExecuteLLMReviewAgentUsesBoundedLoopForStageContextTask(t *testing.T) {
	stage := review.LLMStageContext{Purpose: review.LLMStageSecondReview, StageID: "SF-LOOP", Finding: review.NormalizedFinding{ID: "SF-LOOP", Category: "命令执行", Severity: "高风险", Confidence: "高", CodeEvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}}}
	refined := review.Result{ReviewAgentTasks: []review.ReviewAgentTask{{FindingID: "SF-LOOP", Objective: "复核命令执行", Prompt: "prompt-loop", StrictStandards: []string{"证据完整性"}, StageContext: &stage}}}
	client := &fakeLLMReviewClient{completions: []string{
		`{"tool":"locateRiskyCode","args":{"pattern":"os.system"}}`,
		`{"verdict":"confirmed","reason":"存在命令执行证据","risks":[{"severity":"high","status":"confirmed","description":"命令拼接进入 shell","key_code_location":"scripts/run.py:10","evidence_refs":["scripts/run.py:10 os.system(cmd)"],"remediation":"在 scripts/run.py:10 移除 shell 拼接，改用固定命令 allowlist 和参数数组。","verification_step":"重新扫描 scripts/run.py:10，确认 os.system(cmd) 证据消失。","remediation_quality":"high"}]}`,
	}}

	verdicts, stats, err := executeLLMReviewAgentWithStats(context.Background(), client, refined, nil)
	if err != nil {
		t.Fatalf("execute llm reviewer with loop: %v", err)
	}
	if len(verdicts) != 1 || verdicts[0].Verdict != "confirmed" {
		t.Fatalf("expected confirmed bounded loop verdict, got %+v", verdicts)
	}
	if len(verdicts[0].ToolTrace) != 1 || verdicts[0].ToolTrace[0].ToolName != "locateRiskyCode" || verdicts[0].ToolTrace[0].Status != "completed" {
		t.Fatalf("expected structured tool trace on verdict, got %+v", verdicts[0].ToolTrace)
	}
	for _, missing := range verdicts[0].MissingEvidence {
		if strings.Contains(missing, "tool:") {
			t.Fatalf("expected tool trace separated from missing evidence, got %+v", verdicts[0].MissingEvidence)
		}
	}
	if len(client.completeCalls) != 2 || len(client.calls) != 0 {
		t.Fatalf("expected Complete loop path only, complete=%d analyze=%d", len(client.completeCalls), len(client.calls))
	}
	if !strings.Contains(client.completeCalls[1], "<TOOL_OBSERVATION") || !strings.Contains(client.completeCalls[1], "os.system") {
		t.Fatalf("expected second completion prompt with tool observation, got %s", client.completeCalls[1])
	}
	if stats.Reviewer != "llm-vuln-reviewer" || stats.TaskCount != 1 || stats.MaxConcurrency == 0 {
		t.Fatalf("expected stats for bounded loop reviewer, got %+v", stats)
	}
}

func TestRenderReviewWorkflowIntegratedCardShowsToolTrace(t *testing.T) {
	refined := review.Result{StructuredFindings: []review.StructuredFinding{{ID: "SF-TRACE", Title: "命令执行"}}, ReviewAgentTasks: []review.ReviewAgentTask{{FindingID: "SF-TRACE", AgentRole: "vuln-reviewer", Objective: "复核命令执行", StageContext: &review.LLMStageContext{Finding: review.NormalizedFinding{Category: "远程命令执行", Severity: "高风险", Status: "needs_manual_review", PrimaryLocation: "scripts/run.py:10", ExplanationSummary: "用户输入可能进入 shell", CodeEvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, BehaviorEvidenceRefs: []string{"sandbox: exec /bin/sh"}, ContextEvidenceRefs: []string{"README.md:12 说明"}, EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)", "sandbox: exec /bin/sh", "README.md:12 说明"}}}}}, ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-TRACE", Verdict: "confirmed", Confidence: "高", Reason: "工具证据确认", Reviewer: "llm-vuln-reviewer", ToolTrace: []review.ToolTraceEntry{{Iteration: 1, ToolName: "locateRiskyCode", Status: "completed", Summary: "定位到 os.system"}}}}}

	html := renderReviewWorkflowIntegratedCard(refined)
	for _, want := range []string{"LLM 工具轨迹", "locateRiskyCode", "已完成", "定位到 os.system", "阶段上下文", "关键位置=scripts/run.py:10", "证据计数", "代码证据=1", "行为证据=1", "上下文证据=1", "总证据=3", "已确认风险", "已采用"} {
		if !strings.Contains(html, want) {
			t.Fatalf("expected review workflow card contains %q, got %s", want, html)
		}
	}
}

func TestExecuteLLMReviewAgentRunsTasksInParallelAndKeepsOrder(t *testing.T) {
	refined := review.Result{ReviewAgentTasks: []review.ReviewAgentTask{{FindingID: "SF-001", Objective: "复核命令执行", Prompt: "prompt-1", StrictStandards: []string{"零误报"}}, {FindingID: "SF-002", Objective: "复核示例外联", Prompt: "prompt-2", StrictStandards: []string{"排除示例"}}, {FindingID: "SF-003", Objective: "复核凭据访问", Prompt: "prompt-3", StrictStandards: []string{"入口可达性"}}}}
	client := &fakeLLMReviewClient{delay: 40 * time.Millisecond, results: map[string]*llm.AnalysisResult{
		"漏洞二次复核 SF-001": {IntentRiskLevel: "high", IntentMismatch: "存在真实命令执行", Risks: []llm.RiskItem{{Severity: "high", Description: "命令拼接进入 shell", KeyCodeLocation: "scripts/run.py:10", EvidenceRefs: []string{"scripts/run.py:10 os.system(cmd)"}, Remediation: "在 scripts/run.py:10 移除 shell 拼接，改为固定命令 allowlist 和参数数组传递。", VerificationStep: "重新扫描 scripts/run.py:10，确认 os.system(cmd) 证据消失。", RemediationQuality: "high"}}},
		"漏洞二次复核 SF-002": {IntentRiskLevel: "low", IntentConsistency: 95, ConsistencyEvidence: []string{"示例不会进入发布包"}},
		"漏洞二次复核 SF-003": {IntentRiskLevel: "medium", IntentMismatch: "存在凭据访问风险", Risks: []llm.RiskItem{{Severity: "medium", Description: "凭据文件被读取", KeyCodeLocation: "auth.py:8", EvidenceRefs: []string{"auth.py:8 open('/root/.netrc')"}, Remediation: "在 auth.py:8 移除固定凭据文件读取，改为显式配置的最小权限 token 读取并限制路径 allowlist。", VerificationStep: "重新扫描 auth.py:8，确认固定凭据文件读取证据消失。", RemediationQuality: "high"}}},
	}}

	start := time.Now()
	verdicts, stats, err := executeLLMReviewAgentWithStats(context.Background(), client, refined, nil)
	if err != nil {
		t.Fatalf("execute llm reviewer in parallel: %v", err)
	}
	if len(verdicts) != 3 {
		t.Fatalf("expected three verdicts, got %+v", verdicts)
	}
	if verdicts[0].FindingID != "SF-001" || verdicts[1].FindingID != "SF-002" || verdicts[2].FindingID != "SF-003" {
		t.Fatalf("expected verdict order to stay aligned with tasks, got %+v", verdicts)
	}
	if client.maxConcurrent < 2 {
		t.Fatalf("expected parallel llm execution, got max concurrency %d", client.maxConcurrent)
	}
	if stats.MaxConcurrency < 2 || stats.WorkerCount < 2 {
		t.Fatalf("expected llm stats capture concurrency, got %+v", stats)
	}
	if elapsed := time.Since(start); elapsed >= 100*time.Millisecond {
		t.Fatalf("expected parallel execution to finish faster than near-serial runtime, took %s", elapsed)
	}
}

func TestCountReviewedFindingRisksKeepsStrongConfirmedHighRisk(t *testing.T) {
	findings := []plugins.Finding{{RuleID: "V7-009", Severity: "高风险", Title: "命令执行"}}
	refined := review.Result{Behavior: review.BehaviorProfile{SequenceAlerts: []string{"命中下载后执行时序"}}, StructuredFindings: []review.StructuredFinding{{ID: "SF-001", RuleID: "V7-009", Severity: "高风险", Title: "命令执行", Category: "命令执行", Confidence: "高", Evidence: []string{"scripts/run.py:10 exec.Command(payload)", "scripts/run.py:12 os.WriteFile(dropper)"}, CalibrationBasis: []string{"存在高危时序告警"}}}, ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "confirmed", Reviewer: "deterministic-vuln-reviewer"}}}
	high, medium, low := countReviewedFindingRisks(findings, refined)
	if high != 1 || medium != 0 || low != 0 {
		t.Fatalf("expected strong confirmed finding remain high, got %d/%d/%d", high, medium, low)
	}
}

func TestFinalReviewMappingUsesStableFindingKeyAfterNormalizationAndSeverityCalibration(t *testing.T) {
	findings := []plugins.Finding{{RuleID: "LLM-DETECT", Severity: "低风险", Title: "Python 环境隔离被绕过", Location: "bootstrap.sh:12", CodeSnippet: `pip3 install -r requirements.txt --break-system-packages`}}
	refined := review.Result{StructuredFindings: []review.StructuredFinding{{ID: "SF-001", RuleID: "LLM-DETECT", Severity: "中风险", Title: "Python 系统包安装风险", Category: "环境与构建风险", Evidence: []string{"bootstrap.sh:12 pip3 install -r requirements.txt --break-system-packages"}}}, ReviewAgentVerdicts: []review.ReviewAgentVerdict{{FindingID: "SF-001", Verdict: "confirmed", Reviewer: "deterministic-vuln-reviewer"}}}
	if got := finalReviewSummaryForFinding(findings[0], refined); !strings.Contains(got, "确认风险") {
		t.Fatalf("expected final review summary resolved through stable key, got %q", got)
	}
	ordered := sortFindingsByReview(findings, refined)
	if len(ordered) != 1 || ordered[0].RuleID != "LLM-DETECT" {
		t.Fatalf("expected stable-key sort keeps finding accessible, got %+v", ordered)
	}
}

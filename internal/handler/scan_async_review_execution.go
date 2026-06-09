package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"skill-scanner/internal/config"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/review"
)

func reviewPolicyConfig() *config.ReviewPolicyConfig {
	cfg, err := config.DefaultReviewPolicy()
	if err != nil {
		return nil
	}
	return cfg
}

func reviewPolicyWeakStaticTitles() []string {
	if cfg := reviewPolicyConfig(); cfg != nil {
		return cfg.EffectiveWeakStaticTitles()
	}
	return (&config.ReviewPolicyConfig{}).EffectiveWeakStaticTitles()
}

func reviewPolicyOpenWeakTitles() []string {
	if cfg := reviewPolicyConfig(); cfg != nil {
		return cfg.EffectiveOpenWeakTitles()
	}
	return (&config.ReviewPolicyConfig{}).EffectiveOpenWeakTitles()
}

func reviewPolicyEvidenceIntentMismatchMarkers() []string {
	if cfg := reviewPolicyConfig(); cfg != nil {
		return cfg.EffectiveEvidenceIntentMismatchMarkers()
	}
	return (&config.ReviewPolicyConfig{}).EffectiveEvidenceIntentMismatchMarkers()
}

func reviewPolicyRefutedPrimaryClaimMarkers(title string) []string {
	if cfg := reviewPolicyConfig(); cfg != nil {
		return cfg.RefutedPrimaryClaimMarkers(title)
	}
	return nil
}

func reviewPolicyCategoryRefutationMarkers(category string) []string {
	if cfg := reviewPolicyConfig(); cfg != nil {
		return cfg.CategoryRefutationMarkers(category)
	}
	return nil
}

func requiresRuntimeClosure(category string) bool {
	if cfg := reviewPolicyConfig(); cfg != nil {
		return cfg.RequiresRuntimeClosure(category, true, cfg.EffectiveRuntimeClosureCategoriesWithoutRuntime())
	}
	return (&config.ReviewPolicyConfig{}).RequiresRuntimeClosure(category, true, nil)
}

func weakStaticThreshold(category string) (config.ReviewCategoryMissingThreshold, bool) {
	if cfg := reviewPolicyConfig(); cfg != nil {
		return cfg.WeakStaticThreshold(category)
	}
	return (&config.ReviewPolicyConfig{}).WeakStaticThreshold(category)
}

func isOpenWeakCategory(category string) bool {
	if cfg := reviewPolicyConfig(); cfg != nil {
		return cfg.IsOpenWeakCategory(category, nil)
	}
	return (&config.ReviewPolicyConfig{}).IsOpenWeakCategory(category, nil)
}

func isEvidenceIntentMismatchCategory(category string) bool {
	if cfg := reviewPolicyConfig(); cfg != nil {
		return cfg.IsEvidenceIntentMismatchCategory(category, nil)
	}
	return (&config.ReviewPolicyConfig{}).IsEvidenceIntentMismatchCategory(category, nil)
}

func executeDeterministicReviewAgent(refined review.Result) []review.ReviewAgentVerdict {
	verdicts, _ := executeDeterministicReviewAgentWithStats(refined)
	return verdicts
}

func executeDeterministicReviewAgentWithStats(refined review.Result) ([]review.ReviewAgentVerdict, review.ReviewAgentExecutionStats) {
	stats := review.ReviewAgentExecutionStats{Reviewer: "deterministic-vuln-reviewer", TaskCount: len(refined.ReviewAgentTasks)}
	if len(refined.ReviewAgentTasks) == 0 {
		return nil, stats
	}
	startedAt := time.Now()
	findingByID := map[string]review.StructuredFinding{}
	for _, finding := range refined.StructuredFindings {
		findingByID[finding.ID] = finding
	}
	fpByID := map[string]review.FalsePositiveReview{}
	for _, fp := range refined.FalsePositiveReviews {
		fpByID[fp.FindingID] = fp
	}
	verdicts := make([]review.ReviewAgentVerdict, len(refined.ReviewAgentTasks))
	workerCount := reviewAgentWorkerCount(len(refined.ReviewAgentTasks))
	stats.WorkerCount = workerCount
	stats.MaxConcurrency = workerCount
	var wg sync.WaitGroup
	jobs := make(chan int)
	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				task := refined.ReviewAgentTasks[idx]
				finding := findingByID[task.FindingID]
				fp := fpByID[task.FindingID]
				verdicts[idx] = deterministicVerdictForTask(task, finding, fp, refined)
			}
		}()
	}
	for idx := range refined.ReviewAgentTasks {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	stats.DurationMs = time.Since(startedAt).Milliseconds()
	return verdicts, stats
}

type reviewProgressStage string

const (
	reviewProgressStarted   reviewProgressStage = "started"
	reviewProgressCompleted reviewProgressStage = "completed"
	reviewProgressFailed    reviewProgressStage = "failed"
)

type reviewProgressEvent struct {
	Stage      reviewProgressStage
	Done       int
	Total      int
	Task       review.ReviewAgentTask
	Verdict    review.ReviewAgentVerdict
	DurationMs int64
	Err        error
}

func executeLLMReviewAgent(ctx context.Context, client llm.Client, refined review.Result) ([]review.ReviewAgentVerdict, error) {
	verdicts, _, err := executeLLMReviewAgentWithStats(ctx, client, refined, nil)
	return verdicts, err
}

func executeLLMReviewAgentWithStats(ctx context.Context, client llm.Client, refined review.Result, progress func(event reviewProgressEvent)) ([]review.ReviewAgentVerdict, review.ReviewAgentExecutionStats, error) {
	stats := review.ReviewAgentExecutionStats{Reviewer: "llm-vuln-reviewer", TaskCount: len(refined.ReviewAgentTasks)}
	if client == nil {
		stats.Failed = true
		stats.ErrorMessage = "LLM reviewer 客户端不可用"
		return nil, stats, fmt.Errorf("LLM reviewer 客户端不可用")
	}
	if len(refined.ReviewAgentTasks) == 0 {
		return nil, stats, nil
	}
	startedAt := time.Now()
	verdicts := make([]review.ReviewAgentVerdict, len(refined.ReviewAgentTasks))
	failedKinds := make([]string, len(refined.ReviewAgentTasks))
	workerCount := reviewAgentWorkerCount(len(refined.ReviewAgentTasks))
	stats.WorkerCount = workerCount
	jobs := make(chan int)
	var wg sync.WaitGroup
	var activeWorkers int32
	var maxConcurrency int32
	var completed int32
	var failed int32
	for worker := 0; worker < workerCount; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				current := atomic.AddInt32(&activeWorkers, 1)
				for {
					seen := atomic.LoadInt32(&maxConcurrency)
					if current <= seen || atomic.CompareAndSwapInt32(&maxConcurrency, seen, current) {
						break
					}
				}
				task := refined.ReviewAgentTasks[idx]
				if progress != nil {
					progress(reviewProgressEvent{Stage: reviewProgressStarted, Done: int(atomic.LoadInt32(&completed) + atomic.LoadInt32(&failed)), Total: len(refined.ReviewAgentTasks), Task: task})
				}
				taskStartedAt := time.Now()
				verdict, err := executeLLMReviewTask(ctx, client, task)
				durationMs := time.Since(taskStartedAt).Milliseconds()
				atomic.AddInt32(&activeWorkers, -1)
				if err != nil {
					atomic.AddInt32(&failed, 1)
					failedKinds[idx], _ = classifyReviewFailure(err.Error())
					if progress != nil {
						progress(reviewProgressEvent{Stage: reviewProgressFailed, Done: int(atomic.LoadInt32(&completed) + atomic.LoadInt32(&failed)), Total: len(refined.ReviewAgentTasks), Task: task, DurationMs: durationMs, Err: err})
					}
					verdicts[idx] = review.ReviewAgentVerdict{
						FindingID:        task.FindingID,
						Verdict:          "needs_manual_review",
						Confidence:       "低",
						Reason:           llmReviewFailureReason(err),
						MissingEvidence:  []string{err.Error()},
						Fix:              "恢复可用的 LLM 配置或补充规则复核所需证据后重新执行二次复核。",
						Reviewer:         "llm-vuln-reviewer",
						StandardsApplied: task.StrictStandards,
					}
					continue
				}
				verdicts[idx] = normalizeReviewAgentVerdict(verdict, task.FindingID, "llm-vuln-reviewer", task.StrictStandards)
				if progress != nil {
					done := int(atomic.AddInt32(&completed, 1) + atomic.LoadInt32(&failed))
					progress(reviewProgressEvent{Stage: reviewProgressCompleted, Done: done, Total: len(refined.ReviewAgentTasks), Task: task, Verdict: verdict, DurationMs: durationMs})
				}
			}
		}()
	}
	for idx := range refined.ReviewAgentTasks {
		jobs <- idx
	}
	close(jobs)
	wg.Wait()
	stats.DurationMs = time.Since(startedAt).Milliseconds()
	stats.MaxConcurrency = int(maxConcurrency)
	if atomic.LoadInt32(&failed) > 0 {
		stats.Failed = true
		trace := &review.ReviewTrace{Total: len(refined.ReviewAgentTasks), Completed: int(atomic.LoadInt32(&completed) + atomic.LoadInt32(&failed))}
		for idx, task := range refined.ReviewAgentTasks {
			entry := review.ReviewTraceEntry{FindingID: task.FindingID, Status: "completed"}
			if strings.TrimSpace(failedKinds[idx]) != "" {
				entry.Status = "failed"
				entry.FailureKind = failedKinds[idx]
			}
			trace.Entries = append(trace.Entries, entry)
		}
		stats.ErrorMessage = reviewTraceErrorSummary(trace)
	}
	return verdicts, stats, nil
}

func llmReviewFailureReason(err error) string {
	message := strings.TrimSpace(err.Error())
	lower := strings.ToLower(message)
	switch {
	case strings.Contains(lower, "insufficient balance"):
		return "LLM 复核未完成：账户余额不足，当前项已回退为需人工复核。"
	case strings.Contains(lower, "context canceled"):
		return "LLM 复核未完成：请求被取消，当前项已回退为需人工复核。"
	case strings.Contains(lower, "context deadline exceeded") || strings.Contains(lower, "deadline exceeded"):
		return "LLM 复核未完成：请求超时，当前项已回退为需人工复核。"
	default:
		if message == "" {
			return "LLM 复核未完成：执行异常，当前项已回退为需人工复核。"
		}
		return "LLM 复核未完成：" + message + "，当前项已回退为需人工复核。"
	}
}

func executeLLMReviewTask(ctx context.Context, client llm.Client, task review.ReviewAgentTask) (review.ReviewAgentVerdict, error) {
	timeoutCtx, cancel := context.WithTimeout(ctx, llmReviewTaskTimeout())
	defer cancel()
	if task.StageContext == nil {
		analysis, err := client.AnalyzeCode(timeoutCtx, "漏洞二次复核 "+task.FindingID, task.Objective, task.Prompt)
		if err != nil {
			return review.ReviewAgentVerdict{}, err
		}
		return llmAnalysisToReviewVerdict(task, analysis), nil
	}
	loopResult, err := review.RunBoundedLLMAnalysisLoop(timeoutCtx, client, *task.StageContext, review.LLMAnalysisLoopConfig{MaxIterations: 3, UserPrompt: task.Prompt})
	if err != nil {
		return review.ReviewAgentVerdict{}, err
	}
	return llmLoopResultToReviewVerdict(task, loopResult), nil
}

func llmReviewTaskTimeout() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("REVIEW_LLM_TASK_TIMEOUT_SECS")); raw != "" {
		if secs, err := strconv.Atoi(raw); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return 90 * time.Second
}

func reviewAgentWorkerCount(taskCount int) int {
	if taskCount <= 1 {
		return taskCount
	}
	if taskCount > 4 {
		return 4
	}
	return taskCount
}

func llmAnalysisToReviewVerdict(task review.ReviewAgentTask, analysis *llm.AnalysisResult) review.ReviewAgentVerdict {
	if analysis == nil {
		return review.ReviewAgentVerdict{FindingID: task.FindingID, Verdict: "needs_manual_review", Confidence: "低", Reason: "LLM reviewer 未返回有效分析。", MissingEvidence: []string{"缺少 LLM reviewer 输出"}, Reviewer: "llm-vuln-reviewer", StandardsApplied: task.StrictStandards}
	}
	riskLevel := strings.ToLower(strings.TrimSpace(analysis.IntentRiskLevel))
	bestRisk := strongestReviewRisk(analysis.Risks)
	highestRisk := strings.ToLower(strings.TrimSpace(bestRisk.Severity))
	verdict := "needs_manual_review"
	confidence := "中"
	reason := strings.TrimSpace(analysis.IntentMismatch)
	if reason == "" {
		reason = strings.TrimSpace(analysis.ActualBehavior)
	}
	if reason == "" {
		reason = "LLM reviewer 已执行，但未给出详细原因。"
	}
	missing := append([]string{}, analysis.ConsistencyEvidence...)
	missing = append(missing, reviewRiskMissingEvidence(bestRisk)...)
	qualityLow := reviewRiskQualityLow(bestRisk)
	if (highestRisk == "high" || riskLevel == "high" || riskLevel == "medium") && !qualityLow {
		verdict = "confirmed"
		confidence = "高"
	} else if highestRisk == "high" || riskLevel == "high" || riskLevel == "medium" {
		verdict = "needs_manual_review"
		confidence = "低"
		reason = "LLM reviewer 指出风险，但缺少 confirmed 所需的关键代码、证据引用、修复建议或验证步骤。"
	} else if len(analysis.Risks) == 0 && (riskLevel == "none" || riskLevel == "low" || analysis.IntentConsistency >= 80) {
		verdict = "likely_false_positive"
		confidence = "中高"
		if len(missing) == 0 {
			missing = append(missing, "LLM reviewer 未发现足够风险证据")
		}
	}
	fix := evidenceBoundReviewFix(bestRisk)
	if fix == "" {
		fix = "按 LLM reviewer 输出和规则解释卡修复或补证。"
	}
	confirmedEvidenceMissing := validatedConfirmedRiskMissing(task, verdict, bestRisk)
	if len(confirmedEvidenceMissing) > 0 {
		verdict = "needs_manual_review"
		confidence = "低"
		reason = "LLM reviewer 给出了 confirmed，但返回证据未通过二审阶段的代码/行为证据硬校验。"
		missing = append(missing, confirmedEvidenceMissing...)
	}
	return review.ReviewAgentVerdict{
		FindingID:        task.FindingID,
		Verdict:          verdict,
		Confidence:       confidence,
		Reason:           reason,
		MissingEvidence:  uniqueStrings(missing),
		Fix:              fix,
		Reviewer:         "llm-vuln-reviewer",
		StandardsApplied: task.StrictStandards,
	}
}

type llmReviewVerdictPayload struct {
	Verdict         string         `json:"verdict"`
	Reason          string         `json:"reason"`
	MissingEvidence []string       `json:"missing_evidence"`
	Fix             string         `json:"fix"`
	Risks           []llm.RiskItem `json:"risks"`
}

func llmLoopResultToReviewVerdict(task review.ReviewAgentTask, loopResult review.LLMAnalysisLoopResult) review.ReviewAgentVerdict {
	if loopResult.LimitReached {
		missing := []string{"LLM reviewer 达到最大工具迭代次数"}
		missing = append(missing, loopResult.Warnings...)
		return review.ReviewAgentVerdict{FindingID: task.FindingID, Verdict: "needs_manual_review", Confidence: "低", Reason: "LLM reviewer 未在迭代上限内输出最终裁决。", MissingEvidence: uniqueStrings(missing), Fix: "补充关键代码、证据引用和修复验证步骤后重新复核。", Reviewer: "llm-vuln-reviewer", StandardsApplied: task.StrictStandards, ToolTrace: loopResult.ToolTrace}
	}
	var payload llmReviewVerdictPayload
	if err := json.Unmarshal([]byte(llm.ExtractJSON(loopResult.FinalResponse)), &payload); err != nil {
		return fallbackLLMReviewVerdictFromText(task, loopResult, err)
	}
	analysis := &llm.AnalysisResult{IntentRiskLevel: reviewVerdictRiskLevel(payload.Verdict), IntentMismatch: payload.Reason, ConsistencyEvidence: payload.MissingEvidence, Risks: payload.Risks}
	verdict := llmAnalysisToReviewVerdict(task, analysis)
	confirmedEvidenceMissing := validatedConfirmedEvidenceMissing(task, payload)
	if len(confirmedEvidenceMissing) > 0 {
		wasConfirmed := verdict.Verdict == "confirmed"
		verdict.Verdict = "needs_manual_review"
		verdict.Confidence = "低"
		if strings.TrimSpace(verdict.Reason) == "" || wasConfirmed {
			verdict.Reason = "LLM reviewer 给出了 confirmed，但返回证据未通过二审阶段的代码/行为证据硬校验。"
		}
		verdict.MissingEvidence = uniqueStrings(append(verdict.MissingEvidence, confirmedEvidenceMissing...))
	}
	if strings.TrimSpace(payload.Verdict) != "" && !reviewRiskQualityLow(strongestReviewRisk(payload.Risks)) {
		switch strings.TrimSpace(payload.Verdict) {
		case "confirmed", "likely_false_positive", "needs_manual_review":
			if !(strings.TrimSpace(payload.Verdict) == "confirmed" && len(confirmedEvidenceMissing) > 0) {
				verdict.Verdict = strings.TrimSpace(payload.Verdict)
			}
		}
	}
	if strings.TrimSpace(payload.Fix) != "" && strings.TrimSpace(verdict.Fix) == "" {
		verdict.Fix = strings.TrimSpace(payload.Fix)
	}
	verdict.ToolTrace = append([]review.ToolTraceEntry{}, loopResult.ToolTrace...)
	return normalizeReviewAgentVerdict(verdict, task.FindingID, "llm-vuln-reviewer", task.StrictStandards)
}

func fallbackLLMReviewVerdictFromText(task review.ReviewAgentTask, loopResult review.LLMAnalysisLoopResult, parseErr error) review.ReviewAgentVerdict {
	text := strings.TrimSpace(loopResult.FinalResponse)
	verdict := review.ReviewAgentVerdict{
		FindingID:        task.FindingID,
		Verdict:          fallbackReviewVerdictFromText(text),
		Confidence:       "低",
		Reason:           fallbackReviewReasonFromText(text),
		MissingEvidence:  []string{"LLM reviewer bounded loop 未返回有效 JSON 裁决，已从文本输出提取有限结论。"},
		Fix:              "要求 LLM reviewer 只输出符合二审 schema 的 JSON，并补齐 evidence_refs、key_code_location 和修复验证步骤。",
		Reviewer:         "llm-vuln-reviewer",
		StandardsApplied: task.StrictStandards,
		ToolTrace:        append([]review.ToolTraceEntry{}, loopResult.ToolTrace...),
	}
	if parseErr != nil && strings.TrimSpace(parseErr.Error()) != "" {
		verdict.MissingEvidence = append(verdict.MissingEvidence, parseErr.Error())
	}
	if verdict.Verdict == "confirmed" {
		verdict.Verdict = "needs_manual_review"
		verdict.Reason = "LLM reviewer 文本输出倾向 confirmed，但未返回结构化证据，已回退为需人工复核。"
		verdict.MissingEvidence = append(verdict.MissingEvidence, "非 JSON confirmed 缺少可校验 risks、evidence_refs 和 key_code_location")
	}
	return normalizeReviewAgentVerdict(verdict, task.FindingID, "llm-vuln-reviewer", task.StrictStandards)
}

func fallbackReviewVerdictFromText(text string) string {
	lower := strings.ToLower(strings.TrimSpace(text))
	for _, marker := range []string{"likely_false_positive", "false positive", "误报", "倾向误报", "不构成", "风险不成立"} {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return "likely_false_positive"
		}
	}
	for _, marker := range []string{"needs_manual_review", "manual review", "人工复核", "待复核", "证据不足", "无法确认"} {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return "needs_manual_review"
		}
	}
	for _, marker := range []string{"confirmed", "true positive", "真实风险", "确认风险", "风险成立", "漏洞成立"} {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return "confirmed"
		}
	}
	for _, marker := range []string{"policy", "策略风险", "准入策略"} {
		if strings.Contains(lower, strings.ToLower(marker)) {
			return "policy"
		}
	}
	return "needs_manual_review"
}

func fallbackReviewReasonFromText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return "LLM reviewer 返回了非 JSON 空输出，已回退为需人工复核。"
	}
	lines := limitNonEmptyStrings(strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n"), 3)
	if len(lines) == 0 {
		return "LLM reviewer 返回了非 JSON 输出，已回退为需人工复核。"
	}
	reason := strings.Join(lines, " ")
	if len([]rune(reason)) > 220 {
		reason = string([]rune(reason)[:220]) + "..."
	}
	return reason
}

func validatedConfirmedEvidenceMissing(task review.ReviewAgentTask, payload llmReviewVerdictPayload) []string {
	if strings.TrimSpace(payload.Verdict) != "confirmed" || task.StageContext == nil {
		return nil
	}
	bestRisk := strongestReviewRisk(payload.Risks)
	return validatedConfirmedRiskMissing(task, payload.Verdict, bestRisk)
}

func validatedConfirmedRiskMissing(task review.ReviewAgentTask, verdict string, risk llm.RiskItem) []string {
	if strings.TrimSpace(verdict) != "confirmed" || task.StageContext == nil {
		return nil
	}
	bestRisk := risk
	if strings.TrimSpace(bestRisk.Title+bestRisk.Description+bestRisk.Evidence+bestRisk.Remediation) == "" {
		return []string{"LLM reviewer confirmed 但未返回可校验的风险条目"}
	}
	allowedEvidence := append([]string{}, task.StageContext.Finding.CodeEvidenceRefs...)
	allowedEvidence = append(allowedEvidence, task.StageContext.Finding.BehaviorEvidenceRefs...)
	if len(allowedEvidence) == 0 {
		return []string{"二审上下文缺少可用于 confirmed 的代码或行为证据"}
	}
	allowedAliases := append([]string{}, allowedEvidence...)
	allowedAliases = append(allowedAliases, task.StageContext.Finding.EvidenceAliases...)
	allowedAliases = append(allowedAliases, task.StageContext.Finding.ChainSummaries...)
	if loc := strings.TrimSpace(task.StageContext.Finding.PrimaryLocation); loc != "" {
		allowedAliases = append(allowedAliases, loc)
	}
	missing := make([]string, 0, 2)
	if !reviewRiskMatchesAllowedEvidence(bestRisk, allowedAliases) {
		missing = append(missing, "LLM reviewer confirmed 使用的 evidence_refs 未命中允许的代码、行为或闭环别名证据集合")
	}
	if !reviewRiskLocationMatchesAllowedEvidence(bestRisk, allowedAliases) {
		missing = append(missing, "LLM reviewer confirmed 的 key_code_location 未绑定允许的代码、行为或闭环别名定位")
	}
	return missing
}

func reviewRiskMatchesAllowedEvidence(risk llm.RiskItem, allowed []string) bool {
	if len(allowed) == 0 || len(risk.EvidenceRefs) == 0 {
		return false
	}
	for _, ref := range risk.EvidenceRefs {
		if reviewTextMatchesAllowedEvidence(ref, allowed) {
			return true
		}
	}
	return false
}

func reviewRiskLocationMatchesAllowedEvidence(risk llm.RiskItem, allowed []string) bool {
	location := strings.TrimSpace(risk.KeyCodeLocation)
	if location == "" || len(allowed) == 0 {
		return false
	}
	return reviewTextMatchesAllowedEvidence(location, allowed)
}

func reviewTextMatchesAllowedEvidence(text string, allowed []string) bool {
	needle := strings.ToLower(strings.TrimSpace(text))
	if needle == "" {
		return false
	}
	for _, item := range allowed {
		candidate := strings.ToLower(strings.TrimSpace(item))
		if candidate == "" {
			continue
		}
		if strings.Contains(candidate, needle) || strings.Contains(needle, candidate) {
			return true
		}
		loc := strings.ToLower(strings.TrimSpace(extractEvidenceLocation(candidate)))
		if loc != "" && (strings.Contains(loc, needle) || strings.Contains(needle, loc)) {
			return true
		}
	}
	return false
}

func extractEvidenceLocation(text string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return ""
	}
	if idx := strings.Index(text, " |"); idx > 0 {
		return strings.TrimSpace(text[:idx])
	}
	fields := strings.Fields(text)
	if len(fields) == 0 {
		return ""
	}
	return strings.TrimSpace(fields[0])
}

func reviewVerdictRiskLevel(verdict string) string {
	switch strings.TrimSpace(verdict) {
	case "confirmed":
		return "high"
	case "likely_false_positive":
		return "none"
	default:
		return "medium"
	}
}

func strongestReviewRisk(risks []llm.RiskItem) llm.RiskItem {
	var best llm.RiskItem
	bestScore := -1
	for _, risk := range risks {
		severity := normalizedReviewRiskSeverity(risk.Severity)
		score := risk.RiskScore
		switch severity {
		case "high":
			score += 300
		case "medium":
			score += 200
		case "low":
			score += 100
		}
		if strings.EqualFold(strings.TrimSpace(risk.Status), "confirmed") {
			score += 25
		}
		if score > bestScore {
			bestScore = score
			best = risk
		}
	}
	best.Severity = normalizedReviewRiskSeverity(best.Severity)
	return best
}

func normalizedReviewRiskSeverity(severity string) string {
	switch strings.ToLower(strings.TrimSpace(severity)) {
	case "high", "高", "高风险", "critical", "严重":
		return "high"
	case "medium", "中", "中风险":
		return "medium"
	case "low", "低", "低风险":
		return "low"
	default:
		return ""
	}
}

func reviewRiskMissingEvidence(risk llm.RiskItem) []string {
	if strings.TrimSpace(risk.Title+risk.Description+risk.Evidence+risk.Remediation) == "" {
		return nil
	}
	missing := make([]string, 0, 5)
	if strings.TrimSpace(risk.KeyCodeLocation) == "" {
		missing = append(missing, "LLM reviewer 未给出 key_code_location")
	}
	if len(risk.EvidenceRefs) == 0 {
		missing = append(missing, "LLM reviewer 未给出 evidence_refs")
	}
	if strings.TrimSpace(risk.Remediation) == "" {
		missing = append(missing, "LLM reviewer 未给出证据绑定修复建议")
	}
	if strings.TrimSpace(risk.VerificationStep) == "" {
		missing = append(missing, "LLM reviewer 未给出修复验证步骤")
	}
	if reviewRiskQualityLow(risk) {
		missing = append(missing, "LLM reviewer 修复建议质量门禁未通过")
	}
	return missing
}

func reviewRiskQualityLow(risk llm.RiskItem) bool {
	if strings.TrimSpace(risk.Title+risk.Description+risk.Evidence+risk.Remediation) == "" {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(risk.RemediationQuality), "low") {
		return true
	}
	remediation := strings.TrimSpace(risk.Remediation)
	verification := strings.TrimSpace(risk.VerificationStep)
	if remediation == "" || verification == "" || strings.TrimSpace(risk.KeyCodeLocation) == "" || len(risk.EvidenceRefs) == 0 {
		return true
	}
	joined := strings.ToLower(remediation + " " + verification)
	return containsAny(joined, []string{"加强安全", "做好校验", "遵循最佳实践", "建议修复", "注意安全", "security best practices"})
}

func evidenceBoundReviewFix(risk llm.RiskItem) string {
	if strings.TrimSpace(risk.Title+risk.Description+risk.Evidence+risk.Remediation) == "" {
		return ""
	}
	parts := []string{}
	if strings.TrimSpace(risk.KeyCodeLocation) != "" {
		parts = append(parts, "关键代码: "+strings.TrimSpace(risk.KeyCodeLocation))
	}
	if len(risk.EvidenceRefs) > 0 {
		parts = append(parts, "证据: "+strings.Join(risk.EvidenceRefs, "；"))
	}
	if strings.TrimSpace(risk.Remediation) != "" {
		parts = append(parts, "修复: "+strings.TrimSpace(risk.Remediation))
	}
	if strings.TrimSpace(risk.VerificationStep) != "" {
		parts = append(parts, "验证: "+strings.TrimSpace(risk.VerificationStep))
	}
	return strings.Join(parts, "\n")
}

func mergeReviewAgentVerdicts(deterministic, llmVerdicts []review.ReviewAgentVerdict) []review.ReviewAgentVerdict {
	out := make([]review.ReviewAgentVerdict, 0, len(llmVerdicts)+len(deterministic))
	out = append(out, llmVerdicts...)
	out = append(out, deterministic...)
	return out
}

func deterministicVerdictForTask(task review.ReviewAgentTask, finding review.StructuredFinding, fp review.FalsePositiveReview, refined review.Result) review.ReviewAgentVerdict {
	missing := make([]string, 0, 4)
	hasRelevantBehavior := hasRelevantBehaviorSupport(finding.Category, refined.Behavior)
	closure := buildFindingClosureSummary(finding, refined)
	tiSemantic := threatIntelSemantics(reputationForFinding(finding, refined))
	docOnly := isLikelyDocumentationOnlyFinding(finding)
	internalOnly := isLikelyInternalDevelopmentFinding(finding)
	standards := []string{
		"入口可达性",
		"证据完整性",
		"排除条件",
		"真实影响",
	}
	if len(finding.Evidence) == 0 {
		missing = append(missing, "缺少具体证据定位或代码片段")
	}
	if strings.TrimSpace(finding.AttackPath) == "" {
		missing = append(missing, "缺少攻击路径说明")
	}
	if strings.EqualFold(strings.TrimSpace(finding.Source), "BehaviorGuard") && len(finding.Evidence) > 0 {
		missing = removeMissingEvidence(missing, "缺少具体证据定位或代码片段")
	}
	if tiSemantic != "policy" && !strings.Contains(fp.EvidenceStrength, "强") && !hasRelevantBehavior {
		missing = append(missing, "缺少多源行为证据或高危时序印证")
	}
	if len(fp.ReachabilityChecks) == 0 && !hasAutoReachabilitySupport(finding, refined, closure, hasRelevantBehavior) {
		// 即使没有显式的可达性检查，如果有行为支撑或代码证据，也不标记为缺失
		if !hasRelevantBehavior && len(finding.CodeEvidenceRefs) == 0 && !containsConcreteCodeLocation(finding.Evidence) {
			missing = append(missing, "缺少可达性检查结论")
		}
	}
	requiresRuntimeClosure := requiresRuntimeClosure(finding.Category)
	if !closure.HasSource {
		missing = append(missing, "缺少链路入口/source 证据")
	}
	if !closure.HasSink {
		missing = append(missing, "缺少链路落点/sink 证据")
	}
	if requiresRuntimeClosure && !closure.HasRuntimeSupport && tiSemantic != "policy" {
		missing = append(missing, "缺少运行链路或行为支撑")
	}
	if hasCrossFileDeterministicSupport(finding, refined, closure, requiresRuntimeClosure) {
		missing = removeMissingEvidence(missing, "缺少可达性检查结论")
		missing = removeMissingEvidence(missing, "缺少运行链路或行为支撑")
	}
	// 如果有行为支撑，移除运行链路相关缺失
	if hasRelevantBehavior {
		missing = removeMissingEvidence(missing, "缺少运行链路或行为支撑")
		missing = removeMissingEvidence(missing, "缺少多源行为证据或高危时序印证")
	}
	if docOnly && !hasThreatLikeFindingSignals(finding) {
		missing = append(missing, "缺少文档/示例内容进入真实发布或执行链路的证据")
	}
	if internalOnly && !hasThreatLikeFindingSignals(finding) {
		missing = append(missing, "缺少本地开发目标会扩展到真实外联或生产环境的证据")
	}
	hasBlockingCrossFileGap := hasCrossFileBlockingGap(finding, refined)
	preferFalsePositiveForWeakStatic := shouldPreferFalsePositiveForWeakStaticFinding(finding, fp, closure, missing, hasRelevantBehavior, docOnly, internalOnly)
	preserveManualForExposureSink := shouldPreserveManualReviewForExposureSink(finding, closure)
	if isDirectlyConfirmedFinding(finding, refined) && !hasBlockingCrossFileGap {
		verdict := review.ReviewAgentVerdict{
			FindingID:        task.FindingID,
			Verdict:          "confirmed",
			Confidence:       "高",
			Reason:           "证据已满足直接确认条件，可自动确认为真实风险。",
			MissingEvidence:  uniqueStrings(removeMissingEvidence(missing, "缺少多源行为证据或高危时序印证")),
			Fix:              defaultIfEmpty(finding.ReviewGuidance, "按规则解释卡和复核清单补齐修复建议。"),
			Reviewer:         "deterministic-vuln-reviewer",
			StandardsApplied: standards,
		}
		return verdict
	}

	verdict := "needs_manual_review"
	confidence := "中"
	reason := "证据存在但仍需人工确认入口可达性、影响和排除条件。"

	// 新增：如果有沙箱行为支撑且有代码证据，自动确认
	if hasRelevantBehavior && len(finding.Evidence) > 0 && !docOnly && !internalOnly && !hasBlockingCrossFileGap {
		// 检查是否有具体代码位置
		hasConcreteLocation := containsConcreteCodeLocation(finding.Evidence)
		// 检查是否有威胁信号
		hasThreatSignals := hasThreatLikeFindingSignals(finding)
		if hasConcreteLocation || hasThreatSignals {
			verdict = "confirmed"
			confidence = "中高"
			reason = "沙箱已观测到与当前风险相关的行为证据，且存在具体代码定位或威胁信号，可自动确认为真实风险。"
			missing = removeMissingEvidence(missing, "缺少多源行为证据或高危时序印证")
			missing = removeMissingEvidence(missing, "缺少可达性检查结论")
		}
	}

	if (docOnly || internalOnly) && !hasThreatLikeFindingSignals(finding) && !hasRelevantBehavior && !preserveManualForExposureSink {
		verdict = "likely_false_positive"
		confidence = "中高"
		reason = "当前主要是文档示例或本地开发证据，且缺少真实发布链路或高危行为支撑，按零误报标准先归为疑似误报。"
	} else if preferFalsePositiveForWeakStatic {
		verdict = "likely_false_positive"
		confidence = "中高"
		reason = "当前属于弱静态线索或环境健壮性问题，且缺少真实发布链路、闭环落点或运行支撑，按零误报标准先归为疑似误报。"
	} else if strings.Contains(fp.Verdict, "疑似误报") && len(missing) > 0 && !strings.Contains(fp.EvidenceStrength, "强") && !hasRelevantBehavior {
		verdict = "likely_false_positive"
		confidence = "中高"
		reason = "现有证据不足且已出现排除线索，按零误报标准先标记为疑似误报，仍需补充发布路径与运行链路结论。"
	} else if shouldDowngradeContextOnlyManualFinding(finding, closure, missing, hasRelevantBehavior, preserveManualForExposureSink) {
		verdict = "likely_false_positive"
		confidence = "中高"
		reason = "当前仅保留语义上下文证据，缺少代码定位和行为支撑，按零误报标准先归为疑似误报。"
	} else if tiSemantic == "policy" && len(finding.Evidence) > 0 && !hasBlockingCrossFileGap {
		verdict = "confirmed"
		confidence = "中高"
		reason = "该发现属于明确的准入策略命中，主要依据目标信誉语义和策略证据确认，不要求恶意行为链闭环。"
	} else if len(finding.Evidence) > 0 && len(finding.CalibrationBasis) > 0 && closure.HasSource && closure.HasSink && (closure.HasRuntimeSupport || (!requiresRuntimeClosure && closure.HasTransform)) && !docOnly && !internalOnly && !hasBlockingCrossFileGap {
		verdict = "confirmed"
		confidence = "中高"
		reason = "已存在具体定位、校准依据和闭环链路支撑，满足确认风险的最低证据要求。"
	} else if hasCrossFileDeterministicSupport(finding, refined, closure, requiresRuntimeClosure) && len(finding.Evidence) > 0 && len(finding.CalibrationBasis) > 0 && !docOnly && !internalOnly && !hasBlockingCrossFileGap {
		verdict = "confirmed"
		confidence = "中高"
		reason = "跨文件闭环研判已补充主要链路关系，当前仅剩少量运行或变换缺口，可按自动收敛规则先确认为真实风险。"
	} else if len(missing) == 0 && (strings.Contains(fp.Verdict, "倾向真实风险") || strings.Contains(fp.EvidenceStrength, "强") || finding.Confidence == "高") && !hasBlockingCrossFileGap {
		verdict = "confirmed"
		confidence = "高"
		reason = "结构化发现、复核清单和行为/校准证据形成闭环，满足确认风险的最低标准。"
	} else if len(missing) >= 3 {
		confidence = "低"
		reason = "关键证据缺失较多，必须补充证据后才能确认或排除。"
	}
	if strings.EqualFold(strings.TrimSpace(finding.Source), "BehaviorGuard") && len(finding.Evidence) > 0 && closure.HasSource && closure.HasSink && (closure.HasRuntimeSupport || (!requiresRuntimeClosure && closure.HasTransform)) && !docOnly && !internalOnly && !hasBlockingCrossFileGap {
		if verdict == "needs_manual_review" {
			verdict = "confirmed"
			confidence = "中高"
			reason = "行为证据已提供关键样本并形成链路闭环，可自动确认为真实风险，减少人工复核负担。"
		}
	}
	if verdict == "needs_manual_review" {
		missing = append(missing, "复核分流: "+manualReviewTriageLabel(finding, refined, missing))
	}

	return review.ReviewAgentVerdict{
		FindingID:        task.FindingID,
		Verdict:          verdict,
		Confidence:       confidence,
		Reason:           reason,
		MissingEvidence:  uniqueStrings(missing),
		Fix:              defaultIfEmpty(finding.ReviewGuidance, "按规则解释卡和复核清单补齐修复建议。"),
		Reviewer:         "deterministic-vuln-reviewer",
		StandardsApplied: standards,
	}
}

func shouldDowngradeContextOnlyManualFinding(finding review.StructuredFinding, closure findingClosureSummary, missing []string, hasRelevantBehavior, preserveManualForExposureSink bool) bool {
	if preserveManualForExposureSink || hasRelevantBehavior {
		return false
	}
	if len(missing) < 2 {
		return false
	}
	if closure.HasSink || closure.HasRuntimeSupport {
		return false
	}
	if len(finding.CodeEvidenceRefs) > 0 || len(finding.BehaviorEvidenceRefs) > 0 {
		return false
	}
	if len(finding.ContextEvidenceRefs) == 0 {
		return false
	}
	if containsConcreteCodeLocation(finding.Evidence) {
		return false
	}
	category := strings.TrimSpace(finding.Category)
	switch category {
	case "网络请求与SSRF", "外联与情报", "凭据访问", "凭据暴露", "声明与行为差异", "静态规则发现", "环境与构建风险":
		return true
	default:
		return false
	}
}

func hasAutoReachabilitySupport(finding review.StructuredFinding, refined review.Result, closure findingClosureSummary, hasRelevantBehavior bool) bool {
	if len(finding.Evidence) == 0 {
		return false
	}
	requiresRuntimeClosure := requiresRuntimeClosure(finding.Category)
	hasClosure := closure.HasSource && closure.HasSink && (closure.HasRuntimeSupport || (!requiresRuntimeClosure && closure.HasTransform))
	if hasClosure && (len(finding.CalibrationBasis) > 0 || hasRelevantBehavior) {
		return true
	}
	if isDirectlyConfirmedFinding(finding, refined) && !hasCrossFileBlockingGap(finding, refined) {
		return true
	}
	if hasCrossFileDeterministicSupport(finding, refined, closure, requiresRuntimeClosure) {
		return true
	}
	// 新增：如果有行为支撑且有部分闭环证据，也视为有自动可达性支撑
	if hasRelevantBehavior && (closure.HasSource || closure.HasSink || closure.HasRuntimeSupport) {
		return true
	}
	return false
}

func hasCrossFileDeterministicSupport(finding review.StructuredFinding, refined review.Result, closure findingClosureSummary, requiresRuntimeClosure bool) bool {
	consolidation := refined.CrossFileConsolidation
	if !crossFileConsolidationAppliesToFinding(finding, consolidation) || consolidation == nil {
		return false
	}
	if !closure.HasSource || !closure.HasSink {
		return false
	}
	missing := normalizedCrossFileMissingParts(consolidation.MissingParts)
	if len(missing) == 0 {
		return true
	}
	if len(missing) == 1 && missing[0] == "runtime" {
		return true
	}
	if !requiresRuntimeClosure && len(missing) == 1 && missing[0] == "transform" {
		return true
	}
	if !requiresRuntimeClosure && len(missing) == 2 && missing[0] == "runtime" && missing[1] == "transform" {
		return true
	}
	return false
}

func hasCrossFileBlockingGap(finding review.StructuredFinding, refined review.Result) bool {
	consolidation := refined.CrossFileConsolidation
	if !crossFileConsolidationAppliesToFinding(finding, consolidation) || consolidation == nil {
		return false
	}
	missing := normalizedCrossFileMissingParts(consolidation.MissingParts)
	for _, item := range missing {
		switch item {
		case "source", "sink":
			return true
		}
	}
	return false
}

func normalizedCrossFileMissingParts(items []string) []string {
	normalized := make([]string, 0, len(items))
	for _, item := range items {
		text := strings.ToLower(strings.TrimSpace(item))
		if text == "" {
			continue
		}
		normalized = append(normalized, text)
	}
	sort.Strings(normalized)
	return uniqueStrings(normalized)
}

func shouldPreferFalsePositiveForWeakStaticFinding(finding review.StructuredFinding, fp review.FalsePositiveReview, closure findingClosureSummary, missing []string, hasRelevantBehavior bool, docOnly bool, internalOnly bool) bool {
	if shouldPreferFalsePositiveForConfigWebhookSSRF(finding, fp) {
		return true
	}
	if shouldPreferFalsePositiveForLicenseLocalFallback(finding, fp) {
		return true
	}
	if shouldPreferFalsePositiveForSmokeImportDeclarationMismatch(finding, fp, closure) {
		return true
	}
	if shouldPreferFalsePositiveForDeclarationOnlyDataCollectionClaim(finding, fp, closure) {
		return true
	}
	if shouldPreferFalsePositiveForTemplateAutoescapeExposure(finding, fp, closure) {
		return true
	}
	if shouldPreferFalsePositiveForDependencyAdvisoryOnly(finding, fp, closure) {
		return true
	}
	if strings.TrimSpace(finding.Category) == "隐私合规与数据最小化" {
		joined := strings.ToLower(strings.Join(append(append(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), finding.ContextEvidenceRefs...), fp.ExclusionChecks...), " "))
		markers := reviewPolicyCategoryRefutationMarkers("隐私合规与数据最小化")
		if len(markers) == 0 {
			markers = []string{"sqlite3.connect", "select * from", "仅本地 sqlite", "仅本地数据库读取", "当前缺少外发或暴露链路", "仅本地读取"}
		}
		if containsAny(joined, markers) && !closure.HasSink && !closure.HasRuntimeSupport {
			return true
		}
	}
	if docOnly || internalOnly || hasRelevantBehavior || hasThreatLikeFindingSignals(finding) {
		return false
	}
	missing = uniqueStrings(missing)
	missingCount := len(missing)
	title := strings.TrimSpace(finding.Title)
	category := strings.TrimSpace(finding.Category)
	hasMeaningfulClosure := closure.HasSource || closure.HasTransform || closure.HasSink || closure.HasRuntimeSupport
	fullyOpenClosure := !closure.HasSource && !closure.HasTransform && !closure.HasSink && !closure.HasRuntimeSupport

	if threshold, ok := weakStaticThreshold(category); ok && missingCount >= threshold.MissingThreshold {
		if (!threshold.RequireOpenClosure || fullyOpenClosure) && (!threshold.RequireNoMeaningfulClosure || !hasMeaningfulClosure) {
			return true
		}
	}
	if shouldPreferFalsePositiveForEvidenceIntentMismatch(finding, fp, closure) {
		return true
	}
	if shouldPreferFalsePositiveForRefutedPrimaryClaim(finding, fp, closure, missingCount) {
		return true
	}
	if shouldPreferFalsePositiveForOpenWeakFinding(finding, closure, missingCount) {
		return true
	}

	if containsAny(title, reviewPolicyWeakStaticTitles()) {
		return missingCount >= 3 && !closure.HasSink && !closure.HasRuntimeSupport
	}

	return false
}

func shouldPreferFalsePositiveForConfigWebhookSSRF(finding review.StructuredFinding, fp review.FalsePositiveReview) bool {
	if strings.TrimSpace(finding.Category) != "网络请求与SSRF" {
		return false
	}
	joined := strings.ToLower(strings.Join(append(append(finding.Evidence, finding.ContextEvidenceRefs...), fp.ExclusionChecks...), " "))
	if !containsAny(joined, []string{"discord_webhook", "webhook", "config.get", "来源类型=config_value", "config_value"}) {
		return false
	}
	if containsAny(joined, []string{"target_url", "来源类型=user_input", "用户输入", "危险目标=", "169.254.169.254", "metadata", "内网"}) {
		return false
	}
	return true
}

func shouldPreferFalsePositiveForLicenseLocalFallback(finding review.StructuredFinding, fp review.FalsePositiveReview) bool {
	if strings.TrimSpace(finding.Category) != "授权与许可证校验" {
		return false
	}
	joined := strings.ToLower(strings.Join(append(append(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), finding.ContextEvidenceRefs...), fp.ExclusionChecks...), " "))
	if !containsAny(joined, []string{"license_server", "/api/validate", "localhost:8080", "本地默认许可证服务"}) {
		return false
	}
	if containsAny(joined, []string{"verify_failed", "fail open", "fail-open", "continue on failure", "校验失败后继续", "失败分支放行"}) {
		return false
	}
	return containsAny(joined, []string{"return false", "空 key", "if not pro_license_key", "开发态 fallback", "localhost"})
}

func shouldPreferFalsePositiveForSmokeImportDeclarationMismatch(finding review.StructuredFinding, fp review.FalsePositiveReview, closure findingClosureSummary) bool {
	if strings.TrimSpace(finding.Category) != "声明与行为差异" {
		return false
	}
	if closure.HasSource || closure.HasTransform || closure.HasSink || closure.HasRuntimeSupport {
		return false
	}
	joined := strings.ToLower(strings.Join(append(append(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), finding.ContextEvidenceRefs...), fp.ExclusionChecks...), " "))
	if !containsAny(joined, []string{"test_smoke.py", "import scripts.", "import scripts.polymarket as sniper"}) {
		return false
	}
	return !containsAny(joined, []string{"create_order", "signed_order", "wallet_private_key", "requests.post", "subprocess", "os.system"})
}

func shouldPreferFalsePositiveForDeclarationOnlyDataCollectionClaim(finding review.StructuredFinding, fp review.FalsePositiveReview, closure findingClosureSummary) bool {
	if strings.TrimSpace(finding.Category) != "声明与行为差异" {
		return false
	}
	if closure.HasSource || closure.HasTransform || closure.HasSink || closure.HasRuntimeSupport {
		return false
	}
	joined := strings.ToLower(strings.Join(append(append(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), finding.ContextEvidenceRefs...), fp.ExclusionChecks...), " "))
	if !containsAny(joined, []string{"技能声明与数据收集行为对照", "声明收集数据", "skill.md", "manifest"}) {
		return false
	}
	return containsAny(joined, []string{"文档或示例证据不进入主证据集", "插件命中位于文档、示例或内部开发语境", "声明外收集: 未声明或未识别", "位置: 技能声明与数据收集行为对照"})
}

func shouldPreferFalsePositiveForTemplateAutoescapeExposure(finding review.StructuredFinding, fp review.FalsePositiveReview, closure findingClosureSummary) bool {
	if strings.TrimSpace(finding.Category) != "暴露面与未鉴权服务" {
		return false
	}
	if closure.HasSink || closure.HasRuntimeSupport {
		return false
	}
	joined := strings.ToLower(strings.Join(append(append(append([]string{finding.AttackPath}, finding.Evidence...), finding.ContextEvidenceRefs...), fp.ExclusionChecks...), " "))
	if !containsAny(joined, []string{"jinja", "template", "{{", "autoescape", "纯 html 模板", "纯html模板", "没有代码实现", "无网络暴露"}) {
		return false
	}
	return !containsAny(joined, []string{"app.run", "0.0.0.0", "listen", "public network", "公网", "监听"})
}

func shouldPreferFalsePositiveForDependencyAdvisoryOnly(finding review.StructuredFinding, fp review.FalsePositiveReview, closure findingClosureSummary) bool {
	if strings.TrimSpace(finding.Title) != "依赖漏洞与恶意依赖-高危漏洞依赖" {
		return false
	}
	if closure.HasSource || closure.HasTransform || closure.HasSink || closure.HasRuntimeSupport {
		return false
	}
	joined := strings.ToLower(strings.Join(append(append(append([]string{finding.AttackPath}, finding.Evidence...), finding.ContextEvidenceRefs...), fp.ExclusionChecks...), " "))
	if containsAny(joined, []string{"dependency=", "ghsa-", "cve-", "osv 证据", "version="}) {
		return false
	}
	return containsAny(joined, []string{"建议补充依赖清单并锁定版本", "补充依赖清单", "锁定版本", "缺少sbom", "缺少 sbom", "缺少版本信息", "无法完成漏洞精确比对"})
}

func shouldPreferFalsePositiveForEvidenceIntentMismatch(finding review.StructuredFinding, fp review.FalsePositiveReview, closure findingClosureSummary) bool {
	if closure.HasSink || closure.HasRuntimeSupport {
		return false
	}
	if hasThreatLikeFindingSignals(finding) {
		return false
	}
	category := strings.TrimSpace(finding.Category)
	if !isEvidenceIntentMismatchCategory(category) {
		return false
	}
	joined := strings.ToLower(strings.Join(append(append(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), finding.ContextEvidenceRefs...), fp.ExclusionChecks...), " "))
	markers := reviewPolicyEvidenceIntentMismatchMarkers()
	return containsAny(joined, markers)
}

func shouldPreferFalsePositiveForRefutedPrimaryClaim(finding review.StructuredFinding, fp review.FalsePositiveReview, closure findingClosureSummary, missingCount int) bool {
	if missingCount < 2 {
		return false
	}
	joined := strings.ToLower(strings.Join(append(append(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), finding.ContextEvidenceRefs...), fp.ExclusionChecks...), " "))
	category := strings.TrimSpace(finding.Category)
	title := strings.TrimSpace(finding.Title)

	if category == "暴露面与未鉴权服务" {
		markers := reviewPolicyCategoryRefutationMarkers(category)
		if len(markers) == 0 {
			markers = []string{"不构成可利用的安全漏洞", "完整性或合规问题", "分类与证据不符", "功能缺失属于完整性或合规问题"}
		}
		if containsAny(joined, markers) && !closure.HasRuntimeSupport {
			return true
		}
	}

	if title == "资源耗尽与级联失败-无限循环/无超时" {
		markers := reviewPolicyRefutedPrimaryClaimMarkers(title)
		if len(markers) == 0 {
			markers = []string{"未发现递归调用", "与代码事实不符", "不成立", "无递归"}
		}
		if containsAny(joined, markers) && !closure.HasRuntimeSupport {
			return true
		}
	}

	if title == "日志审计与敏感信息脱敏-关键事件无审计" {
		markers := reviewPolicyRefutedPrimaryClaimMarkers(title)
		if len(markers) == 0 {
			markers = []string{"已有审计日志", "已有 logger", "已有 logger/audit", "存在审计记录", "已有结果记录"}
		}
		if containsAny(joined, markers) && !closure.HasRuntimeSupport {
			return true
		}
	}

	if category == "隐私合规与数据最小化" {
		markers := reviewPolicyCategoryRefutationMarkers(category)
		if len(markers) == 0 {
			markers = []string{"sqlite3.connect", "select * from", "普通文件读取", "仅本地 sqlite", "仅本地数据库读取", "当前缺少外发或暴露链路", "仅本地读取"}
		}
		if containsAny(joined, markers) && !closure.HasSink && !closure.HasRuntimeSupport {
			return true
		}
	}

	return false
}

func shouldPreferFalsePositiveForOpenWeakFinding(finding review.StructuredFinding, closure findingClosureSummary, missingCount int) bool {
	if missingCount < 4 {
		return false
	}
	if closure.HasSource || closure.HasTransform || closure.HasSink || closure.HasRuntimeSupport {
		return false
	}
	if len(finding.CodeEvidenceRefs) > 0 {
		return false
	}
	if containsConcreteCodeLocation(finding.Evidence) || containsConcreteCodeLocation(finding.ContextEvidenceRefs) {
		return false
	}
	title := strings.TrimSpace(finding.Title)
	category := strings.TrimSpace(finding.Category)
	if !isOpenWeakCategory(category) {
		return false
	}
	if containsAny(title, reviewPolicyOpenWeakTitles()) {
		return true
	}
	return false
}

func containsConcreteCodeLocation(items []string) bool {
	for _, item := range items {
		text := strings.TrimSpace(item)
		if text == "" {
			continue
		}
		if strings.Contains(text, ":") && (strings.Contains(text, ".py:") || strings.Contains(text, ".go:") || strings.Contains(text, ".js:") || strings.Contains(text, ".ts:") || strings.Contains(text, ".tsx:") || strings.Contains(text, ".jsx:") || strings.Contains(text, ".sh:")) {
			return true
		}
	}
	return false
}

func shouldPreserveManualReviewForExposureSink(finding review.StructuredFinding, closure findingClosureSummary) bool {
	if strings.TrimSpace(finding.Category) != "暴露面与未鉴权服务" {
		return false
	}
	if !closure.HasSink {
		return false
	}
	joined := strings.ToLower(strings.Join(append(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), finding.CodeEvidenceRefs...), " "))
	return containsAny(joined, []string{"0.0.0.0", "app.run", "listen", "port=", "公网", "public network", "监听"})
}

func manualReviewTriageLabel(finding review.StructuredFinding, refined review.Result, missing []string) string {
	closure := buildFindingClosureSummary(finding, refined)
	missing = uniqueStrings(missing)
	missingJoined := strings.Join(missing, " ")
	switch {
	case len(finding.CodeEvidenceRefs) == 0 && len(finding.BehaviorEvidenceRefs) == 0 && len(finding.ContextEvidenceRefs) > 0:
		return "可机审降级-仅上下文证据"
	case isLikelyDocumentationOnlyFinding(finding):
		return "可机审降级-文档示例证据"
	case isLikelyInternalDevelopmentFinding(finding):
		return "可机审降级-开发态证据"
	case closure.HasSource && closure.HasSink && (closure.HasRuntimeSupport || !requiresRuntimeClosure(finding.Category)) && len(finding.Evidence) > 0:
		return "可机审确认-闭环基本完整"
	case !closure.HasSource && !closure.HasSink && !closure.HasRuntimeSupport:
		return "需补证-source/sink/runtime全缺"
	case strings.Contains(missingJoined, "运行链路") || strings.Contains(missingJoined, "行为支撑"):
		return "需补证-runtime"
	case strings.Contains(missingJoined, "source") || strings.Contains(missingJoined, "入口"):
		return "需补证-source"
	case strings.Contains(missingJoined, "sink") || strings.Contains(missingJoined, "落点"):
		return "需补证-sink"
	default:
		return "需补证-可达性或影响"
	}
}

func removeMissingEvidence(items []string, target string) []string {
	target = strings.TrimSpace(target)
	if target == "" {
		return items
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if strings.TrimSpace(item) == target {
			continue
		}
		out = append(out, item)
	}
	return out
}

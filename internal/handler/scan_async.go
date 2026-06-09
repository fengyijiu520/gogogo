package handler

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	admissionmodel "skill-scanner/internal/admission/model"
	"skill-scanner/internal/analyzer"
	"skill-scanner/internal/config"
	"skill-scanner/internal/docx"
	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/ir"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/logx"
	"skill-scanner/internal/models"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
	"skill-scanner/internal/review/evidence"
	"skill-scanner/internal/review/inventory"
	"skill-scanner/internal/review/orchestrator"
	reviewreport "skill-scanner/internal/review/report"
	"skill-scanner/internal/storage"
)

type customRuleInput struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Severity string   `json:"severity"`
	Layer    string   `json:"layer"`
	Patterns []string `json:"patterns"`
	Reason   string   `json:"reason"`
}

type differentialOptions struct {
	Enabled            bool
	DelayThresholdSecs int
}

type baseScanOutput struct {
	findings         []plugins.Finding
	evalLogs         []ruleEvaluationLog
	trace            []analysisTraceEvent
	taskID           string
	requestID        string
	score            float64
	totalRules       int
	evaluatedRules   int
	uncheckedRules   []string
	coverageNote     string
	ruleCoverage     ruleCoverageSummary
	intentSummary    intentReportSummary
	profile          skillAnalysisProfile
	ruleProfile      ruleSetProfile
	ruleExplanations []review.RuleExplanation
	llmClient        llm.Client
	sourceRoot       string
	sourceFiles      []evaluator.SourceFile
	cacheStats       incrementalCacheStats
	detectionErrors  []evaluator.DetectionError
}

type incrementalCacheStats struct {
	Enabled        bool
	Candidate      int
	Hit            int
	Miss           int
	Missing        int
	Stale          int
	ReadErrors     int
	ContentReused  int
	DerivedReused  int
	CacheEntries   int
	CacheFilePath  string
	CacheVersion   string
	DisabledReason string
	LoadWarning    string
	SaveWarning    string
}

type scanFileFingerprint struct {
	RelPath  string `json:"rel_path"`
	Language string `json:"language"`
	SHA256   string `json:"sha256"`
	Size     int64  `json:"size"`
	ModUnix  int64  `json:"mod_unix"`
}

type cachedSourceArtifact struct {
	Fingerprint scanFileFingerprint  `json:"fingerprint"`
	Source      evaluator.SourceFile `json:"source"`
}

type sourceArtifactCache struct {
	Version string                          `json:"version"`
	Order   []string                        `json:"order,omitempty"`
	Files   map[string]cachedSourceArtifact `json:"files"`
}

type sourceArtifactCacheLoadStatus struct {
	Found           bool
	InvalidJSON     bool
	VersionMismatch bool
	Version         string
	EntryCount      int
}

const sourceArtifactCacheVersion = "dev"

type skillAnalysisProfile = inventory.Profile

type analysisTraceEvent struct {
	Stage   string `json:"stage"`
	Status  string `json:"status"`
	Message string `json:"message"`
	Detail  string `json:"detail,omitempty"`
}

type uploadedScanRequest struct {
	files           []*multipart.FileHeader
	originalName    string
	folderName      string // 上传的文件夹名（用于技能名回退）
	skillName       string // 用户手动指定的技能名
	taskID          string
	taskDir         string
	requestID       string
	description     string
	permissions     []string
	selectedRuleIDs []string
	customRules     []customRuleInput
	diffOptions     differentialOptions
	userNotes       string // 用户补充说明
}

type riskCalibrationSummary struct {
	Policy             string   `json:"policy"`
	RiskLevel          string   `json:"risk_level"`
	Decision           string   `json:"decision"`
	UserActionRequired bool     `json:"user_action_required"`
	Basis              []string `json:"basis"`
	ConfidenceNotes    []string `json:"confidence_notes"`
}

const reportGeneratorNote = "Skill Scanner 结构化审查流水线"

type ruleSetProfile struct {
	Version         string   `json:"version"`
	Total           int      `json:"total"`
	ByLayer         []string `json:"by_layer"`
	BySeverity      []string `json:"by_severity"`
	ByDetectionType []string `json:"by_detection_type"`
	BlockedRules    []string `json:"blocked_rules"`
	ReviewRules     []string `json:"review_rules"`
	Reason          string   `json:"reason"`
	Benefit         string   `json:"benefit"`
}

type intentReportSummary struct {
	Available              bool                        `json:"available"`
	DeclaredIntent         string                      `json:"declared_intent"`
	ActualBehavior         string                      `json:"actual_behavior"`
	DeclaredCapabilities   []string                    `json:"declared_capabilities,omitempty"`
	ActualCapabilities     []string                    `json:"actual_capabilities,omitempty"`
	ConsistencyEvidence    []string                    `json:"consistency_evidence,omitempty"`
	CrossFileConsolidation *llm.CrossFileConsolidation `json:"cross_file_consolidation,omitempty"`
	IntentRiskLevel        string                      `json:"intent_risk_level"`
	IntentMismatch         string                      `json:"intent_mismatch,omitempty"`
	UnavailableReason      string                      `json:"unavailable_reason,omitempty"`
}

type ruleCoverageSummary struct {
	Version          string
	AutoTotal        int
	AutoCovered      int
	AutoUncovered    []string
	ManualTotal      int
	ManualCandidates []string
	Note             string
}

type ruleEvaluationLog struct {
	RuleID            string   `json:"rule_id"`
	RuleName          string   `json:"rule_name"`
	Layer             string   `json:"layer"`
	DetectionType     string   `json:"detection_type"`
	DetectionProcess  string   `json:"detection_process"`
	DetectionResult   string   `json:"detection_result"`
	RiskLabel         string   `json:"risk_label"`
	Evaluated         bool     `json:"evaluated"`
	EvidenceLocations []string `json:"evidence_locations,omitempty"`
}

func handleScanAsync(store *storage.Store, w http.ResponseWriter, r *http.Request, sess *Session) bool {
	for _, item := range store.AnalyzerFalsePositiveFeedback() {
		analyzer.LearnFalsePositives(item.RuleID, item.Tokens)
	}
	taskStore.pruneExpired(scanTaskTTL)
	if ok, reason := taskStore.canCreate(sess.Username); !ok {
		sendJSON(w, http.StatusTooManyRequests, map[string]string{"error": reason})
		return true
	}

	validation := validateScanPreflight(store, sess.Username)
	if validation.Err != nil {
		errorText, suggestion, action := BuildScanPreflightErrorResponse(store, sess.Username, validation.Assessment, validation.Err)
		sendJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
			"error":      errorText,
			"details":    validation.Err.Error(),
			"suggestion": suggestion,
			"action":     action,
		})
		return true
	}

	req, handled := prepareUploadedScanRequest(store, w, r)
	if handled {
		return true
	}
	taskStore.create(req.taskID, sess.Username, req.originalName, req.requestID)
	ctx, cancel := context.WithCancel(context.WithValue(context.Background(), logx.RequestIDContextKey, strings.TrimSpace(req.requestID)))
	taskStore.setCancel(req.taskID, cancel)

	go runScanTask(ctx, store, req.taskID, req.taskDir, sess.Username, req.originalName, req.folderName, req.skillName, req.requestID, req.description, req.permissions, req.selectedRuleIDs, req.customRules, req.diffOptions, req.userNotes)

	sendJSON(w, http.StatusOK, map[string]interface{}{
		"success":    true,
		"task_id":    req.taskID,
		"request_id": strings.TrimSpace(req.requestID),
		"status":     review.PhaseQueued,
		"file_name":  req.originalName,
	})
	return true
}

func prepareUploadedScanRequest(store *storage.Store, w http.ResponseWriter, r *http.Request) (uploadedScanRequest, bool) {
	files, handled := parseUploadedScanFiles(w, r)
	if handled {
		return uploadedScanRequest{}, true
	}
	taskID, taskDir, handled := createScanTaskDir(store, w)
	if handled {
		return uploadedScanRequest{}, true
	}
	if handled = writeUploadedScanFiles(taskDir, files, w); handled {
		return uploadedScanRequest{}, true
	}
	if err := validateExtractedFiles(taskDir); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return uploadedScanRequest{}, true
	}
	requestID, _ := r.Context().Value(logx.RequestIDContextKey).(string)
	displayName, folderName := buildUploadedOriginalNameAndFolder(files)
	return uploadedScanRequest{
		files:           files,
		originalName:    displayName,
		folderName:      folderName,
		skillName:       strings.TrimSpace(r.FormValue("skill_name")),
		taskID:          taskID,
		taskDir:         taskDir,
		requestID:       requestID,
		description:     r.FormValue("description"),
		userNotes:       sanitizeUserNotes(r.FormValue("user_notes")),
		permissions:     parsePermissions(r.FormValue("permissions")),
		selectedRuleIDs: parseSelectedRuleIDs(r.FormValue("selected_rule_ids")),
		customRules:     parseCustomRules(r.FormValue("custom_rules")),
		diffOptions: differentialOptions{
			Enabled:            parseBoolWithDefault(r.FormValue("differential_enabled"), readDifferentialEnabled()),
			DelayThresholdSecs: parsePositiveIntWithDefault(r.FormValue("evasion_delay_threshold_secs"), readDelayThresholdSec()),
		},
	}, false
}

func parseUploadedScanFiles(w http.ResponseWriter, r *http.Request) ([]*multipart.FileHeader, bool) {
	limitMultipartBody(w, r)
	if err := r.ParseMultipartForm(100 << 20); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "文件太大或解析失败"})
		return nil, true
	}
	files := r.MultipartForm.File["files"]
	if len(files) == 0 {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "请上传至少一个文件"})
		return nil, true
	}
	if err := validateUploadedFiles(files); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return nil, true
	}
	return files, false
}

func buildUploadedOriginalName(files []*multipart.FileHeader) string {
	name, _ := buildUploadedOriginalNameAndFolder(files)
	return name
}

// buildUploadedOriginalNameAndFolder 返回显示名和原始文件夹名
func buildUploadedOriginalNameAndFolder(files []*multipart.FileHeader) (displayName, folderName string) {
	if len(files) == 0 {
		return "未知技能", ""
	}
	// 调试：记录所有文件名
	for i, fh := range files {
		logx.With("component", "upload").Debug("uploaded file",
			"index", i,
			"filename", fh.Filename,
			"size", fh.Size,
		)
	}
	// 文件夹上传时，浏览器会传带路径的文件名如 "skill-shell/cleanup.sh"
	// 提取顶层目录名作为技能名
	firstFile := filepath.ToSlash(files[0].Filename)
	parts := strings.SplitN(firstFile, "/", 2)
	if len(parts) > 1 {
		// 有子路径 → 取顶层目录名
		folder := strings.TrimSpace(parts[0])
		if folder != "" && folder != "." {
			if len(files) > 1 {
				return fmt.Sprintf("%s 等 %d 个文件", folder, len(files)), folder
			}
			return folder, folder
		}
	}
	// 单文件或无路径 → 用文件名
	name := files[0].Filename
	if len(files) > 1 {
		return fmt.Sprintf("%s 等 %d 个文件", name, len(files)), ""
	}
	return name, ""
}

func createScanTaskDir(store *storage.Store, w http.ResponseWriter) (string, string, bool) {
	taskID, err := storage.GenerateID()
	if err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "生成任务ID失败"})
		return "", "", true
	}
	taskDir := filepath.Join(store.DataDir(), "tasks", taskID)
	if err := os.MkdirAll(taskDir, 0755); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "创建任务目录失败"})
		return "", "", true
	}
	return taskID, taskDir, false
}

func writeUploadedScanFiles(taskDir string, files []*multipart.FileHeader, w http.ResponseWriter) bool {
	for _, fh := range files {
		if fh.Size == 0 {
			continue
		}
		relPath := filepath.Clean(fh.Filename)
		logx.With("component", "upload").Debug("writing file",
			"filename", fh.Filename,
			"relPath", relPath,
			"destPath", filepath.Join(taskDir, relPath),
		)
		destPath := filepath.Join(taskDir, relPath)
		if !storage.IsPathSafe(taskDir, relPath) {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "文件路径不安全"})
			return true
		}
		if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "创建目录失败"})
			return true
		}
		src, openErr := fh.Open()
		if openErr != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "读取文件失败"})
			return true
		}
		dst, createErr := os.Create(destPath)
		if createErr != nil {
			src.Close()
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "保存文件失败"})
			return true
		}
		_, copyErr := io.Copy(dst, src)
		src.Close()
		dst.Close()
		if copyErr != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "写入文件失败"})
			return true
		}
	}
	return false
}

func runScanTask(ctx context.Context, store *storage.Store, taskID, scanPath, username, originalName, folderName, userSkillName, requestID, description string, permissions []string, selectedRuleIDs []string, customRules []customRuleInput, diffOptions differentialOptions, userNotes string) {
	defer os.RemoveAll(scanPath)
	defer taskStore.setCancel(taskID, nil)
	if err := ctx.Err(); err != nil {
		taskStore.release(taskID, review.PhaseFailed, "任务已取消")
		return
	}
	description = resolveSkillDescription(description, scanPath)
	// 提取技能名：用户手动输入 > SKILL.md name 字段 > 文件夹名
	skillName := userSkillName
	if skillName == "" {
		skillName = extractSkillName(description, scanPath, folderName)
	}
	logx.With("component", "scan").Debug("skill name extracted",
		"skill_name", skillName,
		"user_skill_name", userSkillName,
		"folder_name", folderName,
		"original_name", originalName,
	)
	if skillName != "" {
		displayName := skillName + "，共存在 " + originalName
		taskStore.update(taskID, func(t *scanTask) {
			t.FileName = displayName
		})
	}
	trace := []analysisTraceEvent{
		newAnalysisTraceEvent("queued", "completed", "扫描任务已入队并完成技能声明解析", originalName),
	}

	updateScanTaskPhase(taskID, review.PhaseP0, "执行规则基线检测（含高/中/低风险规则，准备中）", "p0")

	base, err := performBaseScan(taskID, store, username, scanPath, originalName, description, permissions, selectedRuleIDs, customRules)
	if err != nil {
		taskStore.release(taskID, review.PhaseFailed, err.Error())
		return
	}
	if err := ctx.Err(); err != nil {
		taskStore.release(taskID, review.PhaseFailed, "任务已取消")
		return
	}
	base.trace = append(trace, base.trace...)

	updateScanTaskPhase(taskID, review.PhaseP1, "执行行为与差分复核", "p1")

	// 提取用户 LLM 配置，传给 zeroclaw Agent
	llmProvider, llmProtocol, llmBaseURL, llmModel, llmAPIKey := extractUserLLMConfig(store, username)
	logx.With("component", "scan").Info("extracted LLM config for Agent",
		"username", username,
		"provider", llmProvider,
		"protocol", llmProtocol,
		"base_url", llmBaseURL,
		"model", llmModel,
		"api_key_len", len(llmAPIKey),
	)

	orc := orchestrator.New()
	refined, reviewErr := orc.Run(orchestrator.Input{
		Context:             ctx,
		RequestID:           strings.TrimSpace(requestID),
		Description:         description,
		Permissions:         permissions,
		ScanPath:            scanPath,
		BaseScore:           base.score,
		BaseFindings:        base.findings,
		DifferentialEnabled: diffOptions.Enabled,
		DelayThresholdSecs:  diffOptions.DelayThresholdSecs,
		LLMProvider:         llmProvider,
		LLMProtocol:         llmProtocol,
		LLMBaseURL:          llmBaseURL,
		LLMModel:            llmModel,
		LLMAPIKey:           llmAPIKey,
		UserNotes:           userNotes,
	})
	if reviewErr != nil {
		if ctx.Err() != nil {
			taskStore.release(taskID, review.PhaseFailed, "任务已取消")
			return
		}
		taskStore.release(taskID, review.PhaseFailed, reviewErr.Error())
		return
	}
	refined.ObfuscationEvidence = buildObfuscationEvidence(base.sourceFiles)
	base.trace = append(base.trace, newAnalysisTraceEvent("behavior_review", "completed", "沙箱行为、差分执行和威胁情报复核完成", fmt.Sprintf("行为证据类别: %d", countBehaviorEvidenceCategories(refined.Behavior))))

	updateScanTaskPhase(taskID, review.PhaseP2, "执行结构化整理与 LLM 复核：整理补充风险与结构化结果", "p2")

	if err := ctx.Err(); err != nil {
		taskStore.release(taskID, review.PhaseFailed, "任务已取消")
		return
	}
	refined, findings, llmReviewErr := completeStructuredReviewFlowWithContext(ctx, store, taskID, base, refined)
	if llmReviewErr != nil {
		base.trace = append(base.trace, newAnalysisTraceEvent("llm_review", "warning", "LLM 二次复核未完整完成，已回退为规则复核结果继续生成报告", llmReviewErr.Error()))
	}
	highRisk, mediumRisk, lowRisk := displayRiskCounts(refined)
	base.trace = append(base.trace, newAnalysisTraceEvent("risk_calibration", "completed", "风险等级已按证据重新校准，结论保留为用户决策", fmt.Sprintf("高:%d 中:%d 低:%d", highRisk, mediumRisk, lowRisk)))

	updateScanTaskPhase(taskID, review.PhaseScoring, "汇总风险等级并生成报告", "scoring")
	if err := ctx.Err(); err != nil {
		taskStore.release(taskID, review.PhaseFailed, "任务已取消")
		return
	}

	reportID, pdfTrace, reportErr := persistReports(store, taskID, username, originalName, folderName, userSkillName, description, findings, base, refined)
	if reportErr != nil {
		failScanTaskWithPDFTrace(taskID, reportErr, pdfTrace)
		return
	}

	completeScanTaskWithReport(taskID, reportID, len(findings), base, refined, pdfTrace)
}

func buildSupplementedFindings(base baseScanOutput, refined review.Result) []plugins.Finding {
	findings := append([]plugins.Finding{}, refined.Findings...)
	findings = append(findings, synthesizeIntentFindings(refined.IntentDiffs)...)
	findings = append(findings, synthesizeTIFindings(refined.TIReputations)...)
	findings = append(findings, synthesizeEvasionFindings(refined.Evasion)...)
	findings = append(findings, synthesizeBehaviorFindings(refined.Behavior)...)
	findings = append(findings, synthesizeRuleCoverageFindings(base.ruleCoverage)...)
	return localizeFindings(findings)
}

func enrichRefinedResult(base baseScanOutput, refined review.Result, findings []plugins.Finding) review.Result {
	refined.CrossFileConsolidation = base.intentSummary.CrossFileConsolidation
	refined.StructuredFindings = buildStructuredFindings(findings, refined, base.intentSummary.CrossFileConsolidation, base.sourceRoot, base.sourceFiles)
	refined.VulnerabilityBlocks = buildVulnerabilityBlocks(refined.StructuredFindings)
	refined.RuleExplanations = markTriggeredRuleExplanations(base.ruleExplanations, findings)
	refined.FalsePositiveReviews = buildFalsePositiveReviews(refined.StructuredFindings, refined)
	refined.DetectionComparison = buildDetectionChainComparison(base, refined)
	refined.OptimizationNotes = append(refined.OptimizationNotes, buildDetectionComparisonOptimizationNotes(refined.DetectionComparison)...)
	refined.ReviewAgentTasks = buildReviewAgentTasks(refined)
	return refined
}

func runReviewAgents(taskID string, base baseScanOutput, refined review.Result) (review.Result, error) {
	return runReviewAgentsWithContext(context.Background(), taskID, base, refined)
}

func runReviewAgentsWithContext(ctx context.Context, taskID string, base baseScanOutput, refined review.Result) (review.Result, error) {
	taskByFindingID := make(map[string]review.ReviewAgentTask, len(refined.ReviewAgentTasks))
	for _, task := range refined.ReviewAgentTasks {
		taskByFindingID[task.FindingID] = task
	}
	deterministicVerdicts, deterministicStats := executeDeterministicReviewAgentWithStats(refined)
	refined.ReviewAgentVerdicts = deterministicVerdicts
	if deterministicStats.TaskCount > 0 {
		refined.ReviewAgentStats = append(refined.ReviewAgentStats, deterministicStats)
		if strings.TrimSpace(taskID) != "" {
			taskStore.update(taskID, func(t *scanTask) {
				t.Message = fmt.Sprintf("执行结构化整理与 LLM 复核：规则复核完成 %d/%d，准备执行 LLM 二次复核", deterministicStats.TaskCount, deterministicStats.TaskCount)
				t.CurrentRule = "deterministic-review"
				t.ReviewTrace = buildInitialReviewTrace(refined.ReviewAgentTasks)
			})
		}
	}
	if len(refined.ReviewAgentTasks) == 0 {
		if strings.TrimSpace(taskID) != "" {
			taskStore.update(taskID, func(t *scanTask) {
				t.Message = "执行结构化整理与 LLM 复核：无待复核风险，准备汇总结果"
				t.CurrentRule = "no-review-task"
			})
		}
		return refined, nil
	}
	if strings.TrimSpace(taskID) != "" {
		taskStore.update(taskID, func(t *scanTask) {
			t.Message = fmt.Sprintf("执行结构化整理与 LLM 复核：开始 LLM 二次复核（共 %d 项）", len(refined.ReviewAgentTasks))
			t.CurrentRule = "llm-review-pending"
			t.ReviewTrace = buildInitialReviewTrace(refined.ReviewAgentTasks)
		})
	}
	llmVerdicts, llmStats, err := executeLLMReviewAgentWithStats(ctx, base.llmClient, refined, func(event reviewProgressEvent) {
		if strings.TrimSpace(taskID) == "" {
			return
		}
		taskStore.update(taskID, func(t *scanTask) {
			switch event.Stage {
			case reviewProgressStarted:
				t.Message = fmt.Sprintf("执行结构化整理与 LLM 复核：LLM 二次复核启动 %d/%d", event.Done, event.Total)
			case reviewProgressCompleted:
				t.Message = fmt.Sprintf("执行结构化整理与 LLM 复核：LLM 二次复核进行中 %d/%d", event.Done, event.Total)
			case reviewProgressFailed:
				t.Message = fmt.Sprintf("执行结构化整理与 LLM 复核：LLM 二次复核失败 %d/%d", event.Done, event.Total)
			default:
				t.Message = fmt.Sprintf("执行结构化整理与 LLM 复核：LLM 二次复核处理中 %d/%d", event.Done, event.Total)
			}
			t.CurrentRule = strings.TrimSpace(event.Task.FindingID)
			if t.ReviewTrace == nil {
				t.ReviewTrace = buildInitialReviewTrace(refined.ReviewAgentTasks)
			}
			applyReviewProgressEvent(t.ReviewTrace, event)
		})
	})
	if llmStats.TaskCount > 0 {
		refined.ReviewAgentStats = append(refined.ReviewAgentStats, llmStats)
	}
	if err != nil {
		if strings.TrimSpace(taskID) != "" {
			taskStore.update(taskID, func(t *scanTask) {
				if t.ReviewTrace == nil {
					t.ReviewTrace = buildInitialReviewTrace(refined.ReviewAgentTasks)
				}
				t.ReviewTrace.Failed = true
				if strings.TrimSpace(t.ReviewTrace.ErrorMessage) == "" {
					t.ReviewTrace.ErrorMessage = reviewTraceErrorSummary(t.ReviewTrace)
				}
				if strings.TrimSpace(t.ReviewTrace.ErrorMessage) == "" {
					t.ReviewTrace.ErrorMessage = err.Error()
				}
			})
		}
		return refined, err
	}
	refined.ReviewAgentVerdicts = mergeReviewAgentVerdicts(refined.ReviewAgentVerdicts, llmVerdicts)
	if strings.TrimSpace(taskID) != "" {
		taskStore.update(taskID, func(t *scanTask) {
			if t.ReviewTrace == nil {
				t.ReviewTrace = buildInitialReviewTrace(refined.ReviewAgentTasks)
			}
			for _, verdict := range llmVerdicts {
				if task, ok := taskByFindingID[verdict.FindingID]; ok {
					applyReviewProgressEvent(t.ReviewTrace, reviewProgressEvent{Stage: reviewProgressCompleted, Done: t.ReviewTrace.Completed, Total: len(refined.ReviewAgentTasks), Task: task, Verdict: verdict})
				}
			}
		})
	}
	if strings.TrimSpace(taskID) != "" {
		if task := taskStore.get(taskID); task != nil {
			refined.ReviewTrace = cloneScanTaskReviewTrace(task.ReviewTrace)
		}
	}
	return refined, nil
}

func buildInitialReviewTrace(tasks []review.ReviewAgentTask) *review.ReviewTrace {
	trace := &review.ReviewTrace{Total: len(tasks)}
	for _, task := range tasks {
		trace.Entries = append(trace.Entries, review.ReviewTraceEntry{
			FindingID:        strings.TrimSpace(task.FindingID),
			FindingTitle:     reviewTraceFindingTitle(task),
			Objective:        strings.TrimSpace(task.Objective),
			PromptSummary:    reviewTracePromptSummary(task),
			InputDigest:      reviewTraceInputDigest(task),
			StandardsApplied: append([]string{}, task.StrictStandards...),
			Status:           "pending",
		})
	}
	return trace
}

func applyReviewProgressEvent(trace *review.ReviewTrace, event reviewProgressEvent) {
	if trace == nil {
		return
	}
	trace.Total = event.Total
	trace.Completed = event.Done
	trace.CurrentFindingID = strings.TrimSpace(event.Task.FindingID)
	trace.CurrentFindingTitle = reviewTraceFindingTitle(event.Task)
	trace.CurrentObjective = strings.TrimSpace(event.Task.Objective)
	trace.CurrentSummary = reviewTraceContextSummary(event.Task)
	if event.DurationMs > 0 {
		trace.LastDurationMs = event.DurationMs
	}
	if event.Err != nil {
		trace.Failed = true
	}
	if strings.TrimSpace(event.Verdict.Verdict) != "" {
		trace.LastVerdict = strings.TrimSpace(event.Verdict.Verdict)
		trace.LastReason = strings.TrimSpace(event.Verdict.Reason)
	}
	for i := range trace.Entries {
		entry := &trace.Entries[i]
		if entry.FindingID != strings.TrimSpace(event.Task.FindingID) {
			continue
		}
		entry.FindingTitle = reviewTraceFindingTitle(event.Task)
		entry.Objective = strings.TrimSpace(event.Task.Objective)
		entry.PromptSummary = reviewTracePromptSummary(event.Task)
		entry.InputDigest = reviewTraceInputDigest(event.Task)
		entry.StandardsApplied = append([]string{}, event.Task.StrictStandards...)
		entry.UpdatedAt = time.Now().Unix()
		switch event.Stage {
		case reviewProgressStarted:
			entry.Status = "running"
		case reviewProgressCompleted:
			entry.Status = "completed"
			entry.Verdict = strings.TrimSpace(event.Verdict.Verdict)
			entry.Confidence = strings.TrimSpace(event.Verdict.Confidence)
			entry.Reviewer = strings.TrimSpace(event.Verdict.Reviewer)
			entry.Reason = strings.TrimSpace(event.Verdict.Reason)
			entry.MissingEvidence = append([]string{}, event.Verdict.MissingEvidence...)
			entry.Fix = strings.TrimSpace(event.Verdict.Fix)
			entry.ToolTrace = append([]review.ToolTraceEntry{}, event.Verdict.ToolTrace...)
			entry.DurationMs = event.DurationMs
		case reviewProgressFailed:
			entry.Status = "failed"
			entry.DurationMs = event.DurationMs
			if event.Err != nil {
				entry.Reason = event.Err.Error()
			}
			entry.FailureKind, entry.FailureLabel = classifyReviewFailure(entry.Reason)
		}
		break
	}
	trace.ErrorMessage = reviewTraceErrorSummary(trace)
}

func reviewTraceErrorSummary(trace *review.ReviewTrace) string {
	if trace == nil {
		return ""
	}
	return reviewTraceStatsErrorSummary(trace.Total, reviewTraceFinishedCount(trace), summarizeReviewTrace(trace))
}

func reviewTraceStatsErrorSummary(total, finished int, stats reviewTraceSummaryStats) string {
	parts := make([]string, 0, 7)
	if finished > 0 || total > 0 {
		parts = append(parts, fmt.Sprintf("%d/%d 项复核已结束", finished, total))
	}
	if stats.successCount > 0 {
		parts = append(parts, fmt.Sprintf("成功 %d 项", stats.successCount))
	}
	if stats.balanceExhaustedCount > 0 {
		parts = append(parts, fmt.Sprintf("余额不足 %d 项", stats.balanceExhaustedCount))
	}
	if stats.requestCanceledCount > 0 {
		parts = append(parts, fmt.Sprintf("请求取消 %d 项", stats.requestCanceledCount))
	}
	if stats.timeoutCount > 0 {
		parts = append(parts, fmt.Sprintf("超时 %d 项", stats.timeoutCount))
	}
	if stats.invalidResponseCount > 0 {
		parts = append(parts, fmt.Sprintf("无效响应 %d 项", stats.invalidResponseCount))
	}
	if stats.toolRejectedCount > 0 {
		parts = append(parts, fmt.Sprintf("工具拒绝 %d 项", stats.toolRejectedCount))
	}
	if stats.iterationLimitCount > 0 {
		parts = append(parts, fmt.Sprintf("迭代上限 %d 项", stats.iterationLimitCount))
	}
	if stats.executionErrorCount > 0 {
		parts = append(parts, fmt.Sprintf("执行失败 %d 项", stats.executionErrorCount))
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "；")
}

func classifyReviewFailure(reason string) (string, string) {
	lower := strings.ToLower(strings.TrimSpace(reason))
	switch {
	case lower == "":
		return "", ""
	case strings.Contains(lower, "insufficient balance") || strings.Contains(lower, "余额不足"):
		return "balance_exhausted", "LLM 账户余额不足"
	case strings.Contains(lower, "context deadline exceeded") || strings.Contains(lower, "deadline exceeded"):
		return "timeout", "LLM 复核超时"
	case strings.Contains(lower, "context canceled") || strings.Contains(lower, "request canceled"):
		return "request_canceled", "LLM 请求被取消"
	case strings.Contains(lower, "iteration limit") || strings.Contains(lower, "最大工具迭代次数"):
		return "iteration_limit", "工具迭代达到上限"
	case strings.Contains(lower, "rejected") || strings.Contains(lower, "工具调用被拒绝"):
		return "tool_rejected", "工具调用被拒绝"
	case strings.Contains(lower, "invalid json") || strings.Contains(lower, "未返回有效 json") || strings.Contains(lower, "未返回有效分析"):
		return "invalid_response", "模型返回无效结果"
	default:
		return "execution_error", "LLM 执行失败"
	}
}

func reviewTraceFindingTitle(task review.ReviewAgentTask) string {
	if task.StageContext != nil && strings.TrimSpace(task.StageContext.Finding.Title) != "" {
		return strings.TrimSpace(task.StageContext.Finding.Title)
	}
	if strings.TrimSpace(task.FindingID) != "" {
		return strings.TrimSpace(task.FindingID)
	}
	return "待复核风险"
}

func reviewTraceContextSummary(task review.ReviewAgentTask) string {
	if task.StageContext == nil {
		return strings.TrimSpace(task.Objective)
	}
	parts := make([]string, 0, 4)
	finding := task.StageContext.Finding
	if strings.TrimSpace(finding.Category) != "" {
		parts = append(parts, "分类:"+strings.TrimSpace(finding.Category))
	}
	if strings.TrimSpace(finding.Severity) != "" {
		parts = append(parts, "级别:"+strings.TrimSpace(finding.Severity))
	}
	if strings.TrimSpace(finding.PrimaryLocation) != "" {
		parts = append(parts, "位置:"+sanitizeReviewTraceLocation(finding.PrimaryLocation))
	}
	if len(finding.CodeEvidenceRefs) > 0 {
		parts = append(parts, fmt.Sprintf("代码证据:%d", len(finding.CodeEvidenceRefs)))
	}
	if len(finding.BehaviorEvidenceRefs) > 0 {
		parts = append(parts, fmt.Sprintf("行为证据:%d", len(finding.BehaviorEvidenceRefs)))
	}
	if len(parts) == 0 {
		return strings.TrimSpace(task.Objective)
	}
	return strings.Join(parts, " | ")
}

func reviewTracePromptSummary(task review.ReviewAgentTask) string {
	return compactStageContextSentence(strings.TrimSpace(task.Prompt), 220)
}

func reviewTraceInputDigest(task review.ReviewAgentTask) []string {
	items := make([]string, 0, 8)
	if text := strings.TrimSpace(task.Objective); text != "" {
		items = append(items, "目标: "+compactStageContextSentence(text, 72))
	}
	if text := strings.TrimSpace(reviewTraceContextSummary(task)); text != "" {
		items = append(items, "上下文: "+compactStageContextSentence(text, 96))
	}
	if task.StageContext != nil {
		finding := task.StageContext.Finding
		if len(finding.CodeEvidenceRefs) > 0 {
			items = append(items, fmt.Sprintf("代码证据引用: %d 条", len(finding.CodeEvidenceRefs)))
		}
		if len(finding.BehaviorEvidenceRefs) > 0 {
			items = append(items, fmt.Sprintf("行为证据引用: %d 条", len(finding.BehaviorEvidenceRefs)))
		}
		if len(finding.ContextEvidenceRefs) > 0 {
			items = append(items, fmt.Sprintf("上下文证据引用: %d 条", len(finding.ContextEvidenceRefs)))
		}
	}
	if len(task.StrictStandards) > 0 {
		items = append(items, "复核标准: "+compactStageContextSentence(strings.Join(task.StrictStandards, "；"), 120))
	}
	return items
}

func sanitizeReviewTraceLocation(location string) string {
	location = strings.TrimSpace(location)
	if location == "" {
		return ""
	}
	parts := strings.Fields(location)
	for i, part := range parts {
		parts[i] = sanitizeReviewTracePathToken(part)
	}
	return strings.Join(parts, " ")
}

func sanitizeReviewTracePathToken(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if !strings.Contains(token, "/") && !strings.Contains(token, "\\") {
		return token
	}
	suffix := ""
	if idx := strings.LastIndex(token, ":"); idx > 0 && idx < len(token)-1 {
		maybeLine := token[idx+1:]
		if _, err := strconv.Atoi(maybeLine); err == nil {
			suffix = token[idx:]
			token = token[:idx]
		}
	}
	base := filepath.Base(strings.ReplaceAll(token, "\\", "/"))
	if base == "." || base == "/" || strings.TrimSpace(base) == "" {
		base = token
	}
	return base + suffix
}

func finalizeRefinedResult(base baseScanOutput, refined review.Result, findings []plugins.Finding) review.Result {
	refined.CapabilityMatrix = buildCapabilityMatrix(findings, base, refined)
	refined.AuditEvents = buildAuditEvents(base, refined)
	refined = sanitizeReportResult(refined, base.sourceRoot)
	refined.Summary.HighRisk, refined.Summary.MediumRisk, refined.Summary.LowRisk = countReviewedFindingRisks(findings, refined)
	refined.Summary.RiskLevel, refined.Summary.Admission = decisionFromReviewedFindings(base, refined)
	return refined
}

func applyAutomaticFalsePositiveFeedback(store *storage.Store, refined review.Result) {
	if store == nil || len(refined.StructuredFindings) == 0 || len(refined.ReviewAgentVerdicts) == 0 {
		return
	}
	verdicts := preferredVerdictsByFinding(refined.ReviewAgentVerdicts)
	for _, finding := range refined.StructuredFindings {
		verdict, ok := verdicts[finding.ID]
		if !ok || verdict.Verdict != "likely_false_positive" {
			continue
		}
		tokens := extractFalsePositiveFeedbackTokens(finding)
		if len(tokens) == 0 {
			continue
		}
		ruleID := strings.TrimSpace(finding.RuleID)
		for _, token := range tokens {
			_ = store.AddAnalyzerFalsePositiveFeedback(ruleID, token)
		}
		analyzer.LearnFalsePositives(ruleID, tokens)
	}
}

func extractFalsePositiveFeedbackTokens(finding review.StructuredFinding) []string {
	set := map[string]bool{}
	for _, ev := range finding.Evidence {
		line := strings.ToLower(strings.TrimSpace(ev))
		if line == "" {
			continue
		}
		for _, token := range localHostTokens {
			if strings.Contains(line, token) {
				set[token] = true
			}
		}
		for _, token := range internalDevelopmentTokens {
			if strings.Contains(line, token) {
				set[token] = true
			}
		}
		if isDocumentationLikeText(line) {
			for _, token := range documentationLikeTokens {
				if strings.Contains(line, token) {
					set[token] = true
				}
			}
		}
	}
	out := make([]string, 0, len(set))
	for token := range set {
		out = append(out, token)
	}
	sort.Strings(out)
	return out
}

func resolveSkillDescription(formDescription, scanPath string) string {
	return reviewreport.ResolveSkillDescription(formDescription, scanPath)
}

func extractSkillDeclaration(scanPath string) string {
	return reviewreport.ExtractSkillDeclaration(scanPath)
}

// extractSkillNameFromDescription 从 description 字符串中提取技能名
// 只提取 name: 字段
func extractSkillNameFromDescription(description string) string {
	desc := strings.TrimSpace(description)
	if desc == "" {
		return ""
	}
	if strings.HasPrefix(desc, "SKILL.md:") {
		desc = strings.TrimSpace(strings.TrimPrefix(desc, "SKILL.md:"))
	}
	lines := strings.Split(desc, "\n")
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "name:") {
			name := strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
			name = strings.Trim(name, "\"'")
			if name != "" && len(name) < 100 {
				return name
			}
		}
	}
	return ""
}

// extractSkillName 提取技能名，优先级：
// 1. SKILL.md 的 name: 字段
// 2. 上传的文件夹名（folderName）
func extractSkillName(description, scanPath, folderName string) string {
	// 1. 从 SKILL.md 提取 name: 字段
	if scanPath != "" {
		skillMD := filepath.Join(scanPath, "SKILL.md")
		data, err := os.ReadFile(skillMD)
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				trimmed := strings.TrimSpace(line)
				if strings.HasPrefix(trimmed, "name:") {
					name := strings.TrimSpace(strings.TrimPrefix(trimmed, "name:"))
					name = strings.Trim(name, "\"'")
					if name != "" && len(name) < 100 {
						return name
					}
				}
			}
		}
	}

	// 2. 使用文件夹名
	if folderName != "" {
		return folderName
	}

	return ""
}

func performBaseScan(taskID string, store *storage.Store, username, scanPath, originalName, description string, permissions []string, selectedRuleIDs []string, customRules []customRuleInput) (baseScanOutput, error) {
	out := baseScanOutput{score: 100}
	out.trace = append(out.trace, newAnalysisTraceEvent("preflight", "running", "开始关键组件自检", "语义模型、LLM、规则矩阵"))
	cfg := loadEffectiveScanConfig(selectedRuleIDs, customRules)
	out.totalRules = len(cfg.Rules)
	out.ruleProfile = buildRuleSetProfile(cfg)
	out.ruleExplanations = buildRuleExplanations(cfg)
	if err := ensureBaseScanPrerequisites(); err != nil {
		return out, err
	}
	llmClient, err := buildBaseScanLLMClient(store, username)
	if err != nil {
		return out, err
	}
	out.llmClient = llmClient
	out.trace = append(out.trace, newAnalysisTraceEvent("preflight", "completed", "关键组件自检通过", fmt.Sprintf("规则数:%d", out.totalRules)))

	files, dependencies, cacheStats := collectBaseScanArtifacts(scanPath, llmClient)
	out.sourceRoot = scanPath
	out.sourceFiles = append([]evaluator.SourceFile{}, files...)
	out.cacheStats = cacheStats
	out.profile = buildSkillAnalysisProfile(scanPath, files, dependencies, permissions)
	out.trace = append(out.trace, newAnalysisTraceEvent("artifact_collection", "completed", "已收集技能声明、源码和依赖画像", fmt.Sprintf("文件:%d 依赖:%d", out.profile.SourceFileCount, out.profile.DependencyCount)))
	if cacheStats.Enabled {
		hitRate := incrementalCacheHitRate(cacheStats)
		detail := fmt.Sprintf("模式:增量 候选:%d 命中:%d 未命中:%d 命中率:%.1f%%", cacheStats.Candidate, cacheStats.Hit, cacheStats.Miss, hitRate)
		if cacheStats.LoadWarning != "" {
			detail += "；" + cacheStats.LoadWarning
		}
		out.trace = append(out.trace, newAnalysisTraceEvent("incremental_cache", "completed", "增量扫描缓存统计", detail))
	} else {
		detail := "模式:全量重建（缓存关闭）"
		if cacheStats.DisabledReason != "" {
			detail += "；" + cacheStats.DisabledReason
		}
		out.trace = append(out.trace, newAnalysisTraceEvent("incremental_cache", "completed", "增量扫描缓存统计", detail))
	}
	skill := &evaluator.Skill{
		Name:         originalName,
		Description:  description,
		Files:        files,
		Dependencies: dependencies,
		Permissions:  permissions,
	}
	result, evalErr := evaluateBaseSkill(taskID, llmClient, cfg, skill)
	if evalErr != nil {
		return out, fmt.Errorf("级联评估执行失败，已阻断扫描，请修复评估引擎后重试: %w", evalErr)
	}
	applyBaseScanEvaluationResult(&out, cfg, result)

	// IR 增强分析：污点/链/相似性/Agent 探索
	irResult := runIRAnalysis(skill)
	if len(irResult.Findings) > 0 {
		out.findings = append(out.findings, irResult.Findings...)
		out.trace = append(out.trace, newAnalysisTraceEvent("ir_analysis", "completed", "IR 增强分析完成", irResult.Summary))
	}

	if len(out.uncheckedRules) == 0 {
		out.coverageNote = buildCoverageNote("已完成当前规则集全量检测；系统仅提供证据、风险标记和复核建议，最终是否使用由用户判断", out.ruleCoverage)
	} else {
		out.coverageNote = buildCoverageNote("当前规则集中存在未评估项，请优先修复引擎或补齐规则实现后复扫", out.ruleCoverage)
	}
	return out, nil
}

func loadEffectiveScanConfig(selectedRuleIDs []string, customRules []customRuleInput) *config.Config {
	cfg, err := config.Load(config.RulesConfigPath())
	if err != nil {
		cfg = getDefaultConfig()
	}
	return buildEffectiveConfig(cfg, selectedRuleIDs, customRules)
}

func ensureBaseScanPrerequisites() error {
	if globalEmbedder != nil && embedderInitError == nil {
		return nil
	}
	errMsg := "模型未初始化"
	if embedderInitError != nil {
		errMsg = embedderInitError.Error()
	}
	return fmt.Errorf("语义引擎不可用，已阻断扫描，请启用并修复语义模型后重试: %s", errMsg)
}

func buildBaseScanLLMClient(store *storage.Store, username string) (llm.Client, error) {
	userLLM := store.GetUserLLMConfig(username)
	if userLLM != nil && userLLM.Enabled {
		provider, ok := resolveUserLLMProviderConfig(store, userLLM)
		if ok {
			client, err := llm.NewClient(llm.ProviderConfig{Provider: provider.ID, Name: provider.Name, Protocol: provider.Protocol, BaseURL: provider.BaseURL, Model: provider.Model, APIKey: provider.APIKey})
			if err == nil {
				return client, nil
			}
		}
	}
	return nil, fmt.Errorf("LLM 功能未启用，已阻断扫描，请在个人中心配置可用的 LLM 后重试")
}

// extractUserLLMConfig 提取用户的 LLM 配置参数，用于 zeroclaw Agent。
// 返回 (provider, protocol, baseURL, model, apiKey)。如果未配置则全为空串。
func extractUserLLMConfig(store *storage.Store, username string) (string, string, string, string, string) {
	userLLM := store.GetUserLLMConfig(username)
	if userLLM == nil || !userLLM.Enabled {
		return "", "", "", "", ""
	}
	provider, ok := resolveUserLLMProviderConfig(store, userLLM)
	if !ok {
		return "", "", "", "", ""
	}
	return provider.ID, provider.Protocol, provider.BaseURL, provider.Model, provider.APIKey
}

func collectBaseScanArtifacts(scanPath string, llmClient llm.Client) ([]evaluator.SourceFile, []evaluator.Dependency, incrementalCacheStats) {
	return collectSourceArtifacts(scanPath, llmClient)
}

func evaluateBaseSkill(taskID string, llmClient llm.Client, cfg *config.Config, skill *evaluator.Skill) (*evaluator.EvaluationResult, error) {
	eval := evaluator.NewEvaluator(globalEmbedder, llmClient, cfg)
	eval.SetProgressHook(func(ev evaluator.ProgressEvent) {
		if strings.TrimSpace(taskID) == "" {
			return
		}
		riskLabel := mapRuleLayerToRisk(ev.Layer)
		label := strings.TrimSpace(ev.RuleID)
		if strings.TrimSpace(ev.RuleName) != "" {
			label = label + " " + strings.TrimSpace(ev.RuleName)
		}
		msg := fmt.Sprintf("正在检查%s规则 %d/%d：%s", riskLabel, ev.Index, ev.Total, label)
		taskStore.update(taskID, func(t *scanTask) {
			t.CurrentRule = label
			t.Message = msg
		})
	})
	return eval.Evaluate(context.Background(), skill)
}

func applyBaseScanEvaluationResult(out *baseScanOutput, cfg *config.Config, result *evaluator.EvaluationResult) {
	if result.IntentAnalysis == nil {
		detail := strings.TrimSpace(result.IntentAnalysisError)
		if detail == "" {
			detail = "LLM 返回空结果"
		}
		out.trace = append(out.trace, newAnalysisTraceEvent("llm_intent_analysis", "warning", "LLM 意图分析未返回有效结果，已降级继续扫描", detail))
	} else {
		out.trace = append(out.trace, newAnalysisTraceEvent("llm_intent_analysis", "completed", "LLM 意图分析完成", localizeIntentRiskLevel(result.IntentAnalysis.IntentRiskLevel)))
	}
	out.trace = append(out.trace, newAnalysisTraceEvent("semantic_evaluation", "completed", "规则集和语义模型检测完成", fmt.Sprintf("已评估规则:%d", len(result.ItemScores))))
	out.findings = convertResultToFindings(result, cfg)
	out.evalLogs = buildRuleEvaluationLogs(cfg.Rules, result.ItemScores, result.FindingDetails)
	out.score = result.Score
	out.intentSummary = buildIntentReportSummaryWithError(result.IntentAnalysis, result.IntentAnalysisError)
	out.detectionErrors = append([]evaluator.DetectionError{}, result.DetectionErrors...)
	out.evaluatedRules = len(result.ItemScores)
	out.uncheckedRules = collectUncheckedRuleIDs(cfg, result.ItemScores)
	out.ruleCoverage = buildRuleCoverageSummary(cfg, result.ItemScores)
}

func mapRuleLayerToRisk(layer string) string {
	switch strings.ToUpper(strings.TrimSpace(layer)) {
	case "P0":
		return "高风险"
	case "P1":
		return "中风险"
	case "P2":
		return "低风险"
	default:
		if strings.TrimSpace(layer) == "" {
			return "规则"
		}
		return strings.TrimSpace(layer)
	}
}

func buildIntentReportSummary(analysis *llm.AnalysisResult) intentReportSummary {
	return buildIntentReportSummaryWithError(analysis, "")
}

func buildIntentReportSummaryWithError(analysis *llm.AnalysisResult, analysisError string) intentReportSummary {
	if analysis == nil {
		reason := strings.TrimSpace(analysisError)
		if reason == "" {
			reason = "LLM 未启用或本次未返回有效的声明意图分析，因此报告不展示原始声明替代分析结论。"
		}
		return intentReportSummary{
			Available:         false,
			UnavailableReason: reason,
		}
	}
	return intentReportSummary{
		Available:              true,
		DeclaredIntent:         localizeFreeText(defaultIfEmpty(strings.TrimSpace(analysis.StatedIntent), "LLM 未给出明确的声明意图摘要。")),
		ActualBehavior:         localizeFreeText(defaultIfEmpty(strings.TrimSpace(analysis.ActualBehavior), "LLM 未给出明确的实际行为摘要。")),
		DeclaredCapabilities:   localizeList(analysis.DeclaredCapabilities),
		ActualCapabilities:     localizeList(analysis.ActualCapabilities),
		ConsistencyEvidence:    localizeList(analysis.ConsistencyEvidence),
		CrossFileConsolidation: analysis.CrossFileConsolidation,
		IntentRiskLevel:        localizeIntentRiskLevel(analysis.IntentRiskLevel),
		IntentMismatch:         localizeFreeText(strings.TrimSpace(analysis.IntentMismatch)),
	}
}

func toDocxIntentSummary(summary intentReportSummary) docx.IntentSummary {
	return docx.IntentSummary{
		Available:            summary.Available,
		DeclaredIntent:       summary.DeclaredIntent,
		ActualBehavior:       summary.ActualBehavior,
		DeclaredCapabilities: summary.DeclaredCapabilities,
		ActualCapabilities:   summary.ActualCapabilities,
		ConsistencyEvidence:  summary.ConsistencyEvidence,
		IntentRiskLevel:      summary.IntentRiskLevel,
		IntentMismatch:       summary.IntentMismatch,
		UnavailableReason:    summary.UnavailableReason,
	}
}

func toDocxAnalysisProfile(profile skillAnalysisProfile) docx.AnalysisProfile {
	return docx.AnalysisProfile{
		AnalysisMode:       profile.AnalysisMode,
		DeclarationSources: profile.DeclarationSources,
		SourceFiles:        profile.SourceFiles,
		Dependencies:       profile.Dependencies,
		Permissions:        profile.Permissions,
		LanguageSummary:    profile.LanguageSummary,
		CapabilitySignals:  profile.CapabilitySignals,
	}
}

func localizeIntentRiskLevel(level string) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "high", "高风险", "critical", "block":
		return "高风险"
	case "medium", "中风险", "review":
		return "中风险"
	case "low", "低风险":
		return "低风险"
	case "none", "pass", "无风险", "":
		return "无风险"
	default:
		return localizeFreeText(level)
	}
}

func localizeList(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item != "" {
			out = append(out, localizeFreeText(item))
		}
	}
	return out
}

func localizeFreeText(text string) string {
	text = strings.TrimSpace(text)
	if text == "" || containsCJK(text) {
		return text
	}
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "read") && strings.Contains(lower, "blockchain"):
		return "读取链上公开数据。"
	case strings.Contains(lower, "network"):
		return "使用网络访问外部服务。"
	case strings.Contains(lower, "file"):
		return "读取或处理文件内容。"
	case strings.Contains(lower, "command") || strings.Contains(lower, "shell"):
		return "涉及命令或 Shell 执行能力。"
	case strings.Contains(lower, "credential") || strings.Contains(lower, "secret") || strings.Contains(lower, "token"):
		return "涉及凭据、密钥或令牌相关数据。"
	default:
		return "LLM 返回了英文分析内容，需在报告复核时翻译确认: " + text
	}
}

func containsCJK(text string) bool {
	for _, r := range text {
		if r >= '\u4e00' && r <= '\u9fff' {
			return true
		}
	}
	return false
}

func collectRuleIDs(cfg *config.Config) []string {
	out := make([]string, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		out = append(out, rule.ID)
	}
	return out
}

func buildRuleCoverageSummary(cfg *config.Config, itemScores map[string]float64) ruleCoverageSummary {
	summary := ruleCoverageSummary{}
	if cfg == nil {
		summary.Note = "规则配置为空，无法统计覆盖率"
		return summary
	}

	summary.Version = strings.TrimSpace(cfg.Version)
	if summary.Version == "" {
		summary.Version = "unknown"
	}

	evaluatedSet := make(map[string]struct{}, len(itemScores))
	for ruleID := range itemScores {
		evaluatedSet[strings.TrimSpace(ruleID)] = struct{}{}
	}

	autoUncovered := make([]string, 0)
	for _, rule := range cfg.Rules {
		ruleID := strings.TrimSpace(rule.ID)
		ruleName := strings.TrimSpace(rule.Name)
		if ruleID == "" {
			continue
		}
		summary.AutoTotal++
		if len(evaluatedSet) == 0 {
			summary.AutoCovered++
			continue
		}
		if _, ok := evaluatedSet[ruleID]; ok {
			summary.AutoCovered++
			continue
		}
		if ruleName == "" {
			ruleName = ruleID
		}
		autoUncovered = append(autoUncovered, fmt.Sprintf("%s %s", ruleID, ruleName))
	}

	summary.AutoUncovered = autoUncovered
	if summary.AutoTotal == 0 {
		summary.Note = "当前规则集中没有可评估规则"
	} else if len(summary.AutoUncovered) == 0 {
		summary.Note = fmt.Sprintf("规则自动评估项已覆盖：%d/%d", summary.AutoCovered, summary.AutoTotal)
	} else {
		summary.Note = fmt.Sprintf("规则自动评估项覆盖不足：%d/%d；未覆盖项需优先补齐", summary.AutoCovered, summary.AutoTotal)
	}

	return summary
}

func buildCoverageNote(base string, rc ruleCoverageSummary) string {
	base = strings.TrimSpace(base)
	ruleNote := strings.TrimSpace(rc.Note)
	if ruleNote == "" {
		return base
	}
	if base == "" {
		return ruleNote
	}
	return base + "；" + ruleNote
}

func buildDetectionDegradationPayload(items []evaluator.DetectionError) map[string]interface{} {
	skipped := 0
	failed := 0
	rows := make([]map[string]string, 0, len(items))
	for _, item := range items {
		kind := strings.ToLower(strings.TrimSpace(item.Kind))
		if kind == "skipped" {
			skipped++
		} else {
			failed++
			kind = "failed"
		}
		rows = append(rows, map[string]string{
			"rule_id":  displayRuleName(item.RuleID),
			"kind":     kind,
			"message":  strings.TrimSpace(item.Message),
			"severity": defaultIfEmpty(strings.TrimSpace(item.Severity), "warning"),
		})
	}
	return map[string]interface{}{
		"total":   len(items),
		"skipped": skipped,
		"failed":  failed,
		"items":   rows,
	}
}

func buildRuleEvaluationLogs(rules []config.Rule, itemScores map[string]float64, details []evaluator.FindingDetail) []ruleEvaluationLog {
	detailMap := make(map[string][]evaluator.FindingDetail)
	for _, d := range details {
		rid := strings.TrimSpace(d.RuleID)
		if rid == "" {
			continue
		}
		detailMap[rid] = append(detailMap[rid], d)
	}

	logs := make([]ruleEvaluationLog, 0, len(rules))
	for _, rule := range rules {
		score, evaluated := itemScores[rule.ID]
		riskLabel := "未评估"
		resultText := "未执行该评估项（引擎降级、规则未接入或执行失败）。"
		if evaluated {
			riskLabel = riskLabelFromRule(rule, score, detailMap[rule.ID])
			if riskLabel == "无风险" {
				resultText = "未发现风险。"
			} else {
				evDesc, evLoc := summarizeRuleEvidence(detailMap[rule.ID])
				if evDesc == "" {
					evDesc = "检测命中风险条件。"
				}
				resultText = evDesc
				logs = append(logs, ruleEvaluationLog{
					RuleID:            publicRuleIDForOutput(rule.ID),
					RuleName:          rule.Name,
					Layer:             rule.Layer,
					DetectionType:     normalizeDetectionType(rule.Detection.Type),
					DetectionProcess:  buildDetectionProcessText(rule),
					DetectionResult:   resultText,
					RiskLabel:         riskLabel,
					Evaluated:         true,
					EvidenceLocations: evLoc,
				})
				continue
			}
		}

		logs = append(logs, ruleEvaluationLog{
			RuleID:           publicRuleIDForOutput(rule.ID),
			RuleName:         rule.Name,
			Layer:            rule.Layer,
			DetectionType:    normalizeDetectionType(rule.Detection.Type),
			DetectionProcess: buildDetectionProcessText(rule),
			DetectionResult:  resultText,
			RiskLabel:        riskLabel,
			Evaluated:        evaluated,
		})
	}
	return logs
}

func normalizeDetectionType(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "pattern":
		return "模式匹配"
	case "function":
		return "函数检测"
	case "semantic":
		return "语义检测"
	default:
		if strings.TrimSpace(v) == "" {
			return "未定义"
		}
		return v
	}
}

func buildDetectionProcessText(rule config.Rule) string {
	base := fmt.Sprintf("检测方式: %s", normalizeDetectionType(rule.Detection.Type))
	switch strings.ToLower(strings.TrimSpace(rule.Detection.Type)) {
	case "pattern":
		if len(rule.Detection.Patterns) == 0 {
			return base + "；匹配规则未配置"
		}
		limit := len(rule.Detection.Patterns)
		if limit > 3 {
			limit = 3
		}
		return base + "；关键模式: " + strings.Join(rule.Detection.Patterns[:limit], " | ")
	case "function":
		if strings.TrimSpace(rule.Detection.Function) == "" {
			return base + "；检测函数未配置"
		}
		return base + "；执行函数: " + rule.Detection.Function
	case "semantic":
		return fmt.Sprintf("%s；阈值区间: %.2f - %.2f", base, rule.Detection.ThresholdLow, rule.Detection.ThresholdHigh)
	default:
		return base
	}
}

func riskLabelFromRule(rule config.Rule, score float64, details []evaluator.FindingDetail) string {
	_ = score
	for _, detail := range details {
		if detail.Severity == "高风险" || detail.Severity == "中风险" || detail.Severity == "低风险" {
			return detail.Severity
		}
	}
	severity := strings.TrimSpace(rule.Severity)
	if severity == "高风险" || severity == "中风险" || severity == "低风险" {
		return "无风险"
	}
	if strings.EqualFold(strings.TrimSpace(rule.Layer), "P0") {
		return "无风险"
	}
	if strings.EqualFold(strings.TrimSpace(rule.Layer), "P1") {
		return "无风险"
	}
	return "无风险"
}

func summarizeRuleEvidence(items []evaluator.FindingDetail) (string, []string) {
	if len(items) == 0 {
		return "", nil
	}
	max := 2
	if len(items) < max {
		max = len(items)
	}
	descParts := make([]string, 0, max)
	locs := make([]string, 0, max)
	for i := 0; i < max; i++ {
		d := items[i]
		if strings.TrimSpace(d.Description) != "" {
			descParts = append(descParts, d.Description)
		}
		if strings.TrimSpace(d.Location) != "" {
			locs = append(locs, d.Location)
		}
	}
	return strings.Join(descParts, "；"), uniqueStringsLocal(locs)
}

func uniqueStringsLocal(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func collectUncheckedRuleIDs(cfg *config.Config, itemScores map[string]float64) []string {
	out := make([]string, 0)
	for _, rule := range cfg.Rules {
		if _, ok := itemScores[rule.ID]; !ok {
			out = append(out, rule.ID)
		}
	}
	return out
}

func parseSelectedRuleIDs(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		id := strings.TrimSpace(p)
		if id == "" {
			continue
		}
		if len(id) > 64 {
			continue
		}
		if _, ok := seen[id]; ok {
			continue
		}
		seen[id] = struct{}{}
		out = append(out, id)
		if len(out) >= 512 {
			break
		}
	}
	return out
}

func parseBoolWithDefault(raw string, def bool) bool {
	s := strings.ToLower(strings.TrimSpace(raw))
	if s == "" {
		return def
	}
	return s == "true" || s == "1" || s == "on" || s == "enabled"
}

func parsePositiveIntWithDefault(raw string, def int) int {
	v, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || v <= 0 {
		return def
	}
	if v > 86400 {
		return 86400
	}
	return v
}

func parseCustomRules(raw string) []customRuleInput {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	if len(raw) > 256<<10 {
		return nil
	}
	var in []customRuleInput
	if err := json.Unmarshal([]byte(raw), &in); err != nil {
		return nil
	}
	if len(in) > maxCustomRuleCount {
		in = in[:maxCustomRuleCount]
	}
	out := make([]customRuleInput, 0, len(in))
	for _, item := range in {
		name := strings.TrimSpace(item.Name)
		severity := normalizeCustomRuleSeverity(item.Severity)
		if severity == "" {
			severity = severityFromLegacyLayer(item.Layer)
		}
		reason := strings.TrimSpace(item.Reason)
		if name == "" || severity == "" || len(name) > 128 {
			continue
		}
		patterns := make([]string, 0, len(item.Patterns))
		for _, p := range item.Patterns {
			p = strings.TrimSpace(p)
			if p != "" && len(p) <= 512 {
				patterns = append(patterns, p)
				if len(patterns) >= maxCustomRulePatterns {
					break
				}
			}
		}
		if len(patterns) == 0 {
			continue
		}
		if reason == "" {
			reason = "命中自定义规则"
		}
		if len(reason) > 256 {
			reason = reason[:256]
		}
		item.Name = name
		item.Severity = severity
		item.Layer = legacyLayerFromSeverity(severity)
		item.Patterns = patterns
		item.Reason = reason
		out = append(out, item)
	}
	return out
}

func normalizeCustomRuleSeverity(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "高风险", "high":
		return "高风险"
	case "中风险", "medium":
		return "中风险"
	case "低风险", "low":
		return "低风险"
	default:
		return ""
	}
}

func severityFromLegacyLayer(raw string) string {
	switch strings.ToUpper(strings.TrimSpace(raw)) {
	case "P0":
		return "高风险"
	case "P1":
		return "中风险"
	case "P2":
		return "低风险"
	default:
		return ""
	}
}

func legacyLayerFromSeverity(severity string) string {
	switch severity {
	case "高风险":
		return "P0"
	case "中风险":
		return "P1"
	case "低风险":
		return "P2"
	default:
		return ""
	}
}

func buildEffectiveConfig(base *config.Config, selectedRuleIDs []string, customRules []customRuleInput) *config.Config {
	if base == nil {
		base = getDefaultConfig()
	}

	selected := make(map[string]struct{}, len(selectedRuleIDs))
	for _, id := range selectedRuleIDs {
		id = normalizeSelectedRuleID(strings.TrimSpace(id))
		if id == "" {
			continue
		}
		selected[id] = struct{}{}
	}

	rules := make([]config.Rule, 0, len(base.Rules)+len(customRules))
	if len(selected) == 0 {
		rules = append(rules, base.Rules...)
	} else {
		for _, rule := range base.Rules {
			if _, ok := selected[rule.ID]; ok {
				rules = append(rules, rule)
			}
		}
	}

	for i, cr := range customRules {
		id := strings.TrimSpace(cr.ID)
		if id == "" {
			id = fmt.Sprintf("CUSTOM-%d", i+1)
		}
		severity := normalizeCustomRuleSeverity(cr.Severity)
		if severity == "" {
			severity = severityFromLegacyLayer(cr.Layer)
		}
		layer := legacyLayerFromSeverity(severity)
		action := "remediate"
		if severity == "高风险" {
			action = "block"
		} else if severity == "中风险" {
			action = "review"
		}
		rules = append(rules, config.Rule{
			ID:       id,
			Name:     cr.Name,
			Severity: severity,
			Layer:    layer,
			Detection: config.Detection{
				Type:     "pattern",
				Patterns: cr.Patterns,
			},
			OnFail: config.OnFail{
				Action: action,
				Reason: cr.Reason,
			},
		})
	}

	return &config.Config{
		Version:    base.Version,
		RiskLevels: base.RiskLevels,
		Rules:      rules,
	}
}

func collectSourceArtifacts(scanPath string, llmClient llm.Client) ([]evaluator.SourceFile, []evaluator.Dependency, incrementalCacheStats) {
	var files []evaluator.SourceFile
	var dependencies []evaluator.Dependency
	stats := incrementalCacheStats{Enabled: config.IncrementalScanCacheEnabled(), CacheFilePath: filepath.Join(scanPath, ".scan-cache.json"), CacheVersion: sourceArtifactCacheVersion}
	if !stats.Enabled {
		stats.DisabledReason = "SKILL_SCANNER_INCREMENTAL_SCAN_CACHE=false"
	}
	maxEntries := config.IncrementalScanCacheMaxEntries()
	cache, loadStatus := loadSourceArtifactCache(stats.CacheFilePath)
	stats.CacheEntries = loadStatus.EntryCount
	stats.LoadWarning = sourceArtifactCacheLoadWarning(loadStatus)
	if cache.Files == nil {
		cache.Files = make(map[string]cachedSourceArtifact)
	}
	nextCache := sourceArtifactCache{Version: sourceArtifactCacheVersion, Files: make(map[string]cachedSourceArtifact), Order: make([]string, 0, len(cache.Order))}

	_ = filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if strings.EqualFold(filepath.Base(path), ".scan-cache.json") {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		baseName := strings.ToLower(filepath.Base(path))
		lang := ""
		switch {
		case baseName == "go.mod":
			lang = "gomod"
		case baseName == "package.json":
			lang = "json"
		case ext == ".md":
			if baseName != "skill.md" && baseName != "readme.md" && baseName != "description.md" && baseName != "manifest.md" {
				return nil
			}
			lang = "markdown"
		case ext == ".go":
			lang = "go"
		case ext == ".js":
			lang = "javascript"
		case ext == ".ts":
			lang = "typescript"
		case ext == ".py":
			lang = "python"
		case ext == ".java":
			lang = "java"
		case ext == ".rs":
			lang = "rust"
		case ext == ".php":
			lang = "php"
		case ext == ".rb":
			lang = "ruby"
		case ext == ".sh" || ext == ".bash" || ext == ".zsh":
			lang = "shell"
		case ext == ".sql":
			lang = "sql"
		case ext == ".html" || ext == ".htm":
			lang = "html"
		case ext == ".css":
			lang = "css"
		case ext == ".c" || ext == ".h":
			lang = "c"
		case ext == ".cpp" || ext == ".cc" || ext == ".hpp":
			lang = "cpp"
		default:
			return nil
		}
		stats.Candidate++
		fp, fpErr := buildScanFileFingerprint(scanPath, path, info, lang)
		if fpErr == nil && stats.Enabled {
			if cached, reused, ok := sourceArtifactCacheMatch(cache, fp); ok {
				files = append(files, cached.Source)
				nextCache.Files[fp.RelPath] = cachedSourceArtifact{Fingerprint: fp, Source: cached.Source}
				nextCache.Order = append(nextCache.Order, fp.RelPath)
				stats.Hit++
				if reused {
					stats.ContentReused++
					stats.DerivedReused += cachedDerivedSignalCount(cached.Source)
				}
				dependencies = append(dependencies, collectManifestDependencies(baseName, []byte(cached.Source.Content))...)
				return nil
			}
			if _, ok := cache.Files[fp.RelPath]; ok {
				stats.Stale++
			} else {
				stats.Missing++
			}
		}
		stats.Miss++
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			stats.ReadErrors++
			return nil
		}
		content := string(data)
		source := evaluator.BuildSourceFile(context.Background(), llmClient, path, content, lang)
		files = append(files, source)
		if fpErr == nil {
			nextCache.Files[fp.RelPath] = cachedSourceArtifact{Fingerprint: fp, Source: source}
			nextCache.Order = append(nextCache.Order, fp.RelPath)
		}

		dependencies = append(dependencies, collectManifestDependencies(baseName, data)...)

		if lang == "go" {
			_ = analyzer.AnalyzeGoCode(files[len(files)-1].AnalysisContent(), path)
		}
		return nil
	})
	if stats.Enabled {
		trimSourceArtifactCache(&nextCache, maxEntries)
		stats.CacheEntries = len(nextCache.Files)
		if err := saveSourceArtifactCache(stats.CacheFilePath, nextCache); err != nil {
			stats.SaveWarning = err.Error()
		}
	}

	depMap := make(map[string]evaluator.Dependency)
	for _, dep := range dependencies {
		key := dep.Name + "@" + dep.Version
		depMap[key] = dep
	}
	unique := make([]evaluator.Dependency, 0, len(depMap))
	for _, dep := range depMap {
		unique = append(unique, dep)
	}

	return files, unique, stats
}

func buildSkillAnalysisProfile(scanPath string, files []evaluator.SourceFile, dependencies []evaluator.Dependency, permissions []string) skillAnalysisProfile {
	return inventory.BuildProfile(scanPath, files, dependencies, permissions)
}

func buildScanFileFingerprint(root, path string, info os.FileInfo, language string) (scanFileFingerprint, error) {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return scanFileFingerprint{}, err
	}
	rel = filepath.ToSlash(strings.TrimSpace(rel))
	if rel == "" || strings.HasPrefix(rel, "../") {
		return scanFileFingerprint{}, fmt.Errorf("invalid relative path: %s", path)
	}
	hash, err := fileSHA256(path)
	if err != nil {
		return scanFileFingerprint{}, err
	}
	return scanFileFingerprint{
		RelPath:  rel,
		Language: strings.TrimSpace(language),
		SHA256:   hash,
		Size:     info.Size(),
		ModUnix:  info.ModTime().Unix(),
	}, nil
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func sameFingerprint(a, b scanFileFingerprint) bool {
	return strings.TrimSpace(a.RelPath) == strings.TrimSpace(b.RelPath) && strings.TrimSpace(a.Language) == strings.TrimSpace(b.Language) && strings.TrimSpace(a.SHA256) == strings.TrimSpace(b.SHA256) && a.Size == b.Size
}

func sourceArtifactCacheMatch(cache sourceArtifactCache, fp scanFileFingerprint) (cachedSourceArtifact, bool, bool) {
	cached, ok := cache.Files[fp.RelPath]
	if ok && sameFingerprint(cached.Fingerprint, fp) {
		return cached, false, true
	}
	if ok {
		return cachedSourceArtifact{}, false, false
	}
	for _, candidate := range cache.Files {
		if sameContentFingerprint(candidate.Fingerprint, fp) {
			return candidate, true, true
		}
	}
	return cachedSourceArtifact{}, false, false
}

func sameContentFingerprint(a, b scanFileFingerprint) bool {
	return strings.TrimSpace(a.Language) == strings.TrimSpace(b.Language) && strings.TrimSpace(a.SHA256) == strings.TrimSpace(b.SHA256) && a.Size == b.Size
}

func loadSourceArtifactCache(path string) (sourceArtifactCache, sourceArtifactCacheLoadStatus) {
	cache := sourceArtifactCache{Version: sourceArtifactCacheVersion, Files: map[string]cachedSourceArtifact{}}
	status := sourceArtifactCacheLoadStatus{}
	data, err := os.ReadFile(path)
	if err != nil {
		return cache, status
	}
	status.Found = true
	if json.Unmarshal(data, &cache) != nil {
		status.InvalidJSON = true
		return sourceArtifactCache{Version: sourceArtifactCacheVersion, Files: map[string]cachedSourceArtifact{}}, status
	}
	status.Version = strings.TrimSpace(cache.Version)
	if strings.TrimSpace(cache.Version) != sourceArtifactCacheVersion {
		status.VersionMismatch = true
		status.EntryCount = len(cache.Files)
		return sourceArtifactCache{Version: sourceArtifactCacheVersion, Files: map[string]cachedSourceArtifact{}}, status
	}
	if cache.Files == nil {
		cache.Files = make(map[string]cachedSourceArtifact)
	}
	status.EntryCount = len(cache.Files)
	return cache, status
}

func sourceArtifactCacheLoadWarning(status sourceArtifactCacheLoadStatus) string {
	if status.InvalidJSON {
		return "缓存文件 JSON 无法解析，已重建"
	}
	if status.VersionMismatch {
		version := strings.TrimSpace(status.Version)
		if version == "" {
			version = "unknown"
		}
		return "缓存版本不匹配，已重建: " + version
	}
	if !status.Found {
		return "缓存文件不存在，首次扫描将全量构建"
	}
	return ""
}

func saveSourceArtifactCache(path string, cache sourceArtifactCache) error {
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func collectManifestDependencies(baseName string, data []byte) []evaluator.Dependency {
	baseName = strings.ToLower(strings.TrimSpace(baseName))
	switch baseName {
	case "go.mod":
		deps, err := parseGoMod(string(data))
		if err != nil {
			return nil
		}
		return deps
	case "package.json":
		var pkg struct {
			Dependencies map[string]string `json:"dependencies"`
		}
		if json.Unmarshal(data, &pkg) != nil {
			return nil
		}
		deps := make([]evaluator.Dependency, 0, len(pkg.Dependencies))
		for name, version := range pkg.Dependencies {
			deps = append(deps, evaluator.Dependency{Name: name, Version: version})
		}
		return deps
	default:
		return nil
	}
}

func trimSourceArtifactCache(cache *sourceArtifactCache, maxEntries int) {
	if cache == nil || maxEntries <= 0 {
		return
	}
	if cache.Files == nil {
		cache.Files = make(map[string]cachedSourceArtifact)
		cache.Order = nil
		return
	}
	seen := make(map[string]struct{}, len(cache.Order))
	orderedUnique := make([]string, 0, len(cache.Order))
	for _, key := range cache.Order {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if _, ok := cache.Files[key]; !ok {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		orderedUnique = append(orderedUnique, key)
	}
	if len(orderedUnique) < len(cache.Files) {
		for key := range cache.Files {
			if _, ok := seen[key]; ok {
				continue
			}
			orderedUnique = append(orderedUnique, key)
		}
	}
	if len(orderedUnique) > maxEntries {
		removeCount := len(orderedUnique) - maxEntries
		for i := 0; i < removeCount; i++ {
			delete(cache.Files, orderedUnique[i])
		}
		orderedUnique = orderedUnique[removeCount:]
	}
	cache.Order = orderedUnique
}

func incrementalCacheHitRate(stats incrementalCacheStats) float64 {
	if stats.Candidate <= 0 {
		return 0
	}
	if stats.Hit <= 0 {
		return 0
	}
	return float64(stats.Hit) * 100 / float64(stats.Candidate)
}

func incrementalCacheReuseRate(stats incrementalCacheStats) float64 {
	if stats.Hit <= 0 || stats.ContentReused <= 0 {
		return 0
	}
	return float64(stats.ContentReused) * 100 / float64(stats.Hit)
}

func cachedDerivedSignalCount(source evaluator.SourceFile) int {
	count := 0
	if strings.TrimSpace(source.Language) != "" {
		count++
	}
	if strings.TrimSpace(source.PreprocessedContent) != "" {
		count++
	}
	if strings.TrimSpace(source.Content) != "" {
		count++
	}
	return count
}

func ruleCoverageRate(covered, total int) float64 {
	if total <= 0 || covered <= 0 {
		return 0
	}
	return float64(covered) * 100 / float64(total)
}

func percentRate(part, total int) float64 {
	if total <= 0 || part <= 0 {
		return 0
	}
	return float64(part) * 100 / float64(total)
}

func writeInvalidSourceArtifactCache(path string) error {
	return os.WriteFile(path, []byte("{invalid-json"), 0600)
}

func inferCapabilitySignals(content string) []string {
	return inventory.InferCapabilitySignals(content)
}

func uniqueStrings(items []string) []string {
	return inventory.UniqueStrings(items)
}

func limitList(items []string, limit int) []string {
	if limit <= 0 {
		return append([]string{}, items...)
	}
	if len(items) <= limit {
		return append([]string{}, items...)
	}
	return append([]string{}, items[:limit]...)
}

func buildReportBaseName(sourceName string, createdAt time.Time) string {
	name := strings.TrimSpace(sourceName)
	if name == "" {
		name = "skill-scan-report"
	}
	base := strings.TrimSuffix(filepath.Base(name), filepath.Ext(filepath.Base(name)))
	base = strings.TrimSpace(base)
	if base == "" || base == "." {
		base = "skill-scan-report"
	}
	cleaned := strings.Map(func(r rune) rune {
		switch {
		case r == '/' || r == '\\' || r == ':' || r == '*' || r == '?' || r == '"' || r == '<' || r == '>' || r == '|' || r == 0:
			return '-'
		case unicode.IsSpace(r):
			return '_'
		default:
			return r
		}
	}, base)
	cleaned = strings.Trim(cleaned, "-_.")
	if cleaned == "" {
		cleaned = "skill-scan-report"
	}
	return cleaned + "_" + createdAt.Format("20060102_150405")
}

func newAnalysisTraceEvent(stage, status, message, detail string) analysisTraceEvent {
	return analysisTraceEvent{Stage: stage, Status: status, Message: message, Detail: strings.TrimSpace(detail)}
}

func countBehaviorEvidenceCategories(behavior review.BehaviorProfile) int {
	return evidence.CountBehaviorCategories(behavior)
}

func displayRelPath(root, path string) string {
	return inventory.DisplayRelPath(root, path)
}

func countLocalizedFindingRisks(findings []plugins.Finding) (int, int, int) {
	high, medium, low := 0, 0, 0
	for _, f := range findings {
		switch localizeSeverity(f.Severity) {
		case "高风险":
			high++
		case "中风险":
			medium++
		default:
			low++
		}
	}
	return high, medium, low
}

func countReviewedFindingRisks(findings []plugins.Finding, refined review.Result) (int, int, int) {
	if len(refined.StructuredFindings) == 0 || len(refined.ReviewAgentVerdicts) == 0 {
		return countLocalizedFindingRisks(findings)
	}
	return newReviewedFindingContext(refined).normalizedSeverityCounts()
}

func preferredVerdictsByFinding(verdicts []review.ReviewAgentVerdict) map[string]review.ReviewAgentVerdict {
	grouped := map[string][]review.ReviewAgentVerdict{}
	for _, verdict := range verdicts {
		if strings.TrimSpace(verdict.FindingID) == "" {
			continue
		}
		verdict = normalizeReviewAgentVerdict(verdict, verdict.FindingID, "unknown-reviewer", nil)
		grouped[verdict.FindingID] = append(grouped[verdict.FindingID], verdict)
	}
	out := make(map[string]review.ReviewAgentVerdict, len(grouped))
	for findingID, items := range grouped {
		out[findingID] = synthesizePreferredVerdict(items)
	}
	return out
}

func synthesizePreferredVerdict(items []review.ReviewAgentVerdict) review.ReviewAgentVerdict {
	if len(items) == 0 {
		return review.ReviewAgentVerdict{}
	}
	byVerdict := map[string][]review.ReviewAgentVerdict{}
	for _, item := range items {
		key := normalizedReviewVerdict(item.Verdict)
		if key == "" {
			key = "needs_manual_review"
		}
		byVerdict[key] = append(byVerdict[key], item)
	}
	if len(byVerdict) == 1 {
		for _, sameVerdicts := range byVerdict {
			return strongestVerdict(sameVerdicts)
		}
	}
	if preferred, ok := preferredReasonedFalsePositiveVerdict(items, byVerdict); ok {
		return preferred
	}
	return mergeConflictingVerdicts(items, byVerdict)
}

func strongestVerdict(items []review.ReviewAgentVerdict) review.ReviewAgentVerdict {
	best := items[0]
	for _, item := range items[1:] {
		if confidencePriority(item.Confidence) > confidencePriority(best.Confidence) {
			best = item
			continue
		}
		if confidencePriority(item.Confidence) == confidencePriority(best.Confidence) && reviewerPriority(item.Reviewer) > reviewerPriority(best.Reviewer) {
			best = item
		}
	}
	return best
}

func mergeConflictingVerdicts(items []review.ReviewAgentVerdict, byVerdict map[string][]review.ReviewAgentVerdict) review.ReviewAgentVerdict {
	if direct, ok := preferredDirectConfirmationVerdict(items); ok {
		return direct
	}
	merged := strongestVerdict(items)
	merged.Verdict = "needs_manual_review"
	merged.Confidence = "低"
	merged.Reviewer = joinVerdictReviewers(items)
	merged.Reason = fmt.Sprintf("复核结论存在分歧: %s，已回退为需人工复核。", strings.Join(sortedVerdictLabels(byVerdict), " / "))
	merged.MissingEvidence = uniqueStrings(append(merged.MissingEvidence, collectVerdictMissingEvidence(items)...))
	merged.StandardsApplied = uniqueStrings(collectVerdictStandards(items))
	if strings.TrimSpace(merged.Fix) == "" {
		merged.Fix = "复核结论不一致，请补充可达性、运行链路和真实影响证据后再判断。"
		return merged
	}
	merged.Fix = merged.Fix + "；若复核结论仍不一致，请补充可达性、运行链路和真实影响证据。"
	return merged
}

func preferredDirectConfirmationVerdict(items []review.ReviewAgentVerdict) (review.ReviewAgentVerdict, bool) {
	var best review.ReviewAgentVerdict
	found := false
	for _, item := range items {
		if normalizedReviewVerdict(item.Verdict) != "confirmed" {
			continue
		}
		if !strings.Contains(strings.ToLower(strings.TrimSpace(item.Reviewer)), "deterministic") {
			continue
		}
		if !strings.Contains(item.Reason, "直接确认条件") {
			continue
		}
		if !found || confidencePriority(item.Confidence) > confidencePriority(best.Confidence) {
			best = item
			found = true
		}
	}
	if !found {
		return review.ReviewAgentVerdict{}, false
	}
	return best, true
}

func preferredReasonedFalsePositiveVerdict(items []review.ReviewAgentVerdict, byVerdict map[string][]review.ReviewAgentVerdict) (review.ReviewAgentVerdict, bool) {
	if len(byVerdict) != 2 {
		return review.ReviewAgentVerdict{}, false
	}
	manualItems, hasManual := byVerdict["needs_manual_review"]
	fpItems, hasFP := byVerdict["likely_false_positive"]
	if !hasManual || !hasFP || len(manualItems) == 0 || len(fpItems) == 0 {
		return review.ReviewAgentVerdict{}, false
	}
	for verdict := range byVerdict {
		if verdict != "needs_manual_review" && verdict != "likely_false_positive" {
			return review.ReviewAgentVerdict{}, false
		}
	}
	best := strongestVerdict(fpItems)
	if !hasStrongFalsePositiveRationale(best) {
		return review.ReviewAgentVerdict{}, false
	}
	best.Reviewer = joinVerdictReviewers(items)
	best.StandardsApplied = uniqueStrings(collectVerdictStandards(items))
	best.MissingEvidence = uniqueStrings(append(best.MissingEvidence, collectVerdictMissingEvidence(manualItems)...))
	if strings.TrimSpace(best.Reason) == "" {
		best.Reason = "复核理由已明确指向文档示例、无真实攻击面或高概率误报，采用疑似误报裁决。"
	}
	if strings.TrimSpace(best.Fix) == "" {
		best.Fix = "保留当前条目为疑似误报；如需提升置信度，再补充真实发布路径、可达性或运行链路证据。"
	}
	if confidencePriority(best.Confidence) < confidencePriority("中高") {
		best.Confidence = "中高"
	}
	return best, true
}

func hasStrongFalsePositiveRationale(item review.ReviewAgentVerdict) bool {
	if normalizedReviewVerdict(item.Verdict) != "likely_false_positive" {
		return false
	}
	if confidencePriority(item.Confidence) < confidencePriority("中高") {
		return false
	}
	text := strings.ToLower(strings.TrimSpace(strings.Join(append([]string{item.Reason}, item.MissingEvidence...), " ")))
	if text == "" {
		return false
	}
	markers := []string{
		"高概率误报",
		"疑似误报",
		"文档示例",
		"纯文档",
		"纯 html 模板",
		"纯html模板",
		"只是模板",
		"没有代码实现",
		"无代码实现",
		"没有网络暴露",
		"无网络暴露",
		"未鉴权端点",
		"不符合漏洞定义",
		"不构成可利用的安全漏洞",
		"仅属于文档质量问题",
		"文档质量问题",
		"完整性或合规问题",
		"分类与证据不符",
		"功能缺失属于完整性或合规问题",
		"主题与证据不匹配",
		"规则主题与证据不匹配",
		"普通文件读取",
		"未发现递归调用",
		"readme",
		"deployment",
		"无攻击面",
		"无可达攻击面",
		"缺少 exploit path",
		"不构成可利用",
		"正常管理操作",
		"缺少真实发布链路",
	}
	for _, marker := range markers {
		if strings.Contains(text, strings.ToLower(marker)) {
			return true
		}
	}
	return false
}

func sortedVerdictLabels(byVerdict map[string][]review.ReviewAgentVerdict) []string {
	labels := make([]string, 0, len(byVerdict))
	for verdict := range byVerdict {
		labels = append(labels, localizeReviewVerdict(verdict))
	}
	sort.Strings(labels)
	return labels
}

func collectVerdictMissingEvidence(items []review.ReviewAgentVerdict) []string {
	out := make([]string, 0, len(items)*2)
	for _, item := range items {
		out = append(out, item.MissingEvidence...)
	}
	return out
}

func collectVerdictStandards(items []review.ReviewAgentVerdict) []string {
	out := make([]string, 0, len(items)*2)
	for _, item := range items {
		out = append(out, item.StandardsApplied...)
	}
	return out
}

func joinVerdictReviewers(items []review.ReviewAgentVerdict) string {
	reviewers := make([]string, 0, len(items))
	seen := map[string]bool{}
	for _, item := range items {
		reviewer := strings.TrimSpace(item.Reviewer)
		if reviewer == "" || seen[reviewer] {
			continue
		}
		seen[reviewer] = true
		reviewers = append(reviewers, reviewer)
	}
	if len(reviewers) == 0 {
		return "multi-review"
	}
	sort.Strings(reviewers)
	return strings.Join(reviewers, "+")
}

func reviewerPriority(reviewer string) int {
	reviewer = strings.ToLower(strings.TrimSpace(reviewer))
	if strings.Contains(reviewer, "deterministic") {
		return 2
	}
	if strings.Contains(reviewer, "llm") {
		return 1
	}
	return 0
}

func confidencePriority(confidence string) int {
	switch strings.TrimSpace(confidence) {
	case "高":
		return 4
	case "中高":
		return 3
	case "中":
		return 2
	case "中低":
		return 1
	case "低":
		return 0
	default:
		return -1
	}
}

func normalizedReviewVerdict(verdict string) string {
	value := strings.ToLower(strings.TrimSpace(verdict))
	value = strings.ReplaceAll(value, "-", "_")
	value = strings.ReplaceAll(value, " ", "_")
	switch value {
	case "confirmed", "needs_manual_review", "likely_false_positive", "policy":
		return value
	case "true_positive", "real_risk", "valid", "vulnerable", "确认", "已确认", "真实风险", "确认风险", "成立", "漏洞成立":
		return "confirmed"
	case "false_positive", "likely_fp", "fp", "not_vulnerable", "误报", "疑似误报", "倾向误报", "非真实风险", "风险不成立":
		return "likely_false_positive"
	case "manual_review", "review", "needs_review", "uncertain", "inconclusive", "需人工复核", "待人工复核", "需要人工复核", "证据不足":
		return "needs_manual_review"
	case "准入策略", "策略风险", "合规策略", "policy_risk":
		return "policy"
	default:
		return ""
	}
}

func normalizeReviewAgentVerdict(verdict review.ReviewAgentVerdict, findingID, defaultReviewer string, defaultStandards []string) review.ReviewAgentVerdict {
	if strings.TrimSpace(verdict.FindingID) == "" {
		verdict.FindingID = strings.TrimSpace(findingID)
	}
	if normalized := normalizedReviewVerdict(verdict.Verdict); normalized != "" {
		verdict.Verdict = normalized
	} else {
		verdict.Verdict = "needs_manual_review"
		verdict.MissingEvidence = uniqueStrings(append(verdict.MissingEvidence, "复核输出缺少有效 verdict，已归一化为需人工复核"))
	}
	if strings.TrimSpace(verdict.Confidence) == "" {
		verdict.Confidence = defaultConfidenceForVerdict(verdict.Verdict)
	}
	if strings.TrimSpace(verdict.Reviewer) == "" {
		verdict.Reviewer = strings.TrimSpace(defaultReviewer)
	}
	if strings.TrimSpace(verdict.Reviewer) == "" {
		verdict.Reviewer = "unknown-reviewer"
	}
	if strings.TrimSpace(verdict.Reason) == "" {
		verdict.Reason = defaultReasonForVerdict(verdict.Verdict)
	}
	if strings.TrimSpace(verdict.Fix) == "" && verdict.Verdict == "confirmed" {
		verdict.Fix = "补充针对该风险的修复方案、回归验证步骤和证据闭环后再发布。"
	}
	if len(verdict.StandardsApplied) == 0 {
		verdict.StandardsApplied = canonicalStrictStandards(defaultStandards)
	}
	verdict.MissingEvidence = uniqueStrings(verdict.MissingEvidence)
	verdict.StandardsApplied = uniqueStrings(verdict.StandardsApplied)
	return verdict
}

func defaultConfidenceForVerdict(verdict string) string {
	switch normalizedReviewVerdict(verdict) {
	case "confirmed":
		return "中"
	case "likely_false_positive":
		return "中"
	case "policy":
		return "中"
	default:
		return "低"
	}
}

func defaultReasonForVerdict(verdict string) string {
	switch normalizedReviewVerdict(verdict) {
	case "confirmed":
		return "复核输出确认风险成立，但未提供详细原因。"
	case "likely_false_positive":
		return "复核输出倾向误报，但未提供详细原因。"
	case "policy":
		return "复核输出为策略或准入风险，但未提供详细原因。"
	default:
		return "复核输出证据不足，已回退为需人工复核。"
	}
}

func decisionFromRiskCounts(high, medium int) (string, string) {
	if high > 0 {
		return "high", "UserDecisionRequired"
	}
	if medium > 0 {
		return "medium", "UserDecisionRequired"
	}
	return "low", "UserDecisionRequired"
}

func decisionFromReviewedFindings(base baseScanOutput, refined review.Result) (string, string) {
	if refined.Evasion.Detected {
		return "high", "UserDecisionRequired"
	}
	if len(refined.StructuredFindings) == 0 {
		return decisionFromRiskCounts(refined.Summary.HighRisk, refined.Summary.MediumRisk)
	}
	ctx := newReviewedFindingContext(refined)
	highSignals, mediumSignals, _ := ctx.normalizedSeverityCounts()
	if highSignals > 0 {
		return "high", "UserDecisionRequired"
	}
	if mediumSignals > 0 {
		return "medium", "UserDecisionRequired"
	}
	if refined.Summary.HighRisk > 0 || refined.Summary.MediumRisk > 1 {
		return "medium", "UserDecisionRequired"
	}
	return "low", "UserDecisionRequired"
}

type reviewedFindingContext struct {
	refined         review.Result
	verdicts        map[string]review.ReviewAgentVerdict
	verdictHistory  map[string][]review.ReviewAgentVerdict
	fpReviews       map[string]review.FalsePositiveReview
	structuredByKey map[string]review.StructuredFinding
}

func newReviewedFindingContext(refined review.Result) reviewedFindingContext {
	return reviewedFindingContext{
		refined:         refined,
		verdicts:        preferredVerdictsByFinding(refined.ReviewAgentVerdicts),
		verdictHistory:  reviewVerdictsByFinding(refined.ReviewAgentVerdicts),
		fpReviews:       falsePositiveReviewsByFinding(refined.FalsePositiveReviews),
		structuredByKey: structuredFindingByStableKey(refined.StructuredFindings),
	}
}

func (c reviewedFindingContext) finalVerdict(findingID string) review.ReviewAgentVerdict {
	return c.verdicts[findingID]
}

func (c reviewedFindingContext) hasFinalVerdict(findingID string) bool {
	v, ok := c.verdicts[findingID]
	return ok && strings.TrimSpace(v.Verdict) != ""
}

func (c reviewedFindingContext) falsePositiveReview(findingID string) review.FalsePositiveReview {
	return c.fpReviews[findingID]
}

func (c reviewedFindingContext) verdictsForFinding(findingID string) []review.ReviewAgentVerdict {
	return c.verdictHistory[findingID]
}

func (c reviewedFindingContext) structuredFindingTitle(findingID string) string {
	for _, finding := range c.refined.StructuredFindings {
		if finding.ID == findingID {
			return finding.Title
		}
	}
	return ""
}

func (c reviewedFindingContext) structuredFindingForPluginFinding(finding plugins.Finding) (review.StructuredFinding, bool) {
	return lookupStructuredFindingForPluginFinding(finding, c.structuredByKey)
}

func (c reviewedFindingContext) normalizedSeverityCounts() (int, int, int) {
	high, medium, low := 0, 0, 0
	for _, finding := range c.refined.StructuredFindings {
		switch c.normalizedSeverity(finding) {
		case "高风险":
			high++
		case "中风险":
			medium++
		default:
			low++
		}
	}
	return high, medium, low
}

func (c reviewedFindingContext) reviewVerdictCoverage() (confirmed int, policy int, fp int, manual int, total int) {
	total = len(c.refined.StructuredFindings)
	for _, finding := range c.refined.StructuredFindings {
		if strings.TrimSpace(finding.ApplicabilityVerdict) == "not_applicable" {
			fp++
			continue
		}
		switch normalizedReviewVerdict(c.finalVerdict(finding.ID).Verdict) {
		case "confirmed":
			confirmed++
		case "policy":
			policy++
		case "likely_false_positive":
			fp++
		default:
			manual++
		}
	}
	return
}

func (c reviewedFindingContext) manualReviewBuckets() []string {
	buckets := map[string]int{}
	for _, finding := range c.refined.StructuredFindings {
		verdict := c.finalVerdict(finding.ID)
		normalized := normalizedReviewVerdict(verdict.Verdict)
		if normalized == "policy" {
			buckets["命中准入/合规策略，需按策略处置或替换目标"]++
			continue
		}
		if strings.TrimSpace(finding.ApplicabilityVerdict) == "not_applicable" {
			buckets["规则前提不成立，当前更适合作为观察项或低优先级复核"]++
			continue
		}
		if normalized != "" && normalized != "needs_manual_review" {
			continue
		}
		reason := manualReviewTriageLabel(finding, c.refined, verdict.MissingEvidence)
		if strings.TrimSpace(reason) == "" {
			reason = "证据闭环不足"
		}
		if len(verdict.MissingEvidence) > 0 {
			for _, item := range verdict.MissingEvidence {
				if label := strings.TrimSpace(strings.TrimPrefix(item, "复核分流:")); label != item && label != "" {
					reason = label
					break
				}
			}
		}
		titleLower := strings.ToLower(finding.Title)
		if strings.Contains(titleLower, "自更新") || strings.Contains(titleLower, "下载") {
			reason = "下载链缺少执行落点或可达性证据"
		}
		if strings.Contains(titleLower, "恶意代码") {
			reason = "恶意链路缺少入口触发与影响证据"
		}
		buckets[reason]++
	}
	if len(buckets) == 0 {
		return nil
	}
	out := make([]string, 0, len(buckets))
	for reason, cnt := range buckets {
		out = append(out, fmt.Sprintf("%s：%d 项", reason, cnt))
	}
	return out
}

func (c reviewedFindingContext) normalizedSeverity(finding review.StructuredFinding) string {
	verdict := c.verdicts[finding.ID]
	fp := c.fpReviews[finding.ID]
	tier := evidenceTierForFinding(finding, verdict, c.refined)
	if strings.TrimSpace(finding.ApplicabilityVerdict) == "not_applicable" && verdict.Verdict != "confirmed" {
		return "低风险"
	}
	if shouldKeepLicenseBypassAtHigh(finding, verdict) {
		return "高风险"
	}
	if shouldKeepLicenseLocalFallbackAtLow(finding, verdict) {
		return "低风险"
	}
	if displaySeverity := shouldKeepDashboardExposureSeverity(finding, verdict); displaySeverity != "" {
		return displaySeverity
	}
	if displaySeverity := shouldKeepAutoTradingSeverity(finding, verdict); displaySeverity != "" {
		return displaySeverity
	}
	if displaySeverity := shouldKeepOutboundSeverity(finding, verdict); displaySeverity != "" {
		return displaySeverity
	}
	if displaySeverity := shouldKeepDeclarationMismatchSeverity(finding, verdict); displaySeverity != "" {
		return displaySeverity
	}
	if displaySeverity := shouldKeepCredentialSeverity(finding, verdict); displaySeverity != "" {
		return displaySeverity
	}
	if displaySeverity := shouldKeepSSRFSeverity(finding, verdict); displaySeverity != "" {
		return displaySeverity
	}
	if displaySeverity := shouldKeepPythonSystemPackageSeverity(finding, verdict); displaySeverity != "" {
		return displaySeverity
	}
	if shouldDowngradeFindingToLow(finding, verdict, fp, tier) {
		return "低风险"
	}
	if verdict.Verdict == "likely_false_positive" && tier != evidenceTierStrong {
		return "低风险"
	}
	severity := localizeSeverity(finding.Severity)
	switch {
	case severity == "高风险" && tier == evidenceTierStrong && verdict.Verdict != "needs_manual_review":
		return "高风险"
	case severity == "高风险":
		return "中风险"
	case severity == "中风险" && tier == evidenceTierWeak:
		return "低风险"
	case severity == "中风险" && verdict.Verdict == "needs_manual_review" && tier == evidenceTierModerate && strings.Contains(fp.EvidenceStrength, "弱"):
		return "低风险"
	case severity == "中风险":
		return "中风险"
	default:
		return "低风险"
	}
}

func shouldKeepLicenseBypassAtHigh(finding review.StructuredFinding, verdict review.ReviewAgentVerdict) bool {
	if strings.TrimSpace(finding.Category) != "授权与许可证校验" {
		return false
	}
	if localizeSeverity(finding.Severity) != "高风险" {
		return false
	}
	if verdict.Verdict == "likely_false_positive" {
		return false
	}
	text := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), " "))
	return containsAny(text, []string{"verify_failed", "fail open", "fail-open", "return true", "continue on failure", "校验失败后继续", "失败分支放行"})
}

func shouldKeepLicenseLocalFallbackAtLow(finding review.StructuredFinding, verdict review.ReviewAgentVerdict) bool {
	if strings.TrimSpace(finding.Category) != "授权与许可证校验" {
		return false
	}
	if verdict.Verdict == "confirmed" {
		return false
	}
	text := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), " "))
	if !containsAny(text, []string{"license_server", "/api/validate", "localhost:8080", "本地默认许可证服务"}) {
		return false
	}
	if containsAny(text, []string{"verify_failed", "fail open", "fail-open", "return true", "continue on failure", "校验失败后继续", "失败分支放行"}) {
		return false
	}
	return containsAny(text, []string{"127.0.0.1", "localhost", "本地", "dev", "development", "fallback"})
}

func shouldKeepDashboardExposureSeverity(finding review.StructuredFinding, verdict review.ReviewAgentVerdict) string {
	if strings.TrimSpace(finding.Category) != "暴露面与未鉴权服务" {
		return ""
	}
	if verdict.Verdict == "likely_false_positive" {
		return ""
	}
	text := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), " "))
	if containsAny(text, []string{"0.0.0.0", "公网", "public network", "publicly accessible", "listen all interfaces", "监听所有网络接口"}) {
		return "高风险"
	}
	if containsAny(text, []string{"127.0.0.1", "localhost", "本地", "loopback", "dev", "development"}) && verdict.Verdict != "confirmed" {
		return "低风险"
	}
	return ""
}

func shouldKeepAutoTradingSeverity(finding review.StructuredFinding, verdict review.ReviewAgentVerdict) string {
	if strings.TrimSpace(finding.Category) != "业务自动化高风险行为" {
		return ""
	}
	if verdict.Verdict == "likely_false_positive" {
		return ""
	}
	text := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), " "))
	if containsAny(text, []string{"create_order", "signed_order", "place_order", "submit_order"}) {
		if containsAny(text, []string{"live trading", "real funds", "真实交易", "真实资金", "自动下单"}) {
			return "高风险"
		}
		if verdict.Verdict != "confirmed" {
			return "中风险"
		}
	}
	if containsAny(text, []string{"market query", "gamma_api", "/markets", "行情查询", "市场查询"}) && verdict.Verdict != "confirmed" {
		return "低风险"
	}
	return ""
}

func shouldKeepOutboundSeverity(finding review.StructuredFinding, verdict review.ReviewAgentVerdict) string {
	if strings.TrimSpace(finding.Category) != "外联与情报" {
		return ""
	}
	if verdict.Verdict == "likely_false_positive" {
		return ""
	}
	text := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), " "))
	if strings.Contains(text, "命中黑名单目标") || strings.Contains(text, "policy blacklist") || strings.Contains(text, "策略黑名单") {
		return "中风险"
	}
	if containsAny(text, []string{"api_key", "oem_api_key", "token", "secret", "authorization", "cookie"}) {
		return "高风险"
	}
	if strings.Contains(text, "requests.post(target") || strings.Contains(text, "upload target") || strings.Contains(text, "用户可控外联目标") || strings.Contains(text, "allowlist") {
		return "高风险"
	}
	if strings.Contains(text, "固定售后平台") || strings.Contains(text, "已声明外联回传") || strings.Contains(text, "after-sales.example.com") {
		return "低风险"
	}
	return ""
}

func shouldKeepDeclarationMismatchSeverity(finding review.StructuredFinding, verdict review.ReviewAgentVerdict) string {
	if strings.TrimSpace(finding.Category) != "声明与行为差异" {
		return ""
	}
	if verdict.Verdict == "likely_false_positive" {
		return ""
	}
	if isLikelyDocumentationOnlyFinding(finding) && verdict.Verdict != "confirmed" {
		return "低风险"
	}
	text := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), " "))
	if containsAny(text, []string{"create_order", "signed_order", "live trading", "wallet_private_key", "token", "secret", "subprocess", "os.system", "exec("}) {
		return "高风险"
	}
	if containsAny(text, []string{"license_server", "localhost", "http", "webhook", "network", "网络访问", "数据库", "sqlite"}) {
		return "中风险"
	}
	return "低风险"
}

func shouldKeepCredentialSeverity(finding review.StructuredFinding, verdict review.ReviewAgentVerdict) string {
	category := strings.TrimSpace(finding.Category)
	if category != "凭据访问" && category != "凭据暴露" {
		return ""
	}
	if verdict.Verdict == "likely_false_positive" {
		return ""
	}
	text := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), " "))
	if containsAny(text, []string{"wallet_private_key", "private key", "token", "secret"}) && containsAny(text, []string{"requests.post", "webhook", "create_order", "signed_order", "real funds", "外发"}) {
		return "高风险"
	}
	if containsAny(text, []string{"localhost", "127.0.0.1", "dev", "development", "placeholder", "empty", "示例", "sample"}) && verdict.Verdict != "confirmed" {
		return "低风险"
	}
	if containsAny(text, []string{"wallet_private_key", "private key", "token", "secret"}) {
		return "中风险"
	}
	return ""
}

func shouldKeepSSRFSeverity(finding review.StructuredFinding, verdict review.ReviewAgentVerdict) string {
	if strings.TrimSpace(finding.Category) != "网络请求与SSRF" {
		return ""
	}
	if verdict.Verdict == "likely_false_positive" {
		return ""
	}
	text := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), " "))
	if containsAny(text, []string{"metadata.google", "169.254.169.254", "危险目标=metadata.google", "危险目标=10.", "危险目标=192.168.", "危险目标=172.", "危险目标=169.254."}) && containsAny(text, []string{"target_url", "来源类型=user_input", "输入来源="}) && containsAny(text, []string{"missing-guard", "缺少校验"}) {
		return "高风险"
	}
	if containsAny(text, []string{"target_url", "来源类型=user_input", "输入来源="}) && containsAny(text, []string{"missing-guard", "缺少校验"}) {
		return "中风险"
	}
	if containsAny(text, []string{"localhost", "127.0.0.1", "dev", "development", "allowlist", "白名单"}) && verdict.Verdict != "confirmed" {
		return "低风险"
	}
	return ""
}

func shouldKeepPythonSystemPackageSeverity(finding review.StructuredFinding, verdict review.ReviewAgentVerdict) string {
	if strings.TrimSpace(finding.Category) != "环境与构建风险" || strings.TrimSpace(finding.Title) != "Python 系统包安装风险" {
		return ""
	}
	if verdict.Verdict == "likely_false_positive" {
		return ""
	}
	text := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), " "))
	if containsAny(text, []string{"curl ", "wget ", "| sh", "| bash", "git clone", "远程脚本", "供应链"}) {
		return "高风险"
	}
	if isLocalBootstrapPythonSystemPackageText(text) && verdict.Verdict != "confirmed" {
		return "低风险"
	}
	if containsAny(text, []string{"dockerfile", "container", "image build", "镜像构建", "容器构建", "builder stage", "构建阶段", "ci image"}) && verdict.Verdict != "confirmed" {
		return "低风险"
	}
	if containsAny(text, []string{"break-system-packages", "pep 668", "pip3 install", "pip install"}) {
		return "中风险"
	}
	return ""
}

func isLocalBootstrapPythonSystemPackageText(text string) bool {
	return containsAny(text, []string{"bootstrap.sh", "scripts/bootstrap.sh"}) &&
		containsAny(text, []string{"break-system-packages", "pip3 install", "pip install"}) &&
		!containsAny(text, []string{"curl ", "wget ", "| sh", "| bash", "git clone", "远程脚本", "供应链", "dockerfile", "container", "image build", "镜像构建", "容器构建", "builder stage", "构建阶段", "ci image"})
}

func normalizedReviewedSeverityForFinding(finding review.StructuredFinding, refined review.Result) string {
	return newReviewedFindingContext(refined).normalizedSeverity(finding)
}

func displayRiskCounts(refined review.Result) (int, int, int) {
	if len(refined.StructuredFindings) == 0 {
		return refined.Summary.HighRisk, refined.Summary.MediumRisk, refined.Summary.LowRisk
	}
	return newReviewedFindingContext(refined).normalizedSeverityCounts()
}

func falsePositiveReviewsByFinding(items []review.FalsePositiveReview) map[string]review.FalsePositiveReview {
	out := make(map[string]review.FalsePositiveReview, len(items))
	for _, item := range items {
		if strings.TrimSpace(item.FindingID) == "" {
			continue
		}
		out[item.FindingID] = item
	}
	return out
}

func shouldDowngradeFindingToLow(finding review.StructuredFinding, verdict review.ReviewAgentVerdict, fp review.FalsePositiveReview, tier evidenceTier) bool {
	if strings.TrimSpace(finding.ApplicabilityVerdict) == "not_applicable" && verdict.Verdict != "confirmed" {
		return true
	}
	if tier == evidenceTierStrong {
		return false
	}
	if verdict.Verdict == "likely_false_positive" {
		return true
	}
	if verdict.Verdict != "needs_manual_review" {
		return false
	}
	if tier != evidenceTierWeak {
		if !(tier == evidenceTierModerate && strings.Contains(fp.EvidenceStrength, "弱")) {
			return false
		}
	}
	if isLikelyDocumentationOnlyFinding(finding) || isLikelyInternalDevelopmentFinding(finding) {
		return true
	}
	if strings.Contains(fp.Verdict, "疑似误报") {
		return true
	}
	return strings.Contains(fp.EvidenceStrength, "弱") && !hasThreatLikeFindingSignals(finding)
}

func buildRiskCalibrationSummary(findings []plugins.Finding, base baseScanOutput, refined review.Result) riskCalibrationSummary {
	highRisk, mediumRisk, lowRisk := displayRiskCounts(refined)
	built := reviewreport.BuildRiskCalibrationSummary(reviewreport.RiskCalibrationInput{
		RiskLevel:             localizeRiskLevel(refined.Summary.RiskLevel),
		Decision:              localizeAdmission(refined.Summary.Admission),
		HighRisk:              highRisk,
		MediumRisk:            mediumRisk,
		LowRisk:               lowRisk,
		IntentDiffCount:       len(refined.IntentDiffs),
		BehaviorCategoryCount: countBehaviorEvidenceCategories(refined.Behavior),
		EvasionDetected:       refined.Evasion.Detected,
		FindingCount:          len(findings),
		EvaluatedRules:        base.evaluatedRules,
		TotalRules:            base.totalRules,
		UncheckedRules:        append([]string{}, base.uncheckedRules...),
		IntentSummaryReady:    base.intentSummary.Available,
	})
	return riskCalibrationSummary(built)
}

func buildRuleSetProfile(cfg *config.Config) ruleSetProfile {
	profile := ruleSetProfile{
		Version: cfg.Version,
		Total:   len(cfg.Rules),
		Reason:  "规则不再只作为命中列表，而是作为可解释的审查矩阵参与覆盖率、优先级、复核和整改分层。",
		Benefit: "用户能看到规则体系本身是否完整、哪些规则需要优先整改、哪些规则负责复核，从而判断报告可信度。",
	}
	layers := map[string]int{}
	severities := map[string]int{}
	detectionTypes := map[string]int{}
	for _, rule := range cfg.Rules {
		layers[defaultIfEmpty(rule.Layer, "未分层")]++
		severities[localizeSeverity(rule.Severity)]++
		detectionTypes[defaultIfEmpty(rule.Detection.Type, "unknown")]++
		label := displayRuleNameWithFallback(rule.ID, rule.Name)
		switch strings.ToLower(strings.TrimSpace(rule.OnFail.Action)) {
		case "block":
			profile.BlockedRules = append(profile.BlockedRules, label)
		case "review":
			profile.ReviewRules = append(profile.ReviewRules, label)
		}
	}
	profile.ByLayer = countMapToSortedList(layers)
	profile.BySeverity = countMapToSortedList(severities)
	profile.ByDetectionType = countMapToSortedList(detectionTypes)
	sort.Strings(profile.BlockedRules)
	sort.Strings(profile.ReviewRules)
	return profile
}

func buildRuleExplanations(cfg *config.Config) []review.RuleExplanation {
	if cfg == nil {
		return nil
	}
	out := make([]review.RuleExplanation, 0, len(cfg.Rules))
	for _, rule := range cfg.Rules {
		category := structuredFindingCategory(plugins.Finding{RuleID: rule.ID, Title: rule.Name, Description: rule.OnFail.Reason})
		criteria := mergeRuleMetadata(rule.Review.DetectionCriteria, ruleDetectionCriteria(rule))
		exclusions := mergeRuleMetadata(rule.Review.ExclusionConditions, ruleExclusionConditions(category))
		verification := mergeRuleMetadata(rule.Review.VerificationRequirements, ruleVerificationRequirements(category))
		outputs := mergeRuleMetadata(rule.Review.OutputRequirements, ruleOutputRequirements(category))
		promptSummary := strings.TrimSpace(rule.Review.PromptTemplate)
		if promptSummary == "" {
			promptSummary = buildRulePromptTemplateSummary(rule, category, criteria)
		}
		remediationFocus := strings.TrimSpace(rule.Review.RemediationFocus)
		if remediationFocus == "" {
			remediationFocus = ruleRemediationFocus(category)
		}
		out = append(out, review.RuleExplanation{
			RuleID:                   rule.ID,
			Name:                     rule.Name,
			Severity:                 rule.Severity,
			DetectionType:            rule.Detection.Type,
			Action:                   defaultIfEmpty(rule.OnFail.Action, "review"),
			DetectionCriteria:        criteria,
			ExclusionConditions:      exclusions,
			VerificationRequirements: verification,
			OutputRequirements:       outputs,
			PromptTemplateSummary:    promptSummary,
			RemediationFocus:         remediationFocus,
		})
	}
	return out
}

func mergeRuleMetadata(primary, fallback []string) []string {
	primary = sanitizeRuleMetadata(primary)
	fallback = sanitizeRuleMetadata(fallback)
	if len(primary) == 0 {
		return fallback
	}
	return uniqueStrings(append(append([]string{}, primary...), fallback...))
}

func sanitizeRuleMetadata(items []string) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		lower := strings.ToLower(trimmed)
		if trimmed == "" || trimmed == "未生成" || trimmed == "未声明" || strings.HasSuffix(lower, ": 未生成") || strings.HasSuffix(lower, ": 未声明") {
			continue
		}
		out = append(out, trimmed)
	}
	return out
}

func persistReports(store *storage.Store, taskID, username, originalName, folderName, userSkillName, declaredDescription string, findings []plugins.Finding, base baseScanOutput, refined review.Result) (string, pdfRenderTrace, error) {
	trace := pdfRenderTrace{}
	reportID, err := storage.GenerateID()
	if err != nil {
		return "", trace, err
	}
	reportCreatedAt := time.Now()
	// 优先用用户指定技能名，其次 SKILL.md name 字段，再文件夹名，最后文件名
	reportSourceName := userSkillName
	if reportSourceName == "" {
		reportSourceName = extractSkillNameFromDescription(declaredDescription)
	}
	if reportSourceName == "" {
		reportSourceName = folderName
	}
	if reportSourceName == "" {
		reportSourceName = originalName
	}
	reportBaseName := buildReportBaseName(reportSourceName, reportCreatedAt)
	htmlReport, textReport := buildPersistedReportContent(originalName, declaredDescription, findings, base, refined)
	reportFiles, err := writePersistedReportFiles(store.ReportsDir(), reportBaseName, htmlReport, textReport, findings, base, refined)
	if err != nil {
		return "", trace, err
	}
	pdfName, pdfErrMsg, pdfTrace := renderPersistedPDFReport(reportFiles)
	trace = pdfTrace
	high, medium, low := displayRiskCounts(refined)
	riskLevel, decision := decisionFromReviewedFindings(base, refined)

	user := store.GetUser(username)
	team := ""
	if user != nil {
		team = user.Team
	}

	rep := &models.Report{
		ID:               reportID,
		TaskID:           taskID,
		RequestID:        strings.TrimSpace(base.requestID),
		Status:           string(review.PhaseDone),
		Username:         username,
		Team:             team,
		FileName:         reportBaseName,
		FilePath:         reportFiles.docxName,
		HTMLPath:         reportFiles.htmlName,
		JSONPath:         reportFiles.jsonName,
		PDFPath:          pdfName,
		PDFError:         pdfErrMsg,
		CreatedAt:        reportCreatedAt.Unix(),
		FindingCount:     len(findings),
		HighRisk:         high,
		MediumRisk:       medium,
		LowRisk:          low,
		NoRisk:           len(findings) == 0,
		Score:            0,
		RiskLevel:        riskLevel,
		Decision:         decision,
		TrustScore:       refined.Summary.TrustScore,
		RiskScore:        refined.Summary.RiskScore,
		Exploitability:   refined.Summary.Exploitability,
		BusinessImpact:   refined.Summary.BusinessImpact,
		ICS:              refined.Summary.ICS,
		RuleTotal:        base.totalRules,
		RuleEvaluated:    base.evaluatedRules,
		RuleUnchecked:    len(base.uncheckedRules),
		RuleUncheckedIDs: base.uncheckedRules,
		CoverageNote:     base.coverageNote,
		ItemScores: map[string]float64{
			"rule_total":     float64(base.totalRules),
			"rule_evaluated": float64(base.evaluatedRules),
			"rule_unchecked": float64(len(base.uncheckedRules)),
		},
	}
	if task := taskStore.get(taskID); task != nil {
		rep.RequestID = strings.TrimSpace(task.RequestID)
	}

	if err := store.AddReport(rep); err != nil {
		return "", trace, err
	}
	return reportID, trace, nil
}

type persistedReportFiles struct {
	docxName string
	docxPath string
	htmlName string
	htmlPath string
	jsonName string
	jsonPath string
	pdfName  string
	pdfPath  string
}

func buildPersistedReportContent(originalName, declaredDescription string, findings []plugins.Finding, base baseScanOutput, refined review.Result) (string, string) {
	htmlReport := buildHTMLReport(originalName, declaredDescription, findings, base, refined, base.evalLogs)
	textReport := docx.TextFromHTMLReport(htmlReport)
	return htmlReport, textReport
}

func writePersistedReportFiles(reportsDir, reportBaseName, htmlReport, textReport string, findings []plugins.Finding, base baseScanOutput, refined review.Result) (persistedReportFiles, error) {
	files := persistedReportFiles{
		docxName: reportBaseName + ".docx",
		htmlName: reportBaseName + ".html",
		jsonName: reportBaseName + ".json",
		pdfName:  reportBaseName + ".pdf",
	}
	files.docxPath = filepath.Join(reportsDir, files.docxName)
	files.htmlPath = filepath.Join(reportsDir, files.htmlName)
	files.jsonPath = filepath.Join(reportsDir, files.jsonName)
	files.pdfPath = filepath.Join(reportsDir, files.pdfName)
	if err := writePersistedDocxReport(reportBaseName, htmlReport, files.docxPath); err != nil {
		return persistedReportFiles{}, err
	}
	if err := os.WriteFile(files.htmlPath, []byte(htmlReport), 0600); err != nil {
		return persistedReportFiles{}, err
	}
	if err := writePersistedJSONReport(files.jsonPath, htmlReport, textReport, findings, base, refined); err != nil {
		return persistedReportFiles{}, err
	}
	return files, nil
}

func writePersistedDocxReport(reportBaseName, htmlReport, docxPath string) error {
	gen := docx.NewGenerator()
	if err := gen.GenerateFromHTMLReport(reportBaseName, htmlReport, docxPath); err != nil {
		return err
	}
	return os.Chmod(docxPath, 0600)
}

func writePersistedJSONReport(jsonPath, htmlReport, textReport string, findings []plugins.Finding, base baseScanOutput, refined review.Result) error {
	jsonPayload := buildJSONReportPayload(htmlReport, textReport, findings, base, refined)
	jsonData, err := json.MarshalIndent(jsonPayload, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(jsonPath, jsonData, 0600)
}

func renderPersistedPDFReport(files persistedReportFiles) (string, string, pdfRenderTrace) {
	pdfTrace, err := renderPDFReport(files.htmlPath, files.docxPath, files.pdfPath)
	if err != nil {
		pdfTrace.Error = err.Error()
		return "", err.Error(), pdfTrace
	}
	// 外部工具（Chromium/LibreOffice）可能用默认权限创建 PDF，强制设为 0600
	_ = os.Chmod(files.pdfPath, 0600)
	return files.pdfName, "", pdfTrace
}

func countFindingSeverities(findings []plugins.Finding) (int, int, int) {
	high, medium, low := 0, 0, 0
	for _, f := range findings {
		switch f.Severity {
		case "高风险":
			high++
		case "中风险":
			medium++
		default:
			low++
		}
	}
	return high, medium, low
}

type pdfRenderTrace struct {
	Engine       string
	FontFile     string
	FontDir      string
	UsedFallback bool
	Error        string
}

func (t pdfRenderTrace) TraceMessage() string {
	parts := make([]string, 0, 5)
	if strings.TrimSpace(t.Engine) != "" {
		parts = append(parts, "engine="+strings.TrimSpace(t.Engine))
	}
	if strings.TrimSpace(t.FontFile) != "" {
		parts = append(parts, "font_file="+strings.TrimSpace(t.FontFile))
	}
	if strings.TrimSpace(t.FontDir) != "" {
		parts = append(parts, "font_dir="+strings.TrimSpace(t.FontDir))
	}
	if t.UsedFallback {
		parts = append(parts, "fallback=docx")
	} else {
		parts = append(parts, "fallback=none")
	}
	if strings.TrimSpace(t.Error) != "" {
		parts = append(parts, "error="+strings.TrimSpace(t.Error))
	}
	return strings.Join(parts, "; ")
}

type reportIntegritySummary struct {
	Status      string
	Issues      []string
	AutoFixes   []string
	MappingGaps []string
}

func enforceReportConsistency(findings []plugins.Finding, base baseScanOutput, refined review.Result) (baseScanOutput, review.Result, reportIntegritySummary) {
	adjustedBase := base
	adjustedRefined := refined
	adjustedRefined.StructuredFindings = append([]review.StructuredFinding(nil), refined.StructuredFindings...)
	adjustedRefined.ReviewAgentVerdicts = append([]review.ReviewAgentVerdict(nil), refined.ReviewAgentVerdicts...)
	integrity := reportIntegritySummary{Status: "passed"}
	concreteRuleIDs := concreteFindingRuleIDs(findings)

	sanitizedCachePath := strings.TrimSpace(filepath.Base(strings.ReplaceAll(adjustedBase.cacheStats.CacheFilePath, "\\", "/")))
	if sanitizedCachePath == "" {
		sanitizedCachePath = sanitizeReportText(adjustedBase.cacheStats.CacheFilePath, "")
	}
	if sanitizedCachePath != adjustedBase.cacheStats.CacheFilePath {
		adjustedBase.cacheStats.CacheFilePath = sanitizedCachePath
		integrity.AutoFixes = append(integrity.AutoFixes, "已净化增量缓存文件路径")
	}

	if downgradeConfirmedFindingsWithoutEvidence(&adjustedRefined) > 0 {
		integrity.AutoFixes = append(integrity.AutoFixes, "已将缺少代码/行为证据的 confirmed 风险降级为需人工复核")
	}
	if downgradeConfirmedFindingsWithEvidenceGaps(&adjustedRefined) > 0 {
		integrity.AutoFixes = append(integrity.AutoFixes, "已将闭环证据缺口过多的 confirmed 风险降级为需人工复核")
	}

	mergedFindings, mergedVerdicts, merged := mergeDuplicateStructuredFindings(adjustedRefined.StructuredFindings, adjustedRefined.ReviewAgentVerdicts)
	if merged > 0 {
		adjustedRefined.StructuredFindings = mergedFindings
		adjustedRefined.ReviewAgentVerdicts = mergedVerdicts
		integrity.AutoFixes = append(integrity.AutoFixes, fmt.Sprintf("已自动合并 %d 组重复主风险", merged))
	}

	structuredByKey := structuredFindingByStableKey(adjustedRefined.StructuredFindings)
	missingMappings := 0
	for _, finding := range findings {
		if !shouldRequireStructuredFindingMapping(finding, concreteRuleIDs) {
			continue
		}
		if _, ok := lookupStructuredFindingForPluginFinding(finding, structuredByKey); !ok {
			missingMappings++
			if len(integrity.MappingGaps) < 8 {
				integrity.MappingGaps = append(integrity.MappingGaps, missingMappingSummary(finding))
			}
		}
	}
	if missingMappings > 0 {
		integrity.Issues = append(integrity.Issues, fmt.Sprintf("仍有 %d 条原始风险未映射到结构化 finding", missingMappings))
	}

	duplicateGroups := countDuplicateStructuredFindingGroups(adjustedRefined.StructuredFindings)
	if duplicateGroups > 0 {
		integrity.Issues = append(integrity.Issues, fmt.Sprintf("结构化 finding 中仍有 %d 组重复主风险", duplicateGroups))
	}

	high, medium, low := countReviewedFindingRisks(findings, adjustedRefined)
	adjustedRefined.Summary.HighRisk = high
	adjustedRefined.Summary.MediumRisk = medium
	adjustedRefined.Summary.LowRisk = low

	if len(integrity.AutoFixes) > 0 && len(integrity.Issues) == 0 {
		integrity.Status = "passed_with_fixes"
	}
	if len(integrity.Issues) > 0 {
		integrity.Status = "needs_attention"
	}
	adjustedBase.coverageNote = appendReportIntegrityNote(adjustedBase.coverageNote, integrity)
	return adjustedBase, adjustedRefined, integrity
}

func missingMappingSummary(finding plugins.Finding) string {
	parts := []string{}
	if ruleID := publicRuleIDForOutput(finding.RuleID); strings.TrimSpace(ruleID) != "" {
		parts = append(parts, "规则="+ruleID)
	}
	if title := normalizeStructuredFindingTitle(finding.Title); strings.TrimSpace(title) != "" {
		parts = append(parts, "标题="+title)
	}
	if location := sanitizeReportText(finding.Location, ""); strings.TrimSpace(location) != "" {
		parts = append(parts, "位置="+location)
	}
	if len(parts) == 0 {
		return "未映射原始风险"
	}
	return strings.Join(parts, "；")
}

func shouldRequireStructuredFindingMapping(finding plugins.Finding, concreteRuleIDs map[string]struct{}) bool {
	if shouldSkipStructuredFinding(finding, concreteRuleIDs) {
		return false
	}
	if isBehaviorSummaryFinding(finding) {
		return false
	}
	if hasConcreteStructuredFindingLocation([]plugins.Finding{finding}) {
		return true
	}
	return hasConcreteStructuredFindingEvidence([]string{finding.CodeSnippet, finding.Description})
}

func downgradeConfirmedFindingsWithoutEvidence(refined *review.Result) int {
	if refined == nil {
		return 0
	}
	missingByFinding := map[string]bool{}
	for i, finding := range refined.StructuredFindings {
		if strings.TrimSpace(finding.SecurityVerdict) == "confirmed" && !structuredFindingHasConfirmedEvidence(finding) {
			refined.StructuredFindings[i].SecurityVerdict = "review"
			missingByFinding[finding.ID] = true
		}
	}
	changed := 0
	for i, verdict := range refined.ReviewAgentVerdicts {
		if strings.TrimSpace(verdict.Verdict) != "confirmed" {
			continue
		}
		if !missingByFinding[verdict.FindingID] {
			continue
		}
		refined.ReviewAgentVerdicts[i].Verdict = "needs_manual_review"
		refined.ReviewAgentVerdicts[i].Confidence = "低"
		refined.ReviewAgentVerdicts[i].Reason = "报告一致性预检发现该 finding 缺少可用于 confirmed 的代码或行为证据，已回退为需人工复核。"
		refined.ReviewAgentVerdicts[i].MissingEvidence = uniqueStrings(append(refined.ReviewAgentVerdicts[i].MissingEvidence, "报告一致性预检: 缺少可用于 confirmed 的代码或行为证据"))
		changed++
	}
	return changed
}

func structuredFindingHasConfirmedEvidence(finding review.StructuredFinding) bool {
	if strings.TrimSpace(finding.ApplicabilityVerdict) == "not_applicable" {
		return false
	}
	codeRefs := limitNonEmptyStrings(finding.CodeEvidenceRefs, 4)
	behaviorRefs := limitNonEmptyStrings(finding.BehaviorEvidenceRefs, 4)
	if len(codeRefs) > 0 || len(behaviorRefs) > 0 {
		return true
	}
	codeRefs, behaviorRefs, _ = classifyFindingEvidenceRefs(finding.Evidence)
	return len(codeRefs) > 0 || len(behaviorRefs) > 0
}

func downgradeConfirmedFindingsWithEvidenceGaps(refined *review.Result) int {
	if refined == nil {
		return 0
	}
	changed := 0
	manualByFinding := map[string]bool{}
	for i, finding := range refined.StructuredFindings {
		if strings.TrimSpace(finding.SecurityVerdict) != "confirmed" {
			continue
		}
		gaps := closureGapLabels(finding)
		if len(gaps) < 3 {
			continue
		}
		refined.StructuredFindings[i].SecurityVerdict = "review"
		manualByFinding[finding.ID] = true
		changed++
	}
	for i, verdict := range refined.ReviewAgentVerdicts {
		if strings.TrimSpace(verdict.Verdict) != "confirmed" || !manualByFinding[verdict.FindingID] {
			continue
		}
		refined.ReviewAgentVerdicts[i].Verdict = "needs_manual_review"
		refined.ReviewAgentVerdicts[i].Confidence = "低"
		refined.ReviewAgentVerdicts[i].Reason = "报告一致性预检发现 source、transform、sink、runtime 闭环证据缺口过多，已回退为需人工复核。"
		refined.ReviewAgentVerdicts[i].MissingEvidence = uniqueStrings(append(refined.ReviewAgentVerdicts[i].MissingEvidence, "报告一致性预检: confirmed 缺少完整证据链闭环"))
	}
	return changed
}

func mergeDuplicateStructuredFindings(findings []review.StructuredFinding, verdicts []review.ReviewAgentVerdict) ([]review.StructuredFinding, []review.ReviewAgentVerdict, int) {
	if len(findings) <= 1 {
		return findings, verdicts, 0
	}
	groups := map[string][]review.StructuredFinding{}
	order := make([]string, 0, len(findings))
	for _, finding := range findings {
		key := stableFindingKeyFromStructuredFinding(finding)
		if _, ok := groups[key]; !ok {
			order = append(order, key)
		}
		groups[key] = append(groups[key], finding)
	}
	if len(order) == len(findings) {
		return findings, verdicts, 0
	}
	verdictsByFinding := map[string][]review.ReviewAgentVerdict{}
	for _, verdict := range verdicts {
		verdictsByFinding[strings.TrimSpace(verdict.FindingID)] = append(verdictsByFinding[strings.TrimSpace(verdict.FindingID)], verdict)
	}
	mergedFindings := make([]review.StructuredFinding, 0, len(order))
	mergedVerdicts := make([]review.ReviewAgentVerdict, 0, len(verdicts))
	mergedCount := 0
	for i, key := range order {
		items := groups[key]
		if len(items) == 1 {
			mergedFindings = append(mergedFindings, items[0])
			mergedVerdicts = append(mergedVerdicts, verdictsByFinding[items[0].ID]...)
			continue
		}
		mergedCount++
		representative := representativeStructuredFinding(items)
		representative.ID = fmt.Sprintf("SF-%03d", i+1)
		representative.DeduplicatedCount = summedDeduplicatedCount(items)
		representative.Source = joinStructuredFindingSources(items)
		representative.SecurityVerdict = mergedStructuredFindingSecurityVerdict(items)
		representative.DeclarationVerdict = mergedStructuredFindingDeclarationVerdict(items)
		representative.Confidence = mergedStructuredFindingConfidence(items)
		representative.CodeEvidenceRefs = uniqueTypedEvidenceStrings(flattenStructuredFindingLists(items, func(item review.StructuredFinding) []string { return item.CodeEvidenceRefs }))
		representative.BehaviorEvidenceRefs = uniqueTypedEvidenceStrings(flattenStructuredFindingLists(items, func(item review.StructuredFinding) []string { return item.BehaviorEvidenceRefs }))
		representative.ContextEvidenceRefs = uniqueTypedEvidenceStrings(flattenStructuredFindingLists(items, func(item review.StructuredFinding) []string { return item.ContextEvidenceRefs }))
		representative.Evidence = uniqueStrings(flattenStructuredFindingLists(items, func(item review.StructuredFinding) []string { return item.Evidence }))
		representative.EvidenceItems = mergeStructuredEvidenceItems(items, func(item review.StructuredFinding) []review.StructuredEvidenceItem { return item.EvidenceItems })
		representative.ExcludedEvidence = mergeStructuredEvidenceItems(items, func(item review.StructuredFinding) []review.StructuredEvidenceItem { return item.ExcludedEvidence })
		representative.Closure = mergeFindingClosure(items)
		representative.ChainSummaries = uniqueStrings(flattenStructuredFindingLists(items, func(item review.StructuredFinding) []string { return item.ChainSummaries }))
		representative.ApplicabilityVerdict = mergedStructuredFindingApplicabilityVerdict(items)
		representative.ApplicabilityBasis = uniqueStrings(flattenStructuredFindingLists(items, func(item review.StructuredFinding) []string { return item.ApplicabilityBasis }))
		representative.CalibrationBasis = uniqueStrings(flattenStructuredFindingLists(items, func(item review.StructuredFinding) []string { return item.CalibrationBasis }))
		representative.FalsePositiveChecks = uniqueStrings(flattenStructuredFindingLists(items, func(item review.StructuredFinding) []string { return item.FalsePositiveChecks }))
		representative.Chains = mergeFindingChains(items)
		mergedFindings = append(mergedFindings, representative)

		collectedVerdicts := make([]review.ReviewAgentVerdict, 0, len(items))
		for _, item := range items {
			for _, verdict := range verdictsByFinding[item.ID] {
				verdict.FindingID = representative.ID
				collectedVerdicts = append(collectedVerdicts, verdict)
			}
		}
		mergedVerdicts = append(mergedVerdicts, collectedVerdicts...)
	}
	return mergedFindings, mergedVerdicts, mergedCount
}

func representativeStructuredFinding(items []review.StructuredFinding) review.StructuredFinding {
	best := items[0]
	for _, item := range items[1:] {
		if severityRank(item.Severity) < severityRank(best.Severity) {
			best = item
			continue
		}
		if severityRank(item.Severity) == severityRank(best.Severity) && structuredFindingEvidenceWeight(item) > structuredFindingEvidenceWeight(best) {
			best = item
		}
	}
	return best
}

func structuredFindingEvidenceWeight(item review.StructuredFinding) int {
	weight := 0
	if len(item.CodeEvidenceRefs) > 0 {
		weight += 3
	}
	if len(item.BehaviorEvidenceRefs) > 0 {
		weight += 2
	}
	if len(item.Evidence) > 0 {
		weight++
	}
	return weight
}

func summedDeduplicatedCount(items []review.StructuredFinding) int {
	total := 0
	for _, item := range items {
		if item.DeduplicatedCount > 0 {
			total += item.DeduplicatedCount
			continue
		}
		total++
	}
	if total == 0 {
		return len(items)
	}
	return total
}

func joinStructuredFindingSources(items []review.StructuredFinding) string {
	parts := make([]string, 0, len(items))
	seen := map[string]struct{}{}
	for _, item := range items {
		for _, source := range strings.Split(strings.TrimSpace(item.Source), "+") {
			source = strings.TrimSpace(source)
			if source == "" {
				continue
			}
			if _, ok := seen[source]; ok {
				continue
			}
			seen[source] = struct{}{}
			parts = append(parts, source)
		}
	}
	if len(parts) == 0 {
		return "规则/行为综合分析"
	}
	return strings.Join(parts, "+")
}

func mergeStructuredEvidenceItems(items []review.StructuredFinding, pick func(review.StructuredFinding) []review.StructuredEvidenceItem) []review.StructuredEvidenceItem {
	out := make([]review.StructuredEvidenceItem, 0)
	seen := map[string]struct{}{}
	for _, item := range items {
		for _, evidence := range pick(item) {
			key := normalizeEvidenceDedupKey(strings.Join([]string{evidence.Location, evidence.Snippet, evidence.Summary, evidence.SourceType, evidence.Status, evidence.Reason}, " | "))
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, evidence)
		}
	}
	return out
}

func mergeFindingClosure(items []review.StructuredFinding) review.FindingClosure {
	merged := review.FindingClosure{}
	for _, item := range items {
		merged.Source = merged.Source || item.Closure.Source
		merged.Transform = merged.Transform || item.Closure.Transform
		merged.Sink = merged.Sink || item.Closure.Sink
		merged.RuntimeSupport = merged.RuntimeSupport || item.Closure.RuntimeSupport
	}
	return merged
}

func mergedStructuredFindingApplicabilityVerdict(items []review.StructuredFinding) string {
	best := ""
	for _, item := range items {
		switch strings.TrimSpace(item.ApplicabilityVerdict) {
		case "applicable":
			return "applicable"
		case "not_applicable":
			best = "not_applicable"
		}
	}
	return best
}

func mergedStructuredFindingSecurityVerdict(items []review.StructuredFinding) string {
	best := "review"
	for _, item := range items {
		switch normalizedReviewVerdict(item.SecurityVerdict) {
		case "confirmed":
			return "confirmed"
		case "policy":
			best = "policy"
		case "needs_manual_review":
			best = "review"
		}
	}
	return best
}

func mergedStructuredFindingDeclarationVerdict(items []review.StructuredFinding) string {
	status := "declared"
	for _, item := range items {
		switch strings.TrimSpace(item.DeclarationVerdict) {
		case "undeclared":
			return "undeclared"
		case "partially_declared":
			status = "partially_declared"
		}
	}
	return status
}

func mergedStructuredFindingConfidence(items []review.StructuredFinding) string {
	best := "待复核"
	for _, item := range items {
		if confidencePriority(item.Confidence) > confidencePriority(best) {
			best = item.Confidence
		}
	}
	return best
}

func flattenStructuredFindingLists(items []review.StructuredFinding, extract func(review.StructuredFinding) []string) []string {
	out := make([]string, 0)
	for _, item := range items {
		out = append(out, extract(item)...)
	}
	return out
}

func mergeFindingChains(items []review.StructuredFinding) []review.FindingChain {
	out := make([]review.FindingChain, 0)
	for _, item := range items {
		out = append(out, item.Chains...)
	}
	return dedupeFindingChains(out)
}

func countDuplicateStructuredFindingGroups(findings []review.StructuredFinding) int {
	seen := map[string]int{}
	duplicates := 0
	for _, finding := range findings {
		key := stableFindingKeyFromStructuredFinding(finding)
		if key == "\x00\x00" || strings.TrimSpace(key) == "" {
			continue
		}
		seen[key]++
		if seen[key] == 2 {
			duplicates++
		}
	}
	return duplicates
}

func appendReportIntegrityNote(note string, integrity reportIntegritySummary) string {
	note = strings.TrimSpace(note)
	if strings.Contains(note, "报告一致性预检:") {
		return note
	}
	parts := []string{"报告一致性预检: 状态=" + integrity.Status}
	if len(integrity.AutoFixes) > 0 {
		parts = append(parts, fmt.Sprintf("自动修正 %d 项", len(integrity.AutoFixes)))
	}
	if len(integrity.Issues) > 0 {
		parts = append(parts, fmt.Sprintf("待关注 %d 项", len(integrity.Issues)))
	}
	integrityNote := strings.Join(parts, "，")
	if note == "" {
		return integrityNote
	}
	return note + "；" + integrityNote
}

func reportIntegrityPayload(integrity reportIntegritySummary) map[string]interface{} {
	return map[string]interface{}{
		"status":       integrity.Status,
		"issues":       append([]string{}, integrity.Issues...),
		"auto_fixes":   append([]string{}, integrity.AutoFixes...),
		"mapping_gaps": append([]string{}, integrity.MappingGaps...),
	}
}

func buildJSONReportPayload(htmlReport, textReport string, findings []plugins.Finding, base baseScanOutput, refined review.Result) map[string]interface{} {
	rawRiskCounts := map[string]int{
		"high":   refined.Summary.HighRisk,
		"medium": refined.Summary.MediumRisk,
		"low":    refined.Summary.LowRisk,
	}
	base, refined, integrity := enforceReportConsistency(findings, base, refined)
	riskCalibration := buildRiskCalibrationSummary(findings, base, refined)
	highRisk, mediumRisk, lowRisk := displayRiskCounts(refined)
	normalizedRiskCounts := map[string]int{
		"high":   highRisk,
		"medium": mediumRisk,
		"low":    lowRisk,
	}
	behaviorCombination := buildSingleSkillBehaviorCombination(refined)
	supplyChainSummary := buildSupplyChainSummary(refined.StructuredFindings)
	sandboxRetrySummary := buildSandboxRetrySummary(refined)
	traceMetadataSummary := buildTraceMetadataSummary(base, refined, rawRiskCounts)
	closureSummary := buildClosureSummary(refined)
	closureNarrative := buildClosureNarrative(refined)
	coverage := map[string]interface{}{
		"rule_total":         base.totalRules,
		"rule_evaluated":     base.evaluatedRules,
		"rule_unchecked":     len(base.uncheckedRules),
		"unchecked_rule_ids": base.uncheckedRules,
		"note":               base.coverageNote,
		"incremental_cache": map[string]interface{}{
			"enabled":          base.cacheStats.Enabled,
			"candidate_files":  base.cacheStats.Candidate,
			"hit_files":        base.cacheStats.Hit,
			"miss_files":       base.cacheStats.Miss,
			"missing_files":    base.cacheStats.Missing,
			"stale_files":      base.cacheStats.Stale,
			"read_error_files": base.cacheStats.ReadErrors,
			"content_reused":   base.cacheStats.ContentReused,
			"derived_reused":   base.cacheStats.DerivedReused,
			"reuse_rate":       incrementalCacheReuseRate(base.cacheStats),
			"hit_rate":         incrementalCacheHitRate(base.cacheStats),
			"cache_entries":    base.cacheStats.CacheEntries,
			"cache_version":    base.cacheStats.CacheVersion,
			"cache_file":       base.cacheStats.CacheFilePath,
			"disabled_reason":  base.cacheStats.DisabledReason,
			"load_warning":     base.cacheStats.LoadWarning,
			"save_warning":     base.cacheStats.SaveWarning,
		},
		"report_integrity": reportIntegrityPayload(integrity),
		"rule_coverage": map[string]interface{}{
			"version":                base.ruleCoverage.Version,
			"auto_total":             base.ruleCoverage.AutoTotal,
			"auto_covered":           base.ruleCoverage.AutoCovered,
			"auto_uncovered":         base.ruleCoverage.AutoUncovered,
			"auto_uncovered_samples": limitList(base.ruleCoverage.AutoUncovered, 8),
			"auto_coverage_rate":     ruleCoverageRate(base.ruleCoverage.AutoCovered, base.ruleCoverage.AutoTotal),
			"manual_total":           base.ruleCoverage.ManualTotal,
			"manual_candidates":      limitList(base.ruleCoverage.ManualCandidates, 8),
			"note":                   base.ruleCoverage.Note,
		},
		"detection_degradation": buildDetectionDegradationPayload(base.detectionErrors),
	}
	payload := reviewreport.BuildJSONReportPayload(reviewreport.JSONReportPayloadInput{
		Generator:               reportGeneratorNote,
		HTMLReport:              htmlReport,
		TextReport:              textReport,
		Result:                  refined,
		SkillAnalysisProfile:    base.profile,
		RuleSetProfile:          base.ruleProfile,
		RuleExplanations:        refined.RuleExplanations,
		AnalysisTrace:           base.trace,
		RiskCalibration:         reviewreport.RiskCalibrationSummary(riskCalibration),
		IntentAnalysis:          base.intentSummary,
		ObfuscationEvidence:     refined.ObfuscationEvidence,
		RuleEvaluationRecords:   base.evalLogs,
		DecisionLabel:           localizeAdmission(refined.Summary.Admission),
		RiskLevelLabel:          localizeRiskLevel(refined.Summary.RiskLevel),
		HighRisk:                highRisk,
		MediumRisk:              mediumRisk,
		LowRisk:                 lowRisk,
		RiskScore:               refined.Summary.RiskScore,
		Exploitability:          refined.Summary.Exploitability,
		BusinessImpact:          refined.Summary.BusinessImpact,
		RemediationSuggestions:  buildDynamicSuggestions(findings, refined),
		Coverage:                coverage,
		MITRESummary:            buildMITRESummary(refined.StructuredFindings),
		BehaviorCombination:     behaviorCombination,
		RemediationVerification: refined.RemediationVerification,
		ReviewTrace:             refined.ReviewTrace,
		ReviewAgentStats:        refined.ReviewAgentStats,
	})
	if supplyChainSummary != nil {
		payload["supply_chain_summary"] = supplyChainSummary
	}
	if sandboxRetrySummary != nil {
		payload["sandbox_retry_summary"] = sandboxRetrySummary
	}
	if httpProbeSummary := buildHTTPProbeSummary(sandboxRetrySummary); httpProbeSummary != nil {
		payload["http_probe_summary"] = httpProbeSummary
		payload["http_probe_overview"] = buildHTTPProbeOverviewPayload(httpProbeSummary)
	}
	if traceMetadataSummary != nil {
		traceMetadataSummary["closure_summary"] = closureSummary
		traceMetadataSummary["closure_narrative"] = closureNarrative
		payload["trace_metadata"] = traceMetadataSummary
	}
	if summaryCN, ok := payload["summary_cn"].(map[string]interface{}); ok {
		summaryCN["raw_risk_counts"] = rawRiskCounts
		summaryCN["normalized_risk_counts"] = normalizedRiskCounts
		summaryCN["closure_summary"] = closureSummary
		summaryCN["closure_narrative"] = closureNarrative
	}
	return payload
}

func buildClosureSummary(refined review.Result) map[string]interface{} {
	if len(refined.StructuredFindings) == 0 {
		return map[string]interface{}{
			"confirmed_count":         0,
			"total_count":             0,
			"closure_rate":            0.0,
			"missing_source_count":    0,
			"missing_transform_count": 0,
			"missing_sink_count":      0,
			"missing_runtime_count":   0,
			"top_gaps":                []string{},
			"top_gap_details":         []string{},
		}
	}
	ctx := newReviewedFindingContext(refined)
	confirmedCount := 0
	closedCount := 0
	missingSource := 0
	missingTransform := 0
	missingSink := 0
	missingRuntime := 0
	topGaps := make([]string, 0, 6)
	topGapDetails := make([]string, 0, 6)
	for _, finding := range sortStructuredFindingsByReview(refined.StructuredFindings, refined) {
		if len(closureGapLabels(finding)) == 0 {
			closedCount++
		}
		verdict := ctx.finalVerdict(finding.ID)
		if strings.EqualFold(strings.TrimSpace(verdict.Verdict), "confirmed") {
			confirmedCount++
		}
		missing := closureGapLabels(finding)
		if len(missing) == 0 {
			continue
		}
		if !finding.Closure.Source {
			missingSource++
		}
		if !finding.Closure.Transform {
			missingTransform++
		}
		if !finding.Closure.Sink {
			missingSink++
		}
		if !finding.Closure.RuntimeSupport {
			missingRuntime++
		}
		topGaps = append(topGaps, finding.ID+" / "+finding.Title+"：缺少"+strings.Join(missing, "、"))
		topGapDetails = append(topGapDetails, closureDetailForFinding(finding))
	}
	totalCount := len(refined.StructuredFindings)
	return map[string]interface{}{
		"confirmed_count":         confirmedCount,
		"closed_count":            closedCount,
		"total_count":             totalCount,
		"closure_rate":            percentRate(closedCount, totalCount),
		"missing_source_count":    missingSource,
		"missing_transform_count": missingTransform,
		"missing_sink_count":      missingSink,
		"missing_runtime_count":   missingRuntime,
		"top_gaps":                limitList(topGaps, 6),
		"top_gap_details":         limitList(topGapDetails, 6),
	}
}

func closureDetailForFinding(finding review.StructuredFinding) string {
	parts := []string{finding.ID + " / " + finding.Title}
	missing := closureGapLabels(finding)
	if len(missing) > 0 {
		parts = append(parts, "缺口="+strings.Join(missing, ","))
	}
	if len(finding.CodeEvidenceRefs) > 0 {
		parts = append(parts, "source/sink候选="+strings.Join(limitList(finding.CodeEvidenceRefs, 2), "；"))
	}
	if len(finding.BehaviorEvidenceRefs) > 0 {
		parts = append(parts, "runtime候选="+strings.Join(limitList(finding.BehaviorEvidenceRefs, 2), "；"))
	}
	if len(finding.ChainSummaries) > 0 {
		parts = append(parts, "链路="+strings.Join(limitList(finding.ChainSummaries, 2), "；"))
	}
	guidance := closureGuidanceForFinding(finding)
	if len(guidance) > 0 {
		parts = append(parts, "下一步="+strings.Join(limitList(guidance, 2), "；"))
	}
	return strings.Join(parts, " | ")
}

func closureGapLabels(finding review.StructuredFinding) []string {
	missing := make([]string, 0, 4)
	if !finding.Closure.Source {
		missing = append(missing, "source")
	}
	if !finding.Closure.Transform {
		missing = append(missing, "transform")
	}
	if !finding.Closure.Sink {
		missing = append(missing, "sink")
	}
	if !finding.Closure.RuntimeSupport {
		missing = append(missing, "runtime")
	}
	return missing
}

func closureGuidanceForFinding(finding review.StructuredFinding) []string {
	guidance := make([]string, 0, 4)
	for _, gap := range closureGapLabels(finding) {
		switch gap {
		case "source":
			guidance = append(guidance, "补充 source 证据: 明确真实入口、触发参数、配置来源或用户可控输入。")
		case "transform":
			guidance = append(guidance, "补充 transform 证据: 说明数据如何在模板、拼接、编码、序列化或中间函数中流转到风险点。")
		case "sink":
			guidance = append(guidance, "补充 sink 证据: 明确最终调用点、外联目标、执行点或落地位置。")
		case "runtime":
			guidance = append(guidance, "补充 runtime 证据: 提供沙箱复现、运行日志、探针命中或最小可执行样例。")
		}
	}
	return guidance
}

func buildClosureNarrative(refined review.Result) string {
	ctx := newReviewedFindingContext(refined)
	confirmedCategories := make([]string, 0)
	confirmedSeen := map[string]struct{}{}
	missingCounts := map[string]int{}
	for _, finding := range refined.StructuredFindings {
		verdict := ctx.finalVerdict(finding.ID)
		if strings.EqualFold(strings.TrimSpace(verdict.Verdict), "confirmed") {
			category := strings.TrimSpace(finding.Category)
			if category != "" {
				if _, ok := confirmedSeen[category]; !ok {
					confirmedSeen[category] = struct{}{}
					confirmedCategories = append(confirmedCategories, category)
				}
			}
			continue
		}
		for _, gap := range closureGapLabels(finding) {
			missingCounts[gap]++
		}
	}
	parts := make([]string, 0, 2)
	if len(confirmedCategories) > 0 {
		parts = append(parts, "本次高风险主要成立于"+strings.Join(limitList(confirmedCategories, 3), "、")+"闭环")
	}
	if len(missingCounts) > 0 {
		type pair struct {
			name  string
			count int
		}
		ordered := []pair{{"source", missingCounts["source"]}, {"transform", missingCounts["transform"]}, {"sink", missingCounts["sink"]}, {"runtime", missingCounts["runtime"]}}
		gaps := make([]string, 0, 2)
		for _, item := range ordered {
			if item.count > 0 {
				gaps = append(gaps, item.name)
			}
			if len(gaps) == 2 {
				break
			}
		}
		if len(gaps) > 0 {
			parts = append(parts, "待复核项主要缺少"+strings.Join(gaps, "与")+"证据")
		}
	}
	if len(parts) == 0 {
		return "当前未形成需要强调的闭环差异，优先结合单条 finding 复核结果判断。"
	}
	return strings.Join(parts, "；") + "。"
}

func heroDecisionText(decision string, refined review.Result) string {
	base := localizeAdmission(decision)
	if !strings.EqualFold(strings.TrimSpace(decision), "UserDecisionRequired") {
		return base
	}
	manualGaps := make(map[string]int)
	hasManual := false
	ctx := newReviewedFindingContext(refined)
	for _, finding := range refined.StructuredFindings {
		verdict := ctx.finalVerdict(finding.ID)
		if !strings.EqualFold(strings.TrimSpace(verdict.Verdict), "needs_manual_review") && strings.TrimSpace(verdict.Verdict) != "" {
			continue
		}
		hasManual = true
		for _, gap := range closureGapLabels(finding) {
			manualGaps[gap]++
		}
	}
	if !hasManual {
		return base
	}
	ordered := []string{"source", "sink", "runtime", "transform"}
	top := make([]string, 0, 2)
	for _, gap := range ordered {
		if manualGaps[gap] > 0 {
			top = append(top, gap)
		}
		if len(top) == 2 {
			break
		}
	}
	if len(top) == 0 {
		return base
	}
	return base + "（优先补 " + strings.Join(top, "/") + "）"
}

func buildHTTPProbeOverviewPayload(httpProbeSummary map[string]interface{}) map[string]interface{} {
	if httpProbeSummary == nil {
		return nil
	}
	failureReasonCounts, _ := httpProbeSummary["failure_reason_counts"].([]string)
	repairActions, _ := httpProbeSummary["probe_repair_actions"].([]string)
	matchedTargets, _ := httpProbeSummary["matched_targets"].([]string)
	missedTargets, _ := httpProbeSummary["missed_targets"].([]string)
	candidateTargets, _ := httpProbeSummary["candidate_targets"].([]string)
	pathMethodDiagnostics, _ := httpProbeSummary["path_method_diagnostics"].([]string)
	responseDigests, _ := httpProbeSummary["response_digests"].([]string)
	if len(failureReasonCounts) == 0 && len(repairActions) == 0 && len(matchedTargets) == 0 && len(missedTargets) == 0 && len(responseDigests) == 0 {
		return nil
	}
	missDiagnostics := uniqueStrings(append(append([]string{}, failureReasonCounts...), missedTargets...))
	return map[string]interface{}{
		"top_failure_reasons":   limitList(failureReasonCounts, 5),
		"failure_reason_counts": limitList(failureReasonCounts, 8),
		"probe_repair_actions":  limitList(repairActions, 8),
		"candidate_diagnostics": limitList(uniqueStrings(append(filterStringsContaining(candidateTargets, "path_methods="), pathMethodDiagnostics...)), 8),
		"response_digests":      limitList(responseDigests, 8),
		"evidence_column":       limitList(responseDigests, 8),
		"miss_reason_column":    limitList(missDiagnostics, 8),
		"repair_action_column":  limitList(repairActions, 8),
		"matched_target_count":  len(matchedTargets),
		"missed_target_count":   len(missedTargets),
	}
}

func buildHTTPProbeSummary(sandboxRetrySummary map[string]interface{}) map[string]interface{} {
	if sandboxRetrySummary == nil {
		return nil
	}
	candidates, _ := sandboxRetrySummary["http_probe_candidates"].([]string)
	misses, _ := sandboxRetrySummary["http_probe_misses"].([]string)
	results, _ := sandboxRetrySummary["http_probe_results"].([]string)
	pathMethods, _ := sandboxRetrySummary["http_probe_path_methods"].([]string)
	responseDigests, _ := sandboxRetrySummary["http_probe_response_digests"].([]string)
	reachable, _ := sandboxRetrySummary["http_probe_reachable"].([]string)
	authRequired, _ := sandboxRetrySummary["http_probe_auth_required"].([]string)
	methodMismatch, _ := sandboxRetrySummary["http_probe_method_mismatch"].([]string)
	otherStatus, _ := sandboxRetrySummary["http_probe_other_status"].([]string)
	timeoutTargets, _ := sandboxRetrySummary["http_probe_timeout"].([]string)
	startupFailedTargets, _ := sandboxRetrySummary["http_probe_startup_failed"].([]string)
	earlyExitTargets, _ := sandboxRetrySummary["http_probe_early_exit"].([]string)
	serviceUnreachableTargets, _ := sandboxRetrySummary["http_probe_service_unreachable"].([]string)
	failureReasons, _ := sandboxRetrySummary["http_probe_failure_reasons"].([]string)
	failureReasonCounts := summarizeHTTPProbeFailureReasons(failureReasons)
	repairActions := buildHTTPProbeRepairActions(failureReasonCounts)
	if len(candidates) == 0 && len(misses) == 0 && len(results) == 0 && len(reachable) == 0 && len(authRequired) == 0 && len(methodMismatch) == 0 && len(otherStatus) == 0 && len(timeoutTargets) == 0 && len(startupFailedTargets) == 0 && len(earlyExitTargets) == 0 && len(serviceUnreachableTargets) == 0 && len(failureReasons) == 0 {
		return nil
	}
	return map[string]interface{}{
		"candidate_targets":           limitList(candidates, 8),
		"missed_targets":              limitList(misses, 8),
		"matched_targets":             limitList(results, 8),
		"path_method_diagnostics":     limitList(pathMethods, 8),
		"response_digests":            limitList(responseDigests, 8),
		"reachable_targets":           limitList(reachable, 8),
		"auth_required_targets":       limitList(authRequired, 8),
		"method_mismatch_targets":     limitList(methodMismatch, 8),
		"other_status_targets":        limitList(otherStatus, 8),
		"timeout_targets":             limitList(timeoutTargets, 8),
		"startup_failed_targets":      limitList(startupFailedTargets, 8),
		"early_exit_targets":          limitList(earlyExitTargets, 8),
		"service_unreachable_targets": limitList(serviceUnreachableTargets, 8),
		"failure_reasons":             limitList(failureReasons, 8),
		"failure_reason_counts":       failureReasonCounts,
		"probe_repair_actions":        repairActions,
	}
}

func buildHTTPProbeRepairActions(reasonCounts []string) []string {
	if len(reasonCounts) == 0 {
		return nil
	}
	actions := make([]string, 0, len(reasonCounts))
	for _, item := range reasonCounts {
		reason := probeFailureReasonFromCount(item)
		if reason == "" {
			continue
		}
		if action := httpProbeRepairAction(reason); action != "" {
			actions = append(actions, action)
		}
	}
	return uniqueStrings(limitList(actions, 8))
}

func filterStringsContaining(items []string, token string) []string {
	token = strings.TrimSpace(token)
	if token == "" {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, item := range items {
		if strings.Contains(item, token) {
			out = append(out, item)
		}
	}
	return out
}

func probeFailureReasonFromCount(item string) string {
	item = strings.TrimSpace(item)
	if item == "" {
		return ""
	}
	if idx := strings.Index(item, "="); idx >= 0 {
		item = item[:idx]
	}
	return strings.TrimSpace(item)
}

func httpProbeRepairAction(reason string) string {
	switch strings.TrimSpace(reason) {
	case "probe_timeout":
		return "probe_timeout: 延长启动等待时间，确认服务启动耗时和健康检查路径，必要时拆分慢启动场景。"
	case "probe_budget_exhausted":
		return "probe_budget_exhausted: 收窄候选端口、路径和 HTTP 方法，优先保留源码提取入口与健康检查路径。"
	case "module_missing", "import_error":
		return reason + ": 补齐运行依赖或锁定 requirements/pyproject，确保沙箱入口能完成 import。"
	case "bind_failed", "address_in_use":
		return reason + ": 检查监听 host/port、端口冲突和重复启动逻辑，优先改为动态端口或单实例启动。"
	case "runtime_exception":
		return "runtime_exception: 收集启动 traceback，补齐必需环境变量、配置文件和输入样例后复测。"
	case "process_early_exit":
		return "process_early_exit: 修正启动命令或 CLI 参数，确认进程保持运行到 HTTP 探针完成。"
	case "connection_refused", "no_listener_detected", "connection_reset":
		return reason + ": 确认服务实际监听端口和路径，补充端口/路由提取规则或启动后探测等待。"
	case "dns_failure":
		return "dns_failure: 检查测试环境 DNS、代理配置和目标域名解析，必要时将外部依赖替换为可控 mock。"
	default:
		return reason + ": 保留失败样本并补充启动日志、端口列表和探针请求/响应内容。"
	}
}

func summarizeHTTPProbeFailureReasons(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	counts := map[string]int{}
	for _, item := range items {
		reason := extractProbeFailureReason(item)
		if reason == "" {
			continue
		}
		counts[reason]++
	}
	if len(counts) == 0 {
		return nil
	}
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Slice(keys, func(i, j int) bool {
		if counts[keys[i]] != counts[keys[j]] {
			return counts[keys[i]] > counts[keys[j]]
		}
		return keys[i] < keys[j]
	})
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, fmt.Sprintf("%s=%d", key, counts[key]))
	}
	return limitList(out, 8)
}

func extractProbeFailureReason(item string) string {
	const key = "reason="
	idx := strings.Index(strings.ToLower(item), key)
	if idx < 0 {
		return ""
	}
	segment := item[idx+len(key):]
	if cut := strings.Index(segment, " |"); cut >= 0 {
		segment = segment[:cut]
	}
	return strings.TrimSpace(segment)
}

func buildCapabilityProfileFromBehavior(behavior review.BehaviorProfile) *admissionmodel.CapabilityProfile {
	profile := &admissionmodel.CapabilityProfile{}
	profile.NetworkAccess = len(behavior.NetworkTargets) > 0 || len(behavior.OutboundIOCs) > 0 || len(behavior.C2BeaconIOCs) > 0
	profile.FileRead = len(behavior.FileTargets) > 0 || len(behavior.CredentialIOCs) > 0
	profile.FileWrite = len(behavior.DropIOCs) > 0 || len(behavior.PersistenceIOCs) > 0
	profile.CommandExec = len(behavior.ExecTargets) > 0 || len(behavior.ExecuteIOCs) > 0
	profile.SensitiveDataAccess = len(behavior.CredentialIOCs) > 0
	profile.ExternalFetch = len(behavior.DownloadIOCs) > 0 || len(behavior.OutboundIOCs) > 0
	profile.DataCollection = len(behavior.CollectionIOCs) > 0
	profile.Persistence = len(behavior.PersistenceIOCs) > 0
	profile.PrivilegeUse = len(behavior.PrivEscIOCs) > 0
	profile.ToolInvocation = profile.CommandExec
	profile.CapabilityScopes = buildCapabilityScopesFromBehavior(behavior, profile)
	profile.Evidence = collectBehaviorEvidence(behavior)
	profile.Normalize()
	return profile
}

func buildCapabilityScopesFromBehavior(behavior review.BehaviorProfile, profile *admissionmodel.CapabilityProfile) map[string][]string {
	scopes := map[string][]string{}
	appendScope := func(capability, scope string) {
		capability = strings.TrimSpace(capability)
		scope = strings.TrimSpace(scope)
		if capability == "" || scope == "" {
			return
		}
		scopes[capability] = uniqueNonEmptyStrings(append(scopes[capability], scope))
	}
	for _, target := range append([]string{}, append(behavior.NetworkTargets, behavior.OutboundIOCs...)...) {
		lower := strings.ToLower(strings.TrimSpace(target))
		if lower == "" {
			continue
		}
		if isPrivateOrLocalHostText(lower) {
			appendScope("network_access", "loopback")
			continue
		}
		if strings.Contains(lower, ".svc") || strings.Contains(lower, "internal") || strings.Contains(lower, "k8s") {
			appendScope("network_access", "internal_api")
			continue
		}
		appendScope("network_access", "internet")
	}
	for _, item := range behavior.C2BeaconIOCs {
		if strings.TrimSpace(item) != "" {
			appendScope("network_access", "c2_like")
		}
	}
	for _, item := range behavior.FileTargets {
		lower := strings.ToLower(strings.TrimSpace(item))
		if lower == "" {
			continue
		}
		if strings.Contains(lower, "/etc/shadow") || strings.Contains(lower, "/etc/passwd") || strings.Contains(lower, "/root/") {
			appendScope("file_read", "sensitive_system_file")
			continue
		}
		if strings.Contains(lower, ".env") || strings.Contains(lower, "config") || strings.Contains(lower, "credential") || strings.Contains(lower, "token") {
			appendScope("file_read", "config_file")
			continue
		}
		appendScope("file_read", "workspace_file")
	}
	for _, item := range behavior.CredentialIOCs {
		if strings.TrimSpace(item) != "" {
			appendScope("file_read", "credential_store")
		}
	}
	for _, item := range behavior.DownloadIOCs {
		if strings.TrimSpace(item) != "" {
			appendScope("external_fetch", "internet_payload")
		}
	}
	for _, item := range behavior.ExecTargets {
		lower := strings.ToLower(strings.TrimSpace(item))
		if lower == "" {
			continue
		}
		if strings.Contains(lower, "bash") || strings.Contains(lower, "sh ") || strings.Contains(lower, "powershell") || strings.Contains(lower, "cmd.exe") {
			appendScope("command_exec", "shell_exec")
		} else {
			appendScope("command_exec", "program_exec")
		}
	}
	if profile != nil {
		if profile.NetworkAccess && len(scopes["network_access"]) == 0 {
			appendScope("network_access", "unspecified")
		}
		if profile.FileRead && len(scopes["file_read"]) == 0 {
			appendScope("file_read", "unspecified")
		}
	}
	return scopes
}

func buildResidualRisksFromBehavior(behavior review.BehaviorProfile, profile *admissionmodel.CapabilityProfile) []admissionmodel.ResidualRisk {
	risks := make([]admissionmodel.ResidualRisk, 0, 6)
	addRisk := func(id, category, level, title, desc, mitigation string) {
		risks = append(risks, admissionmodel.ResidualRisk{ID: id, Category: category, Level: level, Title: title, Description: desc, Mitigation: mitigation})
	}
	if profile != nil && profile.NetworkAccess {
		addRisk("network-access", "网络访问", "medium", "存在外联能力", "技能具备网络访问或外联能力，后续组合使用时可能参与数据外发链路。", "收敛目标白名单并限制传输字段。")
	}
	if profile != nil && profile.CommandExec {
		addRisk("command-exec", "命令执行", "high", "存在命令执行能力", "技能具备命令执行能力，后续组合使用时可能放大执行风险。", "移除 shell 拼接并限制可执行指令集合。")
	}
	if profile != nil && profile.SensitiveDataAccess {
		addRisk("sensitive-access", "敏感数据访问", "high", "存在敏感数据访问能力", "技能具备凭据或敏感文件访问能力，组合使用时需重点关注外发链路。", "收敛访问范围并隔离凭据读取路径。")
	}
	if len(behavior.BehaviorChains) > 0 {
		addRisk("behavior-chain", "行为链", "high", "存在高风险行为链摘要", "扫描报告中已识别下载、执行、外联等高风险行为链信号。", "按链路逐项收敛能力，并复扫确认。")
	}
	if len(behavior.SequenceAlerts) > 0 {
		addRisk("sequence-alert", "时序告警", "medium", "存在高风险时序告警", "扫描报告中识别出高风险行为时序。", "核对触发前提并补充限制条件。")
	}
	return dedupeResidualRisks(risks)
}

func collectBehaviorEvidence(behavior review.BehaviorProfile) []string {
	out := make([]string, 0, 24)
	out = append(out, limitList(behavior.NetworkTargets, 2)...)
	out = append(out, limitList(behavior.OutboundIOCs, 2)...)
	out = append(out, limitList(behavior.FileTargets, 2)...)
	out = append(out, limitList(behavior.CredentialIOCs, 2)...)
	out = append(out, limitList(behavior.ExecTargets, 2)...)
	out = append(out, limitList(behavior.ExecuteIOCs, 2)...)
	out = append(out, limitList(behavior.PersistenceIOCs, 2)...)
	out = append(out, limitList(behavior.BehaviorChains, 2)...)
	out = append(out, limitList(behavior.SequenceAlerts, 2)...)
	// zeroclaw 详细数据
	if behavior.ZeroclawProcessTree != "" {
		out = append(out, "进程树: "+behavior.ZeroclawProcessTree)
	}
	out = append(out, limitList(behavior.ZeroclawCommands, 3)...)
	out = append(out, limitList(behavior.ZeroclawDNSQueries, 3)...)
	out = append(out, limitList(behavior.ZeroclawHTTPRequests, 3)...)
	if behavior.ZeroclawConsistency != "" {
		out = append(out, "声明与行为一致性: "+behavior.ZeroclawConsistency)
	}
	return uniqueNonEmptyStrings(out)
}

func dedupeResidualRisks(in []admissionmodel.ResidualRisk) []admissionmodel.ResidualRisk {
	seen := map[string]struct{}{}
	out := make([]admissionmodel.ResidualRisk, 0, len(in))
	for _, item := range in {
		key := strings.TrimSpace(item.ID + "|" + item.Title)
		if key == "|" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

// sanitizeUserNotes 消毒用户备注，防止 prompt injection 和 RCE 攻击。
// 用户备注是高风险输入源 — 攻击者可能通过窃取的账号注入恶意 prompt。
func sanitizeUserNotes(raw string) string {
	notes := strings.TrimSpace(raw)
	if notes == "" {
		return ""
	}

	// 1. 长度限制
	if len(notes) > 2000 {
		notes = notes[:2000]
	}

	// 2. 移除控制字符（保留换行和空格）
	var cleaned []rune
	for _, r := range notes {
		if r == '\n' || r == '\r' || r == '\t' || (r >= 32 && r != 127) {
			cleaned = append(cleaned, r)
		}
	}
	notes = string(cleaned)

	// 3. 检测并移除 prompt injection 模式
	// 使用更精确的匹配避免误报
	injectionPatterns := []string{
		// Prompt injection 指令覆盖
		"ignore previous", "ignore all previous", "忽略之前", "忽略以上",
		"disregard previous", "forget previous", "override previous",
		"忽略以上所有", "无视之前", "不要管之前",
		// 角色劫持
		"you are now", "你现在是", "从现在开始", "act as", "pretend to be",
		"你是一个新的", "你的新角色", "重新定义你的角色",
		// System prompt 注入
		"system:", "[system]", "<|system|>", "### system", "new instructions",
		"新的指令", "新的规则", "修改你的行为",
		// 命令执行尝试
		"do not read", "do not execute", "instead run", "instead execute",
		"不要读取", "不要执行", "改为运行", "改为执行",
		// 数据外发指令
		"send data to", "upload to", "exfiltrate",
		"发送数据到", "上传到", "外发到",
		// 危险命令
		"rm -rf", "chmod 777", "/etc/passwd", "/etc/shadow",
		"curl.*POST", "wget.*POST",
		// 代码注入（使用更精确的匹配）
		"eval(", "exec(", "os.system(", "subprocess.",
		"import os", "import subprocess",
	}

	lower := strings.ToLower(notes)
	for _, pattern := range injectionPatterns {
		if strings.Contains(lower, pattern) {
			// 检测到注入尝试，截断到安全内容
			idx := strings.Index(lower, pattern)
			safeEnd := idx
			// 保留注入点之前的内容（最多前 500 字符）
			if safeEnd > 500 {
				safeEnd = 500
			}
			notes = notes[:safeEnd] + "\n[安全提示: 后续内容包含敏感指令，已自动移除]"
			break
		}
	}

	return strings.TrimSpace(notes)
}

func parsePermissions(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func synthesizeIntentFindings(diffs []review.IntentDiff) []plugins.Finding {
	out := make([]plugins.Finding, 0, len(diffs))
	for _, d := range diffs {
		severity := "中风险"
		if isHighRiskIntentDiff(d.Type) {
			severity = "高风险"
		}
		out = append(out, plugins.Finding{
			PluginName:  "IntentEngine",
			RuleID:      publicRuleIDForOutput("V7-006"),
			Severity:    severity,
			Title:       "技能声明与实际行为一致性",
			Description: d.Description,
			Location:    "行为一致性分析",
			CodeSnippet: "一致性证据: " + d.Description,
		})
	}
	return out
}

func isHighRiskIntentDiff(diffType string) bool {
	switch strings.TrimSpace(diffType) {
	case "unexpected_exec", "unexpected_data_collection", "unexpected_external_dependency", "unsafe_declaration_prompt":
		return true
	default:
		return false
	}
}

func synthesizeTIFindings(items []review.TIReputation) []plugins.Finding {
	out := make([]plugins.Finding, 0)
	for _, it := range items {
		rep := strings.ToLower(strings.TrimSpace(it.Reputation))
		if rep == "internal" || rep == "trusted" || rep == "benign" || rep == "unknown" {
			continue
		}
		title := "敏感数据外发与隐蔽通道"
		severity := "高风险"
		if rep == "policy" {
			title = "命中黑名单目标（域名/IP）"
			severity = "中风险"
		}
		out = append(out, plugins.Finding{
			PluginName:  "ThreatIntel",
			RuleID:      publicRuleIDForOutput("V7-003"),
			Severity:    severity,
			Title:       title,
			Description: it.Reason,
			Location:    it.Target,
			CodeSnippet: "目标证据: " + defaultIfEmpty(it.Target, "未知目标") + "\n判定依据: " + defaultIfEmpty(it.Reason, "无"),
		})
	}
	return out
}

func threatIntelSemantics(rep string) string {
	switch strings.ToLower(strings.TrimSpace(rep)) {
	case "malicious", "high-risk", "suspicious":
		return "threat"
	case "policy":
		return "policy"
	case "internal":
		return "internal"
	case "trusted", "benign":
		return "benign"
	default:
		return "unknown"
	}
}

func reputationForFinding(finding review.StructuredFinding, refined review.Result) string {
	for _, item := range refined.TIReputations {
		if strings.TrimSpace(item.Target) == "" {
			continue
		}
		if strings.Contains(strings.ToLower(strings.Join(finding.Evidence, " ")), strings.ToLower(strings.TrimSpace(item.Target))) {
			return item.Reputation
		}
		if strings.EqualFold(strings.TrimSpace(finding.Title), "命中黑名单目标（域名/IP）") && threatIntelSemantics(item.Reputation) == "policy" {
			return item.Reputation
		}
	}
	return ""
}

func synthesizeEvasionFindings(evasion review.EvasionAssessment) []plugins.Finding {
	out := make([]plugins.Finding, 0)
	if !evasion.Detected {
		return out
	}
	for _, sig := range evasion.Signals {
		out = append(out, plugins.Finding{
			PluginName:  "EvasionGuard",
			RuleID:      publicRuleIDForOutput("V7-008"),
			Severity:    "高风险",
			Title:       "沙箱逃逸与提权风险",
			Description: sig,
			Location:    "差分执行与行为审计",
			CodeSnippet: "逃逸信号: " + sig,
		})
	}
	return out
}

func synthesizeBehaviorFindings(behavior review.BehaviorProfile) []plugins.Finding {
	out := make([]plugins.Finding, 0, 8)
	add := func(ruleID, severity, title string, evidence []string, location string) {
		count := len(evidence)
		if count == 0 {
			return
		}
		desc := fmt.Sprintf("检测到 %d 条行为证据，已提取关键样本用于自动复核。", count)
		snippets := limitList(evidence, 6)
		code := "行为证据摘要: " + desc
		if len(snippets) > 0 {
			code += "\n关键样本:\n- " + strings.Join(snippets, "\n- ")
		}
		resolvedLocation := location
		if first := firstEvidenceLocator(snippets); first != "" {
			resolvedLocation = first
		}
		out = append(out, plugins.Finding{
			PluginName:  "BehaviorGuard",
			RuleID:      ruleID,
			Severity:    severity,
			Title:       title,
			Description: desc,
			Location:    resolvedLocation,
			CodeSnippet: code,
		})
	}

	add(publicRuleIDForOutput("V7-001"), "高风险", "恶意代码与破坏性行为", append(append(append(append(append([]string{}, behavior.BehaviorChains...), behavior.PersistenceIOCs...), behavior.DefenseEvasionIOCs...), behavior.LateralMoveIOCs...), append(behavior.C2BeaconIOCs, behavior.SequenceAlerts...)...), "行为证据采集")
	add(publicRuleIDForOutput("V7-003"), "高风险", "敏感数据外发与隐蔽通道", append([]string{}, append(behavior.OutboundIOCs, behavior.CollectionIOCs...)...), "行为证据采集")
	add(publicRuleIDForOutput("V7-008"), "高风险", "沙箱逃逸与提权风险", append([]string{}, append(behavior.PrivEscIOCs, behavior.EvasionSignals...)...), "行为证据采集")
	add(publicRuleIDForOutput("V7-009"), "高风险", "自更新与远程下载执行", append([]string{}, append(behavior.DownloadIOCs, behavior.ExecuteIOCs...)...), "行为证据采集")
	add(publicRuleIDForOutput("V7-016"), "中风险", "凭据缓存与跨任务隔离", append([]string{}, behavior.CredentialIOCs...), "行为证据采集")

	// zeroclaw 声明与行为一致性
	if behavior.ZeroclawConsistency != "" {
		evidence := []string{
			"声明能力: " + strings.Join(behavior.ZeroclawDeclaredCaps, ", "),
			"观测能力: " + strings.Join(behavior.ZeroclawObservedCaps, ", "),
			"一致性: " + behavior.ZeroclawConsistency,
		}
		add(publicRuleIDForOutput("V7-020"), "中风险", "声明与行为一致性分析", evidence, "zeroclaw 沙箱")
	}

	return out
}

func firstEvidenceLocator(items []string) string {
	for _, item := range items {
		text := strings.TrimSpace(item)
		if text == "" {
			continue
		}
		if idx := strings.Index(text, "|"); idx > 0 {
			left := strings.TrimSpace(text[:idx])
			left = strings.TrimPrefix(left, "[sandbox-runtime]")
			left = strings.TrimSpace(left)
			if left != "" && strings.Contains(left, ":") {
				return left
			}
		}
	}
	return ""
}

func synthesizeRuleCoverageFindings(rc ruleCoverageSummary) []plugins.Finding {
	out := make([]plugins.Finding, 0)
	if rc.AutoTotal == 0 || len(rc.AutoUncovered) == 0 {
		return out
	}
	desc := "未覆盖项: " + strings.Join(rc.AutoUncovered, "；")
	out = append(out, plugins.Finding{
		PluginName:  "RuleCoverage",
		RuleID:      "RULE-AUTO-COVERAGE",
		Severity:    "高风险",
		Title:       "规则可自动评估项覆盖不足",
		Description: desc,
		Location:    "评估规则配置",
		CodeSnippet: desc,
	})
	return out
}

func structuredFindingGroupKey(finding plugins.Finding) string {
	title := normalizeStructuredFindingTitle(strings.TrimSpace(finding.Title))
	ruleID := strings.TrimSpace(finding.RuleID)
	category := structuredFindingCategory(finding)
	if title == "许可证验证配置缺陷" || title == "授权绕过风险 - 许可证校验逻辑不闭环" {
		return strings.Join([]string{"license-config", title}, "\x00")
	}
	if title == "命中黑名单目标（域名/IP）" {
		return strings.Join([]string{"policy-blacklist", title}, "\x00")
	}
	if title == "敏感数据外发与隐蔽通道" && category == "外联与情报" {
		return strings.Join([]string{"outbound-risk", title}, "\x00")
	}
	if title == "SSRF-内网探测" && category == "网络请求与SSRF" {
		return strings.Join([]string{"ssrf-risk", title}, "\x00")
	}
	if title == "远程下载执行" && category == "下载执行" {
		return strings.Join([]string{"download-execute", title}, "\x00")
	}
	if title == "外部代码仓库引入风险" {
		return strings.Join([]string{"remote-repo-risk", title}, "\x00")
	}
	if title == "外部脚本与依赖引入风险" {
		return strings.Join([]string{"supply-chain-risk", title}, "\x00")
	}
	if title == "仪表板未鉴权暴露" {
		return strings.Join([]string{"dashboard-exposure", title}, "\x00")
	}
	if title == "明文私钥配置风险" {
		return strings.Join([]string{"plaintext-private-key", title}, "\x00")
	}
	if title == "许可证本地默认服务需复核" {
		return strings.Join([]string{"license-local-default", title}, "\x00")
	}
	if title == "自动交易资金风险需复核" {
		return strings.Join([]string{"auto-trading-risk", title}, "\x00")
	}
	if title == "技能声明与实际行为一致性" && category == "声明与行为差异" {
		group := declarationFindingGroup(finding)
		return strings.Join([]string{"declaration-mismatch", group}, "\x00")
	}
	if title == "声明与交付内容需人工复核" {
		return strings.Join([]string{"delivery-mismatch", title}, "\x00")
	}
	return strings.Join([]string{ruleID, title}, "\x00")
}

type findingTitleNormalizationRule struct {
	target     string
	matchLower bool
	patterns   []string
}

var findingTitleNormalizationRules = []findingTitleNormalizationRule{
	{target: "敏感数据外发与隐蔽通道", patterns: []string{"敏感数据外发与隐蔽通道-未声明外联"}},
	{target: "远程下载执行", patterns: []string{"自更新与远程下载执行-远程下载执行", "远程下载执行"}},
	{target: "外部代码仓库引入风险", patterns: []string{"外部仓库代码投毒风险", "未经验证的远程代码仓库"}},
	{target: "外部脚本与依赖引入风险", patterns: []string{"远程脚本执行与供应链风险", "供应链攻击风险（外部脚本执行）", "依赖来源未经验证"}},
	{target: "仪表板未鉴权暴露", patterns: []string{"仪表板缺少身份验证导致未授权访问", "仪表板服务缺少认证", "仪表板监听所有网络接口且无身份验证", "仪表板未授权访问", "未授权网络服务暴露风险", "仪表板监听所有网络接口导致暴露风险", "仪表板缺乏访问控制可能导致敏感交易信息泄露", "Flask 仪表板未提及认证机制"}},
	{target: "仪表板未鉴权暴露", matchLower: true, patterns: []string{"缺乏身份验证的web仪表盘", "flask仪表盘缺乏认证可能导致未授权访问"}},
	{target: "明文私钥配置风险", patterns: []string{"私钥泄露风险", "配置文件明文存储私钥的部署设计缺陷", "私钥明文存储风险", "明文私钥存储风险"}},
	{target: "凭据外发风险需复核", matchLower: true, patterns: []string{"私钥与api凭据可能被窃取"}},
	{target: "明文凭据配置风险", patterns: []string{"敏感凭证暴露而无功能收益"}},
	{target: "声明与交付内容需人工复核", patterns: []string{"声明意图与实际行为严重不符", "欺骗性技能", "声明功能与实际代码完全不符", "声明与实际交付功能严重不符", "声明功能与交付代码严重不符", "技能包功能完全缺失", "声明与提供代码严重不一致", "声明与实际交付内容严重不符", "代码完全缺失，声明功能均未实现"}},
	{target: "技能声明与实际行为一致性", patterns: []string{"网络访问需复核", "凭据处理需复核", "命令执行需复核", "数据收集需复核", "破坏性操作需复核", "自动交易需复核"}},
	{target: "许可证本地默认服务需复核", patterns: []string{"许可证本地默认服务", "license_server", "localhost:8080", "本地默认许可证服务"}},
	{target: "自动交易资金风险需复核", patterns: []string{"未经审计的自动交易可能导致资金损失"}},
	{target: "Python 系统包安装风险", patterns: []string{"Python 环境隔离被绕过"}},
	{target: "命中黑名单目标（域名/IP）", patterns: []string{"命中黑名单目标（域名/IP）"}},
	{target: "依赖漏洞与供应链风险", patterns: []string{"命中 osv 漏洞", "依赖漏洞与供应链风险"}, matchLower: true},
}

func normalizeStructuredFindingTitle(title string) string {
	t := strings.TrimSpace(title)
	t = strings.TrimPrefix(t, "LLM检测:")
	t = strings.TrimPrefix(t, "LLM 检测:")
	t = strings.TrimSpace(t)
	lower := strings.ToLower(t)
	if strings.Contains(t, "敏感数据外发与隐蔽通道-未声明外联") {
		return "敏感数据外发与隐蔽通道"
	}
	if strings.Contains(lower, "ssrf") && strings.Contains(t, "内网探测") {
		return "SSRF-内网探测"
	}
	for _, rule := range findingTitleNormalizationRules {
		haystack := t
		if rule.matchLower {
			haystack = lower
		}
		for _, pattern := range rule.patterns {
			if strings.Contains(haystack, pattern) {
				return rule.target
			}
		}
	}
	return t
}

func concreteFindingRuleIDs(findings []plugins.Finding) map[string]struct{} {
	ruleIDs := make(map[string]struct{})
	for _, finding := range findings {
		if strings.EqualFold(strings.TrimSpace(finding.PluginName), "BehaviorGuard") {
			continue
		}
		if !isConcreteFinding(finding) {
			continue
		}
		ruleID := strings.TrimSpace(finding.RuleID)
		if ruleID == "" {
			continue
		}
		ruleIDs[ruleID] = struct{}{}
	}
	return ruleIDs
}

func shouldSkipStructuredFinding(finding plugins.Finding, concreteRuleIDs map[string]struct{}) bool {
	if !strings.EqualFold(strings.TrimSpace(finding.PluginName), "BehaviorGuard") {
		return false
	}
	if !isBehaviorSummaryFinding(finding) {
		return false
	}
	_, exists := concreteRuleIDs[strings.TrimSpace(finding.RuleID)]
	return exists
}

func isBehaviorSummaryFinding(finding plugins.Finding) bool {
	return strings.Contains(strings.TrimSpace(finding.CodeSnippet), "行为证据摘要:")
}

func isConcreteFinding(finding plugins.Finding) bool {
	location := strings.TrimSpace(finding.Location)
	joined := strings.Join([]string{finding.Location, finding.CodeSnippet, finding.Description, finding.Title}, " ")
	if location != "" && location != "未提供定位" && location != "行为证据采集" && strings.Contains(location, ":") && !isInternalScanArtifactPath(location) && !isSkippableDocumentationEvidenceText(joined) && !isPlaceholderLocatorText(joined) {
		return true
	}
	code := strings.TrimSpace(finding.CodeSnippet)
	if code != "" && !strings.HasPrefix(code, "行为证据摘要:") && !strings.HasPrefix(code, "一致性证据:") && !strings.HasPrefix(code, "目标证据:") && strings.Contains(code, "\n") && !isSkippableDocumentationEvidenceText(joined) && !isPlaceholderLocatorText(joined) {
		return true
	}
	return false
}

func buildVulnerabilityBlocks(findings []review.StructuredFinding) []review.VulnerabilityBlock {
	return reviewreport.BuildVulnerabilityBlocks(findings)
}

func buildFalsePositiveReviews(findings []review.StructuredFinding, refined review.Result) []review.FalsePositiveReview {
	reviews := make([]review.FalsePositiveReview, 0, len(findings))
	for _, finding := range findings {
		requiredFollowUp := followUpForFinding(finding, refined)
		if crossFileConsolidationAppliesToFinding(finding, refined.CrossFileConsolidation) && refined.CrossFileConsolidation != nil && len(refined.CrossFileConsolidation.MissingParts) > 0 {
			requiredFollowUp = uniqueStrings(append(requiredFollowUp, "补齐跨文件链路缺口: "+strings.Join(refined.CrossFileConsolidation.MissingParts, "/")+"。"))
		}
		reviewItem := review.FalsePositiveReview{
			FindingID:          finding.ID,
			Exploitability:     exploitabilityForFinding(finding, refined),
			Impact:             impactForFinding(finding),
			EvidenceStrength:   evidenceStrengthForFinding(finding, refined),
			ReachabilityChecks: reachabilityChecksForFinding(finding, refined),
			ExclusionChecks:    exclusionChecksForFinding(finding, refined),
			RequiredFollowUp:   requiredFollowUp,
		}
		reviewItem.Verdict = falsePositiveVerdict(reviewItem, finding, refined)
		reviews = append(reviews, reviewItem)
	}
	return reviews
}

func applyRemediationVerification(refined *review.Result, previous []review.StructuredFinding) {
	if refined == nil || len(previous) == 0 {
		return
	}
	refined.RemediationVerification = review.VerifyRemediation(review.RemediationVerificationInput{
		PreviousFindings: previous,
		CurrentFindings:  refined.StructuredFindings,
	})
}

func exploitabilityForFinding(finding review.StructuredFinding, refined review.Result) string {
	if threatIntelSemantics(reputationForFinding(finding, refined)) == "policy" {
		return "中等: 该项主要体现准入/合规策略风险，而非恶意攻击链成立。"
	}
	if hasRelevantBehaviorSupport(finding.Category, refined.Behavior) {
		return "较高: 存在行为链或高危时序证据，可支持攻击路径复核。"
	}
	if finding.Confidence == "高" {
		return "中高: 结构化证据置信度较高，但仍需确认入口可达性。"
	}
	return "待复核: 当前主要由规则命中支撑，需要补充入口、参数和运行路径证据。"
}

func impactForFinding(finding review.StructuredFinding) string {
	switch finding.Category {
	case "命令执行":
		return "可能导致任意命令执行、供应链污染或本地环境破坏。"
	case "下载执行":
		return "可能导致远程内容未经校验进入本地执行链路，形成供应链污染或任意代码执行。"
	case "凭据暴露":
		return "可能导致私钥、口令或认证凭据泄露，并进一步扩大到账户接管或后续资金风险。"
	case "恶意代码":
		return "可能组合执行、外联、落地或凭据访问行为，影响取决于具体可达链路。"
	case "外联与情报":
		return "可能导致敏感数据外发、远程控制通道或不受控第三方通信。"
	case "暴露面与未鉴权服务":
		return "可能导致未授权访问管理界面、运行状态、配置参数或调试接口，并进一步扩大到远程操控风险。"
	case "网络请求与SSRF":
		return "可能导致访问内网、本地服务或云元数据接口，并扩大到敏感信息泄露。"
	case "凭据访问":
		return "可能导致 token、密钥或认证文件泄露，并扩大到后续外联链路。"
	case "环境与构建风险":
		return "可能导致运行环境污染、依赖冲突或系统包边界被破坏，并增加后续维护与供应链风险。"
	case "授权与许可证校验":
		return "可能导致未授权用户绕过付费能力、许可证约束或运行许可校验。"
	case "持久化":
		return "可能导致技能在用户不知情情况下保留自启动或长期驻留能力。"
	case "反分析/逃逸":
		return "可能导致沙箱结果低估真实风险，需要差分执行复测。"
	case "业务自动化高风险行为":
		return "可能导致未经充分验证的自动下单、资金损失或策略误触发，需要结合业务控制与源码实现复核。"
	case "声明与行为差异":
		return "可能导致用户基于错误声明授权危险能力。"
	default:
		return "影响取决于入口可达性、权限范围和证据链完整性。"
	}
}

func evidenceStrengthForFinding(finding review.StructuredFinding, refined review.Result) string {
	score := 0
	tiSemantic := threatIntelSemantics(reputationForFinding(finding, refined))
	if len(finding.Evidence) > 0 {
		score++
	}
	if len(finding.CalibrationBasis) > 0 {
		score++
	}
	if finding.DeduplicatedCount > 1 {
		score++
	}
	if hasRelevantBehaviorSupport(finding.Category, refined.Behavior) {
		score += 2
	}
	if hasHighSignalSequenceAlert(finding.Category, refined.Behavior) {
		score++
	}
	if tiSemantic == "policy" {
		score++
	}
	if isLikelyDocumentationOnlyFinding(finding) {
		score--
	}
	switch {
	case score >= 4:
		return "强: 多源证据或行为链可互相印证。"
	case score >= 2:
		return "中: 有定位或校准依据，但仍需补充入口可达性。"
	default:
		return "弱: 证据不足，应优先人工复核并补充运行链路。"
	}
}

type evidenceTier string

const (
	evidenceTierStrong   evidenceTier = "strong"
	evidenceTierModerate evidenceTier = "moderate"
	evidenceTierWeak     evidenceTier = "weak"
)

func evidenceTierForFinding(finding review.StructuredFinding, verdict review.ReviewAgentVerdict, refined review.Result) evidenceTier {
	strength := evidenceStrengthForFinding(finding, refined)
	closure := buildFindingClosureSummary(finding, refined)
	hasClosure := closure.HasSource && closure.HasSink
	requiresRuntimeClosure := true
	switch strings.TrimSpace(finding.Category) {
	case "外联与情报", "凭据访问", "凭据暴露":
		requiresRuntimeClosure = false
	}
	hasStrongClosure := hasClosure && (closure.HasRuntimeSupport || (!requiresRuntimeClosure && closure.HasTransform))
	if strings.Contains(strength, "强") {
		if verdict.Verdict == "likely_false_positive" && isLikelyDocumentationOnlyFinding(finding) {
			return evidenceTierModerate
		}
		if !hasStrongClosure && threatIntelSemantics(reputationForFinding(finding, refined)) != "policy" {
			return evidenceTierModerate
		}
		return evidenceTierStrong
	}
	if strings.Contains(strength, "中") {
		if finding.Confidence == "高" && hasStrongClosure {
			return evidenceTierStrong
		}
		return evidenceTierModerate
	}
	return evidenceTierWeak
}

func hasHighSignalSequenceAlert(category string, behavior review.BehaviorProfile) bool {
	for _, alert := range relevantBehaviorSupport(category, behavior).alerts {
		lower := strings.ToLower(strings.TrimSpace(alert))
		if strings.Contains(lower, "下载") || strings.Contains(lower, "execute") || strings.Contains(lower, "外联") || strings.Contains(lower, "凭据") {
			return true
		}
	}
	return false
}

func isLikelyDocumentationOnlyFinding(finding review.StructuredFinding) bool {
	if len(finding.Evidence) == 0 {
		return false
	}
	docHits := 0
	for _, item := range finding.Evidence {
		if isDocumentationLikeText(item) {
			docHits++
		}
	}
	return docHits > 0 && docHits == len(finding.Evidence)
}

func isLikelyInternalDevelopmentFinding(finding review.StructuredFinding) bool {
	if len(finding.Evidence) == 0 {
		return false
	}
	internalHits := 0
	for _, item := range finding.Evidence {
		if isInternalDevelopmentLikeText(item) {
			internalHits++
		}
	}
	return internalHits > 0 && internalHits == len(finding.Evidence)
}

func hasThreatLikeFindingSignals(finding review.StructuredFinding) bool {
	joined := strings.ToLower(strings.Join(append(append([]string{finding.Title, finding.AttackPath}, finding.Evidence...), finding.ChainSummaries...), " "))
	threatSignals := []string{"命令执行", "下载后执行", "隐蔽通道", "凭据", "c2", "提权", "持久化", "外发", "exfil", "shell", "dropper", "subprocess", "os.system", "exec.command"}
	if cfg := reviewPolicyConfig(); cfg != nil {
		threatSignals = cfg.EffectiveThreatSignals(threatSignals)
	}
	for _, signal := range threatSignals {
		if strings.Contains(joined, signal) {
			return true
		}
	}
	return false
}

func reviewPolicySSRFPhrases() config.ReviewSSRFDirectConfirmation {
	fallback := config.ReviewSSRFDirectConfirmation{
		RequestCall:         []string{"requests.get", "requests.post", "httpx", "urllib"},
		UserControlledInput: []string{"target_url", "metadata", "169.254.169.254", "内网", "用户输入"},
		DangerousTarget:     []string{"metadata", "169.254.169.254", "内网"},
		MissingGuard:        []string{"缺少校验"},
	}
	if cfg := reviewPolicyConfig(); cfg != nil {
		ssrf := cfg.ScanAsync.DirectConfirmation.SSRF
		if len(ssrf.RequestCall) == 0 {
			ssrf.RequestCall = fallback.RequestCall
		}
		if len(ssrf.UserControlledInput) == 0 {
			ssrf.UserControlledInput = fallback.UserControlledInput
		}
		if len(ssrf.DangerousTarget) == 0 {
			ssrf.DangerousTarget = fallback.DangerousTarget
		}
		if len(ssrf.MissingGuard) == 0 {
			ssrf.MissingGuard = fallback.MissingGuard
		}
		return ssrf
	}
	return fallback
}

func closureSignalsForCategory(category string) config.ReviewClosureSignals {
	defaults := map[string]config.ReviewClosureSignals{
		"命令执行": {
			Source:    []string{"payload", "cmd", "command", "user input", "用户输入", "download", "下载", "requests.get", "wget", "curl", "decoded", "base64", "dropper", "写入脚本", "高危时序", "时序告警"},
			Transform: []string{"format(", "f-string", "拼接", "decode", "base64", "writefile", "tmp/", "临时文件", "command flow", "构造链"},
			Sink:      []string{"os.system", "subprocess", "exec.command", "exec(", "bash", "sh", "shell", "执行链", "执行", "run("},
		},
		"下载执行": {
			Source:    []string{"payload", "cmd", "command", "user input", "用户输入", "download", "下载", "requests.get", "wget", "curl", "decoded", "base64", "dropper", "写入脚本", "高危时序", "时序告警"},
			Transform: []string{"format(", "f-string", "拼接", "decode", "base64", "writefile", "tmp/", "临时文件", "command flow", "构造链"},
			Sink:      []string{"os.system", "subprocess", "exec.command", "exec(", "bash", "sh", "shell", "执行链", "执行", "run("},
		},
		"恶意代码": {
			Source:    []string{"payload", "cmd", "command", "user input", "用户输入", "download", "下载", "requests.get", "wget", "curl", "decoded", "base64", "dropper", "写入脚本", "高危时序", "时序告警"},
			Transform: []string{"format(", "f-string", "拼接", "decode", "base64", "writefile", "tmp/", "临时文件", "command flow", "构造链"},
			Sink:      []string{"os.system", "subprocess", "exec.command", "exec(", "bash", "sh", "shell", "执行链", "执行", "run("},
		},
		"外联与情报": {
			Source:    []string{"webhook", "target", "url", "domain", "http://", "https://", "外联", "c2", "upload", "输入来源=", "配置来源=", "目标服务=", "curl", "wget", "POST", "GET", "transfer", "备份", "同步", "云端"},
			Transform: []string{"json=", "data=", "payload", "content", "private_key", "token", "secret", "cookie", "body", "headers", "数据字段=", "敏感字段=", "Authorization", "Bearer", "sk-proj", "api_key"},
			Sink:      []string{"requests.post", "requests.get", "httpx", "urllib", "webhook", "post(", "send(", "网络链", "请求调用=", "curl", "wget", "POST", "transfer", "上传", "外发", "发送"},
		},
		"凭据访问": {
			Source:    []string{"private_key", "token", "secret", "passphrase", ".netrc", "credential", "wallet_private_key", "api_key", "Authorization", "Bearer", "sk-proj"},
			Transform: []string{"json=", "data=", "content", "headers", "config.get", "open(", "sqlite", "serialize", "load", "Authorization", "Bearer"},
			Sink:      []string{"requests.post", "webhook", "print(", "logger", "writefile", "sqlite", "signed_order", "create_order", "外发", "外联", "curl", "POST", "transfer"},
		},
		"凭据暴露": {
			Source:    []string{"private_key", "token", "secret", "passphrase", ".netrc", "credential", "wallet_private_key"},
			Transform: []string{"json=", "data=", "content", "headers", "config.get", "open(", "sqlite", "serialize", "load"},
			Sink:      []string{"requests.post", "webhook", "print(", "logger", "writefile", "sqlite", "signed_order", "create_order", "外发", "外联"},
		},
		"暴露面与未鉴权服务": {
			Source:    []string{"flask", "dashboard", "app =", "route(", "仪表板", "服务"},
			Transform: []string{"without auth", "未鉴权", "no auth", "no authentication", "未授权", "route", "debug"},
			Sink:      []string{"app.run", "listen", "0.0.0.0", "127.0.0.1", "port=", "public network", "监听"},
		},
		"网络请求与SSRF": {
			Source:    []string{"target", "url", "param", "用户输入", "metadata", "169.254.169.254", "内网", "请求参数", "来源类型=user_input", "输入来源=", "配置来源="},
			Transform: []string{"format", "f-string", "拼接", "query", "params", "headers", "redirect", "构造", "缺少校验=", "allowlist", "urljoin"},
			Sink:      []string{"requests.get", "requests.post", "httpx", "urllib", "fetch", "get(", "post(", "请求调用=", "目标服务="},
		},
		"授权与许可证校验": {
			Source:    []string{"license", "license_server", "pro_license_key", "api/validate", "许可证", "授权", "授权服务=", "配置来源="},
			Transform: []string{"verify", "validate", "status_code", "expires_at", "entitlements", "校验", "授权结果=", "缺少校验="},
			Sink:      []string{"requests.post", "api/validate", "return true", "fail open", "verify_failed", "启用受限能力", "授权调用="},
		},
		"业务自动化高风险行为": {
			Source:    []string{"wallet_private_key", "live trading", "real funds", "order_args", "自动下单", "资金", "输入来源=", "配置来源=", "敏感字段="},
			Transform: []string{"signed_order", "create_order", "order_args", "amount", "price", "side", "market", "数据字段="},
			Sink:      []string{"create_order", "place_order", "submit", "broadcast", "self.client", "交易", "订单调用="},
		},
		"勒索与加密": {
			Source:    []string{"hostname", "whoami", "uname", "系统信息", "收集", "采集", "文件", "读取", "cat", "content"},
			Transform: []string{"openssl", "encrypt", "加密", "enc ", "aes", "cipher", "base64", "编码", "压缩"},
			Sink:      []string{"curl", "wget", "POST", "transfer", "上传", "外发", "发送", "rm ", "删除", "覆写"},
		},
		"数据外发": {
			Source:    []string{"hostname", "whoami", "uname", "系统信息", "收集", "采集", "敏感数据", "个人信息", "凭据"},
			Transform: []string{"json=", "data=", "payload", "content", "headers", "序列化", "编码"},
			Sink:      []string{"curl", "wget", "POST", "transfer", "上传", "外发", "发送", "requests.post", "httpx"},
		},
	}
	if cfg := reviewPolicyConfig(); cfg != nil {
		signals := cfg.ClosureSignals(category)
		fallback := defaults[strings.TrimSpace(category)]
		if len(signals.Source) == 0 {
			signals.Source = fallback.Source
		}
		if len(signals.Transform) == 0 {
			signals.Transform = fallback.Transform
		}
		if len(signals.Sink) == 0 {
			signals.Sink = fallback.Sink
		}
		return signals
	}
	return defaults[strings.TrimSpace(category)]
}

type directConfirmationRule struct {
	category string
	match    func(finding review.StructuredFinding, refined review.Result, joined string, hasBehaviorSupport bool) bool
}

type findingClosureSummary struct {
	HasSource         bool
	HasTransform      bool
	HasSink           bool
	HasRuntimeSupport bool
}

func (s findingClosureSummary) toReviewFindingClosure() review.FindingClosure {
	return review.FindingClosure{
		Source:         s.HasSource,
		Transform:      s.HasTransform,
		Sink:           s.HasSink,
		RuntimeSupport: s.HasRuntimeSupport,
	}
}

var directConfirmationRules = []directConfirmationRule{
	{
		category: "网络请求与SSRF",
		match: func(finding review.StructuredFinding, refined review.Result, joined string, hasBehaviorSupport bool) bool {
			ssrf := reviewPolicySSRFPhrases()
			hasRequestCall := containsAny(joined, ssrf.RequestCall) || containsStructuredFindingSignal(finding, "请求调用=")
			hasUserControlledInput := containsAny(joined, ssrf.UserControlledInput) || containsStructuredFindingSignalValue(finding, "来源类型=", "user_input")
			hasDangerousTarget := containsAny(joined, ssrf.DangerousTarget) || containsStructuredFindingSignal(finding, "危险目标=")
			hasMissingGuard := containsAny(joined, ssrf.MissingGuard) || containsStructuredFindingSignal(finding, "缺少校验=")
			return hasRequestCall && hasUserControlledInput && hasDangerousTarget && (hasMissingGuard || hasBehaviorSupport)
		},
	},
	{
		category: "外联与情报",
		match: func(finding review.StructuredFinding, refined review.Result, joined string, hasBehaviorSupport bool) bool {
			closure := buildFindingClosureSummary(finding, refined)
			if threatIntelSemantics(reputationForFinding(finding, refined)) == "threat" {
				return true
			}
			return closure.HasSource && closure.HasSink && (closure.HasRuntimeSupport || closure.HasTransform)
		},
	},
	{
		category: "命令执行",
		match: func(finding review.StructuredFinding, refined review.Result, joined string, hasBehaviorSupport bool) bool {
			closure := buildFindingClosureSummary(finding, refined)
			return closure.HasSource && closure.HasSink && closure.HasRuntimeSupport
		},
	},
	{
		category: "下载执行",
		match: func(finding review.StructuredFinding, refined review.Result, joined string, hasBehaviorSupport bool) bool {
			closure := buildFindingClosureSummary(finding, refined)
			return closure.HasSource && closure.HasSink && closure.HasRuntimeSupport
		},
	},
	{
		category: "恶意代码",
		match: func(finding review.StructuredFinding, refined review.Result, joined string, hasBehaviorSupport bool) bool {
			closure := buildFindingClosureSummary(finding, refined)
			return closure.HasSource && closure.HasSink && closure.HasRuntimeSupport
		},
	},
	{
		category: "凭据访问",
		match: func(finding review.StructuredFinding, refined review.Result, joined string, hasBehaviorSupport bool) bool {
			closure := buildFindingClosureSummary(finding, refined)
			return closure.HasSource && closure.HasSink && (closure.HasRuntimeSupport || closure.HasTransform)
		},
	},
	{
		category: "凭据暴露",
		match: func(finding review.StructuredFinding, refined review.Result, joined string, hasBehaviorSupport bool) bool {
			closure := buildFindingClosureSummary(finding, refined)
			return closure.HasSource && closure.HasSink && (closure.HasRuntimeSupport || closure.HasTransform)
		},
	},
	{
		category: "暴露面与未鉴权服务",
		match: func(finding review.StructuredFinding, refined review.Result, joined string, hasBehaviorSupport bool) bool {
			closure := buildFindingClosureSummary(finding, refined)
			return closure.HasSource && closure.HasSink && (closure.HasRuntimeSupport || strings.Contains(joined, "0.0.0.0"))
		},
	},
}

func containsStructuredFindingSignal(finding review.StructuredFinding, prefix string) bool {
	for _, group := range [][]string{finding.CodeEvidenceRefs, finding.ContextEvidenceRefs, finding.Evidence} {
		for _, item := range group {
			if strings.HasPrefix(strings.TrimSpace(item), prefix) {
				return true
			}
		}
	}
	return false
}

func containsStructuredFindingSignalValue(finding review.StructuredFinding, prefix, want string) bool {
	want = strings.ToLower(strings.TrimSpace(want))
	if want == "" {
		return false
	}
	for _, group := range [][]string{finding.CodeEvidenceRefs, finding.ContextEvidenceRefs, finding.Evidence} {
		for _, item := range group {
			item = strings.TrimSpace(item)
			if !strings.HasPrefix(item, prefix) {
				continue
			}
			value := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(item, prefix)))
			if value == want {
				return true
			}
		}
	}
	return false
}

func buildFindingClosureSummary(finding review.StructuredFinding, refined review.Result) findingClosureSummary {
	joined := strings.ToLower(strings.Join(append(append(append(append(append([]string{finding.Title, finding.AttackPath, finding.Category}, finding.Evidence...), finding.CodeEvidenceRefs...), finding.BehaviorEvidenceRefs...), append(finding.ContextEvidenceRefs, finding.ChainSummaries...)...), finding.CalibrationBasis...), " "))
	summary := findingClosureSummary{
		HasRuntimeSupport: hasRelevantBehaviorSupport(finding.Category, refined.Behavior) || len(finding.BehaviorEvidenceRefs) > 0 || len(finding.ChainSummaries) > 0 || containsAny(joined, []string{"高危时序", "时序告警", "behaviorguard", "真实请求", "可控目标", "runtime=", "沙箱=", "探针=", "http_probe", "scenario=", "exit="}),
	}
	if signals := closureSignalsForCategory(finding.Category); len(signals.Source)+len(signals.Transform)+len(signals.Sink) > 0 {
		summary.HasSource = containsAny(joined, signals.Source)
		summary.HasTransform = containsAny(joined, signals.Transform)
		summary.HasSink = containsAny(joined, signals.Sink)
	}
	if !summary.HasSource {
		summary.HasSource = hasClosureEvidenceRole(finding, "source")
	}
	if !summary.HasTransform {
		summary.HasTransform = hasClosureEvidenceRole(finding, "transform")
	}
	if !summary.HasSink {
		summary.HasSink = hasClosureEvidenceRole(finding, "sink")
	}
	if !summary.HasRuntimeSupport {
		summary.HasRuntimeSupport = hasClosureEvidenceRole(finding, "runtime")
	}
	return summary
}

func hasClosureEvidenceRole(finding review.StructuredFinding, role string) bool {
	texts := closureEvidenceTexts(finding)
	if len(texts) == 0 {
		return false
	}
	signals := genericClosureRoleSignals(role)
	if len(signals) == 0 {
		return false
	}
	for _, text := range texts {
		if containsAny(strings.ToLower(text), signals) {
			return true
		}
	}
	return false
}

func closureEvidenceTexts(finding review.StructuredFinding) []string {
	texts := make([]string, 0, len(finding.Evidence)+len(finding.CodeEvidenceRefs)+len(finding.BehaviorEvidenceRefs)+len(finding.ContextEvidenceRefs)+len(finding.ChainSummaries)+len(finding.CalibrationBasis)+len(finding.EvidenceItems))
	texts = append(texts, finding.Evidence...)
	texts = append(texts, finding.CodeEvidenceRefs...)
	texts = append(texts, finding.BehaviorEvidenceRefs...)
	texts = append(texts, finding.ContextEvidenceRefs...)
	texts = append(texts, finding.ChainSummaries...)
	texts = append(texts, finding.CalibrationBasis...)
	for _, item := range finding.EvidenceItems {
		texts = append(texts, strings.Join([]string{item.Location, item.Snippet, item.Summary, item.SourceType}, " "))
	}
	return limitNonEmptyStrings(texts, 64)
}

func genericClosureRoleSignals(role string) []string {
	switch role {
	case "source":
		return []string{"输入来源=", "来源类型=", "配置来源=", "敏感字段=", "数据字段=", "request.args", "request.json", "request.form", "request.get_json", "sys.argv", "argparse", "click.option", "input(", "os.getenv", "getenv", "config[", "config.get", ".env", "wallet_private_key", "license_server", "target_url", "webhook", "token", "secret", "private_key", "hostname", "whoami", "uname", "系统信息", "收集", "采集"}
	case "transform":
		return []string{"缺少校验=", "授权结果=", "payload", "json=", "data=", "params=", "headers=", "format(", "f-string", "拼接", "urljoin", "base64", "decode", "encode", "serialize", "signed_order", "create_order", "validate", "verify", "status_code", "openssl", "encrypt", "加密", "enc ", "aes", "cipher"}
	case "sink":
		return []string{"请求调用=", "执行调用=", "订单调用=", "授权调用=", "目标服务=", "requests.get", "requests.post", "httpx", "urllib", "fetch(", "subprocess", "os.system", "exec.command", "exec(", "eval(", "app.run", "listen", "create_order", "place_order", "submit", "broadcast", "webhook", "api/validate", "open(", "write(", "curl", "wget", "POST", "GET", "transfer", "上传", "外发", "发送"}
	case "runtime":
		return []string{"runtime=", "沙箱=", "探针=", "http_probe", "scenario=", "exit=", "关键样本", "行为链", "行为证据", "sequence_alert:", "behavior_chain:", "时序", "真实请求", "可控目标", "zeroclaw", "agent", "bash", "执行", "运行"}
	default:
		return nil
	}
}

func isDirectlyConfirmedFinding(finding review.StructuredFinding, refined review.Result) bool {
	if len(finding.Evidence) == 0 {
		return false
	}
	if isLikelyDocumentationOnlyFinding(finding) || isLikelyInternalDevelopmentFinding(finding) {
		return false
	}
	joined := strings.ToLower(strings.Join(append([]string{finding.Title, finding.AttackPath, finding.Category}, append(finding.Evidence, finding.ChainSummaries...)...), " "))
	hasBehaviorSupport := hasRelevantBehaviorSupport(finding.Category, refined.Behavior) || len(finding.ChainSummaries) > 0 || len(finding.CalibrationBasis) > 0
	for _, rule := range directConfirmationRules {
		if rule.category != finding.Category {
			continue
		}
		if rule.match(finding, refined, joined, hasBehaviorSupport) {
			return true
		}
	}
	return false
}

func reachabilityChecksForFinding(finding review.StructuredFinding, refined review.Result) []string {
	checks := []string{
		"确认风险代码所在文件是否属于技能发布包和主执行路径。",
		"确认用户输入、配置或模型输出是否能到达该风险点。",
	}
	if contextCheck := contextualReviewHintForFinding(finding); contextCheck != "" {
		checks = append(checks, contextCheck)
	}
	if hasRelevantBehaviorSupport(finding.Category, refined.Behavior) {
		checks = append(checks, "沙箱已记录与当前风险相关的行为链或时序，可优先沿该链路回溯入口。")
	} else {
		checks = append(checks, "沙箱未记录对应时序时，不应直接视为无风险；需检查条件触发和动态拼接。")
	}
	if finding.Category == "声明与行为差异" {
		checks = append(checks, "将 SKILL.md、manifest、权限声明和源码行为放在同一链路中复核。")
	}
	return checks
}

func exclusionChecksForFinding(finding review.StructuredFinding, refined review.Result) []string {
	checks := append([]string{}, finding.FalsePositiveChecks...)
	checks = append(checks, "若证据位于文档、注释、测试或示例文件，需继续确认其是否会被打包、引用、解析或动态加载，不能仅凭路径名排除。")
	if contextCheck := contextualReviewHintForFinding(finding); contextCheck != "" {
		checks = append(checks, contextCheck)
	}
	for _, rule := range refined.RuleExplanations {
		if rule.RuleID == finding.RuleID {
			checks = append(checks, limitList(rule.ExclusionConditions, 3)...)
			break
		}
	}
	return uniqueStrings(limitList(checks, 6))
}

func followUpForFinding(finding review.StructuredFinding, refined review.Result) []string {
	followUp := []string{
		"补充最小复现路径: 入口 -> 参数/配置 -> 风险点 -> 影响。",
		"复核文档、注释、测试或示例中的相关内容是否会被实际引用、打包、解析或动态加载。",
	}
	followUp = append(followUp, closureGuidanceForFinding(finding)...)
	if contextFollowUp := contextualFollowUpHintForFinding(finding); contextFollowUp != "" {
		followUp = append(followUp, contextFollowUp)
	}
	if finding.Confidence != "高" {
		followUp = append(followUp, "当前置信度不是高，建议补充沙箱触发样例或源码调用链。")
	}
	if len(refined.Behavior.ProbeWarnings) > 0 {
		followUp = append(followUp, "存在沙箱探针告警，需确认未触发是否由条件执行、动态拼接或探针覆盖不足导致。")
	}
	return uniqueStrings(followUp)
}

func contextualReviewHintForFinding(finding review.StructuredFinding) string {
	if isLikelyDocumentationOnlyFinding(finding) {
		return "当前证据主要位于文档、示例或测试上下文，需优先确认该文件是否会进入发布包、运行镜像或动态加载链路。"
	}
	if isLikelyInternalDevelopmentFinding(finding) {
		return "当前证据主要位于本地开发、sandbox 或调试语境，需优先确认该路径或配置是否会进入真实发布链路。"
	}
	return ""
}

func contextualFollowUpHintForFinding(finding review.StructuredFinding) string {
	if isLikelyDocumentationOnlyFinding(finding) {
		return "补充发布物清单或构建产物证明，确认文档、示例或测试内容不会进入真实运行链路。"
	}
	if isLikelyInternalDevelopmentFinding(finding) {
		return "补充环境隔离或发布配置证明，确认本地开发、sandbox 或调试路径不会进入生产或交付包。"
	}
	return ""
}

func falsePositiveVerdict(item review.FalsePositiveReview, finding review.StructuredFinding, refined review.Result) string {
	joined := strings.Join(append(append(item.ReachabilityChecks, item.ExclusionChecks...), item.RequiredFollowUp...), " ")
	closure := buildFindingClosureSummary(finding, refined)
	requiresRuntimeClosure := true
	switch strings.TrimSpace(finding.Category) {
	case "外联与情报", "凭据访问", "凭据暴露":
		requiresRuntimeClosure = false
	}
	hasStrongClosure := closure.HasSource && closure.HasSink && (closure.HasRuntimeSupport || (!requiresRuntimeClosure && closure.HasTransform))
	if isLikelyInternalDevelopmentFinding(finding) && !hasThreatLikeFindingSignals(finding) {
		return "疑似误报: 当前证据主要指向本地开发或环回调用，除非能证明会进入真实发布链路，否则不应按恶意外联处理。"
	}
	if strings.Contains(item.EvidenceStrength, "强") && strings.Contains(item.Exploitability, "较高") && hasStrongClosure && !isLikelyDocumentationOnlyFinding(finding) {
		return "倾向真实风险: 建议优先修复并复扫。"
	}
	if strings.Contains(item.EvidenceStrength, "强") && !hasStrongClosure && !isLikelyDocumentationOnlyFinding(finding) {
		return "待人工复核: 当前证据强度较高，但链路闭环仍缺少入口、落点或运行支撑，需补齐后再确认。"
	}
	hasConfirmedExclusion := strings.Contains(joined, "已确认") && (strings.Contains(joined, "不会进入发布包") || strings.Contains(joined, "不会被动态加载") || strings.Contains(joined, "不会被引用"))
	if (strings.Contains(item.EvidenceStrength, "弱") || isLikelyDocumentationOnlyFinding(finding)) && hasConfirmedExclusion {
		return "疑似误报: 已有排除线索，但仍建议保留证据并复核发布路径。"
	}
	if isLikelyDocumentationOnlyFinding(finding) && !hasThreatLikeFindingSignals(finding) {
		return "疑似误报: 当前证据主要来自文档、注释或示例内容，若无真实调用链与发布路径支撑，不应直接按漏洞确认。"
	}
	return "待人工复核: 证据可疑但仍需确认可达性、影响和排除条件。"
}

func structuredFindingCalibration(category string, items []plugins.Finding, refined review.Result) (string, []string) {
	basis := make([]string, 0, 6)
	confidenceScore := 1
	joinedText := strings.ToLower(strings.Join(flattenStructuredFindingTexts(items), " "))
	if isDocumentationOrInternalContextText(joinedText) {
		basis = append(basis, "当前证据主要位于文档、示例、测试或开发态上下文，优先按低优先级线索处理并保留人工复核。")
		confidenceScore = 0
	}
	if len(items) > 1 {
		confidenceScore++
		basis = append(basis, fmt.Sprintf("同类证据命中 %d 次，已合并展示", len(items)))
	}
	support := relevantBehaviorSupport(category, refined.Behavior)
	if len(support.chains) > 0 {
		confidenceScore += 2
		basis = append(basis, "存在与当前风险相关的高风险行为链，静态发现与运行行为可相互印证")
	}
	if len(support.alerts) > 0 {
		confidenceScore += 2
		basis = append(basis, "存在与当前风险相关的高危时序告警，可支持攻击路径成立性复核")
	}
	if len(support.httpProbes) > 0 {
		confidenceScore++
		basis = append(basis, "存在 HTTP 探针命中与响应摘要，可支持运行时可达性复核")
	}
	if len(support.runtimeNotes) > 0 {
		basis = append(basis, "存在运行时探针诊断信息，可辅助判断入口、端口和响应闭环")
	}
	if category == "外联与情报" && len(refined.TIReputations) > 0 {
		confidenceScore++
		basis = append(basis, "存在外联目标信誉信息，可用于区分普通网络访问与可疑目标")
	}
	if category == "声明与行为差异" && len(refined.IntentDiffs) > 0 {
		confidenceScore++
		basis = append(basis, "存在声明与实际行为差异，需结合权限声明复核")
	}
	if category == "反分析/逃逸" && refined.Evasion.Detected {
		confidenceScore += 2
		basis = append(basis, "差分执行或逃逸信号已触发，需优先复测")
	}
	if len(basis) == 0 {
		basis = append(basis, "当前主要由规则命中和证据片段支撑，需人工验证入口可达性")
	}
	switch {
	case confidenceScore >= 4:
		return "高", basis
	case confidenceScore >= 2:
		return "中", basis
	default:
		return "待复核", basis
	}
}

func flattenStructuredFindingTexts(items []plugins.Finding) []string {
	out := make([]string, 0, len(items)*4)
	for _, item := range items {
		out = append(out, item.Title, item.Description, item.Location, item.CodeSnippet)
	}
	return out
}

func structuredFindingChainSummaries(category string, behavior review.BehaviorProfile, obfuscationChains []review.FindingChain) []string {
	support := relevantBehaviorSupport(category, behavior)
	out := make([]string, 0, 4)
	out = appendLabeledSummaryItems(out, "行为链", support.chains)
	out = appendLabeledSummaryItems(out, "时序告警", support.alerts)
	out = appendLabeledSummaryItems(out, "HTTP探针", support.httpProbes)
	out = appendLabeledSummaryItems(out, "运行诊断", support.runtimeNotes)
	for _, chain := range obfuscationChains {
		summary := strings.TrimSpace(chain.Summary)
		if summary == "" {
			continue
		}
		out = append(out, "混淆传播: "+summary)
	}
	return uniqueStrings(out)
}

func appendLabeledSummaryItems(out []string, label string, items []string) []string {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, label+": "+item)
	}
	return out
}

func structuredFindingChains(category string, behavior review.BehaviorProfile, obfuscationChains []review.FindingChain) []review.FindingChain {
	support := relevantBehaviorSupport(category, behavior)
	out := make([]review.FindingChain, 0, 4+len(obfuscationChains))
	for _, item := range support.chains {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		source := item
		path := ""
		if pipe := strings.Index(item, "|"); pipe > 0 {
			source = strings.TrimSpace(item[:pipe])
		}
		path = filepath.ToSlash(strings.TrimSpace(chainSourcePath(source)))
		out = append(out, review.FindingChain{Kind: "behavior_chain", Summary: item, Source: source, Path: path})
	}
	for _, item := range support.alerts {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, review.FindingChain{Kind: "sequence_alert", Summary: item})
	}
	for _, item := range support.httpProbes {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, review.FindingChain{Kind: "http_probe", Summary: item})
	}
	for _, item := range support.runtimeNotes {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		out = append(out, review.FindingChain{Kind: "runtime_observation", Summary: item})
	}
	out = append(out, obfuscationChains...)
	return dedupeFindingChains(out)
}

type codeEvidenceWindow struct {
	path     string
	start    int
	end      int
	hitLines map[int]bool
	lines    map[int]string
}

func newCodeEvidenceWindow(item plugins.Finding, sourceIndex map[string][]string) (codeEvidenceWindow, bool) {
	path, line, ok := parseSourceLocation(item.Location)
	if !ok {
		return codeEvidenceWindow{}, false
	}
	if window, ok := buildWindowFromSourceIndex(path, line, sourceIndex); ok {
		return window, true
	}
	lines := normalizeCodeSnippetLines(item.CodeSnippet)
	if len(lines) == 0 {
		return codeEvidenceWindow{}, false
	}
	window := codeEvidenceWindow{
		path:     path,
		start:    line,
		end:      line + len(lines) - 1,
		hitLines: map[int]bool{line: true},
		lines:    make(map[int]string, len(lines)),
	}
	for idx, snippetLine := range lines {
		window.lines[line+idx] = snippetLine
	}
	return window, true
}

func buildWindowFromSourceIndex(path string, hitLine int, sourceIndex map[string][]string) (codeEvidenceWindow, bool) {
	if len(sourceIndex) == 0 {
		return codeEvidenceWindow{}, false
	}
	lines, ok := sourceIndex[filepath.ToSlash(strings.TrimSpace(path))]
	if !ok || hitLine <= 0 || hitLine > len(lines) {
		return codeEvidenceWindow{}, false
	}
	start := hitLine - 3
	if start < 1 {
		start = 1
	}
	end := hitLine + 3
	if end > len(lines) {
		end = len(lines)
	}
	window := codeEvidenceWindow{
		path:     filepath.ToSlash(strings.TrimSpace(path)),
		start:    start,
		end:      end,
		hitLines: map[int]bool{hitLine: true},
		lines:    make(map[int]string, end-start+1),
	}
	for lineNo := start; lineNo <= end; lineNo++ {
		window.lines[lineNo] = lines[lineNo-1]
	}
	return window, true
}

func parseSourceLocation(location string) (string, int, bool) {
	return reviewreport.ParseSourceLocation(location)
}

func normalizeCodeSnippetLines(snippet string) []string {
	snippet = strings.ReplaceAll(snippet, "\r\n", "\n")
	rawLines := strings.Split(snippet, "\n")
	for len(rawLines) > 0 && strings.TrimSpace(rawLines[0]) == "" {
		rawLines = rawLines[1:]
	}
	for len(rawLines) > 0 && strings.TrimSpace(rawLines[len(rawLines)-1]) == "" {
		rawLines = rawLines[:len(rawLines)-1]
	}
	if len(rawLines) == 0 {
		return nil
	}
	return rawLines
}

func mergeCodeEvidenceWindows(windows []codeEvidenceWindow) []codeEvidenceWindow {
	if len(windows) == 0 {
		return nil
	}
	sorted := append([]codeEvidenceWindow(nil), windows...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].path == sorted[j].path {
			if sorted[i].start == sorted[j].start {
				return sorted[i].end < sorted[j].end
			}
			return sorted[i].start < sorted[j].start
		}
		return sorted[i].path < sorted[j].path
	})
	merged := []codeEvidenceWindow{sorted[0]}
	for _, current := range sorted[1:] {
		last := &merged[len(merged)-1]
		if last.path == current.path && current.start <= last.end+1 {
			mergeIntoCodeEvidenceWindow(last, current)
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func mergeIntoCodeEvidenceWindow(dst *codeEvidenceWindow, src codeEvidenceWindow) {
	if src.start < dst.start {
		dst.start = src.start
	}
	if src.end > dst.end {
		dst.end = src.end
	}
	for line, value := range src.lines {
		if _, exists := dst.lines[line]; !exists {
			dst.lines[line] = value
		}
	}
	for line := range src.hitLines {
		dst.hitLines[line] = true
	}
}

func renderMergedCodeEvidence(window codeEvidenceWindow) string {
	lineNumbers := make([]int, 0, len(window.lines))
	for line := range window.lines {
		lineNumbers = append(lineNumbers, line)
	}
	sort.Ints(lineNumbers)
	var b strings.Builder
	b.WriteString(window.path)
	b.WriteString(":")
	b.WriteString(strconv.Itoa(window.start))
	if window.end > window.start {
		b.WriteString("-")
		b.WriteString(strconv.Itoa(window.end))
	}
	for _, line := range lineNumbers {
		marker := "  "
		if window.hitLines[line] {
			marker = "> "
		}
		b.WriteString("\n")
		b.WriteString(fmt.Sprintf("%s%4d | %s", marker, line, window.lines[line]))
	}
	return b.String()
}

func structuredFindingCategory(f plugins.Finding) string {
	text := strings.ToLower(strings.Join([]string{f.RuleID, f.Title, f.Description}, " "))
	normalizedTitle := normalizeStructuredFindingTitle(f.Title)
	switch {
	case normalizedTitle == "技能声明与实际行为一致性":
		return "声明与行为差异"
	case normalizedTitle == "声明与交付内容需人工复核":
		return "静态规则发现"
	case normalizedTitle == "自动交易资金风险需复核":
		return "业务自动化高风险行为"
	case normalizedTitle == "仪表板未鉴权暴露":
		return "暴露面与未鉴权服务"
	case normalizedTitle == "明文私钥配置风险":
		return "凭据暴露"
	case normalizedTitle == "外部脚本与依赖引入风险":
		return "环境与构建风险"
	case normalizedTitle == "依赖漏洞与供应链风险":
		return "环境与构建风险"
	case normalizedTitle == "许可证本地默认服务需复核":
		return "授权与许可证校验"
	case strings.Contains(text, "仪表板") || strings.Contains(text, "dashboard") || strings.Contains(text, "flask") || strings.Contains(text, "监听所有网络接口") || strings.Contains(text, "无身份验证"):
		return "暴露面与未鉴权服务"
	case strings.Contains(text, "敏感凭证暴露") || strings.Contains(text, "private key") || strings.Contains(text, "wallet_private_key") || strings.Contains(text, "无功能收益"):
		return "凭据暴露"
	case strings.Contains(text, "break-system-packages") || strings.Contains(text, "pep 668") || strings.Contains(text, "python 环境隔离") || strings.Contains(text, "pip3 install"):
		return "环境与构建风险"
	case strings.Contains(text, "osv") || strings.Contains(text, "ghsa-") || strings.Contains(text, "依赖漏洞"):
		return "环境与构建风险"
	case strings.Contains(text, "许可证") || strings.Contains(text, "授权绕过") || strings.Contains(text, "授权校验") || strings.Contains(text, "license") || strings.Contains(text, "licence"):
		return "授权与许可证校验"
	case (strings.Contains(text, "ssrf") || strings.Contains(text, "内网探测")) && !strings.Contains(text, "license_server"):
		return "网络请求与SSRF"
	case strings.Contains(text, "metadata") || strings.Contains(text, "169.254.169.254"):
		return "网络请求与SSRF"
	case strings.Contains(text, "自动交易") || strings.Contains(text, "下单") || strings.Contains(text, "create_order") || strings.Contains(text, "资金损失") || strings.Contains(text, "live trading"):
		return "业务自动化高风险行为"
	case strings.Contains(text, "外联") || strings.Contains(text, "外发") || strings.Contains(text, "隐蔽通道") || strings.Contains(text, "webhook") || strings.Contains(text, "network") || strings.Contains(text, "http") || strings.Contains(text, "c2") || strings.Contains(text, "情报"):
		return "外联与情报"
	case strings.Contains(text, "声明") || strings.Contains(text, "意图") || strings.Contains(text, "一致"):
		return "声明与行为差异"
	case strings.Contains(text, "恶意代码") || strings.Contains(text, "破坏性") || strings.Contains(text, "malicious"):
		return "恶意代码"
	case strings.Contains(text, "凭据") || strings.Contains(text, "credential") || strings.Contains(text, "token") || strings.Contains(text, "secret"):
		return "凭据访问"
	case strings.Contains(text, "远程下载执行") || strings.Contains(text, "下载执行") || strings.Contains(text, "自更新"):
		return "下载执行"
	case strings.Contains(text, "执行") || strings.Contains(text, "command") || strings.Contains(text, "shell") || strings.Contains(text, "命令"):
		return "命令执行"
	case strings.Contains(text, "持久化") || strings.Contains(text, "persistence") || strings.Contains(text, "cron"):
		return "持久化"
	case strings.Contains(text, "提权") || strings.Contains(text, "privilege") || strings.Contains(text, "sudo"):
		return "提权"
	case strings.Contains(text, "逃逸") || strings.Contains(text, "规避") || strings.Contains(text, "evasion") || strings.Contains(text, "sandbox"):
		return "反分析/逃逸"
	case strings.Contains(text, "覆盖") || strings.Contains(text, "coverage"):
		return "规则覆盖"
	default:
		return "静态规则发现"
	}
}

func declarationFindingGroup(f plugins.Finding) string {
	text := strings.ToLower(strings.Join([]string{f.RuleID, f.Title, f.Description, f.Location, f.CodeSnippet}, " "))
	switch {
	case strings.Contains(text, "凭据") || strings.Contains(text, "private_key") || strings.Contains(text, "token") || strings.Contains(text, "secret"):
		return "credential"
	case strings.Contains(text, "网络") || strings.Contains(text, "http") || strings.Contains(text, "webhook") || strings.Contains(text, "localhost") || strings.Contains(text, "license_server"):
		return "network"
	case strings.Contains(text, "自动交易") || strings.Contains(text, "下单") || strings.Contains(text, "create_order") || strings.Contains(text, "live trading"):
		return "trading"
	case strings.Contains(text, "命令") || strings.Contains(text, "exec") || strings.Contains(text, "shell") || strings.Contains(text, "subprocess"):
		return "command"
	case strings.Contains(text, "收集") || strings.Contains(text, "session") || strings.Contains(text, "data"):
		return "collection"
	default:
		return "general"
	}
}

func hasRelevantBehaviorSupport(category string, behavior review.BehaviorProfile) bool {
	support := relevantBehaviorSupport(category, behavior)
	if len(support.chains) > 0 || len(support.alerts) > 0 || len(support.httpProbes) > 0 || len(support.runtimeNotes) > 0 {
		return true
	}
	// Agent 证据（IOCs）也视为相关行为支撑
	categoryLower := strings.ToLower(strings.TrimSpace(category))
	switch {
	case strings.Contains(categoryLower, "network") || strings.Contains(categoryLower, "外联") || strings.Contains(categoryLower, "情报") || strings.Contains(categoryLower, "外发"):
		return len(behavior.OutboundIOCs) > 0
	case strings.Contains(categoryLower, "command") || strings.Contains(categoryLower, "执行") || strings.Contains(categoryLower, "命令") || strings.Contains(categoryLower, "下载"):
		return len(behavior.ExecuteIOCs) > 0
	case strings.Contains(categoryLower, "credential") || strings.Contains(categoryLower, "凭据"):
		return len(behavior.CredentialIOCs) > 0
	case strings.Contains(categoryLower, "file") || strings.Contains(categoryLower, "文件") || strings.Contains(categoryLower, "勒索") || strings.Contains(categoryLower, "加密"):
		return len(behavior.DropIOCs) > 0
	}
	return len(behavior.OutboundIOCs) > 0 || len(behavior.ExecuteIOCs) > 0 || len(behavior.DropIOCs) > 0
}

type behaviorSupport struct {
	chains       []string
	alerts       []string
	httpProbes   []string
	runtimeNotes []string
}

func relevantBehaviorSupport(category string, behavior review.BehaviorProfile) behaviorSupport {
	return behaviorSupport{
		chains:       relevantBehaviorChains(category, behavior),
		alerts:       relevantSequenceAlerts(category, behavior),
		httpProbes:   relevantHTTPProbeRuntimeEvidence(category, behavior),
		runtimeNotes: relevantRuntimeObservationEvidence(category, behavior),
	}
}

func relevantHTTPProbeRuntimeEvidence(category string, behavior review.BehaviorProfile) []string {
	if !categoryAllowsRuntimeHTTPProbe(category) {
		return nil
	}
	out := make([]string, 0, len(behavior.ScenarioExecutions))
	for _, exec := range behavior.ScenarioExecutions {
		if exec.HTTPStatusCode <= 0 {
			continue
		}
		parts := []string{"runtime=http_probe"}
		if name := strings.TrimSpace(exec.Name); name != "" {
			parts = append(parts, "scenario="+name)
		}
		if method := strings.TrimSpace(exec.HTTPMethod); method != "" {
			parts = append(parts, "method="+method)
		}
		if exec.HTTPPort > 0 {
			parts = append(parts, fmt.Sprintf("port=%d", exec.HTTPPort))
		}
		if path := strings.TrimSpace(exec.HTTPPath); path != "" {
			parts = append(parts, "path="+path)
		}
		parts = append(parts, fmt.Sprintf("status=%d", exec.HTTPStatusCode))
		for _, line := range exec.Output {
			line = strings.TrimSpace(line)
			if !strings.Contains(line, "http_probe") {
				continue
			}
			if bodyHash := extractRuntimeHTTPProbeToken(line, "body_sha256="); bodyHash != "" {
				parts = append(parts, "body_sha256="+bodyHash)
			}
			if bodySample := extractRuntimeHTTPProbeBodySample(line); bodySample != "" {
				parts = append(parts, "body_sample="+bodySample)
			}
			break
		}
		out = append(out, strings.Join(parts, " "))
	}
	return uniqueStrings(out)
}

func relevantRuntimeObservationEvidence(category string, behavior review.BehaviorProfile) []string {
	if !categoryAllowsRuntimeHTTPProbe(category) {
		return nil
	}
	out := make([]string, 0, len(behavior.ScenarioExecutions))
	for _, exec := range behavior.ScenarioExecutions {
		for _, line := range exec.Output {
			line = strings.TrimSpace(line)
			if line == "" || !containsAny(strings.ToLower(line), []string{"http_probe_runtime_ports", "http_probe_budget", "http_probe_error", "body_sha256", "body_sample"}) {
				continue
			}
			prefix := "runtime_observation"
			if exec.Name != "" {
				prefix += " scenario=" + exec.Name
			}
			out = append(out, compactRuntimeEvidenceLine(prefix+" "+line, 180))
		}
	}
	return uniqueStrings(out)
}

func categoryAllowsRuntimeHTTPProbe(category string) bool {
	return strings.TrimSpace(category) != ""
}

func extractRuntimeHTTPProbeToken(line, prefix string) string {
	idx := strings.Index(line, prefix)
	if idx < 0 {
		return ""
	}
	value := strings.TrimSpace(line[idx+len(prefix):])
	if value == "" {
		return ""
	}
	if space := strings.Index(value, " "); space >= 0 {
		value = value[:space]
	}
	return strings.Trim(value, `"'`)
}

func extractRuntimeHTTPProbeBodySample(line string) string {
	idx := strings.Index(line, "body_sample=")
	if idx < 0 {
		return ""
	}
	return compactRuntimeEvidenceLine(strings.TrimSpace(line[idx+len("body_sample="):]), 120)
}

func compactRuntimeEvidenceLine(text string, max int) string {
	text = strings.Join(strings.Fields(strings.TrimSpace(text)), " ")
	if max <= 0 || len([]rune(text)) <= max {
		return text
	}
	runes := []rune(text)
	return string(runes[:max])
}

func relevantBehaviorChains(category string, behavior review.BehaviorProfile) []string {
	keys := relevantBehaviorCategories(category)
	if len(keys) == 0 {
		return nil
	}
	out := make([]string, 0, len(behavior.BehaviorChains))
	for _, chain := range behavior.BehaviorChains {
		if isInternalScanArtifactText(chain) {
			continue
		}
		if behaviorChainMatchesAnyCategory(chain, keys) {
			out = append(out, chain)
		}
	}
	return uniqueStrings(out)
}

func relevantSequenceAlerts(category string, behavior review.BehaviorProfile) []string {
	allowed := relevantSequenceAlertLabels(category)
	if len(allowed) == 0 {
		return nil
	}
	allowSet := make(map[string]struct{}, len(allowed))
	for _, item := range allowed {
		allowSet[item] = struct{}{}
	}
	out := make([]string, 0, len(behavior.SequenceAlerts))
	for _, alert := range behavior.SequenceAlerts {
		if _, ok := allowSet[strings.TrimSpace(alert)]; ok {
			out = append(out, alert)
		}
	}
	return uniqueStrings(out)
}

var relevantBehaviorCategoriesByFindingCategory = map[string][]string{
	"命令执行":   {"执行"},
	"下载执行":   {"下载", "执行"},
	"外联与情报":  {"外联", "C2信标", "收集打包", "凭据访问", "横向移动"},
	"凭据访问":   {"凭据访问", "外联", "收集打包"},
	"持久化":    {"持久化"},
	"提权":     {"提权"},
	"反分析/逃逸": {"防御规避", "执行"},
}

func relevantBehaviorCategories(category string) []string {
	return relevantBehaviorCategoriesByFindingCategory[category]
}

var relevantSequenceAlertLabelsByFindingCategory = map[string][]string{
	"命令执行":   {"命中下载后执行时序", "命中防御规避后执行时序", "命中横向移动联动控制时序"},
	"下载执行":   {"命中下载后执行时序"},
	"外联与情报":  {"命中收集后外联时序", "命中凭据访问后外联时序", "命中横向移动联动控制时序"},
	"凭据访问":   {"命中凭据访问后外联时序"},
	"反分析/逃逸": {"命中防御规避后执行时序"},
}

func relevantSequenceAlertLabels(category string) []string {
	return relevantSequenceAlertLabelsByFindingCategory[category]
}

func behaviorChainMatchesAnyCategory(chain string, categories []string) bool {
	for _, category := range categories {
		if behaviorChainHasPositiveCount(chain, category) {
			return true
		}
	}
	return false
}

func behaviorChainHasPositiveCount(chain string, category string) bool {
	needle := category + "="
	idx := strings.Index(chain, needle)
	if idx < 0 {
		return false
	}
	start := idx + len(needle)
	end := start
	for end < len(chain) && chain[end] >= '0' && chain[end] <= '9' {
		end++
	}
	if end == start {
		return false
	}
	count, err := strconv.Atoi(chain[start:end])
	if err != nil {
		return false
	}
	return count > 0
}

func structuredAttackPath(category string, f plugins.Finding, refined review.Result) string {
	support := relevantBehaviorSupport(category, refined.Behavior)
	if len(support.chains) > 0 {
		return strings.Join(limitList(support.chains, 2), "；")
	}
	if len(support.alerts) > 0 {
		return strings.Join(limitList(support.alerts, 2), "；")
	}
	if specialized := specializedAttackPath(category, f); specialized != "" {
		return specialized
	}
	return defaultIfEmpty(structuredAttackPathFallback(category), defaultIfEmpty(f.Description, "当前发现依赖规则命中和证据片段，需要结合上下文复核可达性与真实影响。"))
}

func falsePositiveChecks(category string, f plugins.Finding, refined review.Result) []string {
	checks := []string{
		"确认证据是否位于真实运行路径；即使位于 README、注释、测试或示例文件，也要继续检查是否会被实际引用、打包、解析或动态加载。",
		"确认触发位置是否可由技能入口到达，且不依赖不可用配置或未启用功能。",
	}
	checks = append(checks, specializedFalsePositiveChecks(category, f)...)
	if categoryCheck := falsePositiveCategoryCheck(category); categoryCheck != "" {
		checks = append(checks, categoryCheck)
	}
	if len(refined.EvidenceInventory) == 0 {
		checks = append(checks, "当前发现缺少归一化证据目录支撑，应回溯原始规则记录和源码上下文。")
	}
	return checks
}

func structuredReviewGuidance(category string, f plugins.Finding) string {
	severity := f.Severity
	if guidance := specializedReviewGuidanceForFinding(category, f); guidance != "" {
		return guidance
	}
	if specialized := specializedReviewGuidance(category); specialized != "" {
		return specialized
	}
	if severity == "高风险" {
		return "优先复核攻击路径是否成立；若成立，应先修复或移除相关能力，再进行全量复扫。"
	}
	return defaultIfEmpty(structuredReviewGuidanceFallback(category), "结合证据片段、行为时序和业务用途复核，确认是否为必要能力或可收敛实现。")
}

func specializedReviewGuidanceForFinding(category string, f plugins.Finding) string {
	if category == "网络请求与SSRF" {
		text := strings.ToLower(strings.Join([]string{f.Title, f.Description, f.Location, f.CodeSnippet}, " "))
		switch {
		case strings.Contains(text, "危险目标=metadata.google") || strings.Contains(text, "169.254.169.254") || strings.Contains(text, "危险目标=") || strings.Contains(text, "危险目标=10.") || strings.Contains(text, "危险目标=192.168.") || strings.Contains(text, "危险目标=172."):
			return "先阻断 metadata、本地和内网地址访问，再增加 host/IP 白名单、协议限制和重定向校验，确保请求不会进入宿主或云环境敏感面。"
		case strings.Contains(text, "缺少校验") || strings.Contains(text, "missing-guard") || strings.Contains(text, "target_url") || strings.Contains(text, "来源类型=user_input"):
			return "先固定请求目标或增加 allowlist/parse 校验，再验证解析后 host、IP 和重定向目标，确保用户输入不能直接进入请求地址。"
		default:
			return "先按三段式复核 SSRF 风险：确认存在真实请求、目标可控且缺少有效校验，再补齐白名单、协议限制和重定向保护。"
		}
	}
	if category == "外联与情报" {
		text := strings.ToLower(strings.Join([]string{f.Title, f.Description, f.Location, f.CodeSnippet}, " "))
		switch {
		case strings.Contains(text, "命中黑名单目标") || strings.Contains(text, "policy blacklist") || strings.Contains(text, "策略黑名单"):
			return "先确认目标是否命中准入或合规策略；命中策略时应替换为允许目标、补充业务白名单或按平台准入流程拦截。"
		case containsAny(text, []string{"api_key", "oem_api_key", "token", "secret", "authorization", "cookie"}):
			return "先移除高敏感字段的外发路径，限制出站目标到白名单，并补齐鉴权、字段裁剪和审计告警。"
		case strings.Contains(text, "requests.post(target") || strings.Contains(text, "upload target") || strings.Contains(text, "用户可控外联目标") || strings.Contains(text, "allowlist"):
			return "先固定外联目标或增加 allowlist 校验，再补齐鉴权和字段范围限制，确保用户输入无法直接决定上传目的地。"
		case strings.Contains(text, "固定售后平台") || strings.Contains(text, "已声明外联回传") || strings.Contains(text, "after-sales.example.com"):
			return "先确认固定业务目标是否已备案，再收敛回传字段、调用频率和失败重试策略，确保外联保持在声明范围内。"
		default:
			return "先核验外联目标、字段范围和授权边界，再根据是否为固定业务目标、用户可控目标或策略命中选择对应收敛路径。"
		}
	}
	if category == "授权与许可证校验" {
		text := strings.ToLower(strings.Join([]string{f.Title, f.Description, f.Location, f.CodeSnippet}, " "))
		switch {
		case containsAny(text, []string{"verify_failed", "fail open", "fail-open", "return true", "continue on failure", "校验失败后继续", "失败分支放行"}):
			return "先把许可证校验改成失败即拒绝，并同时移除本地默认服务和失败放行分支，确保超时、异常、空 key 与失败响应都不能继续启用受限能力。"
		case strings.Contains(text, "license_server") || strings.Contains(text, "/api/validate") || strings.Contains(text, "localhost:8080"):
			return "先确认 localhost 许可证服务是否只用于开发态 fallback，再要求生产环境显式配置许可证端点，并验证缺省配置、超时和异常路径都会阻断受限能力启用。"
		default:
			return ""
		}
	}
	if category == "暴露面与未鉴权服务" {
		text := strings.ToLower(strings.Join([]string{f.Title, f.Description, f.Location, f.CodeSnippet}, " "))
		switch {
		case containsAny(text, []string{"127.0.0.1", "localhost", "本地", "loopback", "dev", "development"}):
			return "先确认该管理面是否只用于本地开发或单机运维，再通过回环绑定、显式环境开关和默认关闭策略把入口固定在非公网范围。"
		case containsAny(text, []string{"0.0.0.0", "公网", "public network", "publicly accessible", "监听所有网络接口"}):
			return "先移除公网监听或前置鉴权网关，再补齐身份验证、会话保护和来源限制，确保仪表板不会直接暴露给未授权访问者。"
		default:
			return "先确认仪表板绑定范围和调用人群，再补齐身份验证、来源限制和默认关闭策略，避免运维入口滑入公网暴露。"
		}
	}
	if category == "环境与构建风险" {
		text := strings.ToLower(strings.Join([]string{f.Title, f.Description, f.Location, f.CodeSnippet}, " "))
		switch {
		case containsAny(text, []string{"curl ", "wget ", "| sh", "| bash", "git clone", "远程脚本", "供应链"}):
			return "先移除远程脚本直拉直执行链路，固定可信源并补齐版本锁定、哈希或签名校验，再把安装步骤收敛到可复现构建流程。"
		case containsAny(text, []string{"break-system-packages", "pep 668", "pip3 install", "pip install"}):
			return "先把 Python 依赖安装迁移到虚拟环境或镜像构建阶段，再保留最小化系统包变更，避免运行时直接破坏宿主 Python 边界。"
		default:
			return "先确认构建链是否可复现、依赖是否锁版本，再补齐来源校验和环境隔离，避免安装步骤把风险带入运行环境。"
		}
	}
	title := normalizeStructuredFindingTitle(strings.TrimSpace(f.Title))
	if category != "静态规则发现" || (title != "数据最小化与收集边界" && publicRuleIDForOutput(f.RuleID) != "S2-P1-031") {
		return ""
	}
	text := strings.ToLower(strings.Join([]string{f.Title, f.Description, f.Location, f.CodeSnippet}, " "))
	switch {
	case strings.Contains(text, "requests.post") || strings.Contains(text, "requests.put") || strings.Contains(text, "axios.post") || strings.Contains(text, "网络发送"):
		if containsAny(text, []string{"api_key", "oem_api_key", "token", "secret", "凭据"}) {
			return "先移除高敏感凭据的对外发送路径，收敛到最小必要字段，并同时限制上传目标、鉴权方式和出站白名单。"
		}
		return "先确认外发字段是否最小必要，再收敛同步目标、授权边界和白名单范围，确保会话或联系方式不会被无边界转发。"
	case strings.Contains(text, "logger.") || strings.Contains(text, "print(") || strings.Contains(text, "日志"):
		return "先收敛日志输出字段，增加脱敏和采样策略，并为联系方式或会话字段设置最短保留周期。"
	case strings.Contains(text, "insert") || strings.Contains(text, "update") || strings.Contains(text, "db.execute") || strings.Contains(text, "持久化"):
		return "先确认持久化字段是否属于业务必需，再补齐保留周期、用途说明和访问控制，避免联系方式或会话字段长期留存。"
	default:
		return "先按字段类型和动作语义复核数据边界，确认是否存在不必要的日志、持久化或外发路径。"
	}
}

func specializedAttackPath(category string, f plugins.Finding) string {
	text := strings.ToLower(strings.Join([]string{f.Title, f.Description, f.Location, f.CodeSnippet}, " "))
	switch category {
	case "网络请求与SSRF":
		if strings.Contains(text, "请求调用=") || strings.Contains(text, "输入来源=") || strings.Contains(text, "缺少校验=") {
			targetScope := "外部请求目标"
			if strings.Contains(text, "metadata.google") || strings.Contains(text, "169.254.169.254") {
				targetScope = "云 metadata 目标"
			} else if strings.Contains(text, "内网") {
				targetScope = "内网或本地目标"
			}
			return "检测到真实请求调用，且请求目标受输入或运行参数影响；当前证据显示目标可进入" + targetScope + "，同时缺少有效白名单或解析后校验，可能形成 SSRF 访问链路。"
		}
	case "授权与许可证校验":
		if strings.Contains(text, "license_server") || strings.Contains(text, "/api/validate") || strings.Contains(text, "localhost:8080") {
			if containsAny(text, []string{"verify_failed", "fail open", "fail-open", "return true", "continue on failure", "校验失败后继续", "失败分支放行"}) {
				return "许可证校验链路当前同时包含本地默认服务和失败后继续放行信号；一旦校验超时、异常或返回失败结果，受限能力仍可能被继续启用，形成更接近 fail-open 的授权绕过路径。"
			}
			return "许可证校验依赖本地默认服务或固定校验端点，若失败分支、异常分支或空 key 处理不严格，可能在未完成授权校验时继续启用受限能力。"
		}
	case "暴露面与未鉴权服务":
		if containsAny(text, []string{"127.0.0.1", "localhost", "本地", "loopback", "dev", "development"}) {
			return "管理面当前更接近本地开发或单机运维入口；若后续通过反向代理、环境切换或错误配置扩展到非回环地址，未鉴权页面仍可能滑入可访问面。"
		}
		if containsAny(text, []string{"0.0.0.0", "公网", "public network", "publicly accessible", "监听所有网络接口"}) {
			return "仪表板直接监听公网或全部网络接口，且当前证据未体现有效身份验证；一旦服务启动并暴露到外部网络，未授权访问者可能直接读取状态、配置或触发管理操作。"
		}
	case "环境与构建风险":
		if containsAny(text, []string{"curl ", "wget ", "| sh", "| bash", "git clone", "远程脚本", "供应链"}) {
			return "构建链当前允许远程脚本、外部仓库或即时下载内容直接进入安装与执行路径；若来源被篡改、版本漂移或依赖未锁定，风险会在构建阶段直接落入交付包。"
		}
		if containsAny(text, []string{"break-system-packages", "pep 668", "pip3 install", "pip install"}) {
			return "安装流程当前通过系统 Python 边界直接写入依赖，虽然不等同于远程执行，但会放大环境污染、依赖冲突和宿主运行时漂移风险。"
		}
	case "业务自动化高风险行为":
		if strings.Contains(text, "create_order") || strings.Contains(text, "live trading") || strings.Contains(text, "signed_order") {
			return "技能具备自动构造并提交订单的能力，若默认启用真实交易、缺少金额限制或缺少二次确认，可能直接导致资金操作和策略误触发。"
		}
	}
	return ""
}

func specializedFalsePositiveChecks(category string, f plugins.Finding) []string {
	text := strings.ToLower(strings.Join([]string{f.Title, f.Description, f.Location, f.CodeSnippet}, " "))
	checks := make([]string, 0, 2)
	switch category {
	case "授权与许可证校验":
		if strings.Contains(text, "license_server") || strings.Contains(text, "/api/validate") || strings.Contains(text, "localhost:8080") {
			if containsAny(text, []string{"verify_failed", "fail open", "fail-open", "return true", "continue on failure", "校验失败后继续", "失败分支放行"}) {
				checks = append(checks,
					"确认失败分支、超时和异常路径是否存在 continue、return true 或等价放行逻辑，并逐条改成失败即拒绝。",
					"确认受限能力启用前必须拿到成功的许可证校验结果，避免请求失败或响应异常时继续运行。",
				)
				break
			}
			checks = append(checks,
				"确认本地默认许可证服务是否只用于开发模式，以及生产路径是否仍可能落到 localhost 或空配置。",
				"确认许可证校验失败、超时、异常响应和空 key 场景都会阻断受限能力启用。",
			)
		}
	case "业务自动化高风险行为":
		if strings.Contains(text, "create_order") || strings.Contains(text, "live trading") || strings.Contains(text, "signed_order") {
			checks = append(checks,
				"确认自动交易是否默认关闭，以及真实资金模式是否需要显式开关和人工确认。",
				"确认订单金额、频率、市场范围和失败回滚是否存在硬限制与熔断保护。",
			)
		}
	}
	return checks
}

func specializedReviewGuidance(category string) string {
	switch category {
	case "授权与许可证校验":
		return "先收敛许可证校验链路：移除本地默认服务，要求显式配置许可证端点，并把失败、超时和异常统一改成失败即拒绝。"
	case "业务自动化高风险行为":
		return "先收敛真实交易链路：默认关闭 live trading，增加金额/频率限制、模拟模式保护和人工二次确认，再复扫验证。"
	default:
		return ""
	}
}

var structuredAttackPathFallbackByCategory = map[string]string{
	"命令执行":       "源码或运行时证据显示技能可能调用 shell、解释器或系统命令，需要确认入口参数是否可控。",
	"下载执行":       "源码或运行时证据显示技能可能下载远程内容并进入执行链路，需要确认来源校验、签名校验和触发入口。",
	"恶意代码":       "检测到疑似恶意行为组合或破坏性语义，需要按证据拆分确认真实可达链路。",
	"凭据访问":       "技能存在访问 token、密钥、环境变量或认证文件的证据，需要确认是否为声明用途必要行为。",
	"网络请求与SSRF":  "外部请求目标可能受用户输入、配置或运行数据影响，需要确认是否存在内网、本地或重定向访问。",
	"授权与许可证校验":   "许可证校验逻辑存在失败分支、默认本地服务或空 key 处理风险，需要确认是否可能导致未授权放行。",
	"外联与情报":      "技能存在网络访问或可疑目标信誉证据，需要确认请求目标、数据内容和授权范围。",
	"业务自动化高风险行为": "技能可能执行自动化交易或资金操作，需要确认触发条件、保护措施和人工确认边界。",
	"声明与行为差异":    "技能声明与实际行为存在偏差，需要将声明、权限和源码行为放在同一证据链中复核。",
}

func structuredAttackPathFallback(category string) string {
	return structuredAttackPathFallbackByCategory[category]
}

var falsePositiveCategoryCheckByCategory = map[string]string{
	"命令执行":       "确认命令参数是否固定、是否经过白名单校验，以及是否允许用户输入拼接。",
	"下载执行":       "确认下载内容是否固定可信、是否校验签名或哈希，以及下载结果是否会被执行。",
	"恶意代码":       "将恶意代码结论拆到具体行为证据，确认是否同时存在入口、执行路径和真实影响。",
	"外联与情报":      "确认外联域名是否为声明服务、是否传输敏感数据，以及威胁情报结果是否来自真实 IoC。",
	"网络请求与SSRF":  "确认 URL、host、重定向地址和解析后 IP 是否都经过白名单校验并阻断内网地址。",
	"凭据访问":       "确认读取凭据是否为用户显式授权，并检查是否存在后续外联或落地链路。",
	"授权与许可证校验":   "确认许可证服务器、许可证 key、校验失败分支和异常分支是否都按失败即拒绝处理。",
	"业务自动化高风险行为": "确认自动交易是否默认启用、是否存在金额限制、仿真保护和用户二次确认。",
	"声明与行为差异":    "确认 SKILL.md、manifest 和权限声明是否遗漏实际能力，必要时补充声明后复扫。",
}

func falsePositiveCategoryCheck(category string) string {
	return falsePositiveCategoryCheckByCategory[category]
}

var structuredReviewGuidanceFallbackByCategory = map[string]string{
	"规则覆盖":       "补齐自动化覆盖或记录人工复核结论，避免规则盲区影响最终判断。",
	"业务自动化高风险行为": "为自动交易、资金操作和模式切换补充显式保护措施，并验证默认行为符合文档声明。",
	"声明与行为差异":    "同步修正技能声明、权限说明和实际实现，确保用户能基于透明能力做判断。",
}

func structuredReviewGuidanceFallback(category string) string {
	return structuredReviewGuidanceFallbackByCategory[category]
}

func findingsText(findings []plugins.Finding) string {
	parts := make([]string, 0, len(findings))
	for _, f := range findings {
		parts = append(parts, f.RuleID, f.Title, f.Description, f.CodeSnippet)
	}
	return strings.Join(parts, " ")
}

func containsAny(text string, needles []string) bool {
	for _, needle := range needles {
		if strings.Contains(text, strings.ToLower(needle)) {
			return true
		}
	}
	return false
}

func capabilityStatus(declared, staticDetected, llmDetected, sandboxDetected bool) (string, string) {
	observed := staticDetected || llmDetected || sandboxDetected
	switch {
	case declared && observed && sandboxDetected:
		return "已声明且多源验证", ""
	case declared && observed:
		return "已声明但沙箱未验证", "沙箱未检出对应行为，需检查入口触发、动态拼接、环境条件或探针覆盖"
	case !declared && observed && sandboxDetected:
		return "未声明但沙箱检出", "能力未在声明或权限中清晰披露，存在隐瞒能力风险"
	case !declared && observed:
		return "未声明但静态/LLM 检出", "能力未声明且缺少运行时验证，需要人工确认是否为真实可达行为"
	case declared:
		return "已声明但未检出", "声明中提及能力，但当前静态/LLM/沙箱未形成有效证据"
	default:
		return "未观察到", ""
	}
}

func capabilityEvidence(capability string, sandboxEvidence []string, findings []plugins.Finding, base baseScanOutput, refined review.Result) []string {
	evidence := make([]string, 0, 6)
	if len(sandboxEvidence) > 0 {
		evidence = append(evidence, "沙箱证据: "+strings.Join(sandboxEvidence, "；"))
	}
	for _, f := range findings {
		cat := structuredFindingCategory(f)
		if capabilityMatchesFindingCategory(capability, cat) {
			evidence = append(evidence, "规则证据: "+f.RuleID+" "+f.Title)
			break
		}
	}
	if base.intentSummary.Available && len(base.intentSummary.ActualCapabilities) > 0 {
		evidence = append(evidence, "LLM 实际能力: "+strings.Join(base.intentSummary.ActualCapabilities, "；"))
	}
	if capability == "外联/网络访问" && len(refined.TIReputations) > 0 {
		targets := make([]string, 0, len(refined.TIReputations))
		for _, rep := range refined.TIReputations {
			targets = append(targets, rep.Target+" -> "+localizeReputation(rep.Reputation))
		}
		evidence = append(evidence, "情报证据: "+strings.Join(targets, "；"))
	}
	return evidence
}

var capabilityFindingCategoryMap = map[string]string{
	"外联/网络访问": "外联与情报",
	"命令执行":    "命令执行",
	"文件读写/落地": "文件读写/落地",
	"凭据访问":    "凭据访问",
	"持久化":     "持久化",
	"提权/沙箱逃逸": "反分析/逃逸",
	"数据收集/打包": "数据收集/打包",
}

func capabilityMatchesFindingCategory(capability, category string) bool {
	return capabilityFindingCategoryMap[capability] == category
}

func buildDynamicSuggestions(findings []plugins.Finding, refined review.Result) []string {
	return reviewreport.BuildDynamicSuggestions(findings, refined)
}

func remediationForHTMLFinding(f plugins.Finding) string {
	return reviewreport.RemediationForHTMLFinding(f)
}

func sortFindingsBySeverity(findings []plugins.Finding) []plugins.Finding {
	return reviewreport.SortFindingsBySeverity(findings)
}

func sortFindingsByReview(findings []plugins.Finding, refined review.Result) []plugins.Finding {
	out := append([]plugins.Finding(nil), findings...)
	if len(refined.StructuredFindings) == 0 || len(refined.ReviewAgentVerdicts) == 0 {
		return sortFindingsBySeverity(out)
	}
	ctx := newReviewedFindingContext(refined)
	sort.SliceStable(out, func(i, j int) bool {
		left := reviewSortKeyForFinding(out[i], ctx)
		right := reviewSortKeyForFinding(out[j], ctx)
		if left.reviewRank != right.reviewRank {
			return left.reviewRank < right.reviewRank
		}
		if left.severityRank != right.severityRank {
			return left.severityRank < right.severityRank
		}
		return left.ruleID < right.ruleID
	})
	return out
}

func sortStructuredFindingsByReview(findings []review.StructuredFinding, refined review.Result) []review.StructuredFinding {
	out := append([]review.StructuredFinding(nil), findings...)
	if len(refined.ReviewAgentVerdicts) == 0 {
		sort.SliceStable(out, func(i, j int) bool {
			return severityRank(out[i].Severity) < severityRank(out[j].Severity)
		})
		return out
	}
	ctx := newReviewedFindingContext(refined)
	sort.SliceStable(out, func(i, j int) bool {
		left := reviewSortKeyForStructuredFinding(out[i], ctx)
		right := reviewSortKeyForStructuredFinding(out[j], ctx)
		if left.reviewRank != right.reviewRank {
			return left.reviewRank < right.reviewRank
		}
		if left.severityRank != right.severityRank {
			return left.severityRank < right.severityRank
		}
		return left.id < right.id
	})
	return out
}

type reviewFindingSortKey struct {
	reviewRank   int
	severityRank int
	ruleID       string
	id           string
}

func reviewSortKeyForFinding(finding plugins.Finding, ctx reviewedFindingContext) reviewFindingSortKey {
	structured, ok := ctx.structuredFindingForPluginFinding(finding)
	if !ok {
		return reviewFindingSortKey{reviewRank: reviewVerdictRank(""), severityRank: severityRank(finding.Severity), ruleID: finding.RuleID}
	}
	verdict := ctx.finalVerdict(structured.ID)
	return reviewFindingSortKey{reviewRank: reviewVerdictRank(verdict.Verdict), severityRank: severityRank(ctx.normalizedSeverity(structured)), ruleID: structured.RuleID, id: structured.ID}
}

func reviewSortKeyForStructuredFinding(finding review.StructuredFinding, ctx reviewedFindingContext) reviewFindingSortKey {
	verdict := ctx.finalVerdict(finding.ID)
	return reviewFindingSortKey{reviewRank: reviewVerdictRank(verdict.Verdict), severityRank: severityRank(ctx.normalizedSeverity(finding)), ruleID: finding.RuleID, id: finding.ID}
}

func structuredFindingByStableKey(findings []review.StructuredFinding) map[string]review.StructuredFinding {
	out := make(map[string]review.StructuredFinding, len(findings)*2)
	for _, finding := range findings {
		for _, key := range stableFindingKeysFromStructuredFinding(finding) {
			out[key] = finding
		}
	}
	return out
}

func stableFindingKeyFromStructuredFinding(finding review.StructuredFinding) string {
	return stableFindingKey(finding.RuleID, finding.Category, finding.Title)
}

func stableFindingKeysFromStructuredFinding(finding review.StructuredFinding) []string {
	keys := []string{stableFindingKeyFromStructuredFinding(finding), fallbackFindingKey(finding.RuleID, finding.Title)}
	publicRuleID := publicRuleIDForOutput(finding.RuleID)
	if publicRuleID != strings.TrimSpace(finding.RuleID) {
		keys = append(keys, stableFindingKey(publicRuleID, finding.Category, finding.Title), fallbackFindingKey(publicRuleID, finding.Title))
	}
	return uniqueStrings(keys)
}

func stableFindingKeyFromPluginFinding(finding plugins.Finding) string {
	return stableFindingKey(finding.RuleID, structuredFindingCategory(finding), normalizeStructuredFindingTitle(finding.Title))
}

func stableFindingKeysFromPluginFinding(finding plugins.Finding) []string {
	title := normalizeStructuredFindingTitle(finding.Title)
	ruleID := strings.TrimSpace(finding.RuleID)
	publicRuleID := publicRuleIDForOutput(ruleID)
	keys := []string{stableFindingKeyFromPluginFinding(finding), fallbackFindingKey(ruleID, title), fallbackFindingKey(ruleID, strings.TrimSpace(finding.Title))}
	if publicRuleID != ruleID {
		keys = append(keys, stableFindingKey(publicRuleID, structuredFindingCategory(finding), title), fallbackFindingKey(publicRuleID, title), fallbackFindingKey(publicRuleID, strings.TrimSpace(finding.Title)))
	}
	return uniqueStrings(keys)
}

func stableFindingKey(ruleID, category, title string) string {
	return strings.Join([]string{strings.TrimSpace(ruleID), strings.TrimSpace(category), strings.TrimSpace(title)}, "\x00")
}

func fallbackFindingKey(ruleID, title string) string {
	return strings.Join([]string{strings.TrimSpace(ruleID), strings.TrimSpace(title)}, "\x00")
}

func lookupStructuredFindingForPluginFinding(finding plugins.Finding, structuredByKey map[string]review.StructuredFinding) (review.StructuredFinding, bool) {
	for _, key := range stableFindingKeysFromPluginFinding(finding) {
		if structured, ok := structuredByKey[key]; ok {
			return structured, true
		}
	}
	return lookupStructuredFindingByEvidenceOverlap(finding, structuredByKey)
}

func lookupStructuredFindingByEvidenceOverlap(finding plugins.Finding, structuredByKey map[string]review.StructuredFinding) (review.StructuredFinding, bool) {
	category := strings.TrimSpace(structuredFindingCategory(finding))
	if category == "" {
		return review.StructuredFinding{}, false
	}
	findingLocators := evidenceLocatorsFromPluginFinding(finding)
	findingTokens := evidenceTokensFromPluginFinding(finding)
	if len(findingLocators) == 0 && len(findingTokens) == 0 {
		return review.StructuredFinding{}, false
	}
	seen := map[string]struct{}{}
	for _, structured := range structuredByKey {
		if _, ok := seen[structured.ID]; ok {
			continue
		}
		seen[structured.ID] = struct{}{}
		if strings.TrimSpace(structured.Category) != category {
			continue
		}
		if evidenceLocatorOverlap(findingLocators, evidenceLocatorsFromStructuredFinding(structured)) || evidenceTokenOverlap(findingTokens, evidenceTokensFromStructuredFinding(structured)) {
			return structured, true
		}
	}
	return review.StructuredFinding{}, false
}

func evidenceLocatorsFromPluginFinding(finding plugins.Finding) map[string]struct{} {
	items := []string{finding.Location, finding.CodeSnippet, finding.Description}
	return evidenceLocatorsFromTexts(items)
}

func evidenceLocatorsFromStructuredFinding(finding review.StructuredFinding) map[string]struct{} {
	items := make([]string, 0, len(finding.Evidence)+len(finding.CodeEvidenceRefs)+len(finding.ContextEvidenceRefs)+len(finding.EvidenceItems)*2)
	items = append(items, finding.Evidence...)
	items = append(items, finding.CodeEvidenceRefs...)
	items = append(items, finding.ContextEvidenceRefs...)
	for _, item := range finding.EvidenceItems {
		items = append(items, item.Location, item.Snippet, item.Summary)
	}
	return evidenceLocatorsFromTexts(items)
}

func evidenceLocatorsFromTexts(items []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range items {
		for _, line := range strings.Split(strings.ReplaceAll(item, "\r\n", "\n"), "\n") {
			if p, l, ok := tryParseInlineLocator(line); ok && strings.TrimSpace(p) != "" {
				out[strings.ToLower(filepath.ToSlash(strings.TrimSpace(p)))+":"+strconv.Itoa(l)] = struct{}{}
			}
		}
	}
	return out
}

func evidenceLocatorOverlap(left, right map[string]struct{}) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	for item := range left {
		if _, ok := right[item]; ok {
			return true
		}
	}
	return false
}

func evidenceTokensFromPluginFinding(finding plugins.Finding) map[string]struct{} {
	return evidenceTokensFromTexts([]string{finding.CodeSnippet, finding.Description, finding.Title})
}

func evidenceTokensFromStructuredFinding(finding review.StructuredFinding) map[string]struct{} {
	items := make([]string, 0, len(finding.Evidence)+len(finding.CodeEvidenceRefs)+len(finding.ContextEvidenceRefs)+len(finding.EvidenceItems)*2)
	items = append(items, finding.Evidence...)
	items = append(items, finding.CodeEvidenceRefs...)
	items = append(items, finding.ContextEvidenceRefs...)
	for _, item := range finding.EvidenceItems {
		items = append(items, item.Snippet, item.Summary)
	}
	return evidenceTokensFromTexts(items)
}

func evidenceTokensFromTexts(items []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, item := range items {
		for _, token := range strings.FieldsFunc(strings.ToLower(item), func(r rune) bool {
			return !(r == '_' || r == '-' || r == '.' || r == '/' || r == ':' || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'))
		}) {
			token = strings.Trim(token, "'\"`.,;:()[]{}")
			if len(token) < 6 || isWeakEvidenceToken(token) {
				continue
			}
			out[token] = struct{}{}
		}
	}
	return out
}

func isWeakEvidenceToken(token string) bool {
	switch strings.TrimSpace(token) {
	case "finding", "security", "risk", "plugin", "source", "target", "payload", "request", "response", "evidence", "description", "summary", "status", "import", "return", "config", "python", "script":
		return true
	default:
		return false
	}
}

func evidenceTokenOverlap(left, right map[string]struct{}) bool {
	if len(left) == 0 || len(right) == 0 {
		return false
	}
	matches := 0
	for item := range left {
		if _, ok := right[item]; ok {
			matches++
			if matches >= 2 {
				return true
			}
		}
	}
	return false
}

func reviewVerdictRank(verdict string) int {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed":
		return 0
	case "policy":
		return 1
	case "needs_manual_review":
		return 2
	case "likely_false_positive":
		return 3
	default:
		return 4
	}
}

func severityRank(severity string) int {
	switch localizeSeverity(severity) {
	case "高风险":
		return 0
	case "中风险":
		return 1
	case "低风险":
		return 2
	default:
		return 3
	}
}

func finalReviewSummaryForFinding(finding plugins.Finding, refined review.Result) string {
	ctx := newReviewedFindingContext(refined)
	structured, ok := ctx.structuredFindingForPluginFinding(finding)
	if !ok {
		return "无匹配结构化发现"
	}
	return finalReviewSummaryForStructuredFinding(structured.ID, ctx)
}

func finalReviewSummaryForStructuredFinding(findingID string, ctx reviewedFindingContext) string {
	verdict := ctx.finalVerdict(findingID)
	if strings.TrimSpace(verdict.Verdict) == "" {
		return "未生成最终裁决"
	}
	return localizeReviewVerdict(verdict.Verdict) + " / " + localizeReviewerLabel(defaultIfEmpty(verdict.Reviewer, "unknown-reviewer")) + " / 置信度: " + defaultIfEmpty(verdict.Confidence, "未标注")
}

func localizeReviewerLabel(reviewer string) string {
	reviewer = strings.TrimSpace(reviewer)
	if reviewer == "" {
		return "未知复核器"
	}
	parts := strings.Split(reviewer, "+")
	labels := make([]string, 0, len(parts))
	for _, part := range parts {
		switch strings.TrimSpace(part) {
		case "deterministic-vuln-reviewer":
			labels = append(labels, "规则复核器")
		case "llm-vuln-reviewer":
			labels = append(labels, "语义复核器")
		default:
			labels = append(labels, strings.TrimSpace(part))
		}
	}
	return strings.Join(labels, "+")
}

func localizeReviewVerdict(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "confirmed":
		return "已确认风险"
	case "policy":
		return "策略风险"
	case "needs_manual_review":
		return "需人工复核"
	case "likely_false_positive":
		return "疑似误报"
	case "review":
		return "需人工复核"
	default:
		return defaultIfEmpty(verdict, "未裁决")
	}
}

func localizeDeclarationVerdict(verdict string) string {
	switch strings.ToLower(strings.TrimSpace(verdict)) {
	case "declared":
		return "已声明"
	case "undeclared":
		return "未声明"
	case "partially_declared":
		return "部分声明"
	default:
		return "未标注"
	}
}

func defaultIfEmpty(v, fallback string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return fallback
	}
	return v
}

func localizeAdmission(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "userdecisionrequired", "user_decision_required":
		return "待用户基于证据判断"
	case "pass":
		return "系统建议通过，仍需用户确认"
	case "review":
		return "需人工复核"
	case "block":
		return "需完成修复并复测"
	default:
		if strings.TrimSpace(v) == "" {
			return "未给出结论"
		}
		return v
	}
}

func localizeSeverity(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "high", "high risk", "critical", "严重", "严重风险", "高", "高风险":
		return "高风险"
	case "medium", "medium risk", "中", "中风险":
		return "中风险"
	case "low", "low risk", "低", "低风险":
		return "低风险"
	default:
		if strings.TrimSpace(v) == "" {
			return "低风险"
		}
		return v
	}
}

func localizeFindings(findings []plugins.Finding) []plugins.Finding {
	localized := make([]plugins.Finding, 0, len(findings))
	for _, f := range findings {
		item := f
		item.Severity = localizeSeverity(f.Severity)
		item.Title = localizeFindingText(f.Title, "检测到潜在风险")
		item.Description = localizeFindingText(f.Description, "检测到可疑行为，请结合规则与关键代码片段复核。")
		if strings.TrimSpace(item.Location) == "" {
			item.Location = "未提供定位"
		}
		localized = append(localized, item)
	}
	return localized
}

func localizeFindingText(text, fallback string) string {
	text = strings.TrimSpace(text)
	if text == "" {
		return fallback
	}
	if containsChinese(text) {
		return text
	}

	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "backdoor"):
		return "检测到后门触发或隐藏执行风险"
	case strings.Contains(lower, "hardcoded") || strings.Contains(lower, "credential"):
		return "检测到硬编码凭据或敏感信息访问风险"
	case strings.Contains(lower, "download"):
		return "检测到可疑下载行为风险"
	case strings.Contains(lower, "execute") || strings.Contains(lower, "command"):
		return "检测到可疑执行链路风险"
	case strings.Contains(lower, "outbound") || strings.Contains(lower, "network") || strings.Contains(lower, "c2") || strings.Contains(lower, "beacon"):
		return "检测到可疑外联或远程控制风险"
	case strings.Contains(lower, "persistence"):
		return "检测到可疑持久化风险"
	case strings.Contains(lower, "privilege") || strings.Contains(lower, "privesc"):
		return "检测到提权相关风险"
	case strings.Contains(lower, "evasion") || strings.Contains(lower, "sandbox") || strings.Contains(lower, "vm"):
		return "检测到反分析或规避检测风险"
	case strings.Contains(lower, "lateral"):
		return "检测到横向移动风险"
	case strings.Contains(lower, "collection"):
		return "检测到敏感数据收集风险"
	case strings.Contains(lower, "suspicious") || strings.Contains(lower, "malicious"):
		return "检测到可疑恶意行为风险"
	default:
		return fallback
	}
}

func containsChinese(s string) bool {
	for _, r := range s {
		if unicode.Is(unicode.Han, r) {
			return true
		}
	}
	return false
}

func localizeRiskLevel(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "low":
		return "低风险"
	case "medium":
		return "中风险"
	case "high":
		return "高风险"
	case "critical":
		return "严重风险"
	default:
		if strings.TrimSpace(v) == "" {
			return "未评估"
		}
		return v
	}
}

func localizeReputation(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "trusted":
		return "可信"
	case "internal":
		return "内网或本地目标"
	case "suspicious":
		return "可疑"
	case "unknown":
		return "未知"
	default:
		if strings.TrimSpace(v) == "" {
			return "未知"
		}
		return v
	}
}

func buildBehaviorSummary(behavior review.BehaviorProfile) string {
	parts := make([]string, 0, 4)
	if len(behavior.NetworkTargets) > 0 {
		parts = append(parts, fmt.Sprintf("外联目标 %d 个（证据: %s）", len(behavior.NetworkTargets), sampleTarget(behavior.NetworkTargets)))
	}
	if len(behavior.FileTargets) > 0 {
		parts = append(parts, fmt.Sprintf("文件操作 %d 个（证据: %s）", len(behavior.FileTargets), sampleTarget(behavior.FileTargets)))
	}
	if len(behavior.ExecTargets) > 0 {
		parts = append(parts, fmt.Sprintf("命令执行 %d 个（证据: %s）", len(behavior.ExecTargets), sampleTarget(behavior.ExecTargets)))
	}
	if len(behavior.BehaviorChains) > 0 {
		parts = append(parts, fmt.Sprintf("高风险链路 %d 条", len(behavior.BehaviorChains)))
	}
	if len(parts) == 0 {
		return "未检测到明显运行时行为证据"
	}
	return strings.Join(parts, "；")
}

func buildObfuscationEvidence(files []evaluator.SourceFile) []review.ObfuscationEvidence {
	out := make([]review.ObfuscationEvidence, 0)
	for _, file := range files {
		pre := strings.TrimSpace(file.PreprocessedContent)
		if pre == "" {
			continue
		}
		relPath := filepath.ToSlash(strings.TrimSpace(file.Path))
		ev := review.ObfuscationEvidence{
			Path:            relPath,
			DataFlowSignals: evaluator.ExtractDataFlowSignals(file.Content, file.PreprocessedContent),
		}
		for _, line := range strings.Split(pre, "\n") {
			line = strings.TrimSpace(line)
			switch {
			case strings.HasPrefix(line, "technique: "):
				ev.Technique = strings.TrimSpace(strings.TrimPrefix(line, "technique: "))
			case strings.HasPrefix(line, "confidence: "):
				ev.Confidence = strings.TrimSpace(strings.TrimPrefix(line, "confidence: "))
			case strings.HasPrefix(line, "summary: "):
				ev.Summary = strings.TrimSpace(strings.TrimPrefix(line, "summary: "))
			case strings.HasPrefix(line, "decoded: "):
				ev.DecodedText = strings.TrimSpace(strings.TrimPrefix(line, "decoded: "))
			case strings.HasPrefix(line, "benign: "):
				ev.BenignIndicators = splitPipeList(strings.TrimSpace(strings.TrimPrefix(line, "benign: ")))
			case strings.HasPrefix(line, "risk: "):
				ev.RiskIndicators = splitPipeList(strings.TrimSpace(strings.TrimPrefix(line, "risk: ")))
			}
		}
		if ev.Summary == "" && ev.DecodedText == "" && ev.Technique == "" {
			continue
		}
		out = append(out, ev)
	}
	return out
}

func splitPipeList(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, "|")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func sampleTarget(items []string) string {
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		r := []rune(item)
		if len(r) > 40 {
			return string(r[:40]) + "..."
		}
		return item
	}
	return "无"
}

// reportLang 从环境变量获取报告语言，默认中文。
func reportLang() string {
	lang := strings.TrimSpace(os.Getenv("REPORT_LANG"))
	if lang == "" {
		return "zh"
	}
	return lang
}

func buildHTMLReport(fileName, declaredDescription string, findings []plugins.Finding, base baseScanOutput, refined review.Result, evalLogs []ruleEvaluationLog) string {
	base, refined, integrity := enforceReportConsistency(findings, base, refined)
	var b strings.Builder
	_ = buildRiskCalibrationSummary(findings, base, refined) // 用于 JSON 报告
	highRisk, mediumRisk, lowRisk := displayRiskCounts(refined)
	lang := reportLang()
	t := ir.NewTranslator(ir.Language(lang))
	riskLevel, decision := decisionFromReviewedFindings(base, refined)
	rawRiskCounts := map[string]int{
		"high":   refined.Summary.HighRisk,
		"medium": refined.Summary.MediumRisk,
		"low":    refined.Summary.LowRisk,
	}
	supplyChainSummary := buildSupplyChainSummary(refined.StructuredFindings)
	sandboxRetrySummary := buildSandboxRetrySummary(refined)
	httpProbeOverview := buildHTTPProbeOverviewPayload(buildHTTPProbeSummary(sandboxRetrySummary))
	traceMetadataSummary := buildTraceMetadataSummary(base, refined, rawRiskCounts)
	closureNarrative := buildClosureNarrative(refined)
	langAttr := "zh-CN"
	if lang == "en" {
		langAttr = "en"
	} else if lang == "ja" {
		langAttr = "ja"
	}
	b.WriteString(fmt.Sprintf("<!doctype html><html lang=\"%s\"><head><meta charset=\"utf-8\"><title>%s</title>", langAttr, t.T("report.title")))
	b.WriteString(renderReportStyles())
	b.WriteString("<h1>" + t.T("report.title") + "</h1>")
	b.WriteString("<section class=\"hero\"><p class=\"pill\">" + html.EscapeString(reportGeneratorNote) + "</p><p>" + t.T("report.disclaimer") + "</p>")
	b.WriteString("<p class=\"hint\" style=\"color:rgba(255,255,255,.84);margin:8px 0 0\">" + t.T("report.score_hint") + "</p>")
	b.WriteString("<p class=\"hint\" style=\"color:rgba(255,255,255,.84);margin:8px 0 0\">" + t.T("report.generated_at") + ": " + html.EscapeString(time.Now().Format("2006-01-02 15:04:05")) + "</p>")
	if strings.TrimSpace(declaredDescription) != "" {
		b.WriteString("<p class=\"hint\" style=\"color:rgba(255,255,255,.84);margin:8px 0 0\"><strong>" + t.T("report.declaration") + ":</strong> " + html.EscapeString(declaredDescription) + "</p>")
	}
	b.WriteString("<div class=\"hero-grid\">")
	b.WriteString("<div class=\"hero-stat\"><strong>" + t.T("report.file") + "</strong><span>" + html.EscapeString(fileName) + "</span></div>")
	b.WriteString("<div class=\"hero-stat\"><strong>" + t.T("report.decision") + "</strong><span>" + html.EscapeString(heroDecisionText(decision, refined)) + "</span><p class=\"hint\" style=\"color:rgba(255,255,255,.78);margin:6px 0 0\">" + t.T("report.decision_hint") + "</p></div>")
	b.WriteString("<div class=\"hero-stat\"><strong>" + t.T("report.risk_level") + "</strong><span>" + html.EscapeString(localizeRiskLevel(riskLevel)) + "</span></div>")
	b.WriteString(fmt.Sprintf("<div class=\"hero-stat\"><strong>"+t.T("report.risk_summary")+"</strong><span>%d / %d / %d</span><p class=\"hint\" style=\"color:rgba(255,255,255,.78);margin:6px 0 0\">"+t.T("risk.high")+" / "+t.T("risk.medium")+" / "+t.T("risk.low")+"</p></div>", highRisk, mediumRisk, lowRisk))
	b.WriteString(renderHeroHTTPProbeStats(httpProbeOverview))
	b.WriteString("</div></section>")
	b.WriteString("<div class=\"card\" style=\"margin-top:14px\"><p><strong>" + t.T("report.closure_summary") + ":</strong> " + html.EscapeString(closureNarrative) + "</p></div>")
	b.WriteString("<nav class=\"nav\"><a href=\"#verification-summary\">" + t.T("nav.verification") + "</a><a href=\"#behavior-combination\">" + t.T("nav.behavior") + "</a><a href=\"#analysis-profile\">" + t.T("nav.profile") + "</a><a href=\"#structured-findings\">" + t.T("nav.findings") + "</a><a href=\"#review-trace\">" + t.T("nav.trace") + "</a><a href=\"#mitre-summary\">" + t.T("nav.mitre") + "</a><a href=\"#appendix\">" + t.T("nav.appendix") + "</a></nav>")
	b.WriteString(renderBusinessRiskDashboard(refined))

	b.WriteString(renderVerificationSummaryCard(refined))
	b.WriteString(renderSingleSkillBehaviorCombinationSection(refined))
	b.WriteString(renderRemediationVerificationSection(refined.RemediationVerification))
	b.WriteString(renderDetectionDegradationSection(fileName, refined, base.detectionErrors))

	b.WriteString("<div id=\"analysis-profile\" class=\"card\"><div class=\"section-head\"><h2>技能分析画像</h2><span class=\"hint\">声明、依赖、权限与源码能力信号统一汇总。</span></div>")
	b.WriteString("<p><strong>分析模式:</strong> " + html.EscapeString(defaultIfEmpty(base.profile.AnalysisMode, "全链路分析")) + "</p>")
	b.WriteString(renderIntentList("声明来源", base.profile.DeclarationSources))
	b.WriteString(renderIntentList("纳入分析的源码/声明文件", base.profile.SourceFiles))
	b.WriteString(renderIntentList("依赖清单", base.profile.Dependencies))
	b.WriteString(renderIntentList("用户声明权限", base.profile.Permissions))
	b.WriteString(renderIntentList("语言/文件类型分布", base.profile.LanguageSummary))
	b.WriteString(renderIntentList("源码能力信号", base.profile.CapabilitySignals))
	b.WriteString(fmt.Sprintf("<p class=\"hint\">纳入分析文件 %d 个，声明来源 %d 个，依赖 %d 个。</p>", base.profile.SourceFileCount, base.profile.DeclarationCount, base.profile.DependencyCount))
	if len(refined.ObfuscationEvidence) > 0 {
		items := make([]string, 0, len(refined.ObfuscationEvidence))
		for _, ev := range refined.ObfuscationEvidence {
			parts := []string{ev.Path}
			if strings.TrimSpace(ev.Technique) != "" {
				parts = append(parts, "技术="+ev.Technique)
			}
			if strings.TrimSpace(ev.Confidence) != "" {
				parts = append(parts, "置信度="+ev.Confidence)
			}
			if strings.TrimSpace(ev.Summary) != "" {
				parts = append(parts, "摘要="+ev.Summary)
			}
			if len(ev.DataFlowSignals) > 0 {
				parts = append(parts, "数据流="+strings.Join(ev.DataFlowSignals, "、"))
			}
			items = append(items, strings.Join(parts, "；"))
		}
		b.WriteString(renderIntentList("混淆解析证据", items))
	}
	b.WriteString("</div>")
	b.WriteString(renderSupplyChainSummarySection(supplyChainSummary))
	b.WriteString(renderHTTPProbeOverviewSection(sandboxRetrySummary))
	b.WriteString(renderSandboxRetrySummarySection(sandboxRetrySummary))
	b.WriteString(renderTraceMetadataSummarySection(traceMetadataSummary))

	b.WriteString(renderStructuredFindingsSection(refined))
	b.WriteString(renderReviewTraceIntegratedCard(refined))
	b.WriteString(renderMITRESummarySection(refined.StructuredFindings))

	b.WriteString(renderAppendixSection(base, evalLogs, integrity))

	// “汇总修复建议”与综合研判重复，已移除并以每条风险内的一一对应建议为准。

	b.WriteString("</body></html>")
	return b.String()
}

func renderHeroHTTPProbeStats(overview map[string]interface{}) string {
	if overview == nil {
		return ""
	}
	matchedCount, _ := overview["matched_target_count"].(int)
	missedCount, _ := overview["missed_target_count"].(int)
	topFailureReasons, _ := overview["top_failure_reasons"].([]string)
	topFailureBadges := []string{"未提取"}
	if len(topFailureReasons) > 0 {
		topFailureBadges = limitList(topFailureReasons, 3)
	}
	var b strings.Builder
	b.WriteString(fmt.Sprintf("<div class=\"hero-stat\"><strong>HTTP 命中</strong><span>%d</span><p class=\"hint\" style=\"color:rgba(255,255,255,.78);margin:6px 0 0\">本次本地探针命中的入口数</p></div>", matchedCount))
	b.WriteString(fmt.Sprintf("<div class=\"hero-stat\"><strong>HTTP 未命中</strong><span>%d</span><p class=\"hint\" style=\"color:rgba(255,255,255,.78);margin:6px 0 0\">候选入口仍未命中的数量</p></div>", missedCount))
	b.WriteString("<div class=\"hero-stat\"><strong>Top Failure</strong><div style=\"margin-top:8px;display:flex;flex-wrap:wrap;gap:8px\">")
	for _, item := range topFailureBadges {
		b.WriteString("<span class=\"pill\" style=\"" + html.EscapeString(httpProbeFailureBadgeStyle(item)) + "\">" + html.EscapeString(item) + "</span>")
	}
	b.WriteString("</div><p class=\"hint\" style=\"color:rgba(255,255,255,.78);margin:10px 0 0\">最高频的 HTTP 探针失败根因</p></div>")
	return b.String()
}

func httpProbeFailureBadgeStyle(item string) string {
	base := "font-size:14px;color:#fff;"
	lower := strings.ToLower(strings.TrimSpace(item))
	switch {
	case strings.Contains(lower, "bind_failed"), strings.Contains(lower, "module_missing"), strings.Contains(lower, "import_error"), strings.Contains(lower, "runtime_exception"), strings.Contains(lower, "address_in_use"):
		return base + "background:rgba(180,35,24,.32);border-color:rgba(255,255,255,.30)"
	case strings.Contains(lower, "connection_refused"), strings.Contains(lower, "no_listener_detected"), strings.Contains(lower, "connection_reset"), strings.Contains(lower, "dns_failure"):
		return base + "background:rgba(33,86,209,.30);border-color:rgba(255,255,255,.30)"
	default:
		return base + "background:rgba(181,71,8,.30);border-color:rgba(255,255,255,.30)"
	}
}

func buildSupplyChainSummary(findings []review.StructuredFinding) map[string]interface{} {
	matched := make([]review.StructuredFinding, 0)
	packages := make([]string, 0)
	vulns := make([]string, 0)
	evidence := make([]string, 0)
	seenPackages := map[string]struct{}{}
	seenVulns := map[string]struct{}{}
	seenEvidence := map[string]struct{}{}
	for _, finding := range findings {
		if !isSupplyChainFinding(finding) {
			continue
		}
		matched = append(matched, finding)
		for _, line := range append([]string{}, finding.Evidence...) {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" {
				continue
			}
			lower := strings.ToLower(trimmed)
			if strings.Contains(lower, "dependency=") {
				if pkg := extractSupplyChainField(trimmed, "dependency="); pkg != "" {
					if _, ok := seenPackages[pkg]; !ok {
						seenPackages[pkg] = struct{}{}
						packages = append(packages, pkg)
					}
				}
				if vuln := extractSupplyChainField(trimmed, "vuln="); vuln != "" {
					if _, ok := seenVulns[vuln]; !ok {
						seenVulns[vuln] = struct{}{}
						vulns = append(vulns, vuln)
					}
				}
			}
			if _, ok := seenEvidence[trimmed]; ok {
				continue
			}
			seenEvidence[trimmed] = struct{}{}
			evidence = append(evidence, trimmed)
		}
	}
	if len(matched) == 0 {
		return nil
	}
	return map[string]interface{}{
		"count":             len(matched),
		"packages":          packages,
		"vulnerability_ids": vulns,
		"evidence":          limitList(evidence, 6),
	}
}

func isSupplyChainFinding(finding review.StructuredFinding) bool {
	if finding.Category == "环境与构建风险" && finding.Title == "依赖漏洞与供应链风险" {
		return true
	}
	text := strings.ToLower(strings.Join(append([]string{finding.RuleID, finding.Title}, finding.Evidence...), " "))
	return strings.Contains(text, "osv") || strings.Contains(text, "ghsa-") || strings.Contains(text, "dependency=")
}

func extractSupplyChainField(line, key string) string {
	idx := strings.Index(strings.ToLower(line), strings.ToLower(key))
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	segment := line[start:]
	for _, sep := range []string{" ", "\n", "\t", "；", ","} {
		if idx := strings.Index(segment, sep); idx >= 0 {
			segment = segment[:idx]
		}
	}
	return strings.TrimSpace(segment)
}

func renderSupplyChainSummarySection(summary map[string]interface{}) string {
	if summary == nil {
		return ""
	}
	count, _ := summary["count"].(int)
	packages, _ := summary["packages"].([]string)
	vulns, _ := summary["vulnerability_ids"].([]string)
	evidence, _ := summary["evidence"].([]string)
	var b strings.Builder
	b.WriteString("<div id=\"supply-chain-summary\" class=\"card\"><div class=\"section-head\"><h2>依赖漏洞与供应链摘要</h2><span class=\"hint\">集中展示 OSV 命中依赖、漏洞编号和关键证据，便于快速判断是否需要阻断发布。</span></div>")
	b.WriteString("<p><strong>命中项数:</strong> " + strconv.Itoa(count) + "</p>")
	b.WriteString(renderHTMLLabeledList("命中依赖", packages, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("漏洞编号", vulns, 8, "未提取"))
	b.WriteString(renderHTMLEvidenceList("关键证据", evidence, "未提取"))
	b.WriteString("</div>")
	return b.String()
}

func renderHTTPProbeOverviewSection(summary map[string]interface{}) string {
	if summary == nil {
		return ""
	}
	httpProbeCandidates, _ := summary["http_probe_candidates"].([]string)
	httpProbeMisses, _ := summary["http_probe_misses"].([]string)
	httpProbeResults, _ := summary["http_probe_results"].([]string)
	httpReachableResults, _ := summary["http_probe_reachable"].([]string)
	httpAuthRequiredResults, _ := summary["http_probe_auth_required"].([]string)
	httpMethodMismatchResults, _ := summary["http_probe_method_mismatch"].([]string)
	httpOtherResults, _ := summary["http_probe_other_status"].([]string)
	httpTimeoutResults, _ := summary["http_probe_timeout"].([]string)
	httpStartupFailedResults, _ := summary["http_probe_startup_failed"].([]string)
	httpEarlyExitResults, _ := summary["http_probe_early_exit"].([]string)
	httpServiceUnreachableResults, _ := summary["http_probe_service_unreachable"].([]string)
	httpFailureReasons, _ := summary["http_probe_failure_reasons"].([]string)
	httpFailureReasonCounts, _ := summary["http_probe_failure_reason_counts"].([]string)
	httpProbeRepairActions, _ := summary["http_probe_repair_actions"].([]string)
	httpProbeResponseDigests, _ := summary["http_probe_response_digests"].([]string)
	runtimeObservationSummary, _ := summary["runtime_observation_summary"].([]string)
	if len(httpProbeCandidates) == 0 && len(httpProbeMisses) == 0 && len(httpProbeResults) == 0 && len(httpProbeResponseDigests) == 0 && len(httpReachableResults) == 0 && len(httpAuthRequiredResults) == 0 && len(httpMethodMismatchResults) == 0 && len(httpOtherResults) == 0 && len(httpTimeoutResults) == 0 && len(httpStartupFailedResults) == 0 && len(httpEarlyExitResults) == 0 && len(httpServiceUnreachableResults) == 0 && len(httpFailureReasons) == 0 && len(httpProbeRepairActions) == 0 && len(runtimeObservationSummary) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("<div id=\"http-probe-overview\" class=\"card\"><div class=\"section-head\"><h2>HTTP 探针概览</h2><span class=\"hint\">突出展示源码提取出的候选端口与路径、仍未命中的入口，以及最终实际命中的服务响应。</span></div>")
	b.WriteString(renderHTMLLabeledList("Runtime 观测摘要", runtimeObservationSummary, 5, "未提取"))
	b.WriteString(renderHTMLLabeledList("候选端口与路径", httpProbeCandidates, 8, "未提取"))
	b.WriteString(renderHTTPProbeThreeColumnSection(httpProbeResults, httpProbeResponseDigests, httpProbeMisses, httpFailureReasonCounts, httpProbeRepairActions))
	b.WriteString(renderHTMLLabeledList("可达入口", httpReachableResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("需认证入口", httpAuthRequiredResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("方法不匹配入口", httpMethodMismatchResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("其他状态入口", httpOtherResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("探针超时入口", httpTimeoutResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("启动失败入口", httpStartupFailedResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("提前退出入口", httpEarlyExitResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("服务未起入口", httpServiceUnreachableResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("失败根因聚合", httpFailureReasonCounts, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("建议修复动作", httpProbeRepairActions, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("失败根因标签", httpFailureReasons, 8, "未提取"))
	b.WriteString("</div>")
	return b.String()
}

func renderHTTPProbeThreeColumnSection(results, responseDigests, misses, failureReasonCounts, repairActions []string) string {
	missReasons := uniqueStrings(append(append([]string{}, misses...), failureReasonCounts...))
	var b strings.Builder
	b.WriteString("<div class=\"grid-two\">")
	b.WriteString(renderHTMLLabeledList("命中证据", uniqueStrings(append(append([]string{}, results...), responseDigests...)), 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("未命中原因", missReasons, 8, "未提取"))
	b.WriteString("</div>")
	b.WriteString(renderHTMLLabeledList("修复动作", repairActions, 8, "未提取"))
	return b.String()
}

func buildSandboxRetrySummary(refined review.Result) map[string]interface{} {
	var retryStage *review.PipelineStage
	for i := range refined.Pipeline {
		if refined.Pipeline[i].Name == "sandbox_retry" {
			retryStage = &refined.Pipeline[i]
			break
		}
	}
	triggeredDiffs := make([]string, 0)
	for _, diff := range refined.Behavior.Differentials {
		if diff.Triggered {
			triggeredDiffs = append(triggeredDiffs, defaultIfEmpty(strings.TrimSpace(diff.Summary), strings.TrimSpace(diff.Scenario)))
		}
	}
	if retryStage == nil && len(refined.Behavior.ProbeWarnings) == 0 && len(triggeredDiffs) == 0 {
		return nil
	}
	status := "未执行"
	input := ""
	output := ""
	scenarios := limitList(refined.Behavior.ExecutionScenarios, 8)
	executionResults := make([]string, 0, len(refined.Behavior.ScenarioExecutions))
	runtimeObservationSummary := make([]string, 0, 5)
	httpProbeCandidates := make([]string, 0)
	httpProbeMisses := make([]string, 0)
	httpProbeResults := make([]string, 0)
	httpProbeResponseDigests := make([]string, 0)
	httpProbePathMethods := make([]string, 0)
	httpReachableResults := make([]string, 0)
	httpAuthRequiredResults := make([]string, 0)
	httpMethodMismatchResults := make([]string, 0)
	httpOtherResults := make([]string, 0)
	httpTimeoutResults := make([]string, 0)
	httpStartupFailedResults := make([]string, 0)
	httpEarlyExitResults := make([]string, 0)
	httpServiceUnreachableResults := make([]string, 0)
	httpFailureReasons := make([]string, 0)
	for _, item := range refined.Behavior.ScenarioExecutions {
		parts := []string{defaultIfEmpty(strings.TrimSpace(item.Name), "default")}
		if strings.TrimSpace(item.Command) != "" {
			parts = append(parts, "command="+strings.TrimSpace(item.Command))
		}
		parts = append(parts, fmt.Sprintf("exit=%d", item.ExitCode))
		if len(item.InputFiles) > 0 {
			parts = append(parts, "inputs="+strings.Join(item.InputFiles, ","))
		}
		if len(item.Output) > 0 {
			parts = append(parts, "output="+strings.Join(limitList(item.Output, 2), " | "))
		}
		candidateParts := []string{defaultIfEmpty(strings.TrimSpace(item.Name), "default")}
		if len(item.HTTPPorts) > 0 {
			candidateParts = append(candidateParts, "ports="+strings.Join(intListToStrings(limitIntList(item.HTTPPorts, 4)), ","))
		}
		if len(item.HTTPPaths) > 0 {
			candidateParts = append(candidateParts, "paths="+strings.Join(limitList(item.HTTPPaths, 4), ","))
		}
		if len(item.HTTPPathMethods) > 0 {
			formattedPathMethods := formatHTTPPathMethodsForPaths(item.HTTPPathMethods, item.HTTPPaths, 4)
			candidateParts = append(candidateParts, "path_methods="+strings.Join(formattedPathMethods, ","))
			if len(formattedPathMethods) > 0 {
				httpProbePathMethods = append(httpProbePathMethods, defaultIfEmpty(strings.TrimSpace(item.Name), "default")+" | path_methods="+strings.Join(formattedPathMethods, ","))
			}
		}
		if len(candidateParts) > 1 {
			httpProbeCandidates = append(httpProbeCandidates, strings.Join(candidateParts, " | "))
		}
		missParts := []string{defaultIfEmpty(strings.TrimSpace(item.Name), "default")}
		missCandidateParts := make([]string, 0, 2)
		if len(item.HTTPPorts) > 0 {
			missPorts := make([]int, 0, len(item.HTTPPorts))
			for _, port := range item.HTTPPorts {
				if port != item.HTTPPort {
					missPorts = append(missPorts, port)
				}
			}
			if len(missPorts) > 0 {
				missCandidateParts = append(missCandidateParts, "ports="+strings.Join(intListToStrings(limitIntList(missPorts, 4)), ","))
			}
		}
		if len(item.HTTPPaths) > 0 {
			missPaths := make([]string, 0, len(item.HTTPPaths))
			for _, path := range item.HTTPPaths {
				if strings.TrimSpace(path) != strings.TrimSpace(item.HTTPPath) {
					missPaths = append(missPaths, path)
				}
			}
			if len(missPaths) > 0 {
				missCandidateParts = append(missCandidateParts, "paths="+strings.Join(limitList(missPaths, 4), ","))
				if len(item.HTTPPathMethods) > 0 {
					missCandidateParts = append(missCandidateParts, "path_methods="+strings.Join(formatHTTPPathMethodsForPaths(item.HTTPPathMethods, missPaths, 4), ","))
				}
			}
		}
		if len(missCandidateParts) > 0 {
			missSummary := strings.Join(append(missParts, missCandidateParts...), " | ")
			httpProbeMisses = append(httpProbeMisses, missSummary)
			if item.HTTPPort == 0 {
				failureType, failureReason := classifyHTTPProbeMiss(item)
				if failureReason != "" {
					httpFailureReasons = append(httpFailureReasons, missSummary+" | reason="+failureReason)
				}
				switch failureType {
				case "timeout":
					httpTimeoutResults = append(httpTimeoutResults, missSummary)
				case "startup_failed":
					httpStartupFailedResults = append(httpStartupFailedResults, missSummary)
				case "early_exit":
					httpEarlyExitResults = append(httpEarlyExitResults, missSummary)
				default:
					httpServiceUnreachableResults = append(httpServiceUnreachableResults, missSummary)
				}
			}
		}
		if item.HTTPPort > 0 {
			probeParts := []string{defaultIfEmpty(strings.TrimSpace(item.Name), "default"), fmt.Sprintf("port=%d", item.HTTPPort)}
			if strings.TrimSpace(item.HTTPMethod) != "" {
				probeParts = append(probeParts, "method="+strings.TrimSpace(item.HTTPMethod))
			}
			if strings.TrimSpace(item.HTTPPath) != "" {
				probeParts = append(probeParts, "path="+strings.TrimSpace(item.HTTPPath))
			}
			probeParts = append(probeParts, fmt.Sprintf("status=%d", item.HTTPStatusCode))
			probeSummary := strings.Join(probeParts, " | ")
			httpProbeResults = append(httpProbeResults, probeSummary)
			if digest := httpProbeResponseDigest(item); digest != "" {
				httpProbeResponseDigests = append(httpProbeResponseDigests, digest)
			}
			switch item.HTTPStatusCode {
			case 200, 201, 202, 204:
				httpReachableResults = append(httpReachableResults, probeSummary)
			case 401, 403:
				httpAuthRequiredResults = append(httpAuthRequiredResults, probeSummary)
			case 405:
				httpMethodMismatchResults = append(httpMethodMismatchResults, probeSummary)
			default:
				httpOtherResults = append(httpOtherResults, probeSummary)
			}
		}
		executionResults = append(executionResults, strings.Join(parts, " | "))
	}
	if retryStage != nil {
		status = localizePipelineStageStatus(retryStage.Status)
		input = strings.TrimSpace(retryStage.Input)
		output = strings.TrimSpace(retryStage.Output)
	}
	httpFailureReasonCounts := summarizeHTTPProbeFailureReasons(httpFailureReasons)
	if len(refined.Behavior.ScenarioExecutions) > 0 {
		runtimeObservationSummary = append(runtimeObservationSummary, fmt.Sprintf("执行场景 %d 个，HTTP 候选 %d 个，命中 %d 个，未命中 %d 个", len(refined.Behavior.ScenarioExecutions), len(httpProbeCandidates), len(httpProbeResults), len(httpProbeMisses)))
	}
	if len(httpReachableResults) > 0 {
		runtimeObservationSummary = append(runtimeObservationSummary, fmt.Sprintf("可达入口 %d 个", len(httpReachableResults)))
	}
	if len(httpAuthRequiredResults) > 0 || len(httpMethodMismatchResults) > 0 || len(httpOtherResults) > 0 {
		runtimeObservationSummary = append(runtimeObservationSummary, fmt.Sprintf("非 2xx 响应 %d 个", len(httpAuthRequiredResults)+len(httpMethodMismatchResults)+len(httpOtherResults)))
	}
	if len(httpFailureReasonCounts) > 0 {
		runtimeObservationSummary = append(runtimeObservationSummary, "失败根因: "+strings.Join(limitList(httpFailureReasonCounts, 4), "；"))
	}
	httpProbeRepairActions := buildHTTPProbeRepairActions(httpFailureReasonCounts)
	if len(refined.Behavior.ProbeWarnings) > 0 {
		runtimeObservationSummary = append(runtimeObservationSummary, fmt.Sprintf("探针告警 %d 条", len(refined.Behavior.ProbeWarnings)))
	}
	return map[string]interface{}{
		"status":                           status,
		"trigger_input":                    input,
		"result":                           output,
		"runtime_observation_summary":      limitList(runtimeObservationSummary, 5),
		"probe_warnings":                   limitList(refined.Behavior.ProbeWarnings, 6),
		"execution_scenarios":              scenarios,
		"scenario_executions":              limitList(executionResults, 8),
		"http_probe_candidates":            limitList(httpProbeCandidates, 8),
		"http_probe_misses":                limitList(httpProbeMisses, 8),
		"http_probe_results":               limitList(httpProbeResults, 8),
		"http_probe_response_digests":      limitList(uniqueStrings(httpProbeResponseDigests), 8),
		"http_probe_path_methods":          limitList(httpProbePathMethods, 8),
		"http_probe_reachable":             limitList(httpReachableResults, 8),
		"http_probe_auth_required":         limitList(httpAuthRequiredResults, 8),
		"http_probe_method_mismatch":       limitList(httpMethodMismatchResults, 8),
		"http_probe_other_status":          limitList(httpOtherResults, 8),
		"http_probe_timeout":               limitList(httpTimeoutResults, 8),
		"http_probe_startup_failed":        limitList(httpStartupFailedResults, 8),
		"http_probe_early_exit":            limitList(httpEarlyExitResults, 8),
		"http_probe_service_unreachable":   limitList(httpServiceUnreachableResults, 8),
		"http_probe_failure_reasons":       limitList(httpFailureReasons, 8),
		"http_probe_failure_reason_counts": httpFailureReasonCounts,
		"http_probe_repair_actions":        httpProbeRepairActions,
		"triggered_differentials":          limitList(triggeredDiffs, 6),
	}
}

func classifyHTTPProbeMiss(item review.ScenarioExecution) (string, string) {
	joinedOutput := strings.ToLower(strings.Join(item.Output, " | "))
	switch {
	case strings.Contains(joinedOutput, "http_probe_budget"):
		return "service_unreachable", "probe_budget_exhausted"
	case strings.Contains(joinedOutput, "timed out") || strings.Contains(joinedOutput, "timeout") || item.ExitCode == 124:
		return "timeout", "probe_timeout"
	case strings.Contains(joinedOutput, "connection refused") || strings.Contains(joinedOutput, "[errno 111]"):
		return "service_unreachable", "connection_refused"
	case strings.Contains(joinedOutput, "bind failed") || strings.Contains(joinedOutput, "listen failed"):
		return "startup_failed", "bind_failed"
	case strings.Contains(joinedOutput, "address already in use"):
		return "startup_failed", "address_in_use"
	case strings.Contains(joinedOutput, "no module named"):
		return "startup_failed", "module_missing"
	case strings.Contains(joinedOutput, "importerror") || strings.Contains(joinedOutput, "cannot import"):
		return "startup_failed", "import_error"
	case strings.Contains(joinedOutput, "traceback") || strings.Contains(joinedOutput, "exception") || item.ExitCode == 125:
		return "startup_failed", "runtime_exception"
	case strings.Contains(joinedOutput, "process exited before http probe completed"):
		return "early_exit", "process_early_exit"
	case item.ExitCode != 0:
		return "early_exit", "process_early_exit"
	default:
		return "service_unreachable", "no_listener_detected"
	}
}

func httpProbeResponseDigest(item review.ScenarioExecution) string {
	if item.HTTPPort <= 0 {
		return ""
	}
	parts := []string{defaultIfEmpty(strings.TrimSpace(item.Name), "default")}
	if method := strings.TrimSpace(item.HTTPMethod); method != "" {
		parts = append(parts, "method="+method)
	}
	if item.HTTPPort > 0 {
		parts = append(parts, fmt.Sprintf("port=%d", item.HTTPPort))
	}
	if path := strings.TrimSpace(item.HTTPPath); path != "" {
		parts = append(parts, "path="+path)
	}
	parts = append(parts, fmt.Sprintf("status=%d", item.HTTPStatusCode))
	for _, line := range item.Output {
		line = strings.TrimSpace(line)
		if !strings.Contains(line, "http_probe") {
			continue
		}
		if bodyHash := extractRuntimeHTTPProbeToken(line, "body_sha256="); bodyHash != "" {
			parts = append(parts, "body_sha256="+bodyHash)
		}
		if bodySample := extractRuntimeHTTPProbeBodySample(line); bodySample != "" {
			parts = append(parts, "body_sample="+bodySample)
		}
		break
	}
	if len(parts) <= 4 {
		return ""
	}
	return strings.Join(parts, " | ")
}

func formatHTTPPathMethods(pathMethods map[string][]string, max int) []string {
	if len(pathMethods) == 0 {
		return nil
	}
	paths := make([]string, 0, len(pathMethods))
	for path := range pathMethods {
		path = strings.TrimSpace(path)
		if path != "" {
			paths = append(paths, path)
		}
	}
	sort.Strings(paths)
	return formatHTTPPathMethodsForPaths(pathMethods, paths, max)
}

func formatHTTPPathMethodsForPaths(pathMethods map[string][]string, paths []string, max int) []string {
	if len(pathMethods) == 0 || max == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, max)
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		methods := uniqueStrings(pathMethods[path])
		if len(methods) == 0 {
			continue
		}
		out = append(out, path+":"+strings.Join(methods, "+"))
		if max > 0 && len(out) >= max {
			break
		}
	}
	return out
}

func renderSandboxRetrySummarySection(summary map[string]interface{}) string {
	if summary == nil {
		return ""
	}
	status, _ := summary["status"].(string)
	input, _ := summary["trigger_input"].(string)
	result, _ := summary["result"].(string)
	warnings, _ := summary["probe_warnings"].([]string)
	runtimeObservationSummary, _ := summary["runtime_observation_summary"].([]string)
	scenarios, _ := summary["execution_scenarios"].([]string)
	executions, _ := summary["scenario_executions"].([]string)
	httpProbeCandidates, _ := summary["http_probe_candidates"].([]string)
	httpProbeMisses, _ := summary["http_probe_misses"].([]string)
	httpProbeResults, _ := summary["http_probe_results"].([]string)
	httpReachableResults, _ := summary["http_probe_reachable"].([]string)
	httpAuthRequiredResults, _ := summary["http_probe_auth_required"].([]string)
	httpMethodMismatchResults, _ := summary["http_probe_method_mismatch"].([]string)
	httpOtherResults, _ := summary["http_probe_other_status"].([]string)
	httpTimeoutResults, _ := summary["http_probe_timeout"].([]string)
	httpStartupFailedResults, _ := summary["http_probe_startup_failed"].([]string)
	httpEarlyExitResults, _ := summary["http_probe_early_exit"].([]string)
	httpServiceUnreachableResults, _ := summary["http_probe_service_unreachable"].([]string)
	httpFailureReasons, _ := summary["http_probe_failure_reasons"].([]string)
	httpFailureReasonCounts, _ := summary["http_probe_failure_reason_counts"].([]string)
	httpProbeRepairActions, _ := summary["http_probe_repair_actions"].([]string)
	diffs, _ := summary["triggered_differentials"].([]string)
	var b strings.Builder
	b.WriteString("<div id=\"sandbox-retry-summary\" class=\"card\"><div class=\"section-head\"><h2>沙箱自动复测摘要</h2><span class=\"hint\">集中展示自动复测是否触发、触发原因和复测结果，便于判断当前行为证据是否完整。</span></div>")
	b.WriteString("<p><strong>复测状态:</strong> " + html.EscapeString(defaultIfEmpty(status, "未执行")) + "</p>")
	if strings.TrimSpace(input) != "" {
		b.WriteString(renderParagraphText("触发输入: " + input))
	}
	if strings.TrimSpace(result) != "" {
		b.WriteString(renderParagraphText("复测结果: " + result))
	}
	b.WriteString(renderHTMLLabeledList("Runtime 观测摘要", runtimeObservationSummary, 5, "未提取"))
	b.WriteString(renderHTMLLabeledList("探针告警", warnings, 6, "未提取"))
	b.WriteString(renderHTMLLabeledList("执行场景", scenarios, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("场景执行结果", executions, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 候选探针", httpProbeCandidates, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 未命中候选", httpProbeMisses, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 探针结果", httpProbeResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 可达入口", httpReachableResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 需认证入口", httpAuthRequiredResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 方法不匹配入口", httpMethodMismatchResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 其他状态入口", httpOtherResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 探针超时入口", httpTimeoutResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 启动失败入口", httpStartupFailedResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 提前退出入口", httpEarlyExitResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 服务未起入口", httpServiceUnreachableResults, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 失败根因聚合", httpFailureReasonCounts, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 建议修复动作", httpProbeRepairActions, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("HTTP 失败根因标签", httpFailureReasons, 8, "未提取"))
	b.WriteString(renderHTMLLabeledList("触发的差分信号", diffs, 6, "未提取"))
	b.WriteString("</div>")
	return b.String()
}

func localizePipelineStageStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "completed":
		return "已完成"
	case "running":
		return "执行中"
	case "failed":
		return "失败"
	default:
		return defaultIfEmpty(strings.TrimSpace(status), "未执行")
	}
}

func limitIntList(items []int, max int) []int {
	if max <= 0 || len(items) <= max {
		return append([]int{}, items...)
	}
	return append([]int{}, items[:max]...)
}

func intListToStrings(items []int) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, strconv.Itoa(item))
	}
	return out
}

func buildTraceMetadataSummary(base baseScanOutput, refined review.Result, rawRiskCounts map[string]int) map[string]interface{} {
	taskID := strings.TrimSpace(base.taskID)
	requestID := strings.TrimSpace(base.requestID)
	if taskID == "" && requestID == "" && len(base.trace) == 0 {
		return nil
	}
	highRisk, mediumRisk, lowRisk := displayRiskCounts(refined)
	stages := make([]string, 0, len(base.trace))
	for _, item := range base.trace {
		stage := strings.TrimSpace(item.Stage)
		status := strings.TrimSpace(item.Status)
		message := strings.TrimSpace(item.Message)
		if stage == "" && message == "" {
			continue
		}
		parts := make([]string, 0, 3)
		if stage != "" {
			parts = append(parts, stage)
		}
		if status != "" {
			parts = append(parts, localizePipelineStageStatus(status))
		}
		if message != "" {
			parts = append(parts, message)
		}
		stages = append(stages, strings.Join(parts, " / "))
	}
	summary := map[string]interface{}{
		"task_id":         taskID,
		"request_id":      requestID,
		"trace_stages":    limitList(stages, 8),
		"raw_risk_counts": rawRiskCounts,
		"normalized_risk_counts": map[string]int{
			"high":   highRisk,
			"medium": mediumRisk,
			"low":    lowRisk,
		},
	}
	if refined.CrossFileConsolidation != nil {
		summary["cross_file_consolidation"] = refined.CrossFileConsolidation
	}
	return summary
}

func renderTraceMetadataSummarySection(summary map[string]interface{}) string {
	if summary == nil {
		return ""
	}
	taskID, _ := summary["task_id"].(string)
	requestID, _ := summary["request_id"].(string)
	stages, _ := summary["trace_stages"].([]string)
	var b strings.Builder
	b.WriteString("<div id=\"trace-metadata-summary\" class=\"card\"><div class=\"section-head\"><h2>追踪元信息摘要</h2><span class=\"hint\">串联请求、异步任务和阶段化分析轨迹，便于排障、复盘和审计检索。</span></div>")
	b.WriteString("<p><strong>任务 ID:</strong> " + html.EscapeString(defaultIfEmpty(taskID, "未记录")) + "</p>")
	b.WriteString("<p><strong>请求 ID:</strong> " + html.EscapeString(defaultIfEmpty(requestID, "未记录")) + "</p>")
	b.WriteString(renderHTMLLabeledList("关键阶段", stages, 8, "未提取"))
	b.WriteString("</div>")
	return b.String()
}

func renderBusinessRiskDashboard(refined review.Result) string {
	highRisk, mediumRisk, lowRisk := displayRiskCounts(refined)
	total := highRisk + mediumRisk + lowRisk
	if total <= 0 {
		total = 1
	}
	httpFailureReasonCounts := httpProbeFailureReasonCountsFromResult(refined)
	highPct := float64(highRisk) * 100 / float64(total)
	medPct := float64(mediumRisk) * 100 / float64(total)
	lowPct := 100 - highPct - medPct
	var b strings.Builder
	b.WriteString("<div class=\"card\"><div class=\"section-head\"><h2>业务风险看板</h2><span class=\"hint\">用业务语言展示本次风险分布与优先级。</span></div>")
	b.WriteString("<p><strong>闭环解释:</strong> " + html.EscapeString(buildClosureNarrative(refined)) + "</p>")
	b.WriteString("<div class=\"grid-two\">")
	b.WriteString("<div class=\"finding-section\"><h3>风险分布</h3>")
	b.WriteString("<div style=\"display:flex;width:100%;height:18px;border-radius:999px;overflow:hidden;border:1px solid #d0d7e4\">")
	b.WriteString(fmt.Sprintf("<div style=\"width:%.2f%%;background:#b42318\" title=\"高风险\"></div>", highPct))
	b.WriteString(fmt.Sprintf("<div style=\"width:%.2f%%;background:#b54708\" title=\"中风险\"></div>", medPct))
	b.WriteString(fmt.Sprintf("<div style=\"width:%.2f%%;background:#067647\" title=\"低风险\"></div>", lowPct))
	b.WriteString("</div>")
	b.WriteString(fmt.Sprintf("<p style=\"margin-top:8px\"><strong>高风险:</strong> %d（%.1f%%） · <strong>中风险:</strong> %d（%.1f%%） · <strong>低风险:</strong> %d（%.1f%%）</p>", highRisk, highPct, mediumRisk, medPct, lowRisk, lowPct))
	b.WriteString("</div>")
	b.WriteString("<div class=\"finding-section\"><h3>业务优先级建议</h3>")
	if highRisk > 0 {
		b.WriteString("<p><strong>高优先级（今天处理）:</strong> 先关闭高风险入口，优先处理可被外部触发或可导致数据外发的链路。</p>")
	}
	if mediumRisk > 0 {
		b.WriteString("<p><strong>中优先级（本周处理）:</strong> 收敛权限边界、目标白名单和参数校验，避免风险升级。</p>")
	}
	b.WriteString("<p><strong>低优先级（排期优化）:</strong> 对低风险项进行代码规范化和防误用加固。</p>")
	b.WriteString(renderHTMLLabeledList("HTTP 失败根因聚合", httpFailureReasonCounts, 4, "当前无可聚合的 HTTP 探针失败根因。"))
	b.WriteString("</div></div></div>")
	return b.String()
}

func httpProbeFailureReasonCountsFromResult(refined review.Result) []string {
	summary := buildSandboxRetrySummary(refined)
	if summary == nil {
		return nil
	}
	counts, _ := summary["http_probe_failure_reason_counts"].([]string)
	return counts
}

func renderDetectionDegradationSection(fileName string, refined review.Result, items []evaluator.DetectionError) string {
	if len(items) == 0 {
		return ""
	}
	highRisk, mediumRisk, lowRisk := displayRiskCounts(refined)
	skipped := 0
	failed := 0
	failedItems := make([]evaluator.DetectionError, 0)
	for _, item := range items {
		if strings.EqualFold(strings.TrimSpace(item.Kind), "skipped") {
			skipped++
			continue
		}
		failed++
		failedItems = append(failedItems, item)
	}
	var b strings.Builder
	b.WriteString("<div class=\"card\" id=\"detection-degradation\"><div class=\"section-head\"><h2>检测降级与执行异常</h2><span class=\"hint\">区分检测器跳过与执行失败，避免误判为无风险。</span></div>")
	b.WriteString(fmt.Sprintf("<p><strong>汇总:</strong> 跳过 %d 项，失败 %d 项。</p>", skipped, failed))
	b.WriteString("<div class=\"table-wrap\"><table><tr><th>类型</th><th>规则</th><th>说明</th></tr>")
	for _, item := range items {
		kind := "执行失败"
		if strings.EqualFold(strings.TrimSpace(item.Kind), "skipped") {
			kind = "检测跳过"
		}
		b.WriteString("<tr><td>" + html.EscapeString(kind) + "</td><td>" + html.EscapeString(defaultIfEmpty(displayRuleName(item.RuleID), "-")) + "</td><td>" + html.EscapeString(defaultIfEmpty(strings.TrimSpace(item.Message), "未知原因")) + "</td></tr>")
	}
	b.WriteString("</table></div>")
	if len(failedItems) > 0 {
		plainLines := make([]string, 0, len(failedItems)+1)
		plainLines = append(plainLines,
			"执行失败项清单",
			"- 任务文件: "+defaultIfEmpty(strings.TrimSpace(fileName), "未知"),
			"- 生成时间: "+time.Now().Format("2006-01-02 15:04:05"),
			"- 风险汇总(高/中/低): "+fmt.Sprintf("%d/%d/%d", highRisk, mediumRisk, lowRisk),
			"- 风险等级: "+localizeRiskLevel(refined.Summary.RiskLevel),
			"- 处置建议: "+localizeAdmission(refined.Summary.Admission),
			"- 失败项详情:",
		)
		for _, item := range failedItems {
			plainLines = append(plainLines, fmt.Sprintf("- %s: %s", defaultIfEmpty(displayRuleName(item.RuleID), "-"), defaultIfEmpty(strings.TrimSpace(item.Message), "未知原因")))
		}
		plainText := strings.Join(plainLines, "\n")
		b.WriteString("<div style=\"margin:10px 0 12px\"><button type=\"button\" onclick=\"copyDetectionFailedText()\" style=\"padding:6px 12px;border-radius:8px;border:1px solid #cddcff;background:#eef3ff;color:#1f3f9a;cursor:pointer;font-weight:600\">导出失败项为纯文本</button><textarea id=\"failed-export-text\" style=\"position:absolute;left:-9999px;top:-9999px\">" + html.EscapeString(plainText) + "</textarea></div>")
		b.WriteString("<details class=\"appendix-details\"><summary>仅看执行失败项（" + strconv.Itoa(len(failedItems)) + "）</summary><div class=\"appendix-body\">")
		b.WriteString("<div class=\"table-wrap\"><table><tr><th>规则</th><th>失败原因</th></tr>")
		for _, item := range failedItems {
			b.WriteString("<tr><td>" + html.EscapeString(defaultIfEmpty(displayRuleName(item.RuleID), "-")) + "</td><td>" + html.EscapeString(defaultIfEmpty(strings.TrimSpace(item.Message), "未知原因")) + "</td></tr>")
		}
		b.WriteString("</table></div></div></details>")
		b.WriteString("<script>function copyDetectionFailedText(){var el=document.getElementById('failed-export-text');if(!el){return;}el.style.display='block';el.select();el.setSelectionRange(0,el.value.length);try{document.execCommand('copy');}catch(e){}el.style.display='none';}</script>")
	}
	b.WriteString("<p class=\"hint\">建议优先处理“执行失败”项，其次评估“检测跳过”项是否因输入缺失导致。</p>")
	b.WriteString("</div>")
	return b.String()
}

func renderPDFReport(htmlPath, docxPath, pdfPath string) (pdfRenderTrace, error) {
	htmlTrace, err := renderPDFFromHTML(htmlPath, pdfPath)
	if err == nil {
		htmlTrace.Engine = defaultIfEmpty(strings.TrimSpace(htmlTrace.Engine), "html")
		return htmlTrace, nil
	}

	docxTrace, fallbackErr := renderPDFFromDocx(docxPath, pdfPath)
	docxTrace.UsedFallback = true
	if fallbackErr == nil {
		docxTrace.Engine = defaultIfEmpty(strings.TrimSpace(docxTrace.Engine), "docx")
		docxTrace.Error = "html_failed: " + err.Error()
		return docxTrace, nil
	}
	t := pdfRenderTrace{
		Engine:       "none",
		UsedFallback: true,
		Error:        fmt.Sprintf("html=%v; docx=%v", err, fallbackErr),
	}
	return t, fmt.Errorf("HTML 转 PDF 失败后 DOCX 回退也失败: html=%v; docx=%v", err, fallbackErr)
}

func renderPDFFromHTML(htmlPath, pdfPath string) (pdfRenderTrace, error) {
	trace := pdfRenderTrace{Engine: "html"}
	effectiveHTMLPath, fontFile, cleanup, err := prepareHTMLForPDF(htmlPath)
	trace.FontFile = fontFile
	if err != nil {
		trace.Error = err.Error()
		return trace, err
	}
	defer cleanup()
	htmlAbs, err := filepath.Abs(effectiveHTMLPath)
	if err != nil {
		trace.Error = err.Error()
		return trace, err
	}
	pdfAbs, err := filepath.Abs(pdfPath)
	if err != nil {
		trace.Error = err.Error()
		return trace, err
	}
	browsers := []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "microsoft-edge"}
	var bin string
	for _, candidate := range browsers {
		if _, err := exec.LookPath(candidate); err == nil {
			bin = candidate
			break
		}
	}
	if bin == "" {
		err := errors.New("未找到可用于 HTML 转 PDF 的浏览器引擎")
		trace.Error = err.Error()
		return trace, err
	}
	trace.Engine = "html:" + bin
	htmlURL := (&url.URL{Scheme: "file", Path: htmlAbs}).String()
	cmd := exec.Command(bin,
		"--headless",
		"--disable-gpu",
		"--allow-file-access-from-files",
		"--no-pdf-header-footer",
		"--run-all-compositor-stages-before-draw",
		"--print-to-pdf="+pdfAbs,
		htmlURL,
	)
	cmd.Env = append(os.Environ(), "LANG=zh_CN.UTF-8", "LC_ALL=zh_CN.UTF-8")
	output, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%s HTML 转 PDF 失败: %v, output: %s", bin, err, strings.TrimSpace(string(output)))
		trace.Error = err.Error()
		return trace, err
	}
	if _, statErr := os.Stat(pdfAbs); statErr != nil {
		err = fmt.Errorf("HTML 转 PDF 后未找到产物: %s", pdfAbs)
		trace.Error = err.Error()
		return trace, err
	}
	return trace, nil
}

func prepareHTMLForPDF(htmlPath string) (string, string, func(), error) {
	fontFile := resolvePDFCJKFontFile()
	if fontFile == "" {
		return htmlPath, "", func() {}, nil
	}
	fontAbs, err := filepath.Abs(fontFile)
	if err != nil {
		return "", "", nil, fmt.Errorf("解析 REVIEW_REPORT_CJK_FONT_FILE 失败: %w", err)
	}
	fontData, err := os.ReadFile(fontAbs)
	if err != nil {
		return "", "", nil, fmt.Errorf("读取中文字体文件失败: %w", err)
	}
	mimeType, formatHint := fontMimeAndFormat(fontAbs)
	if mimeType == "" || formatHint == "" {
		return "", "", nil, fmt.Errorf("不支持的字体格式: %s", fontAbs)
	}
	htmlData, err := os.ReadFile(htmlPath)
	if err != nil {
		return "", "", nil, err
	}
	encodedFont := base64.StdEncoding.EncodeToString(fontData)
	embeddedCSS := renderEmbeddedPDFFontCSS(mimeType, formatHint, encodedFont)
	html := string(htmlData)
	if strings.Contains(strings.ToLower(html), "</head>") {
		html = strings.Replace(html, "</head>", embeddedCSS+"</head>", 1)
	} else {
		html = embeddedCSS + html
	}
	tmpFile, err := os.CreateTemp("", "skill-scanner-pdf-*.html")
	if err != nil {
		return "", "", nil, err
	}
	if _, err := tmpFile.WriteString(html); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpFile.Name())
		return "", "", nil, err
	}
	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpFile.Name())
		return "", "", nil, err
	}
	cleanup := func() {
		_ = os.Remove(tmpFile.Name())
	}
	return tmpFile.Name(), fontAbs, cleanup, nil
}

func fontMimeAndFormat(fontPath string) (string, string) {
	switch strings.ToLower(filepath.Ext(fontPath)) {
	case ".ttf":
		return "font/ttf", "truetype"
	case ".otf":
		return "font/otf", "opentype"
	case ".woff":
		return "font/woff", "woff"
	case ".woff2":
		return "font/woff2", "woff2"
	default:
		return "", ""
	}
}

func resolvePDFCJKFontFile() string {
	for _, candidate := range expandFontCandidates(config.PDFCJKFontCandidates()) {
		mimeType, formatHint := fontMimeAndFormat(candidate)
		if mimeType == "" || formatHint == "" {
			continue
		}
		return candidate
	}
	return ""
}

func resolvePDFCJKFontDir() string {
	for _, candidate := range expandFontCandidates(config.PDFCJKFontCandidates()) {
		if _, err := os.Stat(candidate); err == nil {
			return filepath.Dir(candidate)
		}
	}
	return ""
}

func expandFontCandidates(items []string) []string {
	seen := map[string]struct{}{}
	result := make([]string, 0, len(items)*3)
	appendIfExists := func(p string) {
		p = strings.TrimSpace(p)
		if p == "" {
			return
		}
		if _, ok := seen[p]; ok {
			return
		}
		if _, err := os.Stat(p); err != nil {
			return
		}
		seen[p] = struct{}{}
		result = append(result, p)
	}
	wd, _ := os.Getwd()
	exeDir := ""
	if exePath, err := os.Executable(); err == nil {
		exeDir = filepath.Dir(exePath)
	}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if filepath.IsAbs(item) {
			appendIfExists(item)
			continue
		}
		appendIfExists(item)
		if wd != "" {
			appendIfExists(filepath.Join(wd, item))
		}
		if exeDir != "" {
			appendIfExists(filepath.Join(exeDir, item))
		}
	}
	return result
}

func renderPDFFromDocx(docxPath, pdfPath string) (pdfRenderTrace, error) {
	trace := pdfRenderTrace{Engine: "docx"}
	docxAbs, err := filepath.Abs(docxPath)
	if err != nil {
		trace.Error = err.Error()
		return trace, err
	}
	pdfAbs, err := filepath.Abs(pdfPath)
	if err != nil {
		trace.Error = err.Error()
		return trace, err
	}
	outDir := filepath.Dir(pdfAbs)

	bin := ""
	if _, err := exec.LookPath("soffice"); err == nil {
		bin = "soffice"
	} else if _, err := exec.LookPath("libreoffice"); err == nil {
		bin = "libreoffice"
	} else {
		err := errors.New("未找到 soffice/libreoffice")
		trace.Error = err.Error()
		return trace, err
	}
	trace.Engine = "docx:" + bin

	cmd := exec.Command(bin, "--headless", "--convert-to", "pdf", "--outdir", outDir, docxAbs)
	env := append(os.Environ(), "LANG=zh_CN.UTF-8", "LC_ALL=zh_CN.UTF-8")
	if fontDir := strings.TrimSpace(resolvePDFCJKFontDir()); fontDir != "" {
		trace.FontDir = fontDir
		env = append(env,
			"SAL_FONTPATH="+fontDir,
			"GDFONTPATH="+fontDir,
		)
	}
	trace.FontFile = resolvePDFCJKFontFile()
	cmd.Env = env
	output, err := cmd.CombinedOutput()
	if err != nil {
		err = fmt.Errorf("%s 转换失败: %v, output: %s", bin, err, strings.TrimSpace(string(output)))
		trace.Error = err.Error()
		return trace, err
	}

	generated := strings.TrimSuffix(docxAbs, filepath.Ext(docxAbs)) + ".pdf"
	if _, statErr := os.Stat(generated); statErr != nil {
		err = fmt.Errorf("未找到转换产物: %s", generated)
		trace.Error = err.Error()
		return trace, err
	}
	if generated != pdfAbs {
		data, readErr := os.ReadFile(generated)
		if readErr != nil {
			trace.Error = readErr.Error()
			return trace, readErr
		}
		if writeErr := os.WriteFile(pdfAbs, data, 0600); writeErr != nil {
			trace.Error = writeErr.Error()
			return trace, writeErr
		}
	}
	return trace, nil
}

func describeTargetIntent(target string, behavior review.BehaviorProfile) string {
	hasDownloadCmd := false
	for _, execTarget := range behavior.ExecTargets {
		l := strings.ToLower(execTarget)
		if strings.Contains(l, "curl") || strings.Contains(l, "wget") || strings.Contains(l, "invoke-webrequest") {
			hasDownloadCmd = true
			break
		}
	}

	u, err := url.Parse(strings.TrimSpace(target))
	if err != nil || strings.TrimSpace(u.Host) == "" {
		if hasDownloadCmd {
			return "检测到下载命令，请关联该目标审计下载后执行链路。"
		}
		return "未识别为标准 URL，建议结合代码上下文复核。"
	}

	host := strings.ToLower(strings.TrimSpace(u.Host))
	p := strings.ToLower(u.Path)

	if host == "github.com" {
		if strings.Contains(p, "/releases/download/") || strings.HasSuffix(p, ".zip") || strings.HasSuffix(p, ".tar.gz") || strings.HasSuffix(p, ".tgz") {
			if hasDownloadCmd {
				return "命中 GitHub 下载型链接，且存在下载命令，需重点审计下载文件的落地与执行行为。"
			}
			return "命中 GitHub 下载型链接，当前未直接观察到下载命令，请继续核查是否有间接下载。"
		}
		return "更偏向代码仓库展示链接，平台可信不等于仓库内容可信。"
	}

	if host == "raw.githubusercontent.com" {
		if hasDownloadCmd {
			return "命中 Raw 直链并存在下载命令，建议审计文件完整性校验与后续执行路径。"
		}
		return "命中 Raw 直链，可能用于直接下发脚本或配置，建议审计后续使用方式。"
	}

	if hasDownloadCmd {
		return "检测到下载命令，需审计该目标对应文件的下载、落地和执行流程。"
	}
	return "未发现显式下载行为，可结合业务语义继续确认访问必要性。"
}

func renderEvidenceSection(title string, items []string) string {
	if len(items) == 0 {
		return "<p><strong>" + html.EscapeString(title) + ":</strong> 未检出。</p>"
	}
	var b strings.Builder
	b.WriteString("<p><strong>" + html.EscapeString(title) + ":</strong></p><ul>")
	for i := 0; i < len(items); i++ {
		b.WriteString("<li>" + html.EscapeString(items[i]) + "</li>")
	}
	b.WriteString("</ul>")
	return b.String()
}

func renderFindingDigestIntegratedCard(findings []plugins.Finding, refined review.Result) string {
	orderedFindings := sortFindingsByReview(findings, refined)
	return reviewreport.RenderFindingDigestIntegratedCard(findings, orderedFindings, reviewreport.FindingDigestRenderOptions{
		FinalReviewSummary: func(f plugins.Finding) string {
			return finalReviewSummaryForFinding(f, refined)
		},
	})
}

func normalizeEvidenceBody(text string) string {
	text = strings.ReplaceAll(text, "；", "；\n")
	text = strings.ReplaceAll(text, ";", ";\n")
	for strings.Contains(text, "\n\n") {
		text = strings.ReplaceAll(text, "\n\n", "\n")
	}
	return text
}

func renderSourceBadgeStrip(items []string) string {
	return reviewreport.RenderSourceBadgeStrip(items)
}

func structuredFindingSourceLabels(finding review.StructuredFinding, finalReview string, reviewDepth int) []string {
	return reviewreport.StructuredFindingSourceLabels(finding, finalReview, reviewDepth)
}

func capabilitySourceLabels(item review.CapabilityConsistency, finalReview string, reviewDepth int) []string {
	return reviewreport.CapabilitySourceLabels(item, finalReview, reviewDepth)
}

func reviewVerdictCountByFinding(items []review.ReviewAgentVerdict) map[string]int {
	return reviewreport.ReviewVerdictCountByFinding(items)
}

func sourcePillClass(item string) string {
	return reviewreport.SourcePillClass(item)
}

func splitCodeEvidenceLabelAndBody(item string) (string, string) {
	return reviewreport.SplitCodeEvidenceLabelAndBody(item)
}

func inferEvidenceLabel(item string) string {
	return reviewreport.InferEvidenceLabel(item)
}

func looksLikeSourceLocator(line string) bool {
	return reviewreport.LooksLikeSourceLocator(line)
}

func shortenEvidenceLabel(line string) string {
	return reviewreport.ShortenEvidenceLabel(line)
}

func severityClassSuffix(severity string) string {
	return reviewreport.SeverityClassSuffix(severity)
}

func ruleExplanationByID(items []review.RuleExplanation) map[string]review.RuleExplanation {
	return reviewreport.RuleExplanationByID(items)
}

func falsePositiveReviewByID(items []review.FalsePositiveReview) map[string]review.FalsePositiveReview {
	return reviewreport.FalsePositiveReviewByID(items)
}

func reviewVerdictsByFinding(items []review.ReviewAgentVerdict) map[string][]review.ReviewAgentVerdict {
	out := make(map[string][]review.ReviewAgentVerdict, len(items))
	for _, item := range items {
		out[item.FindingID] = append(out[item.FindingID], item)
	}
	return out
}

func structuredFindingTitleByID(items []review.StructuredFinding) map[string]string {
	out := make(map[string]string, len(items))
	for _, item := range items {
		out[item.ID] = item.Title
	}
	return out
}

func capabilityItemsForFinding(finding review.StructuredFinding, items []review.CapabilityConsistency) []review.CapabilityConsistency {
	return reviewreport.CapabilityItemsForFinding(finding, items)
}

func unmatchedCapabilityItems(items []review.CapabilityConsistency, findings []review.StructuredFinding) []review.CapabilityConsistency {
	out := make([]review.CapabilityConsistency, 0)
	for _, item := range items {
		matched := false
		for _, finding := range findings {
			if capabilityMatchesFinding(item.Capability, finding) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, item)
		}
	}
	return out
}

func capabilityEvidenceForFinding(finding review.StructuredFinding, matrix []review.CapabilityConsistency, inventory []review.EvidenceInventory, behavior review.BehaviorProfile) []string {
	return reviewreport.CapabilityEvidenceForFinding(finding, matrix, inventory, behavior)
}

func capabilityPrimaryEvidenceForFinding(finding review.StructuredFinding, item review.CapabilityConsistency, inventory []review.EvidenceInventory, behavior review.BehaviorProfile) string {
	return reviewreport.CapabilityPrimaryEvidenceForFinding(finding, item, inventory, behavior)
}

func unmatchedEvidenceInventory(items []review.EvidenceInventory, matrix []review.CapabilityConsistency) []review.EvidenceInventory {
	out := make([]review.EvidenceInventory, 0)
	for _, item := range items {
		matched := false
		for _, capability := range matrix {
			if inventoryMatchesCapability(capability.Capability, item.Category) {
				matched = true
				break
			}
		}
		if !matched {
			out = append(out, item)
		}
	}
	return out
}

func inventoryMatchesCapability(capability, category string) bool {
	return reviewreport.InventoryMatchesCapability(capability, category)
}

func capabilityMatchesFinding(capability string, finding review.StructuredFinding) bool {
	return reviewreport.CapabilityMatchesFinding(capability, finding)
}

func uniqueNonEmptyStrings(items []string) []string {
	return reviewreport.UniqueNonEmptyStrings(items)
}

func yesNo(v bool) string {
	if v {
		return "是"
	}
	return "否"
}

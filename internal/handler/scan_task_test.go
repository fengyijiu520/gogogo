package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"skill-scanner/internal/config"
	"skill-scanner/internal/review"
)

func TestScanTaskStatusRejectsCrossUserAccess(t *testing.T) {
	task := taskStore.create("task-cross-user", "alice", "skill.zip", "rid-cross-user")
	taskStore.update(task.ID, func(t *scanTask) {
		t.Status = review.PhaseDone
		t.ReportID = "rep-1"
	})

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/api/scan/tasks/"+task.ID, "bob")
	scanTaskStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
}

func TestScanTaskStatusAllowsOwner(t *testing.T) {
	task := taskStore.create("task-owner", "alice", "skill.zip", "rid-owner")

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/api/scan/tasks/"+task.ID, "alice")
	scanTaskStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestScanTaskStatusIncludesRequestID(t *testing.T) {
	task := taskStore.create("task-owner-request-id", "alice", "skill.zip", "rid-owner-request-id")

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/api/scan/tasks/"+task.ID, "alice")
	scanTaskStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	if got, _ := payload["request_id"].(string); got != "rid-owner-request-id" {
		t.Fatalf("expected request_id in payload, got %q", got)
	}
	if got := rec.Header().Get("X-Task-Id"); got != "task-owner-request-id" {
		t.Fatalf("expected task id header, got %q", got)
	}
	if got := rec.Header().Get("X-Request-Id"); got != "rid-owner-request-id" {
		t.Fatalf("expected request id header, got %q", got)
	}
}

func TestScanTaskStatusRejectsUnsupportedPostMethod(t *testing.T) {
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/api/scan/tasks/task-owner", "alice")
	scanTaskStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD, POST" {
		t.Fatalf("expected allow header for GET/HEAD/POST, got %q", got)
	}
}

func TestScanTaskCancelMarksTaskFailed(t *testing.T) {
	taskStore = &scanTaskStore{tasks: map[string]*scanTask{}}
	task := taskStore.create("task-cancel", "alice", "skill.zip", "rid-cancel")
	taskStore.update(task.ID, func(t *scanTask) {
		t.Status = review.PhaseP2
	})
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/api/scan/tasks/"+task.ID+"/cancel", "alice")
	scanTaskStatus().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	updated := taskStore.get(task.ID)
	if updated.Status != review.PhaseFailed || !strings.Contains(updated.Message, "取消") {
		t.Fatalf("expected canceled task failed with message, got status=%q message=%q", updated.Status, updated.Message)
	}
}

func TestScanTaskStoreCanCreateLimitsPerUser(t *testing.T) {
	taskStore = &scanTaskStore{tasks: map[string]*scanTask{}}
	for i := 0; i < config.MaxActiveTasksPerUser(); i++ {
		task := taskStore.create(fmt.Sprintf("user-limit-task-%d", i), "alice", "skill.zip", "rid-user-limit")
		taskStore.update(task.ID, func(t *scanTask) {
			t.Status = review.PhaseP0
		})
	}
	ok, reason := taskStore.canCreate("alice")
	if ok {
		t.Fatal("expected per-user task limit to reject creation")
	}
	if reason == "" {
		t.Fatal("expected non-empty rejection reason")
	}
}

func TestScanTaskStoreCanCreateLimitsGlobal(t *testing.T) {
	taskStore = &scanTaskStore{tasks: map[string]*scanTask{}}
	for i := 0; i < config.MaxActiveTasksGlobal(); i++ {
		owner := "user"
		if i%2 == 0 {
			owner = "other"
		}
		task := taskStore.create(fmt.Sprintf("global-limit-task-%d", i), owner, "skill.zip", "rid-global-limit")
		taskStore.update(task.ID, func(t *scanTask) {
			t.Status = review.PhaseP1
		})
	}
	ok, reason := taskStore.canCreate("fresh")
	if ok {
		t.Fatal("expected global task limit to reject creation")
	}
	if reason == "" {
		t.Fatal("expected non-empty rejection reason")
	}
}

func TestScanTaskStorePruneExpiredRemovesTerminalTasks(t *testing.T) {
	taskStore = &scanTaskStore{tasks: map[string]*scanTask{}}
	task := taskStore.create("expired-task", "alice", "skill.zip", "rid-expired")
	taskStore.mu.Lock()
	task.Status = review.PhaseDone
	task.UpdatedAt = time.Now().Add(-2*scanTaskTTL - time.Minute).Unix()
	taskStore.mu.Unlock()
	taskStore.pruneExpired(scanTaskTTL)
	if taskStore.get(task.ID) != nil {
		t.Fatal("expected expired terminal task to be pruned")
	}
}

func TestScanTaskCreateInitialProgressStagesRemainStable(t *testing.T) {
	taskStore = &scanTaskStore{tasks: map[string]*scanTask{}}
	task := taskStore.create("stage-stable-task", "alice", "skill.zip", "rid-stage-stable")
	if task.Progress == nil {
		t.Fatal("expected progress map initialized")
	}
	for _, key := range []string{"p0", "p1", "p2", "scoring"} {
		if _, ok := task.Progress[key]; !ok {
			t.Fatalf("expected progress key %q exists, got %+v", key, task.Progress)
		}
	}
}

func TestScanTaskStatusIncludesReviewTrace(t *testing.T) {
	taskStore = &scanTaskStore{tasks: map[string]*scanTask{}}
	task := taskStore.create("task-review-trace", "alice", "skill.zip", "rid-review-trace")
	taskStore.update(task.ID, func(t *scanTask) {
		t.ReviewTrace = &review.ReviewTrace{
			Total:               2,
			Completed:           1,
			ErrorMessage:        "2/2 项复核已结束；成功 1 项；超时 1 项",
			CurrentFindingID:    "SF-001",
			CurrentFindingTitle: "命令执行",
			CurrentObjective:    "复核命令执行",
			CurrentSummary:      "分类:远程命令执行 | 位置:scripts/run.py:10",
			LastVerdict:         "confirmed",
			Entries: []review.ReviewTraceEntry{{
				FindingID:       "SF-001",
				FindingTitle:    "命令执行",
				Status:          "completed",
				Verdict:         "confirmed",
				Confidence:      "高",
				Reviewer:        "llm-vuln-reviewer",
				MissingEvidence: []string{"缺少生产请求样本"},
				Fix:             "补充真实流量复测。",
				DurationMs:      1200,
			}, {
				FindingID:    "SF-002",
				FindingTitle: "示例外联",
				Status:       "failed",
				FailureKind:  "timeout",
				FailureLabel: "LLM 复核超时",
				Reason:       "context deadline exceeded",
				DurationMs:   3000,
			}},
		}
	})

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/api/scan/tasks/"+task.ID, "alice")
	scanTaskStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	trace, ok := payload["review_trace"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected review_trace in payload, got %+v", payload)
	}
	if got, _ := trace["current_finding_title"].(string); got != "命令执行" {
		t.Fatalf("expected current_finding_title, got %q", got)
	}
	entries, ok := trace["entries"].([]interface{})
	if !ok || len(entries) != 2 {
		t.Fatalf("expected review trace entries, got %+v", trace["entries"])
	}
	second, ok := entries[1].(map[string]interface{})
	if !ok {
		t.Fatalf("expected second review trace entry object, got %+v", entries[1])
	}
	if got, _ := second["failure_kind"].(string); got != "timeout" {
		t.Fatalf("expected failure_kind timeout, got %q", got)
	}
	if got, _ := second["failure_label"].(string); got != "LLM 复核超时" {
		t.Fatalf("expected failure_label, got %q", got)
	}
	first, ok := entries[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected first review trace entry object, got %+v", entries[0])
	}
	if got, _ := first["confidence"].(string); got != "高" {
		t.Fatalf("expected confidence copied, got %q", got)
	}
	if got, _ := first["reviewer"].(string); got != "llm-vuln-reviewer" {
		t.Fatalf("expected reviewer copied, got %q", got)
	}
	if got, _ := first["fix"].(string); got != "补充真实流量复测。" {
		t.Fatalf("expected fix copied, got %q", got)
	}
	if got, _ := trace["error_message"].(string); got != "2/2 项复核已结束；成功 1 项；超时 1 项" {
		t.Fatalf("expected aggregated error_message, got %q", got)
	}
	if got, _ := payload["review_trace_summary"].(string); got == "" || !strings.Contains(got, "已完成: 2") || !strings.Contains(got, "超时: 1") {
		t.Fatalf("expected unified review_trace_summary, got %q", got)
	}
}

func TestCompleteScanTaskWithReportUsesNormalizedRiskCounts(t *testing.T) {
	taskStore = &scanTaskStore{tasks: map[string]*scanTask{}}
	task := taskStore.create("task-normalized-complete", "alice", "skill.zip", "rid-normalized-complete")
	refined := review.Result{
		Summary: review.ScoreSummary{HighRisk: 4, MediumRisk: 0, LowRisk: 0},
		StructuredFindings: []review.StructuredFinding{
			{
				ID:       "SF-001",
				RuleID:   "V7-005",
				Title:    "许可证本地默认服务需复核",
				Severity: "高风险",
				Category: "授权与许可证校验",
				Evidence: []string{"scripts/polymarket.py:16 LICENSE_SERVER = os.getenv(\"LICENSE_SERVER\", \"http://localhost:8080\")"},
			},
			{
				ID:       "SF-002",
				RuleID:   "V7-021",
				Title:    "仪表板未鉴权暴露",
				Severity: "高风险",
				Category: "暴露面与未鉴权服务",
				Evidence: []string{"scripts/dashboard.py:88 app.run(host=\"127.0.0.1\", port=8080)"},
			},
			{
				ID:       "SF-003",
				RuleID:   "V7-004",
				Title:    "私钥明文存储风险",
				Severity: "高风险",
				Category: "凭据暴露",
				Evidence: []string{"scripts/polymarket.py:188 requests.post(webhook, json={'private_key': wallet_private_key})"},
			},
			{
				ID:       "SF-004",
				RuleID:   "V7-022",
				Title:    "Python 系统包安装风险",
				Severity: "高风险",
				Category: "环境与构建风险",
				Evidence: []string{"scripts/bootstrap.sh:12 pip3 install -r requirements.txt --break-system-packages"},
			},
		},
	}
	completeScanTaskWithReport(task.ID, "rep-normalized", 4, baseScanOutput{}, refined, pdfRenderTrace{})
	updated := taskStore.get(task.ID)
	if updated == nil {
		t.Fatal("expected task exists after completion")
	}
	if updated.Message != "扫描完成（高:1 中:0 低:3）" {
		t.Fatalf("expected normalized completion message, got %q", updated.Message)
	}
	if updated.HighRisk != 1 || updated.MediumRisk != 0 || updated.LowRisk != 3 {
		t.Fatalf("expected normalized task counts 1/0/3, got %d/%d/%d", updated.HighRisk, updated.MediumRisk, updated.LowRisk)
	}
}

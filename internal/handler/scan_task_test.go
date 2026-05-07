package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"skill-scanner/internal/config"
	"skill-scanner/internal/review"
)

func TestScanTaskStatusRejectsCrossUserAccess(t *testing.T) {
	task := taskStore.create("task-cross-user", "alice", "skill.zip")
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
	task := taskStore.create("task-owner", "alice", "skill.zip")

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/api/scan/tasks/"+task.ID, "alice")
	scanTaskStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestScanTaskStatusRejectsPostMethod(t *testing.T) {
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/api/scan/tasks/task-owner", "alice")
	scanTaskStatus().ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("expected allow header for GET/HEAD, got %q", got)
	}
}

	func TestScanTaskStoreCanCreateLimitsPerUser(t *testing.T) {
	taskStore = &scanTaskStore{tasks: map[string]*scanTask{}}
	for i := 0; i < config.MaxActiveTasksPerUser(); i++ {
		task := taskStore.create(fmt.Sprintf("user-limit-task-%d", i), "alice", "skill.zip")
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
		task := taskStore.create(fmt.Sprintf("global-limit-task-%d", i), owner, "skill.zip")
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
	task := taskStore.create("expired-task", "alice", "skill.zip")
	taskStore.mu.Lock()
	task.Status = review.PhaseDone
	task.UpdatedAt = time.Now().Add(-2*scanTaskTTL - time.Minute).Unix()
	taskStore.mu.Unlock()
	taskStore.pruneExpired(scanTaskTTL)
	if taskStore.get(task.ID) != nil {
		t.Fatal("expected expired terminal task to be pruned")
	}
}

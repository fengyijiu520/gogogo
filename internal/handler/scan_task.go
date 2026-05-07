package handler

import (
	"sort"
	"strings"
	"sync"
	"time"

	"skill-scanner/internal/config"
	"skill-scanner/internal/review"
)

const (
	scanTaskTTL = 24 * time.Hour
)

type scanTask struct {
	ID           string          `json:"id"`
	Owner        string          `json:"-"`
	Status       review.Phase    `json:"status"`
	FileName     string          `json:"file_name"`
	CreatedAt    int64           `json:"created_at"`
	UpdatedAt    int64           `json:"updated_at"`
	Message      string          `json:"message,omitempty"`
	ReportID     string          `json:"report_id,omitempty"`
	FindingCount int             `json:"finding_count,omitempty"`
	HighRisk     int             `json:"high_risk,omitempty"`
	MediumRisk   int             `json:"medium_risk,omitempty"`
	LowRisk      int             `json:"low_risk,omitempty"`
	PDFEngine    string          `json:"pdf_engine,omitempty"`
	PDFFontFile  string          `json:"pdf_font_file,omitempty"`
	PDFTrace     string          `json:"pdf_trace,omitempty"`
	Progress     map[string]bool `json:"progress"`
}

type scanTaskStore struct {
	mu    sync.RWMutex
	tasks map[string]*scanTask
}

var taskStore = &scanTaskStore{tasks: map[string]*scanTask{}}

func (s *scanTaskStore) create(id, owner, fileName string) *scanTask {
	now := time.Now().Unix()
	t := &scanTask{
		ID:        id,
		Owner:     owner,
		Status:    review.PhaseQueued,
		FileName:  fileName,
		CreatedAt: now,
		UpdatedAt: now,
		Progress: map[string]bool{
			"p0":      false,
			"p1":      false,
			"p2":      false,
			"scoring": false,
		},
	}
	s.mu.Lock()
	s.tasks[id] = t
	s.mu.Unlock()
	return t
}

func (s *scanTaskStore) get(id string) *scanTask {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t := s.tasks[id]
	if t == nil {
		return nil
	}
	cp := *t
	cp.Progress = map[string]bool{}
	for k, v := range t.Progress {
		cp.Progress[k] = v
	}
	return &cp
}

func (s *scanTaskStore) update(id string, fn func(*scanTask)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.tasks[id]
	if t == nil {
		return
	}
	fn(t)
	t.UpdatedAt = time.Now().Unix()
}

func (s *scanTaskStore) release(id string, finalStatus review.Phase, message string) {
	s.update(id, func(t *scanTask) {
		t.Status = finalStatus
		if strings.TrimSpace(message) != "" {
			t.Message = message
		}
	})
}

func (s *scanTaskStore) pruneExpired(ttl time.Duration) {
	if ttl <= 0 {
		ttl = scanTaskTTL
	}
	cutoff := time.Now().Add(-ttl).Unix()
	s.mu.Lock()
	for id, task := range s.tasks {
		if isTaskTerminal(task.Status) && task.UpdatedAt < cutoff {
			delete(s.tasks, id)
		}
	}
	s.mu.Unlock()
}

func (s *scanTaskStore) canCreate(owner string) (bool, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	activeGlobal := 0
	activeUser := 0
	for _, task := range s.tasks {
		if isTaskTerminal(task.Status) {
			continue
		}
		activeGlobal++
		if task.Owner == owner {
			activeUser++
		}
	}
	if activeUser >= config.MaxActiveTasksPerUser() {
		return false, "当前用户正在执行的扫描任务过多，请等待已有任务完成后重试"
	}
	if activeGlobal >= config.MaxActiveTasksGlobal() {
		return false, "当前扫描队列繁忙，请稍后重试"
	}
	return true, ""
}

func isTaskTerminal(status review.Phase) bool {
	return status == review.PhaseDone || status == review.PhaseFailed
}

func (s *scanTaskStore) list(owner string) []scanTask {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]scanTask, 0, len(s.tasks))
	for _, t := range s.tasks {
		if strings.TrimSpace(owner) != "" && t.Owner != owner {
			continue
		}
		cp := *t
		cp.Progress = map[string]bool{}
		for k, v := range t.Progress {
			cp.Progress[k] = v
		}
		out = append(out, cp)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt == out[j].UpdatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].UpdatedAt > out[j].UpdatedAt
	})
	return out
}

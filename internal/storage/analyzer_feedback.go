package storage

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

type AnalyzerFeedbackEntry struct {
	RuleID string   `json:"rule_id"`
	Tokens []string `json:"tokens"`
}

type analyzerFeedbackStore struct {
	path string
	mu   sync.RWMutex
	data map[string]map[string]bool
}

func newAnalyzerFeedbackStore(dataDir string) (*analyzerFeedbackStore, error) {
	path := filepath.Join(dataDir, "analyzer_feedback.json")
	s := &analyzerFeedbackStore{path: path, data: map[string]map[string]bool{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *analyzerFeedbackStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	items := make([]AnalyzerFeedbackEntry, 0)
	if err := json.Unmarshal(data, &items); err != nil {
		return err
	}
	for _, item := range items {
		rid := strings.TrimSpace(strings.ToUpper(item.RuleID))
		if rid == "" {
			continue
		}
		if _, ok := s.data[rid]; !ok {
			s.data[rid] = map[string]bool{}
		}
		for _, tok := range item.Tokens {
			t := strings.TrimSpace(strings.ToLower(tok))
			if t != "" {
				s.data[rid][t] = true
			}
		}
	}
	return nil
}

func (s *analyzerFeedbackStore) saveLocked() error {
	items := make([]AnalyzerFeedbackEntry, 0, len(s.data))
	for rid, tokens := range s.data {
		entry := AnalyzerFeedbackEntry{RuleID: rid}
		for tok := range tokens {
			entry.Tokens = append(entry.Tokens, tok)
		}
		sort.Strings(entry.Tokens)
		items = append(items, entry)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].RuleID < items[j].RuleID })
	body, err := json.MarshalIndent(items, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, body, 0600)
}

func (s *analyzerFeedbackStore) Add(ruleID string, token string) error {
	rid := strings.TrimSpace(strings.ToUpper(ruleID))
	t := strings.TrimSpace(strings.ToLower(token))
	if rid == "" || t == "" {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.data[rid]; !ok {
		s.data[rid] = map[string]bool{}
	}
	s.data[rid][t] = true
	return s.saveLocked()
}

func (s *analyzerFeedbackStore) Snapshot() []AnalyzerFeedbackEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := make([]AnalyzerFeedbackEntry, 0, len(s.data))
	for rid, tokens := range s.data {
		entry := AnalyzerFeedbackEntry{RuleID: rid}
		for tok := range tokens {
			entry.Tokens = append(entry.Tokens, tok)
		}
		sort.Strings(entry.Tokens)
		items = append(items, entry)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].RuleID < items[j].RuleID })
	return items
}

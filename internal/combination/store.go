package combination

import (
	"errors"
	"os"
	"sort"
	"strings"
	"sync"

	platformfiles "skill-scanner/internal/platform/files"
)

type Store struct {
	mu   sync.RWMutex
	path string
	runs []*RunRecord
}

func NewStore(dataDir string) (*Store, error) {
	paths := platformfiles.NewDataPaths(dataDir)
	if err := platformfiles.EnsureDataDirs(paths); err != nil {
		return nil, err
	}
	s := &Store{path: paths.CombinationRuns}
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return s, nil
}

func (s *Store) Save(record *RunRecord) error {
	if record == nil {
		return errors.New("run record is nil")
	}
	record.SelectionKey = strings.TrimSpace(record.SelectionKey)
	if record.SelectionKey == "" {
		return errors.New("selection_key is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.findIndexBySelectionKey(record.SelectionKey)
	if idx >= 0 {
		record.CreatedAt = s.runs[idx].CreatedAt
		s.runs[idx] = cloneRunRecord(record)
	} else {
		s.runs = append(s.runs, cloneRunRecord(record))
	}
	return s.saveLocked()
}

func (s *Store) GetBySelectionKey(selectionKey string) (*RunRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx := s.findIndexBySelectionKey(selectionKey)
	if idx < 0 {
		return nil, false
	}
	return cloneRunRecord(s.runs[idx]), true
}

func (s *Store) GetByRunID(runID string) (*RunRecord, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return nil, false
	}
	for _, item := range s.runs {
		if item != nil && strings.TrimSpace(item.RunID) == runID {
			return cloneRunRecord(item), true
		}
	}
	return nil, false
}

func (s *Store) List() ([]*RunRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := cloneRunRecords(s.runs)
	sort.Slice(out, func(i, j int) bool {
		return out[i].UpdatedAt > out[j].UpdatedAt
	})
	return out, nil
}

func (s *Store) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []*RunRecord
	if err := platformfiles.ReadJSON(s.path, &items); err != nil {
		return err
	}
	s.runs = items
	return nil
}

func (s *Store) saveLocked() error {
	return platformfiles.WriteJSONAtomic(s.path, s.runs, 0600)
}

func (s *Store) findIndexBySelectionKey(selectionKey string) int {
	selectionKey = strings.TrimSpace(selectionKey)
	for i, item := range s.runs {
		if item != nil && item.SelectionKey == selectionKey {
			return i
		}
	}
	return -1
}

func cloneRunRecords(in []*RunRecord) []*RunRecord {
	out := make([]*RunRecord, 0, len(in))
	for _, item := range in {
		out = append(out, cloneRunRecord(item))
	}
	return out
}

func cloneRunRecord(in *RunRecord) *RunRecord {
	if in == nil {
		return nil
	}
	cp := *in
	cp.Overview.RuleConfigVersion = strings.TrimSpace(in.Overview.RuleConfigVersion)
	cp.Overview.RuleConfigRevision = strings.TrimSpace(in.Overview.RuleConfigRevision)
	cp.Overview.RuleContentHash = strings.TrimSpace(in.Overview.RuleContentHash)
	cp.Overview.RuleSourcePath = strings.TrimSpace(in.Overview.RuleSourcePath)
	cp.SelectedSkills = append([]string(nil), in.SelectedSkills...)
	cp.Overview.Capabilities = append([]string(nil), in.Overview.Capabilities...)
	cp.Overview.CombinedTags = append([]string(nil), in.Overview.CombinedTags...)
	cp.Overview.CombinedRisks = append([]StoredRisk(nil), in.Overview.CombinedRisks...)
	cp.Overview.InferredChains = append([]StoredChain(nil), in.Overview.InferredChains...)
	cp.Overview.SemanticChains = append([]StoredChain(nil), in.Overview.SemanticChains...)
	if in.Overview.CombinedProfile != nil {
		profileCopy := *in.Overview.CombinedProfile
		if in.Overview.CombinedProfile.CapabilityLevels != nil {
			profileCopy.CapabilityLevels = make(map[string]float64, len(in.Overview.CombinedProfile.CapabilityLevels))
			for k, v := range in.Overview.CombinedProfile.CapabilityLevels {
				profileCopy.CapabilityLevels[k] = v
			}
		}
		if in.Overview.CombinedProfile.CapabilityScopes != nil {
			profileCopy.CapabilityScopes = make(map[string][]string, len(in.Overview.CombinedProfile.CapabilityScopes))
			for k, scopes := range in.Overview.CombinedProfile.CapabilityScopes {
				profileCopy.CapabilityScopes[k] = append([]string(nil), scopes...)
			}
		}
		profileCopy.Tags = append([]string(nil), in.Overview.CombinedProfile.Tags...)
		profileCopy.Evidence = append([]string(nil), in.Overview.CombinedProfile.Evidence...)
		cp.Overview.CombinedProfile = &profileCopy
	}
	return &cp
}

func errFileNotExist() error {
	return os.ErrNotExist
}

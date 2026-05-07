package store

import (
	"errors"
	"sync"

	admissionmodel "skill-scanner/internal/admission/model"
	platformfiles "skill-scanner/internal/platform/files"
)

type RiskStore struct {
	mu    sync.RWMutex
	path  string
	risks map[string][]admissionmodel.ResidualRisk
}

func NewRiskStore(dataDir string) (*RiskStore, error) {
	paths := platformfiles.NewDataPaths(dataDir)
	if err := platformfiles.EnsureDataDirs(paths); err != nil {
		return nil, err
	}
	s := &RiskStore{path: paths.AdmissionRisks, risks: map[string][]admissionmodel.ResidualRisk{}}
	if err := s.load(); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return s, nil
}

func (s *RiskStore) Save(skillID string, risks []admissionmodel.ResidualRisk) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := cloneRisks(risks)
	for i := range cloned {
		cloned[i].Normalize()
	}
	s.risks[skillID] = cloned
	return s.saveLocked()
}

func (s *RiskStore) GetBySkillID(skillID string) ([]admissionmodel.ResidualRisk, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRisks(s.risks[skillID]), nil
}

func (s *RiskStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := map[string][]admissionmodel.ResidualRisk{}
	if err := platformfiles.ReadJSON(s.path, &items); err != nil {
		if errors.Is(err, errFileNotExist()) {
			return ErrNotFound
		}
		return err
	}
	for key := range items {
		for i := range items[key] {
			items[key][i].Normalize()
		}
	}
	s.risks = items
	return nil
}

func (s *RiskStore) saveLocked() error {
	return platformfiles.WriteJSONAtomic(s.path, s.risks, 0600)
}

func cloneRisks(in []admissionmodel.ResidualRisk) []admissionmodel.ResidualRisk {
	if len(in) == 0 {
		return nil
	}
	out := make([]admissionmodel.ResidualRisk, len(in))
	copy(out, in)
	return out
}

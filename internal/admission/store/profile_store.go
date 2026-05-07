package store

import (
	"errors"
	"sync"

	admissionmodel "skill-scanner/internal/admission/model"
	platformfiles "skill-scanner/internal/platform/files"
)

type ProfileStore struct {
	mu       sync.RWMutex
	path     string
	profiles map[string]*admissionmodel.CapabilityProfile
}

func NewProfileStore(dataDir string) (*ProfileStore, error) {
	paths := platformfiles.NewDataPaths(dataDir)
	if err := platformfiles.EnsureDataDirs(paths); err != nil {
		return nil, err
	}
	s := &ProfileStore{path: paths.AdmissionProfile, profiles: map[string]*admissionmodel.CapabilityProfile{}}
	if err := s.load(); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return s, nil
}

func (s *ProfileStore) Save(profile *admissionmodel.CapabilityProfile) error {
	if profile == nil {
		return errors.New("profile is nil")
	}
	profile.Normalize()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.profiles[profile.SkillID] = cloneProfile(profile)
	return s.saveLocked()
}

func (s *ProfileStore) GetBySkillID(skillID string) (*admissionmodel.CapabilityProfile, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	profile, ok := s.profiles[skillID]
	if !ok {
		return nil, false
	}
	return cloneProfile(profile), true
}

func (s *ProfileStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	items := map[string]*admissionmodel.CapabilityProfile{}
	if err := platformfiles.ReadJSON(s.path, &items); err != nil {
		if errors.Is(err, errFileNotExist()) {
			return ErrNotFound
		}
		return err
	}
	for _, item := range items {
		item.Normalize()
	}
	s.profiles = items
	return nil
}

func (s *ProfileStore) saveLocked() error {
	return platformfiles.WriteJSONAtomic(s.path, s.profiles, 0600)
}

func cloneProfile(in *admissionmodel.CapabilityProfile) *admissionmodel.CapabilityProfile {
	if in == nil {
		return nil
	}
	cp := *in
	cp.Tags = append([]string(nil), in.Tags...)
	cp.Evidence = append([]string(nil), in.Evidence...)
	return &cp
}

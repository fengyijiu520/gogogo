package store

import (
	"errors"
	"sort"
	"strings"
	"sync"

	admissionmodel "skill-scanner/internal/admission/model"
	platformfiles "skill-scanner/internal/platform/files"
)

type SkillStore struct {
	mu    sync.RWMutex
	path  string
	skills []*admissionmodel.AdmissionSkill
}

func NewSkillStore(dataDir string) (*SkillStore, error) {
	paths := platformfiles.NewDataPaths(dataDir)
	if err := platformfiles.EnsureDataDirs(paths); err != nil {
		return nil, err
	}
	s := &SkillStore{path: paths.AdmissionSkills}
	if err := s.load(); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return s, nil
}

func (s *SkillStore) Create(skill *admissionmodel.AdmissionSkill) error {
	if skill == nil {
		return errors.New("skill is nil")
	}
	skill.Normalize()
	if err := skill.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.findIndexByID(skill.SkillID) >= 0 {
		return errors.New("skill_id already exists")
	}
	if s.findIndexByReportID(skill.ReportID) >= 0 {
		return errors.New("report already imported")
	}
	s.skills = append(s.skills, cloneSkill(skill))
	return s.saveLocked()
}

func (s *SkillStore) Update(skill *admissionmodel.AdmissionSkill) error {
	if skill == nil {
		return errors.New("skill is nil")
	}
	skill.Normalize()
	if err := skill.Validate(); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	idx := s.findIndexByID(skill.SkillID)
	if idx < 0 {
		return ErrNotFound
	}
	s.skills[idx] = cloneSkill(skill)
	return s.saveLocked()
}

func (s *SkillStore) Save(skill *admissionmodel.AdmissionSkill) error {
	if skill == nil {
		return errors.New("skill is nil")
	}
	if s.ExistsSkillID(skill.SkillID) {
		return s.Update(skill)
	}
	return s.Create(skill)
}

func (s *SkillStore) GetByID(skillID string) (*admissionmodel.AdmissionSkill, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx := s.findIndexByID(skillID)
	if idx < 0 {
		return nil, false
	}
	return cloneSkill(s.skills[idx]), true
}

func (s *SkillStore) GetByReportID(reportID string) (*admissionmodel.AdmissionSkill, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	idx := s.findIndexByReportID(reportID)
	if idx < 0 {
		return nil, false
	}
	return cloneSkill(s.skills[idx]), true
}

func (s *SkillStore) List() ([]*admissionmodel.AdmissionSkill, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := cloneSkills(s.skills)
	sort.Slice(out, func(i, j int) bool {
		if out[i].UpdatedAt == out[j].UpdatedAt {
			return out[i].CreatedAt > out[j].CreatedAt
		}
		return out[i].UpdatedAt > out[j].UpdatedAt
	})
	return out, nil
}

func (s *SkillStore) Search(query string, limit int) ([]*admissionmodel.AdmissionSkill, error) {
	query = strings.TrimSpace(strings.ToLower(query))
	if limit <= 0 {
		limit = 20
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*admissionmodel.AdmissionSkill, 0)
	for _, item := range s.skills {
		if query == "" || skillMatchesQuery(item, query) {
			out = append(out, cloneSkill(item))
			if len(out) >= limit {
				break
			}
		}
	}
	return out, nil
}

func (s *SkillStore) ExistsSkillID(skillID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findIndexByID(skillID) >= 0
}

func (s *SkillStore) ExistsByReportID(reportID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.findIndexByReportID(reportID) >= 0
}

func (s *SkillStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []*admissionmodel.AdmissionSkill
	if err := platformfiles.ReadJSON(s.path, &items); err != nil {
		if errors.Is(err, errFileNotExist()) {
			s.skills = nil
			return ErrNotFound
		}
		return err
	}
	for _, item := range items {
		item.Normalize()
	}
	s.skills = items
	return nil
}

func (s *SkillStore) saveLocked() error {
	return platformfiles.WriteJSONAtomic(s.path, s.skills, 0600)
}

func (s *SkillStore) findIndexByID(skillID string) int {
	skillID = strings.TrimSpace(skillID)
	for i, item := range s.skills {
		if item != nil && item.SkillID == skillID {
			return i
		}
	}
	return -1
}

func (s *SkillStore) findIndexByReportID(reportID string) int {
	reportID = strings.TrimSpace(reportID)
	for i, item := range s.skills {
		if item != nil && item.ReportID == reportID {
			return i
		}
	}
	return -1
}

func skillMatchesQuery(skill *admissionmodel.AdmissionSkill, query string) bool {
	if skill == nil {
		return false
	}
	joined := strings.ToLower(strings.Join([]string{
		skill.SkillID,
		skill.Name,
		skill.DisplayName,
		skill.Version,
		skill.Description,
		skill.ReviewSummary,
	}, " "))
	return strings.Contains(joined, query)
}

func cloneSkills(in []*admissionmodel.AdmissionSkill) []*admissionmodel.AdmissionSkill {
	out := make([]*admissionmodel.AdmissionSkill, 0, len(in))
	for _, item := range in {
		out = append(out, cloneSkill(item))
	}
	return out
}

func cloneSkill(in *admissionmodel.AdmissionSkill) *admissionmodel.AdmissionSkill {
	if in == nil {
		return nil
	}
	cp := *in
	cp.DeclaredCapabilities = append([]string(nil), in.DeclaredCapabilities...)
	cp.DetectedCapabilities = append([]string(nil), in.DetectedCapabilities...)
	cp.RiskTags = append([]string(nil), in.RiskTags...)
	return &cp
}

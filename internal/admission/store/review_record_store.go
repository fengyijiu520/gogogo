package store

import (
	"errors"
	"sync"

	admissionmodel "skill-scanner/internal/admission/model"
	platformfiles "skill-scanner/internal/platform/files"
)

type ReviewRecordStore struct {
	mu      sync.RWMutex
	path    string
	records []*admissionmodel.ReviewRecord
}

func NewReviewRecordStore(dataDir string) (*ReviewRecordStore, error) {
	paths := platformfiles.NewDataPaths(dataDir)
	if err := platformfiles.EnsureDataDirs(paths); err != nil {
		return nil, err
	}
	s := &ReviewRecordStore{path: paths.AdmissionReviews}
	if err := s.load(); err != nil && !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	return s, nil
}

func (s *ReviewRecordStore) Create(record *admissionmodel.ReviewRecord) error {
	if record == nil {
		return errors.New("review record is nil")
	}
	record.Normalize()
	if err := record.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records = append(s.records, cloneRecord(record))
	return s.saveLocked()
}

func (s *ReviewRecordStore) List() ([]*admissionmodel.ReviewRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneRecords(s.records), nil
}

func (s *ReviewRecordStore) ListBySkillID(skillID string) ([]*admissionmodel.ReviewRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*admissionmodel.ReviewRecord, 0)
	for _, item := range s.records {
		if item != nil && item.SkillID == skillID {
			out = append(out, cloneRecord(item))
		}
	}
	return out, nil
}

func (s *ReviewRecordStore) ListByReportID(reportID string) ([]*admissionmodel.ReviewRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*admissionmodel.ReviewRecord, 0)
	for _, item := range s.records {
		if item != nil && item.ReportID == reportID {
			out = append(out, cloneRecord(item))
		}
	}
	return out, nil
}

func (s *ReviewRecordStore) load() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var items []*admissionmodel.ReviewRecord
	if err := platformfiles.ReadJSON(s.path, &items); err != nil {
		if errors.Is(err, errFileNotExist()) {
			return ErrNotFound
		}
		return err
	}
	for _, item := range items {
		item.Normalize()
	}
	s.records = items
	return nil
}

func (s *ReviewRecordStore) saveLocked() error {
	return platformfiles.WriteJSONAtomic(s.path, s.records, 0600)
}

func cloneRecords(in []*admissionmodel.ReviewRecord) []*admissionmodel.ReviewRecord {
	out := make([]*admissionmodel.ReviewRecord, 0, len(in))
	for _, item := range in {
		out = append(out, cloneRecord(item))
	}
	return out
}

func cloneRecord(in *admissionmodel.ReviewRecord) *admissionmodel.ReviewRecord {
	if in == nil {
		return nil
	}
	cp := *in
	cp.CapabilityNotes = append([]string(nil), in.CapabilityNotes...)
	cp.ResidualRisks = cloneRisks(in.ResidualRisks)
	return &cp
}

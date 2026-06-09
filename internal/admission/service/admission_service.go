package service

import (
	"errors"
	"path/filepath"
	"strings"
	"time"

	admissionmodel "skill-scanner/internal/admission/model"
	admissionstore "skill-scanner/internal/admission/store"
	"skill-scanner/internal/models"
	platformid "skill-scanner/internal/platform/id"
)

type ReportLookup interface {
	GetReport(id string) *models.Report
	ReportsDir() string
}

type CreateSkillFromReportInput struct {
	ReportID        string
	DisplayName     string
	Version         string
	Description     string
	ReviewSummary   string
	AdmissionStatus admissionmodel.AdmissionStatus
	ReviewDecision  admissionmodel.ReviewDecision
	Operator        string
}

type CreateSkillFromReportOutput struct {
	Skill   *admissionmodel.AdmissionSkill
	Profile *admissionmodel.CapabilityProfile
	Risks   []admissionmodel.ResidualRisk
}

type SkillDetail struct {
	Skill         *admissionmodel.AdmissionSkill
	Profile       *admissionmodel.CapabilityProfile
	Risks         []admissionmodel.ResidualRisk
	ReviewRecords []*admissionmodel.ReviewRecord
}

type AdmissionService struct {
	reports     ReportLookup
	skills      *admissionstore.SkillStore
	profiles    *admissionstore.ProfileStore
	risks       *admissionstore.RiskStore
	reviews     *admissionstore.ReviewRecordStore
	profileBldr *ProfileBuilder
}

func NewAdmissionService(
	reports ReportLookup,
	skills *admissionstore.SkillStore,
	profiles *admissionstore.ProfileStore,
	risks *admissionstore.RiskStore,
	reviews *admissionstore.ReviewRecordStore,
	profileBldr *ProfileBuilder,
) *AdmissionService {
	return &AdmissionService{
		reports:     reports,
		skills:      skills,
		profiles:    profiles,
		risks:       risks,
		reviews:     reviews,
		profileBldr: profileBldr,
	}
}

func (s *AdmissionService) validate() error {
	if s == nil {
		return errors.New("admission service is nil")
	}
	if s.reports == nil {
		return errors.New("admission service reports lookup is nil")
	}
	if s.skills == nil {
		return errors.New("admission service skill store is nil")
	}
	if s.profiles == nil {
		return errors.New("admission service profile store is nil")
	}
	if s.risks == nil {
		return errors.New("admission service risk store is nil")
	}
	if s.reviews == nil {
		return errors.New("admission service review store is nil")
	}
	if s.profileBldr == nil {
		return errors.New("admission service profile builder is nil")
	}
	return nil
}

func (s *AdmissionService) CreateSkillFromReport(in CreateSkillFromReportInput) (*CreateSkillFromReportOutput, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	reportID := strings.TrimSpace(in.ReportID)
	if reportID == "" {
		return nil, errors.New("report_id is required")
	}
	if err := s.ensureReportNotImported(reportID); err != nil {
		return nil, err
	}
	rep := s.reports.GetReport(reportID)
	if rep == nil {
		return nil, errors.New("report not found")
	}
	skillID, err := s.generateUniqueSkillID()
	if err != nil {
		return nil, err
	}
	built, err := s.profileBldr.Build(ProfileBuildInput{Report: rep, DescriptionHint: in.Description, ReportsDir: s.reports.ReportsDir()})
	if err != nil {
		return nil, err
	}
	now := time.Now().Unix()
	name := strings.TrimSuffix(filepath.Base(rep.FileName), filepath.Ext(rep.FileName))
	if name == "" {
		name = rep.FileName
	}
	skill := &admissionmodel.AdmissionSkill{
		SkillID:              skillID,
		Name:                 name,
		DisplayName:          strings.TrimSpace(in.DisplayName),
		SourceType:           "report_import",
		SourceLocation:       reportID,
		Version:              strings.TrimSpace(in.Version),
		Description:          strings.TrimSpace(in.Description),
		PurposeSummary:       built.PurposeSummary,
		DeclaredCapabilities: built.DeclaredCaps,
		DetectedCapabilities: built.DetectedCaps,
		RiskTags:             built.RiskTags,
		AdmissionStatus:      in.AdmissionStatus,
		ReviewDecision:       in.ReviewDecision,
		ReviewSummary:        strings.TrimSpace(in.ReviewSummary),
		ReportID:             rep.ID,
		FileName:             rep.FileName,
		FileHash:             "",
		CreatedBy:            strings.TrimSpace(in.Operator),
		ReviewedBy:           strings.TrimSpace(in.Operator),
		WorkflowStage:        "verified",
		VerificationRequired: false,
		LastVerifiedAt:       now,
		CreatedAt:            now,
		UpdatedAt:            now,
	}
	skill.Normalize()
	if skill.DisplayName == "" {
		skill.DisplayName = skill.Name
	}
	if skill.Description == "" {
		skill.Description = rep.FileName + " 审查导入"
	}
	if err := s.skills.Create(skill); err != nil {
		return nil, err
	}
	built.Profile.SkillID = skillID
	built.Profile.Normalize()
	if err := s.profiles.Save(built.Profile); err != nil {
		return nil, err
	}
	if err := s.risks.Save(skillID, built.Risks); err != nil {
		return nil, err
	}
	recordID, err := platformid.GenerateHexID(16)
	if err != nil {
		return nil, err
	}
	record := &admissionmodel.ReviewRecord{
		RecordID:        recordID,
		SkillID:         skillID,
		ReportID:        rep.ID,
		Reviewer:        strings.TrimSpace(in.Operator),
		Decision:        skill.ReviewDecision,
		Summary:         skill.ReviewSummary,
		ResidualRisks:   built.Risks,
		CapabilityNotes: append([]string(nil), built.Profile.Evidence...),
		CreatedAt:       now,
	}
	if err := s.reviews.Create(record); err != nil {
		return nil, err
	}
	return &CreateSkillFromReportOutput{Skill: skill, Profile: built.Profile, Risks: built.Risks}, nil
}

func (s *AdmissionService) GetSkillDetail(skillID string) (*SkillDetail, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	skill, ok := s.skills.GetByID(skillID)
	if !ok {
		return nil, admissionstore.ErrNotFound
	}
	profile, _ := s.profiles.GetBySkillID(skillID)
	risks, err := s.risks.GetBySkillID(skillID)
	if err != nil {
		return nil, err
	}
	records, err := s.reviews.ListBySkillID(skillID)
	if err != nil {
		return nil, err
	}
	return &SkillDetail{Skill: skill, Profile: profile, Risks: risks, ReviewRecords: records}, nil
}

func (s *AdmissionService) ListSkills(query string, limit int) ([]*admissionmodel.AdmissionSkill, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if strings.TrimSpace(query) == "" {
		return s.skills.List()
	}
	return s.skills.Search(query, limit)
}

func (s *AdmissionService) generateUniqueSkillID() (string, error) {
	for i := 0; i < 10; i++ {
		skillID, err := platformid.GenerateSkillID()
		if err != nil {
			return "", err
		}
		if !s.skills.ExistsSkillID(skillID) {
			return skillID, nil
		}
	}
	return "", errors.New("failed to allocate unique skill id")
}

func (s *AdmissionService) ensureReportNotImported(reportID string) error {
	if s.skills.ExistsByReportID(reportID) {
		return errors.New("report already imported into admission registry")
	}
	return nil
}

package model

import (
	"errors"
	"strings"
)

type AdmissionStatus string
type ReviewDecision string

const (
	AdmissionStatusPending  AdmissionStatus = "pending"
	AdmissionStatusApproved AdmissionStatus = "approved"
	AdmissionStatusRejected AdmissionStatus = "rejected"
)

const (
	ReviewDecisionPass   ReviewDecision = "pass"
	ReviewDecisionReview ReviewDecision = "review"
	ReviewDecisionBlock  ReviewDecision = "block"
)

type AdmissionSkill struct {
	SkillID              string          `json:"skill_id"`
	Name                 string          `json:"name"`
	DisplayName          string          `json:"display_name"`
	SourceType           string          `json:"source_type"`
	SourceLocation       string          `json:"source_location"`
	Version              string          `json:"version"`
	Description          string          `json:"description"`
	PurposeSummary       string          `json:"purpose_summary"`
	DeclaredCapabilities []string        `json:"declared_capabilities"`
	DetectedCapabilities []string        `json:"detected_capabilities"`
	RiskTags             []string        `json:"risk_tags"`
	AdmissionStatus      AdmissionStatus `json:"admission_status"`
	ReviewDecision       ReviewDecision  `json:"review_decision"`
	ReviewSummary        string          `json:"review_summary"`
	ReportID             string          `json:"report_id"`
	FileName             string          `json:"file_name"`
	FileHash             string          `json:"file_hash"`
	CreatedBy            string          `json:"created_by"`
	ReviewedBy           string          `json:"reviewed_by"`
	CreatedAt            int64           `json:"created_at"`
	UpdatedAt            int64           `json:"updated_at"`
}

func (s *AdmissionSkill) Normalize() {
	if s == nil {
		return
	}
	s.SkillID = strings.TrimSpace(s.SkillID)
	s.Name = strings.TrimSpace(s.Name)
	s.DisplayName = strings.TrimSpace(s.DisplayName)
	s.SourceType = strings.TrimSpace(s.SourceType)
	s.SourceLocation = strings.TrimSpace(s.SourceLocation)
	s.Version = strings.TrimSpace(s.Version)
	s.Description = strings.TrimSpace(s.Description)
	s.PurposeSummary = strings.TrimSpace(s.PurposeSummary)
	s.ReviewSummary = strings.TrimSpace(s.ReviewSummary)
	s.ReportID = strings.TrimSpace(s.ReportID)
	s.FileName = strings.TrimSpace(s.FileName)
	s.FileHash = strings.TrimSpace(s.FileHash)
	s.CreatedBy = strings.TrimSpace(s.CreatedBy)
	s.ReviewedBy = strings.TrimSpace(s.ReviewedBy)
	s.DeclaredCapabilities = normalizeStringSlice(s.DeclaredCapabilities)
	s.DetectedCapabilities = normalizeStringSlice(s.DetectedCapabilities)
	s.RiskTags = normalizeStringSlice(s.RiskTags)
	if s.AdmissionStatus == "" {
		s.AdmissionStatus = AdmissionStatusPending
	}
	if s.ReviewDecision == "" {
		s.ReviewDecision = ReviewDecisionReview
	}
}

func (s *AdmissionSkill) Validate() error {
	if s == nil {
		return errors.New("skill is nil")
	}
	if s.SkillID == "" {
		return errors.New("skill_id is required")
	}
	if s.ReportID == "" {
		return errors.New("report_id is required")
	}
	if s.Name == "" && s.DisplayName == "" {
		return errors.New("name or display_name is required")
	}
	return nil
}

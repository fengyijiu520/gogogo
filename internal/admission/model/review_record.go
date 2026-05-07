package model

import (
	"errors"
	"strings"
)

type ReviewRecord struct {
	RecordID        string         `json:"record_id"`
	SkillID         string         `json:"skill_id"`
	ReportID        string         `json:"report_id"`
	Reviewer        string         `json:"reviewer"`
	Decision        ReviewDecision `json:"decision"`
	Summary         string         `json:"summary"`
	ResidualRisks   []ResidualRisk `json:"residual_risks"`
	CapabilityNotes []string       `json:"capability_notes"`
	CreatedAt       int64          `json:"created_at"`
}

func (r *ReviewRecord) Normalize() {
	if r == nil {
		return
	}
	r.RecordID = strings.TrimSpace(r.RecordID)
	r.SkillID = strings.TrimSpace(r.SkillID)
	r.ReportID = strings.TrimSpace(r.ReportID)
	r.Reviewer = strings.TrimSpace(r.Reviewer)
	r.Summary = strings.TrimSpace(r.Summary)
	r.CapabilityNotes = normalizeStringSlice(r.CapabilityNotes)
	for i := range r.ResidualRisks {
		r.ResidualRisks[i].Normalize()
	}
	if r.Decision == "" {
		r.Decision = ReviewDecisionReview
	}
}

func (r *ReviewRecord) Validate() error {
	if r == nil {
		return errors.New("review record is nil")
	}
	if r.RecordID == "" {
		return errors.New("record_id is required")
	}
	if r.SkillID == "" {
		return errors.New("skill_id is required")
	}
	if r.ReportID == "" {
		return errors.New("report_id is required")
	}
	return nil
}

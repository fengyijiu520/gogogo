package store

import (
	"testing"
	"time"

	admissionmodel "skill-scanner/internal/admission/model"
)

func TestSkillStoreCreateGetAndSearch(t *testing.T) {
	store, err := NewSkillStore(t.TempDir())
	if err != nil {
		t.Fatalf("new skill store: %v", err)
	}
	now := time.Now().Unix()
	skill := &admissionmodel.AdmissionSkill{
		SkillID:         "Ab3X9Kq1Lm8Pz2RtY",
		Name:            "mcp-http-fetch",
		DisplayName:     "HTTP Fetch Skill",
		ReportID:        "report-001",
		ReviewSummary:   "允许准入",
		AdmissionStatus: admissionmodel.AdmissionStatusApproved,
		ReviewDecision:  admissionmodel.ReviewDecisionPass,
		CreatedAt:       now,
		UpdatedAt:       now,
	}
	if err := store.Create(skill); err != nil {
		t.Fatalf("create skill: %v", err)
	}
	got, ok := store.GetByID(skill.SkillID)
	if !ok {
		t.Fatal("expected skill found by id")
	}
	if got.Name != skill.Name {
		t.Fatalf("expected name %q, got %q", skill.Name, got.Name)
	}
	items, err := store.Search("fetch", 10)
	if err != nil {
		t.Fatalf("search skills: %v", err)
	}
	if len(items) != 1 {
		t.Fatalf("expected 1 search result, got %d", len(items))
	}
	if items[0].SkillID != skill.SkillID {
		t.Fatalf("expected skill id %q, got %q", skill.SkillID, items[0].SkillID)
	}
}

func TestSkillStoreRejectsDuplicateReportID(t *testing.T) {
	store, err := NewSkillStore(t.TempDir())
	if err != nil {
		t.Fatalf("new skill store: %v", err)
	}
	now := time.Now().Unix()
	first := &admissionmodel.AdmissionSkill{SkillID: "Ab3X9Kq1Lm8Pz2RtY", Name: "a", ReportID: "report-001", CreatedAt: now, UpdatedAt: now}
	second := &admissionmodel.AdmissionSkill{SkillID: "Zz3X9Kq1Lm8Pz2RtY", Name: "b", ReportID: "report-001", CreatedAt: now, UpdatedAt: now}
	if err := store.Create(first); err != nil {
		t.Fatalf("create first skill: %v", err)
	}
	if err := store.Create(second); err == nil {
		t.Fatal("expected duplicate report create to fail")
	}
}

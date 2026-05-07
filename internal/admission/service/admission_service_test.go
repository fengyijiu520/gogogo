package service

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	admissionmodel "skill-scanner/internal/admission/model"
	admissionstore "skill-scanner/internal/admission/store"
	"skill-scanner/internal/models"
	"skill-scanner/internal/review"
)

type fakeReportLookup struct {
	report     *models.Report
	reportsDir string
}

func (f fakeReportLookup) GetReport(id string) *models.Report {
	if f.report != nil && f.report.ID == id {
		return f.report
	}
	return nil
}

func (f fakeReportLookup) ReportsDir() string {
	return f.reportsDir
}

func TestAdmissionServiceCreateSkillFromReport(t *testing.T) {
	dataDir := t.TempDir()
	reportsDir := filepath.Join(dataDir, "reports")
	skills, err := admissionstore.NewSkillStore(dataDir)
	if err != nil {
		t.Fatalf("new skill store: %v", err)
	}
	profiles, err := admissionstore.NewProfileStore(dataDir)
	if err != nil {
		t.Fatalf("new profile store: %v", err)
	}
	risks, err := admissionstore.NewRiskStore(dataDir)
	if err != nil {
		t.Fatalf("new risk store: %v", err)
	}
	reviews, err := admissionstore.NewReviewRecordStore(dataDir)
	if err != nil {
		t.Fatalf("new review store: %v", err)
	}
	report := &models.Report{ID: "report-001", FileName: "demo-skill.zip"}
	builder := NewProfileBuilder()
	svc := NewAdmissionService(fakeReportLookup{report: report, reportsDir: reportsDir}, skills, profiles, risks, reviews, builder)
	out, err := svc.CreateSkillFromReport(CreateSkillFromReportInput{
		ReportID:        report.ID,
		DisplayName:     "Demo Skill",
		Description:     "支持网络访问",
		AdmissionStatus: admissionmodel.AdmissionStatusApproved,
		ReviewDecision:  admissionmodel.ReviewDecisionPass,
		ReviewSummary:   "允许准入",
		Operator:        "admin",
	})
	if err != nil {
		t.Fatalf("create skill from report: %v", err)
	}
	if out.Skill == nil || out.Skill.SkillID == "" {
		t.Fatalf("expected created skill with id, got %+v", out)
	}
	if out.Skill.DisplayName != "Demo Skill" {
		t.Fatalf("expected display name propagated, got %+v", out.Skill)
	}
	if _, ok := skills.GetByID(out.Skill.SkillID); !ok {
		t.Fatalf("expected created skill persisted")
	}
	if profile, ok := profiles.GetBySkillID(out.Skill.SkillID); !ok || profile == nil {
		t.Fatalf("expected profile persisted, got %+v", profile)
	}
	if records, err := reviews.ListBySkillID(out.Skill.SkillID); err != nil || len(records) != 1 {
		t.Fatalf("expected one review record, records=%+v err=%v", records, err)
	}
}

func TestProfileBuilderUsesReviewResultSignals(t *testing.T) {
	b := NewProfileBuilder()
	out, err := b.Build(ProfileBuildInput{
		Report: &models.Report{ID: "report-001", FileName: "demo.zip"},
		ReviewResult: &review.Result{Behavior: review.BehaviorProfile{
			NetworkTargets: []string{"https://example.com/api"},
			ExecuteIOCs:    []string{"exec.Command"},
			CredentialIOCs: []string{"/root/.netrc"},
			BehaviorChains: []string{"下载=1, 执行=1, 外联=1"},
			SequenceAlerts: []string{"命中下载后执行时序"},
		}},
	})
	if err != nil {
		t.Fatalf("build profile: %v", err)
	}
	if !out.Profile.NetworkAccess || !out.Profile.CommandExec || !out.Profile.SensitiveDataAccess {
		t.Fatalf("expected profile populated from review result, got %+v", out.Profile)
	}
	if !containsString(out.Profile.Evidence, "/root/.netrc") {
		t.Fatalf("expected credential evidence collected, got %+v", out.Profile.Evidence)
	}
	if !containsString(out.Profile.Evidence, "命中下载后执行时序") {
		t.Fatalf("expected sequence alert evidence collected, got %+v", out.Profile.Evidence)
	}
	if len(out.Risks) == 0 {
		t.Fatalf("expected residual risks generated, got %+v", out.Risks)
	}
}

func TestProfileBuilderLoadsSignalsFromRealisticReportFixture(t *testing.T) {
	reportsDir := t.TempDir()
	report := &models.Report{ID: "report-fixture", FileName: "fixture-skill.zip", FilePath: filepath.Join(reportsDir, "fixture-skill.zip"), JSONPath: "report-fixture.json"}
	result := review.Result{Behavior: review.BehaviorProfile{
		NetworkTargets: []string{"https://example.com/api"},
		ExecuteIOCs:    []string{"exec.Command"},
		CredentialIOCs: []string{"/root/.netrc"},
		BehaviorChains: []string{"下载=1, 执行=1, 外联=1"},
		SequenceAlerts: []string{"命中下载后执行时序"},
	}}
	data, err := json.Marshal(struct {
		Result review.Result `json:"result"`
	}{Result: result})
	if err != nil {
		t.Fatalf("marshal report fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(reportsDir, report.JSONPath), data, 0644); err != nil {
		t.Fatalf("write report fixture: %v", err)
	}

	b := NewProfileBuilder()
	out, err := b.Build(ProfileBuildInput{Report: report})
	if err != nil {
		t.Fatalf("build profile from realistic fixture: %v", err)
	}
	if !out.Profile.NetworkAccess || !out.Profile.CommandExec || !out.Profile.SensitiveDataAccess {
		t.Fatalf("expected profile populated from realistic fixture, got %+v", out.Profile)
	}
	for _, want := range []string{"https://example.com/api", "exec.Command", "/root/.netrc", "命中下载后执行时序"} {
		if !containsString(out.Profile.Evidence, want) {
			t.Fatalf("expected evidence %q in %+v", want, out.Profile.Evidence)
		}
	}
}

func containsString(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

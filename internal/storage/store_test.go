package storage

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"skill-scanner/internal/llm"
	"skill-scanner/internal/models"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	t.Setenv("SKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD", "admin-test-password")
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store
}

func TestNewStoreUsesDefaultAdminPassword(t *testing.T) {
	store, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	admin := store.GetUser("admin")
	if admin == nil {
		t.Fatal("expected admin user")
	}
	if !store.CheckPassword("admin", "admin") {
		t.Fatal("expected default admin/admin password to work")
	}
	if !store.IsAdminDefaultPassword() {
		t.Fatal("expected admin to be using default password")
	}
}

func TestNewStoreBootstrapsAdminWithConfiguredPassword(t *testing.T) {
	store := newTestStore(t)
	admin := store.GetUser("admin")
	if admin == nil {
		t.Fatal("expected admin user")
	}
	if !store.CheckPassword("admin", "admin-test-password") {
		t.Fatal("expected configured admin password to work")
	}
	if store.CheckPassword("admin", "admin") {
		t.Fatal("expected default weak admin password to be rejected")
	}
	if store.IsAdminDefaultPassword() {
		t.Fatal("expected admin NOT to be using default password")
	}
}

func TestUserScopedConfigPathsDoNotUseRawUsername(t *testing.T) {
	store := newTestStore(t)
	username := "../evil/user"
	llmPath := store.userLLMConfigPath(username)
	profilePath := store.ruleProfilesPath(username)
	for _, path := range []string{llmPath, profilePath} {
		base := filepath.Base(path)
		if strings.Contains(base, "evil") || strings.Contains(base, "/") || strings.Contains(base, "..") {
			t.Fatalf("expected hashed user-scoped path, got %q", path)
		}
	}
	if err := store.SaveUserLLMConfig(username, &models.LLMConfig{Enabled: true, Provider: "deepseek"}); err != nil {
		t.Fatalf("save llm config: %v", err)
	}
	if err := store.SaveUserRuleProfile(username, models.RuleProfile{Name: "demo", SelectedRuleIDs: []string{"SF-001"}}); err != nil {
		t.Fatalf("save rule profile: %v", err)
	}
}

func TestDefaultLLMConfigIncludesEnabledDeepSeekProvider(t *testing.T) {
	store := newTestStore(t)
	providers := store.ListLLMProviders(false)
	if len(providers) == 0 {
		t.Fatal("expected enabled default provider")
	}
	if providers[0].ID != llm.DeepSeekProviderConfig.Provider {
		t.Fatalf("expected deepseek provider, got %q", providers[0].ID)
	}
	if providers[0].Model != llm.DeepSeekModel {
		t.Fatalf("expected deepseek model %q, got %q", llm.DeepSeekModel, providers[0].Model)
	}
}

func TestMigratedLLMConfigAddsEnabledDeepSeekProvider(t *testing.T) {
	store := newTestStore(t)
	store.ForceSetLLMConfigForTest(&LLMConfig{})
	providers := store.ListLLMProviders(false)
	if len(providers) == 0 {
		t.Fatal("expected migrated deepseek provider")
	}
	if providers[0].ID != llm.DeepSeekProviderConfig.Provider {
		t.Fatalf("expected deepseek provider, got %q", providers[0].ID)
	}
}

func TestListLLMProvidersShowsEnabledProviderWithoutAPIKey(t *testing.T) {
	store := newTestStore(t)
	store.ForceSetLLMConfigForTest(&LLMConfig{Providers: []LLMProviderConfig{{ID: "demo", Name: "Demo", Protocol: "openai", BaseURL: "https://api.example.com/chat/completions", Model: "demo-model", Enabled: true}}})
	providers := store.ListLLMProviders(false)
	if len(providers) == 0 {
		t.Fatal("expected enabled provider without api key to be listed")
	}
	found := false
	for _, provider := range providers {
		if provider.ID == "demo" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected demo provider in list, got %+v", providers)
	}
}

func TestUserLLMConfigEncryptsAndReadsPersonalAPIKey(t *testing.T) {
	store := newTestStore(t)
	if err := store.SaveUserLLMConfig("alice", &models.LLMConfig{Enabled: true, Provider: "deepseek", APIKey: "personal-secret"}); err != nil {
		t.Fatalf("save user llm config: %v", err)
	}
	config := store.GetUserLLMConfig("alice")
	if config == nil {
		t.Fatal("expected user llm config")
	}
	if config.APIKey != "personal-secret" {
		t.Fatalf("expected decrypted api key, got %q", config.APIKey)
	}
}

func TestSetLLMProviderEnabledControlsVisibleProviders(t *testing.T) {
	store := newTestStore(t)
	if err := store.SetLLMProviderEnabled(llm.DeepSeekProviderConfig.Provider, false); err != nil {
		t.Fatalf("disable provider: %v", err)
	}
	if providers := store.ListLLMProviders(false); len(providers) != 0 {
		t.Fatalf("expected no visible enabled providers, got %+v", providers)
	}
	if err := store.SetLLMProviderEnabled(llm.DeepSeekProviderConfig.Provider, true); err != nil {
		t.Fatalf("enable provider: %v", err)
	}
	providers := store.ListLLMProviders(false)
	if len(providers) == 0 || providers[0].ID != llm.DeepSeekProviderConfig.Provider {
		t.Fatalf("expected visible deepseek provider, got %+v", providers)
	}
}

func TestIsPathSafeRejectsSiblingPrefixDirectory(t *testing.T) {
	base := filepath.Join(t.TempDir(), "reports")
	sibling := base + "-evil"
	if IsPathSafe(base, filepath.Join("..", filepath.Base(sibling), "x.html")) {
		t.Fatal("expected sibling directory with shared prefix to be rejected")
	}
	if !IsPathSafe(base, filepath.Join("nested", "x.html")) {
		t.Fatal("expected nested relative path to be accepted")
	}
}

func TestReportIndexTracksAddReloadAndDelete(t *testing.T) {
	store := newTestStore(t)
	report := &models.Report{
		ID:       "rep-001",
		Username: "alice",
		Team:     "red",
		FilePath: "report-1.html",
		HTMLPath: "report-1.html",
		JSONPath: "report-1.json",
		PDFPath:  "report-1.pdf",
	}
	for _, rel := range []string{report.HTMLPath, report.JSONPath, report.PDFPath} {
		if err := os.WriteFile(filepath.Join(store.ReportsDir(), rel), []byte(rel), 0600); err != nil {
			t.Fatalf("write artifact %s: %v", rel, err)
		}
	}
	if err := store.AddReport(report); err != nil {
		t.Fatalf("add report: %v", err)
	}
	if got := store.GetReport(report.ID); got == nil || got.ID != report.ID {
		t.Fatalf("expected report from index after add, got %+v", got)
	}

	reloaded, err := NewStore(store.dataDir)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}
	if got := reloaded.GetReport(report.ID); got == nil || got.ID != report.ID {
		t.Fatalf("expected report from reloaded index, got %+v", got)
	}
	if err := reloaded.DeleteReport("admin", report.ID); err != nil {
		t.Fatalf("delete report: %v", err)
	}
	if got := reloaded.GetReport(report.ID); got != nil {
		t.Fatalf("expected index entry removed after delete, got %+v", got)
	}
	for _, rel := range []string{report.HTMLPath, report.JSONPath, report.PDFPath} {
		if _, err := os.Stat(filepath.Join(reloaded.ReportsDir(), rel)); !os.IsNotExist(err) {
			t.Fatalf("expected artifact %s removed, stat err=%v", rel, err)
		}
	}
}

func TestAddReportRollsBackMemoryWhenSaveFails(t *testing.T) {
	store := newTestStore(t)
	if err := os.Remove(store.reportsPath()); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove reports file: %v", err)
	}
	if err := os.Mkdir(store.reportsPath(), 0700); err != nil {
		t.Fatalf("replace reports path with directory: %v", err)
	}

	report := &models.Report{ID: "rep-save-fail", Username: "alice", FilePath: "a.docx"}
	err := store.AddReport(report)
	if err == nil {
		t.Fatal("expected add report to fail when reports file cannot be written")
	}
	if got := store.GetReport(report.ID); got != nil {
		t.Fatalf("expected report index rolled back after save failure, got %+v", got)
	}
	if len(store.ListReports("admin")) != 0 {
		t.Fatalf("expected in-memory report slice rolled back after save failure, got %+v", store.ListReports("admin"))
	}
}

func TestDeleteReportIgnoresArtifactRemovalFailureAfterMetadataPersisted(t *testing.T) {
	store := newTestStore(t)
	report := &models.Report{
		ID:       "rep-delete-artifact-fail",
		Username: "alice",
		FilePath: "report-2.docx",
		HTMLPath: "report-2.html",
	}
	for _, rel := range []string{report.FilePath, report.HTMLPath} {
		if err := os.WriteFile(filepath.Join(store.ReportsDir(), rel), []byte(rel), 0600); err != nil {
			t.Fatalf("write artifact %s: %v", rel, err)
		}
	}
	blockerPath := filepath.Join(store.ReportsDir(), report.FilePath)
	if err := os.Remove(blockerPath); err != nil {
		t.Fatalf("remove file to create blocker dir: %v", err)
	}
	if err := os.Mkdir(blockerPath, 0700); err != nil {
		t.Fatalf("create blocker dir: %v", err)
	}
	if err := store.AddReport(report); err != nil {
		t.Fatalf("add report: %v", err)
	}

	if err := store.DeleteReport("admin", report.ID); err != nil {
		t.Fatalf("expected metadata delete to succeed even if artifact cleanup fails, got %v", err)
	}
	if got := store.GetReport(report.ID); got != nil {
		t.Fatalf("expected report metadata removed, got %+v", got)
	}
	reloaded, err := NewStore(store.dataDir)
	if err != nil {
		t.Fatalf("reload store: %v", err)
	}
	if got := reloaded.GetReport(report.ID); got != nil {
		t.Fatalf("expected persisted metadata removed, got %+v", got)
	}
}

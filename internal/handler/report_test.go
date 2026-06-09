package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admissionmodel "skill-scanner/internal/admission/model"
	admissionservice "skill-scanner/internal/admission/service"
	"skill-scanner/internal/models"
	"skill-scanner/internal/review"
	"skill-scanner/internal/storage"
)

func newAuthenticatedRequest(t *testing.T, method, target, username string) *http.Request {
	t.Helper()
	req := httptest.NewRequest(method, target, nil)
	sessionID := generateSessionID(username)
	sessionStore.Store(sessionID, &Session{Username: username, CreatedAt: time.Now()})
	t.Cleanup(func() {
		sessionStore.Delete(sessionID)
	})
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID, Path: "/"})
	return req
}

func newTestStore(t *testing.T) *storage.Store {
	t.Helper()
	t.Setenv("SKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD", "admin-test-password")
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store
}

func writeReportArtifact(t *testing.T, store *storage.Store, name, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(store.ReportsDir(), name), []byte(body), 0644); err != nil {
		t.Fatalf("write report artifact %s: %v", name, err)
	}
}

func addTestReport(t *testing.T, store *storage.Store, report *models.Report) {
	t.Helper()
	if report.CreatedAt == 0 {
		report.CreatedAt = time.Now().Unix()
	}
	if err := store.AddReport(report); err != nil {
		t.Fatalf("add report: %v", err)
	}
}

func TestViewReportServesHTMLInline(t *testing.T) {
	store := newTestStore(t)
	htmlName := "demo_20260501_120000.html"
	htmlBody := "<html><body><h1>在线报告</h1></body></html>"
	if err := os.WriteFile(filepath.Join(store.ReportsDir(), htmlName), []byte(htmlBody), 0644); err != nil {
		t.Fatalf("write html report: %v", err)
	}
	report := &models.Report{ID: "rep-view", TaskID: "task-view-001", RequestID: "rid-view-001", Username: "admin", FileName: "demo_20260501_120000", HTMLPath: htmlName, CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports/view/rep-view", "admin")
	viewReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("expected html content type, got %q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); got != "inline" {
		t.Fatalf("expected inline content disposition, got %q", got)
	}
	if got := rec.Header().Get("Content-Security-Policy"); got != reportContentSecurityPolicy {
		t.Fatalf("expected strict report csp, got %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected no-store cache control, got %q", got)
	}
	if !strings.Contains(rec.Body.String(), "在线报告") {
		t.Fatalf("expected html body served, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "返回报告列表") {
		t.Fatalf("expected inline report toolbar in online view")
	}
	if !strings.Contains(rec.Body.String(), "进入准入库") || !strings.Contains(rec.Body.String(), "进入组合分析") {
		t.Fatalf("expected inline report toolbar exposes admission and combination entry, got %q", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "任务 task-view-001") || !strings.Contains(rec.Body.String(), "请求 rid-view-001") {
		t.Fatalf("expected inline report toolbar exposes trace metadata, got %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "返回上一页") {
		t.Fatalf("expected inline report toolbar removes back button")
	}
}

func TestViewReportRejectsCrossTeamAccess(t *testing.T) {
	store := newTestStore(t)
	if err := store.CreateUserWithTeam("owner", "pass123", "team-a"); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := store.CreateUserWithTeam("outsider", "pass123", "team-b"); err != nil {
		t.Fatalf("create outsider: %v", err)
	}
	htmlName := "isolated_20260501_120000.html"
	if err := os.WriteFile(filepath.Join(store.ReportsDir(), htmlName), []byte("<html><body>private</body></html>"), 0644); err != nil {
		t.Fatalf("write html report: %v", err)
	}
	report := &models.Report{ID: "rep-private", Username: "owner", Team: "team-a", FileName: "isolated_20260501_120000", HTMLPath: htmlName, CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports/view/rep-private", "outsider")
	viewReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "private") {
		t.Fatalf("expected forbidden response without report body, got %q", rec.Body.String())
	}
}

func TestDownloadReportSanitizesAttachmentFilename(t *testing.T) {
	store := newTestStore(t)
	docxName := "stored.docx"
	if err := os.WriteFile(filepath.Join(store.ReportsDir(), docxName), []byte("docx"), 0644); err != nil {
		t.Fatalf("write docx: %v", err)
	}
	report := &models.Report{ID: "rep-download", TaskID: "task-download-001", RequestID: "rid-download-001", Username: "admin", FileName: "bad\r\nname\";x", FilePath: docxName, CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports/download/rep-download", "admin")
	downloadReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	got := rec.Header().Get("Content-Disposition")
	if strings.Contains(got, "\r") || strings.Contains(got, "\n") || strings.Contains(got, ";x") {
		t.Fatalf("expected sanitized content disposition, got %q", got)
	}
	if !strings.Contains(got, "bad__name__x.docx") {
		t.Fatalf("expected sanitized file name, got %q", got)
	}
	if got := rec.Header().Get("X-Task-Id"); got != "task-download-001" {
		t.Fatalf("expected task id header, got %q", got)
	}
	if got := rec.Header().Get("X-Request-Id"); got != "rid-download-001" {
		t.Fatalf("expected request id header, got %q", got)
	}
}

func TestDownloadReportHTMLDoesNotRequireDocxArtifact(t *testing.T) {
	store := newTestStore(t)
	htmlName := "standalone.html"
	htmlBody := "<html><body>html only</body></html>"
	if err := os.WriteFile(filepath.Join(store.ReportsDir(), htmlName), []byte(htmlBody), 0644); err != nil {
		t.Fatalf("write html report: %v", err)
	}
	report := &models.Report{ID: "rep-download-html", Username: "admin", FileName: "standalone", HTMLPath: htmlName, CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports/download/rep-download-html?format=html", "admin")
	downloadReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for html download without docx artifact, got %d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "text/html") {
		t.Fatalf("expected html content type for html download, got %q", got)
	}
	if !strings.Contains(rec.Body.String(), "html only") {
		t.Fatalf("expected html artifact body served, got %q", rec.Body.String())
	}
}

func TestDownloadReportJSONDoesNotRequireDocxArtifact(t *testing.T) {
	store := newTestStore(t)
	jsonName := "standalone.json"
	jsonBody := `{"status":"ok"}`
	if err := os.WriteFile(filepath.Join(store.ReportsDir(), jsonName), []byte(jsonBody), 0644); err != nil {
		t.Fatalf("write json report: %v", err)
	}
	report := &models.Report{ID: "rep-download-json", Username: "admin", FileName: "standalone", JSONPath: jsonName, CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports/download/rep-download-json?format=json", "admin")
	downloadReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for json download without docx artifact, got %d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("expected json content type, got %q", got)
	}
	if strings.TrimSpace(rec.Body.String()) != jsonBody {
		t.Fatalf("expected json artifact body served, got %q", rec.Body.String())
	}
}

func TestDownloadReportReturnsFailedDependencyWhenPDFMissing(t *testing.T) {
	store := newTestStore(t)
	report := &models.Report{
		ID:        "rep-download-pdf-missing",
		Username:  "admin",
		FileName:  "standalone",
		CreatedAt: time.Now().Unix(),
		PDFError:  "wkhtmltopdf not available",
	}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports/download/rep-download-pdf-missing?format=pdf", "admin")
	downloadReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusFailedDependency {
		t.Fatalf("expected 424 for missing pdf artifact, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "wkhtmltopdf not available") {
		t.Fatalf("expected pdf error detail in response, got %q", rec.Body.String())
	}
}

func TestDownloadReportReturnsNotFoundWhenRequestedFormatNotAvailable(t *testing.T) {
	store := newTestStore(t)
	report := &models.Report{ID: "rep-download-no-html", Username: "admin", FileName: "standalone", CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "html", target: "/reports/download/rep-download-no-html?format=html", want: "该报告不支持 HTML 下载"},
		{name: "json", target: "/reports/download/rep-download-no-html?format=json", want: "该报告不支持 JSON 下载"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := newAuthenticatedRequest(t, http.MethodGet, tc.target, "admin")
			downloadReport(store).ServeHTTP(rec, req)
			if rec.Code != http.StatusNotFound {
				t.Fatalf("expected 404, got %d body=%q", rec.Code, rec.Body.String())
			}
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Fatalf("expected response to contain %q, got %q", tc.want, rec.Body.String())
			}
		})
	}
}

func TestDownloadReportRejectsUnsafeTargetPath(t *testing.T) {
	store := newTestStore(t)
	report := &models.Report{ID: "rep-download-unsafe", Username: "admin", FileName: "standalone", HTMLPath: "../escape.html", CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports/download/rep-download-unsafe?format=html", "admin")
	downloadReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for unsafe path, got %d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "无效的报告路径") {
		t.Fatalf("expected unsafe path message, got %q", rec.Body.String())
	}
}

func TestViewReportRejectsPostMethod(t *testing.T) {
	store := newTestStore(t)
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/reports/view/rep-view", "admin")
	viewReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("expected allow header for GET/HEAD, got %q", got)
	}
}

func TestDownloadReportRejectsPostMethod(t *testing.T) {
	store := newTestStore(t)
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/reports/download/rep-download", "admin")
	downloadReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "GET, HEAD" {
		t.Fatalf("expected allow header for GET/HEAD, got %q", got)
	}
}

func TestDeleteReportRejectsGetMethod(t *testing.T) {
	store := newTestStore(t)
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports/delete/rep-delete", "admin")
	deleteReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
	if got := rec.Header().Get("Allow"); got != "POST" {
		t.Fatalf("expected allow header for POST, got %q", got)
	}
}

func TestDeleteReportAllowsOwnerAndRemovesArtifacts(t *testing.T) {
	store := newTestStore(t)
	writeReportArtifact(t, store, "owner.docx", "docx")
	writeReportArtifact(t, store, "owner.html", "html")
	writeReportArtifact(t, store, "owner.json", "json")
	report := &models.Report{ID: "rep-owner-delete", Username: "admin", FileName: "owner_report", FilePath: "owner.docx", HTMLPath: "owner.html", JSONPath: "owner.json", CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/reports/delete/rep-owner-delete", "admin")
	deleteReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/reports?report_status=deleted" {
		t.Fatalf("expected success redirect, got %q", got)
	}
	if store.GetReport("rep-owner-delete") != nil {
		t.Fatalf("expected report metadata removed")
	}
	for _, name := range []string{"owner.docx", "owner.html", "owner.json"} {
		if _, err := os.Stat(filepath.Join(store.ReportsDir(), name)); !os.IsNotExist(err) {
			t.Fatalf("expected artifact %s removed, stat err=%v", name, err)
		}
	}
}

func TestDeleteReportRejectsSameTeamNonOwner(t *testing.T) {
	store := newTestStore(t)
	if err := store.CreateUserWithTeam("owner", "pass123", "team-a"); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := store.CreateUserWithTeam("teammate", "pass123", "team-a"); err != nil {
		t.Fatalf("create teammate: %v", err)
	}
	writeReportArtifact(t, store, "team.html", "private")
	report := &models.Report{ID: "rep-team-delete", Username: "owner", Team: "team-a", FileName: "team_report", HTMLPath: "team.html", CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/reports/delete/rep-team-delete", "teammate")
	deleteReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if store.GetReport("rep-team-delete") == nil {
		t.Fatalf("expected report metadata preserved for forbidden delete")
	}
}

func TestDeleteReportAllowsAdminToDeleteOthersReport(t *testing.T) {
	store := newTestStore(t)
	if err := store.CreateUserWithTeam("owner", "pass123", "team-a"); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	writeReportArtifact(t, store, "admin-delete.html", "admin")
	report := &models.Report{ID: "rep-admin-delete", Username: "owner", Team: "team-a", FileName: "owner_owned_report", HTMLPath: "admin-delete.html", CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodPost, "/reports/delete/rep-admin-delete", "admin")
	deleteReport(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if store.GetReport("rep-admin-delete") != nil {
		t.Fatalf("expected admin delete to remove report metadata")
	}
}

func TestListReportsShowsViewEntryAndSecondPrecisionTime(t *testing.T) {
	store := newTestStore(t)
	report := &models.Report{
		ID:           "rep-list",
		TaskID:       "task-report-list",
		RequestID:    "rid-report-list",
		Username:     "admin",
		FileName:     "demo_20260501_120001",
		HTMLPath:     "demo_20260501_120001.html",
		CreatedAt:    time.Date(2026, 5, 1, 16, 7, 8, 0, time.UTC).Unix(),
		Status:       "completed",
		Decision:     "user_decision_required",
		FindingCount: 3,
		HighRisk:     1,
		MediumRisk:   1,
		LowRisk:      1,
	}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports", "admin")
	listReports(store).ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(body, "/reports/view/rep-list") {
		t.Fatalf("expected view link in reports page, got %q", body)
	}
	if !strings.Contains(body, "/reports/download/rep-list") {
		t.Fatalf("expected download link in reports page, got %q", body)
	}
	if !strings.Contains(body, "/admission/import/rep-list") || !strings.Contains(body, "/combination/overview?report_id=rep-list") {
		t.Fatalf("expected reports page exposes admission and combination entry, got %q", body)
	}
	if !strings.Contains(body, "/reports/delete/rep-list") || !strings.Contains(body, "report-delete-form") {
		t.Fatalf("expected delete action for deletable report, got %q", body)
	}
	if !strings.Contains(body, "直接查看") || !strings.Contains(body, "已完成") || !strings.Contains(body, "决策 待用户基于证据判断") {
		t.Fatalf("expected reports page contains unified view button and status/decision labels, got %q", body)
	}
	wantTime := time.Date(2026, 5, 1, 16, 7, 8, 0, time.UTC).In(time.Local).Format("2006-01-02 15:04:05")
	if !strings.Contains(body, wantTime) {
		t.Fatalf("expected second precision timestamp %s, got %q", wantTime, body)
	}
	if !strings.Contains(body, "请求 rid-report-list") {
		t.Fatalf("expected request id in report meta, got %q", body)
	}
	if !strings.Contains(body, "任务 task-report-list") {
		t.Fatalf("expected task id in report meta, got %q", body)
	}
	if strings.Contains(body, "?format=pdf") {
		t.Fatalf("expected pdf link hidden when PDF path missing")
	}
	for _, want := range []string{"🔴 高 1", "🟡 中 1", "🟢 低 1", "共 3 项"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected reports page shows risk badge %q, got %q", want, body)
		}
	}
}

func TestListReportsFilterByRequestID(t *testing.T) {
	store := newTestStore(t)
	reportA := &models.Report{ID: "rep-filter-a", Username: "admin", FileName: "a", RequestID: "rid-a-123", CreatedAt: time.Now().Unix()}
	reportB := &models.Report{ID: "rep-filter-b", Username: "admin", FileName: "b", RequestID: "rid-b-456", CreatedAt: time.Now().Unix()}
	addTestReport(t, store, reportA)
	addTestReport(t, store, reportB)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports?request_id=rid-a", "admin")
	listReports(store).ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(body, "rep-filter-a") {
		t.Fatalf("expected filtered report A shown, got %q", body)
	}
	if strings.Contains(body, "rep-filter-b") {
		t.Fatalf("expected report B hidden by request_id filter, got %q", body)
	}
}

func TestListReportsFilterByTaskID(t *testing.T) {
	store := newTestStore(t)
	reportA := &models.Report{ID: "rep-task-filter-a", TaskID: "task-a-123", Username: "admin", FileName: "a", CreatedAt: time.Now().Unix()}
	reportB := &models.Report{ID: "rep-task-filter-b", TaskID: "task-b-456", Username: "admin", FileName: "b", CreatedAt: time.Now().Unix()}
	addTestReport(t, store, reportA)
	addTestReport(t, store, reportB)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports?task_id=task-a", "admin")
	listReports(store).ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(body, "rep-task-filter-a") {
		t.Fatalf("expected filtered report A shown, got %q", body)
	}
	if strings.Contains(body, "rep-task-filter-b") {
		t.Fatalf("expected report B hidden by task_id filter, got %q", body)
	}
	if !strings.Contains(body, "name=\"task_id\"") {
		t.Fatalf("expected task_id filter input rendered, got %q", body)
	}
}

func TestListReportsUsesSkillContextForCombinationEntryAfterImport(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	report := &models.Report{
		ID:        "rep-imported",
		Username:  "admin",
		FileName:  "imported_skill.zip",
		FilePath:  filepath.Join(store.ReportsDir(), "imported_skill.zip"),
		JSONPath:  "rep-imported.json",
		Status:    "completed",
		CreatedAt: time.Date(2026, 5, 1, 16, 7, 8, 0, time.UTC).Unix(),
	}
	writeReportArtifact(t, store, "rep-imported.json", `{"result":{"behavior":{}}}`)
	addTestReport(t, store, report)
	out, err := svc.CreateSkillFromReport(admissionservice.CreateSkillFromReportInput{
		ReportID:        report.ID,
		DisplayName:     "imported skill",
		Description:     "imported",
		AdmissionStatus: admissionmodel.AdmissionStatusApproved,
		ReviewDecision:  admissionmodel.ReviewDecisionPass,
		ReviewSummary:   "ok",
		Operator:        "admin",
	})
	if err != nil {
		t.Fatalf("import report as skill: %v", err)
	}
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports", "admin")
	listReports(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "/combination/overview?skill_id="+out.Skill.SkillID) {
		t.Fatalf("expected imported report combination entry to carry skill context, got %q", body)
	}
}

func TestAdmissionListShowsAddToCombinationEntry(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	skill := createAdmissionTestSkill(t, store, svc, "rep-admission-combo", "combo_skill.zip", review.Result{})
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/admission/skills", "admin")
	admissionList(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "加入组合") {
		t.Fatalf("expected add-to-combination entry rendered, got %q", body)
	}
	if !strings.Contains(body, "/combination/overview?skill_id="+skill.SkillID) {
		t.Fatalf("expected add-to-combination link carries skill id, got %q", body)
	}
}

func TestListReportsHidesDeleteForSameTeamNonOwner(t *testing.T) {
	store := newTestStore(t)
	if err := store.CreateUserWithTeam("owner", "pass123", "team-a"); err != nil {
		t.Fatalf("create owner: %v", err)
	}
	if err := store.CreateUserWithTeam("viewer", "pass123", "team-a"); err != nil {
		t.Fatalf("create viewer: %v", err)
	}
	report := &models.Report{ID: "rep-shared", Username: "owner", Team: "team-a", FileName: "shared_report", CreatedAt: time.Now().Unix()}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports", "viewer")
	listReports(store).ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "shared_report") {
		t.Fatalf("expected same-team report visible, got %q", body)
	}
	if strings.Contains(body, "/reports/delete/rep-shared") {
		t.Fatalf("expected delete action hidden for same-team non-owner, got %q", body)
	}
}

func TestDashboardShowsViewEntryForRecentReport(t *testing.T) {
	store := newTestStore(t)
	report := &models.Report{
		ID:           "rep-dashboard",
		TaskID:       "task-dashboard-001",
		RequestID:    "rid-dashboard-001",
		Username:     "admin",
		FileName:     "demo_20260501_120002",
		HTMLPath:     "demo_20260501_120002.html",
		Status:       "running",
		Decision:     "review",
		FindingCount: 4,
		HighRisk:     1,
		MediumRisk:   1,
		LowRisk:      2,
		CreatedAt:    time.Date(2026, 5, 1, 16, 7, 9, 0, time.UTC).Unix(),
	}
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/dashboard", "admin")
	dashboard(store).ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if !strings.Contains(body, "/reports/view/rep-dashboard") {
		t.Fatalf("expected dashboard view link, got %q", body)
	}
	if !strings.Contains(body, "直接查看") || !strings.Contains(body, "进行中") || !strings.Contains(body, "决策 需人工复核") {
		t.Fatalf("expected dashboard contains unified view button and report state labels, got %q", body)
	}
	wantDashTime := time.Date(2026, 5, 1, 16, 7, 9, 0, time.UTC).In(time.Local).Format("2006-01-02 15:04:05")
	if !strings.Contains(body, wantDashTime) {
		t.Fatalf("expected second precision dashboard timestamp %s, got %q", wantDashTime, body)
	}
	if !strings.Contains(body, "任务 task-dashboard-001") || !strings.Contains(body, "请求 rid-dashboard-001") {
		t.Fatalf("expected dashboard includes trace identifiers, got %q", body)
	}
	for _, want := range []string{"🔴 高 1", "🟡 中 1", "🟢 低 2", "共 4 项"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected dashboard shows risk badge %q, got %q", want, body)
		}
	}
}

func TestListReportsUsesPersistedNormalizedDecisionLabel(t *testing.T) {
	store := newTestStore(t)
	report := &models.Report{
		ID:           "rep-normalized-decision",
		TaskID:       "task-normalized-decision-001",
		RequestID:    "rid-normalized-decision-001",
		Username:     "admin",
		FileName:     "normalized_decision_report",
		HTMLPath:     "normalized_decision_report.html",
		Status:       "completed",
		Decision:     "UserDecisionRequired",
		FindingCount: 4,
		HighRisk:     1,
		MediumRisk:   1,
		LowRisk:      2,
		CreatedAt:    time.Date(2026, 5, 1, 16, 7, 10, 0, time.UTC).Unix(),
	}
	writeReportArtifact(t, store, "normalized_decision_report.json", `{"summary_cn":{"closure_narrative":"待复核项主要缺少source与sink证据。"}}`)
	report.JSONPath = "normalized_decision_report.json"
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/reports", "admin")
	listReports(store).ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	for _, want := range []string{"决策 待用户基于证据判断", "处置提示：待复核项主要缺少source与sink证据。", "🔴 高 1", "🟡 中 1", "🟢 低 2", "共 4 项"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected reports page contains %q, got %q", want, body)
		}
	}
}

func TestDashboardShowsDecisionHintFromPersistedJSON(t *testing.T) {
	store := newTestStore(t)
	report := &models.Report{
		ID:           "rep-dashboard-hint",
		TaskID:       "task-dashboard-hint-001",
		RequestID:    "rid-dashboard-hint-001",
		Username:     "admin",
		FileName:     "dashboard_hint_report",
		HTMLPath:     "dashboard_hint_report.html",
		JSONPath:     "dashboard_hint_report.json",
		Status:       "completed",
		Decision:     "UserDecisionRequired",
		FindingCount: 2,
		HighRisk:     1,
		LowRisk:      1,
		CreatedAt:    time.Date(2026, 5, 1, 16, 7, 11, 0, time.UTC).Unix(),
	}
	writeReportArtifact(t, store, "dashboard_hint_report.json", `{"summary_cn":{"closure_narrative":"待复核项主要缺少source与runtime证据。"}}`)
	addTestReport(t, store, report)

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/dashboard", "admin")
	dashboard(store).ServeHTTP(rec, req)

	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	for _, want := range []string{"决策 待用户基于证据判断", "处置提示：待复核项主要缺少source与runtime证据。"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected dashboard contains %q, got %q", want, body)
		}
	}
}

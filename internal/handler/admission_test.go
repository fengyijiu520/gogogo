package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	admissionmodel "skill-scanner/internal/admission/model"
	admissionservice "skill-scanner/internal/admission/service"
	admissionstore "skill-scanner/internal/admission/store"
	combinationservice "skill-scanner/internal/combination"
	"skill-scanner/internal/models"
	"skill-scanner/internal/review"
	"skill-scanner/internal/storage"
)

func TestCombinationOverviewAggregatesSelectedSkills(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}

	first := createAdmissionTestSkill(t, store, svc, "report-a", "skill-a.zip", review.Result{Behavior: review.BehaviorProfile{
		NetworkTargets: []string{"https://example.com/a"},
		CredentialIOCs: []string{"/root/.netrc"},
		BehaviorChains: []string{"下载=1, 执行=0, 外联=1"},
	}})
	second := createAdmissionTestSkill(t, store, svc, "report-b", "skill-b.zip", review.Result{Behavior: review.BehaviorProfile{
		ExecTargets:    []string{"exec.Command"},
		ExecuteIOCs:    []string{"exec.Command"},
		BehaviorChains: []string{"下载=1, 执行=1, 外联=1"},
	}})

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?skill_id="+first.SkillID+"&skill_id="+second.SkillID, "admin")
	combinationOverview(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "组合风险分析") {
		t.Fatalf("expected combination page title, got %q", body)
	}
	if !strings.Contains(body, first.DisplayName) || !strings.Contains(body, second.DisplayName) {
		t.Fatalf("expected selected skills rendered, got %q", body)
	}
	if !strings.Contains(body, "快照 ID") {
		t.Fatalf("expected saved snapshot metadata rendered, got %q", body)
	}
	if !strings.Contains(body, "组合结论") || !strings.Contains(body, "高风险") {
		t.Fatalf("expected conclusion summary rendered, got %q", body)
	}
	if !strings.Contains(body, "建议暂停组合准入") {
		t.Fatalf("expected recommendation rendered, got %q", body)
	}
	if !strings.Contains(body, "组合闭环摘要：") {
		t.Fatalf("expected combination closure narrative rendered, got %q", body)
	}
	if !strings.Contains(body, "动态链路推理") {
		t.Fatalf("expected inferred chain section rendered, got %q", body)
	}
	if !strings.Contains(body, "潜在完整攻击链") {
		t.Fatalf("expected full attack chain rendered, got %q", body)
	}
	if strings.Contains(body, "潜在远程指令执行链") {
		t.Fatalf("expected weaker inferred chain folded, got %q", body)
	}
	if !strings.Contains(body, "触发证据：") || !strings.Contains(body, "https://example.com/a") || !strings.Contains(body, "exec.Command") {
		t.Fatalf("expected inferred chain evidence rendered, got %q", body)
	}
	if !strings.Contains(body, "network_access") {
		t.Fatalf("expected aggregated network capability, got %q", body)
	}
	if !strings.Contains(body, "command_exec") {
		t.Fatalf("expected aggregated command capability, got %q", body)
	}
	if count := strings.Count(body, "存在高风险行为链摘要"); count != 1 {
		t.Fatalf("expected deduplicated behavior-chain risk once, got %d in %q", count, body)
	}
	if !strings.Contains(body, "来源技能：") {
		t.Fatalf("expected risk source skills rendered, got %q", body)
	}
	if !strings.Contains(body, first.SkillID) || !strings.Contains(body, second.SkillID) {
		t.Fatalf("expected source skill ids rendered, got %q", body)
	}
	if !strings.Contains(body, "存在外联能力") {
		t.Fatalf("expected network residual risk rendered, got %q", body)
	}
	if !strings.Contains(body, "存在命令执行能力") {
		t.Fatalf("expected command residual risk rendered, got %q", body)
	}
}

func TestCombinationOverviewSupportsSearchAndPreservesSelection(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	first := createAdmissionTestSkill(t, store, svc, "report-search-a", "alpha-skill.zip", review.Result{})
	second := createAdmissionTestSkill(t, store, svc, "report-search-b", "beta-skill.zip", review.Result{})
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?q=alpha&skill_id="+second.SkillID, "admin")
	combinationOverview(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "value=\"alpha\"") {
		t.Fatalf("expected search query echoed, got %q", body)
	}
	if !strings.Contains(body, first.DisplayName) {
		t.Fatalf("expected matched skill rendered, got %q", body)
	}
	if strings.Contains(body, second.DisplayName) && !strings.Contains(body, "以下列表展示当前纳入组合分析的技能资产") {
		t.Fatalf("expected non-matching option hidden from result list while selection preserved, got %q", body)
	}
	if !strings.Contains(body, "type=\"hidden\" name=\"skill_id\" value=\""+second.SkillID+"\"") {
		t.Fatalf("expected selected skill preserved across search, got %q", body)
	}
	if !strings.Contains(body, second.DisplayName) {
		t.Fatalf("expected selected skill summary still rendered, got %q", body)
	}
	if !strings.Contains(body, "模糊搜索技能 ID、技能名") {
		t.Fatalf("expected advanced search input rendered, got %q", body)
	}
	if strings.Contains(body, "快照 ID") {
		t.Fatalf("expected search-only page with single preserved selection not to create snapshot, got %q", body)
	}
}

func TestAdmissionDetailShowsCombinationEntry(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	skill := createAdmissionTestSkill(t, store, svc, "report-admission-detail-combo", "detail-skill.zip", review.Result{})
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/admission/skills/"+skill.SkillID, "admin")
	admissionDetail(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "进入组合分析") {
		t.Fatalf("expected combination entry rendered, got %q", body)
	}
	if !strings.Contains(body, "/combination/overview?skill_id="+skill.SkillID) {
		t.Fatalf("expected combination link carries skill id, got %q", body)
	}
}

func TestCombinationOverviewSupportsAdvancedFilters(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	matched := createAdmissionTestSkill(t, store, svc, "report-filter-a", "alpha-filter.zip", review.Result{})
	selected := createAdmissionTestSkill(t, store, svc, "report-filter-b", "beta-filter.zip", review.Result{})
	other := createAdmissionTestSkill(t, store, svc, "report-filter-c", "gamma-filter.zip", review.Result{})
	skillStore, err := admissionstore.NewSkillStore(store.DataDir())
	if err != nil {
		t.Fatalf("new skill store: %v", err)
	}

	matched.AdmissionStatus = admissionmodel.AdmissionStatusApproved
	matched.ReviewDecision = admissionmodel.ReviewDecisionPass
	matched.RiskTags = []string{"outbound_network", "credential_access"}
	if err := skillStore.Update(matched); err != nil {
		t.Fatalf("update matched skill: %v", err)
	}

	selected.AdmissionStatus = admissionmodel.AdmissionStatusRejected
	selected.ReviewDecision = admissionmodel.ReviewDecisionBlock
	selected.RiskTags = []string{"persistence"}
	if err := skillStore.Update(selected); err != nil {
		t.Fatalf("update selected skill: %v", err)
	}

	other.AdmissionStatus = admissionmodel.AdmissionStatusPending
	other.ReviewDecision = admissionmodel.ReviewDecisionReview
	other.RiskTags = []string{"outbound_network"}
	if err := skillStore.Update(other); err != nil {
		t.Fatalf("update other skill: %v", err)
	}

	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?q=alpha&status=approved&decision=pass&risk_tag=outbound_network&skill_id="+selected.SkillID, "admin")
	combinationOverview(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, matched.DisplayName) {
		t.Fatalf("expected matched filtered skill rendered, got %q", body)
	}
	if strings.Contains(body, other.DisplayName) {
		t.Fatalf("expected non-matching filtered skill hidden, got %q", body)
	}
	if !strings.Contains(body, "value=\"alpha\"") || !strings.Contains(body, "name=\"risk_tag\" value=\"outbound_network\"") {
		t.Fatalf("expected search inputs preserved, got %q", body)
	}
	if !strings.Contains(body, "<option value=\"approved\" selected") || !strings.Contains(body, "<option value=\"pass\" selected") {
		t.Fatalf("expected filter selects preserved, got %q", body)
	}
	if !strings.Contains(body, "type=\"hidden\" name=\"status\" value=\"approved\"") ||
		!strings.Contains(body, "type=\"hidden\" name=\"decision\" value=\"pass\"") ||
		!strings.Contains(body, "type=\"hidden\" name=\"risk_tag\" value=\"outbound_network\"") {
		t.Fatalf("expected analyze form preserves advanced filters, got %q", body)
	}
	if !strings.Contains(body, "type=\"hidden\" name=\"skill_id\" value=\""+selected.SkillID+"\"") {
		t.Fatalf("expected selected skill preserved across filtered search, got %q", body)
	}
	if !strings.Contains(body, selected.DisplayName) {
		t.Fatalf("expected selected skill tray still rendered, got %q", body)
	}
	if !strings.Contains(body, strings.ReplaceAll(buildCombinationRemoveURL([]string{selected.SkillID}, selected.SkillID, "alpha", "approved", "pass", "outbound_network", ""), "&", "&amp;")) {
		t.Fatalf("expected remove link preserves advanced filters, got %q", body)
	}
}

func TestCombinationOverviewSupportsReportContext(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	skill := createAdmissionTestSkill(t, store, svc, "report-context-a", "context-skill.zip", review.Result{})
	writeReportArtifact(t, store, "report-context-a.json", `{"summary_cn":{"closure_narrative":"待复核项主要缺少source与sink证据。"}}`)
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?report_id=report-context-a", "admin")
	combinationOverview(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, skill.DisplayName) || !strings.Contains(body, skill.SkillID) {
		t.Fatalf("expected report context to preselect imported skill, got %q", body)
	}
	if !strings.Contains(body, "来源报告 report-context-a") {
		t.Fatalf("expected report context summary rendered, got %q", body)
	}
	if !strings.Contains(body, "查看来源报告") || !strings.Contains(body, "/reports/view/report-context-a") {
		t.Fatalf("expected source report view entry rendered, got %q", body)
	}
	if !strings.Contains(body, "/reports/download/report-context-a?format=json") {
		t.Fatalf("expected source report json download entry rendered, got %q", body)
	}
	if !strings.Contains(body, "来源报告闭环摘要：待复核项主要缺少source与sink证据。") {
		t.Fatalf("expected source report decision hint rendered, got %q", body)
	}
	if strings.Contains(body, "快照 ID") {
		t.Fatalf("expected single report context not to create snapshot, got %q", body)
	}
}

func TestCombinationOverviewShowsSelectionTray(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	first := createAdmissionTestSkill(t, store, svc, "report-tray-a", "tray-a.zip", review.Result{})
	second := createAdmissionTestSkill(t, store, svc, "report-tray-b", "tray-b.zip", review.Result{})
	writeReportArtifact(t, store, "report-tray-a.json", `{"summary_cn":{"closure_narrative":"待复核项主要缺少source与runtime证据。"}}`)
	writeReportArtifact(t, store, "report-tray-b.json", `{"summary_cn":{"closure_narrative":"待复核项主要缺少sink与runtime证据。"}}`)
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?q=tray&skill_id="+first.SkillID+"&skill_id="+second.SkillID, "admin")
	combinationOverview(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "清空已选") {
		t.Fatalf("expected clear selection entry rendered, got %q", body)
	}
	if !strings.Contains(body, strings.ReplaceAll(buildCombinationClearSelectionURL("tray", "", "", "", ""), "&", "&amp;")) {
		t.Fatalf("expected clear selection to preserve filters, got %q", body)
	}
	if !strings.Contains(body, strings.ReplaceAll(buildCombinationRemoveURL([]string{first.SkillID, second.SkillID}, first.SkillID, "tray", "", "", "", ""), "&", "&amp;")) {
		t.Fatalf("expected remove link for first skill rendered, got %q", body)
	}
	if !strings.Contains(body, "type=\"hidden\" name=\"q\" value=\"tray\"") {
		t.Fatalf("expected analyze form preserves search query, got %q", body)
	}
	if !strings.Contains(body, "type=\"checkbox\" name=\"skill_id\" value=\""+first.SkillID+"\" checked") {
		t.Fatalf("expected selected checkbox remains checked, got %q", body)
	}
	for _, want := range []string{"闭环摘要：待复核项主要缺少source与runtime证据。", "闭环摘要：待复核项主要缺少sink与runtime证据。"} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected selected skill closure hint rendered %q, got %q", want, body)
		}
	}
}

func createAdmissionTestSkill(t *testing.T, store *storage.Store, svc *admissionservice.AdmissionService, reportID, fileName string, result review.Result) *admissionmodel.AdmissionSkill {
	t.Helper()
	reportsDir := store.ReportsDir()
	jsonName := reportID + ".json"
	jsonPath := filepath.Join(reportsDir, jsonName)
	payload := struct {
		Result review.Result `json:"result"`
	}{Result: result}
	data, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal review result: %v", err)
	}
	if err := os.WriteFile(jsonPath, data, 0644); err != nil {
		t.Fatalf("write review result: %v", err)
	}
	report := &models.Report{
		ID:       reportID,
		TaskID:   "task-" + reportID,
		RequestID: "rid-" + reportID,
		Username: "admin",
		FileName: fileName,
		FilePath: filepath.Join(reportsDir, fileName),
		JSONPath: jsonName,
	}
	if err := store.AddReport(report); err != nil {
		t.Fatalf("add report: %v", err)
	}
	out, err := svc.CreateSkillFromReport(admissionservice.CreateSkillFromReportInput{
		ReportID:        reportID,
		DisplayName:     strings.TrimSuffix(fileName, filepath.Ext(fileName)),
		Description:     "测试技能",
		AdmissionStatus: admissionmodel.AdmissionStatusApproved,
		ReviewDecision:  admissionmodel.ReviewDecisionPass,
		ReviewSummary:   "测试导入",
		Operator:        "admin",
	})
	if err != nil {
		t.Fatalf("create skill from report: %v", err)
	}
	return out.Skill
}

func TestNewAdmissionServiceIncludesUnderlyingStores(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	if svc == nil {
		t.Fatal("expected service instance")
	}
}

func TestCombinationRunsPagesRender(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	first := createAdmissionTestSkill(t, store, svc, "report-runs-a", "skill-a.zip", review.Result{Behavior: review.BehaviorProfile{
		NetworkTargets: []string{"https://example.com/a"},
	}})
	second := createAdmissionTestSkill(t, store, svc, "report-runs-b", "skill-b.zip", review.Result{Behavior: review.BehaviorProfile{
		ExecTargets: []string{"exec.Command"},
	}})
	overviewRec := httptest.NewRecorder()
	overviewReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?skill_id="+first.SkillID+"&skill_id="+second.SkillID, "admin")
	combinationOverview(store).ServeHTTP(overviewRec, overviewReq)
	if overviewRec.Code != http.StatusOK {
		t.Fatalf("expected overview 200, got %d", overviewRec.Code)
	}
	if !strings.Contains(overviewRec.Body.String(), "快照 ID") {
		t.Fatalf("expected run id in overview, got %q", overviewRec.Body.String())
	}
	runsRec := httptest.NewRecorder()
	runsReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs", "admin")
	combinationRuns(store).ServeHTTP(runsRec, runsReq)
	if runsRec.Code != http.StatusOK {
		t.Fatalf("expected runs 200, got %d", runsRec.Code)
	}
	body := runsRec.Body.String()
	if !strings.Contains(body, "历史快照") || !strings.Contains(body, "/combination/runs/") {
		t.Fatalf("expected run list rendered, got %q", body)
	}
	start := strings.Index(body, "/combination/runs/")
	if start < 0 {
		t.Fatalf("expected detail link in %q", body)
	}
	start += len("/combination/runs/")
	end := start
	for end < len(body) {
		ch := body[end]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') {
			break
		}
		end++
	}
	runID := body[start:end]
	if runID == "" {
		t.Fatalf("expected parsed run id from %q", body)
	}
	if !strings.Contains(body, "/combination/overview?run_id="+runID) {
		t.Fatalf("expected overview reload link rendered, got %q", body)
	}
	detailRec := httptest.NewRecorder()
	detailReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs/"+runID, "admin")
	combinationRunDetail(store).ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("expected detail 200, got %d", detailRec.Code)
	}
	detailBody := detailRec.Body.String()
	if !strings.Contains(detailBody, "组合快照详情") || !strings.Contains(detailBody, runID) {
		t.Fatalf("expected run detail rendered, got %q", detailBody)
	}
	if !strings.Contains(detailBody, "闭环摘要 ") {
		t.Fatalf("expected run detail closure narrative rendered, got %q", detailBody)
	}
	if !strings.Contains(detailBody, first.DisplayName+" ("+first.SkillID+")") || !strings.Contains(detailBody, second.DisplayName+" ("+second.SkillID+")") {
		t.Fatalf("expected selected skill display names rendered, got %q", detailBody)
	}
	if !strings.Contains(detailBody, "重新载入该组合") {
		t.Fatalf("expected overview reload action rendered, got %q", detailBody)
	}
	if !strings.Contains(detailBody, "展开 diagnostics JSON") || !strings.Contains(detailBody, "ti_target_count") {
		t.Fatalf("expected diagnostics json block rendered, got %q", detailBody)
	}
	if !strings.Contains(detailBody, "聚合残余风险") {
		t.Fatalf("expected risk section rendered, got %q", detailBody)
	}
}

func TestCombinationOverviewSupportsRunID(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	first := createAdmissionTestSkill(t, store, svc, "report-runid-a", "skill-a.zip", review.Result{Behavior: review.BehaviorProfile{
		NetworkTargets: []string{"https://example.com/a"},
	}})
	second := createAdmissionTestSkill(t, store, svc, "report-runid-b", "skill-b.zip", review.Result{Behavior: review.BehaviorProfile{
		ExecTargets: []string{"exec.Command"},
	}})
	seedRec := httptest.NewRecorder()
	seedReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?skill_id="+first.SkillID+"&skill_id="+second.SkillID, "admin")
	combinationOverview(store).ServeHTTP(seedRec, seedReq)
	if seedRec.Code != http.StatusOK {
		t.Fatalf("expected seed overview 200, got %d", seedRec.Code)
	}
	body := seedRec.Body.String()
	marker := "快照 ID "
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("expected run id marker in %q", body)
	}
	start := idx + len(marker)
	end := start
	for end < len(body) {
		ch := body[end]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') {
			break
		}
		end++
	}
	runID := body[start:end]
	if runID == "" {
		t.Fatalf("expected parsed run id from %q", body)
	}
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?run_id="+runID, "admin")
	combinationOverview(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected overview by run_id 200, got %d", rec.Code)
	}
	rendered := rec.Body.String()
	if !strings.Contains(rendered, first.DisplayName) || !strings.Contains(rendered, second.DisplayName) {
		t.Fatalf("expected run_id overview to restore skills, got %q", rendered)
	}
	if !strings.Contains(rendered, "快照 ID "+runID) {
		t.Fatalf("expected same run id rendered, got %q", rendered)
	}
}

func TestDownloadCombinationRunExports(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	first := createAdmissionTestSkill(t, store, svc, "report-export-a", "skill-a.zip", review.Result{Behavior: review.BehaviorProfile{
		NetworkTargets: []string{"https://example.com/a"},
		CredentialIOCs: []string{"/root/.netrc"},
	}})
	second := createAdmissionTestSkill(t, store, svc, "report-export-b", "skill-b.zip", review.Result{Behavior: review.BehaviorProfile{
		ExecTargets: []string{"exec.Command"},
	}})
	overviewRec := httptest.NewRecorder()
	overviewReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?skill_id="+first.SkillID+"&skill_id="+second.SkillID, "admin")
	combinationOverview(store).ServeHTTP(overviewRec, overviewReq)
	if overviewRec.Code != http.StatusOK {
		t.Fatalf("expected overview 200, got %d", overviewRec.Code)
	}
	body := overviewRec.Body.String()
	marker := "快照 ID "
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("expected run id marker in %q", body)
	}
	start := idx + len(marker)
	end := start
	for end < len(body) {
		ch := body[end]
		if (ch < '0' || ch > '9') && (ch < 'a' || ch > 'z') && (ch < 'A' || ch > 'Z') {
			break
		}
		end++
	}
	runID := body[start:end]
	if runID == "" {
		t.Fatalf("expected parsed run id from %q", body)
	}
	jsonRec := httptest.NewRecorder()
	jsonReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs/export/"+runID+".json", "admin")
	downloadCombinationRun(store).ServeHTTP(jsonRec, jsonReq)
	if jsonRec.Code != http.StatusOK {
		t.Fatalf("expected json export 200, got %d", jsonRec.Code)
	}
	if got := jsonRec.Header().Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected json content type, got %q", got)
	}
	if got := jsonRec.Header().Get("Content-Disposition"); !strings.Contains(got, strconv.Quote("combination-run-"+runID+".json")) {
		t.Fatalf("expected json attachment filename, got %q", got)
	}
	var exported struct {
		RunID                string   `json:"run_id"`
		SelectedSkills       []string `json:"selected_skills"`
		Diagnostics          struct {
			ClosureNarrative  string `json:"closure_narrative"`
			RuleConfigWarnLevel string `json:"rule_config_warn_level"`
			TITargetCount       int    `json:"ti_target_count"`
			TISuspiciousCount   int    `json:"ti_suspicious_count"`
		} `json:"diagnostics"`
		SelectedSkillDetails []struct {
			SkillID     string `json:"skill_id"`
			DisplayName string `json:"display_name"`
		} `json:"selected_skill_details"`
	}
	if err := json.Unmarshal(jsonRec.Body.Bytes(), &exported); err != nil {
		t.Fatalf("unmarshal exported json: %v", err)
	}
	if exported.RunID != runID {
		t.Fatalf("expected exported run id %q, got %+v", runID, exported)
	}
	if len(exported.SelectedSkills) != 2 || len(exported.SelectedSkillDetails) != 2 {
		t.Fatalf("expected enriched selected skills, got %+v", exported)
	}
	if exported.Diagnostics.TITargetCount == 0 {
		t.Fatalf("expected diagnostics ti target count populated, got %+v", exported.Diagnostics)
	}
	if strings.TrimSpace(exported.Diagnostics.ClosureNarrative) == "" {
		t.Fatalf("expected diagnostics closure narrative populated, got %+v", exported.Diagnostics)
	}
	if lvl := strings.TrimSpace(exported.Diagnostics.RuleConfigWarnLevel); lvl != "" && lvl != "warning" && lvl != "error" {
		t.Fatalf("expected known warning level, got %+v", exported.Diagnostics)
	}
	if exported.SelectedSkillDetails[0].DisplayName == "" || exported.SelectedSkillDetails[0].SkillID == "" {
		t.Fatalf("expected skill detail fields populated, got %+v", exported.SelectedSkillDetails)
	}
	mdRec := httptest.NewRecorder()
	mdReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs/export/"+runID+".md", "admin")
	downloadCombinationRun(store).ServeHTTP(mdRec, mdReq)
	if mdRec.Code != http.StatusOK {
		t.Fatalf("expected markdown export 200, got %d", mdRec.Code)
	}
	if got := mdRec.Header().Get("Content-Type"); got != "text/markdown; charset=utf-8" {
		t.Fatalf("expected markdown content type, got %q", got)
	}
	mdBody := mdRec.Body.String()
	if !strings.Contains(mdBody, "# 组合快照") || !strings.Contains(mdBody, runID) || !strings.Contains(mdBody, first.DisplayName+" (`"+first.SkillID+"`)") || !strings.Contains(mdBody, second.DisplayName+" (`"+second.SkillID+"`)") {
		t.Fatalf("expected markdown export body rendered, got %q", mdBody)
	}
	if !strings.Contains(mdBody, "- 闭环摘要: ") {
		t.Fatalf("expected markdown export closure narrative rendered, got %q", mdBody)
	}
}

func TestCombinationRunsFilters(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	first := createAdmissionTestSkill(t, store, svc, "report-filter-a", "skill-a.zip", review.Result{Behavior: review.BehaviorProfile{
		NetworkTargets: []string{"https://example.com/a"},
		CredentialIOCs: []string{"/root/.netrc"},
	}})
	second := createAdmissionTestSkill(t, store, svc, "report-filter-b", "skill-b.zip", review.Result{Behavior: review.BehaviorProfile{
		ExecTargets: []string{"exec.Command"},
	}})
	third := createAdmissionTestSkill(t, store, svc, "report-filter-c", "skill-c.zip", review.Result{Behavior: review.BehaviorProfile{
		FileTargets: []string{"/tmp/output.txt"},
	}})
	combinationOverview(store).ServeHTTP(httptest.NewRecorder(), newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?skill_id="+first.SkillID+"&skill_id="+second.SkillID, "admin"))
	combinationOverview(store).ServeHTTP(httptest.NewRecorder(), newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?skill_id="+third.SkillID, "admin"))
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs?risk_level=high&q=command_exec", "admin")
	combinationRuns(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected filtered runs 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "value=\"command_exec\"") {
		t.Fatalf("expected query echoed in filter form, got %q", body)
	}
	if !strings.Contains(body, "value=\"high\" selected") {
		t.Fatalf("expected risk level selected in filter form, got %q", body)
	}
	if !strings.Contains(body, "command_exec") || !strings.Contains(body, "已选技能 2") || !strings.Contains(body, "重新载入该组合") {
		t.Fatalf("expected matching run rendered, got %q", body)
	}
	if strings.Contains(body, third.SkillID) {
		t.Fatalf("expected non-matching run filtered out, got %q", body)
	}

	testStore, err := combinationservice.NewStore(store.DataDir())
	if err != nil {
		t.Fatalf("new combination store: %v", err)
	}
	errRun := &combinationservice.RunRecord{
		RunID:          "run-rule-error",
		SelectionKey:   "sel-rule-error",
		SelectedSkills: []string{third.SkillID},
		Overview: combinationservice.RunOverview{
			RiskLevel:            "medium",
			RiskLabel:            "中风险",
			RuleConfigWarning:    "open config failed",
			RuleConfigWarnLevel:  "error",
			Capabilities:         []string{"file_read"},
			CombinedTags:         []string{"filesystem"},
			TISuspiciousCount:    0,
			TIThreatCount:        0,
		},
		CreatedAt: time.Date(2026, 5, 6, 10, 0, 0, 0, time.UTC).Unix(),
		UpdatedAt: time.Date(2026, 5, 6, 10, 0, 0, 0, time.UTC).Unix(),
	}
	if err := testStore.Save(errRun); err != nil {
		t.Fatalf("save error run: %v", err)
	}
	runs, err := testStore.List()
	if err != nil {
		t.Fatalf("list runs: %v", err)
	}
	if len(runs) < 1 {
		t.Fatalf("expected at least one run, got %d", len(runs))
	}
	runs[0].Overview.RuleConfigWarning = "partial parse warning"
	runs[0].Overview.RuleConfigWarnLevel = "warning"
	if err := testStore.Save(runs[0]); err != nil {
		t.Fatalf("save warning run: %v", err)
	}

	warnRec := httptest.NewRecorder()
	warnReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs?rule_warn_level=warning", "admin")
	combinationRuns(store).ServeHTTP(warnRec, warnReq)
	if warnRec.Code != http.StatusOK {
		t.Fatalf("expected warning filtered runs 200, got %d", warnRec.Code)
	}
	warnBody := warnRec.Body.String()
	if !strings.Contains(warnBody, "value=\"warning\" selected") {
		t.Fatalf("expected warning selected in filter form, got %q", warnBody)
	}
	if !strings.Contains(warnBody, "复制筛选链接") {
		t.Fatalf("expected share filter link button rendered, got %q", warnBody)
	}
	if !strings.Contains(warnBody, "当前筛选链接") {
		t.Fatalf("expected share filter url rendered, got %q", warnBody)
	}
	if !strings.Contains(warnBody, "back=%2Fcombination%2Fruns%3F") || !strings.Contains(warnBody, "rule_warn_level%3Dwarning") {
		t.Fatalf("expected detail link carry warning back query, got %q", warnBody)
	}
	if !strings.Contains(warnBody, "规则告警 warning") {
		t.Fatalf("expected warning run rendered, got %q", warnBody)
	}
	if strings.Contains(warnBody, "规则告警 error") {
		t.Fatalf("expected error run filtered out in warning filter, got %q", warnBody)
	}

	noneRec := httptest.NewRecorder()
	noneReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs?rule_warn_level=none", "admin")
	combinationRuns(store).ServeHTTP(noneRec, noneReq)
	if noneRec.Code != http.StatusOK {
		t.Fatalf("expected none filtered runs 200, got %d", noneRec.Code)
	}
	noneBody := noneRec.Body.String()
	if !strings.Contains(noneBody, "value=\"none\" selected") {
		t.Fatalf("expected none selected in filter form, got %q", noneBody)
	}
	if strings.Contains(noneBody, "规则告警 warning") || strings.Contains(noneBody, "规则告警 error") {
		t.Fatalf("expected warning and error runs filtered out in none filter, got %q", noneBody)
	}
}

func TestCombinationRunsSupportDateRangeAndSort(t *testing.T) {
	store := newTestStore(t)
	combinationStore, err := combinationservice.NewStore(store.DataDir())
	if err != nil {
		t.Fatalf("new combination store: %v", err)
	}
	older := &combinationservice.RunRecord{
		RunID:          "run-older",
		SelectionKey:   "sel-older",
		SelectedSkills: []string{"skill-a"},
		Overview: combinationservice.RunOverview{
			RiskLevel:    "low",
			RiskLabel:    "低风险",
			Capabilities: []string{"file_read"},
			CombinedTags: []string{"filesystem"},
		},
		CreatedAt: time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC).Unix(),
		UpdatedAt: time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC).Unix(),
	}
	newer := &combinationservice.RunRecord{
		RunID:          "run-newer",
		SelectionKey:   "sel-newer",
		SelectedSkills: []string{"skill-b", "skill-c"},
		Overview: combinationservice.RunOverview{
			RiskLevel:    "high",
			RiskLabel:    "高风险",
			Capabilities: []string{"command_exec"},
			CombinedTags: []string{"command_execution"},
		},
		CreatedAt: time.Date(2026, 5, 3, 18, 0, 0, 0, time.UTC).Unix(),
		UpdatedAt: time.Date(2026, 5, 3, 18, 0, 0, 0, time.UTC).Unix(),
	}
	if err := combinationStore.Save(older); err != nil {
		t.Fatalf("save older run: %v", err)
	}
	if err := combinationStore.Save(newer); err != nil {
		t.Fatalf("save newer run: %v", err)
	}
	rec := httptest.NewRecorder()
	req := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs?start_date=2026-05-02&end_date=2026-05-03&sort=updated_asc", "admin")
	combinationRuns(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected filtered runs 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "value=\"2026-05-02\"") || !strings.Contains(body, "value=\"2026-05-03\"") {
		t.Fatalf("expected date filters echoed in form, got %q", body)
	}
	if !strings.Contains(body, "value=\"updated_asc\" selected") {
		t.Fatalf("expected sort selected in form, got %q", body)
	}
	if strings.Contains(body, "run-older") {
		t.Fatalf("expected out-of-range run filtered out, got %q", body)
	}
	if !strings.Contains(body, "run-newer") {
		t.Fatalf("expected in-range run rendered, got %q", body)
	}

	ascRec := httptest.NewRecorder()
	ascReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs?sort=updated_asc", "admin")
	combinationRuns(store).ServeHTTP(ascRec, ascReq)
	if ascRec.Code != http.StatusOK {
		t.Fatalf("expected asc runs 200, got %d", ascRec.Code)
	}
	ascBody := ascRec.Body.String()
	olderIdx := strings.Index(ascBody, "run-older")
	newerIdx := strings.Index(ascBody, "run-newer")
	if olderIdx < 0 || newerIdx < 0 || olderIdx > newerIdx {
		t.Fatalf("expected ascending order by updated time, got %q", ascBody)
	}

	badRec := httptest.NewRecorder()
	badReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs?start_date=bad-date", "admin")
	combinationRuns(store).ServeHTTP(badRec, badReq)
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected bad request for invalid date, got %d", badRec.Code)
	}
}

func TestNormalizeCombinationRunRuleWarnLevel(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "warning", raw: "warning", want: "warning"},
		{name: "error upper", raw: " ERROR ", want: "error"},
		{name: "none", raw: "none", want: "none"},
		{name: "invalid", raw: "critical", want: ""},
		{name: "empty", raw: "", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeCombinationRunRuleWarnLevel(tt.raw); got != tt.want {
				t.Fatalf("normalizeCombinationRunRuleWarnLevel(%q)=%q want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestNormalizeCombinationRunsBackURL(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{name: "valid runs base", raw: "/combination/runs", want: "/combination/runs"},
		{name: "valid runs query", raw: "/combination/runs?risk_level=high", want: "/combination/runs?risk_level=high"},
		{name: "trim space", raw: " /combination/runs?sort=updated_asc ", want: "/combination/runs?sort=updated_asc"},
		{name: "empty", raw: "", want: ""},
		{name: "external", raw: "https://example.com/evil", want: ""},
		{name: "other route", raw: "/login", want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeCombinationRunsBackURL(tt.raw); got != tt.want {
				t.Fatalf("normalizeCombinationRunsBackURL(%q)=%q want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestBuildCombinationRunDetailURL(t *testing.T) {
	tests := []struct {
		name   string
		runID  string
		params map[string]string
		checks []string
	}{
		{
			name:  "empty run id",
			runID: "",
			params: map[string]string{
				"risk_level": "high",
			},
			checks: []string{"/combination/runs"},
		},
		{
			name:  "no filters",
			runID: "run-1",
			checks: []string{"/combination/runs/run-1"},
		},
		{
			name:  "with filters",
			runID: "run-2",
			params: map[string]string{
				"risk_level":      "high",
				"ti_risk":         "suspicious",
				"rule_warn_level": "warning",
			},
			checks: []string{"/combination/runs/run-2?back=%2Fcombination%2Fruns%3F", "risk_level%3Dhigh", "ti_risk%3Dsuspicious", "rule_warn_level%3Dwarning"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCombinationRunDetailURL(tt.runID, tt.params)
			for _, check := range tt.checks {
				if !strings.Contains(got, check) {
					t.Fatalf("buildCombinationRunDetailURL()=%q missing %q", got, check)
				}
			}
		})
	}
}

func TestCombinationRunDetailBackLink(t *testing.T) {
	store := newTestStore(t)
	svc, err := newAdmissionService(store)
	if err != nil {
		t.Fatalf("new admission service: %v", err)
	}
	first := createAdmissionTestSkill(t, store, svc, "report-back-a", "skill-a.zip", review.Result{Behavior: review.BehaviorProfile{
		NetworkTargets: []string{"https://example.com/a"},
	}})
	second := createAdmissionTestSkill(t, store, svc, "report-back-b", "skill-b.zip", review.Result{Behavior: review.BehaviorProfile{
		ExecTargets: []string{"exec.Command"},
	}})
	seedRec := httptest.NewRecorder()
	seedReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/overview?skill_id="+first.SkillID+"&skill_id="+second.SkillID, "admin")
	combinationOverview(store).ServeHTTP(seedRec, seedReq)
	if seedRec.Code != http.StatusOK {
		t.Fatalf("expected seed overview 200, got %d", seedRec.Code)
	}
	body := seedRec.Body.String()
	marker := "快照 ID "
	idx := strings.Index(body, marker)
	if idx < 0 {
		t.Fatalf("expected run id marker in overview body, got %q", body)
	}
	start := idx + len(marker)
	end := start
	for end < len(body) {
		ch := body[end]
		if (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') {
			end++
			continue
		}
		break
	}
	runID := body[start:end]
	if runID == "" {
		t.Fatalf("expected run id parsed from overview body, got %q", body)
	}

	back := "/combination/runs?risk_level=high&rule_warn_level=warning"
	detailRec := httptest.NewRecorder()
	detailReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs/"+runID+"?back="+url.QueryEscape(back), "admin")
	combinationRunDetail(store).ServeHTTP(detailRec, detailReq)
	if detailRec.Code != http.StatusOK {
		t.Fatalf("expected detail 200, got %d", detailRec.Code)
	}
	detailBody := detailRec.Body.String()
	if !strings.Contains(detailBody, "href=\"/combination/runs?risk_level=high&amp;rule_warn_level=warning\"") {
		t.Fatalf("expected back link preserved in detail page, got %q", detailBody)
	}

	invalidRec := httptest.NewRecorder()
	invalidReq := newAuthenticatedRequest(t, http.MethodGet, "/combination/runs/"+runID+"?back="+url.QueryEscape("https://example.com/evil"), "admin")
	combinationRunDetail(store).ServeHTTP(invalidRec, invalidReq)
	if invalidRec.Code != http.StatusOK {
		t.Fatalf("expected detail 200 for invalid back fallback, got %d", invalidRec.Code)
	}
	invalidBody := invalidRec.Body.String()
	if !strings.Contains(invalidBody, "href=\"/combination/runs\"") {
		t.Fatalf("expected invalid back fallback to runs root, got %q", invalidBody)
	}
}

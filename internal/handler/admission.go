package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	admissionmodel "skill-scanner/internal/admission/model"
	admissionservice "skill-scanner/internal/admission/service"
	admissionstore "skill-scanner/internal/admission/store"
	combinationservice "skill-scanner/internal/combination"
	"skill-scanner/internal/models"
	platformid "skill-scanner/internal/platform/id"
	"skill-scanner/internal/storage"
)

type admissionListEntry struct {
	SkillID         string
	DisplayName     string
	Name            string
	Version         string
	AdmissionStatus string
	ReviewDecision  string
	DecisionHint    string
	RiskTags        []string
	UpdatedAt       string
	ReportID        string
	AddToComboURL   string
	RemoveComboURL  string
}

type admissionListPageData struct {
	Username        string
	Items           []admissionListEntry
	Query           string
	AdmissionStatus string
	ReviewDecision  string
	RiskTag         string
	HasPersonal     bool
	HasUserMgmt     bool
	HasLogPerm      bool
	ModelStatus     string
	ModelError      bool
	ModelErrMsg     string
}

type admissionImportPageData struct {
	Username    string
	ReportID    string
	FileName    string
	DefaultName string
	DefaultDesc string
	Error       string
	HasPersonal bool
	HasUserMgmt bool
	HasLogPerm  bool
	ModelStatus string
	ModelError  bool
	ModelErrMsg string
}

type admissionEditPageData struct {
	Username        string
	SkillID         string
	FileName        string
	DisplayName     string
	Version         string
	Description     string
	AdmissionStatus string
	ReviewDecision  string
	ReviewSummary   string
	WorkflowStage   string
	VerificationRequired bool
	WorkflowStageLabel string
	LastFixAt       string
	LastVerifiedAt  string
	EnforceVerifyWarning string
	Error           string
	HasPersonal     bool
	HasUserMgmt     bool
	HasLogPerm      bool
	ModelStatus     string
	ModelError      bool
	ModelErrMsg     string
}

type combinationSkillEntry struct {
	SkillID         string
	DisplayName     string
	Version         string
	AdmissionStatus string
	ReviewDecision  string
	Selected        bool
}

type combinationPageData struct {
	Username          string
	Items             []combinationSkillEntry
	SourceReport      *combinationSourceReportContext
	SearchQuery       string
	AdmissionStatus   string
	ReviewDecision    string
	RiskTag           string
	SearchURL         string
	AnalyzeURL        string
	ClearSelectionURL string
	SelectedSkills    []admissionListEntry
	RunID             string
	SavedAt           string
	HistoryURL        string
	CombinedProfile   *admissionmodel.CapabilityProfile
	CombinedRisks     []combinationservice.CombinedRisk
	CombinedTags      []string
	CapabilitySummary []string
	InferredChains    []combinationservice.InferredChain
	Conclusion        combinationservice.Conclusion
	HasPersonal       bool
	HasUserMgmt       bool
	HasLogPerm        bool
	ModelStatus       string
	ModelError        bool
	ModelErrMsg       string
}

type combinationSourceReportContext struct {
	ReportID      string
	TaskID        string
	RequestID     string
	FileName      string
	ReportURL     string
	DownloadURL string
	DecisionHint  string
}

type combinationRunListEntry struct {
	RunID              string
	SelectedSkillCount int
	RiskLabel          string
	RiskLevel          string
	RuleConfigWarning  string
	RuleConfigWarnLevel string
	TIThreatCount      int
	TISuspiciousCount  int
	Capabilities       []string
	CombinedTags       []string
	UpdatedAt          string
	UpdatedAtUnix      int64
	DetailURL          string
	OverviewURL        string
	RuleCoverageHint   string
}

type combinationRunsPageData struct {
	Username    string
	Items       []combinationRunListEntry
	Query       string
	RiskLevel   string
	TIRisk      string
	RuleWarnLevel string
	StartDate   string
	EndDate     string
	Sort        string
	RuleCoverageTop []ruleCoverageStatView
	DeadRulesCount int
	DeadRulesPreview []string
	HasPersonal bool
	HasUserMgmt bool
	HasLogPerm  bool
	ModelStatus string
	ModelError  bool
	ModelErrMsg string
}

type ruleCoverageStatView struct {
	RuleID string
	Count int
	Coverage string
}

type combinationRunDetailPageData struct {
	Username          string
	RunID             string
	HistoryURL        string
	SelectedSkills    []admissionListEntry
	SavedAt           string
	UpdatedAt         string
	ExportJSONURL     string
	ExportMarkdownURL string
	OverviewURL       string
	RiskLabel         string
	RiskLevel         string
	ClosureNarrative  string
	Recommendation    string
	RuleConfigWarning string
	RuleConfigWarnLevel string
	RuleConfigVersion string
	RuleConfigRevision string
	RuleContentHash string
	RuleSourcePath string
	Capabilities      []string
	CombinedTags      []string
	TITargetCount     int
	TIThreatCount     int
	TISuspiciousCount int
	TIAdjustmentScore float64
	DiagnosticsJSON   string
	CombinedRisks     []combinationservice.StoredRisk
	InferredChains    []combinationservice.StoredChain
	HasPersonal       bool
	HasUserMgmt       bool
	HasLogPerm        bool
	ModelStatus       string
	ModelError        bool
	ModelErrMsg       string
}

type combinationRunExport struct {
	RunID                string                `json:"run_id"`
	SelectionKey         string                `json:"selection_key"`
	SelectedSkills       []string              `json:"selected_skills"`
	SelectedSkillDetails []combinationSkillRef `json:"selected_skill_details"`
	Overview             interface{}           `json:"overview"`
	Diagnostics          combinationDiagnostics `json:"diagnostics"`
	CreatedAt            int64                 `json:"created_at"`
	UpdatedAt            int64                 `json:"updated_at"`
}

type combinationDiagnostics struct {
	ClosureNarrative  string  `json:"closure_narrative,omitempty"`
	RuleConfigWarning   string  `json:"rule_config_warning,omitempty"`
	RuleConfigWarnLevel string  `json:"rule_config_warn_level,omitempty"`
	RuleConfigVersion   string  `json:"rule_config_version,omitempty"`
	RuleConfigRevision  string  `json:"rule_config_revision,omitempty"`
	RuleContentHash     string  `json:"rule_content_hash,omitempty"`
	RuleSourcePath      string  `json:"rule_source_path,omitempty"`
	TITargetCount       int     `json:"ti_target_count,omitempty"`
	TIThreatCount       int     `json:"ti_threat_count,omitempty"`
	TISuspiciousCount   int     `json:"ti_suspicious_count,omitempty"`
	TIAdjustmentScore   float64 `json:"ti_adjustment_score,omitempty"`
}

type combinationSkillRef struct {
	SkillID         string `json:"skill_id"`
	DisplayName     string `json:"display_name"`
	Version         string `json:"version,omitempty"`
	AdmissionStatus string `json:"admission_status,omitempty"`
	ReviewDecision  string `json:"review_decision,omitempty"`
}

func normalizeWorkflowStage(stage string) string {
	stage = strings.ToLower(strings.TrimSpace(stage))
	switch stage {
	case "pending_verification", "verified":
		return stage
	default:
		return "verified"
	}
}

func localizeWorkflowStage(stage string) string {
	switch normalizeWorkflowStage(stage) {
	case "pending_verification":
		return "待验证"
	default:
		return "已验证"
	}
}

func summarizeRuleCoverage(runs []*combinationservice.RunRecord) (map[string]int, int) {
	out := map[string]int{}
	base := 0
	for _, run := range runs {
		if run == nil {
			continue
		}
		base++
		seen := map[string]struct{}{}
		for _, chain := range run.Overview.InferredChains {
			id := strings.TrimSpace(chain.ID)
			if id == "" {
				continue
			}
			if strings.HasPrefix(id, "adaptive-") || strings.HasPrefix(id, "semantic-") {
				continue
			}
			seen[id] = struct{}{}
		}
		for id := range seen {
			out[id]++
		}
	}
	return out, base
}

func countRisksByLevel(risks []admissionmodel.ResidualRisk) (high, med, low int) {
	for _, risk := range risks {
		switch strings.ToLower(strings.TrimSpace(risk.Level)) {
		case "high":
			high++
		case "medium":
			med++
		default:
			low++
		}
	}
	return high, med, low
}

func extractRunRuleIDs(run *combinationservice.RunRecord) []string {
	if run == nil {
		return nil
	}
	out := make([]string, 0, len(run.Overview.InferredChains))
	for _, item := range run.Overview.InferredChains {
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		if strings.HasPrefix(id, "adaptive-") || strings.HasPrefix(id, "semantic-") {
			continue
		}
		out = append(out, id)
	}
	return normalizeRuleIDList(out)
}

func extractRunRuleDisplayNames(run *combinationservice.RunRecord) []string {
	ids := extractRunRuleIDs(run)
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		out = append(out, displayRuleName(id))
	}
	return out
}

func normalizeRuleIDList(items []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.TrimSpace(item)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func limitStrings(items []string, max int) []string {
	if max <= 0 || len(items) <= max {
		return append([]string(nil), items...)
	}
	return append([]string(nil), items[:max]...)
}

func admissionList(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		svc, err := newAdmissionService(store)
		if err != nil {
			http.Error(w, "加载准入技能库失败", http.StatusInternalServerError)
			return
		}
		items, err := svc.ListSkills(strings.TrimSpace(r.URL.Query().Get("q")), 100)
		if err != nil {
			http.Error(w, "加载准入技能库失败", http.StatusInternalServerError)
			return
		}
		statusFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
		decisionFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("decision")))
		riskTagFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("risk_tag")))
		entries := make([]admissionListEntry, 0, len(items))
		for _, item := range items {
			if item == nil {
				continue
			}
			if statusFilter != "" && strings.ToLower(string(item.AdmissionStatus)) != statusFilter {
				continue
			}
			if decisionFilter != "" && strings.ToLower(string(item.ReviewDecision)) != decisionFilter {
				continue
			}
			if riskTagFilter != "" && !containsNormalized(item.RiskTags, riskTagFilter) {
				continue
			}
			entries = append(entries, admissionListEntry{
				SkillID:         item.SkillID,
				DisplayName:     defaultIfEmpty(item.DisplayName, item.Name),
				Name:            item.Name,
				Version:         defaultIfEmpty(item.Version, "-"),
				AdmissionStatus: string(item.AdmissionStatus),
				ReviewDecision:  localizeDecisionLabel(string(item.ReviewDecision)),
				RiskTags:        append([]string(nil), item.RiskTags...),
				UpdatedAt:       formatUnixTime(item.UpdatedAt),
				ReportID:        item.ReportID,
				AddToComboURL:   buildCombinationAddURL(nil, item.SkillID),
			})
		}
		modelStatus, modelError, modelErrMsg := GetModelStatus()
		render(w, tmplAdmissionList, admissionListPageData{
			Username:        sess.Username,
			Items:           entries,
			Query:           strings.TrimSpace(r.URL.Query().Get("q")),
			AdmissionStatus: statusFilter,
			ReviewDecision:  decisionFilter,
			RiskTag:         riskTagFilter,
			HasPersonal:     user.HasPermission(models.PermPersonalCenter),
			HasUserMgmt:     user.HasPermission(models.PermUserManagement),
			HasLogPerm:      user.HasPermission(models.PermLoginLog),
			ModelStatus:     modelStatus,
			ModelError:      modelError,
			ModelErrMsg:     modelErrMsg,
		})
	}
}

func admissionDetail(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		skillID := strings.TrimSpace(filepath.Base(r.URL.Path))
		if skillID == "" || skillID == "/" || skillID == "skills" || skillID == "." {
			http.Error(w, "技能不存在", http.StatusNotFound)
			return
		}
		svc, err := newAdmissionService(store)
		if err != nil {
			http.Error(w, "加载准入技能失败", http.StatusInternalServerError)
			return
		}
		detail, err := svc.GetSkillDetail(skillID)
		if err != nil {
			http.Error(w, "技能不存在", http.StatusNotFound)
			return
		}
		type reviewRecordView struct {
			Reviewer  string
			Decision  string
			Summary   string
			CreatedAt string
			HighRisk  int
			MedRisk   int
			LowRisk   int
			TotalRisk int
			DeltaText string
		}
		type riskHistorySummary struct {
			HasHistory      bool
			LatestTotalRisk int
			BaselineTotalRisk int
			TrendText       string
			LatestHigh      int
			LatestMed       int
			LatestLow       int
		}
		sort.SliceStable(detail.ReviewRecords, func(i, j int) bool {
			left, right := detail.ReviewRecords[i], detail.ReviewRecords[j]
			if left == nil {
				return false
			}
			if right == nil {
				return true
			}
			return left.CreatedAt < right.CreatedAt
		})
		records := make([]reviewRecordView, 0, len(detail.ReviewRecords))
		totals := make([]int, 0, len(detail.ReviewRecords))
		for _, item := range detail.ReviewRecords {
			if item == nil {
				continue
			}
			high, med, low := 0, 0, 0
			for _, risk := range item.ResidualRisks {
				switch strings.ToLower(strings.TrimSpace(risk.Level)) {
				case "high":
					high++
				case "medium":
					med++
				default:
					low++
				}
			}
			total := high + med + low
			deltaText := "首次基线"
			if len(totals) > 0 {
				delta := total - totals[len(totals)-1]
				switch {
				case delta > 0:
					deltaText = "较上次 +" + strconv.Itoa(delta)
				case delta < 0:
					deltaText = "较上次 " + strconv.Itoa(delta)
				default:
					deltaText = "较上次 持平"
				}
			}
			totals = append(totals, total)
			records = append(records, reviewRecordView{
				Reviewer:  item.Reviewer,
				Decision:  localizeDecisionLabel(string(item.Decision)),
				Summary:   item.Summary,
				CreatedAt: formatUnixTime(item.CreatedAt),
				HighRisk:  high,
				MedRisk:   med,
				LowRisk:   low,
				TotalRisk: total,
				DeltaText: deltaText,
			})
		}
		historySummary := riskHistorySummary{}
		autoVerifyReady := false
		autoVerifyResult := "尚未触发自动复测验证"
		if len(totals) > 0 {
			historySummary.HasHistory = true
			historySummary.BaselineTotalRisk = totals[0]
			historySummary.LatestTotalRisk = totals[len(totals)-1]
			if len(records) > 0 {
				last := records[len(records)-1]
				historySummary.LatestHigh = last.HighRisk
				historySummary.LatestMed = last.MedRisk
				historySummary.LatestLow = last.LowRisk
			}
			delta := historySummary.LatestTotalRisk - historySummary.BaselineTotalRisk
			switch {
			case delta > 0:
				historySummary.TrendText = "风险较初次上升 +" + strconv.Itoa(delta)
			case delta < 0:
				historySummary.TrendText = "风险较初次下降 " + strconv.Itoa(delta)
			default:
				historySummary.TrendText = "风险较初次持平"
			}
			if len(totals) >= 2 && detail.Skill.VerificationRequired {
				prev := totals[len(totals)-2]
				curr := totals[len(totals)-1]
				if curr <= prev {
					autoVerifyReady = true
					autoVerifyResult = "自动验证通过：最近一次风险总数未上升，可执行“完成复测验证”"
				} else {
					autoVerifyReady = false
					autoVerifyResult = "自动验证未通过：最近一次风险总数上升，建议继续修复后复测"
				}
			}
		}
		modelStatus, modelError, modelErrMsg := GetModelStatus()
		render(w, tmplAdmissionDetail, map[string]interface{}{
			"Username":      sess.Username,
			"Skill":         detail.Skill,
			"Profile":       detail.Profile,
			"Risks":         detail.Risks,
			"CombinationURL": "/combination/overview?skill_id=" + detail.Skill.SkillID,
			"ReviewRecords": records,
			"RiskHistory":   historySummary,
			"WorkflowStageLabel": localizeWorkflowStage(detail.Skill.WorkflowStage),
			"WorkflowStage": normalizeWorkflowStage(detail.Skill.WorkflowStage),
			"VerificationRequired": detail.Skill.VerificationRequired,
			"LastFixAt": formatUnixTime(detail.Skill.LastFixAt),
			"LastVerifiedAt": formatUnixTime(detail.Skill.LastVerifiedAt),
			"AutoVerifyReady": autoVerifyReady,
			"AutoVerifyResult": autoVerifyResult,
			"IsAdmin":       user.Role == models.RoleAdmin,
			"HasPersonal":   user.HasPermission(models.PermPersonalCenter),
			"HasUserMgmt":   user.HasPermission(models.PermUserManagement),
			"HasLogPerm":    user.HasPermission(models.PermLoginLog),
			"ModelStatus":   modelStatus,
			"ModelError":    modelError,
			"ModelErrMsg":   modelErrMsg,
		})
	}
}

func admissionImport(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		reportID := strings.TrimSpace(filepath.Base(r.URL.Path))
		if reportID == "" || reportID == "/" || reportID == "." {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}
		rep := store.GetReport(reportID)
		if rep == nil {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}
		if !store.CanAccessReport(sess.Username, reportID) {
			http.Error(w, "无权访问此报告", http.StatusForbidden)
			return
		}
		defaultName := strings.TrimSuffix(filepath.Base(rep.FileName), filepath.Ext(rep.FileName))
		if defaultName == "" {
			defaultName = rep.FileName
		}
		defaultDesc := rep.FileName + " 扫描报告导入"
		renderPage := func(errMsg string) {
			modelStatus, modelError, modelErrMsg := GetModelStatus()
			render(w, tmplAdmissionImport, admissionImportPageData{
				Username:    sess.Username,
				ReportID:    rep.ID,
				FileName:    rep.FileName,
				DefaultName: defaultName,
				DefaultDesc: defaultDesc,
				Error:       errMsg,
				HasPersonal: user.HasPermission(models.PermPersonalCenter),
				HasUserMgmt: user.HasPermission(models.PermUserManagement),
				HasLogPerm:  user.HasPermission(models.PermLoginLog),
				ModelStatus: modelStatus,
				ModelError:  modelError,
				ModelErrMsg: modelErrMsg,
			})
		}
		if r.Method == http.MethodGet {
			renderPage("")
			return
		}
		if err := r.ParseForm(); err != nil {
			renderPage("表单解析失败，请重试")
			return
		}
		svc, err := newAdmissionService(store)
		if err != nil {
			http.Error(w, "加载准入服务失败", http.StatusInternalServerError)
			return
		}
		out, err := svc.CreateSkillFromReport(admissionservice.CreateSkillFromReportInput{
			ReportID:        rep.ID,
			DisplayName:     strings.TrimSpace(r.FormValue("display_name")),
			Version:         strings.TrimSpace(r.FormValue("version")),
			Description:     strings.TrimSpace(r.FormValue("description")),
			ReviewSummary:   strings.TrimSpace(r.FormValue("review_summary")),
			AdmissionStatus: parseAdmissionStatus(r.FormValue("admission_status")),
			ReviewDecision:  parseReviewDecision(r.FormValue("review_decision")),
			Operator:        sess.Username,
		})
		if err != nil {
			renderPage(err.Error())
			return
		}
		http.Redirect(w, r, "/admission/skills/"+out.Skill.SkillID, http.StatusFound)
	}
}

func admissionEdit(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		skillID := strings.TrimSpace(filepath.Base(r.URL.Path))
		if skillID == "" || skillID == "/" || skillID == "." {
			http.Error(w, "技能不存在", http.StatusNotFound)
			return
		}
		svc, err := newAdmissionService(store)
		if err != nil {
			http.Error(w, "加载准入技能失败", http.StatusInternalServerError)
			return
		}
		detail, err := svc.GetSkillDetail(skillID)
		if err != nil || detail.Skill == nil {
			http.Error(w, "技能不存在", http.StatusNotFound)
			return
		}
		renderPage := func(errMsg string, skill *admissionmodel.AdmissionSkill) {
			enforceMsg := ""
			if skill.VerificationRequired {
				enforceMsg = "当前技能处于待验证状态：需先完成复测验证，才能设置为已准入。"
			}
			modelStatus, modelError, modelErrMsg := GetModelStatus()
			render(w, tmplAdmissionEdit, admissionEditPageData{
				Username:        sess.Username,
				SkillID:         skill.SkillID,
				FileName:        skill.FileName,
				DisplayName:     defaultIfEmpty(skill.DisplayName, skill.Name),
				Version:         skill.Version,
				Description:     skill.Description,
				AdmissionStatus: string(skill.AdmissionStatus),
				ReviewDecision:  string(skill.ReviewDecision),
				ReviewSummary:   skill.ReviewSummary,
				WorkflowStage:   normalizeWorkflowStage(skill.WorkflowStage),
				WorkflowStageLabel: localizeWorkflowStage(skill.WorkflowStage),
				VerificationRequired: skill.VerificationRequired,
				LastFixAt:       formatUnixTime(skill.LastFixAt),
				LastVerifiedAt:  formatUnixTime(skill.LastVerifiedAt),
				EnforceVerifyWarning: enforceMsg,
				Error:           errMsg,
				HasPersonal:     user.HasPermission(models.PermPersonalCenter),
				HasUserMgmt:     user.HasPermission(models.PermUserManagement),
				HasLogPerm:      user.HasPermission(models.PermLoginLog),
				ModelStatus:     modelStatus,
				ModelError:      modelError,
				ModelErrMsg:     modelErrMsg,
			})
		}
		if r.Method == http.MethodGet {
			renderPage("", detail.Skill)
			return
		}
		if err := r.ParseForm(); err != nil {
			renderPage("表单解析失败，请重试", detail.Skill)
			return
		}
		skillStore, err := admissionstore.NewSkillStore(store.DataDir())
		if err != nil {
			http.Error(w, "加载技能存储失败", http.StatusInternalServerError)
			return
		}
		reviewStore, err := admissionstore.NewReviewRecordStore(store.DataDir())
		if err != nil {
			http.Error(w, "加载审查记录失败", http.StatusInternalServerError)
			return
		}
		skill := *detail.Skill
		skill.DisplayName = strings.TrimSpace(r.FormValue("display_name"))
		skill.Version = strings.TrimSpace(r.FormValue("version"))
		skill.Description = strings.TrimSpace(r.FormValue("description"))
		skill.AdmissionStatus = parseAdmissionStatus(r.FormValue("admission_status"))
		skill.ReviewDecision = parseReviewDecision(r.FormValue("review_decision"))
		skill.ReviewSummary = strings.TrimSpace(r.FormValue("review_summary"))
		workflowAction := strings.ToLower(strings.TrimSpace(r.FormValue("workflow_action")))
		now := time.Now().Unix()
		if workflowAction == "mark_fixed" {
			skill.VerificationRequired = true
			skill.WorkflowStage = "pending_verification"
			skill.LastFixAt = now
			skill.AdmissionStatus = admissionmodel.AdmissionStatusPending
			if skill.ReviewDecision == admissionmodel.ReviewDecisionPass {
				skill.ReviewDecision = admissionmodel.ReviewDecisionReview
			}
		}
		if workflowAction == "mark_verified" {
			records := append([]*admissionmodel.ReviewRecord(nil), detail.ReviewRecords...)
			sort.SliceStable(records, func(i, j int) bool {
				left, right := records[i], records[j]
				if left == nil {
					return false
				}
				if right == nil {
					return true
				}
				return left.CreatedAt < right.CreatedAt
			})
			if len(records) < 2 {
				renderPage("自动验证失败：至少需要两次审查记录（修复前/修复后）才能完成复测验证。", &skill)
				return
			}
			prevH, prevM, prevL := countRisksByLevel(records[len(records)-2].ResidualRisks)
			currH, currM, currL := countRisksByLevel(records[len(records)-1].ResidualRisks)
			if (currH + currM + currL) > (prevH + prevM + prevL) {
				renderPage("自动验证失败：最近一次风险总数高于上一次，禁止完成复测验证。", &skill)
				return
			}
			skill.VerificationRequired = false
			skill.WorkflowStage = "verified"
			skill.LastVerifiedAt = now
		}
		if skill.VerificationRequired && skill.AdmissionStatus == admissionmodel.AdmissionStatusApproved {
			renderPage("存在未验证修复项，禁止直接设为已准入。请先执行“完成复测验证”。", &skill)
			return
		}
		skill.WorkflowStage = normalizeWorkflowStage(skill.WorkflowStage)
		skill.ReviewedBy = sess.Username
		skill.UpdatedAt = now
		if err := skillStore.Update(&skill); err != nil {
			renderPage(err.Error(), &skill)
			return
		}
		recordID, err := platformid.GenerateHexID(16)
		if err == nil {
			_ = reviewStore.Create(&admissionmodel.ReviewRecord{
				RecordID:  recordID,
				SkillID:   skill.SkillID,
				ReportID:  skill.ReportID,
				Reviewer:  sess.Username,
				Decision:  skill.ReviewDecision,
				Summary:   skill.ReviewSummary,
				CreatedAt: skill.UpdatedAt,
			})
		}
		http.Redirect(w, r, "/admission/skills/"+skill.SkillID, http.StatusFound)
	}
}

func combinationOverview(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		svc, err := newAdmissionService(store)
		if err != nil {
			http.Error(w, "加载组合分析页面失败", http.StatusInternalServerError)
			return
		}
		combinationStore, err := combinationservice.NewStore(store.DataDir())
		if err != nil {
			http.Error(w, "加载组合分析页面失败", http.StatusInternalServerError)
			return
		}
		selectedSkillIDs := r.URL.Query()["skill_id"]
		searchQuery := strings.TrimSpace(r.URL.Query().Get("q"))
		statusFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("status")))
		decisionFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("decision")))
		riskTagFilter := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("risk_tag")))
		runID := strings.TrimSpace(r.URL.Query().Get("run_id"))
		var sourceReport *combinationSourceReportContext
		if len(selectedSkillIDs) == 0 {
			reportID := strings.TrimSpace(r.URL.Query().Get("report_id"))
			if reportID != "" {
				if rep := store.GetReport(reportID); rep != nil && store.CanAccessReport(sess.Username, reportID) {
					sourceReport = &combinationSourceReportContext{
						ReportID:     rep.ID,
						TaskID:       strings.TrimSpace(rep.TaskID),
						RequestID:    strings.TrimSpace(rep.RequestID),
						FileName:     strings.TrimSpace(rep.FileName),
						ReportURL:    "/reports/view/" + url.PathEscape(rep.ID),
						DownloadURL:  "/reports/download/" + url.PathEscape(rep.ID) + "?format=json",
						DecisionHint: reportDecisionHint(store, rep),
					}
				}
				skillStore, err := admissionstore.NewSkillStore(store.DataDir())
				if err == nil {
					if skill, ok := skillStore.GetByReportID(reportID); ok && skill != nil {
						selectedSkillIDs = append(selectedSkillIDs, skill.SkillID)
					}
				}
			}
		}
		if len(selectedSkillIDs) == 0 && runID != "" {
			run, ok := combinationStore.GetByRunID(runID)
			if !ok || run == nil {
				http.Error(w, "组合快照不存在", http.StatusNotFound)
				return
			}
			selectedSkillIDs = append([]string(nil), run.SelectedSkills...)
		}
		overview, err := combinationservice.NewService(svc, combinationStore).BuildOverview(selectedSkillIDs, 200)
		if err != nil {
			http.Error(w, "加载组合分析页面失败", http.StatusInternalServerError)
			return
		}
		filteredOptions := filterCombinationSkillOptions(overview.Options, searchQuery, statusFilter, decisionFilter, riskTagFilter)
		entries := make([]combinationSkillEntry, 0, len(filteredOptions))
		for _, item := range filteredOptions {
			entries = append(entries, combinationSkillEntry{
				SkillID:         item.SkillID,
				DisplayName:     item.DisplayName,
				Version:         item.Version,
				AdmissionStatus: item.AdmissionStatus,
				ReviewDecision:  localizeDecisionLabel(item.ReviewDecision),
				Selected:        item.Selected,
			})
		}
		selectedSkills := make([]admissionListEntry, 0, len(overview.SelectedSkills))
		for _, item := range overview.SelectedSkills {
			selectedSkills = append(selectedSkills, admissionListEntry{
				SkillID:         item.SkillID,
				DisplayName:     item.DisplayName,
				Name:            item.Name,
				Version:         item.Version,
				AdmissionStatus: item.AdmissionStatus,
				ReviewDecision:  localizeDecisionLabel(item.ReviewDecision),
				DecisionHint:    reportDecisionHint(store, store.GetReport(item.ReportID)),
				RiskTags:        append([]string(nil), item.RiskTags...),
				UpdatedAt:       formatUnixTime(item.UpdatedAt),
				ReportID:        item.ReportID,
				AddToComboURL:   buildCombinationAddURL(selectedSkillIDs, item.SkillID),
				RemoveComboURL:  buildCombinationRemoveURL(selectedSkillIDs, item.SkillID, searchQuery, statusFilter, decisionFilter, riskTagFilter, runID),
			})
		}
		modelStatus, modelError, modelErrMsg := GetModelStatus()
		render(w, tmplCombinationOverview, combinationPageData{
			Username:          sess.Username,
			Items:             entries,
			SourceReport:      sourceReport,
			SearchQuery:       searchQuery,
			AdmissionStatus:   statusFilter,
			ReviewDecision:    decisionFilter,
			RiskTag:           riskTagFilter,
			SearchURL:         buildCombinationOverviewSearchURL(searchQuery, statusFilter, decisionFilter, riskTagFilter, selectedSkillIDs, runID),
			AnalyzeURL:        buildCombinationOverviewAnalyzeURL(selectedSkillIDs),
			ClearSelectionURL: buildCombinationClearSelectionURL(searchQuery, statusFilter, decisionFilter, riskTagFilter, runID),
			SelectedSkills:    selectedSkills,
			RunID:             overview.RunID,
			SavedAt:           formatUnixTime(overview.SavedAt),
			HistoryURL:        "/combination/runs",
			CombinedProfile:   overview.CombinedProfile,
			CombinedRisks:     overview.CombinedRisks,
			CombinedTags:      overview.CombinedTags,
			CapabilitySummary: overview.Capabilities,
			InferredChains:    overview.InferredChains,
			Conclusion:        overview.Conclusion,
			HasPersonal:       user.HasPermission(models.PermPersonalCenter),
			HasUserMgmt:       user.HasPermission(models.PermUserManagement),
			HasLogPerm:        user.HasPermission(models.PermLoginLog),
			ModelStatus:       modelStatus,
			ModelError:        modelError,
			ModelErrMsg:       modelErrMsg,
		})
	}
}

func combinationRuns(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		combinationStore, err := combinationservice.NewStore(store.DataDir())
		if err != nil {
			http.Error(w, "加载组合快照失败", http.StatusInternalServerError)
			return
		}
		runs, err := combinationStore.List()
		if err != nil {
			http.Error(w, "加载组合快照失败", http.StatusInternalServerError)
			return
		}
		query := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		riskLevel := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("risk_level")))
		tiRisk := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("ti_risk")))
		ruleWarnLevel := normalizeCombinationRunRuleWarnLevel(strings.TrimSpace(r.URL.Query().Get("rule_warn_level")))
		startDate := strings.TrimSpace(r.URL.Query().Get("start_date"))
		endDate := strings.TrimSpace(r.URL.Query().Get("end_date"))
		sortOrder := normalizeCombinationRunSort(strings.TrimSpace(r.URL.Query().Get("sort")))
		startUnix, startErr := parseDateStart(startDate)
		endUnix, endErr := parseDateEnd(endDate)
		if startErr != nil || endErr != nil {
			http.Error(w, "日期筛选格式无效，应为 YYYY-MM-DD", http.StatusBadRequest)
			return
		}
		entries := make([]combinationRunListEntry, 0, len(runs))
		ruleHits, coverageBase := summarizeRuleCoverage(runs)
		ruleCatalog := combinationservice.RuleCatalogIDs()
		deadRules := make([]string, 0)
		for _, id := range ruleCatalog {
			if ruleHits[id] == 0 {
			deadRules = append(deadRules, displayRuleName(id))
			}
		}
		type pair struct {
			id string
			count int
		}
		hitPairs := make([]pair, 0, len(ruleHits))
		for id, count := range ruleHits {
			hitPairs = append(hitPairs, pair{id: id, count: count})
		}
		sort.Slice(hitPairs, func(i, j int) bool {
			if hitPairs[i].count == hitPairs[j].count {
				return hitPairs[i].id < hitPairs[j].id
			}
			return hitPairs[i].count > hitPairs[j].count
		})
		topCoverage := make([]ruleCoverageStatView, 0, 5)
		for i, item := range hitPairs {
			if i >= 5 {
				break
			}
			coverage := "0.0%"
			if coverageBase > 0 {
				coverage = fmt.Sprintf("%.1f%%", float64(item.count)*100/float64(coverageBase))
			}
			topCoverage = append(topCoverage, ruleCoverageStatView{RuleID: displayRuleName(item.id), Count: item.count, Coverage: coverage})
		}
		filterParams := map[string]string{
			"q":               query,
			"risk_level":      riskLevel,
			"ti_risk":         tiRisk,
			"rule_warn_level": ruleWarnLevel,
			"start_date":      startDate,
			"end_date":        endDate,
			"sort":            sortOrder,
		}
		for _, item := range runs {
			if item == nil {
				continue
			}
			if startUnix > 0 && item.UpdatedAt < startUnix {
				continue
			}
			if endUnix > 0 && item.UpdatedAt > endUnix {
				continue
			}
			if riskLevel != "" && strings.ToLower(strings.TrimSpace(item.Overview.RiskLevel)) != riskLevel {
				continue
			}
			if !matchCombinationRunTIRisk(item, tiRisk) {
				continue
			}
			if !matchCombinationRunRuleWarnLevel(item, ruleWarnLevel) {
				continue
			}
			if query != "" && !matchCombinationRunQuery(item, query) {
				continue
			}
			entries = append(entries, combinationRunListEntry{
				RunID:              item.RunID,
				SelectedSkillCount: len(item.SelectedSkills),
				RiskLabel:          item.Overview.RiskLabel,
				RiskLevel:          item.Overview.RiskLevel,
				RuleConfigWarning:  item.Overview.RuleConfigWarning,
				RuleConfigWarnLevel: item.Overview.RuleConfigWarnLevel,
				TIThreatCount:      item.Overview.TIThreatCount,
				TISuspiciousCount:  item.Overview.TISuspiciousCount,
				Capabilities:       append([]string(nil), item.Overview.Capabilities...),
				CombinedTags:       append([]string(nil), item.Overview.CombinedTags...),
				UpdatedAt:          formatUnixTime(item.UpdatedAt),
				UpdatedAtUnix:      item.UpdatedAt,
				DetailURL:          buildCombinationRunDetailURL(item.RunID, filterParams),
				OverviewURL:        buildCombinationOverviewRunURL(item.RunID),
				RuleCoverageHint:   strings.Join(extractRunRuleDisplayNames(item), "，"),
			})
		}
		sort.SliceStable(entries, func(i, j int) bool {
			if sortOrder == "updated_asc" {
				return entries[i].UpdatedAtUnix < entries[j].UpdatedAtUnix
			}
			return entries[i].UpdatedAtUnix > entries[j].UpdatedAtUnix
		})
		modelStatus, modelError, modelErrMsg := GetModelStatus()
		render(w, tmplCombinationRuns, combinationRunsPageData{
			Username:    sess.Username,
			Items:       entries,
			Query:       query,
			RiskLevel:   riskLevel,
			TIRisk:      tiRisk,
			RuleWarnLevel: ruleWarnLevel,
			StartDate:   startDate,
			EndDate:     endDate,
			Sort:        sortOrder,
			RuleCoverageTop: topCoverage,
			DeadRulesCount: len(deadRules),
			DeadRulesPreview: limitStrings(deadRules, 8),
			HasPersonal: user.HasPermission(models.PermPersonalCenter),
			HasUserMgmt: user.HasPermission(models.PermUserManagement),
			HasLogPerm:  user.HasPermission(models.PermLoginLog),
			ModelStatus: modelStatus,
			ModelError:  modelError,
			ModelErrMsg: modelErrMsg,
		})
	}
}

func matchCombinationRunTIRisk(run *combinationservice.RunRecord, tiRisk string) bool {
	tiRisk = strings.ToLower(strings.TrimSpace(tiRisk))
	if tiRisk == "" || run == nil {
		return true
	}
	switch tiRisk {
	case "high":
		return run.Overview.TIThreatCount > 0
	case "suspicious":
		return run.Overview.TISuspiciousCount > 0
	case "clean":
		return run.Overview.TIThreatCount == 0 && run.Overview.TISuspiciousCount == 0
	default:
		return true
	}
}

func matchCombinationRunRuleWarnLevel(run *combinationservice.RunRecord, warnLevel string) bool {
	warnLevel = normalizeCombinationRunRuleWarnLevel(warnLevel)
	if warnLevel == "" || run == nil {
		return true
	}
	currentLevel := strings.ToLower(strings.TrimSpace(run.Overview.RuleConfigWarnLevel))
	hasWarning := strings.TrimSpace(run.Overview.RuleConfigWarning) != ""
	switch warnLevel {
	case "warning", "error":
		return currentLevel == warnLevel
	case "none":
		return !hasWarning
	default:
		return true
	}
}

func normalizeCombinationRunRuleWarnLevel(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "warning", "error", "none":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return ""
	}
}

func combinationRunDetail(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		runID := strings.TrimSpace(filepath.Base(r.URL.Path))
		if runID == "" || runID == "/" || runID == "." || runID == "runs" {
			http.Error(w, "组合快照不存在", http.StatusNotFound)
			return
		}
		combinationStore, err := combinationservice.NewStore(store.DataDir())
		if err != nil {
			http.Error(w, "加载组合快照失败", http.StatusInternalServerError)
			return
		}
		run, ok := combinationStore.GetByRunID(runID)
		if !ok || run == nil {
			http.Error(w, "组合快照不存在", http.StatusNotFound)
			return
		}
		svc, err := newAdmissionService(store)
		if err != nil {
			http.Error(w, "加载组合快照失败", http.StatusInternalServerError)
			return
		}
		skills, err := svc.ListSkills("", 0)
		if err != nil {
			http.Error(w, "加载组合快照失败", http.StatusInternalServerError)
			return
		}
		selectedSkills := mapSelectedSkills(skills, run.SelectedSkills)
		historyURL := normalizeCombinationRunsBackURL(strings.TrimSpace(r.URL.Query().Get("back")))
		if historyURL == "" {
			historyURL = "/combination/runs"
		}
		modelStatus, modelError, modelErrMsg := GetModelStatus()
			render(w, tmplCombinationRun, combinationRunDetailPageData{
			Username:          sess.Username,
			RunID:             run.RunID,
			HistoryURL:        historyURL,
			SelectedSkills:    selectedSkills,
			SavedAt:           formatUnixTime(run.CreatedAt),
			UpdatedAt:         formatUnixTime(run.UpdatedAt),
			ExportJSONURL:     "/combination/runs/export/" + run.RunID + ".json",
			ExportMarkdownURL: "/combination/runs/export/" + run.RunID + ".md",
			OverviewURL:       buildCombinationOverviewRunURL(run.RunID),
			RiskLabel:         run.Overview.RiskLabel,
			RiskLevel:         run.Overview.RiskLevel,
			ClosureNarrative:  run.Overview.ClosureNarrative,
			Recommendation:    run.Overview.Recommendation,
			RuleConfigWarning: run.Overview.RuleConfigWarning,
			RuleConfigWarnLevel: run.Overview.RuleConfigWarnLevel,
			RuleConfigVersion: run.Overview.RuleConfigVersion,
			RuleConfigRevision: run.Overview.RuleConfigRevision,
			RuleContentHash: run.Overview.RuleContentHash,
			RuleSourcePath: run.Overview.RuleSourcePath,
			Capabilities:      append([]string(nil), run.Overview.Capabilities...),
			CombinedTags:      append([]string(nil), run.Overview.CombinedTags...),
			TITargetCount:     run.Overview.TITargetCount,
			TIThreatCount:     run.Overview.TIThreatCount,
			TISuspiciousCount: run.Overview.TISuspiciousCount,
			TIAdjustmentScore: run.Overview.TIAdjustmentScore,
			DiagnosticsJSON:   buildCombinationDiagnosticsJSON(run),
			CombinedRisks:     append([]combinationservice.StoredRisk(nil), run.Overview.CombinedRisks...),
			InferredChains:    append([]combinationservice.StoredChain(nil), run.Overview.InferredChains...),
			HasPersonal:       user.HasPermission(models.PermPersonalCenter),
			HasUserMgmt:       user.HasPermission(models.PermUserManagement),
			HasLogPerm:        user.HasPermission(models.PermLoginLog),
			ModelStatus:       modelStatus,
			ModelError:        modelError,
			ModelErrMsg:       modelErrMsg,
		})
	}
}

func normalizeCombinationRunsBackURL(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, "/combination/runs") {
		return value
	}
	return ""
}

func buildCombinationDiagnosticsJSON(run *combinationservice.RunRecord) string {
	if run == nil {
		return "{}"
	}
		diagnostics := combinationDiagnostics{
			ClosureNarrative:  run.Overview.ClosureNarrative,
			RuleConfigWarning:   run.Overview.RuleConfigWarning,
			RuleConfigWarnLevel: run.Overview.RuleConfigWarnLevel,
			RuleConfigVersion:   run.Overview.RuleConfigVersion,
			RuleConfigRevision:  run.Overview.RuleConfigRevision,
			RuleContentHash:     run.Overview.RuleContentHash,
			RuleSourcePath:      run.Overview.RuleSourcePath,
			TITargetCount:       run.Overview.TITargetCount,
		TIThreatCount:       run.Overview.TIThreatCount,
		TISuspiciousCount:   run.Overview.TISuspiciousCount,
		TIAdjustmentScore:   run.Overview.TIAdjustmentScore,
	}
	data, err := json.MarshalIndent(diagnostics, "", "  ")
	if err != nil {
		return "{}"
	}
	return string(data)
}

func downloadCombinationRun(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		raw := strings.TrimSpace(filepath.Base(r.URL.Path))
		if raw == "" || raw == "/" || raw == "." {
			http.Error(w, "组合快照不存在", http.StatusNotFound)
			return
		}
		ext := strings.ToLower(filepath.Ext(raw))
		runID := strings.TrimSpace(strings.TrimSuffix(raw, filepath.Ext(raw)))
		if runID == "" || (ext != ".json" && ext != ".md") {
			http.Error(w, "不支持的导出格式", http.StatusBadRequest)
			return
		}
		combinationStore, err := combinationservice.NewStore(store.DataDir())
		if err != nil {
			http.Error(w, "加载组合快照失败", http.StatusInternalServerError)
			return
		}
		run, ok := combinationStore.GetByRunID(runID)
		if !ok || run == nil {
			http.Error(w, "组合快照不存在", http.StatusNotFound)
			return
		}
		fileBase := sanitizeDownloadFilename("combination-run-"+run.RunID, "combination-run")
		w.Header().Set("Cache-Control", "no-store")
		switch ext {
		case ".json":
			svc, err := newAdmissionService(store)
			if err != nil {
				http.Error(w, "加载组合快照失败", http.StatusInternalServerError)
				return
			}
			skills, err := svc.ListSkills("", 0)
			if err != nil {
				http.Error(w, "加载组合快照失败", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(fileBase+".json"))
			_ = json.NewEncoder(w).Encode(buildCombinationRunExport(run, mapSelectedSkills(skills, run.SelectedSkills)))
		case ".md":
			svc, err := newAdmissionService(store)
			if err != nil {
				http.Error(w, "加载组合快照失败", http.StatusInternalServerError)
				return
			}
			skills, err := svc.ListSkills("", 0)
			if err != nil {
				http.Error(w, "加载组合快照失败", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
			w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(fileBase+".md"))
			_, _ = w.Write([]byte(buildCombinationRunMarkdown(run, mapSelectedSkills(skills, run.SelectedSkills))))
		}
	}
}

func buildCombinationRunMarkdown(run *combinationservice.RunRecord, selectedSkills []admissionListEntry) string {
	if run == nil {
		return "# 组合快照\n\n暂无数据\n"
	}
	var b strings.Builder
	b.WriteString("# 组合快照\n\n")
	b.WriteString("- 快照 ID: " + run.RunID + "\n")
	b.WriteString("- 创建时间: " + formatUnixTime(run.CreatedAt) + "\n")
	b.WriteString("- 更新时间: " + formatUnixTime(run.UpdatedAt) + "\n")
	b.WriteString("- 风险结论: " + defaultIfEmpty(run.Overview.RiskLabel, "-") + "\n")
	if strings.TrimSpace(run.Overview.Recommendation) != "" {
		b.WriteString("- 处置建议: " + run.Overview.Recommendation + "\n")
	}
	if strings.TrimSpace(run.Overview.ClosureNarrative) != "" {
		b.WriteString("- 闭环摘要: " + run.Overview.ClosureNarrative + "\n")
	}
	if strings.TrimSpace(run.Overview.RuleConfigWarning) != "" {
		b.WriteString("- 规则告警: " + run.Overview.RuleConfigWarning + "\n")
	}
	if strings.TrimSpace(run.Overview.RuleConfigVersion) != "" || strings.TrimSpace(run.Overview.RuleConfigRevision) != "" {
		b.WriteString("- 规则版本: " + defaultIfEmpty(strings.TrimSpace(run.Overview.RuleConfigVersion), "-") + "\n")
		b.WriteString("- 规则修订: " + defaultIfEmpty(strings.TrimSpace(run.Overview.RuleConfigRevision), "-") + "\n")
	}
	if strings.TrimSpace(run.Overview.RuleContentHash) != "" {
		b.WriteString("- 规则内容哈希: " + run.Overview.RuleContentHash + "\n")
	}
	if strings.TrimSpace(run.Overview.RuleSourcePath) != "" {
		b.WriteString("- 规则来源路径: " + run.Overview.RuleSourcePath + "\n")
	}
	if run.Overview.TITargetCount > 0 {
		b.WriteString("- TI摘要: 目标 " + strconv.Itoa(run.Overview.TITargetCount) + "，高威胁 " + strconv.Itoa(run.Overview.TIThreatCount) + "，可疑 " + strconv.Itoa(run.Overview.TISuspiciousCount) + "，调整分 " + strconv.FormatFloat(run.Overview.TIAdjustmentScore, 'f', 2, 64) + "\n")
	}
	if len(selectedSkills) > 0 {
		b.WriteString("\n## 已选技能\n")
		for _, item := range selectedSkills {
			if strings.TrimSpace(item.SkillID) == "" {
				continue
			}
			b.WriteString("- " + defaultIfEmpty(item.DisplayName, item.SkillID) + " (`" + item.SkillID + "`)\n")
		}
	}
	if len(run.Overview.Capabilities) > 0 {
		b.WriteString("\n## 能力摘要\n")
		for _, item := range run.Overview.Capabilities {
			if strings.TrimSpace(item) == "" {
				continue
			}
			b.WriteString("- " + item + "\n")
		}
	}
	if len(run.Overview.CombinedRisks) > 0 {
		b.WriteString("\n## 聚合残余风险\n")
		for _, item := range run.Overview.CombinedRisks {
			b.WriteString("- " + defaultIfEmpty(item.Title, item.ID) + " [" + defaultIfEmpty(item.Level, "-") + "]\n")
			if strings.TrimSpace(item.Description) != "" {
				b.WriteString("  - 说明: " + item.Description + "\n")
			}
			if strings.TrimSpace(item.Mitigation) != "" {
				b.WriteString("  - 建议: " + item.Mitigation + "\n")
			}
		}
	}
	if len(run.Overview.InferredChains) > 0 {
		b.WriteString("\n## 动态链路推理\n")
		for _, item := range run.Overview.InferredChains {
			b.WriteString("- " + defaultIfEmpty(item.Title, item.ID) + " [" + defaultIfEmpty(item.Level, "-") + "]\n")
			if strings.TrimSpace(item.Summary) != "" {
				b.WriteString("  - 摘要: " + item.Summary + "\n")
			}
			if len(item.Evidence) > 0 {
				b.WriteString("  - 证据: " + strings.Join(item.Evidence, "、") + "\n")
			}
			if strings.TrimSpace(item.Recommendation) != "" {
				b.WriteString("  - 建议: " + item.Recommendation + "\n")
			}
		}
	}
	b.WriteString("\n")
	return b.String()
}

func buildCombinationRunExport(run *combinationservice.RunRecord, selectedSkills []admissionListEntry) combinationRunExport {
	refs := make([]combinationSkillRef, 0, len(selectedSkills))
	for _, item := range selectedSkills {
		if strings.TrimSpace(item.SkillID) == "" {
			continue
		}
		refs = append(refs, combinationSkillRef{
			SkillID:         item.SkillID,
			DisplayName:     defaultIfEmpty(item.DisplayName, item.SkillID),
			Version:         item.Version,
			AdmissionStatus: item.AdmissionStatus,
			ReviewDecision:  item.ReviewDecision,
		})
	}
	if run == nil {
		return combinationRunExport{}
	}
	return combinationRunExport{
		RunID:                run.RunID,
		SelectionKey:         run.SelectionKey,
		SelectedSkills:       append([]string(nil), run.SelectedSkills...),
		SelectedSkillDetails: refs,
		Overview:             run.Overview,
		Diagnostics: combinationDiagnostics{
			ClosureNarrative:  run.Overview.ClosureNarrative,
			RuleConfigWarning:   run.Overview.RuleConfigWarning,
			RuleConfigWarnLevel: run.Overview.RuleConfigWarnLevel,
			RuleConfigVersion:   run.Overview.RuleConfigVersion,
			RuleConfigRevision:  run.Overview.RuleConfigRevision,
			RuleContentHash:     run.Overview.RuleContentHash,
			RuleSourcePath:      run.Overview.RuleSourcePath,
			TITargetCount:       run.Overview.TITargetCount,
			TIThreatCount:       run.Overview.TIThreatCount,
			TISuspiciousCount:   run.Overview.TISuspiciousCount,
			TIAdjustmentScore:   run.Overview.TIAdjustmentScore,
		},
		CreatedAt:            run.CreatedAt,
		UpdatedAt:            run.UpdatedAt,
	}
}

func mapSelectedSkills(skills []*admissionmodel.AdmissionSkill, selectedIDs []string) []admissionListEntry {
	skillIndex := make(map[string]*admissionmodel.AdmissionSkill, len(skills))
	for _, item := range skills {
		if item == nil {
			continue
		}
		skillIndex[item.SkillID] = item
	}
	selectedSkills := make([]admissionListEntry, 0, len(selectedIDs))
	for _, skillID := range selectedIDs {
		skillID = strings.TrimSpace(skillID)
		if skillID == "" {
			continue
		}
		if item, ok := skillIndex[skillID]; ok && item != nil {
			selectedSkills = append(selectedSkills, admissionListEntry{
				SkillID:         item.SkillID,
				DisplayName:     defaultIfEmpty(item.DisplayName, item.Name),
				Name:            item.Name,
				Version:         defaultIfEmpty(item.Version, "-"),
				AdmissionStatus: string(item.AdmissionStatus),
				ReviewDecision:  localizeDecisionLabel(string(item.ReviewDecision)),
			})
			continue
		}
		selectedSkills = append(selectedSkills, admissionListEntry{SkillID: skillID, DisplayName: skillID})
	}
	return selectedSkills
}

func buildCombinationOverviewURL(selectedIDs []string) string {
	parts := make([]string, 0, len(selectedIDs))
	for _, skillID := range selectedIDs {
		skillID = strings.TrimSpace(skillID)
		if skillID == "" {
			continue
		}
		parts = append(parts, "skill_id="+url.QueryEscape(skillID))
	}
	if len(parts) == 0 {
		return "/combination/overview"
	}
	return "/combination/overview?" + strings.Join(parts, "&")
}

func buildCombinationOverviewRunURL(runID string) string {
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return "/combination/overview"
	}
	return "/combination/overview?run_id=" + url.QueryEscape(runID)
}

func buildCombinationOverviewSearchURL(query, status, decision, riskTag string, selectedIDs []string, runID string) string {
	values := url.Values{}
	if strings.TrimSpace(query) != "" {
		values.Set("q", strings.TrimSpace(query))
	}
	if strings.TrimSpace(status) != "" {
		values.Set("status", strings.TrimSpace(status))
	}
	if strings.TrimSpace(decision) != "" {
		values.Set("decision", strings.TrimSpace(decision))
	}
	if strings.TrimSpace(riskTag) != "" {
		values.Set("risk_tag", strings.TrimSpace(riskTag))
	}
	if strings.TrimSpace(runID) != "" {
		values.Set("run_id", strings.TrimSpace(runID))
	}
	for _, skillID := range normalizeQueryValues(selectedIDs) {
		values.Add("skill_id", skillID)
	}
	encoded := values.Encode()
	if encoded == "" {
		return "/combination/overview"
	}
	return "/combination/overview?" + encoded
}

func buildCombinationOverviewAnalyzeURL(selectedIDs []string) string {
	values := url.Values{}
	for _, skillID := range normalizeQueryValues(selectedIDs) {
		values.Add("skill_id", skillID)
	}
	encoded := values.Encode()
	if encoded == "" {
		return "/combination/overview"
	}
	return "/combination/overview?" + encoded
}

func buildCombinationClearSelectionURL(query, status, decision, riskTag, runID string) string {
	return buildCombinationOverviewSearchURL(query, status, decision, riskTag, nil, runID)
}

func buildCombinationRemoveURL(selectedIDs []string, removeID, query, status, decision, riskTag, runID string) string {
	removeID = strings.TrimSpace(removeID)
	values := url.Values{}
	if strings.TrimSpace(query) != "" {
		values.Set("q", strings.TrimSpace(query))
	}
	if strings.TrimSpace(status) != "" {
		values.Set("status", strings.TrimSpace(status))
	}
	if strings.TrimSpace(decision) != "" {
		values.Set("decision", strings.TrimSpace(decision))
	}
	if strings.TrimSpace(riskTag) != "" {
		values.Set("risk_tag", strings.TrimSpace(riskTag))
	}
	if strings.TrimSpace(runID) != "" {
		values.Set("run_id", strings.TrimSpace(runID))
	}
	for _, skillID := range normalizeQueryValues(selectedIDs) {
		if skillID == removeID {
			continue
		}
		values.Add("skill_id", skillID)
	}
	encoded := values.Encode()
	if encoded == "" {
		return "/combination/overview"
	}
	return "/combination/overview?" + encoded
}

func buildCombinationAddURL(selectedIDs []string, addID string) string {
	values := url.Values{}
	items := append(normalizeQueryValues(selectedIDs), strings.TrimSpace(addID))
	for _, skillID := range normalizeQueryValues(items) {
		values.Add("skill_id", skillID)
	}
	encoded := values.Encode()
	if encoded == "" {
		return "/combination/overview"
	}
	return "/combination/overview?" + encoded
}

func normalizeQueryValues(items []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	return out
}

func filterCombinationSkillOptions(items []combinationservice.SkillOption, query, status, decision, riskTag string) []combinationservice.SkillOption {
	query = strings.ToLower(strings.TrimSpace(query))
	out := make([]combinationservice.SkillOption, 0, len(items))
	for _, item := range items {
		if status != "" && strings.ToLower(strings.TrimSpace(item.AdmissionStatus)) != status {
			continue
		}
		if decision != "" && strings.ToLower(strings.TrimSpace(item.ReviewDecision)) != decision {
			continue
		}
		if riskTag != "" && !containsNormalized(item.RiskTags, riskTag) {
			continue
		}
		if query == "" {
			out = append(out, item)
			continue
		}
		haystacks := []string{item.SkillID, item.DisplayName, item.Name}
		matched := false
		for _, haystack := range haystacks {
			if strings.Contains(strings.ToLower(strings.TrimSpace(haystack)), query) {
				matched = true
				break
			}
		}
		if matched {
			out = append(out, item)
		}
	}
	return out
}

func matchCombinationRunQuery(run *combinationservice.RunRecord, query string) bool {
	if run == nil {
		return false
	}
	query = strings.ToLower(strings.TrimSpace(query))
	if query == "" {
		return true
	}
	if strings.Contains(strings.ToLower(run.RunID), query) || strings.Contains(strings.ToLower(run.Overview.RiskLabel), query) {
		return true
	}
	for _, item := range run.SelectedSkills {
		if strings.Contains(strings.ToLower(strings.TrimSpace(item)), query) {
			return true
		}
	}
	for _, item := range run.Overview.Capabilities {
		if strings.Contains(strings.ToLower(strings.TrimSpace(item)), query) {
			return true
		}
	}
	for _, item := range run.Overview.CombinedTags {
		if strings.Contains(strings.ToLower(strings.TrimSpace(item)), query) {
			return true
		}
	}
	return false
}

func normalizeCombinationRunSort(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "updated_asc" {
		return v
	}
	return "updated_desc"
}

func parseDateStart(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	ts, err := time.Parse("2006-01-02", v)
	if err != nil {
		return 0, err
	}
	return ts.Unix(), nil
}

func parseDateEnd(v string) (int64, error) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, nil
	}
	ts, err := time.Parse("2006-01-02", v)
	if err != nil {
		return 0, err
	}
	return ts.Add(24*time.Hour - time.Second).Unix(), nil
}

func buildCombinationRunsURL(params map[string]string) string {
	values := url.Values{}
	keys := make([]string, 0, len(params))
	for key, value := range params {
		if strings.TrimSpace(value) == "" {
			continue
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values.Set(key, strings.TrimSpace(params[key]))
	}
	encoded := values.Encode()
	if encoded == "" {
		return "/combination/runs"
	}
	return fmt.Sprintf("/combination/runs?%s", encoded)
}

func buildCombinationRunDetailURL(runID string, params map[string]string) string {
	runID = strings.TrimSpace(runID)
	if runID == "" {
		return "/combination/runs"
	}
	backURL := buildCombinationRunsURL(params)
	if backURL == "/combination/runs" {
		return "/combination/runs/" + runID
	}
	return "/combination/runs/" + runID + "?back=" + url.QueryEscape(backURL)
}

func newAdmissionService(store *storage.Store) (*admissionservice.AdmissionService, error) {
	skills, err := admissionstore.NewSkillStore(store.DataDir())
	if err != nil {
		return nil, err
	}
	profiles, err := admissionstore.NewProfileStore(store.DataDir())
	if err != nil {
		return nil, err
	}
	risks, err := admissionstore.NewRiskStore(store.DataDir())
	if err != nil {
		return nil, err
	}
	reviews, err := admissionstore.NewReviewRecordStore(store.DataDir())
	if err != nil {
		return nil, err
	}
	return admissionservice.NewAdmissionService(store, skills, profiles, risks, reviews, admissionservice.NewProfileBuilder()), nil
}

func formatUnixTime(v int64) string {
	if v <= 0 {
		return "-"
	}
	return time.Unix(v, 0).Format("2006-01-02 15:04:05")
}

func parseAdmissionStatus(v string) admissionmodel.AdmissionStatus {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case string(admissionmodel.AdmissionStatusApproved):
		return admissionmodel.AdmissionStatusApproved
	case string(admissionmodel.AdmissionStatusRejected):
		return admissionmodel.AdmissionStatusRejected
	default:
		return admissionmodel.AdmissionStatusPending
	}
}

func parseReviewDecision(v string) admissionmodel.ReviewDecision {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case string(admissionmodel.ReviewDecisionPass):
		return admissionmodel.ReviewDecisionPass
	case string(admissionmodel.ReviewDecisionBlock):
		return admissionmodel.ReviewDecisionBlock
	default:
		return admissionmodel.ReviewDecisionReview
	}
}

func containsNormalized(items []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return true
	}
	for _, item := range items {
		if strings.ToLower(strings.TrimSpace(item)) == target {
			return true
		}
	}
	return false
}

package handler

import (
	"encoding/json"
	"html/template"
	"net/http"

	"skill-scanner/web/templates"
)

// Template names passed to html/template.
const (
	tmplLogin               = "login"
	tmplChangePwd           = "change-password"
	tmplDashboard           = "dashboard"
	tmplScan                = "scan"
	tmplReports             = "reports"
	tmplAdmissionImport     = "admission-import"
	tmplAdmissionEdit       = "admission-edit"
	tmplAdmissionList       = "admission-list"
	tmplAdmissionDetail     = "admission-detail"
	tmplCombinationOverview = "combination-overview"
	tmplCombinationRuns     = "combination-runs"
	tmplCombinationRun      = "combination-run"
	tmplPersonal            = "personal"
	tmplAdminUsers          = "admin-users"
	tmplLoginLog            = "login-log"
)

// templates holds all parsed HTML templates.
var tmplCache = map[string]*template.Template{}

func init() {
	for name, html := range map[string]string{
		tmplLogin:               templates.LoginHTML,
		tmplChangePwd:           templates.ChangePasswordHTML,
		tmplDashboard:           templates.DashboardHTML,
		tmplScan:                templates.ScanHTML,
		tmplReports:             templates.ReportsHTML,
		tmplAdmissionImport:     templates.AdmissionImportHTML,
		tmplAdmissionEdit:       templates.AdmissionEditHTML,
		tmplAdmissionList:       templates.AdmissionListHTML,
		tmplAdmissionDetail:     templates.AdmissionDetailHTML,
		tmplCombinationOverview: templates.CombinationOverviewHTML,
		tmplCombinationRuns:     templates.CombinationRunsHTML,
		tmplCombinationRun:      templates.CombinationRunHTML,
		tmplPersonal:            templates.PersonalHTML,
		tmplAdminUsers:          templates.AdminUsersHTML,
		tmplLoginLog:            templates.LoginLogHTML,
	} {
		tmplCache[name] = template.Must(template.New(name).Parse(html))
	}
}

// render executes the named template with the given data.
func render(w http.ResponseWriter, name string, data interface{}) {
	if err := tmplCache[name].Execute(w, data); err != nil {
		// Log error but don't crash - write a user-friendly message
		http.Error(w, "页面渲染失败，请稍后重试", http.StatusInternalServerError)
	}
}

func SettingsRedirect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/personal", http.StatusFound)
	}
}

func SettingsAPIDeprecated() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		resp := map[string]string{
			"error":    "系统设置接口已下线，请使用个人中心配置",
			"redirect": "/personal",
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusGone)
		_ = json.NewEncoder(w).Encode(resp)
	}
}

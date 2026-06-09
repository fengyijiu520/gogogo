package handler

import (
	"bytes"
	"encoding/json"
	"html/template"
	"log"
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
	tmplPolicyBlacklist     = "policy-blacklist"
	tmplLoginLog            = "login-log"
	tmplSettingsAdmin       = "settings-admin"
	tmplRuntimeHelp         = "runtime-help"
)

// templates holds all parsed HTML templates.
var tmplCache = map[string]*template.Template{}

func dict(values ...interface{}) map[string]interface{} {
	out := make(map[string]interface{}, len(values)/2)
	for i := 0; i+1 < len(values); i += 2 {
		key, ok := values[i].(string)
		if !ok {
			continue
		}
		out[key] = values[i+1]
	}
	return out
}

func init() {
	funcs := template.FuncMap{"dict": dict}
	base := template.Must(template.New("common").Funcs(funcs).Parse(templates.CommonPartialsHTML))
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
		tmplPolicyBlacklist:     templates.PolicyBlacklistHTML,
		tmplLoginLog:            templates.LoginLogHTML,
		tmplSettingsAdmin:       templates.SettingsAdminHTML,
		tmplRuntimeHelp:         templates.RuntimeHelpHTML,
	} {
		tmpl := template.Must(base.Clone())
		tmplCache[name] = template.Must(tmpl.New(name).Parse(html))
	}
}

// render executes the named template with the given data.
func render(w http.ResponseWriter, name string, data interface{}) {
	tmpl, ok := tmplCache[name]
	if !ok {
		log.Printf("template %q not found", name)
		http.Error(w, "页面渲染失败，请稍后重试", http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		log.Printf("template %q render failed: %v", name, err)
		http.Error(w, "页面渲染失败，请稍后重试", http.StatusInternalServerError)
		return
	}
	_, _ = w.Write(buf.Bytes())
}

func SettingsRedirect() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/settings", http.StatusFound)
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

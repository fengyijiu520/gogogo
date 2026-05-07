package handler

import (
	"net/http"

	"skill-scanner/internal/storage"
)

func WithSecurityHeaders(next http.Handler) http.Handler { return withSecurityHeaders(next) }
func WithTrustedOrigin(next http.Handler) http.Handler   { return withTrustedOrigin(next) }

func Login(store *storage.Store) http.HandlerFunc                { return login(store) }
func ChangePassword(store *storage.Store) http.HandlerFunc       { return changePassword(store) }
func Logout() http.HandlerFunc                                   { return logout() }
func Dashboard(store *storage.Store) http.HandlerFunc            { return dashboard(store) }
func Scan(store *storage.Store) http.HandlerFunc                 { return scan(store) }
func ScanTaskStatus() http.HandlerFunc                           { return scanTaskStatus() }
func RulesCatalog(store *storage.Store) http.HandlerFunc         { return rulesCatalog(store) }
func RuleProfile(store *storage.Store) http.HandlerFunc          { return ruleProfileHandler(store) }
func AnalyzerFeedbackAPI(store *storage.Store) http.HandlerFunc  { return analyzerFeedbackAPI(store) }
func ListReports(store *storage.Store) http.HandlerFunc          { return listReports(store) }
func DeleteReport(store *storage.Store) http.HandlerFunc         { return deleteReport(store) }
func ViewReport(store *storage.Store) http.HandlerFunc           { return viewReport(store) }
func DownloadReport(store *storage.Store) http.HandlerFunc       { return downloadReport(store) }
func AdmissionImport(store *storage.Store) http.HandlerFunc      { return admissionImport(store) }
func AdmissionEdit(store *storage.Store) http.HandlerFunc        { return admissionEdit(store) }
func CombinationOverview(store *storage.Store) http.HandlerFunc  { return combinationOverview(store) }
func CombinationRuns(store *storage.Store) http.HandlerFunc      { return combinationRuns(store) }
func CombinationRunDetail(store *storage.Store) http.HandlerFunc { return combinationRunDetail(store) }
func DownloadCombinationRun(store *storage.Store) http.HandlerFunc {
	return downloadCombinationRun(store)
}
func Personal(store *storage.Store) http.HandlerFunc        { return personal(store) }
func AdminUsers(store *storage.Store) http.HandlerFunc      { return adminUsers(store) }
func AdmissionList(store *storage.Store) http.HandlerFunc   { return admissionList(store) }
func AdmissionDetail(store *storage.Store) http.HandlerFunc { return admissionDetail(store) }
func CurrentSession(r *http.Request) *Session               { return getSession(r) }

// LoginLog and RequireAuth are already exported from their respective files.

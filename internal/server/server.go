package server

import (
	"fmt"
	"net/http"

	admissionhttp "skill-scanner/internal/admission/http"
	admissionservice "skill-scanner/internal/admission/service"
	admissionstore "skill-scanner/internal/admission/store"
	"skill-scanner/internal/handler"
	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

func New(store *storage.Store) http.Handler {
	mux := http.NewServeMux()
	admissionHandlers := mustBuildAdmissionHandlers(store)

	// Public routes.
	mux.HandleFunc("/login", handler.Login(store))
	mux.HandleFunc("/change-password", handler.ChangePassword(store))
	mux.HandleFunc("/logout", handler.Logout())

	// Protected routes. (all require authentication).
	mux.HandleFunc("/dashboard", handler.RequireAuth(handler.Dashboard(store)))
	mux.HandleFunc("/scan", handler.RequirePermission(store, models.PermScan)(handler.RequireAuth(handler.Scan(store))))
	mux.HandleFunc("/reports", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.ListReports(store))))
	mux.HandleFunc("/reports/delete/", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.DeleteReport(store))))
	mux.HandleFunc("/reports/view/", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.ViewReport(store))))
	mux.HandleFunc("/reports/download/", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.DownloadReport(store))))
	mux.HandleFunc("/reports/", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.DownloadReport(store))))
	mux.HandleFunc("/admission/import/", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.AdmissionImport(store))))
	mux.HandleFunc("/admission/edit/", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.AdmissionEdit(store))))
	mux.HandleFunc("/admission/skills", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.AdmissionList(store))))
	mux.HandleFunc("/admission/skills/", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.AdmissionDetail(store))))
	mux.HandleFunc("/combination/overview", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.CombinationOverview(store))))
	mux.HandleFunc("/combination/runs", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.CombinationRuns(store))))
	mux.HandleFunc("/combination/runs/export/", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.DownloadCombinationRun(store))))
	mux.HandleFunc("/combination/runs/", handler.RequirePermission(store, models.PermReports)(handler.RequireAuth(handler.CombinationRunDetail(store))))
	mux.HandleFunc("/personal", handler.RequirePermission(store, models.PermPersonalCenter)(handler.RequireAuth(handler.Personal(store))))
	mux.HandleFunc("/admin/users", handler.RequirePermission(store, models.PermUserManagement)(handler.RequireAuth(handler.AdminUsers(store))))
	mux.HandleFunc("/admin/login-log", handler.RequirePermission(store, models.PermLoginLog)(handler.RequireAuth(handler.LoginLog(store))))

	mux.HandleFunc("/settings", handler.RequirePermission(store, models.PermPersonalCenter)(handler.RequireAuth(handler.SettingsRedirect())))
	mux.HandleFunc("/api/settings", handler.RequireAPIPermission(store, models.PermPersonalCenter)(handler.RequireAuth(handler.SettingsAPIDeprecated())))
	// 新增：用户 LLM 配置 API
	mux.HandleFunc("/api/user/llm", handler.RequireAPIPermission(store, models.PermPersonalCenter)(handler.RequireAuth(handler.UserLLMHandler(store))))
	mux.HandleFunc("/api/scan/tasks/", handler.RequireAPIPermission(store, models.PermScan)(handler.RequireAuth(handler.ScanTaskStatus())))
	mux.HandleFunc("/api/rules/catalog", handler.RequireAPIPermission(store, models.PermScan)(handler.RequireAuth(handler.RulesCatalog(store))))
	mux.HandleFunc("/api/rules/profiles", handler.RequireAPIPermission(store, models.PermScan)(handler.RequireAuth(handler.RuleProfile(store))))
	mux.HandleFunc("/api/analyzer/feedback", handler.RequireAPIPermission(store, models.PermScan)(handler.RequireAuth(handler.AnalyzerFeedbackAPI(store))))
	mux.HandleFunc("/api/admission/skills/search", handler.RequireAPIPermission(store, models.PermScan)(handler.RequireAuth(admissionHandlers.search.SearchSkills)))
	mux.HandleFunc("/api/admission/skills/", handler.RequireAPIPermission(store, models.PermScan)(handler.RequireAuth(admissionHandlers.registry.GetSkillDetail)))
	mux.HandleFunc("/api/admission/skills", handler.RequireAPIPermission(store, models.PermScan)(handler.RequireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			admissionHandlers.admission.CreateSkillFromReport(w, r)
			return
		}
		admissionHandlers.registry.ListSkills(w, r)
	})))

	return handler.WithSecurityHeaders(handler.WithTrustedOrigin(mux))
}

type admissionHandlerSet struct {
	admission *admissionhttp.AdmissionHandler
	registry  *admissionhttp.RegistryHandler
	search    *admissionhttp.SearchHandler
}

func mustBuildAdmissionHandlers(store *storage.Store) admissionHandlerSet {
	skills, err := admissionstore.NewSkillStore(store.DataDir())
	if err != nil {
		panic(err)
	}
	profiles, err := admissionstore.NewProfileStore(store.DataDir())
	if err != nil {
		panic(err)
	}
	risks, err := admissionstore.NewRiskStore(store.DataDir())
	if err != nil {
		panic(err)
	}
	reviews, err := admissionstore.NewReviewRecordStore(store.DataDir())
	if err != nil {
		panic(err)
	}
	svc := admissionservice.NewAdmissionService(store, skills, profiles, risks, reviews, admissionservice.NewProfileBuilder())
	currentUser := func(r *http.Request) string {
		sess := handler.CurrentSession(r)
		if sess == nil {
			return ""
		}
		return sess.Username
	}
	return admissionHandlerSet{
		admission: admissionhttp.NewAdmissionHandler(svc, currentUser),
		registry:  admissionhttp.NewRegistryHandler(svc),
		search:    admissionhttp.NewSearchHandler(svc),
	}
}

func Start(addr string, store *storage.Store) error {
	fmt.Printf("🌐 Web 服务已启动: http://%s\n", addr)
	return http.ListenAndServe(addr, New(store))
}

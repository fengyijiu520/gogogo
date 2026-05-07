package handler

import (
	"net/http"
	"sort"
	"time"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

type dashboardReportEntry struct {
	ID           string
	FileName     string
	Username     string
	CreatedAt    string
	StatusLabel  string
	Decision     string
	HasHTML      bool
	FindingCount int
	HighRisk     int
	MediumRisk   int
	LowRisk      int
	NoRisk       bool
}

type dashboardData struct {
	Username    string
	Reports     []*dashboardReportEntry
	IsAdmin     bool
	HasUserMgmt bool
	HasLogPerm  bool
	HasPersonal bool
	Permissions []string // list of permission strings for the dropdown
}

// dashboard renders the main dashboard showing recent reports.
func dashboard(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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

		reports := store.ListReports(sess.Username)

		sort.Slice(reports, func(i, j int) bool {
			return reports[i].CreatedAt > reports[j].CreatedAt
		})

		var entries []*dashboardReportEntry
		for _, rep := range reports {
			if len(entries) >= 10 {
				break
			}
			entries = append(entries, &dashboardReportEntry{
				ID:           rep.ID,
				FileName:     rep.FileName,
				Username:     rep.Username,
				CreatedAt:    time.Unix(rep.CreatedAt, 0).Format("2006-01-02 15:04:05"),
				StatusLabel:  localizeReportStatus(rep.Status),
				Decision:     localizeDecisionLabel(rep.Decision),
				HasHTML:      rep.HTMLPath != "",
				FindingCount: rep.FindingCount,
				HighRisk:     rep.HighRisk,
				MediumRisk:   rep.MediumRisk,
				LowRisk:      rep.LowRisk,
				NoRisk:       rep.NoRisk,
			})
		}

		// Build permission list for the "用户功能" dropdown.
		var perms []string
		for _, p := range []models.Permission{models.PermPersonalCenter, models.PermUserManagement, models.PermLoginLog} {
			if user.HasPermission(p) {
				perms = append(perms, string(p))
			}
		}

		modelStatus, modelError, modelErrMsg := GetModelStatus()
		render(w, tmplDashboard, map[string]interface{}{
			"Username":    sess.Username,
			"Reports":     entries,
			"IsAdmin":     user.Role == models.RoleAdmin,
			"HasUserMgmt": user.HasPermission(models.PermUserManagement),
			"HasLogPerm":  user.HasPermission(models.PermLoginLog),
			"HasPersonal": user.HasPermission(models.PermPersonalCenter),
			"Permissions": perms,
			"ModelStatus": modelStatus,
			"ModelError":  modelError,
			"ModelErrMsg": modelErrMsg,
		})
	}
}

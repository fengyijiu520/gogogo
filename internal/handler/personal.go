package handler

import (
	"net/http"
	"time"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

type personalData struct {
	Username    string
	Team        string
	CreatedAt   string
	ReportCount int
	IsAdmin     bool
	HasPersonal bool
	HasUserMgmt bool
	HasLogPerm  bool
}

// personal renders the personal center page showing the user's profile.
func personal(store *storage.Store) http.HandlerFunc {
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
		team := user.Team
		if team == "" {
			team = "无（管理员）"
		}

		modelStatus, modelError, modelErrMsg := GetModelStatus()
		render(w, tmplPersonal, map[string]interface{}{
			"Username":    user.Username,
			"Team":        team,
			"CreatedAt":   time.Unix(user.CreatedAt, 0).Format("2006-01-02 15:04"),
			"ReportCount": len(reports),
			"IsAdmin":     user.Role == models.RoleAdmin,
			"HasPersonal": user.HasPermission(models.PermPersonalCenter),
			"HasUserMgmt": user.HasPermission(models.PermUserManagement),
			"HasLogPerm":  user.HasPermission(models.PermLoginLog),
			"ModelStatus": modelStatus,
			"ModelError":  modelError,
			"ModelErrMsg": modelErrMsg,
		})
	}
}


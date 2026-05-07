package handler

import (
	"net/http"
	"time"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

type loginLogEntry struct {
	ID           string
	Username     string
	Timestamp    string
	Result       string
	ResultClass  string // "fail" or "success"
	IP           string
}

type loginLogData struct {
	Username    string
	Logs        []loginLogEntry
	IsAdmin     bool
	HasLogPerm  bool
	HasPersonal bool
	HasUserMgmt bool
}

// LoginLog renders the login log page (admin only).
func LoginLog(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		user := store.GetUser(sess.Username)
		if user == nil || !user.HasPermission(models.PermLoginLog) {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}

		logs := store.ListLoginLogs()
		var entries []loginLogEntry
		for _, l := range logs {
			resultStr := "✅ 成功"
			resultClass := "success"
			if l.Result == models.LoginFail {
				resultStr = "❌ 失败"
				resultClass = "fail"
			}
			entries = append(entries, loginLogEntry{
				ID:          l.ID,
				Username:    l.Username,
				Timestamp:   time.Unix(l.Timestamp, 0).Format("2006-01-02 15:04:05"),
				Result:      resultStr,
				ResultClass: resultClass,
				IP:          l.IP,
			})
		}

		modelStatus, modelError, modelErrMsg := GetModelStatus()
		render(w, tmplLoginLog, map[string]interface{}{
			"Username":    sess.Username,
			"Logs":        entries,
			"IsAdmin":     user.Role == models.RoleAdmin,
			"HasLogPerm":  true,
			"HasPersonal": user.HasPermission(models.PermPersonalCenter),
			"HasUserMgmt": user.HasPermission(models.PermUserManagement),
			"ModelStatus": modelStatus,
			"ModelError":  modelError,
			"ModelErrMsg": modelErrMsg,
		})
	}
}


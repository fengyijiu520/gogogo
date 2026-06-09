package handler

import (
	"net/http"

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
		http.Redirect(w, r, "/settings?tab=logs", http.StatusFound)
	}
}

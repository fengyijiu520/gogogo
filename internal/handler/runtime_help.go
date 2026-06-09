package handler

import (
	"net/http"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

func runtimeHelp(store *storage.Store) http.HandlerFunc {
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
		render(w, tmplRuntimeHelp, map[string]interface{}{
			"Username":    sess.Username,
			"HasPersonal": user.HasPermission(models.PermPersonalCenter),
			"HasUserMgmt": user.HasPermission(models.PermUserManagement),
			"HasLogPerm":  user.HasPermission(models.PermLoginLog),
		})
	}
}

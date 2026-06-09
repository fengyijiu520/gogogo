package handler

import (
	"net/http"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

func policyBlacklistPage(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		if user == nil || !user.HasPermission(models.PermUserManagement) {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/settings?tab=blacklist", http.StatusFound)
		return
	}
}

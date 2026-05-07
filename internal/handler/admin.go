package handler

import (
	"net/http"
	"strings"
	"time"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

const (
	maxUsernameLen = 32
	maxTeamLen     = 64
)

// isValidUsername checks that the username contains no HTML/JS special chars
// and is within the length limit. This prevents XSS via username injection.
func isValidUsername(u string) bool {
	if len(u) == 0 || len(u) > maxUsernameLen {
		return false
	}
	for _, c := range u {
		switch c {
		case '<', '>', '&', '"', '\'', '`', '\\':
			return false
		}
	}
	return true
}

// isValidTeam checks team name for the same restrictions.
func isValidTeam(t string) bool {
	if len(t) > maxTeamLen {
		return false
	}
	for _, c := range t {
		switch c {
		case '<', '>', '&', '"', '\'', '`', '\\':
			return false
		}
	}
	return true
}

type userEntry struct {
	Username             string
	Team                 string
	CreatedAt            string
	IsAdmin              bool
	CanDelete            bool
	DeleteConfirmMessage string
}

type adminUserData struct {
	Username    string
	Users       []userEntry
	IsAdmin     bool
	HasUserMgmt bool
	HasLogPerm  bool
	HasPersonal bool
	Permissions []string
	Error       string
	Success     string
}

// adminUsers renders the admin user management page and handles add/delete actions.
func adminUsers(store *storage.Store) http.HandlerFunc {
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

		if r.Method == http.MethodGet {
			renderAdminUsers(w, store, sess.Username, user, "", "")
			return
		}

		if r.Method == http.MethodPost {
			r.ParseForm()
			action := strings.TrimSpace(r.FormValue("action"))

			if action == "add" {
				username := strings.TrimSpace(r.FormValue("username"))
				password := strings.TrimSpace(r.FormValue("password"))
				team := strings.TrimSpace(r.FormValue("team"))

				if username == "" || password == "" {
					renderAdminUsers(w, store, sess.Username, user, "请填写用户名和密码", "")
					return
				}

				if !isValidUsername(username) {
					renderAdminUsers(w, store, sess.Username, user,
						"用户名只能包含字母、数字、中文及常用符号，长度不超过32位", "")
					return
				}

				if !isValidTeam(team) {
					renderAdminUsers(w, store, sess.Username, user,
						"团队名称只能包含字母、数字、中文及常用符号，长度不超过64位", "")
					return
				}

				if err := store.CreateUserWithTeam(username, password, team); err != nil {
					renderAdminUsers(w, store, sess.Username, user, err.Error(), "")
					return
				}

				renderAdminUsers(w, store, sess.Username, user, "",
					"用户 "+username+" 创建成功")
				return
			}

			if action == "delete" {
				target := strings.TrimSpace(r.FormValue("username"))
				if target == "" {
					renderAdminUsers(w, store, sess.Username, user, "请指定要删除的用户", "")
					return
				}

				if err := store.DeleteUser(target); err != nil {
					renderAdminUsers(w, store, sess.Username, user, err.Error(), "")
					return
				}

				renderAdminUsers(w, store, sess.Username, user, "",
					"用户 "+target+" 已删除")
				return
			}

			renderAdminUsers(w, store, sess.Username, user, "未知操作", "")
			return
		}

		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func renderAdminUsers(w http.ResponseWriter, store *storage.Store, adminUsername string, adminUser *models.User, errMsg, succMsg string) {
	users := store.ListUsers()
	var entries []userEntry
	for _, u := range users {
		team := u.Team
		if team == "" {
			team = "无"
		}
		isAdmin := u.Username == "admin"
		entries = append(entries, userEntry{
			Username:             u.Username,
			Team:                 team,
			CreatedAt:            time.Unix(u.CreatedAt, 0).Format("2006-01-02 15:04:05"),
			IsAdmin:              isAdmin,
			CanDelete:            !isAdmin,
			DeleteConfirmMessage: "确认删除用户 " + u.Username + "？",
		})
	}

	var perms []string
	for _, p := range []models.Permission{models.PermPersonalCenter, models.PermUserManagement, models.PermLoginLog} {
		if adminUser.HasPermission(p) {
			perms = append(perms, string(p))
		}
	}

	modelStatus, modelError, modelErrMsg := GetModelStatus()
	render(w, tmplAdminUsers, map[string]interface{}{
		"Username":    adminUsername,
		"Users":       entries,
		"IsAdmin":     adminUser.Role == models.RoleAdmin,
		"HasUserMgmt": adminUser.HasPermission(models.PermUserManagement),
		"HasLogPerm":  adminUser.HasPermission(models.PermLoginLog),
		"HasPersonal": adminUser.HasPermission(models.PermPersonalCenter),
		"Permissions": perms,
		"Error":       errMsg,
		"Success":     succMsg,
		"ModelStatus": modelStatus,
		"ModelError":  modelError,
		"ModelErrMsg": modelErrMsg,
	})
}

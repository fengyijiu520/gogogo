package handler

import (
	"net/http"
	"strings"
	"sync"
	"time"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

// Session stores per-request authentication state.
type Session struct {
	Username  string
	CreatedAt time.Time
}

const sessionCookie = "session_id"
const sessionTTL = 24 * time.Hour

var sessionStore = sync.Map{}

// generateSessionID creates a unique session identifier for the given username.
func generateSessionID(username string) string {
	id, _ := storage.GenerateID()
	return username + "-" + id
}

// setSessionCookie writes the session cookie to the response.
func setSessionCookie(w http.ResponseWriter, r *http.Request, sessionID string) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sessionID,
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		MaxAge:   int(sessionTTL.Seconds()),
		SameSite: http.SameSiteLaxMode,
	})
}

// clearSessionCookie removes the session cookie.
func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   requestIsSecure(r),
		MaxAge:   -1,
		SameSite: http.SameSiteLaxMode,
	})
}

// getSession returns the Session for the given request if valid and not expired.
func getSession(r *http.Request) *Session {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil || cookie == nil {
		return nil
	}

	val, ok := sessionStore.Load(cookie.Value)
	if !ok {
		return nil
	}

	sess := val.(*Session)
	if time.Since(sess.CreatedAt) > sessionTTL {
		sessionStore.Delete(cookie.Value)
		return nil
	}

	return sess
}

func invalidateUserSessions(username string) {
	if strings.TrimSpace(username) == "" {
		return
	}
	sessionStore.Range(func(key, value interface{}) bool {
		sess, ok := value.(*Session)
		if ok && sess.Username == username {
			sessionStore.Delete(key)
		}
		return true
	})
}

// clientIP extracts the real client IP, preferring X-Forwarded-For when present.
func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		return strings.Split(fwd, ",")[0]
	}
	return r.RemoteAddr
}

// login renders the login page and handles form submission.
func login(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		modelStatus, modelError, modelErrMsg := GetModelStatus()

		if r.Method == http.MethodGet {
			render(w, tmplLogin, map[string]interface{}{
				"ModelStatus": modelStatus,
				"ModelError":  modelError,
				"ModelErrMsg": modelErrMsg,
			})
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		username := strings.TrimSpace(r.FormValue("username"))
		password := strings.TrimSpace(r.FormValue("password"))
		ip := clientIP(r)

		// Always log the attempt.
		id, _ := storage.GenerateID()
		if !store.CheckPassword(username, password) {
			render(w, tmplLogin, map[string]interface{}{
				"Error":       "账号或密码错误，请重新输入",
				"ModelStatus": modelStatus,
				"ModelError":  modelError,
				"ModelErrMsg": modelErrMsg,
			})
			return
		}

		// Success.
		id, _ = storage.GenerateID()
		store.AppendLoginLog(models.NewLoginLog(id, username, models.LoginSuccess, ip))

		sessionID := generateSessionID(username)
		sessionStore.Store(sessionID, &Session{
			Username:  username,
			CreatedAt: time.Now(),
		})

		setSessionCookie(w, r, sessionID)
		http.Redirect(w, r, "/dashboard", http.StatusFound)
	}
}

// changePassword renders the change-password page and handles password updates.
func changePassword(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		modelStatus, modelError, modelErrMsg := GetModelStatus()
		if r.Method == http.MethodGet {
			render(w, tmplChangePwd, map[string]interface{}{
				"Username":    sess.Username,
				"ModelStatus": modelStatus,
				"ModelError":  modelError,
				"ModelErrMsg": modelErrMsg,
			})
			return
		}

		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		if err := r.ParseForm(); err != nil {
			http.Error(w, "Bad request", http.StatusBadRequest)
			return
		}

		oldPwd := strings.TrimSpace(r.FormValue("old_password"))
		newPwd := strings.TrimSpace(r.FormValue("new_password"))
		confirmPwd := strings.TrimSpace(r.FormValue("confirm_password"))

		data := map[string]interface{}{
			"Username":    sess.Username,
			"ModelStatus": modelStatus,
			"ModelError":  modelError,
			"ModelErrMsg": modelErrMsg,
		}

		// Verify current password — unified error message.
		if !store.CheckPassword(sess.Username, oldPwd) {
			data["Error"] = "账号或密码错误，请重新输入"
			render(w, tmplChangePwd, data)
			return
		}

		if newPwd == "" || newPwd != confirmPwd {
			data["Error"] = "两次输入的新密码不一致"
			render(w, tmplChangePwd, data)
			return
		}

		if err := store.UpdatePassword(sess.Username, newPwd); err != nil {
			data["Error"] = "密码修改失败，请重试"
			render(w, tmplChangePwd, data)
			return
		}

		invalidateUserSessions(sess.Username)
		clearSessionCookie(w, r)

		data["Success"] = "密码修改成功，请重新登录"
		render(w, tmplChangePwd, data)
	}
}

// logout destroys the session and redirects to login.
func logout() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if cookie, err := r.Cookie(sessionCookie); err == nil {
			sessionStore.Delete(cookie.Value)
		}

		clearSessionCookie(w, r)
		http.Redirect(w, r, "/login", http.StatusFound)
	}
}

// RequireAuth is middleware that redirects unauthenticated requests to /login.
func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if getSession(r) == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		next(w, r)
	}
}

// RequirePermission returns middleware that checks a specific permission before allowing access.
func RequirePermission(store *storage.Store, perm models.Permission) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sess := getSession(r)
			if sess == nil {
				http.Redirect(w, r, "/login", http.StatusFound)
				return
			}
			user := store.GetUser(sess.Username)
			if user == nil || !user.HasPermission(perm) {
				http.Redirect(w, r, "/dashboard", http.StatusFound)
				return
			}
			next(w, r)
		}
	}
}

// RequireAPIPermission checks API permission and returns JSON errors instead of redirects.
func RequireAPIPermission(store *storage.Store, perm models.Permission) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			sess := getSession(r)
			if sess == nil {
				sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录"})
				return
			}
			user := store.GetUser(sess.Username)
			if user == nil || !user.HasPermission(perm) {
				sendJSON(w, http.StatusForbidden, map[string]string{"error": "权限不足"})
				return
			}
			next(w, r)
		}
	}
}

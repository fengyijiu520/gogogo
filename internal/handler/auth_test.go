package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"skill-scanner/internal/storage"
)

func resetLoginLimiterForTest(t *testing.T) {
	t.Helper()
	loginLimiter = newLoginRateLimiter()
	t.Cleanup(func() { loginLimiter = newLoginRateLimiter() })
}

func newHandlerTestStore(t *testing.T) *storage.Store {
	t.Helper()
	t.Setenv("SKILL_SCANNER_BOOTSTRAP_ADMIN_PASSWORD", "admin-test-password")
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store
}

func TestChangePasswordInvalidatesExistingSessions(t *testing.T) {
	store := newHandlerTestStore(t)
	if err := store.CreateUserWithTeam("alice", "oldpass123", "team-a"); err != nil {
		t.Fatalf("create user: %v", err)
	}

	sessionID := generateSessionID("alice")
	sessionStore.Store(sessionID, &Session{Username: "alice", CreatedAt: time.Now()})
	t.Cleanup(func() { sessionStore.Delete(sessionID) })

	body := url.Values{}
	body.Set("old_password", "oldpass123")
	body.Set("new_password", "newpass123")
	body.Set("confirm_password", "newpass123")
	req := httptest.NewRequest(http.MethodPost, "/change-password", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookie, Value: sessionID, Path: "/"})
	rec := httptest.NewRecorder()

	changePassword(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	if getSession(req) != nil {
		t.Fatal("expected existing session to be invalidated after password change")
	}
	if !store.CheckPassword("alice", "newpass123") {
		t.Fatal("expected new password to be persisted")
	}
	cleared := false
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == sessionCookie && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	if !cleared {
		t.Fatal("expected password change response to clear session cookie")
	}
}

func TestGenerateSessionIDDoesNotExposeUsername(t *testing.T) {
	sessionID := generateSessionID("alice")
	if sessionID == "" {
		t.Fatal("expected non-empty session id")
	}
	if strings.Contains(sessionID, "alice") {
		t.Fatalf("expected session id not to contain username, got %q", sessionID)
	}
}

func TestLoginFailureIsAudited(t *testing.T) {
	resetLoginLimiterForTest(t)
	store := newHandlerTestStore(t)
	body := url.Values{}
	body.Set("username", "admin")
	body.Set("password", "wrong")
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	login(store).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected login page response, got %d", rec.Code)
	}
	logs := store.ListLoginLogs()
	if len(logs) != 1 {
		t.Fatalf("expected one login log, got %d", len(logs))
	}
	if logs[0].Username != "admin" || logs[0].Result != "fail" {
		t.Fatalf("expected failed admin login log, got %+v", logs[0])
	}
}

func TestLoginRateLimitBlocksRepeatedFailures(t *testing.T) {
	resetLoginLimiterForTest(t)
	store := newHandlerTestStore(t)
	body := url.Values{}
	body.Set("username", "admin")
	body.Set("password", "wrong")
	for i := 0; i < loginRateLimitMaxFailures; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		login(store).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d expected 200, got %d", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	login(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated failures, got %d", rec.Code)
	}
}

func TestClientIPIgnoresSpoofedForwardedFor(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/login", nil)
	req.RemoteAddr = "198.51.100.7:4567"
	req.Header.Set("X-Forwarded-For", "203.0.113.99")

	if got := clientIP(req); got != "198.51.100.7" {
		t.Fatalf("expected direct remote ip, got %q", got)
	}
}

func TestLoginRateLimitUsesRemoteAddrInsteadOfForwardedFor(t *testing.T) {
	resetLoginLimiterForTest(t)
	store := newHandlerTestStore(t)
	body := url.Values{}
	body.Set("username", "admin")
	body.Set("password", "wrong")
	for i := 0; i < loginRateLimitMaxFailures; i++ {
		req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "198.51.100.7:4567"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("203.0.113.%d", i+1))
		rec := httptest.NewRecorder()
		login(store).ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("attempt %d expected 200, got %d", i+1, rec.Code)
		}
	}
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "198.51.100.7:4567"
	req.Header.Set("X-Forwarded-For", "203.0.113.250")
	rec := httptest.NewRecorder()
	login(store).ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after repeated failures from same remote addr, got %d", rec.Code)
	}
}

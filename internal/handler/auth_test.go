package handler

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"skill-scanner/internal/storage"
)

func TestChangePasswordInvalidatesExistingSessions(t *testing.T) {
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
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

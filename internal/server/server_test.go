package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

func newServerTestStore(t *testing.T) *storage.Store {
	t.Helper()
	store, err := storage.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	return store
}

func loginAs(t *testing.T, h http.Handler, username, password string) *http.Cookie {
	t.Helper()
	body := url.Values{}
	body.Set("username", username)
	body.Set("password", password)
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body.Encode()))
	req.Host = "scanner.example.com"
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://scanner.example.com")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	res := rec.Result()
	for _, cookie := range res.Cookies() {
		if cookie.Name == "session_id" {
			return cookie
		}
	}
	t.Fatalf("session cookie not found: status=%d set-cookie=%q location=%q", rec.Code, rec.Header().Values("Set-Cookie"), rec.Header().Get("Location"))
	return nil
}

func TestAdminRoutesRejectMemberAtRouterLayer(t *testing.T) {
	store := newServerTestStore(t)
	if err := store.CreateUserWithTeam("member", "pass123", "team-a"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	h := New(store)
	cookie := loginAs(t, h, "member", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/admin/users", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/dashboard" {
		t.Fatalf("expected redirect to /dashboard, got %q", got)
	}
}

func TestAPIPermissionRejectsUserWithoutScanPermission(t *testing.T) {
	store := newServerTestStore(t)
	if err := store.CreateUserWithTeam("limited", "pass123", "team-a"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	store.GetUser("limited").Role = ""
	h := New(store)
	cookie := loginAs(t, h, "limited", "pass123")

	req := httptest.NewRequest(http.MethodGet, "/api/rules/catalog", nil)
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("expected json content type, got %q", got)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if body["error"] != "权限不足" {
		t.Fatalf("expected permission error body, got %+v", body)
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect for api permission failure, got %q", got)
	}
}

func TestAPIPermissionRejectsUnauthenticatedWithJSON(t *testing.T) {
	store := newServerTestStore(t)
	h := New(store)

	req := httptest.NewRequest(http.MethodGet, "/api/rules/catalog", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); !strings.Contains(got, "application/json") {
		t.Fatalf("expected json content type, got %q", got)
	}
	var body map[string]string
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode json: %v", err)
	}
	if body["error"] != "未登录" {
		t.Fatalf("expected unauthenticated error body, got %+v", body)
	}
	if got := rec.Header().Get("Location"); got != "" {
		t.Fatalf("expected no redirect for unauthenticated api request, got %q", got)
	}
}

func TestDeleteReportRejectsCrossSitePost(t *testing.T) {
	store := newServerTestStore(t)
	report := &models.Report{ID: "rep-delete-csrf", Username: "admin", FileName: "csrf_report", CreatedAt: 1}
	if err := store.AddReport(report); err != nil {
		t.Fatalf("add report: %v", err)
	}
	h := New(store)
	cookie := loginAs(t, h, "admin", "admin")

	req := httptest.NewRequest(http.MethodPost, "/reports/delete/rep-delete-csrf", nil)
	req.Host = "scanner.example.com"
	req.Header.Set("Origin", "https://evil.example.com")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rec.Code)
	}
	if store.GetReport("rep-delete-csrf") == nil {
		t.Fatalf("expected report preserved when cross-site post is rejected")
	}
}

func TestDeleteReportRouteRejectsUserWithoutReportsPermission(t *testing.T) {
	store := newServerTestStore(t)
	if err := store.CreateUserWithTeam("limited", "pass123", "team-a"); err != nil {
		t.Fatalf("create user: %v", err)
	}
	store.GetUser("limited").Role = ""
	report := &models.Report{ID: "rep-delete-perm", Username: "limited", Team: "team-a", FileName: "limited_report", CreatedAt: 1}
	if err := store.AddReport(report); err != nil {
		t.Fatalf("add report: %v", err)
	}
	h := New(store)
	cookie := loginAs(t, h, "limited", "pass123")

	req := httptest.NewRequest(http.MethodPost, "/reports/delete/rep-delete-perm", nil)
	req.Host = "scanner.example.com"
	req.Header.Set("Origin", "https://scanner.example.com")
	req.AddCookie(cookie)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusFound {
		t.Fatalf("expected 302, got %d", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/dashboard" {
		t.Fatalf("expected redirect to /dashboard, got %q", got)
	}
	if store.GetReport("rep-delete-perm") == nil {
		t.Fatalf("expected report preserved when route permission blocks delete")
	}
}

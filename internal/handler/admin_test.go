package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAdminUsersTemplateEscapesDeleteFormData(t *testing.T) {
	rec := httptest.NewRecorder()
	render(rec, tmplAdminUsers, map[string]interface{}{
		"Username": "admin",
		"Users": []userEntry{{
			Username:             `<img src=x onerror=alert(1)>`,
			Team:                 `red"><script>alert(2)</script>`,
			CreatedAt:            "2026-05-01 18:30:45",
			CanDelete:            true,
			DeleteConfirmMessage: `确认删除用户 <img src=x onerror=alert(1)>？`,
		}},
		"HasUserMgmt": true,
	})

	body := rec.Body.String()
	if !strings.Contains(body, `class="delete-user-form"`) {
		t.Fatalf("expected delete form rendered, got %q", body)
	}
	if !strings.Contains(body, `data-confirm="确认删除用户 &lt;img src=x onerror=alert(1)&gt;？"`) {
		t.Fatalf("expected escaped confirm attribute, got %q", body)
	}
	if !strings.Contains(body, `value="&lt;img src=x onerror=alert(1)&gt;"`) {
		t.Fatalf("expected escaped hidden username value, got %q", body)
	}
	if strings.Contains(body, `<form method="POST" action="/admin/users" style="display:inline;" onsubmit="return confirm('确认删除用户 <img src=x onerror=alert(1)>？')">`) {
		t.Fatalf("expected no inline html-constructed delete form, got %q", body)
	}
	if strings.Contains(body, `<script>alert(2)</script>`) {
		t.Fatalf("expected team content escaped, got %q", body)
	}
}

func TestRenderAdminUsersUsesPlainSuccessMessageData(t *testing.T) {
	store := newTestStore(t)
	admin := store.GetUser("admin")
	if admin == nil {
		t.Fatal("expected admin user")
	}
	rec := httptest.NewRecorder()
	renderAdminUsers(rec, store, "admin", admin, "", `用户 <b>demo</b> 创建成功`)
	body := rec.Body.String()
	if !strings.Contains(body, `用户 &lt;b&gt;demo&lt;/b&gt; 创建成功`) {
		t.Fatalf("expected success message auto-escaped by template, got %q", body)
	}
	if strings.Contains(body, `用户 <b>demo</b> 创建成功`) {
		t.Fatalf("expected no raw html success message, got %q", body)
	}
}

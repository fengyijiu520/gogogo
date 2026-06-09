package handler

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

type blacklistEntryView struct {
	TypeLabel string
	Type      string
	Value     string
	CreatedAt string
	UpdatedAt string
}

type blacklistChangeView struct {
	ActionLabel  string
	OldTypeLabel string
	OldType      string
	OldValue     string
	NewTypeLabel string
	NewType      string
	NewValue     string
	UpdatedAt    string
}

func blacklistTypeLabel(itemType string) string {
	switch itemType {
	case "ipv4":
		return "IPv4"
	case "ipv6":
		return "IPv6"
	default:
		return "域名"
	}
}

func splitLines(raw string) []string {
	parts := strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		v := strings.TrimSpace(p)
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

func parseDateValue(raw string) (time.Time, bool) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return time.Time{}, false
	}
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func safeLocalRedirect(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" || !strings.HasPrefix(value, "/") || strings.HasPrefix(value, "//") || strings.ContainsAny(value, "\r\n") {
		return ""
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.IsAbs() || parsed.Host != "" {
		return ""
	}
	return value
}

func settingsPage(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/dashboard", http.StatusFound)
			return
		}
		hasUserMgmt := user.HasPermission(models.PermUserManagement)
		hasLogPerm := user.HasPermission(models.PermLoginLog)
		if !hasUserMgmt && !hasLogPerm {
			http.Redirect(w, r, "/personal", http.StatusFound)
			return
		}

		tab := strings.TrimSpace(r.URL.Query().Get("tab"))
		if tab == "" {
			tab = "users"
		}
		if tab == "llm" && !hasUserMgmt {
			tab = "users"
		}
		blacklistAddOpen := strings.TrimSpace(r.URL.Query().Get("add")) == "1"
		blacklistAddType := strings.TrimSpace(r.URL.Query().Get("item_type"))
		if blacklistAddType == "" {
			blacklistAddType = "domain"
		}
		blacklistAddValue := ""
		blacklistAddError := ""
		blacklistTypeFilter := strings.TrimSpace(r.URL.Query().Get("type"))
		blacklistDateFrom := strings.TrimSpace(r.URL.Query().Get("date_from"))
		blacklistDateTo := strings.TrimSpace(r.URL.Query().Get("date_to"))

		errMsg, succMsg := "", ""
		redirectAfterPost := ""
		if r.Method == http.MethodPost {
			_ = r.ParseForm()
			action := strings.TrimSpace(r.FormValue("action"))
			redirectAfterPost = safeLocalRedirect(r.FormValue("redirect_to"))
			switch action {
			case "add_user":
				tab = "users"
				if !hasUserMgmt {
					errMsg = "无权限"
					break
				}
				username := strings.TrimSpace(r.FormValue("username"))
				password := strings.TrimSpace(r.FormValue("password"))
				team := strings.TrimSpace(r.FormValue("team"))
				if username == "" || password == "" {
					errMsg = "请填写用户名和密码"
					break
				}
				if !isValidUsername(username) {
					errMsg = "用户名格式无效"
					break
				}
				if !isValidTeam(team) {
					errMsg = "团队名称格式无效"
					break
				}
				if err := store.CreateUserWithTeam(username, password, team); err != nil {
					errMsg = err.Error()
				} else {
					succMsg = "用户创建成功"
				}
			case "delete_user":
				tab = "users"
				if !hasUserMgmt {
					errMsg = "无权限"
					break
				}
				target := strings.TrimSpace(r.FormValue("username"))
				if err := store.DeleteUser(target); err != nil {
					errMsg = err.Error()
				} else {
					invalidateUserSessions(target)
					succMsg = "用户已删除"
				}
			case "add_blacklist", "remove_blacklist", "update_blacklist", "save_blacklist", "discard_blacklist":
				tab = "blacklist"
				if !hasUserMgmt {
					errMsg = "无权限"
					break
				}
				switch action {
				case "add_blacklist":
					blacklistAddOpen = true
					blacklistAddType = strings.TrimSpace(r.FormValue("item_type"))
					if blacklistAddType == "" {
						blacklistAddType = "domain"
					}
					blacklistAddValue = strings.TrimSpace(r.FormValue("item_value"))
					items := splitLines(blacklistAddValue)
					if len(items) == 0 {
						blacklistAddError = "请至少填写一个黑名单目标"
						break
					}
					for _, item := range items {
						if err := store.AddPolicyBlacklistWithType(blacklistAddType, item); err != nil {
							blacklistAddError = err.Error()
							break
						}
					}
					if blacklistAddError == "" {
						succMsg = "已写入草稿，点击“保存配置”后生效"
						blacklistAddValue = ""
						blacklistAddOpen = false
					}
				case "remove_blacklist":
					itemType := strings.TrimSpace(r.FormValue("item_type"))
					item := strings.TrimSpace(r.FormValue("item"))
					if err := store.RemovePolicyBlacklistWithType(itemType, item); err != nil {
						errMsg = err.Error()
					} else {
						succMsg = "已从草稿删除，点击“保存配置”后生效"
					}
				case "update_blacklist":
					oldType := strings.TrimSpace(r.FormValue("old_type"))
					oldValue := strings.TrimSpace(r.FormValue("old_value"))
					itemType := strings.TrimSpace(r.FormValue("item_type"))
					item := strings.TrimSpace(r.FormValue("item"))
					if err := store.ReplacePolicyBlacklist(oldType, oldValue, itemType, item); err != nil {
						errMsg = err.Error()
					} else {
						succMsg = "已更新草稿，点击“保存配置”后生效"
					}
				case "save_blacklist":
					if err := store.SavePolicyBlacklist(); err != nil {
						errMsg = err.Error()
					} else {
						succMsg = "黑名单配置已保存并生效"
					}
				case "discard_blacklist":
					if err := store.DiscardPolicyBlacklistDraft(); err != nil {
						errMsg = err.Error()
					} else {
						succMsg = "已放弃保存，草稿已与生效配置对齐"
					}
				}
			}
			if errMsg == "" && redirectAfterPost != "" {
				http.Redirect(w, r, redirectAfterPost, http.StatusFound)
				return
			}
		}

		users := store.ListUsers()
		userEntries := make([]userEntry, 0, len(users))
		for _, u := range users {
			team := u.Team
			if strings.TrimSpace(team) == "" {
				team = "无"
			}
			userEntries = append(userEntries, userEntry{Username: u.Username, Team: team, CreatedAt: time.Unix(u.CreatedAt, 0).Format("2006-01-02 15:04:05"), IsAdmin: u.Username == "admin", CanDelete: u.Username != "admin", DeleteConfirmMessage: "确认删除用户 " + u.Username + "？"})
		}

		blSize := 20
		if v, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page_size"))); err == nil && (v == 20 || v == 50 || v == 100) {
			blSize = v
		}
		blPage := 1
		if v, err := strconv.Atoi(strings.TrimSpace(r.URL.Query().Get("page"))); err == nil && v > 0 {
			blPage = v
		}
		keyword := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		dateFrom, hasDateFrom := parseDateValue(blacklistDateFrom)
		dateTo, hasDateTo := parseDateValue(blacklistDateTo)
		if hasDateTo {
			dateTo = dateTo.Add(24*time.Hour - time.Second)
		}
		activeAll := store.ListPolicyBlacklistActiveEntries()
		activeViews := make([]blacklistEntryView, 0, len(activeAll))
		for _, item := range activeAll {
			if keyword != "" && !strings.Contains(strings.ToLower(item.Value), keyword) {
				continue
			}
			if blacklistTypeFilter != "" && item.Type != blacklistTypeFilter {
				continue
			}
			itemTime := time.Unix(item.CreatedAt, 0)
			if hasDateFrom && itemTime.Before(dateFrom) {
				continue
			}
			if hasDateTo && itemTime.After(dateTo) {
				continue
			}
			activeViews = append(activeViews, blacklistEntryView{TypeLabel: blacklistTypeLabel(item.Type), Type: item.Type, Value: item.Value, CreatedAt: time.Unix(item.CreatedAt, 0).Format("2006-01-02 15:04:05"), UpdatedAt: time.Unix(item.UpdatedAt, 0).Format("2006-01-02 15:04:05")})
		}
		changesRaw := store.ListPolicyBlacklistDraftChanges()
		changeViews := make([]blacklistChangeView, 0, len(changesRaw))
		for _, change := range changesRaw {
			changeViews = append(changeViews, blacklistChangeView{
				ActionLabel:  map[string]string{"add": "添加", "delete": "删除", "modify": "修改"}[change.Action],
				OldTypeLabel: blacklistTypeLabel(change.OldType),
				OldType:      change.OldType,
				OldValue:     change.OldValue,
				NewTypeLabel: blacklistTypeLabel(change.NewType),
				NewType:      change.NewType,
				NewValue:     change.NewValue,
				UpdatedAt:    time.Unix(change.UpdatedAt, 0).Format("2006-01-02 15:04:05"),
			})
		}
		total := len(activeViews)
		totalPages := total / blSize
		if total%blSize != 0 {
			totalPages++
		}
		if totalPages == 0 {
			totalPages = 1
		}
		if blPage > totalPages {
			blPage = totalPages
		}
		start := (blPage - 1) * blSize
		end := start + blSize
		if end > total {
			end = total
		}
		paged := []blacklistEntryView{}
		if start < end {
			paged = activeViews[start:end]
		}
		pages := make([]int, 0, totalPages)
		for i := 1; i <= totalPages; i++ {
			pages = append(pages, i)
		}

		logs := store.ListLoginLogs()
		logEntries := make([]loginLogEntry, 0, len(logs))
		for _, l := range logs {
			resultStr, resultClass := "✅ 成功", "success"
			if l.Result == models.LoginFail {
				resultStr, resultClass = "❌ 失败", "fail"
			}
			logEntries = append(logEntries, loginLogEntry{ID: l.ID, Username: l.Username, Timestamp: time.Unix(l.Timestamp, 0).Format("2006-01-02 15:04:05"), Result: resultStr, ResultClass: resultClass, IP: l.IP})
		}

		render(w, tmplSettingsAdmin, map[string]interface{}{
			"Username": sess.Username, "Tab": tab, "Error": errMsg, "Success": succMsg,
			"HasPersonal": user.HasPermission(models.PermPersonalCenter), "HasUserMgmt": hasUserMgmt, "HasLogPerm": hasLogPerm,
			"RuntimeStatus":  buildRuntimeStatusResponse(store, sess.Username),
			"LLMProviders": store.ListLLMProviders(true),
			"Users":        userEntries, "Logs": logEntries,
			"BlacklistItems": paged, "BlacklistChanges": changeViews, "BlacklistDraftDirty": store.IsPolicyBlacklistDraftDirty(), "Page": blPage, "PageSize": blSize, "Keyword": keyword, "Pages": pages,
			"BlacklistAddOpen": blacklistAddOpen, "BlacklistAddType": blacklistAddType, "BlacklistAddValue": blacklistAddValue, "BlacklistAddError": blacklistAddError,
			"BlacklistTypeFilter": blacklistTypeFilter, "BlacklistDateFrom": blacklistDateFrom, "BlacklistDateTo": blacklistDateTo,
			"PrevPage": maxIntPB(1, blPage-1), "NextPage": minIntPB(totalPages, blPage+1),
		})
	}
}

func maxIntPB(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func minIntPB(a, b int) int {
	if a < b {
		return a
	}
	return b
}

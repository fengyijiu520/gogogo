package handler

import (
	"errors"
	"net/http"
	"strings"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

func ruleProfileHandler(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		switch r.Method {
		case http.MethodPost:
			handleSaveRuleProfile(store, w, r, sess.Username)
		case http.MethodPatch:
			handleRenameRuleProfile(store, w, r, sess.Username)
		case http.MethodDelete:
			handleDeleteRuleProfile(store, w, r, sess.Username)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

func handleSaveRuleProfile(store *storage.Store, w http.ResponseWriter, r *http.Request, username string) {
	var req models.RuleProfile
	if err := decodeStrictJSONBody(w, r, &req, 256<<10); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误"})
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if err := validateRuleProfileRequest(&req); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if req.EvasionDelayThreshold <= 0 {
		req.EvasionDelayThreshold = readDelayThresholdSec()
	}
	if len(req.DifferentialScenarios) > 0 {
		req.DifferentialEnabled = true
	}

	if err := store.SaveUserRuleProfile(username, req); err != nil {
		sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "保存规则配置失败"})
		return
	}

	sendJSON(w, http.StatusOK, map[string]string{"status": "ok"})

}

func handleRenameRuleProfile(store *storage.Store, w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		OldName string `json:"old_name"`
		NewName string `json:"new_name"`
	}
	if err := decodeStrictJSONBody(w, r, &req, 8<<10); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误"})
		return
	}
	req.OldName = strings.TrimSpace(req.OldName)
	req.NewName = strings.TrimSpace(req.NewName)
	if req.OldName == "" || req.NewName == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "旧名称和新名称都不能为空"})
		return
	}
	if len(req.OldName) > 128 || len(req.NewName) > 128 {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "配置名称过长"})
		return
	}
	if err := store.RenameUserRuleProfile(username, req.OldName, req.NewName); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func handleDeleteRuleProfile(store *storage.Store, w http.ResponseWriter, r *http.Request, username string) {
	var req struct {
		Name string `json:"name"`
	}
	if err := decodeStrictJSONBody(w, r, &req, 8<<10); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误"})
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "配置名称不能为空"})
		return
	}
	if len(req.Name) > 128 {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": "配置名称过长"})
		return
	}
	if err := store.DeleteUserRuleProfile(username, req.Name); err != nil {
		sendJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	sendJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func validateRuleProfileRequest(req *models.RuleProfile) error {
	if req == nil {
		return errors.New("配置不能为空")
	}
	if req.Name == "" {
		return errors.New("配置名称不能为空")
	}
	if len(req.Name) > 128 {
		return errors.New("配置名称过长")
	}
	if len(req.SelectedRuleIDs) == 0 && len(req.CustomRules) == 0 {
		return errors.New("至少需要选择一条内置规则或新增一条自定义规则")
	}
	if len(req.SelectedRuleIDs) > 512 {
		return errors.New("内置规则选择数量过多")
	}
	if len(req.CustomRules) > 64 {
		return errors.New("自定义规则数量过多")
	}
	for _, id := range req.SelectedRuleIDs {
		if len(strings.TrimSpace(id)) == 0 || len(id) > 64 {
			return errors.New("存在无效的规则 ID")
		}
	}
	for _, rule := range req.CustomRules {
		if len(strings.TrimSpace(rule.Name)) == 0 || len(rule.Name) > 128 {
			return errors.New("存在无效的自定义规则名称")
		}
		if len(rule.Patterns) == 0 || len(rule.Patterns) > 32 {
			return errors.New("存在无效的自定义规则模式数量")
		}
		for _, p := range rule.Patterns {
			if len(strings.TrimSpace(p)) == 0 || len(p) > 512 {
				return errors.New("存在无效的自定义规则模式")
			}
		}
	}
	return nil
}

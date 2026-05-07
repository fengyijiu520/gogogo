package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"skill-scanner/internal/models"
	"skill-scanner/internal/storage"
)

// GetUserLLMConfig 返回当前用户的 LLM 配置（API Key 不返回真实值）
func GetUserLLMConfig(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		config := store.GetUserLLMConfig(sess.Username)
		resp := map[string]interface{}{
			"enabled":  false,
			"provider": "",
			"has_key":  false,
		}
		if config != nil {
			resp["enabled"] = config.Enabled
			resp["provider"] = config.Provider
			resp["has_key"] = config.APIKey != ""
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

// UpdateUserLLMConfig 更新当前用户的 LLM 配置
func UpdateUserLLMConfig(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		var req struct {
			Enabled        bool   `json:"enabled"`
			Provider       string `json:"provider"`
			APIKey         string `json:"api_key"`
			MiniMaxGroupID string `json:"minimax_group_id"`
			DeleteKey      bool   `json:"delete_key"` // 是否删除已保存的 Key
		}
		if err := decodeStrictJSONBody(w, r, &req, 16<<10); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		if err := validateUserLLMRequest(req.Provider, req.APIKey, req.MiniMaxGroupID, req.Enabled, req.DeleteKey); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		config := store.GetUserLLMConfig(sess.Username)
		if config == nil {
			config = &models.LLMConfig{}
		}

		config.Enabled = req.Enabled
		config.Provider = strings.TrimSpace(req.Provider)
		if req.Provider == "minimax" {
			config.MiniMaxGroupID = strings.TrimSpace(req.MiniMaxGroupID)
		} else {
			config.MiniMaxGroupID = ""
		}

		if req.DeleteKey {
			config.APIKey = ""
		} else if req.APIKey != "" {
			config.APIKey = strings.TrimSpace(req.APIKey)
		}
		// 如果既没有提供新 Key 也没有删除，则保留原有 Key

		if err := store.SaveUserLLMConfig(sess.Username, config); err != nil {
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

func validateUserLLMRequest(provider, apiKey, groupID string, enabled, deleteKey bool) error {
	provider = strings.TrimSpace(provider)
	apiKey = strings.TrimSpace(apiKey)
	groupID = strings.TrimSpace(groupID)
	switch provider {
	case "", "deepseek", "minimax":
	default:
		return errors.New("unsupported provider")
	}
	if len(apiKey) > 4096 {
		return errors.New("api_key too long")
	}
	if len(groupID) > 256 {
		return errors.New("minimax_group_id too long")
	}
	if enabled {
		if provider == "" {
			return errors.New("provider is required when llm is enabled")
		}
		if provider == "minimax" && groupID == "" {
			return errors.New("minimax_group_id is required for minimax")
		}
		if apiKey == "" && !deleteKey {
			return nil
		}
	}
	return nil
}

// UserLLMHandler 处理 /api/user/llm 的 GET 和 POST 请求
func UserLLMHandler(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			GetUserLLMConfig(store)(w, r)
		case http.MethodPost:
			UpdateUserLLMConfig(store)(w, r)
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
}

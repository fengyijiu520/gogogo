package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"skill-scanner/internal/llm"
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
			"enabled":   false,
			"provider":  "",
			"providers": store.ListLLMProviders(false),
		}
		if config != nil {
			resp["enabled"] = config.Enabled
			resp["provider"] = config.Provider
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
			Enabled   bool   `json:"enabled"`
			Provider  string `json:"provider"`
			APIKey    string `json:"api_key"`
			DeleteKey bool   `json:"delete_key"`
		}
		if err := decodeStrictJSONBody(w, r, &req, 16<<10); err != nil {
			http.Error(w, "Invalid request", http.StatusBadRequest)
			return
		}
		if err := validateUserLLMRequest(store, req.Provider, req.Enabled, req.APIKey, req.DeleteKey); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		config := store.GetUserLLMConfig(sess.Username)
		if config == nil {
			config = &models.LLMConfig{}
		}

		config.Enabled = req.Enabled
		config.Provider = strings.TrimSpace(req.Provider)
		switch {
		case req.DeleteKey:
			config.APIKey = ""
		case strings.TrimSpace(req.APIKey) != "":
			config.APIKey = strings.TrimSpace(req.APIKey)
		}

		if err := store.SaveUserLLMConfig(sess.Username, config); err != nil {
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	}
}

func validateUserLLMRequest(store *storage.Store, provider string, enabled bool, apiKey string, deleteKey bool) error {
	provider = strings.TrimSpace(provider)
	switch provider {
	case "":
	default:
		cfg, ok := store.GetLLMProvider(provider)
		if !ok || !cfg.Enabled {
			return errors.New("unsupported provider")
		}
	}
	if enabled {
		if provider == "" {
			return errors.New("provider is required when llm is enabled")
		}
		cfg, ok := store.GetLLMProvider(provider)
		if !ok || !cfg.Enabled {
			return errors.New("unsupported provider")
		}
		if strings.TrimSpace(apiKey) == "" && (deleteKey || strings.TrimSpace(cfg.APIKey) == "") {
			return errors.New("api key is required when llm is enabled")
		}
	}
	return nil
}

func resolveUserLLMProviderConfig(store *storage.Store, userLLM *models.LLMConfig) (*storage.LLMProviderConfig, bool) {
	if store == nil || userLLM == nil || !userLLM.Enabled {
		return nil, false
	}
	provider, ok := store.GetLLMProvider(userLLM.Provider)
	if !ok || !provider.Enabled {
		return nil, false
	}
	if strings.TrimSpace(userLLM.APIKey) != "" {
		provider.APIKey = strings.TrimSpace(userLLM.APIKey)
	}
	if strings.TrimSpace(provider.APIKey) == "" {
		return nil, false
	}
	return provider, true
}

type llmProviderRequest struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Protocol string `json:"protocol"`
	BaseURL  string `json:"base_url"`
	Model    string `json:"model"`
	APIKey   string `json:"api_key"`
	Enabled  bool   `json:"enabled"`
}

func llmProvidersHandler(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		user := store.GetUser(sess.Username)
		if user == nil || !user.HasPermission(models.PermUserManagement) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		switch r.Method {
		case http.MethodGet:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{"providers": store.ListLLMProviders(true)})
		case http.MethodPost:
			var req llmProviderRequest
			if err := decodeStrictJSONBody(w, r, &req, 32<<10); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			provider := storage.LLMProviderConfig{ID: req.ID, Name: req.Name, Protocol: req.Protocol, BaseURL: req.BaseURL, Model: req.Model, APIKey: req.APIKey, Enabled: req.Enabled}
			ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
			defer cancel()
			testCfg := &llm.ProviderConfig{Name: provider.Name, Protocol: provider.Protocol, BaseURL: provider.BaseURL, Model: provider.Model, APIKey: provider.APIKey}
			if err := llm.TestProvider(ctx, testCfg); err != nil {
				sendJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
				return
			}
			// TestProvider 可能修正了 URL（如自动补全 /v1），用修正后的 URL
			provider.BaseURL = testCfg.BaseURL
			provider.Enabled = true
			if err := store.SaveLLMProvider(provider); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		case http.MethodPatch:
			var req struct {
				ID      string `json:"id"`
				Enabled bool   `json:"enabled"`
			}
			if err := decodeStrictJSONBody(w, r, &req, 4<<10); err != nil {
				http.Error(w, "Invalid request", http.StatusBadRequest)
				return
			}
			if err := store.SetLLMProviderEnabled(req.ID, req.Enabled); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
		default:
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		}
	}
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

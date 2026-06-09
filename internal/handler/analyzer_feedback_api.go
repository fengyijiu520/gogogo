package handler

import (
	"net/http"
	"strings"

	"skill-scanner/internal/analyzer"
	"skill-scanner/internal/storage"
)

type analyzerFeedbackRequest struct {
	RuleID string   `json:"rule_id"`
	Tokens []string `json:"tokens"`
}

func analyzerFeedbackAPI(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodPost) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录"})
			return
		}
		if r.Method == http.MethodGet {
			sendJSON(w, http.StatusOK, map[string]interface{}{"items": store.AnalyzerFalsePositiveFeedback()})
			return
		}
		var req analyzerFeedbackRequest
		if err := decodeStrictJSONBody(w, r, &req, 64<<10); err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "请求体格式错误"})
			return
		}
		req.RuleID = strings.TrimSpace(req.RuleID)
		if req.RuleID == "" || len(req.Tokens) == 0 {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "rule_id 和 tokens 不能为空"})
			return
		}
		tokens := make([]string, 0, len(req.Tokens))
		for _, t := range req.Tokens {
			t = strings.TrimSpace(t)
			if t != "" {
				tokens = append(tokens, t)
			}
		}
		if len(tokens) == 0 {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "tokens 不能为空"})
			return
		}
		for _, token := range tokens {
			if err := store.AddAnalyzerFalsePositiveFeedback(req.RuleID, token); err != nil {
				sendJSON(w, http.StatusInternalServerError, map[string]string{"error": "保存反馈失败"})
				return
			}
		}
		analyzer.LearnFalsePositives(req.RuleID, tokens)
		sendJSON(w, http.StatusOK, map[string]interface{}{
			"status":  "ok",
			"rule_id": req.RuleID,
			"tokens":  tokens,
		})
	}
}

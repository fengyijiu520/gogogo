package handler

import (
	"net/http"
	"path/filepath"
	"strings"
)

func scanTaskStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead, http.MethodPost) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录"})
			return
		}
		path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/scan/tasks/"), "/")
		isCancel := strings.HasSuffix(path, "/cancel")
		if isCancel {
			path = strings.TrimSuffix(path, "/cancel")
		}
		taskID := filepath.Base(path)
		if taskID == "" || taskID == "/" {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "无效任务ID"})
			return
		}
		if r.Method == http.MethodPost && isCancel {
			ok, message := taskStore.cancel(taskID, sess.Username)
			if !ok {
				status := http.StatusNotFound
				if strings.Contains(message, "无权") {
					status = http.StatusForbidden
				}
				sendJSON(w, status, map[string]string{"error": message})
				return
			}
			sendJSON(w, http.StatusOK, map[string]interface{}{"success": true, "message": message})
			return
		}
		if r.Method == http.MethodPost {
			w.Header().Set("Allow", "GET, HEAD, POST")
			sendJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "Method not allowed"})
			return
		}
		task := taskStore.get(taskID)
		if task == nil {
			sendJSON(w, http.StatusNotFound, map[string]string{"error": "任务不存在"})
			return
		}
		if task.Owner != sess.Username {
			sendJSON(w, http.StatusForbidden, map[string]string{"error": "无权访问此任务"})
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if task.ID != "" {
			w.Header().Set("X-Task-Id", task.ID)
		}
		if task.RequestID != "" {
			w.Header().Set("X-Request-Id", task.RequestID)
		}
		sendJSON(w, http.StatusOK, task)
	}
}

package handler

import (
	"net/http"
	"path/filepath"
)

func scanTaskStatus() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录"})
			return
		}
		taskID := filepath.Base(r.URL.Path)
		if taskID == "" || taskID == "/" {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": "无效任务ID"})
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
		sendJSON(w, http.StatusOK, task)
	}
}

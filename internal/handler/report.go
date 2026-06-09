package handler

import (
	"archive/zip"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	admissionstore "skill-scanner/internal/admission/store"
	"skill-scanner/internal/models"
	"skill-scanner/internal/review"
	"skill-scanner/internal/storage"
)

type reportEntry struct {
	ID              string
	TaskID          string
	RequestID       string
	FileName        string
	Username        string
	CreatedAt       string
	Status          string
	StatusLabel     string
	Decision        string
	HasHTML         bool
	HasPDF          bool
	CanDelete       bool
	FindingCount    int
	HighRisk        int
	MediumRisk      int
	LowRisk         int
	NoRisk          bool
	Imported        bool
	ImportedSkillID string
	DecisionHint    string
}

type reportsPageData struct {
	Username     string
	Reports      []reportEntry
	RunningTasks []runningTaskEntry
	TaskID       string
	RequestID    string
	IsAdmin      bool
	HasPersonal  bool
	HasUserMgmt  bool
	HasLogPerm   bool
	Notice       string
	Error        string
}

type runningTaskEntry struct {
	ID          string
	RequestID   string
	FileName    string
	CreatedAt   string
	UpdatedAt   string
	StatusLabel string
	Message     string
}

func reportDecisionHint(store *storage.Store, rep *models.Report) string {
	if store == nil || rep == nil {
		return ""
	}
	jsonName := strings.TrimSpace(rep.JSONPath)
	if jsonName == "" {
		return ""
	}
	path := filepath.Join(store.ReportsDir(), filepath.Base(jsonName))
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(data, &payload); err != nil {
		return ""
	}
	summary, _ := payload["summary_cn"].(map[string]interface{})
	narrative, _ := summary["closure_narrative"].(string)
	narrative = strings.TrimSpace(narrative)
	if narrative == "" {
		return ""
	}
	return narrative
}

type reportDownloadTarget struct {
	targetPath    string
	downloadName  string
	contentType   string
	failedMessage string
	statusCode    int
	useZip        bool // 是否打包为 zip
}

// listReports shows all reports accessible to the current user.
func listReports(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		user := store.GetUser(sess.Username)
		if user == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		reports := store.ListReports(sess.Username)
		taskIDFilter := strings.TrimSpace(r.URL.Query().Get("task_id"))
		requestIDFilter := strings.TrimSpace(r.URL.Query().Get("request_id"))
		skillStore, _ := admissionstore.NewSkillStore(store.DataDir())

		sort.Slice(reports, func(i, j int) bool {
			return reports[i].CreatedAt > reports[j].CreatedAt
		})

		var entries []reportEntry
		for _, rep := range reports {
			if taskIDFilter != "" && !strings.Contains(strings.ToLower(strings.TrimSpace(rep.TaskID)), strings.ToLower(taskIDFilter)) {
				continue
			}
			if requestIDFilter != "" && !strings.Contains(strings.ToLower(strings.TrimSpace(rep.RequestID)), strings.ToLower(requestIDFilter)) {
				continue
			}
			importedSkillID := ""
			if skillStore != nil {
				if skill, ok := skillStore.GetByReportID(rep.ID); ok && skill != nil {
					importedSkillID = skill.SkillID
				}
			}
			entries = append(entries, reportEntry{
				ID:              rep.ID,
				TaskID:          rep.TaskID,
				RequestID:       strings.TrimSpace(rep.RequestID),
				FileName:        rep.FileName,
				Username:        rep.Username,
				CreatedAt:       time.Unix(rep.CreatedAt, 0).Format("2006-01-02 15:04:05"),
				Status:          rep.Status,
				StatusLabel:     localizeReportStatus(rep.Status),
				Decision:        localizeDecisionLabel(rep.Decision),
				HasHTML:         strings.TrimSpace(rep.HTMLPath) != "",
				HasPDF:          strings.TrimSpace(rep.PDFPath) != "",
				CanDelete:       store.CanDeleteReport(sess.Username, rep.ID),
				FindingCount:    rep.FindingCount,
				HighRisk:        rep.HighRisk,
				MediumRisk:      rep.MediumRisk,
				LowRisk:         rep.LowRisk,
				NoRisk:          rep.NoRisk,
				Imported:        importedSkillID != "",
				ImportedSkillID: importedSkillID,
				DecisionHint:    reportDecisionHint(store, rep),
			})
		}

		runningTasks := make([]runningTaskEntry, 0)
		for _, task := range taskStore.list(sess.Username) {
			if task.Status == review.PhaseDone || task.Status == review.PhaseFailed {
				continue
			}
			runningTasks = append(runningTasks, runningTaskEntry{
				ID:          task.ID,
				RequestID:   strings.TrimSpace(task.RequestID),
				FileName:    task.FileName,
				CreatedAt:   time.Unix(task.CreatedAt, 0).Format("2006-01-02 15:04:05"),
				UpdatedAt:   time.Unix(task.UpdatedAt, 0).Format("2006-01-02 15:04:05"),
				StatusLabel: localizeReportStatus(string(task.Status)),
				Message:     strings.TrimSpace(task.Message),
			})
		}

		modelStatus, modelError, modelErrMsg := GetModelStatus()
		notice := ""
		errMsg := ""
		switch strings.TrimSpace(r.URL.Query().Get("report_status")) {
		case "deleted":
			notice = "报告已删除。"
		case "delete_failed":
			errMsg = "报告删除失败，请重试。"
		}
		render(w, tmplReports, map[string]interface{}{
			"Username":     sess.Username,
			"Reports":      entries,
			"RunningTasks": runningTasks,
			"TaskID":       taskIDFilter,
			"RequestID":    requestIDFilter,
			"IsAdmin":      user.Role == models.RoleAdmin,
			"HasPersonal":  user.HasPermission(models.PermPersonalCenter),
			"HasUserMgmt":  user.HasPermission(models.PermUserManagement),
			"HasLogPerm":   user.HasPermission(models.PermLoginLog),
			"Notice":       notice,
			"Error":        errMsg,
			"ModelStatus":  modelStatus,
			"ModelError":   modelError,
			"ModelErrMsg":  modelErrMsg,
		})
	}
}

func deleteReport(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodPost) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		reportID := filepath.Base(r.URL.Path)
		if reportID == "" || reportID == "/" {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}
		if reportID != filepath.Clean(reportID) {
			http.Error(w, "无效的报告ID", http.StatusBadRequest)
			return
		}
		if !store.CanDeleteReport(sess.Username, reportID) {
			http.Error(w, "无权删除此报告", http.StatusForbidden)
			return
		}
		if err := store.DeleteReport(sess.Username, reportID); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "报告不存在", http.StatusNotFound)
				return
			}
			if strings.Contains(err.Error(), "permission denied") {
				http.Error(w, "无权删除此报告", http.StatusForbidden)
				return
			}
			http.Redirect(w, r, "/reports?report_status=delete_failed", http.StatusFound)
			return
		}
		http.Redirect(w, r, "/reports?report_status=deleted", http.StatusFound)
	}
}

// viewReport serves a stored HTML report inline after authorization checks.
func viewReport(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		reportID := filepath.Base(r.URL.Path)
		if reportID == "" || reportID == "/" {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}
		if reportID != filepath.Clean(reportID) {
			http.Error(w, "无效的报告ID", http.StatusBadRequest)
			return
		}

		rep := store.GetReport(reportID)
		if rep == nil {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}
		if !store.CanAccessReport(sess.Username, reportID) {
			http.Error(w, "无权访问此报告", http.StatusForbidden)
			return
		}
		if strings.TrimSpace(rep.HTMLPath) == "" {
			http.Error(w, "该报告暂不支持在线查看", http.StatusNotFound)
			return
		}
		if !storage.IsPathSafe(store.ReportsDir(), rep.HTMLPath) {
			http.Error(w, "无效的报告路径", http.StatusBadRequest)
			return
		}

		filePath := filepath.Join(store.ReportsDir(), rep.HTMLPath)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			http.Error(w, "报告文件不存在", http.StatusNotFound)
			return
		}
		htmlData, err := os.ReadFile(filePath)
		if err != nil {
			http.Error(w, "读取报告文件失败", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Disposition", "inline")
		w.Header().Set("Content-Security-Policy", reportContentSecurityPolicy)
		_, _ = w.Write(injectInlineReportToolbar(htmlData, rep))
	}
}

func injectInlineReportToolbar(htmlData []byte, rep *models.Report) []byte {
	htmlText := string(htmlData)
	metaParts := make([]string, 0, 2)
	if rep != nil && strings.TrimSpace(rep.TaskID) != "" {
		metaParts = append(metaParts, "任务 "+rep.TaskID)
	}
	if rep != nil && strings.TrimSpace(rep.RequestID) != "" {
		metaParts = append(metaParts, "请求 "+rep.RequestID)
	}
	toolbar := `<div id="inline-report-toolbar" style="position:sticky;top:0;z-index:9999;padding:10px 16px;background:rgba(18,26,44,.95);color:#fff;display:flex;gap:10px;align-items:center;flex-wrap:wrap;font-family:'Microsoft YaHei','PingFang SC',Segoe UI,Arial,sans-serif"><a href="/reports" style="display:inline-block;padding:7px 12px;border-radius:8px;background:#2156d1;color:#fff;text-decoration:none;font-size:13px;font-weight:600">返回报告列表</a><a href="/scan" style="display:inline-block;padding:7px 12px;border-radius:8px;background:#344054;color:#fff;text-decoration:none;font-size:13px;font-weight:600">返回扫描页</a><a href="/admission/skills" style="display:inline-block;padding:7px 12px;border-radius:8px;background:#0f766e;color:#fff;text-decoration:none;font-size:13px;font-weight:600">进入准入库</a><a href="/combination/overview" style="display:inline-block;padding:7px 12px;border-radius:8px;background:#7c3aed;color:#fff;text-decoration:none;font-size:13px;font-weight:600">进入组合分析</a><span style="opacity:.8;font-size:12px">在线查看模式</span>`
	if len(metaParts) > 0 {
		toolbar += `<span style="opacity:.9;font-size:12px">` + strings.Join(metaParts, " · ") + `</span>`
	}
	toolbar += `</div>`
	if strings.Contains(strings.ToLower(htmlText), "<body") {
		if idx := strings.Index(strings.ToLower(htmlText), ">"); idx >= 0 {
			// Find the end of the first <body ...> tag.
			bodyStart := strings.Index(strings.ToLower(htmlText), "<body")
			if bodyStart >= 0 {
				tagEnd := strings.Index(htmlText[bodyStart:], ">")
				if tagEnd >= 0 {
					insertAt := bodyStart + tagEnd + 1
					return []byte(htmlText[:insertAt] + toolbar + htmlText[insertAt:])
				}
			}
		}
	}
	return []byte(toolbar + htmlText)
}

func resolveReportDownloadTarget(rep *models.Report, format string) reportDownloadTarget {
	baseName := sanitizeDownloadFilename(rep.FileName, "skill-scan-report")
	target := reportDownloadTarget{
		targetPath:   rep.FilePath,
		downloadName: baseName + ".docx",
		contentType:  "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	}
	switch format {
	case "html":
		if rep.HTMLPath == "" {
			target.failedMessage = "该报告不支持 HTML 下载"
			target.statusCode = http.StatusNotFound
			return target
		}
		target.targetPath = rep.HTMLPath
		target.downloadName = baseName + ".html.zip"
		target.contentType = "application/zip"
		target.useZip = true
	case "json":
		if rep.JSONPath == "" {
			target.failedMessage = "该报告不支持 JSON 下载"
			target.statusCode = http.StatusNotFound
			return target
		}
		target.targetPath = rep.JSONPath
		target.downloadName = baseName + ".json"
		target.contentType = "application/json"
	case "pdf":
		if rep.PDFPath == "" {
			errMsg := strings.TrimSpace(rep.PDFError)
			if errMsg == "" {
				errMsg = "PDF 生成失败，当前报告无可下载的 PDF 文件"
			}
			target.failedMessage = "PDF 下载失败: " + errMsg
			target.statusCode = http.StatusFailedDependency
			return target
		}
		target.targetPath = rep.PDFPath
		target.downloadName = baseName + ".pdf"
		target.contentType = "application/pdf"
	}
	return target
}

func localizeDecisionLabel(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "userdecisionrequired", "user_decision_required":
		return "待用户基于证据判断"
	case "pass":
		return "系统建议通过，仍需用户确认"
	case "review":
		return "需人工复核"
	case "block":
		return "需完成修复并复测"
	default:
		return v
	}
}

func localizeReportStatus(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "completed", "done", "success":
		return "已完成"
	case "running", "processing", "queued":
		return "进行中"
	case "failed", "error":
		return "失败"
	default:
		return defaultIfEmpty(v, "未知")
	}
}

// downloadReport serves a report .docx file after checking authorization.
func downloadReport(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		reportID := filepath.Base(r.URL.Path)
		if reportID == "" || reportID == "/" {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}

		// ID must be a clean path segment — no traversal characters.
		if reportID != filepath.Clean(reportID) {
			http.Error(w, "无效的报告ID", http.StatusBadRequest)
			return
		}

		rep := store.GetReport(reportID)
		if rep == nil {
			http.Error(w, "报告不存在", http.StatusNotFound)
			return
		}

		// Authorization using team-aware access check.
		if !store.CanAccessReport(sess.Username, reportID) {
			http.Error(w, "无权访问此报告", http.StatusForbidden)
			return
		}

		format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
		target := resolveReportDownloadTarget(rep, format)
		if target.failedMessage != "" {
			http.Error(w, target.failedMessage, target.statusCode)
			return
		}

		w.Header().Set("Cache-Control", "no-store")
		// 所有格式都设置为下载（包括 HTML）
		w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(target.downloadName))
		w.Header().Set("Content-Type", target.contentType)
		if strings.TrimSpace(rep.TaskID) != "" {
			w.Header().Set("X-Task-Id", strings.TrimSpace(rep.TaskID))
		}
		if strings.TrimSpace(rep.RequestID) != "" {
			w.Header().Set("X-Request-Id", strings.TrimSpace(rep.RequestID))
		}
		if !storage.IsPathSafe(store.ReportsDir(), target.targetPath) {
			http.Error(w, "无效的报告路径", http.StatusBadRequest)
			return
		}
		filePath := filepath.Join(store.ReportsDir(), target.targetPath)
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			http.Error(w, "报告文件不存在", http.StatusNotFound)
			return
		}
		if target.useZip {
			serveFileAsZip(w, r, filePath, filepath.Base(target.downloadName))
			return
		}
		http.ServeFile(w, r, filePath)
	}
}

// serveFileAsZip 将单个文件打包为 zip 返回，避免 Chrome 阻止 HTML/JS 等文件下载
func serveFileAsZip(w http.ResponseWriter, r *http.Request, filePath, zipName string) {
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", "attachment; filename="+strconv.Quote(zipName))

	zipWriter := zip.NewWriter(w)
	defer zipWriter.Close()

	file, err := os.Open(filePath)
	if err != nil {
		http.Error(w, "无法打开报告文件", http.StatusInternalServerError)
		return
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		http.Error(w, "无法读取文件信息", http.StatusInternalServerError)
		return
	}

	header, err := zip.FileInfoHeader(info)
	if err != nil {
		http.Error(w, "无法创建 zip 头", http.StatusInternalServerError)
		return
	}
	header.Method = zip.Deflate

	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		http.Error(w, "无法创建 zip 条目", http.StatusInternalServerError)
		return
	}
	if _, err := io.Copy(writer, file); err != nil {
		// 无法写入响应头，只能记录日志
		return
	}
}

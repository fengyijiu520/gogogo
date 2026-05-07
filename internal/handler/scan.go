package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"golang.org/x/mod/modfile"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"skill-scanner/internal/analyzer"
	"skill-scanner/internal/config"
	"skill-scanner/internal/docx"
	"skill-scanner/internal/embedder"
	"skill-scanner/internal/evaluator"
	"skill-scanner/internal/llm"
	"skill-scanner/internal/models"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/storage"
	"strings"
	"time"
)

// -------- 全局嵌入器单例 --------
var (
	globalEmbedder    *embedder.BgeOnnxEmbedder
	embedderInitError error
	embedderModelName = "BGE-M3 (ONNX)"
)

const (
	maxUploadFiles           = 2000
	maxSingleUploadFileBytes = 10 << 20
	maxCustomRuleCount       = 64
	maxCustomRulePatterns    = 32
)

// InitEmbedder 在程序启动时调用一次，初始化 ONNX 嵌入器。
// 应在 main 函数中调用，并将结果传递给 handler 包。
func InitEmbedder() {
	log.Println("正在加载 BGE 嵌入器...")
	modelExists := false
	for _, modelDir := range config.BGEModelDirCandidates() {
		if _, err := os.Stat(filepath.Join(modelDir, "model.onnx")); err == nil {
			modelExists = true
			break
		}
	}
	if !modelExists {
		embedderInitError = fmt.Errorf("未找到可用 BGE 模型目录: %s", strings.Join(config.BGEModelDirCandidates(), ", "))
		log.Printf("⚠️ 本地模型文件不可访问，进入基础规则模式: %v", embedderInitError)
		embedderModelName = "基础规则 (本地模型不可用)"
		return
	}
	globalEmbedder, embedderInitError = embedder.NewBgeOnnxEmbedder()
	if embedderInitError != nil {
		log.Printf("❌ BGE 嵌入器初始化失败: %v", embedderInitError)
		embedderModelName = "基础规则 (模型加载失败)"
	} else {
		log.Println("✅ BGE 嵌入器初始化成功")
	}
}

// GetModelStatus 返回当前引擎状态，供模板渲染。
func GetModelStatus() (status string, hasError bool, errorMsg string) {
	if embedderInitError != nil {
		return embedderModelName, true, embedderInitError.Error()
	}
	if globalEmbedder == nil {
		return "基础规则 (未初始化)", true, "模型未初始化"
	}
	return "🔬 BGE-M3 语义引擎", false, ""
}

// scan handles the skill scanning page and report generation.
func scan(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := getSession(r)
		if sess == nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		user := store.GetUser(sess.Username)
		userPerms := map[string]bool{
			"HasPersonal": false,
			"HasUserMgmt": false,
			"HasLogPerm":  false,
		}
		if user != nil {
			userPerms["HasPersonal"] = user.HasPermission(models.PermPersonalCenter)
			userPerms["HasUserMgmt"] = user.HasPermission(models.PermUserManagement)
			userPerms["HasLogPerm"] = user.HasPermission(models.PermLoginLog)
		}
		// 获取引擎状态，注入到所有页面模板数据中
		modelStatus, modelError, modelErrMsg := GetModelStatus()
		if r.Method == http.MethodGet {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			render(w, tmplScan, map[string]interface{}{
				"Username":       sess.Username,
				"HasPersonal":    userPerms["HasPersonal"],
				"HasUserMgmt":    userPerms["HasUserMgmt"],
				"HasLogPerm":     userPerms["HasLogPerm"],
				"ModelStatus":    modelStatus,
				"ModelError":     modelError,
				"ModelErrMsg":    modelErrMsg,
				"RuntimeSummary": RuntimeSelfCheckSummary(),
			})
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if handleScanAsync(store, w, r, sess) {
			return
		}
		if err := ValidateScanPreflight(store, sess.Username); err != nil {
			sendJSON(w, http.StatusServiceUnavailable, map[string]interface{}{
				"error":      "扫描前置自检未通过",
				"details":    err.Error(),
				"suggestion": "请根据错误详情逐项修复后重试；如涉及 LLM，请先在个人中心完成配置。",
			})
			return
		}
		if err := r.ParseMultipartForm(100 << 20); err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]string{
				"error": "文件太大或解析失败",
			})
			return
		}
		files := r.MultipartForm.File["files"]
		if len(files) == 0 {
			sendJSON(w, http.StatusBadRequest, map[string]string{
				"error": "请上传至少一个文件",
			})
			return
		}
		if err := validateUploadedFiles(files); err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		// 原始名称取第一个文件名作为代表
		originalName := files[0].Filename
		if len(files) > 1 {
			originalName = fmt.Sprintf("%s 等 %d 个文件", originalName, len(files))
		}
		tmpDir, err := os.MkdirTemp("", "skill-scan-*")
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "创建临时目录失败",
			})
			return
		}
		defer os.RemoveAll(tmpDir)
		// 保存所有上传的文件（支持文件夹内多文件）
		for _, fh := range files {
			if fh.Size == 0 {
				continue
			}
			if !isSafeFilename(fh.Filename) {
				sendJSON(w, http.StatusBadRequest, map[string]string{
					"error": "不支持的文件名",
				})
				return
			}
			// 保留相对路径结构（对于文件夹上传，浏览器会提供带路径的文件名）
			relPath := filepath.Clean(fh.Filename)
			destPath := filepath.Join(tmpDir, relPath)
			// 安全检查
			if !storage.IsPathSafe(tmpDir, relPath) {
				sendJSON(w, http.StatusBadRequest, map[string]string{
					"error": "文件路径不安全",
				})
				return
			}
			// 创建父目录
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				sendJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "创建目录失败",
				})
				return
			}
			src, err := fh.Open()
			if err != nil {
				sendJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "读取文件失败",
				})
				return
			}
			dst, err := os.Create(destPath)
			if err != nil {
				src.Close()
				sendJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "保存文件失败",
				})
				return
			}
			_, err = io.Copy(dst, src)
			src.Close()
			dst.Close()
			if err != nil {
				sendJSON(w, http.StatusInternalServerError, map[string]string{
					"error": "写入文件失败",
				})
				return
			}
		}
		// 安全性校验
		if err := validateExtractedFiles(tmpDir); err != nil {
			sendJSON(w, http.StatusBadRequest, map[string]string{
				"error": err.Error(),
			})
			return
		}
		// 初始化扫描结果
		var findings []plugins.Finding
		var evalResult *evaluator.EvaluationResult
		// 读取表单中的技能描述和权限
		description := r.FormValue("description")
		description = resolveSkillDescription(description, tmpDir)
		permissionsStr := r.FormValue("permissions")
		permissions := []string{}
		if permissionsStr != "" {
			for _, p := range strings.Split(permissionsStr, ",") {
				if p = strings.TrimSpace(p); p != "" {
					permissions = append(permissions, p)
				}
			}
		}
		// 使用全局嵌入器（如果可用）
		if globalEmbedder != nil && embedderInitError == nil {
			cfg, err := config.Load(config.RulesConfigPath())
			if err != nil {
				log.Printf("加载规则配置失败，使用默认内嵌规则: %v", err)
				// 可降级使用原 Evaluator，此处简单处理
				cfg = getDefaultConfig() // 需实现一个兜底配置
			}
			var llmClient llm.Client
			// 使用当前用户的 LLM 配置
			user := store.GetUser(sess.Username)
			if user != nil {
				userLLM := store.GetUserLLMConfig(sess.Username)
				if userLLM != nil && userLLM.Enabled && userLLM.APIKey != "" {
					switch userLLM.Provider {
					case "deepseek":
						llmClient = llm.NewDeepSeekClient(userLLM.APIKey)
						log.Printf("用户 %s 启用了 DeepSeek LLM 分析", sess.Username)
					case "minimax":
						if userLLM.MiniMaxGroupID != "" {
							llmClient = llm.NewMiniMaxClient(userLLM.MiniMaxGroupID, userLLM.APIKey)
							log.Printf("用户 %s 启用了 MiniMax LLM 分析", sess.Username)
						}
					}
				}
			}
			if llmClient == nil {
				sendJSON(w, http.StatusServiceUnavailable, map[string]string{
					"error": "LLM 功能未启用，已阻断扫描，请在个人中心配置可用的 LLM 后重试",
				})
				return
			}
			eval := evaluator.NewEvaluator(globalEmbedder, llmClient, cfg)
			// 收集代码和依赖信息
			var files []evaluator.SourceFile
			var dependencies []evaluator.Dependency
			var codeAnalysis *analyzer.CodeAnalysisResult
			filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
				if err != nil || info.IsDir() {
					return nil
				}
				ext := strings.ToLower(filepath.Ext(path))
				lang := ""
				switch ext {
				case ".md":
					base := strings.ToLower(filepath.Base(path))
					if base != "skill.md" && base != "readme.md" && base != "description.md" && base != "manifest.md" {
						return nil
					}
					lang = "markdown"
				case ".go":
					lang = "go"
				case ".js":
					lang = "javascript"
				case ".ts":
					lang = "typescript"
				case ".py":
					lang = "python"
				default:
					return nil // 跳过不支持的语言
				}
				data, err := os.ReadFile(path)
				if err != nil {
					return nil
				}
				content := string(data)
				file := evaluator.BuildSourceFile(r.Context(), llmClient, path, content, lang)
				files = append(files, file)
				// 静态分析每个文件，累积结果（用于可能的降级展示）
				var fileAnalysis *analyzer.CodeAnalysisResult
				analysisContent := file.AnalysisContent()
				if lang == "go" {
					fileAnalysis = analyzer.AnalyzeGoCode(analysisContent, path)
				} else if lang == "javascript" || lang == "typescript" {
					fileAnalysis = analyzer.AnalyzeJavaScriptCode(analysisContent, path)
				}
				if fileAnalysis != nil {
					if codeAnalysis == nil {
						codeAnalysis = fileAnalysis
					} else {
						codeAnalysis.DangerousCalls = append(codeAnalysis.DangerousCalls, fileAnalysis.DangerousCalls...)
						codeAnalysis.HasHardcoded = codeAnalysis.HasHardcoded || fileAnalysis.HasHardcoded
					}
				}
				// 解析 go.mod
				if filepath.Base(path) == "go.mod" {
					deps, err := parseGoMod(content)
					if err == nil {
						dependencies = append(dependencies, deps...)
					}
				}
				// 解析 package.json
				if filepath.Base(path) == "package.json" {
					var pkg struct {
						Dependencies map[string]string `json:"dependencies"`
					}
					if json.Unmarshal(data, &pkg) == nil {
						for name, version := range pkg.Dependencies {
							dependencies = append(dependencies, evaluator.Dependency{
								Name:    name,
								Version: version,
							})
						}
					}
				}
				return nil
			})
			// 依赖去重（简单实现）
			depMap := make(map[string]evaluator.Dependency)
			for _, dep := range dependencies {
				key := dep.Name + "@" + dep.Version
				if _, exists := depMap[key]; !exists {
					depMap[key] = dep
				}
			}
			dependencies = make([]evaluator.Dependency, 0, len(depMap))
			for _, dep := range depMap {
				dependencies = append(dependencies, dep)
			}
			skill := &evaluator.Skill{
				Name:         originalName,
				Description:  description,
				Code:         "", // 不再使用单一字符串
				Files:        files,
				Dependencies: dependencies,
				Permissions:  permissions,
			}
			evalResult, err = eval.EvaluateWithCascade(context.Background(), skill)
			if err == nil {
				if evalResult.IntentAnalysis == nil {
					sendJSON(w, http.StatusServiceUnavailable, map[string]string{
						"error": "LLM 意图分析未返回有效结果，已阻断扫描，请检查 LLM 配置、网络和服务可用性后重试",
					})
					return
				}
				findings = convertResultToFindings(evalResult, cfg)
			} else {
				sendJSON(w, http.StatusServiceUnavailable, map[string]string{
					"error": "级联评估执行失败，已阻断扫描，请修复评估引擎后重试: " + err.Error(),
				})
				return
			}
		} else {
			sendJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "语义引擎不可用，已阻断扫描，请启用并修复语义模型后重试",
			})
			return
		}
		// 生成报告
		reportFile := filepath.Join(tmpDir, "report.docx")
		gen := docx.NewGenerator()
		modelStatus, _, _ = GetModelStatus()
		llmEnabled := os.Getenv("DEEPSEEK_API_KEY") != "" // 简单判断
		score := 100.0
		if evalResult != nil {
			score = evalResult.Score
		}
		if err := gen.Generate(findings, score, modelStatus, llmEnabled, reportFile); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "生成报告失败",
			})
			return
		}
		reportID, err := storage.GenerateID()
		if err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "生成报告ID失败",
			})
			return
		}
		reportCreatedAt := time.Now()
		reportBaseName := buildReportBaseName(originalName, reportCreatedAt)
		reportFileName := reportBaseName + ".docx"
		reportDest := filepath.Join(store.ReportsDir(), reportFileName)
		if err := copyFile(reportFile, reportDest); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "保存报告失败",
			})
			return
		}
		high, medium, low := 0, 0, 0
		for _, f := range findings {
			switch f.Severity {
			case "高风险":
				high++
			case "中风险":
				medium++
			default:
				low++
			}
		}
		user = store.GetUser(sess.Username)
		team := ""
		if user != nil {
			team = user.Team
		}
		rep := &models.Report{
			ID:           reportID,
			Username:     sess.Username,
			Team:         team,
			FileName:     reportBaseName,
			FilePath:     reportFileName,
			CreatedAt:    reportCreatedAt.Unix(),
			FindingCount: len(findings),
			HighRisk:     high,
			MediumRisk:   medium,
			LowRisk:      low,
			NoRisk:       len(findings) == 0,
		}
		if err := store.AddReport(rep); err != nil {
			sendJSON(w, http.StatusInternalServerError, map[string]string{
				"error": "保存报告记录失败",
			})
			return
		}
		sendJSON(w, http.StatusOK, map[string]interface{}{
			"success":       true,
			"report_id":     reportID,
			"finding_count": len(findings),
		})
	}
}

// -------- File handling helpers --------
func isSafeFilename(name string) bool {
	clean := filepath.Clean(name)
	return !strings.Contains(clean, "..") &&
		!strings.Contains(name, "\x00") &&
		clean != "" && clean != "."
}

func validateUploadedFiles(files []*multipart.FileHeader) error {
	if len(files) == 0 {
		return fmt.Errorf("请上传至少一个文件")
	}
	if len(files) > maxUploadFiles {
		return fmt.Errorf("上传文件数量过多，最多允许 %d 个", maxUploadFiles)
	}
	for _, fh := range files {
		if fh == nil {
			return fmt.Errorf("存在无效文件")
		}
		if fh.Size < 0 || fh.Size > maxSingleUploadFileBytes {
			return fmt.Errorf("文件 %s 超出大小限制，单文件最大 %d MB", fh.Filename, maxSingleUploadFileBytes>>20)
		}
		if !isSafeFilename(fh.Filename) {
			return fmt.Errorf("不支持的文件名")
		}
	}
	return nil
}
func validateExtractedFiles(tmpDir string) error {
	var validationErrors []error
	walkErr := filepath.Walk(tmpDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("failed to access path %s: %w", path, err))
			return filepath.SkipDir
		}
		if info.IsDir() {
			return nil
		}
		relPath, err := filepath.Rel(tmpDir, path)
		if err != nil {
			validationErrors = append(validationErrors, fmt.Errorf("directory traversal detected: invalid path %s, %w", path, err))
			return filepath.SkipDir
		}
		if strings.HasPrefix(relPath, "..") || strings.Contains(relPath, "/../") || !storage.IsPathSafe(tmpDir, relPath) {
			validationErrors = append(validationErrors, fmt.Errorf("directory traversal detected: malicious path %s", path))
			return filepath.SkipDir
		}
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("failed to walk extracted directory: %w", walkErr)
	}
	if len(validationErrors) > 0 {
		return fmt.Errorf("file validation failed: %v", validationErrors)
	}
	return nil
}
func copyFile(src, dst string) error {
	srcF, err := os.Open(src)
	if err != nil {
		return err
	}
	defer srcF.Close()
	dstF, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	defer dstF.Close()
	_, err = io.Copy(dstF, srcF)
	return err
}
func runPlugins(scanPath string) []plugins.Finding {
	ctx := context.Background()
	registry := plugins.DefaultRegistry()
	return plugins.ExecuteAll(ctx, scanPath, registry.BuildWithFilter(config.EnabledPlugins(), config.DisabledPlugins()))
}
func parseGoMod(content string) ([]evaluator.Dependency, error) {
	f, err := modfile.Parse("go.mod", []byte(content), nil)
	if err != nil {
		return nil, err
	}
	var deps []evaluator.Dependency
	for _, r := range f.Require {
		deps = append(deps, evaluator.Dependency{
			Name:    r.Mod.Path,
			Version: r.Mod.Version,
		})
	}
	return deps, nil
}
func convertResultToFindings(result *evaluator.EvaluationResult, cfg *config.Config) []plugins.Finding {
	var findings []plugins.Finding

	// 1. 处理已有的 FindingDetails（这些已经带有精确位置）
	for _, detail := range result.FindingDetails {
		findings = append(findings, plugins.Finding{
			PluginName:  "SecurityEngine",
			RuleID:      detail.RuleID,
			Severity:    detail.Severity,
			Title:       detail.Title,
			Description: detail.Description,
			Location:    detail.Location,
			CodeSnippet: detail.CodeSnippet,
		})
	}

	// 2. 处理高风险阻断原因（仅添加未被覆盖的）
	existingRuleIDs := make(map[string]bool)
	for _, f := range findings {
		existingRuleIDs[f.RuleID] = true
	}

	// 2. 处理高风险阻断原因（仅添加未被覆盖的）
	if result.P0Blocked {
		// 收集已有描述的集合，用于去重
		existDesc := make(map[string]bool)
		for _, f := range findings {
			existDesc[f.Description] = true
		}
		for _, reason := range result.P0Reasons {
			// 跳过 LLM 生成的阻断原因
			if strings.HasPrefix(reason, "LLM深度检测:") {
				continue
			}
			matchedRuleID := "V7-HIGH-RISK-BLOCK"
			matchedTitle := "高风险阻断项"
			if rule, ok := matchReasonToRule(cfg, reason); ok {
				matchedRuleID = rule.ID
				matchedTitle = rule.Name
				if existingRuleIDs[rule.ID] {
					continue
				}
			}
			// 描述去重
			if !existDesc[reason] {
				findings = append(findings, plugins.Finding{
					PluginName:  "SecurityEngine",
					RuleID:      matchedRuleID,
					Severity:    "高风险",
					Title:       matchedTitle,
					Description: reason,
					Location:    "规则阻断判定",
					CodeSnippet: "关键证据: " + reason,
				})
				existDesc[reason] = true
			}
		}
	}

	// 3. 静态分析中的危险调用
	if result.Analysis != nil {
		for _, call := range result.Analysis.DangerousCalls {
			location := ""
			if call.Line > 0 {
				location = fmt.Sprintf("行号: %d", call.Line)
			}
			findings = append(findings, plugins.Finding{
				PluginName:  "StaticAnalyzer",
				RuleID:      "DAN-001",
				Severity:    "中风险",
				Title:       fmt.Sprintf("危险函数调用: %s", call.Function),
				Description: fmt.Sprintf("类别: %s", call.Category),
				Location:    location,
				CodeSnippet: "",
			})
		}
		if result.Analysis.HasHardcoded {
			findings = append(findings, plugins.Finding{
				PluginName:  "StaticAnalyzer",
				RuleID:      "SEC-001",
				Severity:    "高风险",
				Title:       "发现硬编码凭证",
				Description: "代码中包含硬编码的密钥、密码等敏感信息",
				Location:    "",
			})
		}
	}

	return findings
}

func matchReasonToRule(cfg *config.Config, reason string) (config.Rule, bool) {
	reason = strings.TrimSpace(reason)
	for _, rule := range cfg.Rules {
		ruleName := strings.TrimSpace(rule.Name)
		onFail := strings.TrimSpace(rule.OnFail.Reason)
		if reason != "" && (reason == onFail || reason == ruleName+" 无补偿且未通过" || strings.HasPrefix(reason, ruleName+" ")) {
			return rule, true
		}
	}
	return config.Rule{}, false
}
func sendJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// getDefaultConfig 提供一个 V7 风险等级兜底配置，当配置文件加载失败时使用。
func getDefaultConfig() *config.Config {
	return &config.Config{
		Version: "7.0",
		RiskLevels: []config.RiskLevel{
			{Level: "低风险", AutoApprove: true, RequireReview: false, Block: false},
			{Level: "中风险", AutoApprove: false, RequireReview: true, Block: false},
			{Level: "高风险", AutoApprove: false, RequireReview: true, Block: true},
		},
		Rules: []config.Rule{
			{
				ID:       "V7-001",
				Name:     "恶意代码与破坏性行为",
				Severity: "高风险",
				Layer:    "P0",
				Detection: config.Detection{
					Type: "pattern",
					Patterns: []string{
						`(?i)rm\s+-rf\s+/`,
						`(?i)bash\s+-i\s+>&\s+/dev/tcp`,
						`(?i)(c2|beacon|command\s*and\s*control)`,
					},
				},
				OnFail: config.OnFail{
					Action: "block",
					Reason: "检测到恶意代码或破坏性行为",
				},
			},
			{
				ID:       "V7-006",
				Name:     "技能声明与实际行为一致性",
				Severity: "高风险",
				Layer:    "P0",
				Detection: config.Detection{
					Type: "llm_intent",
				},
				OnFail: config.OnFail{
					Action: "block",
					Reason: "技能声明与实际行为严重不一致",
				},
			},
			{
				ID:       "V7-008",
				Name:     "沙箱逃逸与提权风险",
				Severity: "高风险",
				Layer:    "P0",
				Detection: config.Detection{
					Type:     "function",
					Function: "detectEnvironmentEvasion",
				},
				OnFail: config.OnFail{
					Action: "block",
					Reason: "检测到沙箱逃逸、反分析或提权风险",
				},
			},
			{
				ID:       "V7-010",
				Name:     "依赖漏洞与恶意依赖",
				Severity: "高风险",
				Layer:    "P0",
				Detection: config.Detection{
					Type:     "function",
					Function: "evaluateDependencyVulns",
				},
				OnFail: config.OnFail{
					Action: "block",
					Reason: "检测到高危漏洞、恶意依赖或不可信依赖",
				},
			},
			{
				ID:       "V7-012",
				Name:     "权限声明与最小权限",
				Severity: "高风险",
				Layer:    "P0",
				Detection: config.Detection{
					Type:     "function",
					Function: "evaluatePermissions",
				},
				OnFail: config.OnFail{
					Action: "block",
					Reason: "检测到过度权限声明或最小权限缺失",
				},
			},
			{
				ID:       "V7-011",
				Name:     "动态指令注入与可执行上下文拼接",
				Severity: "高风险",
				Layer:    "P0",
				Detection: config.Detection{
					Type:     "function",
					Function: "evaluateInjectionRisk",
				},
				OnFail: config.OnFail{
					Action: "block",
					Reason: "检测到未防护的动态指令注入或可执行上下文拼接",
				},
			},
		},
	}
}

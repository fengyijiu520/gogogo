package handler

import (
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"skill-scanner/internal/config"
	"skill-scanner/internal/logx"
	"skill-scanner/internal/review/sandbox"
	"skill-scanner/internal/storage"
)

type componentCheck struct {
	Name     string
	Enabled  bool
	Required bool
	Ready    bool
	Message  string
}

type runtimeCheckReport struct {
	CheckedAt  time.Time
	Components []componentCheck
}

type runtimeStatusComponent struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Enabled     bool   `json:"enabled"`
	Required    bool   `json:"required"`
	Ready       bool   `json:"ready"`
	Message     string `json:"message"`
	Action      runtimeStatusAction `json:"action"`
}

type runtimeStatusAction struct {
	Label string `json:"label"`
	Href  string `json:"href"`
}

type runtimeStatusUserLLM struct {
	Enabled         bool   `json:"enabled"`
	Configured      bool   `json:"configured"`
	Required        bool   `json:"required"`
	Provider        string `json:"provider"`
	ProviderEnabled bool   `json:"provider_enabled"`
	Ready           bool   `json:"ready"`
	Message         string `json:"message"`
	Action          runtimeStatusAction `json:"action"`
}

type runtimeStatusPreflight struct {
	Ready    bool     `json:"ready"`
	Failures []string `json:"failures"`
	Warnings []string `json:"warnings"`
}

type runtimeStatusResponse struct {
	CheckedAt   time.Time                `json:"checked_at"`
	CheckedAtText string                 `json:"checked_at_text"`
	Ready       bool                     `json:"ready"`
	Summary     string                   `json:"summary"`
	Components  []runtimeStatusComponent `json:"components"`
	UserLLM     runtimeStatusUserLLM     `json:"user_llm"`
	ScanPreview runtimeStatusPreflight   `json:"scan_preflight"`
}

type preflightAssessment struct {
	Failures []string
	Warnings []string
}

type scanPreflightValidation struct {
	Assessment preflightAssessment
	Err        error
}

var (
	runtimeCheckOnce   sync.Once
	runtimeCheckResult runtimeCheckReport
	runtimeCheckReady  bool
)

func InitRuntimeSelfCheck() {
	runtimeCheckOnce.Do(func() {
		runtimeCheckResult = runRuntimeSelfCheck()
		runtimeCheckReady = true
		logx.With("component", "runtime-self-check", "summary", RuntimeSelfCheckSummary()).Info("startup self-check completed")
	})
}

func RuntimeSelfCheckSummary() string {
	items := make([]string, 0, len(runtimeCheckResult.Components))
	for _, c := range runtimeCheckResult.Components {
		state := "正常"
		if !c.Ready {
			state = "未就绪"
		}
		items = append(items, fmt.Sprintf("%s：%s（%s）", localizeComponentName(c.Name), state, c.Message))
	}
	if len(items) == 0 {
		return "未执行自检"
	}
	return strings.Join(items, "；")
}

func ValidateScanPreflight(store *storage.Store, username string) error {
	result := validateScanPreflight(store, username)
	return result.Err
}

func validateScanPreflight(store *storage.Store, username string) scanPreflightValidation {
	assessment := assessScanPreflight(store, username)

	if len(assessment.Failures) == 0 {
		return scanPreflightValidation{Assessment: assessment}
	}

	all := append([]string{}, assessment.Failures...)
	if len(assessment.Warnings) > 0 {
		all = append(all, assessment.Warnings...)
	}
	return scanPreflightValidation{
		Assessment: assessment,
		Err:        fmt.Errorf("%s", strings.Join(all, "；")),
	}
}

func RuntimeStatusAPI(store *storage.Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethods(w, r, http.MethodGet, http.MethodHead) {
			return
		}
		sess := getSession(r)
		if sess == nil {
			sendJSON(w, http.StatusUnauthorized, map[string]string{"error": "未登录"})
			return
		}
		sendJSON(w, http.StatusOK, buildRuntimeStatusResponse(store, sess.Username))
	}
}

func BuildScanPreflightErrorResponse(store *storage.Store, username string, assessment preflightAssessment, err error) (string, string, runtimeStatusAction) {
	userLLM := buildRuntimeStatusUserLLM(store, username)
	if userLLM.Required && !userLLM.Ready {
		action := userLLM.Action
		if action.Href == "" {
			action = runtimeStatusAction{Label: "前往个人中心", Href: "/personal"}
		}
		return "当前账号未配置 LLM API Key", "请前往个人中心完成 LLM API Key 配置后重试。", action
	}
	for _, c := range runtimeCheckResult.Components {
		if !c.Required || c.Ready {
			continue
		}
		action := runtimeStatusComponentAction(c)
		if action.Href == "" {
			continue
		}
		if strings.HasPrefix(action.Href, "/runtime-help#") {
			return "扫描前置自检未通过", "请先完成运行环境修复，再重新提交扫描。", action
		}
		return "扫描前置自检未通过", "请根据页面提示完成配置后重试。", action
	}
	if len(assessment.Failures) > 0 {
		return "扫描前置自检未通过", "请根据错误详情逐项修复后重试。", runtimeStatusAction{}
	}
	if err != nil && strings.TrimSpace(err.Error()) != "" {
		return "扫描前置自检未通过", "请根据错误详情逐项修复后重试。", runtimeStatusAction{}
	}
	return "扫描前置自检未通过", "请检查运行环境与账号配置后重试。", runtimeStatusAction{}
}

func runRuntimeSelfCheck() runtimeCheckReport {
	report := runtimeCheckReport{CheckedAt: time.Now()}
	report.Components = append(report.Components, checkRuleRegexComponent())
	report.Components = append(report.Components, checkSandboxComponent())
	report.Components = append(report.Components, checkSemanticComponent())
	report.Components = append(report.Components, checkLLMComponent())
	return report
}

func buildRuntimeStatusResponse(store *storage.Store, username string) runtimeStatusResponse {
	assessment := assessScanPreflight(store, username)
	components := make([]runtimeStatusComponent, 0, len(runtimeCheckResult.Components))
	ready := runtimeCheckReady
	for _, c := range runtimeCheckResult.Components {
		components = append(components, runtimeStatusComponent{
			Name:        c.Name,
			DisplayName: localizeComponentName(c.Name),
			Enabled:     c.Enabled,
			Required:    c.Required,
			Ready:       c.Ready,
			Message:     c.Message,
			Action:      runtimeStatusComponentAction(c),
		})
		if c.Required && !c.Ready {
			ready = false
		}
	}
	userLLM := buildRuntimeStatusUserLLM(store, username)
	if userLLM.Required && !userLLM.Ready {
		ready = false
	}
	return runtimeStatusResponse{
		CheckedAt:    runtimeCheckResult.CheckedAt,
		CheckedAtText: formatRuntimeCheckedAt(runtimeCheckResult.CheckedAt),
		Ready:        ready && len(assessment.Failures) == 0,
		Summary:      RuntimeSelfCheckSummary(),
		Components:   components,
		UserLLM:      userLLM,
		ScanPreview: runtimeStatusPreflight{
			Ready:    len(assessment.Failures) == 0,
			Failures: append([]string{}, assessment.Failures...),
			Warnings: append([]string{}, assessment.Warnings...),
		},
	}
}

func formatRuntimeCheckedAt(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.Local().Format("2006-01-02 15:04:05")
}

func assessScanPreflight(store *storage.Store, username string) preflightAssessment {
	if !runtimeCheckReady {
		return preflightAssessment{Failures: []string{"系统启动自检未完成，请检查服务启动流程"}}
	}

	assessment := preflightAssessment{
		Failures: make([]string, 0),
		Warnings: make([]string, 0),
	}
	for _, c := range runtimeCheckResult.Components {
		if c.Ready {
			continue
		}
		name := localizeComponentName(c.Name)
		msg := fmt.Sprintf("%s 功能未启用，请检查 %s 功能是否正常", name, name)
		if c.Message != "" {
			msg = c.Message
		}
		if c.Required {
			assessment.Failures = append(assessment.Failures, msg)
			continue
		}
		assessment.Warnings = append(assessment.Warnings, msg)
	}

	userLLM := buildRuntimeStatusUserLLM(store, username)
	if userLLM.Required && !userLLM.Ready {
		assessment.Failures = append(assessment.Failures, "当前账号未配置 LLM API Key，请前往个人中心完成 LLM 配置")
	} else if !userLLM.Ready {
		assessment.Warnings = append(assessment.Warnings, "当前账号未配置 LLM API Key，可在个人中心配置后获得更完整分析")
	}
	return assessment
}

func buildRuntimeStatusUserLLM(store *storage.Store, username string) runtimeStatusUserLLM {
	status := runtimeStatusUserLLM{
		Required: isLLMRequired(),
		Enabled:  readBoolEnv("REVIEW_ENABLE_LLM", true),
		Action:   runtimeStatusAction{Label: "前往个人中心", Href: "/personal"},
	}
	if !status.Enabled {
		status.Message = "LLM 功能未启用，请检查 REVIEW_ENABLE_LLM"
		status.Action = runtimeStatusAction{Label: "前往设置页", Href: "/settings?tab=llm"}
		return status
	}
	if store == nil {
		status.Message = "存储未初始化，暂时无法检查用户 LLM 配置"
		return status
	}
	cfg := store.GetUserLLMConfig(username)
	if cfg == nil {
		status.Message = "当前账号未配置 LLM API Key，请前往个人中心完成 LLM 配置"
		return status
	}
	status.Configured = cfg.Enabled
	status.Provider = strings.TrimSpace(cfg.Provider)
	if !cfg.Enabled {
		status.Message = "当前账号未启用 LLM，请前往个人中心完成 LLM 配置"
		return status
	}
	provider, ok := store.GetLLMProvider(status.Provider)
	if !ok {
		status.Message = "当前账号的 LLM 提供商不存在，请检查个人中心配置"
		status.Action = runtimeStatusAction{Label: "前往个人中心", Href: "/personal"}
		return status
	}
	status.ProviderEnabled = provider.Enabled
	if !provider.Enabled {
		status.Message = "当前账号的 LLM 提供商未启用，请检查个人中心或管理后台配置"
		status.Action = runtimeStatusAction{Label: "前往设置页", Href: "/settings?tab=llm"}
		return status
	}
	if strings.TrimSpace(cfg.APIKey) == "" && strings.TrimSpace(provider.APIKey) == "" {
		status.Message = "当前账号未配置 LLM API Key，请前往个人中心完成 LLM 配置"
		return status
	}
	status.Ready = true
	status.Message = "当前账号 LLM 配置可用"
	status.Action = runtimeStatusAction{}
	return status
}

func runtimeStatusComponentAction(c componentCheck) runtimeStatusAction {
	if c.Ready {
		return runtimeStatusAction{}
	}
	switch strings.ToLower(strings.TrimSpace(c.Name)) {
	case "sandbox":
		return runtimeStatusAction{Label: "查看沙箱修复说明", Href: "/runtime-help#sandbox"}
	case "semantic":
		return runtimeStatusAction{Label: "查看语义引擎说明", Href: "/runtime-help#semantic"}
	case "llm":
		return runtimeStatusAction{Label: "前往设置页", Href: "/settings?tab=llm"}
	default:
		return runtimeStatusAction{}
	}
}

func checkRuleRegexComponent() componentCheck {
	cfg, err := config.Load(config.RulesConfigPath())
	if err != nil {
		return componentCheck{
			Name:     "Rules",
			Enabled:  true,
			Required: true,
			Ready:    false,
			Message:  fmt.Sprintf("规则配置加载失败，请检查规则文件: %v", err),
		}
	}

	invalid := make([]string, 0)
	for _, rule := range cfg.Rules {
		if strings.TrimSpace(rule.Detection.Type) != "pattern" {
			continue
		}
		for _, pat := range rule.Detection.Patterns {
			if strings.TrimSpace(pat) == "" {
				continue
			}
			if _, compileErr := regexp.Compile(pat); compileErr != nil {
				invalid = append(invalid, fmt.Sprintf("%s: %q (%v)", strings.TrimSpace(rule.ID), pat, compileErr))
			}
		}
	}

	if len(invalid) > 0 {
		preview := invalid
		if len(preview) > 3 {
			preview = preview[:3]
		}
		return componentCheck{
			Name:     "Rules",
			Enabled:  true,
			Required: true,
			Ready:    false,
			Message:  fmt.Sprintf("规则正则预校验失败，共 %d 条无效模式: %s", len(invalid), strings.Join(preview, "；")),
		}
	}

	return componentCheck{
		Name:     "Rules",
		Enabled:  true,
		Required: true,
		Ready:    true,
		Message:  fmt.Sprintf("规则正则预校验通过（共检查 %d 条规则）", len(cfg.Rules)),
	}
}

func checkSandboxComponent() componentCheck {
	enabled := readBoolEnv("REVIEW_ENABLE_SANDBOX", true)
	required := readBoolEnv("REVIEW_REQUIRE_SANDBOX", true)
	if !enabled {
		return componentCheck{
			Name:     "Sandbox",
			Enabled:  false,
			Required: required,
			Ready:    false,
			Message:  "Sandbox 功能未启用，请检查 REVIEW_ENABLE_SANDBOX",
		}
	}

	runner := sandbox.NewRunner()
	if err := runner.Prepare(); err != nil {
		return componentCheck{
			Name:     "Sandbox",
			Enabled:  true,
			Required: required,
			Ready:    false,
			Message:  fmt.Sprintf("沙箱不可用: %v", err),
		}
	}

	return componentCheck{
		Name:     "Sandbox",
		Enabled:  true,
		Required: required,
		Ready:    true,
		Message:  "ZeroClaw 沙箱就绪",
	}
}

func checkSemanticComponent() componentCheck {
	enabled := readBoolEnv("REVIEW_ENABLE_SEMANTIC", true)
	required := readBoolEnv("REVIEW_REQUIRE_SEMANTIC", true)

	if !enabled {
		return componentCheck{
			Name:     "Semantic",
			Enabled:  false,
			Required: required,
			Ready:    false,
			Message:  "语义引擎功能未启用，请检查 REVIEW_ENABLE_SEMANTIC",
		}
	}

	if globalEmbedder == nil || embedderInitError != nil {
		errMsg := "模型未初始化"
		if embedderInitError != nil {
			errMsg = embedderInitError.Error()
		}
		return componentCheck{
			Name:     "Semantic",
			Enabled:  true,
			Required: required,
			Ready:    false,
			Message:  fmt.Sprintf("语义引擎功能未启用，请检查语义引擎功能是否正常: %s", errMsg),
		}
	}

	return componentCheck{
		Name:     "Semantic",
		Enabled:  true,
		Required: required,
		Ready:    true,
		Message:  "语义引擎正常",
	}
}

func checkLLMComponent() componentCheck {
	enabled := readBoolEnv("REVIEW_ENABLE_LLM", true)
	required := isLLMRequired()
	if !enabled {
		return componentCheck{
			Name:     "LLM",
			Enabled:  false,
			Required: required,
			Ready:    false,
			Message:  "LLM 功能未启用，请检查 REVIEW_ENABLE_LLM",
		}
	}

	return componentCheck{
		Name:     "LLM",
		Enabled:  true,
		Required: required,
		Ready:    true,
		Message:  "LLM 功能已启用（运行时按用户配置校验）",
	}
}

func isLLMRequired() bool {
	return readBoolEnv("REVIEW_REQUIRE_LLM", true)
}

func isUserLLMReady(store *storage.Store, username string) bool {
	if !readBoolEnv("REVIEW_ENABLE_LLM", true) {
		return false
	}
	if store == nil {
		return false
	}
	cfg := store.GetUserLLMConfig(username)
	if cfg == nil || !cfg.Enabled {
		return false
	}
	provider := strings.TrimSpace(cfg.Provider)
	providerCfg, ok := store.GetLLMProvider(provider)
	if !ok || !providerCfg.Enabled {
		return false
	}
	if strings.TrimSpace(cfg.APIKey) == "" && strings.TrimSpace(providerCfg.APIKey) == "" {
		return false
	}
	return true
}

func readBoolEnv(key string, fallback bool) bool {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v := strings.ToLower(raw)
	if v == "1" || v == "true" || v == "yes" || v == "on" {
		return true
	}
	if v == "0" || v == "false" || v == "no" || v == "off" {
		return false
	}
	return fallback
}

func localizeComponentName(name string) string {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "sandbox":
		return "沙箱"
	case "rules":
		return "规则引擎"
	case "semantic":
		return "语义引擎"
	case "llm":
		return "LLM"
	default:
		if strings.TrimSpace(name) == "" {
			return "未知组件"
		}
		return name
	}
}

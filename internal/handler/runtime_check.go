package handler

import (
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

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

var (
	runtimeCheckOnce   sync.Once
	runtimeCheckResult runtimeCheckReport
	runtimeCheckReady  bool
)

func InitRuntimeSelfCheck() {
	runtimeCheckOnce.Do(func() {
		runtimeCheckResult = runRuntimeSelfCheck()
		runtimeCheckReady = true
		log.Printf("启动自检完成: %s", RuntimeSelfCheckSummary())
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
	if !runtimeCheckReady {
		return fmt.Errorf("系统启动自检未完成，请检查服务启动流程")
	}

	failures := make([]string, 0)
	warnings := make([]string, 0)

	for _, c := range runtimeCheckResult.Components {
		if !c.Ready {
			name := localizeComponentName(c.Name)
			msg := fmt.Sprintf("%s 功能未启用，请检查 %s 功能是否正常", name, name)
			if c.Message != "" {
				msg = c.Message
			}
			if c.Required {
				failures = append(failures, msg)
			} else {
				warnings = append(warnings, msg)
			}
		}
	}

	if isLLMRequired() {
		if !isUserLLMReady(store, username) {
			failures = append(failures, "LLM 功能未启用，请检查个人中心 LLM 配置是否正常")
		}
	} else if !isUserLLMReady(store, username) {
		warnings = append(warnings, "LLM 功能未启用，请检查个人中心 LLM 配置是否正常")
	}

	if len(failures) == 0 {
		return nil
	}

	all := append([]string{}, failures...)
	if len(warnings) > 0 {
		all = append(all, warnings...)
	}
	return fmt.Errorf("%s", strings.Join(all, "；"))
}

func runRuntimeSelfCheck() runtimeCheckReport {
	report := runtimeCheckReport{CheckedAt: time.Now()}
	report.Components = append(report.Components, checkSandboxComponent())
	report.Components = append(report.Components, checkSemanticComponent())
	report.Components = append(report.Components, checkLLMComponent())
	return report
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
			Message:  fmt.Sprintf("Sandbox 功能未启用，请检查 Sandbox 功能是否正常: %v", err),
		}
	}

	return componentCheck{
		Name:     "Sandbox",
		Enabled:  true,
		Required: required,
		Ready:    true,
		Message:  "sandbox runtime 正常",
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
	if cfg == nil || !cfg.Enabled || strings.TrimSpace(cfg.APIKey) == "" {
		return false
	}
	provider := strings.TrimSpace(cfg.Provider)
	if provider == "" {
		return false
	}
	if provider == "minimax" && strings.TrimSpace(cfg.MiniMaxGroupID) == "" {
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

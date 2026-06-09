package combination

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
	admissionmodel "skill-scanner/internal/admission/model"
	"skill-scanner/internal/logx"
)

type chainRulesConfig struct {
	Version    string               `yaml:"version"`
	Revision   string               `yaml:"revision"`
	Rules      []chainRuleSpec      `yaml:"rules"`
	RuleGroups []chainRuleGroupSpec `yaml:"rule_groups"` // v3.0 格式
}

// chainRuleGroupSpec v3.0 规则组
type chainRuleGroupSpec struct {
	ID       string             `yaml:"id"`
	Category string             `yaml:"category"`
	Items    []chainRuleItemSpec `yaml:"items"`
}

// chainRuleItemSpec v3.0 规则条目
type chainRuleItemSpec struct {
	ID              string              `yaml:"id"`
	Item            string              `yaml:"item"`
	RiskPersonal    string              `yaml:"risk_personal"`
	RiskNonPersonal string              `yaml:"risk_nonpersonal"`
	DetectionTarget string              `yaml:"detection_target"`
	FixSuggestion   string              `yaml:"fix_suggestion"`
	Detection       chainDetectionSpec  `yaml:"detection"`
}

// chainDetectionSpec v3.0 检测配置
type chainDetectionSpec struct {
	Type         string                       `yaml:"type"`
	IncludeGlobs []string                     `yaml:"include_globs"`
	Signals      map[string][]string          `yaml:"signals"`
	PassIf       string                       `yaml:"pass_if"`
	Reason       string                       `yaml:"reason"`
}

type chainRuleSpec struct {
	ID             string              `yaml:"id"`
	Title          string              `yaml:"title"`
	Level          string              `yaml:"level"`
	Summary        string              `yaml:"summary"`
	Recommendation string              `yaml:"recommendation"`
	Capabilities   []string            `yaml:"capabilities"`
	ClosureRequirements []string       `yaml:"closure_requirements"`
	RequiredScopes map[string][]string `yaml:"required_scopes"`
	Priority       int                 `yaml:"priority"`
	FoldWhen       []string            `yaml:"fold_when"`
}

var (
	chainRulesMu     sync.Mutex
	cachedChainRules []chainRule
	chainRulesErr    error
	chainRulesPath   string
	chainRulesMTime  time.Time
	chainRulesMeta   rulesConfigMeta
)

type rulesConfigMeta struct {
	Version     string
	Revision    string
	ContentHash string
	SourcePath  string
}

type InferredChain struct {
	ID              string
	Title           string
	Level           string
	Summary         string
	Recommendation  string
	ClosureRequirements []string
	Evidence        []string
	AttackPath      []string
	MITRETechniques []string
	SourceSkills    []RiskSourceSkill
}

type chainRule struct {
	ID             string
	Title          string
	Level          string
	Summary        string
	Recommendation string
	Capabilities   []string
	ClosureRequirements []string
	RequiredScopes map[string][]string
	Required       func(*admissionmodel.CapabilityProfile) bool
	Priority       int
	FoldWhen       []string
}

var defaultChainRules = []chainRule{
	{
		ID:             "sensitive-exfiltration",
		Title:          "潜在敏感数据外发链",
		Level:          "high",
		Summary:        "组合中同时出现敏感数据访问与外联能力，存在将敏感内容发送到外部目标的动态链路风险。",
		Recommendation: "建议优先收敛凭据读取范围、外联白名单和可传输字段。",
		Capabilities:   []string{"sensitive_data_access", "network_access"},
		ClosureRequirements: []string{"source", "sink", "runtime"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.NetworkAccess && profile.SensitiveDataAccess
		},
		Priority: 80,
		FoldWhen: []string{"full-attack-chain"},
	},
	{
		ID:             "write-exec-chain",
		Title:          "潜在落地执行链",
		Level:          "high",
		Summary:        "组合中同时出现文件写入与命令执行能力，存在落地文件后触发执行的动态链路风险。",
		Recommendation: "建议限制落地目录、禁用 shell 拼接，并校验可执行入口。",
		Capabilities:   []string{"file_write", "command_exec"},
		ClosureRequirements: []string{"transform", "sink", "runtime"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.CommandExec && profile.FileWrite
		},
		Priority: 60,
	},
	{
		ID:             "remote-command-chain",
		Title:          "潜在远程指令执行链",
		Level:          "high",
		Summary:        "组合中同时出现外联与命令执行能力，存在接收远程输入后驱动本地执行的动态链路风险。",
		Recommendation: "建议检查远程输入到执行参数之间的边界，阻断动态命令拼接。",
		Capabilities:   []string{"network_access", "command_exec"},
		ClosureRequirements: []string{"source", "sink", "runtime"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.NetworkAccess && profile.CommandExec
		},
		Priority: 70,
		FoldWhen: []string{"full-attack-chain"},
	},
	{
		ID:             "full-attack-chain",
		Title:          "潜在完整攻击链",
		Level:          "high",
		Summary:        "组合中同时具备敏感访问、外联和执行能力，已形成较完整的高危动态行为链。",
		Recommendation: "建议暂停组合准入，并逐项拆分验证最小权限、最小外联与最小执行面。",
		Capabilities:   []string{"sensitive_data_access", "network_access", "command_exec"},
		ClosureRequirements: []string{"source", "transform", "sink", "runtime"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.NetworkAccess && profile.CommandExec && profile.SensitiveDataAccess
		},
		Priority: 100,
	},
	{
		ID:             "file-read-network-chain",
		Title:          "潜在任意文件读取外发链",
		Level:          "medium",
		Summary:        "组合中同时出现文件读取与外联能力，存在将读取内容发送到外部目标的风险。",
		Recommendation: "建议限制可读目录并收敛外联白名单，避免读取结果直接出站。",
		Capabilities:   []string{"file_read", "network_access"},
		ClosureRequirements: []string{"source", "sink"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.FileRead && profile.NetworkAccess
		},
		Priority: 55,
	},
	{
		ID:             "download-write-chain",
		Title:          "潜在下载落地链",
		Level:          "medium",
		Summary:        "组合中同时出现外部下载与文件写入能力，存在将外部内容落地到本地的风险。",
		Recommendation: "建议增加下载来源校验、文件类型校验与落地目录隔离策略。",
		Capabilities:   []string{"external_fetch", "file_write"},
		ClosureRequirements: []string{"source", "transform"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.ExternalFetch && profile.FileWrite
		},
		Priority: 58,
	},
	{
		ID:             "env-exfiltration-chain",
		Title:          "潜在环境信息外发链",
		Level:          "medium",
		Summary:        "组合中同时出现敏感数据访问与外联能力，且证据包含环境或凭据读取迹象。",
		Recommendation: "建议禁止读取环境凭据并限制外联字段，敏感配置改用密钥托管。",
		Capabilities:   []string{"sensitive_data_access", "network_access"},
		ClosureRequirements: []string{"source", "sink", "runtime"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.SensitiveDataAccess && profile.NetworkAccess
		},
		Priority: 65,
	},
	{
		ID:             "collection-exfiltration-chain",
		Title:          "潜在采集后外发链",
		Level:          "high",
		Summary:        "组合中同时出现数据采集与外联能力，存在批量采集后外发的风险。",
		Recommendation: "建议最小化采集字段，增加脱敏策略并限制出站目标。",
		Capabilities:   []string{"data_collection", "network_access"},
		ClosureRequirements: []string{"source", "sink", "runtime"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.DataCollection && profile.NetworkAccess
		},
		Priority: 72,
	},
	{
		ID:             "persistence-c2-chain",
		Title:          "潜在持久化回连链",
		Level:          "high",
		Summary:        "组合中同时出现持久化与网络能力，存在周期性回连或隐蔽控制通道风险。",
		Recommendation: "建议禁用自启动写入，限制后台常驻任务并审计外联行为。",
		Capabilities:   []string{"persistence", "network_access"},
		ClosureRequirements: []string{"sink", "runtime"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.Persistence && profile.NetworkAccess
		},
		Priority: 78,
	},
	{
		ID:             "privilege-exec-chain",
		Title:          "潜在提权执行链",
		Level:          "high",
		Summary:        "组合中同时出现特权使用与命令执行能力，存在高权限执行风险。",
		Recommendation: "建议收敛高权限运行范围并限制命令执行入口。",
		Capabilities:   []string{"privilege_use", "command_exec"},
		ClosureRequirements: []string{"transform", "sink", "runtime"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.PrivilegeUse && profile.CommandExec
		},
		Priority: 85,
	},
	{
		ID:             "fetch-exec-chain",
		Title:          "潜在下载后执行链",
		Level:          "high",
		Summary:        "组合中同时出现外部下载与命令执行能力，存在下载后直接执行风险。",
		Recommendation: "建议对下载内容做签名校验并阻断自动执行路径。",
		Capabilities:   []string{"external_fetch", "command_exec"},
		ClosureRequirements: []string{"source", "sink", "runtime"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.ExternalFetch && profile.CommandExec
		},
		Priority: 82,
	},
	{
		ID:             "fetch-sensitive-chain",
		Title:          "潜在外部拉取敏感联动链",
		Level:          "medium",
		Summary:        "组合中同时出现外部拉取与敏感数据访问能力，存在外部触发敏感读取风险。",
		Recommendation: "建议隔离外部输入与敏感读取逻辑，增加强制审批。",
		Capabilities:   []string{"external_fetch", "sensitive_data_access"},
		ClosureRequirements: []string{"source", "transform"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.ExternalFetch && profile.SensitiveDataAccess
		},
		Priority: 62,
	},
	{
		ID:             "file-read-write-chain",
		Title:          "潜在文件读写联动链",
		Level:          "medium",
		Summary:        "组合中同时出现文件读取与文件写入能力，存在本地数据重写与落地扩散风险。",
		Recommendation: "建议限制读写目录并启用文件完整性审计。",
		Capabilities:   []string{"file_read", "file_write"},
		ClosureRequirements: []string{"source", "transform"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.FileRead && profile.FileWrite
		},
		Priority: 54,
	},
	{
		ID:             "file-read-exec-chain",
		Title:          "潜在读取驱动执行链",
		Level:          "medium",
		Summary:        "组合中同时出现文件读取与命令执行能力，存在读取后拼接执行参数风险。",
		Recommendation: "建议禁止将文件内容直接传入命令执行上下文。",
		Capabilities:   []string{"file_read", "command_exec"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.FileRead && profile.CommandExec
		},
		Priority: 63,
	},
	{
		ID:             "tool-network-chain",
		Title:          "潜在工具外联调用链",
		Level:          "medium",
		Summary:        "组合中同时出现工具调用与网络访问能力，存在通过工具桥接外联行为的风险。",
		Recommendation: "建议最小化工具权限并限制工具触发的网络目标。",
		Capabilities:   []string{"tool_invocation", "network_access"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.ToolInvocation && profile.NetworkAccess
		},
		Priority: 59,
	},
	{
		ID:             "tool-sensitive-chain",
		Title:          "潜在工具敏感数据链",
		Level:          "high",
		Summary:        "组合中同时出现工具调用与敏感数据访问能力，存在间接凭据泄漏风险。",
		Recommendation: "建议隔离敏感读取工具并对调用方启用强约束策略。",
		Capabilities:   []string{"tool_invocation", "sensitive_data_access"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.ToolInvocation && profile.SensitiveDataAccess
		},
		Priority: 76,
	},
	{
		ID:             "persistence-exec-chain",
		Title:          "潜在持久化执行链",
		Level:          "high",
		Summary:        "组合中同时出现持久化与命令执行能力，存在后门驻留后执行风险。",
		Recommendation: "建议移除自启动执行入口并收敛可执行脚本来源。",
		Capabilities:   []string{"persistence", "command_exec"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.Persistence && profile.CommandExec
		},
		Priority: 81,
	},
	{
		ID:             "privilege-network-chain",
		Title:          "潜在高权限外联链",
		Level:          "high",
		Summary:        "组合中同时出现特权使用与外联能力，存在高权限数据外发风险。",
		Recommendation: "建议限制特权网络访问并增加出口审计策略。",
		Capabilities:   []string{"privilege_use", "network_access"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.PrivilegeUse && profile.NetworkAccess
		},
		Priority: 84,
	},
	{
		ID:             "collection-external-fetch-chain",
		Title:          "潜在采集与外部拉取联动链",
		Level:          "medium",
		Summary:        "组合中同时出现数据采集与外部拉取能力，存在数据聚合与二次处理风险。",
		Recommendation: "建议限制采集窗口并启用外部内容来源可信校验。",
		Capabilities:   []string{"data_collection", "external_fetch"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.DataCollection && profile.ExternalFetch
		},
		Priority: 57,
	},
	{
		ID:             "file-write-network-chain",
		Title:          "潜在写入后外发链",
		Level:          "medium",
		Summary:        "组合中同时出现文件写入与网络访问能力，存在中转文件后出站风险。",
		Recommendation: "建议对中间文件执行脱敏并限制上传出口。",
		Capabilities:   []string{"file_write", "network_access"},
		Required: func(profile *admissionmodel.CapabilityProfile) bool {
			return profile != nil && profile.FileWrite && profile.NetworkAccess
		},
		Priority: 56,
	},
}

func getChainRules() []chainRule {
	chainRulesMu.Lock()
	defer chainRulesMu.Unlock()
	path := chainRulesConfigPath()
	mtime := chainRulesFileMTime(path)
	if len(cachedChainRules) > 0 && chainRulesPath == path && mtime.Equal(chainRulesMTime) {
		return cachedChainRules
	}
	var meta rulesConfigMeta
	cachedChainRules, meta, chainRulesErr = loadChainRules(path)
	chainRulesPath = path
	chainRulesMTime = mtime
	chainRulesMeta = meta
	if chainRulesErr != nil {
		logx.With(
			"component", "combination-chain-rules",
			"level", classifyChainRulesWarningLevel(chainRulesErr),
			"path", path,
			"error", chainRulesErr.Error(),
		).Warn("chain rules load warning")
	}
	return cachedChainRules
}

func getChainRulesMeta() rulesConfigMeta {
	_ = getChainRules()
	chainRulesMu.Lock()
	defer chainRulesMu.Unlock()
	return chainRulesMeta
}

func RuleCatalogIDs() []string {
	rules := getChainRules()
	out := make([]string, 0, len(rules))
	for _, item := range rules {
		id := strings.TrimSpace(item.ID)
		if id != "" {
			out = append(out, id)
		}
	}
	return normalizeStrings(out)
}

func chainRulesConfigPath() string {
	if path := strings.TrimSpace(os.Getenv("REVIEW_CHAIN_RULES_PATH")); path != "" {
		return path
	}
	for _, candidate := range []string{"config/rules_approval.yaml", filepath.Join("..", "..", "config", "rules_approval.yaml")} {
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "config/rules_approval.yaml"
}

func chainRulesFileMTime(path string) time.Time {
	info, err := os.Stat(path)
	if err != nil {
		return time.Time{}
	}
	return info.ModTime().UTC()
}

func getChainRulesWarning() string {
	_ = getChainRules()
	if chainRulesErr == nil {
		return ""
	}
	return chainRulesErr.Error()
}

func getChainRulesWarningLevel() string {
	_ = getChainRules()
	return classifyChainRulesWarningLevel(chainRulesErr)
}

func classifyChainRulesWarningLevel(err error) string {
	if err == nil {
		return ""
	}
	errText := strings.ToLower(strings.TrimSpace(err.Error()))
	if strings.Contains(errText, "partial") {
		return "warning"
	}
	return "error"
}

// flattenChainRuleGroups 将 v3.0 的 rule_groups 展平为 v2.0 的 rules 格式
// 只处理 detection.type 为 capability_chain 的规则
func flattenChainRuleGroups(groups []chainRuleGroupSpec) []chainRuleSpec {
	var rules []chainRuleSpec
	for _, group := range groups {
		for _, item := range group.Items {
			// 只处理 capability_chain 类型的规则
			if item.Detection.Type != "capability_chain" {
				continue
			}
			// 从 detection.signals 提取 capabilities
			var rawCapabilities []string
			for cap := range item.Detection.Signals {
				rawCapabilities = append(rawCapabilities, cap)
			}
			// 映射到支持的 capability 名称
			var capabilities []string
			for _, cap := range rawCapabilities {
				mapped := mapLegacyCapability(cap)
				if mapped != "" {
					capabilities = append(capabilities, mapped)
				}
			}
			capabilities = normalizeStrings(capabilities)
			// 如果只有一个 capability，尝试推断 companion
			if len(capabilities) == 1 {
				if extra := inferCompanionCapability(capabilities[0]); extra != "" {
					capabilities = append(capabilities, extra)
					capabilities = normalizeStrings(capabilities)
				}
			}
			// 映射 risk_nonpersonal 到 level
			level := riskNonPersonalToLevel(item.RiskNonPersonal)
			rule := chainRuleSpec{
				ID:             item.ID,
				Title:          item.Item,
				Level:          level,
				Summary:        item.DetectionTarget,
				Recommendation: item.FixSuggestion,
				Capabilities:   capabilities,
				Priority:       levelToPriority(level),
			}
			rules = append(rules, rule)
		}
	}
	return rules
}

func riskNonPersonalToLevel(risk string) string {
	switch strings.TrimSpace(risk) {
	case "高":
		return "high"
	case "中":
		return "medium"
	case "低":
		return "low"
	default:
		return "medium"
	}
}

func levelToPriority(level string) int {
	switch level {
	case "high":
		return 80
	case "medium":
		return 50
	case "low":
		return 30
	default:
		return 50
	}
}

func loadChainRules(path string) ([]chainRule, rulesConfigMeta, error) {
	meta := rulesConfigMeta{
		Version:     "builtin",
		Revision:    "builtin-default",
		ContentHash: "builtin",
		SourcePath:  strings.TrimSpace(path),
	}
	rules := append([]chainRule(nil), defaultChainRules...)
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return rules, meta, err
	}
	meta.ContentHash = sha1Hex(data)
	var cfg chainRulesConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return rules, meta, err
	}
	meta.Version = normalizeRuleVersion(cfg.Version)
	meta.Revision = normalizeRuleRevision(cfg.Revision, meta.ContentHash)
	// v3.0 格式：将 rule_groups 展平为 rules
	if len(cfg.Rules) == 0 && len(cfg.RuleGroups) > 0 {
		cfg.Rules = flattenChainRuleGroups(cfg.RuleGroups)
	}
	if len(cfg.Rules) == 0 {
		return rules, meta, fmt.Errorf("no rules configured")
	}
	if !isSupportedChainRuleConfigVersion(cfg.Version) {
		return rules, meta, fmt.Errorf("unsupported config version: %s", cfg.Version)
	}
	loaded := make([]chainRule, 0, len(cfg.Rules))
	validationErrors := make([]string, 0)
	for _, item := range cfg.Rules {
		item = normalizeChainRuleSpecForCompatibility(item)
		if err := validateChainRuleSpec(item); err != nil {
			validationErrors = append(validationErrors, err.Error())
			continue
		}
		originalID := strings.TrimSpace(item.ID)
		capabilities := normalizeStrings(item.Capabilities)
		id := normalizeChainRuleID(originalID, capabilities)
		title := strings.TrimSpace(item.Title)
		requiredCapabilities := append([]string(nil), capabilities...)
		closureRequirements := normalizeClosureRequirements(item.ClosureRequirements)
		requiredScopes := normalizeScopeMap(item.RequiredScopes)
		baseRule, hasBaseRule := defaultChainRuleByID(id)
		if hasBaseRule && strings.HasPrefix(strings.ToUpper(originalID), "S3-") {
			title = baseRule.Title
		}
		level := normalizeChainLevel(item.Level)
		if hasBaseRule && level == "medium" && strings.TrimSpace(item.Level) == "" {
			level = baseRule.Level
		}
		summary := strings.TrimSpace(item.Summary)
		recommendation := strings.TrimSpace(item.Recommendation)
		if hasBaseRule && strings.HasPrefix(strings.ToUpper(originalID), "S3-") {
			summary = baseRule.Summary
			recommendation = baseRule.Recommendation
		}
		foldWhen := normalizeStrings(item.FoldWhen)
		if len(foldWhen) == 0 && hasBaseRule {
			foldWhen = append([]string(nil), baseRule.FoldWhen...)
		}
		if len(closureRequirements) == 0 && hasBaseRule {
			closureRequirements = append([]string(nil), baseRule.ClosureRequirements...)
		}
		priority := item.Priority
		if priority <= 0 && hasBaseRule {
			priority = baseRule.Priority
		}
		rule := chainRule{
			ID:             id,
			Title:          title,
			Level:          level,
			Summary:        summary,
			Recommendation: recommendation,
			Capabilities:   capabilities,
			ClosureRequirements: closureRequirements,
			RequiredScopes: requiredScopes,
			Priority:       priority,
			FoldWhen:       foldWhen,
			Required: func(profile *admissionmodel.CapabilityProfile) bool {
				if profile == nil {
					return false
				}
				for _, capability := range requiredCapabilities {
					if !profileHasCapability(profile, capability) {
						return false
					}
				}
				return true
			},
		}
		if rule.Priority <= 0 {
			rule.Priority = 50
		}
		loaded = append(loaded, rule)
	}
	merged := mergeChainRules(defaultChainRules, loaded)
	if len(loaded) == 0 {
		if len(validationErrors) == 0 {
			return rules, meta, fmt.Errorf("no valid rules loaded")
		}
		return rules, meta, fmt.Errorf("invalid chain rules: %s", strings.Join(validationErrors, "; "))
	}
	if len(validationErrors) > 0 {
		return merged, meta, fmt.Errorf("partial chain rule load: %s", strings.Join(validationErrors, "; "))
	}
	return merged, meta, nil
}

func normalizeChainRuleID(id string, capabilities []string) string {
	if !strings.HasPrefix(strings.ToUpper(id), "S3-") {
		return id
	}
	capSet := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		capSet[strings.TrimSpace(capability)] = struct{}{}
	}
	has := func(capability string) bool {
		_, ok := capSet[capability]
		return ok
	}
	switch {
	case has("sensitive_data_access") && has("network_access") && has("command_exec"):
		return "full-attack-chain"
	case has("sensitive_data_access") && has("network_access"):
		return "sensitive-exfiltration"
	case has("network_access") && has("command_exec"):
		return "remote-command-chain"
	case has("file_write") && has("command_exec"):
		return "write-exec-chain"
	default:
		if mapped, ok := mapChainIDByCapabilities(capabilities); ok {
			return mapped
		}
		return id
	}
}

func mapChainIDByCapabilities(capabilities []string) (string, bool) {
	capSet := make(map[string]struct{}, len(capabilities))
	for _, capability := range capabilities {
		capSet[strings.TrimSpace(capability)] = struct{}{}
	}
	has := func(capability string) bool {
		_, ok := capSet[capability]
		return ok
	}
	switch {
	case has("file_read") && has("file_write") && has("command_exec"):
		return "full-attack-chain", true
	case has("sensitive_data_access") && has("network_access") && has("command_exec"):
		return "full-attack-chain", true
	case has("sensitive_data_access") && has("network_access"):
		return "sensitive-exfiltration", true
	case has("file_read") && has("network_access"):
		return "file-read-network-chain", true
	case has("network_access") && has("command_exec"):
		return "remote-command-chain", true
	case has("file_write") && has("command_exec"):
		return "write-exec-chain", true
	case has("external_fetch") && has("command_exec"):
		return "fetch-exec-chain", true
	case has("data_collection") && has("network_access"):
		return "collection-exfiltration-chain", true
	default:
		return "", false
	}
}

func mergeChainRules(base []chainRule, overlay []chainRule) []chainRule {
	if len(base) == 0 {
		return append([]chainRule(nil), overlay...)
	}
	overlayIDs := make(map[string]struct{}, len(overlay))
	for _, rule := range overlay {
		overlayIDs[strings.TrimSpace(rule.ID)] = struct{}{}
	}
	out := make([]chainRule, 0, len(base)+len(overlay))
	index := make(map[string]int, len(base)+len(overlay))
	for _, rule := range base {
		id := strings.TrimSpace(rule.ID)
		if _, overridden := overlayIDs[id]; overridden {
			continue
		}
		index[id] = len(out)
		out = append(out, rule)
	}
	for _, rule := range overlay {
		id := strings.TrimSpace(rule.ID)
		if pos, ok := index[id]; ok {
			out[pos] = rule
			continue
		}
		index[id] = len(out)
		out = append(out, rule)
	}
	return out
}

func defaultChainRuleByID(id string) (chainRule, bool) {
	id = strings.TrimSpace(id)
	for _, rule := range defaultChainRules {
		if strings.TrimSpace(rule.ID) == id {
			return rule, true
		}
	}
	return chainRule{}, false
}

func normalizeRuleVersion(version string) string {
	version = strings.TrimSpace(version)
	if version == "" {
		return "v1"
	}
	return version
}

func normalizeRuleRevision(revision, contentHash string) string {
	revision = strings.TrimSpace(revision)
	if revision != "" {
		return revision
	}
	if len(contentHash) >= 8 {
		return "auto-" + contentHash[:8]
	}
	return "auto"
}

func sha1Hex(data []byte) string {
	sum := sha1.Sum(data)
	return hex.EncodeToString(sum[:])
}

func validateChainRuleSpec(rule chainRuleSpec) error {
	id := strings.TrimSpace(rule.ID)
	if id == "" {
		return fmt.Errorf("rule id is required")
	}
	title := strings.TrimSpace(rule.Title)
	if title == "" {
		return fmt.Errorf("rule %s title is required", id)
	}
	if len(rule.Capabilities) < 2 {
		return fmt.Errorf("rule %s requires at least two capabilities", id)
	}
	for _, requirement := range rule.ClosureRequirements {
		if !isSupportedClosureRequirement(strings.TrimSpace(requirement)) {
			return fmt.Errorf("rule %s has unsupported closure requirement: %s", id, requirement)
		}
	}
	for _, c := range rule.Capabilities {
		if !isSupportedCapability(strings.TrimSpace(c)) {
			return fmt.Errorf("rule %s has unsupported capability: %s", id, c)
		}
	}
	for capability, scopes := range rule.RequiredScopes {
		if !isSupportedCapability(strings.TrimSpace(capability)) {
			return fmt.Errorf("rule %s has unsupported scope capability: %s", id, capability)
		}
		if len(scopes) == 0 {
			return fmt.Errorf("rule %s scope for %s cannot be empty", id, capability)
		}
	}
	return nil
}

func normalizeChainRuleSpecForCompatibility(rule chainRuleSpec) chainRuleSpec {
	normalized := make([]string, 0, len(rule.Capabilities))
	for _, capability := range rule.Capabilities {
		mapped := mapLegacyCapability(strings.TrimSpace(capability))
		if mapped == "" {
			continue
		}
		normalized = append(normalized, mapped)
	}
	normalized = normalizeStrings(normalized)
	if len(normalized) == 1 {
		if extra := inferCompanionCapability(normalized[0]); extra != "" {
			normalized = append(normalized, extra)
			normalized = normalizeStrings(normalized)
		}
	}
	rule.Capabilities = normalized
	rule.ClosureRequirements = normalizeClosureRequirements(rule.ClosureRequirements)

	if len(rule.RequiredScopes) > 0 {
		mappedScopes := make(map[string][]string, len(rule.RequiredScopes))
		for capability, scopes := range rule.RequiredScopes {
			mapped := mapLegacyCapability(strings.TrimSpace(capability))
			if mapped == "" {
				continue
			}
			mappedScopes[mapped] = append(mappedScopes[mapped], scopes...)
		}
		rule.RequiredScopes = mappedScopes
	}
	return rule
}

func mapLegacyCapability(capability string) string {
	capability = strings.ToLower(strings.TrimSpace(capability))
	switch capability {
	// 直接支持的能力
	case "network_access", "file_read", "file_write", "command_exec", "sensitive_data_access", "external_fetch", "data_collection", "persistence", "privilege_use", "tool_invocation":
		return capability
	// 网络相关
	case "network", "ssrf", "egress":
		return "network_access"
	// 命令执行相关
	case "exec", "injection", "untrusted_input", "exec_context":
		return "command_exec"
	// 文件相关
	case "file_access", "path_traversal", "upload":
		return "file_write"
	// 敏感数据相关
	case "credential", "credential_read", "sensitive_read", "privacy":
		return "sensitive_data_access"
	// 外部获取相关
	case "download", "dependency", "dependency_conflict", "dependency_overwrite", "vulnerability":
		return "external_fetch"
	// 工具调用相关
	case "tool", "audit_missing", "trace_break":
		return "tool_invocation"
	// 持久化相关
	case "env", "time", "retry", "async", "env_dependent", "time_trigger", "hidden_trigger", "hidden_action":
		return "persistence"
	// 权限相关
	case "privilege", "state", "low_trust", "approval_bypass", "split_approval", "high_impact_chain", "high_risk_operation", "bypass", "privilege_over", "high_privilege", "security_break", "state_conflict":
		return "privilege_use"
	// 审批和控制相关（映射到 privilege_use）
	case "approval", "global_approval", "isolation", "masking", "validation", "integrity":
		return "privilege_use"
	// 数据收集相关
	case "collection":
		return "data_collection"
	default:
		return capability
	}
}

func inferCompanionCapability(capability string) string {
	switch capability {
	case "network_access":
		return "sensitive_data_access"
	case "sensitive_data_access":
		return "network_access"
	case "command_exec":
		return "file_write"
	case "file_read":
		return "network_access"
	case "file_write":
		return "command_exec"
	case "external_fetch":
		return "file_write"
	case "privilege_use":
		return "command_exec"
	case "persistence":
		return "network_access"
	case "tool_invocation":
		return "sensitive_data_access"
	default:
		return ""
	}
}

func normalizeScopeMap(in map[string][]string) map[string][]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string][]string, len(in))
	for capability, scopes := range in {
		capability = strings.TrimSpace(capability)
		if capability == "" {
			continue
		}
		normalized := normalizeStrings(scopes)
		if len(normalized) == 0 {
			continue
		}
		out[capability] = normalized
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeClosureRequirements(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(items))
	for _, item := range items {
		v := strings.ToLower(strings.TrimSpace(item))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func isSupportedClosureRequirement(item string) bool {
	switch strings.ToLower(strings.TrimSpace(item)) {
	case "source", "transform", "sink", "runtime":
		return true
	default:
		return false
	}
}

func isSupportedCapability(capability string) bool {
	switch capability {
	case "network_access", "file_read", "file_write", "command_exec", "sensitive_data_access", "external_fetch", "data_collection", "persistence", "privilege_use", "tool_invocation":
		return true
	default:
		return false
	}
}

func isSupportedChainRuleConfigVersion(version string) bool {
	version = strings.TrimSpace(version)
	if version == "" {
		return true
	}
	return version == "v1" || version == "3.0"
}

func normalizeChainLevel(level string) string {
	level = strings.ToLower(strings.TrimSpace(level))
	switch level {
	case "high", "medium", "low":
		return level
	default:
		return "medium"
	}
}

func inferChains(selected []selectedSignal, profile *admissionmodel.CapabilityProfile) []InferredChain {
	if len(selected) == 0 || profile == nil {
		return nil
	}
	sources := selectedToSources(selected)
	skillCaps := buildSkillCapabilityIndex(selected)
	support := buildChainSupportIndex(selected, skillCaps)
	activeRules := getChainRules()
	candidateRules := filterCandidateRules(activeRules, skillCaps)
	chains := make([]InferredChain, 0, len(candidateRules))
	for _, rule := range candidateRules {
		if rule.Required != nil && !rule.Required(profile) {
			continue
		}
		if !profileHasRequiredScopes(profile, rule.RequiredScopes) {
			continue
		}
		evidence := collectChainEvidence(selected, chainEvidenceKeywords(rule.Capabilities...), append([]string(nil), rule.Capabilities...))
		if !hasChainSupport(support, evidence, rule.Capabilities...) {
			continue
		}
		chains = append(chains, InferredChain{
			ID:              rule.ID,
			Title:           rule.Title,
			Level:           rule.Level,
			Summary:         rule.Summary,
			Recommendation:  rule.Recommendation,
			ClosureRequirements: append([]string(nil), rule.ClosureRequirements...),
			Evidence:        evidence,
			AttackPath:      buildAttackPath(rule.Capabilities),
			MITRETechniques: buildMITRETechniques(rule.Capabilities),
			SourceSkills:    sources,
		})
	}
	chains = ensureWriteExecChain(chains, selected, profile)
	return chains
}

func ensureWriteExecChain(chains []InferredChain, selected []selectedSignal, profile *admissionmodel.CapabilityProfile) []InferredChain {
	if profile == nil || !profile.FileWrite || !profile.CommandExec {
		return chains
	}
	for _, chain := range chains {
		if strings.TrimSpace(chain.ID) == "write-exec-chain" {
			return chains
		}
	}
	activeRules := getChainRules()
	var fallbackRule *chainRule
	for i := range activeRules {
		if strings.TrimSpace(activeRules[i].ID) == "write-exec-chain" {
			fallbackRule = &activeRules[i]
			break
		}
	}
	if fallbackRule == nil {
		for i := range defaultChainRules {
			if strings.TrimSpace(defaultChainRules[i].ID) == "write-exec-chain" {
				fallbackRule = &defaultChainRules[i]
				break
			}
		}
	}
	if fallbackRule == nil {
		return chains
	}
	skillCaps := buildSkillCapabilityIndex(selected)
	support := buildChainSupportIndex(selected, skillCaps)
	evidence := collectChainEvidence(selected, chainEvidenceKeywords(fallbackRule.Capabilities...), append([]string(nil), fallbackRule.Capabilities...))
	if !hasChainSupport(support, evidence, fallbackRule.Capabilities...) {
		return chains
	}
	chains = append(chains, InferredChain{
		ID:              fallbackRule.ID,
		Title:           fallbackRule.Title,
		Level:           fallbackRule.Level,
		Summary:         fallbackRule.Summary,
		Recommendation:  fallbackRule.Recommendation,
		Evidence:        evidence,
		AttackPath:      buildAttackPath(fallbackRule.Capabilities),
		MITRETechniques: buildMITRETechniques(fallbackRule.Capabilities),
		SourceSkills:    selectedToSources(selected),
	})
	return chains
}

func profileHasRequiredScopes(profile *admissionmodel.CapabilityProfile, required map[string][]string) bool {
	if len(required) == 0 {
		return true
	}
	if profile == nil {
		return false
	}
	for capability, scopes := range required {
		matched := false
		for _, scope := range scopes {
			if profile.HasCapabilityScope(capability, scope) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

func filterCandidateRules(rules []chainRule, skillCaps map[string][]string) []chainRule {
	if len(rules) == 0 || len(skillCaps) == 0 {
		return rules
	}
	capRuleIDs := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		for _, capability := range rule.Capabilities {
			if len(skillCaps[capability]) > 0 {
				capRuleIDs[rule.ID] = struct{}{}
				break
			}
		}
	}
	if len(capRuleIDs) == 0 {
		return rules
	}
	out := make([]chainRule, 0, len(capRuleIDs))
	for _, rule := range rules {
		if _, ok := capRuleIDs[rule.ID]; ok {
			out = append(out, rule)
		}
	}
	return out
}

func buildAttackPath(capabilities []string) []string {
	if len(capabilities) == 0 {
		return nil
	}
	path := make([]string, 0, len(capabilities))
	for _, cap := range capabilities {
		switch cap {
		case "sensitive_data_access":
			path = append(path, "Collect sensitive data")
		case "file_write":
			path = append(path, "Drop payload or intermediate file")
		case "network_access":
			path = append(path, "Exfiltrate or receive remote command")
		case "command_exec":
			path = append(path, "Execute local command")
		case "file_read":
			path = append(path, "Read local files")
		case "external_fetch":
			path = append(path, "Fetch remote payload")
		case "data_collection":
			path = append(path, "Collect local or contextual data")
		case "persistence":
			path = append(path, "Establish persistence foothold")
		case "privilege_use":
			path = append(path, "Use elevated privileges")
		case "tool_invocation":
			path = append(path, "Invoke external tool capability")
		default:
			path = append(path, cap)
		}
	}
	return path
}

func buildMITRETechniques(capabilities []string) []string {
	if len(capabilities) == 0 {
		return nil
	}
	out := make([]string, 0, 4)
	for _, cap := range capabilities {
		switch cap {
		case "sensitive_data_access":
			out = append(out, "TA0009 Collection", "T1005 Data from Local System")
		case "file_write":
			out = append(out, "TA0003 Persistence", "T1105 Ingress Tool Transfer")
		case "network_access":
			out = append(out, "TA0011 Command and Control", "T1071 Application Layer Protocol")
		case "command_exec":
			out = append(out, "TA0002 Execution", "T1059 Command and Scripting Interpreter")
		case "file_read":
			out = append(out, "TA0009 Collection", "T1005 Data from Local System")
		case "external_fetch":
			out = append(out, "TA0011 Command and Control", "T1105 Ingress Tool Transfer")
		case "data_collection":
			out = append(out, "TA0009 Collection", "T1005 Data from Local System")
		case "persistence":
			out = append(out, "TA0003 Persistence", "T1547 Boot or Logon Autostart Execution")
		case "privilege_use":
			out = append(out, "TA0004 Privilege Escalation", "T1068 Exploitation for Privilege Escalation")
		case "tool_invocation":
			out = append(out, "TA0005 Defense Evasion", "T1218 Signed Binary Proxy Execution")
		}
	}
	return normalizeStrings(out)
}

func prioritizeInferredChains(chains []InferredChain) []InferredChain {
	if len(chains) <= 1 {
		return chains
	}
	priority := chainPriorityMap()
	kept := make([]InferredChain, 0, len(chains))
	seen := map[string]bool{}
	present := make(map[string]bool, len(chains))
	for _, item := range chains {
		present[item.ID] = true
	}
	for _, item := range chains {
		if seen[item.ID] {
			continue
		}
		if shouldFoldChain(item.ID, present) {
			continue
		}
		seen[item.ID] = true
		kept = append(kept, item)
	}
	sort.SliceStable(kept, func(i, j int) bool {
		left := priority[kept[i].ID]
		right := priority[kept[j].ID]
		if left == right {
			return kept[i].ID < kept[j].ID
		}
		return left > right
	})
	return kept
}

func chainPriorityMap() map[string]int {
	rules := getChainRules()
	out := make(map[string]int, len(rules))
	for _, rule := range rules {
		out[rule.ID] = rule.Priority
	}
	return out
}

func shouldFoldChain(chainID string, present map[string]bool) bool {
	for _, rule := range getChainRules() {
		if rule.ID != chainID {
			continue
		}
		for _, parent := range rule.FoldWhen {
			if present[parent] {
				return true
			}
		}
		return false
	}
	return false
}

func buildConclusion(selected []SkillOption, profile *admissionmodel.CapabilityProfile, risks []CombinedRisk, chains []InferredChain, tiSummary tiRiskSummary) Conclusion {
	conclusion := Conclusion{
		RiskLevel:          "low",
		RiskLabel:          "低风险",
		ClosureNarrative:   "当前组合尚未形成明显跨技能闭环，可继续观察后续能力叠加。",
		Recommendation:     "可继续保持人工复核，并关注后续能力变更。",
		SelectedSkillCount: len(selected),
		TITargetCount:      tiSummary.TargetCount,
		TIThreatCount:      tiSummary.ThreatCount,
		TISuspiciousCount:  tiSummary.SuspiciousCount,
		TIAdjustmentScore:  tiSummary.Adjustment,
	}
	if profile != nil {
		conclusion.CapabilityCount = len(profile.ToDetectedCapabilities())
		conclusion.TransferRiskScore = calculateTransferRisk(profile)
		if profile.NetworkAccess {
			conclusion.SensitiveSignalCount++
		}
		if profile.CommandExec {
			conclusion.SensitiveSignalCount++
		}
		if profile.SensitiveDataAccess {
			conclusion.SensitiveSignalCount++
		}
		if profile.PrivilegeUse {
			conclusion.SensitiveSignalCount++
		}
	}
	conclusion.ClosureNarrative = buildCombinationClosureNarrative(selected, profile, risks, chains, tiSummary)
	for _, item := range risks {
		switch strings.ToLower(strings.TrimSpace(item.Risk.Level)) {
		case "high":
			conclusion.HighRiskCount++
		case "medium":
			conclusion.MediumRiskCount++
		case "low":
			conclusion.LowRiskCount++
		}
	}
	for _, item := range chains {
		if isHighConfidenceChain(item) {
			conclusion.HighConfidenceChains++
		}
	}
	switch {
	case conclusion.HighRiskCount > 0 || conclusion.HighConfidenceChains > 0:
		conclusion.RiskLevel = "high"
		conclusion.RiskLabel = "高风险"
		conclusion.Recommendation = "建议暂停组合准入，优先收敛命令执行、敏感访问或外联链路后再复核。"
	case conclusion.MediumRiskCount > 0 || conclusion.SensitiveSignalCount >= 3 || (conclusion.SensitiveSignalCount >= 2 && len(chains) > 0) || conclusion.TransferRiskScore >= 0.55 || conclusion.TIThreatCount > 0 || conclusion.TISuspiciousCount >= 2:
		conclusion.RiskLevel = "medium"
		conclusion.RiskLabel = "中风险"
		conclusion.Recommendation = "建议补充组合场景限制条件，并对白名单、输入边界和数据流向做二次确认。"
		if conclusion.TIThreatCount > 0 {
			conclusion.Recommendation = "组合外联目标命中高风险情报，建议先阻断对应外联并完成人工复核。"
		} else if conclusion.TISuspiciousCount > 0 {
			conclusion.Recommendation = "组合外联目标存在可疑情报信号，建议收敛目标白名单并补充调用链审计。"
		}
		if conclusion.TransferRiskScore >= 0.55 {
			conclusion.Recommendation = "组合能力存在较强风险传递性，建议按调用链收敛输入来源、外联目标和执行能力后再复核。"
		}
	}
	if conclusion.SelectedSkillCount == 0 {
		conclusion.RiskLevel = "low"
		conclusion.RiskLabel = "待分析"
		conclusion.ClosureNarrative = "当前未选择足够技能，尚未形成可分析的跨技能闭环。"
		conclusion.Recommendation = "请选择两个或以上技能查看组合风险结论。"
	}
	return conclusion
}

func buildCombinationClosureNarrative(selected []SkillOption, profile *admissionmodel.CapabilityProfile, risks []CombinedRisk, chains []InferredChain, tiSummary tiRiskSummary) string {
	selectedCount := len(selected)
	if selectedCount == 0 {
		return "当前未选择足够技能，尚未形成可分析的跨技能闭环。"
	}
	if selectedCount == 1 {
		return "当前仅选中单个技能，已识别局部能力信号，跨技能 source 与 sink 仍待补齐。"
	}
	hasSource := false
	hasSink := false
	hasTransform := false
	hasRuntime := false
	for _, item := range risks {
		level := strings.ToLower(strings.TrimSpace(item.Risk.Level))
		if level == "high" || level == "medium" {
			hasRuntime = true
		}
		text := strings.ToLower(strings.TrimSpace(item.Risk.Category + " " + item.Risk.Title + " " + item.Risk.Description))
		if strings.Contains(text, "credential") || strings.Contains(text, "sensitive") || strings.Contains(text, "file read") || strings.Contains(text, "读取") || strings.Contains(text, "采集") {
			hasSource = true
		}
		if strings.Contains(text, "network") || strings.Contains(text, "外联") || strings.Contains(text, "exfil") || strings.Contains(text, "download") || strings.Contains(text, "执行") || strings.Contains(text, "command") {
			hasSink = true
		}
	}
	if profile != nil {
		hasSource = hasSource || profile.SensitiveDataAccess || profile.FileRead || profile.DataCollection || profile.NetworkAccess || profile.ExternalFetch
		hasTransform = hasTransform || profile.FileWrite || profile.ExternalFetch || profile.ToolInvocation
		hasSink = hasSink || profile.NetworkAccess || profile.CommandExec || profile.Persistence
	}
	for _, chain := range chains {
		if len(chain.SourceSkills) >= 2 {
			hasRuntime = true
		}
		text := strings.ToLower(strings.TrimSpace(chain.Title + " " + chain.Summary + " " + strings.Join(chain.Evidence, " ")))
		if strings.Contains(text, "sensitive") || strings.Contains(text, "credential") || strings.Contains(text, "file read") || strings.Contains(text, "采集") || strings.Contains(text, "读取") {
			hasSource = true
		}
		if strings.Contains(text, "download") || strings.Contains(text, "write") || strings.Contains(text, "fetch") || strings.Contains(text, "落地") || strings.Contains(text, "transform") {
			hasTransform = true
		}
		if strings.Contains(text, "network") || strings.Contains(text, "command") || strings.Contains(text, "exec") || strings.Contains(text, "外联") || strings.Contains(text, "执行") || strings.Contains(text, "回连") {
			hasSink = true
		}
	}
	if tiSummary.ThreatCount > 0 || tiSummary.SuspiciousCount > 0 {
		hasRuntime = true
	}
	required := map[string]bool{}
	for _, chain := range chains {
		for _, item := range chain.ClosureRequirements {
			required[strings.ToLower(strings.TrimSpace(item))] = true
		}
	}
	if len(required) == 0 {
		required["source"] = true
		required["sink"] = true
		required["runtime"] = true
		if hasTransform {
			required["transform"] = true
		}
	}
	meets := func(key string) bool {
		switch key {
		case "source":
			return hasSource
		case "transform":
			return hasTransform
		case "sink":
			return hasSink
		case "runtime":
			return hasRuntime
		default:
			return true
		}
	}
	allMet := true
	for key := range required {
		if !meets(key) {
			allMet = false
			break
		}
	}
	if allMet {
		if hasTransform {
			return "当前组合已形成 source-transform-sink 闭环，且存在跨技能运行支撑，建议按高优先级组合风险处理。"
		}
		return "当前组合已形成 source-sink 主闭环，并具备跨技能运行支撑，建议优先复核触发条件与最小权限边界。"
	}
	gaps := make([]string, 0, 4)
	if required["source"] && !hasSource {
		gaps = append(gaps, "source")
	}
	if required["transform"] && !hasTransform {
		gaps = append(gaps, "transform")
	}
	if required["sink"] && !hasSink {
		gaps = append(gaps, "sink")
	}
	if required["runtime"] && !hasRuntime {
		gaps = append(gaps, "runtime")
	}
	return "当前组合已识别部分跨技能联动信号，闭环仍缺少 " + strings.Join(gaps, "/") + " 支撑，建议沿调用链继续补证。"
}

func capabilityLevel(profile *admissionmodel.CapabilityProfile, key string, fallback bool) float64 {
	if profile == nil {
		return 0
	}
	if profile.CapabilityLevels != nil {
		if v, ok := profile.CapabilityLevels[key]; ok {
			if v < 0 {
				return 0
			}
			if v > 1 {
				return 1
			}
			return v
		}
	}
	if fallback {
		return 0.35
	}
	return 0
}

func calculateTransferRisk(profile *admissionmodel.CapabilityProfile) float64 {
	if profile == nil {
		return 0
	}
	type edge struct {
		from   string
		to     string
		weight float64
	}
	edges := []edge{
		{from: "sensitive_data_access", to: "network_access", weight: 0.9},
		{from: "file_read", to: "network_access", weight: 0.8},
		{from: "external_fetch", to: "file_write", weight: 0.7},
		{from: "external_fetch", to: "command_exec", weight: 0.85},
		{from: "network_access", to: "command_exec", weight: 0.8},
		{from: "file_write", to: "command_exec", weight: 0.75},
	}
	levels := map[string]float64{
		"network_access":        capabilityLevel(profile, "network_access", profile.NetworkAccess),
		"file_read":             capabilityLevel(profile, "file_read", profile.FileRead),
		"file_write":            capabilityLevel(profile, "file_write", profile.FileWrite),
		"command_exec":          capabilityLevel(profile, "command_exec", profile.CommandExec),
		"sensitive_data_access": capabilityLevel(profile, "sensitive_data_access", profile.SensitiveDataAccess),
		"external_fetch":        capabilityLevel(profile, "external_fetch", profile.ExternalFetch),
	}
	total := 0.0
	for _, e := range edges {
		total += levels[e.from] * levels[e.to] * e.weight
	}
	maxScore := float64(len(edges))
	if maxScore <= 0 {
		return 0
	}
	normalized := total / maxScore
	if normalized < 0 {
		normalized = 0
	}
	if normalized > 1 {
		normalized = 1
	}
	return math.Round(normalized*100) / 100
}

func isHighConfidenceChain(chain InferredChain) bool {
	if strings.ToLower(strings.TrimSpace(chain.Level)) != "high" {
		return false
	}
	if len(chain.SourceSkills) < 2 {
		return false
	}
	if len(chain.Evidence) < 2 {
		return false
	}
	return true
}

type chainSupportIndex struct {
	skillCaps      map[string][]string
	skillCapSets   map[string]map[string]struct{}
	evidenceOwners map[string]map[string]struct{}
	skillCount     int
}

func buildChainSupportIndex(selected []selectedSignal, skillCaps map[string][]string) chainSupportIndex {
	idx := chainSupportIndex{
		skillCaps:      skillCaps,
		skillCapSets:   make(map[string]map[string]struct{}, len(selected)),
		evidenceOwners: make(map[string]map[string]struct{}),
		skillCount:     len(selected),
	}
	for _, item := range selected {
		if item.Profile == nil {
			continue
		}
		skillID := strings.TrimSpace(item.Option.SkillID)
		if skillID == "" {
			continue
		}
		capSet := make(map[string]struct{}, 10)
		for _, capability := range item.Profile.ToDetectedCapabilities() {
			capability = strings.TrimSpace(capability)
			if capability == "" {
				continue
			}
			capSet[capability] = struct{}{}
		}
		if len(capSet) > 0 {
			idx.skillCapSets[skillID] = capSet
		}
		for _, profileEvidence := range item.Profile.Evidence {
			evidence := strings.TrimSpace(profileEvidence)
			if evidence == "" {
				continue
			}
			owners := idx.evidenceOwners[evidence]
			if owners == nil {
				owners = map[string]struct{}{}
				idx.evidenceOwners[evidence] = owners
			}
			owners[skillID] = struct{}{}
		}
	}
	return idx
}

func hasChainSupport(index chainSupportIndex, evidence []string, capabilities ...string) bool {
	if index.skillCount < 2 || len(evidence) == 0 || len(capabilities) < 2 {
		return false
	}
	coveredCaps := 0
	for _, capability := range capabilities {
		if len(index.skillCaps[capability]) > 0 {
			coveredCaps++
		}
	}
	if coveredCaps < 2 {
		return false
	}
	if countEvidenceBackedSkills(index, evidence) >= 2 {
		return true
	}
	for skillID, capSet := range index.skillCapSets {
		if capabilityCoverageInSet(capSet, capabilities...) >= 2 && evidenceCoverageForSkill(index, skillID, evidence) >= 2 {
			return true
		}
	}
	return false
}

func buildSkillCapabilityIndex(selected []selectedSignal) map[string][]string {
	index := make(map[string][]string, 10)
	seenByCapability := make(map[string]map[string]struct{}, 10)
	for _, item := range selected {
		if item.Profile == nil {
			continue
		}
		skillID := strings.TrimSpace(item.Option.SkillID)
		if skillID == "" {
			continue
		}
		for _, capability := range item.Profile.ToDetectedCapabilities() {
			capability = strings.TrimSpace(capability)
			if capability == "" {
				continue
			}
			seen := seenByCapability[capability]
			if seen == nil {
				seen = map[string]struct{}{}
				seenByCapability[capability] = seen
			}
			if _, exists := seen[skillID]; exists {
				continue
			}
			seen[skillID] = struct{}{}
			index[capability] = append(index[capability], skillID)
		}
	}
	for capability := range index {
		sort.Strings(index[capability])
	}
	return index
}

func containsString(items []string, target string) bool {
	target = strings.TrimSpace(target)
	if target == "" {
		return false
	}
	for _, item := range items {
		if strings.TrimSpace(item) == target {
			return true
		}
	}
	return false
}

func countEvidenceBackedSkills(index chainSupportIndex, evidence []string) int {
	coveredSkills := map[string]struct{}{}
	for _, item := range evidence {
		e := strings.TrimSpace(item)
		if e == "" {
			continue
		}
		for skillID := range index.evidenceOwners[e] {
			coveredSkills[skillID] = struct{}{}
			if len(coveredSkills) >= 2 {
				return len(coveredSkills)
			}
		}
	}
	return len(coveredSkills)
}

func evidenceCoverageForSkill(index chainSupportIndex, skillID string, evidence []string) int {
	count := 0
	for _, item := range evidence {
		e := strings.TrimSpace(item)
		if e == "" {
			continue
		}
		if owners := index.evidenceOwners[e]; owners != nil {
			if _, ok := owners[skillID]; ok {
				count++
			}
		}
	}
	return count
}

func capabilityCoverageInSet(capSet map[string]struct{}, capabilities ...string) int {
	count := 0
	for _, capability := range capabilities {
		if _, ok := capSet[capability]; ok {
			count++
		}
	}
	return count
}

func profileContainsAnyEvidence(profile *admissionmodel.CapabilityProfile, evidence []string) bool {
	return profileEvidenceCoverage(profile, evidence) > 0
}

func profileEvidenceCoverage(profile *admissionmodel.CapabilityProfile, evidence []string) int {
	if profile == nil {
		return 0
	}
	count := 0
	for _, profileEvidence := range profile.Evidence {
		candidate := strings.TrimSpace(profileEvidence)
		if candidate == "" {
			continue
		}
		for _, item := range evidence {
			if candidate == strings.TrimSpace(item) {
				count++
				break
			}
		}
	}
	return count
}

func profileCapabilityCoverage(profile *admissionmodel.CapabilityProfile, capabilities ...string) int {
	count := 0
	for _, capability := range capabilities {
		if profileHasCapability(profile, capability) {
			count++
		}
	}
	return count
}

func profileHasCapability(profile *admissionmodel.CapabilityProfile, capability string) bool {
	if profile == nil {
		return false
	}
	switch capability {
	case "network_access":
		return profile.NetworkAccess
	case "command_exec":
		return profile.CommandExec
	case "sensitive_data_access":
		return profile.SensitiveDataAccess
	case "file_write":
		return profile.FileWrite
	case "file_read":
		return profile.FileRead
	case "external_fetch":
		return profile.ExternalFetch
	case "data_collection":
		return profile.DataCollection
	case "persistence":
		return profile.Persistence
	case "privilege_use":
		return profile.PrivilegeUse
	case "tool_invocation":
		return profile.ToolInvocation
	default:
		return false
	}
}

func chainEvidenceKeywords(capabilities ...string) []string {
	out := make([]string, 0, len(capabilities)*3)
	for _, capability := range capabilities {
		switch capability {
		case "network_access":
			out = append(out, "http", "https://", "outbound", "api")
		case "command_exec":
			out = append(out, "exec", "command", "shell")
		case "sensitive_data_access":
			out = append(out, "/root/.netrc", "credential", "token", "secret")
		case "file_write":
			out = append(out, "drop", "write", "file")
		case "file_read":
			out = append(out, "read", "open(", "credential", "/etc/", ".env")
		case "external_fetch":
			out = append(out, "download", "fetch", "http", "https://")
		case "data_collection":
			out = append(out, "collect", "harvest", "dump", "gather", "scan")
		case "persistence":
			out = append(out, "autorun", "crontab", "startup", "persist", "systemd")
		case "privilege_use":
			out = append(out, "sudo", "setuid", "admin", "root", "privilege")
		case "tool_invocation":
			out = append(out, "tool", "call_tool", "invoke", "mcp", "agent")
		}
	}
	return normalizeStrings(out)
}

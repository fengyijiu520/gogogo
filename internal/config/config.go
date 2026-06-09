package config

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config 整体配置结构
type Config struct {
	Version    string      `yaml:"version"`
	RiskLevels []RiskLevel `yaml:"risk_levels"`
	Rules      []Rule      `yaml:"rules"`
	RuleGroups []RuleGroup `yaml:"rule_groups"` // v3.0 格式
}

// RuleGroup v3.0 规则组
type RuleGroup struct {
	ID       string     `yaml:"id"`
	Category string     `yaml:"category"`
	Items    []RuleItem `yaml:"items"`
}

// RuleItem v3.0 规则条目
type RuleItem struct {
	ID             string   `yaml:"id"`
	Item           string   `yaml:"item"`
	RiskPersonal   string   `yaml:"risk_personal"`
	RiskNonPersonal string  `yaml:"risk_nonpersonal"`
	DetectionTarget string  `yaml:"detection_target"`
	DetectionMethod string  `yaml:"detection_method"`
	Detection       Detection `yaml:"detection"`
	FixSuggestion  string   `yaml:"fix_suggestion"`
}

// RiskLevel 风险等级阈值定义
type RiskLevel struct {
	Threshold     float64 `yaml:"threshold"`
	Level         string  `yaml:"level"`
	AutoApprove   bool    `yaml:"auto_approve"`
	RequireReview bool    `yaml:"require_review"`
	Block         bool    `yaml:"block"`
}

// Rule 单条规则定义
type Rule struct {
	ID           string    `yaml:"id"`
	Name         string    `yaml:"name"`
	Severity     string    `yaml:"severity"` // high / medium / low 或 高风险 / 中风险 / 低风险
	Layer        string    `yaml:"layer"`    // P0 / P1 / P2
	Weight       float64   `yaml:"weight"`
	Detection    Detection `yaml:"detection"`
	OnFail       OnFail    `yaml:"on_fail"`
	Review       Review    `yaml:"review"`
	Compensation bool      `yaml:"compensation"`
}

// Review 规则复核元数据，借鉴 AI-Infra-Guard 的 prompt_template 规则组织方式。
type Review struct {
	PromptTemplate           string   `yaml:"prompt_template"`
	DetectionCriteria        []string `yaml:"detection_criteria"`
	ExclusionConditions      []string `yaml:"exclusion_conditions"`
	VerificationRequirements []string `yaml:"verification_requirements"`
	OutputRequirements       []string `yaml:"output_requirements"`
	RemediationFocus         string   `yaml:"remediation_focus"`
}

// Detection 检测方式配置
type Detection struct {
	Type          string   `yaml:"type"`          // pattern / forbid_pattern / require_pattern / function / semantic
	Function      string   `yaml:"function"`      // 函数名（type=function时）
	Patterns      []string `yaml:"patterns"`      // 正则列表（type=pattern/forbid_pattern/require_pattern时）
	ThresholdLow  float64  `yaml:"threshold_low"` // semantic用
	ThresholdHigh float64  `yaml:"threshold_high"`
	IncludeGlobs  []string `yaml:"include_globs"` // 文件 glob 白名单
	PassIf        string   `yaml:"pass_if"`       // 通过条件：no_match / match_found
	Reason        string   `yaml:"reason"`        // 检测说明

	// require_pattern / forbid_pattern 用
	RequiredFiles []string `yaml:"required_files"` // require_file_presence 用：必须存在的文件名列表

	// code_vs_docs 用
	CodeIncludeGlobs []string `yaml:"code_include_globs"` // 代码文件 glob
	CodePatterns     []string `yaml:"code_patterns"`      // 代码中要搜索的高风险模式
	DocIncludeGlobs  []string `yaml:"doc_include_globs"`  // 文档文件 glob
	DocPatterns      []string `yaml:"doc_patterns"`       // 文档中应出现的声明模式

	// artifact_vs_docs 用
	ArtifactIncludeGlobs []string `yaml:"artifact_include_globs"` // 制品文件 glob
	ArtifactPatterns     []string `yaml:"artifact_patterns"`      // 制品文件名模式
}

// OnFail 失败处理配置
type OnFail struct {
	Action              string `yaml:"action"`                // block / review / remediate
	Reason              string `yaml:"reason"`                // 风险原因
	NoCompensationBlock bool   `yaml:"no_compensation_block"` // 兼容旧配置的阻断标记
}

// Load 从指定路径加载配置文件
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	// v3.0 格式：将 rule_groups 展平为 rules
	if len(cfg.Rules) == 0 && len(cfg.RuleGroups) > 0 {
		cfg.Rules = flattenRuleGroups(cfg.RuleGroups)
	}
	normalizeRuleCompatibility(&cfg)
	return &cfg, nil
}

// flattenRuleGroups 将 v3.0 的 rule_groups 展平为 v2.0 的 rules 格式
func flattenRuleGroups(groups []RuleGroup) []Rule {
	var rules []Rule
	for _, group := range groups {
		for _, item := range group.Items {
			rule := Rule{
				ID:       item.ID,
				Name:     item.Item,
				Severity: riskLevelToSeverity(item.RiskNonPersonal),
				Layer:    riskLevelToLayer(item.RiskNonPersonal),
				Detection: item.Detection,
			}
			// 如果 detection 没有 type，根据 detection_method 推断
			if rule.Detection.Type == "" {
				rule.Detection.Type = "pattern"
			}
			// 构造 on_fail
			rule.OnFail = OnFail{
				Action: riskLevelToAction(item.RiskNonPersonal),
				Reason: item.Item,
			}
			rules = append(rules, rule)
		}
	}
	return rules
}

func riskLevelToSeverity(risk string) string {
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

func riskLevelToLayer(risk string) string {
	switch strings.TrimSpace(risk) {
	case "高":
		return "P0"
	case "中":
		return "P1"
	case "低":
		return "P2"
	default:
		return "P1"
	}
}

func riskLevelToAction(risk string) string {
	switch strings.TrimSpace(risk) {
	case "高":
		return "block"
	case "中":
		return "review"
	default:
		return "remediate"
	}
}

func normalizeRuleCompatibility(cfg *Config) {
	for i := range cfg.Rules {
		rule := &cfg.Rules[i]
		if rule.Layer == "" {
			switch rule.Severity {
			case "高风险", "high":
				rule.Layer = "P0"
			case "中风险", "medium":
				rule.Layer = "P1"
			case "低风险", "low":
				rule.Layer = "P2"
			}
		}
		if rule.Severity == "" {
			switch rule.Layer {
			case "P0":
				rule.Severity = "高风险"
			case "P1":
				rule.Severity = "中风险"
			case "P2":
				rule.Severity = "低风险"
			}
		}
	}
}

package config

import (
	"gopkg.in/yaml.v3"
	"os"
)

// Config 整体配置结构
type Config struct {
	Version    string      `yaml:"version"`
	RiskLevels []RiskLevel `yaml:"risk_levels"`
	Rules      []Rule      `yaml:"rules"`
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
	Type          string   `yaml:"type"`          // pattern / function / semantic
	Function      string   `yaml:"function"`      // 函数名（type=function时）
	Patterns      []string `yaml:"patterns"`      // 正则列表（type=pattern时）
	ThresholdLow  float64  `yaml:"threshold_low"` // semantic用
	ThresholdHigh float64  `yaml:"threshold_high"`
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
	normalizeRuleCompatibility(&cfg)
	return &cfg, nil
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

package config

import (
	"os"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type ReviewPolicyConfig struct {
	Version        string                    `yaml:"version"`
	ThreatSignals  []string                  `yaml:"threat_signals"`
	FalsePositive  ReviewFalsePositivePolicy `yaml:"false_positive"`
	ScanAsync      ReviewScanAsyncPolicy     `yaml:"scan_async"`
	Evaluator      ReviewEvaluatorPolicy     `yaml:"evaluator"`
	refutedPrimaryClaimIndex map[string][]string
	categoryRefutationIndex  map[string][]string
	closureSignalIndex       map[string]ReviewClosureSignals
	weakStaticThresholdIndex map[string]ReviewCategoryMissingThreshold
}

type ReviewFalsePositivePolicy struct {
	WeakStaticTitles             []string                  `yaml:"weak_static_titles"`
	OpenWeakTitles               []string                  `yaml:"open_weak_titles"`
	EvidenceIntentMismatchMarkers []string                 `yaml:"evidence_intent_mismatch_markers"`
	RefutedPrimaryClaims         []ReviewTitleMarkers      `yaml:"refuted_primary_claims"`
	CategoryRefutations          []ReviewCategoryMarkers   `yaml:"category_refutations"`
}

type ReviewTitleMarkers struct {
	Title   string   `yaml:"title"`
	Markers []string `yaml:"markers"`
}

type ReviewCategoryMarkers struct {
	Category string   `yaml:"category"`
	Markers  []string `yaml:"markers"`
}

type ReviewScanAsyncPolicy struct {
	DirectConfirmation ReviewDirectConfirmationPolicy `yaml:"direct_confirmation"`
	RuntimeClosure     ReviewRuntimeClosurePolicy     `yaml:"runtime_closure"`
	WeakStaticPreference ReviewWeakStaticPreferencePolicy `yaml:"weak_static_preference"`
	ClosureSignals     []ReviewCategoryClosureSignals `yaml:"closure_signals"`
}

type ReviewRuntimeClosurePolicy struct {
	CategoriesWithoutRuntime []string `yaml:"categories_without_runtime"`
}

type ReviewWeakStaticPreferencePolicy struct {
	AlwaysPreferWhenMissingAtLeast []ReviewCategoryMissingThreshold `yaml:"always_prefer_when_missing_at_least"`
	EvidenceIntentMismatchCategories []string                       `yaml:"evidence_intent_mismatch_categories"`
	OpenWeakCategories             []string                         `yaml:"open_weak_categories"`
}

type ReviewCategoryMissingThreshold struct {
	Category                  string `yaml:"category"`
	MissingThreshold          int    `yaml:"missing_threshold"`
	RequireOpenClosure        bool   `yaml:"require_open_closure"`
	RequireNoMeaningfulClosure bool  `yaml:"require_no_meaningful_closure"`
}

type ReviewDirectConfirmationPolicy struct {
	SSRF ReviewSSRFDirectConfirmation `yaml:"ssrf"`
}

type ReviewSSRFDirectConfirmation struct {
	RequestCall       []string `yaml:"request_call"`
	UserControlledInput []string `yaml:"user_controlled_input"`
	DangerousTarget   []string `yaml:"dangerous_target"`
	MissingGuard      []string `yaml:"missing_guard"`
}

type ReviewCategoryClosureSignals struct {
	Category  string   `yaml:"category"`
	Source    []string `yaml:"source"`
	Transform []string `yaml:"transform"`
	Sink      []string `yaml:"sink"`
}

type ReviewClosureSignals struct {
	Source    []string
	Transform []string
	Sink      []string
}

type ReviewEvaluatorPolicy struct {
	SensitiveSignalPatterns map[string][]string        `yaml:"sensitive_signal_patterns"`
	SensitiveActionKeywords ReviewSensitiveActionWords `yaml:"sensitive_action_keywords"`
	ResourceRiskPatterns    ReviewResourceRiskPatterns `yaml:"resource_risk_patterns"`
	AuditPatterns           ReviewAuditPatterns        `yaml:"audit_patterns"`
}

type ReviewSensitiveActionWords struct {
	NetworkSend []string `yaml:"network_send"`
	LogOutput   []string `yaml:"log_output"`
	Persistence []string `yaml:"persistence"`
	InputReceive []string `yaml:"input_receive"`
	SQLWrite    []string `yaml:"sql_write"`
}

type ReviewResourceRiskPatterns struct {
	Loop         string `yaml:"loop"`
	Goroutine    string `yaml:"goroutine"`
	Retry        string `yaml:"retry"`
	Network      string `yaml:"network"`
	TimeoutGuard string `yaml:"timeout_guard"`
	BackoffGuard string `yaml:"backoff_guard"`
}

type ReviewAuditPatterns struct {
	SensitiveLog   string `yaml:"sensitive_log"`
	SilentException string `yaml:"silent_exception"`
	HighImpact     string `yaml:"high_impact"`
	Audit          string `yaml:"audit"`
}

var (
	reviewPolicyOnce sync.Once
	reviewPolicyCfg  *ReviewPolicyConfig
	reviewPolicyErr  error
)

func LoadReviewPolicy(path string) (*ReviewPolicyConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg ReviewPolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.buildIndexes()
	return &cfg, nil
}

func (c *ReviewPolicyConfig) buildIndexes() {
	if c == nil {
		return
	}
	c.refutedPrimaryClaimIndex = make(map[string][]string, len(c.FalsePositive.RefutedPrimaryClaims))
	for _, item := range c.FalsePositive.RefutedPrimaryClaims {
		key := strings.TrimSpace(item.Title)
		if key == "" {
			continue
		}
		c.refutedPrimaryClaimIndex[key] = item.Markers
	}
	c.categoryRefutationIndex = make(map[string][]string, len(c.FalsePositive.CategoryRefutations))
	for _, item := range c.FalsePositive.CategoryRefutations {
		key := strings.TrimSpace(item.Category)
		if key == "" {
			continue
		}
		c.categoryRefutationIndex[key] = item.Markers
	}
	c.closureSignalIndex = make(map[string]ReviewClosureSignals, len(c.ScanAsync.ClosureSignals))
	for _, item := range c.ScanAsync.ClosureSignals {
		key := strings.TrimSpace(item.Category)
		if key == "" {
			continue
		}
		c.closureSignalIndex[key] = ReviewClosureSignals{
			Source:    item.Source,
			Transform: item.Transform,
			Sink:      item.Sink,
		}
	}
	c.weakStaticThresholdIndex = make(map[string]ReviewCategoryMissingThreshold, len(c.ScanAsync.WeakStaticPreference.AlwaysPreferWhenMissingAtLeast))
	for _, item := range c.ScanAsync.WeakStaticPreference.AlwaysPreferWhenMissingAtLeast {
		key := strings.TrimSpace(item.Category)
		if key == "" {
			continue
		}
		c.weakStaticThresholdIndex[key] = item
	}
}

func (c *ReviewPolicyConfig) RefutedPrimaryClaimMarkers(title string) []string {
	if c == nil {
		return nil
	}
	return c.refutedPrimaryClaimIndex[strings.TrimSpace(title)]
}

func (c *ReviewPolicyConfig) CategoryRefutationMarkers(category string) []string {
	if c == nil {
		return nil
	}
	return c.categoryRefutationIndex[strings.TrimSpace(category)]
}

func (c *ReviewPolicyConfig) ClosureSignals(category string) ReviewClosureSignals {
	if c == nil {
		return ReviewClosureSignals{}
	}
	return c.closureSignalIndex[strings.TrimSpace(category)]
}

func (c *ReviewPolicyConfig) RequiresRuntimeClosure(category string, fallback bool, categoriesWithoutRuntime []string) bool {
	if c == nil {
		for _, item := range categoriesWithoutRuntime {
			if strings.TrimSpace(item) == strings.TrimSpace(category) {
				return false
			}
		}
		return fallback
	}
	configured := c.ScanAsync.RuntimeClosure.CategoriesWithoutRuntime
	if len(configured) == 0 {
		configured = categoriesWithoutRuntime
	}
	for _, item := range configured {
		if strings.TrimSpace(item) == strings.TrimSpace(category) {
			return false
		}
	}
	return fallback
}

func (c *ReviewPolicyConfig) EffectiveRuntimeClosureCategoriesWithoutRuntime() []string {
	fallback := []string{"外联与情报", "凭据访问", "凭据暴露"}
	if c != nil && len(c.ScanAsync.RuntimeClosure.CategoriesWithoutRuntime) > 0 {
		return c.ScanAsync.RuntimeClosure.CategoriesWithoutRuntime
	}
	return fallback
}

func (c *ReviewPolicyConfig) WeakStaticThreshold(category string) (ReviewCategoryMissingThreshold, bool) {
	fallback := map[string]ReviewCategoryMissingThreshold{
		"环境与构建风险": {
			Category:         "环境与构建风险",
			MissingThreshold: 3,
		},
		"静态规则发现": {
			Category:           "静态规则发现",
			MissingThreshold:   3,
			RequireOpenClosure: true,
		},
		"授权与许可证校验": {
			Category:                   "授权与许可证校验",
			MissingThreshold:           3,
			RequireNoMeaningfulClosure: true,
		},
		"声明与行为差异": {
			Category:                   "声明与行为差异",
			MissingThreshold:           3,
			RequireNoMeaningfulClosure: true,
		},
	}
	if c == nil {
		item, ok := fallback[strings.TrimSpace(category)]
		return item, ok
	}
	item, ok := c.weakStaticThresholdIndex[strings.TrimSpace(category)]
	if ok {
		return item, true
	}
	item, ok = fallback[strings.TrimSpace(category)]
	return item, ok
}

func (c *ReviewPolicyConfig) IsOpenWeakCategory(category string, fallback []string) bool {
	items := fallback
	if len(items) == 0 {
		items = []string{"环境与构建风险", "静态规则发现", "声明与行为差异", "隐私合规与数据最小化"}
	}
	if c != nil && len(c.ScanAsync.WeakStaticPreference.OpenWeakCategories) > 0 {
		items = c.ScanAsync.WeakStaticPreference.OpenWeakCategories
	}
	for _, item := range items {
		if strings.TrimSpace(item) == strings.TrimSpace(category) {
			return true
		}
	}
	return false
}

func (c *ReviewPolicyConfig) IsEvidenceIntentMismatchCategory(category string, fallback []string) bool {
	items := fallback
	if len(items) == 0 {
		items = []string{"隐私合规与数据最小化", "声明与行为差异", "静态规则发现"}
	}
	if c != nil && len(c.ScanAsync.WeakStaticPreference.EvidenceIntentMismatchCategories) > 0 {
		items = c.ScanAsync.WeakStaticPreference.EvidenceIntentMismatchCategories
	}
	for _, item := range items {
		if strings.TrimSpace(item) == strings.TrimSpace(category) {
			return true
		}
	}
	return false
}

func (c *ReviewPolicyConfig) EffectiveWeakStaticTitles() []string {
	fallback := []string{"Python 系统包安装风险", "依赖漏洞与恶意依赖-高危漏洞依赖", "隐藏风险内容-代码混淆隐藏", "日志审计与敏感信息脱敏-关键事件无审计", "资源耗尽与级联失败-无限循环/无超时", "未声明的模拟动量回退导致可能基于虚假数据交易"}
	if c != nil && len(c.FalsePositive.WeakStaticTitles) > 0 {
		return c.FalsePositive.WeakStaticTitles
	}
	return fallback
}

func (c *ReviewPolicyConfig) EffectiveOpenWeakTitles() []string {
	fallback := []string{"依赖漏洞与恶意依赖-高危漏洞依赖", "隐藏风险内容-代码混淆隐藏", "隐私合规与数据最小化-过度收集个人信息", "Python 系统包安装风险"}
	if c != nil && len(c.FalsePositive.OpenWeakTitles) > 0 {
		return c.FalsePositive.OpenWeakTitles
	}
	return fallback
}

func (c *ReviewPolicyConfig) EffectiveEvidenceIntentMismatchMarkers() []string {
	fallback := []string{"主题与证据不匹配", "规则主题与证据不匹配", "未发现递归调用", "普通文件读取", "仅为文件读取", "仅本地读取", "仅本地 sqlite", "仅本地数据库读取", "当前缺少外发或暴露链路", "仅有规则侧建议", "需结合真实提交与用途核验", "无网络暴露", "没有代码实现"}
	if c != nil && len(c.FalsePositive.EvidenceIntentMismatchMarkers) > 0 {
		return c.FalsePositive.EvidenceIntentMismatchMarkers
	}
	return fallback
}

func (c *ReviewPolicyConfig) EffectiveThreatSignals(fallback []string) []string {
	if c != nil && len(c.ThreatSignals) > 0 {
		return c.ThreatSignals
	}
	return fallback
}

func (c *ReviewPolicyConfig) EffectiveSQLWriteKeywords(fallback []string) []string {
	if c != nil && len(c.Evaluator.SensitiveActionKeywords.SQLWrite) > 0 {
		return c.Evaluator.SensitiveActionKeywords.SQLWrite
	}
	return fallback
}

func (c *ReviewPolicyConfig) EffectiveSensitiveActionKeywords() ReviewSensitiveActionWords {
	return c.Evaluator.SensitiveActionKeywords
}

func (c *ReviewPolicyConfig) EffectiveResourceRiskPatterns(fallback ReviewResourceRiskPatterns) ReviewResourceRiskPatterns {
	if c == nil {
		return fallback
	}
	patterns := fallback
	if strings.TrimSpace(c.Evaluator.ResourceRiskPatterns.Loop) != "" {
		patterns.Loop = c.Evaluator.ResourceRiskPatterns.Loop
	}
	if strings.TrimSpace(c.Evaluator.ResourceRiskPatterns.Goroutine) != "" {
		patterns.Goroutine = c.Evaluator.ResourceRiskPatterns.Goroutine
	}
	if strings.TrimSpace(c.Evaluator.ResourceRiskPatterns.Retry) != "" {
		patterns.Retry = c.Evaluator.ResourceRiskPatterns.Retry
	}
	if strings.TrimSpace(c.Evaluator.ResourceRiskPatterns.Network) != "" {
		patterns.Network = c.Evaluator.ResourceRiskPatterns.Network
	}
	if strings.TrimSpace(c.Evaluator.ResourceRiskPatterns.TimeoutGuard) != "" {
		patterns.TimeoutGuard = c.Evaluator.ResourceRiskPatterns.TimeoutGuard
	}
	if strings.TrimSpace(c.Evaluator.ResourceRiskPatterns.BackoffGuard) != "" {
		patterns.BackoffGuard = c.Evaluator.ResourceRiskPatterns.BackoffGuard
	}
	return patterns
}

func (c *ReviewPolicyConfig) EffectiveAuditPatterns(fallback ReviewAuditPatterns) ReviewAuditPatterns {
	if c == nil {
		return fallback
	}
	patterns := fallback
	if strings.TrimSpace(c.Evaluator.AuditPatterns.SensitiveLog) != "" {
		patterns.SensitiveLog = c.Evaluator.AuditPatterns.SensitiveLog
	}
	if strings.TrimSpace(c.Evaluator.AuditPatterns.SilentException) != "" {
		patterns.SilentException = c.Evaluator.AuditPatterns.SilentException
	}
	if strings.TrimSpace(c.Evaluator.AuditPatterns.HighImpact) != "" {
		patterns.HighImpact = c.Evaluator.AuditPatterns.HighImpact
	}
	if strings.TrimSpace(c.Evaluator.AuditPatterns.Audit) != "" {
		patterns.Audit = c.Evaluator.AuditPatterns.Audit
	}
	return patterns
}

func DefaultReviewPolicy() (*ReviewPolicyConfig, error) {
	reviewPolicyOnce.Do(func() {
		reviewPolicyCfg, reviewPolicyErr = LoadReviewPolicy(ReviewPolicyConfigPath())
	})
	return reviewPolicyCfg, reviewPolicyErr
}

package ir

import (
	"fmt"
	"sort"
	"strings"
)

// =============================================================================
// 自动规则发现 (Rule Discovery)
//
// 从历史扫描结果中学习新模式，自动发现潜在的安全规则。
//
// 工作流：
//   1. 收集多批次扫描的 Finding 结果
//   2. 聚类分析：相同类别/位置/模式的发现归为一组
//   3. 频次分析：反复出现的模式可能是新规则
//   4. 生成候选规则，带置信度评分
//   5. 人工确认后纳入规则库
//
// 与误报/漏报反馈循环：
//   - dismissed 的发现 → 降低对应模式权重
//   - confirmed 的发现 → 提升对应模式权重
//   - 新发现的模式 → 生成候选规则
// =============================================================================

// ScanResult 单次扫描结果（输入）。
type ScanResult struct {
	// ScanID 扫描标识
	ScanID string `json:"scan_id"`
	// SkillName 技能名称
	SkillName string `json:"skill_name"`
	// Findings 发现列表
	Findings []Finding `json:"findings"`
	// Verdicts LLM 判定（可选）
	Verdicts []FindingVerdict `json:"verdicts,omitempty"`
	// Timestamp 时间戳
	Timestamp string `json:"timestamp,omitempty"`
}

// FindingVerdict 发现判定。
type FindingVerdict struct {
	// FindingID 关联的发现标识
	FindingID string `json:"finding_id"`
	// Verdict 判定：confirmed / dismissed / needs_review
	Verdict string `json:"verdict"`
	// Reason 原因
	Reason string `json:"reason"`
}

// DiscoveredRule 发现的候选规则。
type DiscoveredRule struct {
	// ID 候选规则 ID
	ID string `json:"id"`
	// Name 规则名称
	Name string `json:"name"`
	// Category 安全类别
	Category string `json:"category"`
	// Severity 建议严重性
	Severity string `json:"severity"`
	// Pattern 模式描述
	Pattern string `json:"pattern"`
	// FuncNamePattern 函数名模式
	FuncNamePattern string `json:"func_name_pattern,omitempty"`
	// ArgPattern 参数模式
	ArgPattern string `json:"arg_pattern,omitempty"`
	// Occurrences 出现次数
	Occurrences int `json:"occurrences"`
	// Confidence 置信度（0-1）
	Confidence float64 `json:"confidence"`
	// ConfirmedCount 被 LLM 确认的次数
	ConfirmedCount int `json:"confirmed_count"`
	// DismissedCount 被 LLM 驳回的次数
	DismissedCount int `json:"dismissed_count"`
	// SourceScans 来源扫描列表
	SourceScans []string `json:"source_scans"`
	// ExampleCode 示例代码
	ExampleCode string `json:"example_code,omitempty"`
	// ExampleLocation 示例位置
	ExampleLocation string `json:"example_location,omitempty"`
	// Remediation 建议修复方式
	Remediation string `json:"remediation,omitempty"`
}

// RuleDiscoveryEngine 规则发现引擎。
type RuleDiscoveryEngine struct {
	// minOccurrences 最小出现次数（低于此不生成规则）
	minOccurrences int
	// minConfidence 最低置信度
	minConfidence float64
}

// NewRuleDiscoveryEngine 创建规则发现引擎。
func NewRuleDiscoveryEngine(minOccurrences int, minConfidence float64) *RuleDiscoveryEngine {
	if minOccurrences <= 0 {
		minOccurrences = 2
	}
	if minConfidence <= 0 || minConfidence > 1 {
		minConfidence = 0.5
	}
	return &RuleDiscoveryEngine{
		minOccurrences: minOccurrences,
		minConfidence:  minConfidence,
	}
}

// Discover 从多批次扫描结果中发现新规则。
func (e *RuleDiscoveryEngine) Discover(results []ScanResult) []DiscoveredRule {
	if len(results) == 0 {
		return nil
	}

	// 1. 聚类：按类别+模式分组
	clusters := e.clusterFindings(results)

	// 2. 生成候选规则
	var rules []DiscoveredRule
	for key, cluster := range clusters {
		rule := e.buildCandidateRule(key, cluster)
		if rule != nil {
			rules = append(rules, *rule)
		}
	}

	// 3. 按置信度排序
	sort.Slice(rules, func(i, j int) bool {
		return rules[i].Confidence > rules[j].Confidence
	})

	return rules
}

// findingCluster 发现聚类。
type findingCluster struct {
	Category    string
	FuncPattern string
	Count       int
	Confirmed   int
	Dismissed   int
	Scans       []string
	Examples    []Finding
}

// clusterFindings 将发现按类别和模式聚类。
func (e *RuleDiscoveryEngine) clusterFindings(results []ScanResult) map[string]*findingCluster {
	clusters := make(map[string]*findingCluster)

	// 建立 verdict 索引
	verdictMap := make(map[string]string) // findingID → verdict
	for _, result := range results {
		for _, v := range result.Verdicts {
			verdictMap[v.FindingID] = v.Verdict
		}
	}

	for _, result := range results {
		for _, finding := range result.Findings {
			// 提取模式特征
			funcPattern := extractFuncPattern(finding)
			key := finding.Category + ":" + funcPattern

			cluster, exists := clusters[key]
			if !exists {
				cluster = &findingCluster{
					Category:    finding.Category,
					FuncPattern: funcPattern,
				}
				clusters[key] = cluster
			}

			cluster.Count++
			cluster.Scans = appendUniqueStr(cluster.Scans, result.ScanID)

			// 应用 verdict
			verdict := verdictMap[finding.RuleID]
			switch verdict {
			case "confirmed":
				cluster.Confirmed++
			case "dismissed":
				cluster.Dismissed++
			}

			// 保留示例（最多 3 个）
			if len(cluster.Examples) < 3 {
				cluster.Examples = append(cluster.Examples, finding)
			}
		}
	}

	return clusters
}

// buildCandidateRule 从聚类构建候选规则。
func (e *RuleDiscoveryEngine) buildCandidateRule(key string, cluster *findingCluster) *DiscoveredRule {
	if cluster.Count < e.minOccurrences {
		return nil
	}

	// 计算置信度
	confidence := e.calculateConfidence(cluster)
	if confidence < e.minConfidence {
		return nil
	}

	// 确定严重性
	severity := "中风险"
	if cluster.Confirmed > cluster.Dismissed && cluster.Count >= 3 {
		severity = "高风险"
	}

	// 生成规则 ID
	ruleID := fmt.Sprintf("auto-%s-%s",
		strings.ReplaceAll(cluster.Category, "_", "-"),
		strings.ReplaceAll(cluster.FuncPattern, ".", "-"))

	// 取第一个示例
	var exampleCode, exampleLocation string
	if len(cluster.Examples) > 0 {
		exampleCode = truncate(cluster.Examples[0].Description, 100)
		exampleLocation = cluster.Examples[0].Location
	}

	return &DiscoveredRule{
		ID:              ruleID,
		Name:            fmt.Sprintf("自动发现: %s 模式", cluster.FuncPattern),
		Category:        cluster.Category,
		Severity:        severity,
		Pattern:         fmt.Sprintf("在 %s 类别中反复出现 %s 模式", cluster.Category, cluster.FuncPattern),
		FuncNamePattern: cluster.FuncPattern,
		Occurrences:     cluster.Count,
		Confidence:      confidence,
		ConfirmedCount:  cluster.Confirmed,
		DismissedCount:  cluster.Dismissed,
		SourceScans:     cluster.Scans,
		ExampleCode:     exampleCode,
		ExampleLocation: exampleLocation,
	}
}

// calculateConfidence 计算候选规则的置信度。
func (e *RuleDiscoveryEngine) calculateConfidence(cluster *findingCluster) float64 {
	if cluster.Count == 0 {
		return 0
	}

	// 基础分：出现频次
	freqScore := float64(cluster.Count) / 10.0
	if freqScore > 1 {
		freqScore = 1
	}

	// 确认率
	confirmScore := 0.0
	if cluster.Confirmed+cluster.Dismissed > 0 {
		confirmScore = float64(cluster.Confirmed) / float64(cluster.Confirmed+cluster.Dismissed)
	}

	// 跨扫描一致性
	crossScanScore := float64(len(cluster.Scans)) / 5.0
	if crossScanScore > 1 {
		crossScanScore = 1
	}

	// 加权平均
	return freqScore*0.3 + confirmScore*0.5 + crossScanScore*0.2
}

// extractFuncPattern 从发现中提取函数名模式。
func extractFuncPattern(finding Finding) string {
	// 从 description 中提取函数名
	desc := finding.Description

	// 尝试提取 "xxx()" 形式
	if idx := strings.Index(desc, "("); idx > 0 {
		funcName := desc[:idx]
		// 取最后的函数名部分
		parts := strings.Fields(funcName)
		if len(parts) > 0 {
			candidate := parts[len(parts)-1]
			// 清理：去掉引号、括号等
			candidate = strings.Trim(candidate, "\"'`")
			if candidate != "" {
				return candidate
			}
		}
	}

	// 用类别作为备选
	if finding.Category != "" {
		return finding.Category
	}

	return "unknown"
}

// =============================================================================
// 反馈循环
// =============================================================================

// FeedbackEntry 反馈条目。
type FeedbackEntry struct {
	// RuleID 规则 ID
	RuleID string `json:"rule_id"`
	// Feedback 反馈类型：confirmed / dismissed / needs_tuning
	Feedback string `json:"feedback"`
	// Reason 原因
	Reason string `json:"reason,omitempty"`
	// AdjustedSeverity 调整后的严重性（可选）
	AdjustedSeverity string `json:"adjusted_severity,omitempty"`
}

// RuleWeightAdjustment 规则权重调整。
type RuleWeightAdjustment struct {
	RuleID       string  `json:"rule_id"`
	OldWeight    float64 `json:"old_weight"`
	NewWeight    float64 `json:"new_weight"`
	Adjustment   float64 `json:"adjustment"`
	Reason       string  `json:"reason"`
}

// FeedbackProcessor 反馈处理器。
type FeedbackProcessor struct {
	// weights 规则权重（初始为 1.0）
	weights map[string]float64
	// feedbackCount 反馈计数
	feedbackCount map[string]int
}

// NewFeedbackProcessor 创建反馈处理器。
func NewFeedbackProcessor() *FeedbackProcessor {
	return &FeedbackProcessor{
		weights:      make(map[string]float64),
		feedbackCount: make(map[string]int),
	}
}

// ProcessFeedback 处理反馈，返回权重调整。
func (p *FeedbackProcessor) ProcessFeedback(feedbacks []FeedbackEntry) []RuleWeightAdjustment {
	var adjustments []RuleWeightAdjustment

	for _, fb := range feedbacks {
		ruleID := fb.RuleID
		if ruleID == "" {
			continue
		}

		p.feedbackCount[ruleID]++

		oldWeight := p.weights[ruleID]
		if oldWeight == 0 {
			oldWeight = 1.0
		}

		var newWeight float64
		var reason string

		switch fb.Feedback {
		case "confirmed":
			// 确认 → 提升权重（最多 2.0）
			newWeight = oldWeight + 0.1
			if newWeight > 2.0 {
				newWeight = 2.0
			}
			reason = "规则被确认，提升权重"

		case "dismissed":
			// 驳回 → 降低权重（最多降到 0.1）
			newWeight = oldWeight - 0.2
			if newWeight < 0.1 {
				newWeight = 0.1
			}
			reason = "规则被驳回，降低权重"

		case "needs_tuning":
			// 需要调优 → 微调
			newWeight = oldWeight - 0.05
			if newWeight < 0.5 {
				newWeight = 0.5
			}
			reason = "规则需要调优，微调权重"

		default:
			continue
		}

		p.weights[ruleID] = newWeight

		if newWeight != oldWeight {
			adjustments = append(adjustments, RuleWeightAdjustment{
				RuleID:     ruleID,
				OldWeight:  oldWeight,
				NewWeight:  newWeight,
				Adjustment: newWeight - oldWeight,
				Reason:     reason,
			})
		}
	}

	return adjustments
}

// GetWeight 获取规则权重。
func (p *FeedbackProcessor) GetWeight(ruleID string) float64 {
	if w, ok := p.weights[ruleID]; ok {
		return w
	}
	return 1.0
}

// GetFeedbackCount 获取规则反馈次数。
func (p *FeedbackProcessor) GetFeedbackCount(ruleID string) int {
	return p.feedbackCount[ruleID]
}

// =============================================================================
// 辅助函数
// =============================================================================

// DiscoveredRulesToIRRules 将发现的候选规则转换为 IR 规则。
func DiscoveredRulesToIRRules(discovered []DiscoveredRule) []IRRule {
	var rules []IRRule

	for _, d := range discovered {
		rule := IRRule{
			ID:       d.ID,
			Name:     d.Name,
			Severity: d.Severity,
			Detection: IRDetection{
				Type:   "ir_category",
				PassIf: "no_match",
				Reason: d.Pattern,
			},
		}

		// 如果有函数名模式，用 ir_call
		if d.FuncNamePattern != "" && d.FuncNamePattern != "unknown" {
			rule.Detection.Type = "ir_call"
			rule.Detection.Call = &IRCallMatch{
				FuncName: d.FuncNamePattern,
			}
		}

		// 如果有类别，用 ir_category
		if d.Category != "" {
			rule.Detection.Category = &IRCategoryMatch{
				Categories: []string{d.Category},
				MinCount:   1,
			}
		}

		rules = append(rules, rule)
	}

	return rules
}

// FormatDiscoveredRule 格式化发现的规则。
func FormatDiscoveredRule(rule DiscoveredRule) string {
	return fmt.Sprintf("[%s] %s (出现 %d 次, 置信度=%.0f%%, 确认=%d, 驳回=%d)",
		rule.Severity, rule.Name, rule.Occurrences, rule.Confidence*100, rule.ConfirmedCount, rule.DismissedCount)
}

// appendUniqueStr 追加不重复的字符串。
func appendUniqueStr(slice []string, item string) []string {
	for _, s := range slice {
		if s == item {
			return slice
		}
	}
	return append(slice, item)
}

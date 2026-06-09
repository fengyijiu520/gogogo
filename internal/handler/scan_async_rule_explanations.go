package handler

import (
	"fmt"
	"sort"
	"strings"

	"skill-scanner/internal/config"
	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func markTriggeredRuleExplanations(explanations []review.RuleExplanation, findings []plugins.Finding) []review.RuleExplanation {
	triggered := map[string]bool{}
	for _, finding := range findings {
		if strings.TrimSpace(finding.RuleID) != "" {
			triggered[finding.RuleID] = true
		}
	}
	out := append([]review.RuleExplanation(nil), explanations...)
	for i := range out {
		out[i].Triggered = triggered[out[i].RuleID]
	}
	return out
}

func ruleDetectionCriteria(rule config.Rule) []string {
	criteria := []string{fmt.Sprintf("检测方式: %s", defaultIfEmpty(rule.Detection.Type, "未声明"))}
	switch rule.Detection.Type {
	case "pattern":
		if len(rule.Detection.Patterns) == 0 {
			criteria = append(criteria, "未配置正则模式，需补齐后才能可靠检测。")
		} else {
			criteria = append(criteria, fmt.Sprintf("正则模式数量: %d", len(rule.Detection.Patterns)))
			criteria = append(criteria, "必须存在与风险语义一致的源码、配置或声明证据，不能只依赖无上下文关键词。")
		}
	case "function":
		criteria = append(criteria, "由专用检测函数执行上下文分析: "+defaultIfEmpty(rule.Detection.Function, "未声明函数"))
		criteria = append(criteria, "需要结合定位、代码片段和规则原因确认风险链条成立。")
	case "semantic", "llm_intent":
		criteria = append(criteria, "由语义模型或 LLM 对声明、源码和实际行为做一致性判断。")
		criteria = append(criteria, "必须输出可核验证据，不能仅凭推测标记风险。")
	default:
		criteria = append(criteria, "按规则配置的检测器执行，需在报告中保留原始证据。")
	}
	if strings.TrimSpace(rule.OnFail.Reason) != "" {
		criteria = append(criteria, "风险触发原因: "+rule.OnFail.Reason)
	}
	return criteria
}

func ruleExclusionConditions(category string) []string {
	conditions := []string{
		"只有在已确认相关代码、脚本或配置不会进入发布包、运行镜像、动态加载链路时，才能按非风险处理。",
		"只有在已验证白名单、固定参数、最小权限和显式用户授权能实际约束危险影响时，才能降级处理。",
	}
	conditions = appendCategoryNote(conditions, category, ruleExclusionConditionNotes)
	return conditions
}

func ruleVerificationRequirements(category string) []string {
	reqs := []string{
		"确认入口可达性: 风险代码是否会被技能主流程调用。",
		"确认证据完整性: 至少包含位置、片段、规则原因或行为证据之一。",
		"确认影响成立: 风险是否可能造成数据泄露、越权执行、持久化或用户误导。",
	}
	reqs = appendCategoryNote(reqs, category, ruleVerificationRequirementNotes)
	return reqs
}

func appendCategoryNote(items []string, category string, notes map[string]string) []string {
	if note := strings.TrimSpace(notes[category]); note != "" {
		items = append(items, note)
	}
	return items
}

func ruleOutputRequirements(category string) []string {
	return []string{
		"输出具体文件路径或证据定位。",
		"输出触发代码片段或行为证据摘要。",
		"输出攻击路径、影响评估、误报检查和一一对应修复建议。",
		"若证据不足，应标记为待复核而不是直接下结论。",
		"分类标签: " + category,
	}
}

func buildRulePromptTemplateSummary(rule config.Rule, category string, criteria []string) string {
	return fmt.Sprintf("作为安全审计员，仅在满足 %s 相关具体证据时报告 %s；必须先检查排除条件，再给出攻击路径、影响、证据和修复建议。核心检测条件: %s", category, rule.Name, strings.Join(limitList(criteria, 3), "；"))
}

var ruleExclusionConditionNotes = map[string]string{
	"外联与情报":   "若目标限定为受控白名单、开发回环地址或内部服务，仍需确认不会传输敏感数据且不存在重定向、代理转发或动态改写。",
	"命令执行":    "只有在已确认命令参数不可控、不进入 shell 且影响范围受限时，才能按低风险或非风险处理。",
	"凭据访问":    "只有在已确认读取对象是公开模板、占位符或脱敏演示数据，且不存在后续外联、落地或权限放大链路时，才能排除风险。",
	"声明与行为差异": "不要报告声明中已经明确解释且行为证据与声明一致的能力。",
}

var ruleVerificationRequirementNotes = map[string]string{
	"外联与情报":  "确认目标域名、请求方法、传输数据和威胁情报结论。",
	"命令执行":   "确认命令参数是否可控、是否进入 shell、是否有白名单限制。",
	"凭据访问":   "确认凭据来源、访问授权、后续外联或落地链路。",
	"反分析/逃逸": "确认是否存在差分执行、环境探测、延迟触发或规避沙箱证据。",
}

var ruleRemediationFocusByCategory = map[string]string{
	"外联与情报":      "收敛外联目标到白名单，最小化传输字段，记录用户授权与用途。",
	"网络请求与SSRF":  "对目标 URL 做协议、域名、IP 段和重定向白名单校验，禁止访问内网与本地地址。",
	"命令执行":       "移除 shell 拼接，改用参数数组和白名单，禁止用户输入直接进入命令。",
	"下载执行":       "禁止远程脚本下载后直接执行，固定可信源并校验签名、哈希与版本。",
	"恶意代码":       "按证据链拆分执行、外联、凭据和落地能力，移除不可解释的高危组合行为。",
	"凭据访问":       "移除硬编码凭据，改用受控密钥管理，并阻断凭据外发链路。",
	"授权与许可证校验":   "将许可证校验改为失败即拒绝，避免本地默认服务、空 key 或校验异常导致绕过。",
	"业务自动化高风险行为": "将自动交易默认改为关闭，增加金额、频率、市场范围和人工确认限制，并保留模拟模式校验。",
	"持久化":        "移除自启动、计划任务或隐式落地逻辑，保留显式用户触发路径。",
	"反分析/逃逸":     "删除环境探测、延迟触发和差分执行逻辑，确保沙箱与真实环境行为一致。",
	"声明与行为差异":    "补齐声明与权限说明，或移除未声明能力，复扫确认一致。",
}

func limitRuleExplanations(items []review.RuleExplanation, max int) []review.RuleExplanation {
	if len(items) <= max {
		return items
	}
	selected := make([]review.RuleExplanation, 0, max)
	for _, item := range items {
		if item.Triggered {
			selected = append(selected, item)
			if len(selected) == max {
				return selected
			}
		}
	}
	for _, item := range items {
		if !item.Triggered {
			selected = append(selected, item)
			if len(selected) == max {
				return selected
			}
		}
	}
	return selected
}

func ruleRemediationFocus(category string) string {
	return defaultIfEmpty(ruleRemediationFocusByCategory[category], "按证据定位最小化危险能力，并补充测试或声明以便复核。")
}

func countMapToSortedList(counts map[string]int) []string {
	out := make([]string, 0, len(counts))
	for key, count := range counts {
		out = append(out, fmt.Sprintf("%s:%d", key, count))
	}
	sort.Strings(out)
	return out
}

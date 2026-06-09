package handler

import "strings"

var legacyRuleIDToPublicRuleID = map[string]string{
	"V7-001": "S2-P0-001",
	"V7-003": "S2-P0-006",
	"V7-004": "S2-P0-008",
	"V7-005": "S2-P1-002",
	"V7-006": "S2-P1-001",
	"V7-008": "S2-P0-010",
	"V7-009": "S2-P0-012",
	"V7-010": "S2-P1-004",
	"V7-011": "S2-P1-007",
	"V7-012": "S2-P1-003",
	"V7-014": "S2-P1-012",
	"V7-015": "S2-P1-008",
	"V7-016": "S2-P1-014",
	"V7-019": "S2-P1-031",
	"V7-020": "S2-P1-032",
	"V7-021": "S2-P1-033",
	"V7-022": "S2-P1-036",
	"V7-023": "S2-P1-037",
}

var publicRuleIDToDisplayName = map[string]string{
	"S2-P0-001":           "恶意代码与破坏性行为",
	"S2-P0-006":           "敏感数据外发与隐蔽通道",
	"S2-P0-008":           "硬编码真实凭证",
	"S2-P1-001":           "技能声明与实际行为一致性",
	"S2-P1-002":           "声明不完整",
	"S2-P0-010":           "沙箱逃逸与提权风险",
	"S2-P0-012":           "自更新与远程下载执行",
	"S2-P1-003":           "MCP 工具滥用与权限过大",
	"S2-P1-004":           "依赖漏洞与恶意依赖",
	"S2-P1-007":           "动态指令注入与可执行上下文拼接",
	"S2-P1-008":           "工具响应投毒与间接提示注入",
	"S2-P1-012":           "SSRF-内网探测",
	"S2-P1-014":           "凭据缓存与跨任务隔离",
	"S2-P1-031":           "数据最小化与收集边界",
	"S2-P1-032":           "数据删除与脱敏策略",
	"S2-P1-033":           "资源耗尽与级联失败",
	"S2-P1-036":           "调试后门残留",
	"S2-P1-037":           "不安全反序列化",
	"RULE-AUTO-COVERAGE":  "规则可自动评估项覆盖不足",
	"RULE-HIGH-RISK-BLOCK": "高风险阻断项",
}

func publicRuleIDForOutput(ruleID string) string {
	trimmed := strings.TrimSpace(ruleID)
	if mapped, ok := legacyRuleIDToPublicRuleID[trimmed]; ok {
		return mapped
	}
	return trimmed
}

func normalizeSelectedRuleID(ruleID string) string {
	return publicRuleIDForOutput(ruleID)
}

func displayRuleName(ruleID string) string {
	trimmed := publicRuleIDForOutput(ruleID)
	if name, ok := publicRuleIDToDisplayName[trimmed]; ok {
		return name
	}
	return strings.TrimSpace(ruleID)
}

func displayRuleNameWithFallback(ruleID, fallbackName string) string {
	fallbackName = strings.TrimSpace(fallbackName)
	if fallbackName != "" {
		return fallbackName
	}
	return displayRuleName(ruleID)
}

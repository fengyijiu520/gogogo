package registry

type Rule struct {
	ID        string
	Name      string
	Phase     string
	RiskLevel string
	VetoOnHit bool
}

func LoadRules() []Rule {
	return []Rule{
		{ID: "V7-001", Name: "恶意代码与破坏性行为", Phase: "高风险", RiskLevel: "high", VetoOnHit: true},
		{ID: "V7-003", Name: "敏感数据外发与隐蔽通道", Phase: "高风险", RiskLevel: "high", VetoOnHit: true},
		{ID: "V7-004", Name: "硬编码真实凭证", Phase: "高风险", RiskLevel: "high", VetoOnHit: true},
		{ID: "V7-011", Name: "动态指令注入与可执行上下文拼接", Phase: "高风险", RiskLevel: "high", VetoOnHit: true},
		{ID: "V7-012", Name: "权限声明与最小权限", Phase: "高风险", RiskLevel: "high", VetoOnHit: false},
		{ID: "V7-006", Name: "技能声明与实际行为一致性", Phase: "高风险", RiskLevel: "high", VetoOnHit: true},
		{ID: "V7-010", Name: "依赖漏洞与恶意依赖", Phase: "高风险", RiskLevel: "high", VetoOnHit: true},
		{ID: "V7-026", Name: "资源耗尽与级联失败", Phase: "低风险", RiskLevel: "low", VetoOnHit: false},
	}
}

func FindByPhase(phase string) []Rule {
	rules := LoadRules()
	out := make([]Rule, 0, len(rules))
	for _, rule := range rules {
		if rule.Phase == phase {
			out = append(out, rule)
		}
	}
	return out
}

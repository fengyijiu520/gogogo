package evidence

import (
	"skill-scanner/internal/review"
)

func BuildInventory(behavior review.BehaviorProfile, diffs []review.IntentDiff, reputations []review.TIReputation, evasion review.EvasionAssessment) []review.EvidenceInventory {
	items := buildBehaviorEvidenceInventory(behavior)
	if len(diffs) > 0 {
		examples := make([]string, 0, len(diffs))
		for _, diff := range diffs {
			examples = append(examples, diff.Description)
		}
		items = append(items, review.EvidenceInventory{Category: "声明与行为差异", Count: len(diffs), Examples: limitStrings(examples, 5), Meaning: "用于判断技能是否隐瞒能力、扩大权限或偏离声明用途"})
	}
	if len(reputations) > 0 {
		examples := make([]string, 0, len(reputations))
		for _, rep := range reputations {
			examples = append(examples, rep.Target+" -> "+rep.Reputation)
		}
		items = append(items, review.EvidenceInventory{Category: "威胁情报信誉", Count: len(reputations), Examples: limitStrings(examples, 5), Meaning: "用于判断外联目标是否可疑或具有恶意基础设施特征"})
	}
	if evasion.Detected {
		items = append(items, review.EvidenceInventory{Category: "反分析/逃逸", Count: len(evasion.Signals), Examples: limitStrings(evasion.Signals, 5), Meaning: "用于判断技能是否尝试规避沙箱、审计或虚拟化环境"})
	}
	return items
}

func CountBehaviorCategories(behavior review.BehaviorProfile) int {
	return len(buildBehaviorEvidenceInventory(behavior))
}

func buildBehaviorEvidenceInventory(behavior review.BehaviorProfile) []review.EvidenceInventory {
	type categoryDef struct {
		category string
		meaning  string
		items    []string
	}
	defs := []categoryDef{
		{category: "下载/远程获取", meaning: "用于判断技能是否远程拉取内容、载荷或依赖", items: behavior.DownloadIOCs},
		{category: "文件落地/写入", meaning: "用于判断技能是否写入脚本、配置或高敏感目录", items: behavior.DropIOCs},
		{category: "命令执行", meaning: "用于判断技能是否执行系统命令、子进程或解释器", items: behavior.ExecuteIOCs},
		{category: "外联行为", meaning: "用于判断技能是否向外部主机发送数据或建立连接", items: append(append([]string{}, behavior.OutboundIOCs...), behavior.NetworkTargets...)},
		{category: "持久化", meaning: "用于判断技能是否建立长期驻留、启动项或计划任务", items: behavior.PersistenceIOCs},
		{category: "提权行为", meaning: "用于判断技能是否尝试获取更高权限或突破隔离", items: behavior.PrivEscIOCs},
		{category: "凭据访问", meaning: "用于判断技能是否读取 token、密码、密钥或认证文件", items: behavior.CredentialIOCs},
		{category: "防御规避", meaning: "用于判断技能是否清日志、关审计或识别沙箱环境", items: append(append([]string{}, behavior.DefenseEvasionIOCs...), behavior.EvasionSignals...)},
		{category: "横向移动", meaning: "用于判断技能是否尝试访问其他主机、账号或远程管理平面", items: behavior.LateralMoveIOCs},
		{category: "数据收集/打包", meaning: "用于判断技能是否批量收集、压缩或导出敏感数据", items: behavior.CollectionIOCs},
		{category: "C2/心跳", meaning: "用于判断技能是否存在 beacon、轮询或命令控制通道", items: behavior.C2BeaconIOCs},
		{category: "行为链", meaning: "用于还原多个高风险动作之间的链式关系", items: behavior.BehaviorChains},
		{category: "行为时序", meaning: "用于还原关键动作的先后顺序并辅助判断攻击链", items: behavior.BehaviorTimelines},
		{category: "高风险时序告警", meaning: "用于标记下载后执行、凭据访问后外联等高风险组合", items: behavior.SequenceAlerts},
		{category: "探针告警", meaning: "用于提示静态、LLM 与沙箱证据之间的不一致或覆盖不足", items: behavior.ProbeWarnings},
	}
	out := make([]review.EvidenceInventory, 0, len(defs))
	for _, def := range defs {
		cleaned := normalizeStrings(def.items)
		if len(cleaned) == 0 {
			continue
		}
		out = append(out, review.EvidenceInventory{Category: def.category, Count: len(cleaned), Examples: limitStrings(cleaned, 5), Meaning: def.meaning})
	}
	return out
}

func normalizeStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func limitStrings(items []string, max int) []string {
	if len(items) <= max {
		return append([]string{}, items...)
	}
	return append([]string{}, items[:max]...)
}

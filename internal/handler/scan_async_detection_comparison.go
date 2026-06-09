package handler

import (
	"fmt"
	"strings"

	"skill-scanner/internal/review"
)

func buildDetectionChainComparison(base baseScanOutput, refined review.Result) []review.DetectionChainComparison {
	return []review.DetectionChainComparison{
		{
			Area:             "执行策略与降级控制",
			CurrentStatus:    "语义模型、LLM 和沙箱均作为关键能力；任一关键能力不可用时扫描直接失败，不静默降级。",
			BaselineApproach: "参考基线通常强调阶段化执行，但对关键能力失败后的产品化提示不一定做强约束。",
			Winner:           "当前链路更适合上线前质量门禁",
			Gap:              "仍需把关键能力失败原因与恢复建议进一步结构化，便于 UI 和 API 精准提示。",
			Optimization:     "保留不降级策略，并继续把 preflight、sandbox、LLM、semantic 的失败原因纳入审计事件流。",
			Evidence:         []string{fmt.Sprintf("preflight trace:%d", len(base.trace)), fmt.Sprintf("audit events:%d", len(refined.AuditEvents))},
		},
		{
			Area:             "深度审计与多 Agent 推理",
			CurrentStatus:    "当前链路以规则、语义、LLM 意图、沙箱和威胁情报聚合为主，并已生成 Agent 任务包与确定性 reviewer 裁决。",
			BaselineApproach: "参考基线通常会把深度审计任务拆成多阶段任务包，并用独立复核提示提升覆盖。",
			Winner:           "参考基线领先",
			Gap:              "已有确定性 reviewer，但还缺少真实 LLM reviewer 的语义二次审查。",
			Optimization:     "下一步将 ReviewAgentTask 交给 LLM reviewer 执行，并用确定性 reviewer 作为保底校验。",
			Evidence:         []string{fmt.Sprintf("review agent tasks:%d", len(refined.ReviewAgentTasks)), fmt.Sprintf("review verdicts:%d", len(refined.ReviewAgentVerdicts)), "已落地结构化风险、规则解释卡和零误报复核清单作为 Agent 输入"},
		},
		{
			Area:             "规则元数据与 Prompt 模板",
			CurrentStatus:    "已从 rules_access.yaml 自动生成规则解释卡，但规则文件本身尚未原生承载 detection/exclusion/verification/output prompt。",
			BaselineApproach: "参考基线会把说明、检测条件、排除条件、验证要求和提示模板沉淀到同一规则元数据中。",
			Winner:           "参考基线领先",
			Gap:              "当前规则解释多为代码派生，长期应沉淀到 YAML 规则元数据。",
			Optimization:     "将 RuleExplanation 反向推动 rules_access.yaml schema 扩展，支持原生 metadata 与 prompt_template。",
			Evidence:         []string{fmt.Sprintf("rule explanations:%d", len(refined.RuleExplanations))},
		},
		{
			Area:             "行为验证与能力一致性",
			CurrentStatus:    "当前链路已有沙箱、静态/LLM/沙箱交叉校验、能力一致性矩阵和探针告警。",
			BaselineApproach: "参考基线重视阶段化分析，但不一定直接输出面向 Skill 声明与权限的一致性矩阵。",
			Winner:           "当前链路更贴合 Skill 安全审查",
			Gap:              "沙箱仍可能因入口未触发、动态拼接、条件执行而漏检。",
			Optimization:     "继续扩展沙箱探针和行为触发策略，并将未触发行为作为能力矩阵缺口展示。",
			Evidence:         []string{fmt.Sprintf("capability matrix:%d", len(refined.CapabilityMatrix)), fmt.Sprintf("probe warnings:%d", len(refined.Behavior.ProbeWarnings))},
		},
		{
			Area:             "漏洞结构化与误报复核",
			CurrentStatus:    "已支持 StructuredFinding、<vuln> 漏洞块、FalsePositiveReview 和逐项修复建议。",
			BaselineApproach: "参考基线通常提供结构化风险块与零误报复核模板，便于二次消费。",
			Winner:           "能力接近，仍可继续增强",
			Gap:              "还缺少自动二次复核执行器来消费这些结构化块并产出最终差异。",
			Optimization:     "下一步可增加 vuln block round-trip 校验和 LLM reviewer，对每个 <vuln> 块执行独立复核。",
			Evidence:         []string{fmt.Sprintf("structured findings:%d", len(refined.StructuredFindings)), fmt.Sprintf("false-positive reviews:%d", len(refined.FalsePositiveReviews))},
		},
		{
			Area:             "可观测性与审计回放",
			CurrentStatus:    "已新增结构化审计事件流，覆盖 trace、pipeline、结果生成和沙箱探针告警。",
			BaselineApproach: "参考基线通常会把计划、状态、工具调用和错误事件拆开记录，便于完整回放。",
			Winner:           "能力接近，仍可继续增强",
			Gap:              "当前事件流还没有覆盖所有具体工具输入输出，也没有事件级耗时。",
			Optimization:     "后续为每个检测函数、LLM 调用、沙箱动作补充 toolUsed/actionLog 事件和耗时字段。",
			Evidence:         []string{fmt.Sprintf("audit events:%d", len(refined.AuditEvents))},
		},
	}
}

func buildDetectionComparisonOptimizationNotes(items []review.DetectionChainComparison) []review.OptimizationNote {
	notes := make([]review.OptimizationNote, 0, 3)
	for _, item := range items {
		if !strings.Contains(item.Winner, "参考基线领先") && !strings.Contains(item.Winner, "继续增强") {
			continue
		}
		notes = append(notes, review.OptimizationNote{
			Change:  "检测链路差距: " + item.Area,
			Reason:  item.Gap,
			Benefit: item.Optimization,
		})
		if len(notes) == 3 {
			break
		}
	}
	return notes
}

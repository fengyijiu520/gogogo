package handler

import (
	"fmt"
	"strings"
	"time"

	"skill-scanner/internal/plugins"
	"skill-scanner/internal/review"
)

func buildCapabilityMatrix(findings []plugins.Finding, base baseScanOutput, refined review.Result) []review.CapabilityConsistency {
	type def struct {
		name    string
		impact  string
		next    string
		matches []string
		active  func(review.BehaviorProfile) []string
	}
	defs := []def{
		{name: "外联/网络访问", impact: "可能产生数据外发、远程依赖、C2 或供应链风险", next: "核验目标白名单、协议、传输数据和业务必要性", matches: []string{"外联", "网络", "network", "http", "url", "fetch", "requests", "axios", "c2", "远程"}, active: func(b review.BehaviorProfile) []string {
			return append(append([]string{}, b.OutboundIOCs...), b.NetworkTargets...)
		}},
		{name: "命令执行", impact: "可能导致任意命令、下载后执行或宿主环境破坏", next: "确认入口可达性、参数是否可控，并收敛到命令白名单", matches: []string{"命令", "执行", "command", "shell", "exec", "subprocess", "child_process"}, active: func(b review.BehaviorProfile) []string {
			return append(append([]string{}, b.ExecuteIOCs...), b.ExecTargets...)
		}},
		{name: "文件读写/落地", impact: "可能写入载荷、篡改配置或读取敏感文件", next: "核查读写路径、文件权限和是否写入高敏感目录", matches: []string{"文件", "落地", "写入", "读取", "file", "write", "read", "drop"}, active: func(b review.BehaviorProfile) []string {
			return append(append([]string{}, b.DropIOCs...), b.FileTargets...)
		}},
		{name: "凭据访问", impact: "可能读取 token、密钥、认证文件或会话凭据", next: "移除直接凭据读取，改用受控密钥管理接口并检查后续外联链路", matches: []string{"凭据", "密钥", "token", "secret", "password", "credential", "authorization"}, active: func(b review.BehaviorProfile) []string { return b.CredentialIOCs }},
		{name: "持久化", impact: "可能建立启动项、计划任务或长期驻留机制", next: "移除隐式自启动逻辑，改为用户显式授权的生命周期管理", matches: []string{"持久", "启动", "cron", "startup", "autorun", "systemctl"}, active: func(b review.BehaviorProfile) []string { return b.PersistenceIOCs }},
		{name: "提权/沙箱逃逸", impact: "可能越权访问宿主、突破隔离或规避审计", next: "移除提权和环境识别分支，使用最小权限重新复测", matches: []string{"提权", "逃逸", "sandbox", "evasion", "sudo", "setuid", "privilege"}, active: func(b review.BehaviorProfile) []string {
			return append(append([]string{}, b.PrivEscIOCs...), b.EvasionSignals...)
		}},
		{name: "数据收集/打包", impact: "可能批量聚合敏感数据并形成外传前置步骤", next: "限制收集范围，删除批量打包逻辑，并增加数据最小化说明", matches: []string{"收集", "打包", "archive", "zip", "tar", "dump", "collection"}, active: func(b review.BehaviorProfile) []string { return b.CollectionIOCs }},
	}

	declaredText := strings.ToLower(strings.Join(append(append([]string{}, base.profile.Permissions...), base.intentSummary.DeclaredCapabilities...), " "))
	llmText := strings.ToLower(strings.Join(append(append([]string{}, base.intentSummary.ActualCapabilities...), base.intentSummary.ConsistencyEvidence...), " "))
	staticText := strings.ToLower(findingsText(findings))
	tiObserved := len(refined.TIReputations) > 0
	out := make([]review.CapabilityConsistency, 0, len(defs))
	for _, d := range defs {
		declared := containsAny(declaredText, d.matches)
		staticDetected := containsAny(staticText, d.matches)
		llmDetected := containsAny(llmText, d.matches)
		sandboxEvidence := d.active(refined.Behavior)
		sandboxDetected := len(sandboxEvidence) > 0
		status, gap := capabilityStatus(declared, staticDetected, llmDetected, sandboxDetected)
		evidence := capabilityEvidence(d.name, sandboxEvidence, findings, base, refined)
		out = append(out, review.CapabilityConsistency{
			Capability:      d.name,
			Declared:        declared,
			StaticDetected:  staticDetected,
			LLMDetected:     llmDetected,
			SandboxDetected: sandboxDetected,
			TIObserved:      tiObserved && d.name == "外联/网络访问",
			Status:          status,
			RiskImpact:      d.impact,
			Evidence:        evidence,
			Gap:             gap,
			NextStep:        d.next,
		})
	}
	return out
}

func buildAuditEvents(base baseScanOutput, refined review.Result) []review.AuditEvent {
	now := time.Now().UTC().Format(time.RFC3339)
	events := make([]review.AuditEvent, 0, len(base.trace)+len(refined.Pipeline)*2+8)
	add := func(event review.AuditEvent) {
		if event.Timestamp == "" {
			event.Timestamp = now
		}
		events = append(events, event)
	}
	for i, trace := range base.trace {
		stepID := fmt.Sprintf("trace-%02d", i+1)
		add(review.AuditEvent{Type: "statusUpdate", StepID: stepID, Status: trace.Status, Brief: trace.Stage, Detail: strings.TrimSpace(strings.Join([]string{trace.Message, trace.Detail}, "；")), ToolName: "scan-trace"})
	}
	for i, stage := range refined.Pipeline {
		stepID := fmt.Sprintf("pipeline-%02d", i+1)
		add(review.AuditEvent{Type: "newPlanStep", StepID: stepID, Title: stage.Name, Brief: stage.Purpose, Detail: stage.MethodNote})
		add(review.AuditEvent{Type: "statusUpdate", StepID: stepID, Status: stage.Status, Brief: stage.Name, Detail: strings.TrimSpace(strings.Join([]string{stage.Output, stage.Benefit}, "；")), ToolName: "review-orchestrator"})
	}
	add(review.AuditEvent{Type: "resultUpdate", StepID: "result-structured-findings", Status: "completed", Brief: "结构化风险发现生成完成", Detail: fmt.Sprintf("发现 %d 条，复核清单 %d 条，漏洞块 %d 个，Agent任务 %d 个，Agent裁决 %d 个，能力矩阵 %d 项，链路对比 %d 项", len(refined.StructuredFindings), len(refined.FalsePositiveReviews), len(refined.VulnerabilityBlocks), len(refined.ReviewAgentTasks), len(refined.ReviewAgentVerdicts), len(refined.CapabilityMatrix), len(refined.DetectionComparison)), ToolName: "report-builder"})
	for _, stat := range refined.ReviewAgentStats {
		status := "completed"
		if stat.Failed {
			status = "failed"
		}
		detail := fmt.Sprintf("任务 %d 个；worker %d 个；并发峰值 %d；耗时 %dms", stat.TaskCount, stat.WorkerCount, stat.MaxConcurrency, stat.DurationMs)
		if strings.TrimSpace(stat.ErrorMessage) != "" {
			detail += "；错误: " + stat.ErrorMessage
		}
		add(review.AuditEvent{Type: "statusUpdate", StepID: "review-agent-" + strings.ToLower(strings.ReplaceAll(stat.Reviewer, "_", "-")), Status: status, Brief: "二次复核执行统计", Detail: detail, ToolName: stat.Reviewer})
	}
	if len(refined.EvidenceInventory) > 0 {
		add(review.AuditEvent{Type: "resultUpdate", StepID: "result-evidence-inventory", Status: "completed", Brief: "证据目录归一化完成", Detail: fmt.Sprintf("证据类别 %d 类", len(refined.EvidenceInventory)), ToolName: "evidence-normalizer"})
	}
	if len(refined.Behavior.ProbeWarnings) > 0 {
		add(review.AuditEvent{Type: "error", StepID: "probe-warning", Status: "completed", Brief: "沙箱探针存在覆盖或一致性告警", Detail: strings.Join(limitList(refined.Behavior.ProbeWarnings, 4), "；"), ToolName: "sandbox"})
	}
	return events
}

package sandbox

import (
	"fmt"
	"strings"
)

// BehaviorSummary 沙箱行为汇总（供声明与行为一致性分析使用）
type BehaviorSummary struct {
	// 声明的能力
	DeclaredCapabilities []string `json:"declared_capabilities"`
	// 实际观测到的能力
	ObservedCapabilities []string `json:"observed_capabilities"`
	// 一致性评估
	Consistency ConsistencyReport `json:"consistency"`
	// 行为详情
	BehaviorDetails []BehaviorDetail `json:"behavior_details"`
	// 原始行为数据
	RawBehavior *SandboxBehaviorData `json:"raw_behavior"`
}

// ConsistencyReport 一致性报告
type ConsistencyReport struct {
	Score    int    `json:"score"`    // 0-100，100=完全一致
	Level    string `json:"level"`    // high/medium/low
	Mismatches []string `json:"mismatches"` // 不一致项
	ExcessCapabilities []string `json:"excess_capabilities"`   // 声明外的能力
	MissingCapabilities []string `json:"missing_capabilities"` // 声明了但未观测到的能力
}

// BehaviorDetail 行为详情
type BehaviorDetail struct {
	Category    string   `json:"category"`    // network/file/process/credential
	Action      string   `json:"action"`      // 具体动作
	Target      string   `json:"target"`      // 目标（IP/域名/文件路径/命令）
	Evidence    string   `json:"evidence"`    // 证据
	RiskLevel   string   `json:"risk_level"`  // high/medium/low
	IsDeclared  bool     `json:"is_declared"` // 是否在声明范围内
}

// SandboxBehaviorData 沙箱原始行为数据
type SandboxBehaviorData struct {
	// 执行的命令
	Commands []string `json:"commands"`
	// 进程树
	ProcessTree string `json:"process_tree"`
	// 网络目标
	NetworkTargets []OutboundTarget `json:"network_targets"`
	// DNS 查询
	DNSQueries []DNSEvent `json:"dns_queries"`
	// TCP 连接
	TCPConnections []TCPEvent `json:"tcp_connections"`
	// 文件操作
	FileOps []FileOperation `json:"file_ops"`
	// 创建的文件
	FilesCreated []string `json:"files_created"`
	// 修改的文件
	FilesModified []string `json:"files_modified"`
	// 访问的敏感路径
	SensitivePaths []string `json:"sensitive_paths"`
	// 逃逸信号
	EvasionSignals []string `json:"evasion_signals"`
	// 持久化行为
	PersistenceActions []string `json:"persistence_actions"`
}

// GenerateBehaviorSummary 生成行为汇总
func GenerateBehaviorSummary(
	manifest *SkillManifest,
	straceResult *straceResult,
	networkResult *networkResult,
	fileCreated []string,
	evasionSignals []string,
) *BehaviorSummary {

	summary := &BehaviorSummary{
		RawBehavior: &SandboxBehaviorData{
			Commands:       extractCommandsFromStrace(straceResult),
			NetworkTargets: networkResult.OutboundTargets,
			DNSQueries:     networkResult.DNSQueries,
			TCPConnections: networkResult.TCPConnections,
			FileOps:        straceResult.FileOps,
			FilesCreated:   fileCreated,
			EvasionSignals: evasionSignals,
		},
	}

	// 生成进程树文本
	if len(straceResult.ProcessTree) > 0 {
		summary.RawBehavior.ProcessTree = generateProcessTreeText(straceResult.ProcessTree, 0)
	}

	// 提取声明的能力
	if manifest != nil {
		summary.DeclaredCapabilities = extractDeclaredCapabilities(manifest)
	}

	// 提取观测到的能力
	summary.ObservedCapabilities = extractObservedCapabilities(summary.RawBehavior)

	// 生成行为详情
	summary.BehaviorDetails = generateBehaviorDetails(summary.RawBehavior, summary.DeclaredCapabilities)

	// 计算一致性
	summary.Consistency = calculateConsistency(summary.DeclaredCapabilities, summary.ObservedCapabilities, summary.BehaviorDetails)

	return summary
}

// extractDeclaredCapabilities 从 SKILL.md 提取声明的能力
func extractDeclaredCapabilities(manifest *SkillManifest) []string {
	var caps []string
	if manifest == nil {
		return caps
	}

	content := strings.ToLower(manifest.RawContent + " " + manifest.Description)

	// 网络能力
	if containsAny(content, "network", "http", "api", "url", "web", "download", "fetch", "联网", "网络", "接口") {
		caps = append(caps, "network")
	}
	// 文件能力
	if containsAny(content, "file", "read", "write", "save", "load", "文件", "读取", "写入", "保存") {
		caps = append(caps, "file_access")
	}
	// 命令执行
	if containsAny(content, "command", "exec", "shell", "run", "命令", "执行", "运行") {
		caps = append(caps, "command_execution")
	}
	// 数据库
	if containsAny(content, "database", "sql", "sqlite", "mysql", "postgres", "数据库") {
		caps = append(caps, "database")
	}
	// 加密
	if containsAny(content, "encrypt", "decrypt", "hash", "crypto", "加密", "解密") {
		caps = append(caps, "cryptography")
	}
	// AI/ML
	if containsAny(content, "model", "predict", "train", "inference", "llm", "ai", "模型", "预测") {
		caps = append(caps, "ai_ml")
	}

	return uniqueStrings(caps)
}

// extractObservedCapabilities 从行为数据提取观测到的能力
func extractObservedCapabilities(data *SandboxBehaviorData) []string {
	var caps []string

	// 网络能力
	if len(data.NetworkTargets) > 0 || len(data.DNSQueries) > 0 || len(data.TCPConnections) > 0 {
		caps = append(caps, "network")
	}
	// 文件能力
	if len(data.FileOps) > 0 || len(data.FilesCreated) > 0 {
		caps = append(caps, "file_access")
	}
	// 命令执行
	if len(data.Commands) > 0 {
		caps = append(caps, "command_execution")
	}
	// 敏感路径访问
	if len(data.SensitivePaths) > 0 {
		caps = append(caps, "sensitive_access")
	}
	// 逃逸行为
	if len(data.EvasionSignals) > 0 {
		caps = append(caps, "evasion")
	}
	// 持久化
	if len(data.PersistenceActions) > 0 {
		caps = append(caps, "persistence")
	}

	return uniqueStrings(caps)
}

// generateBehaviorDetails 生成行为详情
func generateBehaviorDetails(data *SandboxBehaviorData, declaredCaps []string) []BehaviorDetail {
	var details []BehaviorDetail
	declaredSet := make(map[string]bool)
	for _, c := range declaredCaps {
		declaredSet[c] = true
	}

	// 网络行为
	for _, target := range data.NetworkTargets {
		details = append(details, BehaviorDetail{
			Category:   "network",
			Action:     "outbound_connection",
			Target:     fmt.Sprintf("%s:%d", target.Value, target.Port),
			Evidence:   fmt.Sprintf("通过 %s 连接到 %s", target.Source, target.Value),
			RiskLevel:  "medium",
			IsDeclared: declaredSet["network"],
		})
	}

	// DNS 查询
	for _, dns := range data.DNSQueries {
		details = append(details, BehaviorDetail{
			Category:   "network",
			Action:     "dns_query",
			Target:     dns.Domain,
			Evidence:   fmt.Sprintf("DNS 查询 %s [%s]", dns.Domain, dns.Type),
			RiskLevel:  "low",
			IsDeclared: declaredSet["network"],
		})
	}

	// 文件操作
	for _, f := range data.FilesCreated {
		riskLevel := "low"
		isDeclared := declaredSet["file_access"]
		if strings.Contains(f, "/etc/") || strings.Contains(f, ".ssh") || strings.Contains(f, ".env") {
			riskLevel = "high"
			isDeclared = false
		}
		details = append(details, BehaviorDetail{
			Category:   "file",
			Action:     "create",
			Target:     f,
			Evidence:   fmt.Sprintf("创建文件 %s", f),
			RiskLevel:  riskLevel,
			IsDeclared: isDeclared,
		})
	}

	// 命令执行
	for _, cmd := range data.Commands {
		riskLevel := "medium"
		if isDangerousCommand(cmd) {
			riskLevel = "high"
		}
		details = append(details, BehaviorDetail{
			Category:   "process",
			Action:     "execute",
			Target:     cmd,
			Evidence:   fmt.Sprintf("执行命令 %s", cmd),
			RiskLevel:  riskLevel,
			IsDeclared: declaredSet["command_execution"],
		})
	}

	// 逃逸信号
	for _, signal := range data.EvasionSignals {
		details = append(details, BehaviorDetail{
			Category:   "evasion",
			Action:     "sandbox_detection",
			Target:     signal,
			Evidence:   fmt.Sprintf("检测到逃逸行为: %s", signal),
			RiskLevel:  "high",
			IsDeclared: false,
		})
	}

	return details
}

// calculateConsistency 计算一致性
func calculateConsistency(declared, observed []string, details []BehaviorDetail) ConsistencyReport {
	declaredSet := make(map[string]bool)
	for _, c := range declared {
		declaredSet[c] = true
	}
	observedSet := make(map[string]bool)
	for _, c := range observed {
		observedSet[c] = true
	}

	report := ConsistencyReport{
		Score: 100,
		Level: "high",
	}

	// 检测声明外的能力
	for _, cap := range observed {
		if !declaredSet[cap] {
			report.ExcessCapabilities = append(report.ExcessCapabilities, cap)
			report.Mismatches = append(report.Mismatches, fmt.Sprintf("观测到未声明的能力: %s", cap))
		}
	}

	// 检测声明了但未观测到的能力
	for _, cap := range declared {
		if !observedSet[cap] {
			report.MissingCapabilities = append(report.MissingCapabilities, cap)
		}
	}

	// 检测高风险未声明行为
	for _, detail := range details {
		if !detail.IsDeclared && detail.RiskLevel == "high" {
			report.Mismatches = append(report.Mismatches, fmt.Sprintf("高风险未声明行为: %s → %s", detail.Category, detail.Target))
		}
	}

	// 计算分数
	if len(report.ExcessCapabilities) > 0 {
		report.Score -= len(report.ExcessCapabilities) * 20
	}
	if len(report.Mismatches) > 0 {
		report.Score -= len(report.Mismatches) * 10
	}
	if report.Score < 0 {
		report.Score = 0
	}

	// 设置等级
	if report.Score >= 80 {
		report.Level = "high"
	} else if report.Score >= 50 {
		report.Level = "medium"
	} else {
		report.Level = "low"
	}

	return report
}

// isDangerousCommand 检测危险命令
func isDangerousCommand(cmd string) bool {
	dangerous := []string{
		"curl", "wget", "nc ", "ncat", "netcat",
		"ssh ", "scp ", "rsync",
		"chmod 777", "chmod 4777", "chown root",
		"/etc/shadow", "/etc/passwd",
		"iptables", "nft ",
		"kill -9", "pkill",
		"crontab", "systemctl",
		"base64", "eval(", "exec(",
	}
	lower := strings.ToLower(cmd)
	for _, d := range dangerous {
		if strings.Contains(lower, d) {
			return true
		}
	}
	return false
}

// containsAny 检查字符串是否包含任意一个关键词
func containsAny(s string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(s, kw) {
			return true
		}
	}
	return false
}

// FormatBehaviorSummaryForLLM 格式化行为汇总供 LLM 分析使用
func FormatBehaviorSummaryForLLM(summary *BehaviorSummary) string {
	var lines []string

	lines = append(lines, "## 沙箱动态行为分析报告")
	lines = append(lines, "")

	// 声明能力
	lines = append(lines, "### 声明的能力")
	if len(summary.DeclaredCapabilities) > 0 {
		for _, c := range summary.DeclaredCapabilities {
			lines = append(lines, "- "+c)
		}
	} else {
		lines = append(lines, "- (未声明)")
	}
	lines = append(lines, "")

	// 观测能力
	lines = append(lines, "### 观测到的实际能力")
	if len(summary.ObservedCapabilities) > 0 {
		for _, c := range summary.ObservedCapabilities {
			lines = append(lines, "- "+c)
		}
	} else {
		lines = append(lines, "- (无)")
	}
	lines = append(lines, "")

	// 一致性
	lines = append(lines, "### 声明与行为一致性")
	lines = append(lines, fmt.Sprintf("- 一致性评分: %d/100 (%s)", summary.Consistency.Score, summary.Consistency.Level))
	if len(summary.Consistency.ExcessCapabilities) > 0 {
		lines = append(lines, fmt.Sprintf("- 声明外能力: %s", strings.Join(summary.Consistency.ExcessCapabilities, ", ")))
	}
	if len(summary.Consistency.Mismatches) > 0 {
		lines = append(lines, "- 不一致项:")
		for _, m := range summary.Consistency.Mismatches {
			lines = append(lines, "  - "+m)
		}
	}
	lines = append(lines, "")

	// 行为详情
	lines = append(lines, "### 行为详情")
	for _, detail := range summary.BehaviorDetails {
		declared := ""
		if !detail.IsDeclared {
			declared = " ⚠️ 声明外"
		}
		lines = append(lines, fmt.Sprintf("- [%s/%s] %s → %s%s",
			detail.Category, detail.RiskLevel, detail.Action, detail.Target, declared))
	}
	lines = append(lines, "")

	// 网络目标
	if len(summary.RawBehavior.NetworkTargets) > 0 {
		lines = append(lines, "### 外联目标")
		for _, t := range summary.RawBehavior.NetworkTargets {
			portStr := ""
			if t.Port > 0 {
				portStr = fmt.Sprintf(":%d", t.Port)
			}
			lines = append(lines, fmt.Sprintf("- %s%s [%s]", t.Value, portStr, t.Source))
		}
		lines = append(lines, "")
	}

	// 进程树
	if summary.RawBehavior.ProcessTree != "" {
		lines = append(lines, "### 进程树")
		lines = append(lines, "```")
		lines = append(lines, summary.RawBehavior.ProcessTree)
		lines = append(lines, "```")
	}

	return strings.Join(lines, "\n")
}

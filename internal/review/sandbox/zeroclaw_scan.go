package sandbox

import (
	"context"
	"fmt"
	"strings"
	"time"

	"skill-scanner/internal/logx"
	"skill-scanner/internal/review"
)

// ZeroclawScanRequest zeroclaw 扫描请求
type ZeroclawScanRequest struct {
	SkillPath string // 技能目录路径
	SkillName string // 技能名称
	RequestID string // 请求 ID（用于并发区分）
	Timeout   int    // 超时秒数

	// LLM 配置（可选，有值时启用 Agent 模式）
	LLMProvider string // 提供商名称（如 deepseek、xiaomi-mimo）
	LLMProtocol string // 协议（anthropic / openai）
	LLMBaseURL  string // API 端点
	LLMModel    string // 模型标识
	LLMAPIKey   string // API Key

	// 用户补充说明（可选）
	UserNotes string // 用户提供的补充信息，如依赖、注意事项等
}

// ZeroclawScanResult zeroclaw 扫描结果
type ZeroclawScanResult struct {
	// 请求信息
	RequestID string `json:"request_id"`
	SkillName string `json:"skill_name"`

	// 执行摘要
	Scenarios       []ZeroclawScanScenario `json:"scenarios"`
	TotalDurationMs int64                  `json:"total_duration_ms"`

	// 行为汇总（供声明与行为一致性分析）
	BehaviorSummary *BehaviorSummary `json:"behavior_summary"`

	// 网络监控结果
	NetworkResult *networkResult `json:"network_result"`

	// strace 监控结果
	StraceResult *straceResult `json:"strace_result"`

	// 风险评分
	Verdict string `json:"verdict"` // clean / suspicious / malicious
	Score   int    `json:"score"`   // 0-10

	// 逃逸信号
	EvasionSignals []string `json:"evasion_signals"`

	// 代码级证据（具体到文件、行号、代码内容）
	CodeEvidenceList []CodeEvidence `json:"code_evidence,omitempty"`

	// pcap 文件
	PcapFile string `json:"pcap_file"`

	// 错误信息
	Error string `json:"error,omitempty"`
}

// ZeroclawScanScenario 扫描场景结果
type ZeroclawScanScenario struct {
	Name     string `json:"name"`
	Command  string `json:"command"`
	ExitCode int    `json:"exit_code"`
	Duration int64  `json:"duration_ms"`
	Output   string `json:"output,omitempty"`
	Error    string `json:"error,omitempty"`
}

// RunZeroclawScan 执行 zeroclaw 沙箱扫描（主入口）
// 每个技能独立沙箱，支持并发
func RunZeroclawScan(ctx context.Context, req ZeroclawScanRequest) (*ZeroclawScanResult, error) {
	logger := logx.With("component", "sandbox_zeroclaw", "request_id", req.RequestID, "skill", req.SkillName)
	startedAt := time.Now()

	result := &ZeroclawScanResult{
		RequestID: req.RequestID,
		SkillName: req.SkillName,
		Verdict:   "clean",
	}

	// 1. 检查运行时
	rt := newZeroclawRuntime()
	if err := rt.Prepare(); err != nil {
		return nil, fmt.Errorf("zeroclaw 运行时不可用: %w", err)
	}

	// 2. 创建独立沙箱容器
	logger.Info("creating sandbox container")
	container, err := rt.startContainer(ctx, req.SkillPath)
	if err != nil {
		return nil, fmt.Errorf("创建沙箱失败: %w", err)
	}

	// 确保销毁沙箱
	defer func() {
		logger.Info("destroying sandbox container")
		container.destroy(ctx)
	}()

	// 3. 启动时间加速（如果启用）
	timeAccel := newTimeAccelerator()
	if err := timeAccel.injectTimeAcceleration(ctx, container.name); err != nil {
		logger.Warn("time acceleration failed", "error", err.Error())
	}

	// 4. 启动网络监控
	logger.Info("starting network monitor")
	netMonitor := startNetworkMonitor(ctx, container.name, rt.networkName)

	// 5. 启动 strace 命令监控
	logger.Info("starting strace monitor")
	straceMonitor := startStraceMonitor(ctx, container.name)

	// 6. 发现入口点并构建执行计划
	manifest := parseSkillManifest(req.SkillPath)
	entrypoints := discoverSkillEntrypoints(req.SkillPath)
	logger.Info("entrypoints discovered", "count", len(entrypoints))

	// 6.5 场景分析：根据技能声明引导执行
	scenarioGuide := NewScenarioGuide()
	skillDescription := ""
	skillMD := ""
	if manifest != nil {
		skillDescription = manifest.Description
		skillMD = manifest.RawContent
	}
	scenarios := scenarioGuide.AnalyzeSkill(req.SkillName, skillDescription, skillMD)
	LogScenarioAnalysis(scenarios)
	logger.Info("scenario analysis completed", "scenarios", len(scenarios))

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = rt.timeoutSecs
	}

	// 7. 执行技能 — Agent 模式优先，fallback 到直接执行
	llmCfg := agentLLMConfig{
		Provider: req.LLMProvider,
		Protocol: req.LLMProtocol,
		BaseURL:  req.LLMBaseURL,
		Model:    req.LLMModel,
		APIKey:   req.LLMAPIKey,
	}

	logger.Info("agent config check",
		"has_config", llmCfg.hasLLMConfig(),
		"provider", llmCfg.Provider,
		"protocol", llmCfg.Protocol,
		"base_url", llmCfg.BaseURL,
		"model", llmCfg.Model,
		"api_key_len", len(llmCfg.APIKey),
	)

	// 构建场景引导上下文
	scenarioContext := buildScenarioContext(scenarios)

	agentUsed := false
	if llmCfg.hasLLMConfig() {
		logger.Info("agent mode enabled, running test engineer agent outside container")
		agentStart := time.Now()
		agentOutput, agentEvidence, agentErr := runTestEngineerAgent(ctx, container, llmCfg, req.SkillName, req.UserNotes, timeout, scenarioContext)
		if agentErr != nil {
			logger.Warn("agent failed, falling back to direct exec", "error", agentErr.Error())
		} else {
			agentUsed = true
			result.Scenarios = append(result.Scenarios, ZeroclawScanScenario{
				Name:     "test-engineer-agent",
				Command:  "agent (outside container)",
				ExitCode: 0,
				Duration: time.Since(agentStart).Milliseconds(),
				Output:   agentOutput,
			})
			// 将 Agent 执行证据注入 BehaviorSummary
			if result.BehaviorSummary == nil {
				result.BehaviorSummary = &BehaviorSummary{}
			}
			for _, ev := range agentEvidence {
				detail := BehaviorDetail{
					Category: ev.Category,
					Action:   "exec",
					Target:   ev.Command,
					Evidence: ev.Output,
				}
				result.BehaviorSummary.BehaviorDetails = append(result.BehaviorSummary.BehaviorDetails, detail)
			}
			logger.Debug("agent evidence injected into behavior summary",
				"evidence_count", len(agentEvidence),
				"behavior_details_count", len(result.BehaviorSummary.BehaviorDetails),
			)
		}
	}

	// Agent 未使用或失败时，fallback 到直接执行
	if !agentUsed {
		for i, ep := range entrypoints {
			if ctx.Err() != nil {
				break
			}

			command := buildEntrypointCommand(ep)
			if command == "" {
				continue
			}

			logger.Info("executing scenario", "index", i, "command", command)
			scenarioStart := time.Now()

			exitCode, output, execErr := container.execCommand(ctx, command, timeout)

			scanScenario := ZeroclawScanScenario{
				Name:     ep.name,
				Command:  command,
				ExitCode: exitCode,
				Duration: time.Since(scenarioStart).Milliseconds(),
				Output:   strings.Join(output, "\n"),
			}
			if execErr != nil {
				scanScenario.Error = execErr.Error()
			}

			result.Scenarios = append(result.Scenarios, scanScenario)
		}
	}

	// 8. 收集监控结果
	logger.Info("collecting monitoring results")

	// 收集 strace 结果
	straceResult := straceMonitor.collectStraceOutput(ctx)
	result.StraceResult = straceResult

	// 收集网络结果
	netResult := netMonitor.collectNetworkResult(ctx)
	result.NetworkResult = netResult
	result.PcapFile = netResult.PcapFile

	// 收集文件变化
	filesCreated := snapshotNewFilesSimple(container.name)

	// 检测逃逸信号
	evasionSignals := detectEvasionFromStrace(straceResult)
	result.EvasionSignals = evasionSignals

	// 11. 提取代码级证据
	codeEvidence := CollectCodeEvidence(req.SkillPath, straceResult, netResult)
	if len(codeEvidence) > 0 {
		logger.Info("code evidence collected", "count", len(codeEvidence))

		// 12. LLM 复核：过滤误报
		if llmCfg.hasLLMConfig() {
			llmClient, llmErr := createLLMClient(llmCfg)
			if llmErr == nil {
				skillInfo := ""
				if manifest != nil {
					skillInfo = manifest.RawContent
				}
				beforeCount := len(codeEvidence)
				codeEvidence = ReviewCodeEvidenceWithLLM(ctx, llmClient, req.SkillName, skillInfo, codeEvidence)
				logger.Info("LLM evidence review completed", "before", beforeCount, "after", len(codeEvidence))
			}
		}
	}
	result.CodeEvidenceList = codeEvidence

	// 9. 生成行为汇总（供声明与行为一致性分析）
	// 保存 Agent 证据，避免被 GenerateBehaviorSummary 覆盖
	var agentBehaviorDetails []BehaviorDetail
	if result.BehaviorSummary != nil {
		agentBehaviorDetails = result.BehaviorSummary.BehaviorDetails
	}
	logger.Info("generating behavior summary")
	result.BehaviorSummary = GenerateBehaviorSummary(
		manifest,
		straceResult,
		netResult,
		filesCreated,
		evasionSignals,
	)
	// 合并 Agent 证据到生成的行为汇总中
	if len(agentBehaviorDetails) > 0 {
		result.BehaviorSummary.BehaviorDetails = append(result.BehaviorSummary.BehaviorDetails, agentBehaviorDetails...)
		logger.Debug("agent behavior details merged into summary",
			"agent_details", len(agentBehaviorDetails),
			"total_details", len(result.BehaviorSummary.BehaviorDetails),
		)
	}

	// 10. 计算风险评分
	result.Score = computeZeroclawScanScore(result)
	if result.Score >= 8 {
		result.Verdict = "malicious"
	} else if result.Score >= 4 {
		result.Verdict = "suspicious"
	}

	result.TotalDurationMs = time.Since(startedAt).Milliseconds()

	logger.Info("zeroclaw scan completed",
		"verdict", result.Verdict,
		"score", result.Score,
		"duration_ms", result.TotalDurationMs,
		"commands", len(straceResult.ProcessOps),
		"network_targets", len(netResult.OutboundTargets),
		"files_created", len(filesCreated),
	)

	return result, nil
}

// buildEntrypointCommand 构建入口点命令
func buildEntrypointCommand(ep entrypointCandidate) string {
	if ep.command != "" {
		args := strings.Join(ep.args, " ")
		if args != "" {
			return ep.command + " " + args
		}
		return ep.command
	}

	ext := strings.ToLower(strings.TrimPrefix(
		strings.TrimSpace(
			func() string {
				if ep.signalPath != "" {
					return ep.signalPath
				}
				return ep.path
			}(),
		), ".",
	))

	// 用完整路径
	fullPath := "/home/analyst/skill/" + ep.path

	switch {
	case strings.HasSuffix(ep.path, ".py"):
		return "python3 " + fullPath
	case strings.HasSuffix(ep.path, ".js") || strings.HasSuffix(ep.path, ".mjs"):
		return "node " + fullPath
	case strings.HasSuffix(ep.path, ".sh") || strings.HasSuffix(ep.path, ".bash"):
		return "bash " + fullPath
	case strings.HasSuffix(ep.path, ".go"):
		return "go run " + fullPath
	default:
		_ = ext
		return "bash " + fullPath
	}
}

// snapshotNewFilesSimple 简化的文件快照
func snapshotNewFilesSimple(containerName string) []string {
	var files []string
	dirs := []string{"/tmp", "/home/analyst"}
	for _, d := range dirs {
		out, _ := execCommandSimple(containerName,
			fmt.Sprintf("find %s -type f -newer /home/analyst/.bashrc -maxdepth 3 2>/dev/null", d))
		for _, line := range strings.Split(out, "\n") {
			if t := strings.TrimSpace(line); t != "" && !strings.Contains(t, "skill/") {
				files = append(files, t)
			}
		}
	}
	return files
}

// execCommandSimple 简化的命令执行
func execCommandSimple(containerName, command string) (string, error) {
	out, err := execCommandRaw(containerName, command)
	return strings.TrimSpace(string(out)), err
}

// detectEvasionFromStrace 从 strace 结果检测逃逸信号
func detectEvasionFromStrace(result *straceResult) []string {
	var signals []string
	seen := make(map[string]bool)

	for _, op := range result.FileOps {
		path := strings.ToLower(op.Path)
		if strings.Contains(path, ".dockerenv") && !seen[".dockerenv"] {
			seen[".dockerenv"] = true
			signals = append(signals, "检测到访问 .dockerenv 文件")
		}
		if strings.Contains(path, "/proc/1/cgroup") && !seen["cgroup"] {
			seen["cgroup"] = true
			signals = append(signals, "检测到读取 cgroup 信息")
		}
		if strings.Contains(path, "/proc/self/ns") && !seen["namespace"] {
			seen["namespace"] = true
			signals = append(signals, "检测到访问命名空间信息")
		}
	}

	for _, op := range result.ProcessOps {
		if op.Command != "" {
			cmd := strings.ToLower(op.Command)
			if strings.Contains(cmd, "systemd-detect-virt") && !seen["detect-virt"] {
				seen["detect-virt"] = true
				signals = append(signals, "检测到执行 systemd-detect-virt")
			}
			if strings.Contains(cmd, "dmidecode") && !seen["dmidecode"] {
				seen["dmidecode"] = true
				signals = append(signals, "检测到执行 dmidecode（硬件信息探测）")
			}
		}
	}

	return signals
}

// computeZeroclawScanScore 计算风险评分
func computeZeroclawScanScore(result *ZeroclawScanResult) int {
	score := 0

	// 网络行为
	if result.NetworkResult != nil {
		score += minInt(3, len(result.NetworkResult.OutboundTargets))
		score += minInt(2, len(result.NetworkResult.DNSQueries))
	}

	// 命令执行
	if result.StraceResult != nil {
		score += minInt(3, len(result.StraceResult.ProcessOps))
		score += minInt(2, len(result.StraceResult.FileOps))
	}

	// 逃逸信号
	score += len(result.EvasionSignals) * 2

	// 行为一致性
	if result.BehaviorSummary != nil {
		if result.BehaviorSummary.Consistency.Score < 50 {
			score += 3
		}
		if len(result.BehaviorSummary.Consistency.ExcessCapabilities) > 0 {
			score += 2
		}
	}

	if score > 10 {
		return 10
	}
	return score
}

// FormatScanResultForLLM 格式化扫描结果供 LLM 分析
func FormatScanResultForLLM(result *ZeroclawScanResult) string {
	var lines []string

	lines = append(lines, fmt.Sprintf("## 沙箱扫描结果 (%s)", result.SkillName))
	lines = append(lines, fmt.Sprintf("- 风险评分: %d/10 (%s)", result.Score, result.Verdict))
	lines = append(lines, fmt.Sprintf("- 扫描耗时: %dms", result.TotalDurationMs))
	lines = append(lines, "")

	// 执行摘要
	lines = append(lines, "### 执行摘要")
	for _, s := range result.Scenarios {
		status := "✅"
		if s.ExitCode != 0 {
			status = "❌"
		}
		lines = append(lines, fmt.Sprintf("- %s %s (exit=%d, %dms)", status, s.Name, s.ExitCode, s.Duration))
	}
	lines = append(lines, "")

	// 行为汇总
	if result.BehaviorSummary != nil {
		lines = append(lines, FormatBehaviorSummaryForLLM(result.BehaviorSummary))
	}

	// 逃逸信号
	if len(result.EvasionSignals) > 0 {
		lines = append(lines, "### ⚠️ 逃逸/反分析信号")
		for _, s := range result.EvasionSignals {
			lines = append(lines, "- "+s)
		}
	}

	return strings.Join(lines, "\n")
}

// ConvertToBehaviorProfile 将 ZeroclawScanResult 转换为 review.BehaviorProfile
func (r *ZeroclawScanResult) ConvertToBehaviorProfile() review.BehaviorProfile {
	profile := review.BehaviorProfile{
		SandboxSource:  "zeroclaw",
		SandboxVerdict: r.Verdict,
		SandboxScore:   r.Score,
	}

	// 从网络监控结果提取 IOC（过滤掉 localhost 和常见无害目标）
	if r.NetworkResult != nil {
		for _, target := range r.NetworkResult.OutboundTargets {
			if isBenignNetworkTarget(target.Value) {
				continue
			}
			profile.NetworkTargets = append(profile.NetworkTargets, target.Value)
			profile.OutboundIOCs = append(profile.OutboundIOCs, fmt.Sprintf("[zeroclaw] %s %s:%d", target.Source, target.Value, target.Port))
		}
		for _, dns := range r.NetworkResult.DNSQueries {
			if isBenignNetworkTarget(dns.Domain) {
				continue
			}
			profile.NetworkTargets = append(profile.NetworkTargets, dns.Domain)
		}
		// 填充 zeroclaw 详细网络数据（用于 LLM 分析）
		for _, dns := range r.NetworkResult.DNSQueries {
			profile.ZeroclawDNSQueries = append(profile.ZeroclawDNSQueries, fmt.Sprintf("%s %s", dns.Domain, dns.Type))
		}
		for _, tcp := range r.NetworkResult.TCPConnections {
			profile.ZeroclawTCPConnections = append(profile.ZeroclawTCPConnections, fmt.Sprintf("%s -> %s", tcp.Local, tcp.Remote))
		}
		for _, http := range r.NetworkResult.HTTPRequests {
			profile.ZeroclawHTTPRequests = append(profile.ZeroclawHTTPRequests, fmt.Sprintf("%s %s %s", http.Method, http.Host, http.URL))
		}
	}

	// 从 strace 结果提取 IOC（只保留高风险操作，过滤 print/read/write 等无害操作）
	if r.StraceResult != nil {
		for _, proc := range r.StraceResult.ProcessOps {
			if proc.Command == "" || proc.Op != "execve" {
				continue
			}
			if isBenignCommand(proc.Command) {
				continue
			}
			profile.ExecuteIOCs = append(profile.ExecuteIOCs, fmt.Sprintf("[zeroclaw] cmd=%s", proc.Command))
		}
		for _, fileOp := range r.StraceResult.FileOps {
			if isBenignFilePath(fileOp.Path) {
				continue
			}
			profile.FileTargets = append(profile.FileTargets, fileOp.Path)
			if fileOp.Op == "write" || fileOp.Op == "create" {
				profile.DropIOCs = append(profile.DropIOCs, fmt.Sprintf("[zeroclaw] %s %s", fileOp.Op, fileOp.Path))
			}
		}
		// 填充 zeroclaw 详细 strace 数据（用于 LLM 分析）
		for _, proc := range r.StraceResult.ProcessOps {
			if proc.Command != "" {
				profile.ZeroclawCommands = append(profile.ZeroclawCommands, fmt.Sprintf("[%s] %s", proc.Op, proc.Command))
			}
		}
		for _, fileOp := range r.StraceResult.FileOps {
			profile.ZeroclawFileOps = append(profile.ZeroclawFileOps, fmt.Sprintf("[%s] %s", fileOp.Op, fileOp.Path))
		}
		if len(r.StraceResult.ProcessTree) > 0 {
			profile.ZeroclawProcessTree = generateProcessTreeText(r.StraceResult.ProcessTree, 0)
		}
	}

	// 从行为汇总提取详细信息
	if r.BehaviorSummary != nil {
		logx.With("component", "sandbox_zeroclaw").Debug("converting behavior summary to profile",
			"details_count", len(r.BehaviorSummary.BehaviorDetails),
		)
		for _, detail := range r.BehaviorSummary.BehaviorDetails {
			evidence := fmt.Sprintf("[zeroclaw] %s/%s: %s", detail.Category, detail.Action, detail.Target)
			switch detail.Category {
			case "network":
				profile.OutboundIOCs = append(profile.OutboundIOCs, evidence)
			case "file":
				profile.DropIOCs = append(profile.DropIOCs, evidence)
			case "process":
				profile.ExecuteIOCs = append(profile.ExecuteIOCs, evidence)
			case "credential":
				profile.CredentialIOCs = append(profile.CredentialIOCs, evidence)
			}
		}
		logx.With("component", "sandbox_zeroclaw").Debug("behavior profile IOCs populated",
			"outbound_iocs", len(profile.OutboundIOCs),
			"execute_iocs", len(profile.ExecuteIOCs),
			"drop_iocs", len(profile.DropIOCs),
			"credential_iocs", len(profile.CredentialIOCs),
		)
		// 添加声明与行为一致性信息
		if r.BehaviorSummary.Consistency.Score < 50 {
			profile.ProbeWarnings = append(profile.ProbeWarnings, fmt.Sprintf("声明与行为一致性低 (score=%d): %s", r.BehaviorSummary.Consistency.Score, strings.Join(r.BehaviorSummary.Consistency.Mismatches, "; ")))
		}
		for _, cap := range r.BehaviorSummary.Consistency.ExcessCapabilities {
			profile.ProbeWarnings = append(profile.ProbeWarnings, "声明外能力: "+cap)
		}
		// 填充 zeroclaw 行为汇总数据（用于 LLM 分析）
		profile.ZeroclawDeclaredCaps = r.BehaviorSummary.DeclaredCapabilities
		profile.ZeroclawObservedCaps = r.BehaviorSummary.ObservedCapabilities
		profile.ZeroclawConsistency = fmt.Sprintf("score=%d level=%s mismatches=[%s] excess=[%s]",
			r.BehaviorSummary.Consistency.Score,
			r.BehaviorSummary.Consistency.Level,
			strings.Join(r.BehaviorSummary.Consistency.Mismatches, "; "),
			strings.Join(r.BehaviorSummary.Consistency.ExcessCapabilities, "; "))
	}

	// 逃逸信号
	profile.EvasionSignals = r.EvasionSignals

	// 去重
	profile.NetworkTargets = uniqueStrings(profile.NetworkTargets)
	profile.FileTargets = uniqueStrings(profile.FileTargets)
	profile.ExecuteIOCs = uniqueStrings(profile.ExecuteIOCs)
	profile.OutboundIOCs = uniqueStrings(profile.OutboundIOCs)
	profile.DropIOCs = uniqueStrings(profile.DropIOCs)
	profile.CredentialIOCs = uniqueStrings(profile.CredentialIOCs)
	profile.EvasionSignals = uniqueStrings(profile.EvasionSignals)
	profile.ProbeWarnings = uniqueStrings(profile.ProbeWarnings)

	return profile
}

// isBenignNetworkTarget 判断网络目标是否无害
func isBenignNetworkTarget(host string) bool {
	lower := strings.ToLower(strings.TrimSpace(host))
	if lower == "" {
		return true
	}
	// localhost / 内部地址
	if lower == "localhost" || lower == "127.0.0.1" || lower == "::1" || lower == "0.0.0.0" {
		return true
	}
	// 常见无害域名
	benignDomains := []string{
		"archive.ubuntu.com", "security.ubuntu.com", "deb.debian.org", "dl-cdn.alpinelinux.org",
		"registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
		"github.com", "raw.githubusercontent.com", "objects.githubusercontent.com",
		"crates.io", "static.crates.io",
	}
	for _, d := range benignDomains {
		if lower == d || strings.HasSuffix(lower, "."+d) {
			return true
		}
	}
	return false
}

// isBenignCommand 判断命令是否无害
func isBenignCommand(cmd string) bool {
	lower := strings.ToLower(strings.TrimSpace(cmd))
	if lower == "" {
		return true
	}
	// 常见无害命令
	benignPrefixes := []string{
		"ls", "cat", "echo", "printf", "pwd", "whoami", "id", "date", "env", "printenv",
		"which", "whereis", "head", "tail", "wc", "grep", "find", "sort", "uniq", "cut",
		"tr", "sed", "awk", "xargs", "tee", "true", "false", "test", "[",
		"python3 -c \"print", "python -c \"print",
		"node -e \"console", "node -e 'console",
	}
	for _, prefix := range benignPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	// 纯 print 语句
	if strings.HasPrefix(lower, "print(") || strings.HasPrefix(lower, "console.log") {
		return true
	}
	return false
}

// isBenignFilePath 判断文件路径是否无害
func isBenignFilePath(path string) bool {
	lower := strings.ToLower(strings.TrimSpace(path))
	if lower == "" {
		return true
	}
	// 系统临时目录和常见无害路径
	benignPrefixes := []string{
		"/tmp/", "/var/tmp/", "/proc/self/", "/proc/1/", "/dev/",
		"/etc/ld.so.cache", "/etc/localtime", "/etc/resolv.conf",
		"/usr/lib/", "/usr/share/", "/usr/local/lib/",
	}
	for _, prefix := range benignPrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	// Python/Node 缓存
	if strings.Contains(lower, "__pycache__") || strings.Contains(lower, ".pyc") ||
		strings.Contains(lower, "node_modules/.cache") {
		return true
	}
	return false
}

// buildScenarioContext 构建场景引导上下文（传给 Agent）。
func buildScenarioContext(scenarios []SkillScenario) string {
	if len(scenarios) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("## 技能场景分析\n")
	sb.WriteString("以下是根据技能声明分析出的预期场景，请根据这些场景构造测试用例：\n\n")

	for i, s := range scenarios {
		sb.WriteString(fmt.Sprintf("### 场景 %d: %s\n", i+1, s.Description))
		sb.WriteString(fmt.Sprintf("- 类型: %s\n", string(s.Type)))
		sb.WriteString(fmt.Sprintf("- 预期行为: %s\n", s.ExpectedBehavior))
		sb.WriteString(fmt.Sprintf("- 测试输入: %s\n", s.InputTemplate))
		if len(s.RiskIndicators) > 0 {
			sb.WriteString(fmt.Sprintf("- 风险指标: %s\n", strings.Join(s.RiskIndicators, ", ")))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("请优先使用上述测试输入执行技能，观察实际行为是否与预期一致。\n")

	return sb.String()
}

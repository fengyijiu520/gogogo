package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"skill-scanner/internal/logx"
)

// zeroclawRuntime 实现基于 zeroclaw Docker 沙箱的运行时
type zeroclawRuntime struct {
	image        string
	networkName  string
	seccompPath  string
	cpuLimit     float64
	memoryLimit  string
	pidsLimit    int
	timeoutSecs  int
}

// zeroclawContainer 管理单个沙箱容器的生命周期
type zeroclawContainer struct {
	name        string
	skillPath   string
	runtime     *zeroclawRuntime
	startedAt   time.Time
	pcapFile    string
}

// newZeroclawRuntime 创建 zeroclaw 运行时实例
func newZeroclawRuntime() *zeroclawRuntime {
	return &zeroclawRuntime{
		image:       readEnvOrDefault("REVIEW_SANDBOX_IMAGE", "zeroclaw-sandbox"),
		networkName: readEnvOrDefault("REVIEW_SANDBOX_NETWORK", "analysis-net"),
		seccompPath: readEnvOrDefault("REVIEW_SANDBOX_SECCOMP_PROFILE", ""),
		cpuLimit:    readPositiveFloatEnv("REVIEW_SANDBOX_CPU", 4),
		memoryLimit: readEnvOrDefault("REVIEW_SANDBOX_MEMORY", "4g"),
		pidsLimit:   readPositiveIntEnv("REVIEW_SANDBOX_PIDS_LIMIT", 200),
		timeoutSecs: readPositiveIntEnv("REVIEW_SANDBOX_TIMEOUT_SECS", 60),
	}
}

// Prepare 检查 zeroclaw 运行环境就绪
func (z *zeroclawRuntime) Prepare() error {
	// 检查 Docker 可用
	if _, err := exec.LookPath("docker"); err != nil {
		return fmt.Errorf("docker 不可用: %w", err)
	}

	// 检查镜像存在
	check := exec.Command("docker", "image", "inspect", z.image)
	if out, err := check.CombinedOutput(); err != nil {
		return fmt.Errorf("沙箱镜像 %s 不存在，请先执行 docker build -t %s ./zeroclaw；详情: %s",
			z.image, z.image, strings.TrimSpace(string(out)))
	}

	// 检查 Seccomp 配置文件
	if z.seccompPath != "" {
		if _, err := os.Stat(z.seccompPath); err != nil {
			return fmt.Errorf("Seccomp 配置文件不存在: %s", z.seccompPath)
		}
	}

	return nil
}

// prepareNetwork 确保 Docker 分析网络存在
// 使用 internal 网络：容器有网卡（tcpdump 可抓包），但无法访问外网（防止数据外泄）
func (z *zeroclawRuntime) prepareNetwork() error {
	// 先尝试创建 internal 网络（新网络）
	cmd := exec.Command("docker", "network", "create", "--internal", z.networkName)
	if err := cmd.Run(); err != nil {
		// 网络已存在，检查是否为 internal
		inspectCmd := exec.Command("docker", "network", "inspect", "--format", "{{.Internal}}", z.networkName)
		out, inspectErr := inspectCmd.Output()
		if inspectErr == nil && strings.TrimSpace(string(out)) != "true" {
			// 旧网络不是 internal，删除重建
			exec.Command("docker", "network", "rm", z.networkName).Run()
			return exec.Command("docker", "network", "create", "--internal", z.networkName).Run()
		}
	}
	return nil
}

// startContainer 启动沙箱容器（后台模式）
func (z *zeroclawRuntime) startContainer(ctx context.Context, skillPath string) (*zeroclawContainer, error) {
	if err := z.prepareNetwork(); err != nil {
		return nil, fmt.Errorf("创建分析网络失败: %w", err)
	}

	containerName := fmt.Sprintf("skill-analysis-%d", time.Now().UnixNano())
	absSkillPath, err := filepath.Abs(skillPath)
	if err != nil {
		return nil, fmt.Errorf("获取技能目录绝对路径失败: %w", err)
	}

	args := []string{
		"run", "-d",
		"--name", containerName,
		"--network", z.networkName,
		"--hostname", "workstation",
		"--cpus", fmt.Sprintf("%.0f", z.cpuLimit),
		"--memory", z.memoryLimit,
		"--memory-swap", z.memoryLimit,
		"--pids-limit", fmt.Sprintf("%d", z.pidsLimit),
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=1g",
		"--tmpfs", "/run:rw,noexec,nosuid,size=128m",
		"--tmpfs", "/var/log:rw,noexec,nosuid,size=256m",
		"--tmpfs", "/home/analyst/.zeroclaw:rw,noexec,nosuid,size=64m",
		"--cap-drop", "ALL",
		"--cap-add", "SYS_PTRACE", // strace 监控必需，逃逸风险通过 seccomp 阻止 process_vm_readv/writev 缓解
		"--security-opt", "no-new-privileges:true",
		"--security-opt", "apparmor=docker-default",
	}

	// 强制使用 Seccomp 配置（白名单模式，默认阻止危险 syscall）
	seccompPath := z.seccompPath
	if seccompPath == "" {
		seccompPath = defaultSeccompProfile()
	}
	if seccompPath != "" {
		args = append(args, "--security-opt", fmt.Sprintf("seccomp=%s", seccompPath))
	}

	// 只读挂载技能目录
	args = append(args, "-v", fmt.Sprintf("%s:/home/analyst/skill:ro", absSkillPath))

	// 跳过 entrypoint，以 sleep 保持容器运行
	args = append(args, "--entrypoint", "")
	args = append(args, z.image, "sleep", "3600")

	logger := logx.With("component", "sandbox_zeroclaw", "container", containerName, "image", z.image)
	logger.Info("starting zeroclaw container", "skill_path", absSkillPath)

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("启动容器失败: %s, 输出: %s", err, strings.TrimSpace(string(out)))
	}

	return &zeroclawContainer{
		name:      containerName,
		skillPath: absSkillPath,
		runtime:   z,
		startedAt: time.Now(),
	}, nil
}

// execCommand 在容器内以 analyst 用户执行命令
func (c *zeroclawContainer) execCommand(ctx context.Context, command string, timeoutSecs int) (int, []string, error) {
	// 以 analyst 用户执行命令
	args := []string{"exec", "--user", "analyst", c.name, "/bin/bash", "-c", command}

	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	cmd := exec.CommandContext(execCtx, "docker", args...)
	out, err := cmd.CombinedOutput()

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else if execCtx.Err() == context.DeadlineExceeded {
			return -1, lines, fmt.Errorf("执行超时 (%ds)", timeoutSecs)
		} else {
			return -1, lines, err
		}
	}

	return exitCode, lines, nil
}

// execCommandRaw 执行命令并返回原始输出
func execCommandRaw(containerName, command string) ([]byte, error) {
	return exec.Command("docker", "exec", "--user", "analyst", containerName, "/bin/bash", "-c", command).CombinedOutput()
}

// collectLogs 收集容器日志
func (c *zeroclawContainer) collectLogs(ctx context.Context) ([]string, []string) {
	stdoutCmd := exec.CommandContext(ctx, "docker", "logs", "--tail", "500", c.name)
	stdout, _ := stdoutCmd.CombinedOutput()

	// docker logs 输出到 stderr 的也有
	stderrCmd := exec.CommandContext(ctx, "docker", "logs", "--tail", "500", "--details", c.name)
	stderr, _ := stderrCmd.CombinedOutput()

	stdoutLines := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	stderrLines := strings.Split(strings.TrimSpace(string(stderr)), "\n")

	return stdoutLines, stderrLines
}

// destroy 销毁容器
func (c *zeroclawContainer) destroy(ctx context.Context) {
	logger := logx.With("component", "sandbox_zeroclaw", "container", c.name)

	// 停止容器（最多等 10 秒）
	stopCmd := exec.CommandContext(ctx, "docker", "stop", "-t", "10", c.name)
	stopCmd.Run()

	// 删除容器
	rmCmd := exec.CommandContext(ctx, "docker", "rm", "-f", c.name)
	if err := rmCmd.Run(); err != nil {
		logger.Warn("failed to remove container", "error", err.Error())
	} else {
		logger.Info("container destroyed", "duration_ms", time.Since(c.startedAt).Milliseconds())
	}
}

// isRunning 检查容器是否还在运行
func (c *zeroclawContainer) isRunning(ctx context.Context) bool {
	cmd := exec.CommandContext(ctx, "docker", "inspect", "-f", "{{.State.Running}}", c.name)
	out, err := cmd.CombinedOutput()
	return err == nil && strings.TrimSpace(string(out)) == "true"
}

// zeroclawExecute 使用 zeroclaw Docker 沙箱执行技能
func (r *Runner) zeroclawExecute(ctx context.Context, scanPath string, plan ExecutionPlan, opts ExecuteOptions) (zeroclawSandboxResult, error) {
	result := zeroclawSandboxResult{
		Scenarios: make([]zeroclawScenarioResult, 0, len(plan.Scenarios)),
	}
	startedAt := time.Now()

	rt := newZeroclawRuntime()
	if err := rt.Prepare(); err != nil {
		return result, fmt.Errorf("zeroclaw 运行时准备失败: %w", err)
	}

	logger := logx.With("component", "sandbox_zeroclaw", "request_id", opts.RequestID)
	logger.Info("zeroclaw execute start", "scenario_count", len(plan.Scenarios), "scan_path", scanPath)

	// 启动网络监控
	pcapFile := startNetworkCapture(ctx, rt.networkName)
	result.PcapFile = pcapFile

	// 为每个场景启动独立容器执行
	for i, scenario := range plan.Scenarios {
		if ctx.Err() != nil {
			break
		}

		logger.Info("executing scenario", "index", i, "name", scenario.Name, "command", scenario.Command)

		scenarioResult, err := r.executeZeroclawScenario(ctx, rt, scanPath, scenario, opts)
		if err != nil {
			logger.Warn("scenario execution failed", "scenario", scenario.Name, "error", err.Error())
			scenarioResult = zeroclawScenarioResult{
				Name:      scenario.Name,
				ExitCode:  -1,
				Error:     err.Error(),
			}
		}

		result.Scenarios = append(result.Scenarios, scenarioResult)
		result.TotalDurationMs = time.Since(startedAt).Milliseconds()
	}

	// 停止网络监控
	stopNetworkCapture()

	return result, nil
}

// executeZeroclawScenario 执行单个场景
func (r *Runner) executeZeroclawScenario(ctx context.Context, rt *zeroclawRuntime, scanPath string, scenario ExecutionScenario, opts ExecuteOptions) (zeroclawScenarioResult, error) {
	// 启动容器
	container, err := rt.startContainer(ctx, scanPath)
	if err != nil {
		return zeroclawScenarioResult{}, err
	}
	defer container.destroy(ctx)

	// 构建执行命令
	command := buildScenarioCommand(scenario)
	if command == "" {
		command = "cd /home/analyst/skill && ls -la"
	}

	// 设置环境变量
	envSetup := buildScenarioEnvSetup(scenario)
	if envSetup != "" {
		command = envSetup + " && " + command
	}

	timeoutSecs := scenario.TimeoutSecs
	if timeoutSecs <= 0 {
		timeoutSecs = rt.timeoutSecs
	}

	// 执行命令
	exitCode, output, execErr := container.execCommand(ctx, command, timeoutSecs)

	// 收集容器日志
	stdoutLogs, stderrLogs := container.collectLogs(ctx)

	// 合并所有输出
	allOutput := make([]string, 0, len(output)+len(stdoutLogs)+len(stderrLogs))
	allOutput = append(allOutput, output...)
	allOutput = append(allOutput, stdoutLogs...)
	allOutput = append(allOutput, stderrLogs...)

	result := zeroclawScenarioResult{
		Name:     scenario.Name,
		Command:  command,
		ExitCode: exitCode,
		Output:   allOutput,
		Error:    "",
	}
	if execErr != nil {
		result.Error = execErr.Error()
	}

	return result, nil
}

// buildScenarioCommand 构建场景执行命令
func buildScenarioCommand(scenario ExecutionScenario) string {
	if scenario.Command != "" {
		args := strings.Join(scenario.Args, " ")
		if args != "" {
			return scenario.Command + " " + args
		}
		return scenario.Command
	}
	return ""
}

// buildScenarioEnvSetup 构建环境变量设置
func buildScenarioEnvSetup(scenario ExecutionScenario) string {
	if len(scenario.Env) == 0 {
		return ""
	}
	parts := make([]string, 0, len(scenario.Env))
	for k, v := range scenario.Env {
		parts = append(parts, fmt.Sprintf("export %s=%q", k, v))
	}
	return strings.Join(parts, " && ")
}

// startNetworkCapture 启动网络抓包
func startNetworkCapture(ctx context.Context, networkName string) string {
	// 获取桥接接口名
	bridgeName := getDockerBridgeName(networkName)
	if bridgeName == "" {
		return ""
	}

	pcapDir := filepath.Join(os.TempDir(), "sandbox-captures")
	os.MkdirAll(pcapDir, 0755)
	pcapFile := filepath.Join(pcapDir, fmt.Sprintf("capture-%d.pcap", time.Now().UnixNano()))

	// 启动 tcpdump（后台）
	cmd := exec.CommandContext(ctx, "tcpdump", "-i", bridgeName, "-w", pcapFile, "-n", "-C", "100", "-W", "5")
	if err := cmd.Start(); err != nil {
		logx.With("component", "sandbox_zeroclaw").Warn("failed to start tcpdump", "error", err.Error())
		return ""
	}

	logx.With("component", "sandbox_zeroclaw").Info("network capture started", "interface", bridgeName, "pcap", pcapFile)
	return pcapFile
}

// stopNetworkCapture 停止网络抓包
func stopNetworkCapture() {
	exec.Command("pkill", "-f", "tcpdump.*sandbox-captures").Run()
}

// getDockerBridgeName 获取 Docker 网络的桥接接口名
func getDockerBridgeName(networkName string) string {
	cmd := exec.Command("docker", "network", "inspect", networkName, "-f", "{{index .Options \"com.docker.network.bridge.name\"}}")
	out, err := cmd.CombinedOutput()
	if err == nil {
		bridge := strings.TrimSpace(string(out))
		if bridge != "" {
			return bridge
		}
	}

	// 备用方法：使用网络 ID 前 12 位
	cmd = exec.Command("docker", "network", "inspect", networkName, "-f", "{{.Id}}")
	out, err = cmd.CombinedOutput()
	if err == nil {
		networkID := strings.TrimSpace(string(out))
		if len(networkID) >= 12 {
			return "br-" + networkID[:12]
		}
	}

	return ""
}

// readEnvOrDefault 读取环境变量或返回默认值
func readEnvOrDefault(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

// readPositiveFloatEnv 读取正浮点数环境变量
func readPositiveFloatEnv(key string, fallback float64) float64 {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	var v float64
	if _, err := fmt.Sscanf(raw, "%f", &v); err == nil && v > 0 {
		return v
	}
	return fallback
}

// zeroclawSandboxResult zeroclaw 沙箱执行结果
type zeroclawSandboxResult struct {
	Scenarios       []zeroclawScenarioResult
	PcapFile        string
	TotalDurationMs int64
}

// zeroclawScenarioResult 单个场景执行结果
type zeroclawScenarioResult struct {
	Name     string
	Command  string
	ExitCode int
	Output   []string
	Error    string
}

// extractIOCFromZeroclawOutput 从 zeroclaw 输出中提取 IOC
func extractIOCFromZeroclawOutput(output []string) map[string][]string {
	iocs := map[string][]string{
		"download":        {},
		"drop":            {},
		"execute":         {},
		"outbound":        {},
		"persistence":     {},
		"priv_esc":        {},
		"credential":      {},
		"defense_evasion": {},
		"c2_beacon":       {},
	}

	urlRe := regexp.MustCompile(`https?://[A-Za-z0-9._:/?=&%-]+`)
	ipRe := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	cmdRe := regexp.MustCompile(`\b(exec\.Command|os\.RemoveAll|syscall\.Exec|subprocess\.Popen|child_process)\b`)
	downloadRe := regexp.MustCompile(`(?i)\b(curl\s+|wget\s+|http\.get\b|requests\.get\b|fetch\(|axios\.get\b)`)
	fileDropRe := regexp.MustCompile(`(?i)\b(os\.writefile|ioutil\.writefile|fopen\([^\)]*,\s*"w|chmod\s+\+x)\b`)
	outboundRe := regexp.MustCompile(`(?i)\b(http\.(post|get|newrequest)\b|net\.dial\b|websocket|grpc\.|axios\.|requests\.(post|get)|fetch\(|socket\.)\b`)
	persistRe := regexp.MustCompile(`(?i)\b(crontab\b|/etc/cron\.|systemctl\s+enable\b|schtasks\b|~/.bashrc|~/.profile)\b`)
	privEscRe := regexp.MustCompile(`(?i)\b(sudo\b|setuid\b|setcap\b|chmod\s+4777\b|chmod\s+777\b)\b`)
	credRe := regexp.MustCompile(`(?i)(/etc/shadow|/root/\.netrc|~/.ssh|id_rsa|credentials?\.(json|ya?ml)|\.env\b|secret_access_key|aws_access_key_id)`)
	evasionRe := regexp.MustCompile(`(?i)\b(disable(defender|security)|kill\s+-9\s+(auditd|falco)|history\s+-c|iptables\s+-F\b)\b`)
	c2Re := regexp.MustCompile(`(?i)(beacon\b|heartbeat\b|callback\b|polling\b|/api/checkin|/api/beacon|\bc2\b)`)

	for _, line := range output {
		if urlRe.MatchString(line) {
			for _, m := range urlRe.FindAllString(line, -1) {
				iocs["outbound"] = append(iocs["outbound"], m)
			}
		}
		if ipRe.MatchString(line) {
			for _, m := range ipRe.FindAllString(line, -1) {
				iocs["outbound"] = append(iocs["outbound"], m)
			}
		}
		if cmdRe.MatchString(line) {
			iocs["execute"] = append(iocs["execute"], line)
		}
		if downloadRe.MatchString(line) {
			iocs["download"] = append(iocs["download"], line)
		}
		if fileDropRe.MatchString(line) {
			iocs["drop"] = append(iocs["drop"], line)
		}
		if outboundRe.MatchString(line) {
			iocs["outbound"] = append(iocs["outbound"], line)
		}
		if persistRe.MatchString(line) {
			iocs["persistence"] = append(iocs["persistence"], line)
		}
		if privEscRe.MatchString(line) {
			iocs["priv_esc"] = append(iocs["priv_esc"], line)
		}
		if credRe.MatchString(line) {
			iocs["credential"] = append(iocs["credential"], line)
		}
		if evasionRe.MatchString(line) {
			iocs["defense_evasion"] = append(iocs["defense_evasion"], line)
		}
		if c2Re.MatchString(line) {
			iocs["c2_beacon"] = append(iocs["c2_beacon"], line)
		}
	}

	return iocs
}

// parsePcapFile 解析 pcap 文件提取网络 IOC（需要 tcpdump 命令）
func parsePcapFile(pcapFile string) []string {
	if pcapFile == "" {
		return nil
	}

	cmd := exec.Command("tcpdump", "-r", pcapFile, "-n", "-c", "1000")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil
	}

	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var networkIOCs []string
	ipRe := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)

	for _, line := range lines {
		if strings.Contains(line, "A?") || strings.Contains(line, "AAAA?") {
			// DNS 查询
			networkIOCs = append(networkIOCs, "[DNS] "+strings.TrimSpace(line))
		}
		if ipRe.MatchString(line) {
			networkIOCs = append(networkIOCs, "[NET] "+strings.TrimSpace(line))
		}
	}

	return networkIOCs
}

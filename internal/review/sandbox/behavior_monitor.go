package sandbox

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"skill-scanner/internal/logx"
)

// zeroclawBehaviorMonitor zeroclaw 沙箱行为监控器
type zeroclawBehaviorMonitor struct {
	containerName string
	networkName   string
}

// zeroclawBehaviorReport 行为监控报告
type zeroclawBehaviorReport struct {
	// 网络行为
	DNSQueries   []string `json:"dns_queries"`
	TCPConns     []string `json:"tcp_connections"`
	HTTPRequests []string `json:"http_requests"`
	// 文件行为
	FileCreated []string `json:"file_created"`
	FileDeleted []string `json:"file_deleted"`
	// 进程行为
	Processes []string `json:"processes"`
	// 系统调用
	SyscallViolations []string `json:"syscall_violations"`
	// 综合 IOC
	IOCs map[string][]string `json:"iocs"`
}

// monitorBehavior 在容器执行期间监控行为
func (m *zeroclawBehaviorMonitor) monitorBehavior(ctx context.Context, duration time.Duration) *zeroclawBehaviorReport {
	report := &zeroclawBehaviorReport{
		IOCs: make(map[string][]string),
	}

	logger := logx.With("component", "sandbox_monitor", "container", m.containerName)

	// 并发监控多种行为
	done := make(chan struct{})

	// 1. 监控进程
	go func() {
		defer func() { recover() }()
		m.monitorProcesses(ctx, report, duration)
	}()

	// 2. 监控文件系统变化
	go func() {
		defer func() { recover() }()
		m.monitorFileSystem(ctx, report, duration)
	}()

	// 3. 监控 Seccomp 违规
	go func() {
		defer func() { recover() }()
		m.monitorSyscalls(ctx, report, duration)
	}()

	// 等待监控完成或超时
	go func() {
		time.Sleep(duration)
		close(done)
	}()

	select {
	case <-done:
		logger.Info("behavior monitoring completed")
	case <-ctx.Done():
		logger.Warn("behavior monitoring cancelled")
	}

	return report
}

// monitorProcesses 监控容器内进程
func (m *zeroclawBehaviorMonitor) monitorProcesses(ctx context.Context, report *zeroclawBehaviorReport, duration time.Duration) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	end := time.Now().Add(duration)
	for time.Now().Before(end) {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			cmd := exec.CommandContext(ctx, "docker", "exec", m.containerName, "ps", "aux")
			out, err := cmd.CombinedOutput()
			if err != nil {
				continue
			}
			lines := strings.Split(strings.TrimSpace(string(out)), "\n")
			for _, line := range lines[1:] { // 跳过标题行
				trimmed := strings.TrimSpace(line)
				if trimmed == "" {
					continue
				}
				// 检测可疑进程
				lower := strings.ToLower(trimmed)
				if isSuspiciousProcess(lower) {
					report.Processes = append(report.Processes, trimmed)
					report.IOCs["execute"] = append(report.IOCs["execute"], "[进程] "+trimmed)
				}
			}
		}
	}
}

// monitorFileSystem 监控文件系统变化
func (m *zeroclawBehaviorMonitor) monitorFileSystem(ctx context.Context, report *zeroclawBehaviorReport, duration time.Duration) {
	// 执行前快照
	beforeSnapshot := m.snapshotFileSystem(ctx)

	time.Sleep(duration)

	// 执行后快照
	afterSnapshot := m.snapshotFileSystem(ctx)

	// 对比差异
	for path := range afterSnapshot {
		if _, exists := beforeSnapshot[path]; !exists {
			report.FileCreated = append(report.FileCreated, path)
			report.IOCs["drop"] = append(report.IOCs["drop"], "[文件创建] "+path)
		}
	}
	for path := range beforeSnapshot {
		if _, exists := afterSnapshot[path]; !exists {
			report.FileDeleted = append(report.FileDeleted, path)
			report.IOCs["drop"] = append(report.IOCs["drop"], "[文件删除] "+path)
		}
	}
}

// snapshotFileSystem 文件系统快照
func (m *zeroclawBehaviorMonitor) snapshotFileSystem(ctx context.Context) map[string]bool {
	snapshot := make(map[string]bool)

	// 扫描关键目录
	dirs := []string{"/tmp", "/home/analyst", "/var/log"}
	for _, dir := range dirs {
		cmd := exec.CommandContext(ctx, "docker", "exec", m.containerName, "find", dir, "-type", "f", "-maxdepth", "3")
		out, err := cmd.CombinedOutput()
		if err != nil {
			continue
		}
		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if trimmed := strings.TrimSpace(line); trimmed != "" {
				snapshot[trimmed] = true
			}
		}
	}

	return snapshot
}

// monitorSyscalls 监控系统调用违规
func (m *zeroclawBehaviorMonitor) monitorSyscalls(ctx context.Context, report *zeroclawBehaviorReport, duration time.Duration) {
	// 从宿主机 Seccomp 日志中提取
	cmd := exec.CommandContext(ctx, "journalctl", "-k", "--since", fmt.Sprintf("-%ds", int(duration.Seconds())+5), "--no-pager")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return
	}

	seccompRe := regexp.MustCompile(`(?i)seccomp.*violation|audit.*seccomp`)
	for _, line := range strings.Split(string(out), "\n") {
		if seccompRe.MatchString(line) {
			report.SyscallViolations = append(report.SyscallViolations, strings.TrimSpace(line))
			report.IOCs["syscall_violation"] = append(report.IOCs["syscall_violation"], strings.TrimSpace(line))
		}
	}
}

// isSuspiciousProcess 检测可疑进程
func isSuspiciousProcess(line string) bool {
	suspiciousPatterns := []string{
		"curl ", "wget ", "nc ", "ncat ", "netcat ",
		"ssh ", "scp ", "rsync ",
		"python -c", "python3 -c", "perl -e", "ruby -e",
		"base64", "eval(", "exec(",
		"crontab", "systemctl", "service ",
		"chmod 777", "chmod 4777", "chown root",
		"/etc/shadow", "/etc/passwd",
		"iptables", "nft ",
		"kill -9", "pkill ",
	}
	for _, pattern := range suspiciousPatterns {
		if strings.Contains(line, pattern) {
			return true
		}
	}
	return false
}

// analyzeBehaviorChains 分析行为链
func analyzeBehaviorChains(iocs map[string][]string) []BehaviorChainSegment {
	var chains []BehaviorChainSegment

	// 检测下载→落地→执行链
	downloads := iocs["download"]
	drops := iocs["drop"]
	executes := iocs["execute"]

	if len(downloads) > 0 && len(executes) > 0 {
		chains = append(chains, BehaviorChainSegment{
			Type:     "download-execute",
			Severity: "高风险",
			Segments: []string{"下载", "执行"},
			Evidence: append(downloads, executes...),
			Description: "检测到下载后执行的行为链，可能存在二阶段载荷",
			Remediation: "1. 移除自动下载执行逻辑\n2. 如需下载资源，使用白名单校验来源\n3. 下载后进行完整性校验",
		})
	}

	if len(downloads) > 0 && len(drops) > 0 {
		chains = append(chains, BehaviorChainSegment{
			Type:     "download-drop",
			Severity: "中风险",
			Segments: []string{"下载", "落地"},
			Evidence: append(downloads, drops...),
			Description: "检测到下载并写入文件系统的行为",
			Remediation: "1. 确认下载内容是否在声明范围内\n2. 限制下载目录为临时目录\n3. 使用后清理下载文件",
		})
	}

	if len(drops) > 0 && len(executes) > 0 {
		chains = append(chains, BehaviorChainSegment{
			Type:     "drop-execute",
			Severity: "高风险",
			Segments: []string{"落地", "执行"},
			Evidence: append(drops, executes...),
			Description: "检测到写入文件后执行的行为，可能是持久化或恶意载荷",
			Remediation: "1. 移除写入后执行的逻辑\n2. 如需生成脚本执行，使用安全的临时目录\n3. 执行前进行代码审查",
		})
	}

	// 检测凭据访问→外联链
	credentials := iocs["credential"]
	outbounds := iocs["outbound"]

	if len(credentials) > 0 && len(outbounds) > 0 {
		chains = append(chains, BehaviorChainSegment{
			Type:     "credential-exfiltrate",
			Severity: "高风险",
			Segments: []string{"凭据访问", "外联"},
			Evidence: append(credentials, outbounds...),
			Description: "检测到凭据访问后外联的行为，可能存在数据窃取",
			Remediation: "1. 移除对敏感文件的访问\n2. 使用环境变量或安全存储管理凭据\n3. 限制网络访问目标",
		})
	}

	// 检测持久化行为
	persistence := iocs["persistence"]
	if len(persistence) > 0 {
		chains = append(chains, BehaviorChainSegment{
			Type:     "persistence",
			Severity: "高风险",
			Segments: []string{"持久化"},
			Evidence: persistence,
			Description: "检测到持久化行为（crontab/systemctl/bashrc 修改）",
			Remediation: "1. 移除所有持久化逻辑\n2. 技能不应修改系统启动项\n3. 如需定时任务，通过平台调度而非系统 crontab",
		})
	}

	// 检测提权行为
	privEsc := iocs["priv_esc"]
	if len(privEsc) > 0 {
		chains = append(chains, BehaviorChainSegment{
			Type:     "privilege_escalation",
			Severity: "高风险",
			Segments: []string{"提权"},
			Evidence: privEsc,
			Description: "检测到提权行为（sudo/setuid/chmod 777）",
			Remediation: "1. 移除所有提权操作\n2. 技能应以最小权限运行\n3. 如需特定权限，通过声明申请",
		})
	}

	return chains
}

// BehaviorChainSegment 行为链段
type BehaviorChainSegment struct {
	Type         string   `json:"type"`
	Severity     string   `json:"severity"`
	Segments     []string `json:"segments"`
	Evidence     []string `json:"evidence"`
	Description  string   `json:"description"`
	Remediation  string   `json:"remediation"`
}

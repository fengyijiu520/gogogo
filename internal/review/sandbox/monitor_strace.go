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

// straceMonitor strace 命令监控器
type straceMonitor struct {
	containerName string
	outputDir     string
}

// straceResult strace 监控结果
type straceResult struct {
	// 进程树
	ProcessTree []ProcessNode `json:"process_tree"`
	// 所有系统调用
	Syscalls []SyscallRecord `json:"syscalls"`
	// 文件操作
	FileOps []FileOperation `json:"file_ops"`
	// 网络操作
	NetOps []NetOperation `json:"net_ops"`
	// 进程创建
	ProcessOps []ProcessOperation `json:"process_ops"`
	// 原始输出文件
	TraceFile string `json:"trace_file"`
}

// ProcessNode 进程树节点
type ProcessNode struct {
	PID      int           `json:"pid"`
	PPID     int           `json:"ppid"`
	Command  string        `json:"command"`
	User     string        `json:"user"`
	Children []ProcessNode `json:"children,omitempty"`
}

// SyscallRecord 系统调用记录
type SyscallRecord struct {
	PID     int    `json:"pid"`
	Name    string `json:"name"`
	Args    string `json:"args"`
	Result  string `json:"result"`
	Time    string `json:"time"`
}

// FileOperation 文件操作
type FileOperation struct {
	PID      int    `json:"pid"`
	Op       string `json:"op"` // open/read/write/unlink/rename/chmod
	Path     string `json:"path"`
	Flags    string `json:"flags,omitempty"`
	Size     int    `json:"size,omitempty"`
}

// NetOperation 网络操作
type NetOperation struct {
	PID      int    `json:"pid"`
	Op       string `json:"op"` // connect/sendto/recvfrom/bind/listen
	Family   string `json:"family"` // IPv4/IPv6
	Addr     string `json:"addr"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"` // TCP/UDP
}

// ProcessOperation 进程操作
type ProcessOperation struct {
	PID       int    `json:"pid"`
	Op        string `json:"op"` // fork/clone/execve/exit
	ChildPID  int    `json:"child_pid,omitempty"`
	Command   string `json:"command,omitempty"`
	ExitCode  int    `json:"exit_code,omitempty"`
}

// startStraceMonitor 启动 strace 监控
func startStraceMonitor(ctx context.Context, containerName string) *straceMonitor {
	monitor := &straceMonitor{
		containerName: containerName,
		outputDir:     "/tmp",
	}

	// 在容器内启动 strace 追踪所有进程
	// strace -f -ff -o /tmp/trace -e trace=process,file,network
	go monitor.startTracing(ctx)

	return monitor
}

// startTracing 启动追踪
func (m *straceMonitor) startTracing(ctx context.Context) {
	logger := logx.With("component", "strace_monitor", "container", m.containerName)

	// 获取容器内主进程的 PID
	pidCmd := exec.CommandContext(ctx, "docker", "exec", m.containerName,
		"/bin/bash", "-c", "cat /proc/1/status | grep Pid | awk '{print $2}'")
	pidOut, _ := pidCmd.CombinedOutput()
	pid := strings.TrimSpace(string(pidOut))
	if pid == "" {
		pid = "1"
	}

	logger.Info("starting strace", "target_pid", pid)

	logger.Info("starting strace inside container")

	// 在容器内以 root 身份运行 strace，追踪容器内所有进程
	// 先收集容器内所有进程 PID，再用 strace 同时追踪（包括 docker exec 创建的独立进程）
	// 使用 -d 参数让 docker exec 在后台运行，nohup 确保进程持续
	straceCmd := exec.Command("docker", "exec", "-d", m.containerName,
		"/bin/bash", "-c",
		`pids=$(ps -e -o pid= | tr '\n' ' ' | sed 's/ / -p /g' | sed 's/^/-p /'); `+
			`nohup strace -f $pids -e trace=clone,fork,vfork,execve,open,openat,read,write,connect,sendto,recvfrom,bind,listen,accept,socket -o /tmp/strace.log -t > /dev/null 2>&1 &`)

	if err := straceCmd.Start(); err != nil {
		logger.Warn("strace failed", "error", err.Error())
		return
	}

	// 等待 strace 启动
	time.Sleep(500 * time.Millisecond)
	logger.Info("strace started inside container")

	// 等待 context 结束
	<-ctx.Done()
	// 停止容器内的 strace 进程
	exec.Command("docker", "exec", m.containerName, "/bin/bash", "-c", "pkill -f strace 2>/dev/null").Run()
	logger.Info("strace completed")
}

// collectStraceOutput 收集 strace 输出
func (m *straceMonitor) collectStraceOutput(ctx context.Context) *straceResult {
	result := &straceResult{
		ProcessTree: make([]ProcessNode, 0),
		Syscalls:    make([]SyscallRecord, 0),
		FileOps:     make([]FileOperation, 0),
		NetOps:      make([]NetOperation, 0),
		ProcessOps:  make([]ProcessOperation, 0),
	}

	// 从容器内读取 strace 日志
	cmd := exec.Command("docker", "exec", m.containerName, "/bin/bash", "-c", "cat /tmp/strace.log 2>/dev/null || echo ''")
	out, _ := cmd.CombinedOutput()
	traceData := string(out)
	result.TraceFile = traceData

	if traceData == "" {
		return result
	}

	// 解析 strace 输出
	m.parseStraceOutput(traceData, result)

	// 构建进程树
	result.ProcessTree = m.buildProcessTree(result.ProcessOps)

	return result
}

// parseStraceOutput 解析 strace 输出
func (m *straceMonitor) parseStraceOutput(data string, result *straceResult) {
	lines := strings.Split(data, "\n")

	// 匹配 strace 行: PID syscall(args) = result <time>
	lineRe := regexp.MustCompile(`^\s*(\d+)\s+(\w+)\(([^)]*)\)\s*=\s*(.+?)(?:\s*<([^>]*)>)?\s*$`)
	// 匹配 clone/fork
	cloneRe := regexp.MustCompile(`clone\(([^)]*)\)\s*=\s*(\d+)`)
	execveRe := regexp.MustCompile(`execve\("([^"]+)"`)
	// 匹配网络连接
	connectRe := regexp.MustCompile(`connect\(\d+,\s*\{family=AF_INET(?:6)?,\s*addr=([^,}]+)(?:,\s*port=(\d+))?\}`)
	// 匹配文件操作
	openRe := regexp.MustCompile(`(?:open|openat)\([^,]*,\s*"([^"]+)"`)
	writeRe := regexp.MustCompile(`write\(\d+,\s*"([^"]*)"`)

	pid := 0
	for _, line := range lines {
		if line == "" {
			continue
		}

		matches := lineRe.FindStringSubmatch(line)
		if matches == nil {
			continue
		}

		fmt.Sscanf(matches[1], "%d", &pid)
		syscallName := matches[2]
		args := matches[3]
		resultStr := matches[4]

		// 记录系统调用
		result.Syscalls = append(result.Syscalls, SyscallRecord{
			PID:    pid,
			Name:   syscallName,
			Args:   args,
			Result: resultStr,
		})

		// 解析进程操作
		switch syscallName {
		case "clone", "fork", "vfork":
			if childPID := cloneRe.FindStringSubmatch(line); childPID != nil {
				var cpid int
				fmt.Sscanf(childPID[2], "%d", &cpid)
				result.ProcessOps = append(result.ProcessOps, ProcessOperation{
					PID:      pid,
					Op:       syscallName,
					ChildPID: cpid,
				})
			}
		case "execve":
			if m := execveRe.FindStringSubmatch(args); m != nil {
				result.ProcessOps = append(result.ProcessOps, ProcessOperation{
					PID:     pid,
					Op:      "execve",
					Command: m[1],
				})
			}
		}

		// 解析网络操作
		if syscallName == "connect" {
			if m := connectRe.FindStringSubmatch(line); m != nil {
				addr := strings.Trim(m[1], `"`)
				port := 0
				if len(m) > 2 {
					fmt.Sscanf(m[2], "%d", &port)
				}
				result.NetOps = append(result.NetOps, NetOperation{
					PID:  pid,
					Op:   "connect",
					Addr: addr,
					Port: port,
				})
			}
		}

		// 解析文件操作
		if syscallName == "open" || syscallName == "openat" {
			if m := openRe.FindStringSubmatch(args); m != nil {
				result.FileOps = append(result.FileOps, FileOperation{
					PID:  pid,
					Op:   "open",
					Path: m[1],
				})
			}
		}
		if syscallName == "write" {
			if m := writeRe.FindStringSubmatch(args); m != nil {
				result.FileOps = append(result.FileOps, FileOperation{
					PID:  pid,
					Op:   "write",
					Path: m[1],
				})
			}
		}
	}
}

// buildProcessTree 构建进程树
func (m *straceMonitor) buildProcessTree(ops []ProcessOperation) []ProcessNode {
	// 构建 PID → 命令映射
	pidCmd := make(map[int]string)
	pidParent := make(map[int]int)

	for _, op := range ops {
		if op.Op == "execve" && op.Command != "" {
			pidCmd[op.PID] = op.Command
		}
		if op.ChildPID > 0 {
			pidParent[op.ChildPID] = op.PID
			if op.Op != "execve" {
				pidCmd[op.ChildPID] = fmt.Sprintf("[%s]", op.Op)
			}
		}
	}

	// 找到根进程
	children := make(map[int][]int)
	for child, parent := range pidParent {
		children[parent] = append(children[parent], child)
	}

	// 递归构建树
	var buildNode func(pid int) ProcessNode
	buildNode = func(pid int) ProcessNode {
		node := ProcessNode{
			PID:     pid,
			Command: pidCmd[pid],
		}
		for _, childPID := range children[pid] {
			node.Children = append(node.Children, buildNode(childPID))
		}
		return node
	}

	// 找到所有根 PID（没有父进程的）
	hasParent := make(map[int]bool)
	for _, p := range pidParent {
		hasParent[p] = true
	}

	var roots []ProcessNode
	for pid := range pidCmd {
		if !hasParent[pid] {
			roots = append(roots, buildNode(pid))
		}
	}

	return roots
}

// generateProcessTreeText 生成进程树文本
func generateProcessTreeText(tree []ProcessNode, indent int) string {
	var lines []string
	prefix := strings.Repeat("  ", indent)
	for _, node := range tree {
		line := fmt.Sprintf("%s├── PID %d: %s", prefix, node.PID, node.Command)
		lines = append(lines, line)
		if len(node.Children) > 0 {
			lines = append(lines, generateProcessTreeText(node.Children, indent+1))
		}
	}
	return strings.Join(lines, "\n")
}

// extractNetworkTargetsFromStrace 从 strace 结果提取网络目标
func extractNetworkTargetsFromStrace(result *straceResult) []string {
	var targets []string
	seen := make(map[string]bool)

	for _, op := range result.NetOps {
		key := fmt.Sprintf("%s:%d", op.Addr, op.Port)
		if !seen[key] {
			seen[key] = true
			if op.Port > 0 {
				targets = append(targets, fmt.Sprintf("%s:%d", op.Addr, op.Port))
			} else {
				targets = append(targets, op.Addr)
			}
		}
	}

	return targets
}

// extractCommandsFromStrace 从 strace 结果提取执行的命令
func extractCommandsFromStrace(result *straceResult) []string {
	var commands []string
	seen := make(map[string]bool)

	for _, op := range result.ProcessOps {
		if op.Command != "" && !seen[op.Command] {
			seen[op.Command] = true
			commands = append(commands, op.Command)
		}
	}

	return commands
}

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("用法: sandbox-test <技能目录路径>")
		os.Exit(1)
	}

	skillPath, _ := filepath.Abs(os.Args[1])
	fmt.Println("🔬 ZeroClaw 沙箱完整行为监控测试")
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Printf("📂 技能: %s\n\n", skillPath)

	containerName := fmt.Sprintf("sandbox-test-%d", time.Now().UnixNano())
	networkName := "analysis-net"

	// 1. 创建容器
	fmt.Println("📦 [1/7] 创建独立沙箱容器...")
	exec.Command("docker", "network", "create", networkName).Run()

	args := []string{
		"run", "-d", "--name", containerName,
		"--network", networkName,
		"--hostname", "workstation",
		"--cpus", "2", "--memory", "1g", "--pids-limit", "100",
		"--read-only",
		"--tmpfs", "/tmp:rw,noexec,nosuid,size=256m",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges:true",
		"--entrypoint", "",
		"-v", skillPath + ":/home/analyst/skill:ro",
		"zeroclaw-sandbox", "sleep", "300",
	}
	out, err := exec.Command("docker", args...).CombinedOutput()
	if err != nil {
		fmt.Printf("❌ %v: %s\n", err, string(out))
		return
	}
	fmt.Printf("   ✅ 容器: %s\n\n", containerName[:30]+"...")

	defer func() {
		fmt.Print("\n🧹 清理:\n")
		// 停止所有监控进程
		fmt.Print("   停止监控...")
		exec.Command("pkill", "-f", "strace.*"+containerName).Run()
		exec.Command("pkill", "-f", "tcpdump.*"+containerName).Run()
		time.Sleep(1 * time.Second)
		fmt.Println(" ✅")

		// 销毁容器
		fmt.Print("   销毁容器...")
		exec.Command("docker", "stop", "-t", "5", containerName).Run()
		exec.Command("docker", "rm", "-f", containerName).Run()
		fmt.Println(" ✅")
	}()

	// 2. 启动 strace（在宿主机上追踪容器所有进程）
	fmt.Println("🔍 [2/7] 启动 strace 命令追踪...")
	// 获取容器内所有进程的宿主机 PID
	psOut, _ := exec.Command("docker", "top", containerName, "-o", "pid").CombinedOutput()
	var hostPIDs []string
	for _, line := range strings.Split(strings.TrimSpace(string(psOut)), "\n") {
		pid := strings.TrimSpace(line)
		if pid != "" && pid != "PID" {
			hostPIDs = append(hostPIDs, pid)
		}
	}

	straceLog := "/tmp/strace-" + containerName + ".log"
	var straceCmd *exec.Cmd
	if len(hostPIDs) > 0 {
		// 追踪容器内所有进程
		straceArgs := []string{"-f", "-e", "trace=clone,fork,execve,connect,open,write,socket", "-o", straceLog, "-t"}
		for _, pid := range hostPIDs {
			straceArgs = append(straceArgs, "-p", pid)
		}
		straceCmd = exec.Command("strace", straceArgs...)
		straceCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := straceCmd.Start(); err != nil {
			fmt.Printf("   ⚠️ strace 失败: %v\n", err)
		} else {
			fmt.Printf("   ✅ strace 追踪 %d 个进程 → %s\n", len(hostPIDs), straceLog)
			defer func() {
				if straceCmd != nil && straceCmd.Process != nil {
					straceCmd.Process.Kill()
				}
			}()
		}
	}
	fmt.Println()

	// 3. 启动网络监控
	fmt.Println("🌐 [3/7] 启动网络流量监控...")
	bridgeName := getBridge(networkName)
	pcapFile := "/tmp/sandbox-net-" + containerName + ".pcap"

	var tcpdumpCmd *exec.Cmd
	if bridgeName != "" {
		tcpdumpCmd = exec.Command("tcpdump", "-i", bridgeName, "-w", pcapFile, "-n", "-s", "0")
		tcpdumpCmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := tcpdumpCmd.Start(); err != nil {
			fmt.Printf("   ⚠️ tcpdump 失败: %v\n", err)
		} else {
			fmt.Printf("   ✅ tcpdump 接口: %s → %s\n", bridgeName, pcapFile)
			defer func() {
				if tcpdumpCmd != nil && tcpdumpCmd.Process != nil {
					// 发送 SIGINT 让 tcpdump 优雅退出（刷新缓冲区）
					tcpdumpCmd.Process.Signal(syscall.SIGINT)
					time.Sleep(500 * time.Millisecond)
				}
			}()
		}
	}
	fmt.Println()

	// 4. 发现入口点
	fmt.Println("🔎 [4/7] 发现技能入口点...")
	entrypoints := discoverEntrypoints(skillPath)
	if len(entrypoints) == 0 {
		entrypoints = []string{"ls -la /home/analyst/skill"}
	}
	for i, ep := range entrypoints {
		fmt.Printf("   [%d] %s\n", i+1, ep)
	}
	fmt.Println()

	// 5. 执行技能
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("🚀 [5/7] 执行技能")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	for i, ep := range entrypoints {
		fmt.Printf("\n  ┌─ 场景 %d/%d: %s\n", i+1, len(entrypoints), ep)
		start := time.Now()
		out, err := exec.Command("docker", "exec", "--user", "analyst", containerName, "/bin/bash", "-c", ep).CombinedOutput()
		dur := time.Since(start)

		for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if line != "" {
				fmt.Printf("  │ %s\n", line)
			}
		}
		code := 0
		if err != nil {
			if e, ok := err.(*exec.ExitError); ok {
				code = e.ExitCode()
			}
		}
		fmt.Printf("  └─ exit=%d time=%v\n", code, dur)
	}
	fmt.Println()

	time.Sleep(2 * time.Second)

	// 6. 收集行为数据
	fmt.Println("═══════════════════════════════════════════════════════════════")
	fmt.Println("📊 [6/7] 行为分析结果")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	// 进程树
	fmt.Println("\n  🌲 进程树:")
	treeOut, _ := exec.Command("docker", "exec", "--user", "analyst", containerName,
		"/bin/bash", "-c", "ps -ef --forest 2>/dev/null || ps aux").CombinedOutput()
	for _, line := range strings.Split(strings.TrimSpace(string(treeOut)), "\n") {
		fmt.Printf("     %s\n", line)
	}

	// strace
	fmt.Printf("\n  📋 命令追踪 (strace):\n")
	straceOut, _ := exec.Command("cat", straceLog).CombinedOutput()
	straceLines := strings.Split(strings.TrimSpace(string(straceOut)), "\n")

	var execCalls, connectCalls, openCalls []string
	for _, line := range straceLines {
		if strings.Contains(line, "execve") {
			execCalls = append(execCalls, line)
		}
		if strings.Contains(line, "connect") {
			connectCalls = append(connectCalls, line)
		}
		if strings.Contains(line, "open") {
			openCalls = append(openCalls, line)
		}
	}

	if len(execCalls) > 0 {
		fmt.Println("     ⚙️ 进程执行 (execve):")
		for _, c := range execCalls[:min(10, len(execCalls))] {
			fmt.Printf("        %s\n", strings.TrimSpace(c))
		}
	}
	if len(connectCalls) > 0 {
		fmt.Println("     🌐 网络连接 (connect):")
		for _, c := range connectCalls[:min(10, len(connectCalls))] {
			fmt.Printf("        %s\n", strings.TrimSpace(c))
		}
	}
	if len(openCalls) > 0 {
		fmt.Println("     📁 文件打开 (open):")
		for _, c := range openCalls[:min(10, len(openCalls))] {
			fmt.Printf("        %s\n", strings.TrimSpace(c))
		}
	}
	fmt.Printf("     (共 %d 条系统调用)\n", len(straceLines))

	// 网络
	fmt.Printf("\n  🌐 网络外联:\n")
	if _, err := os.Stat(pcapFile); err == nil {
		dnsOut, _ := exec.Command("tcpdump", "-r", pcapFile, "-n", "port 53", "-l").CombinedOutput()
		dnsLines := strings.Split(strings.TrimSpace(string(dnsOut)), "\n")
		if len(dnsLines) > 0 && dnsLines[0] != "" {
			fmt.Println("     📡 DNS 查询:")
			for _, line := range dnsLines[:min(10, len(dnsLines))] {
				if line != "" {
					fmt.Printf("        %s\n", strings.TrimSpace(line))
				}
			}
		}

		tcpOut, _ := exec.Command("tcpdump", "-r", pcapFile, "-n", "tcp", "-l").CombinedOutput()
		tcpLines := strings.Split(strings.TrimSpace(string(tcpOut)), "\n")
		if len(tcpLines) > 0 && tcpLines[0] != "" {
			fmt.Println("     🔗 TCP 连接:")
			for _, line := range tcpLines[:min(10, len(tcpLines))] {
				if line != "" {
					fmt.Printf("        %s\n", strings.TrimSpace(line))
				}
			}
		}
	}

	// 文件变化
	fmt.Println("\n  📁 新增文件:")
	newFiles, _ := exec.Command("docker", "exec", containerName,
		"/bin/bash", "-c", "find /tmp -type f 2>/dev/null").CombinedOutput()
	for _, f := range strings.Split(strings.TrimSpace(string(newFiles)), "\n") {
		if f != "" {
			fmt.Printf("     + %s\n", f)
		}
	}

	// 7. 安全检查
	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("🔒 [7/7] 安全检查")
	fmt.Println("═══════════════════════════════════════════════════════════════")

	checks := []struct {
		name string
		fn   func() (bool, string)
	}{
		{"技能以 analyst 用户执行", func() (bool, string) {
			out, _ := exec.Command("docker", "exec", "--user", "analyst", containerName, "whoami").CombinedOutput()
			return strings.TrimSpace(string(out)) == "analyst", strings.TrimSpace(string(out))
		}},
		{"技能目录只读", func() (bool, string) {
			out, _ := exec.Command("docker", "exec", "--user", "analyst", containerName,
				"/bin/bash", "-c", "touch /home/analyst/skill/test 2>&1").CombinedOutput()
			return strings.Contains(string(out), "Read-only") || strings.Contains(string(out), "Permission denied"), "写入被拒绝"
		}},
		{"无 sudo 权限", func() (bool, string) {
			out, _ := exec.Command("docker", "exec", "--user", "analyst", containerName,
				"/bin/bash", "-c", "sudo whoami 2>&1 || echo 'no sudo'").CombinedOutput()
			return !strings.Contains(string(out), "root"), strings.TrimSpace(string(out))
		}},
		{"hostname 伪装", func() (bool, string) {
			out, _ := exec.Command("docker", "exec", containerName, "hostname").CombinedOutput()
			return strings.TrimSpace(string(out)) == "workstation", strings.TrimSpace(string(out))
		}},
	}

	for _, check := range checks {
		ok, detail := check.fn()
		if ok {
			fmt.Printf("   ✅ %s (%s)\n", check.name, detail)
		} else {
			fmt.Printf("   ❌ %s (%s)\n", check.name, detail)
		}
	}

	fmt.Println("\n═══════════════════════════════════════════════════════════════")
	fmt.Println("✅ 完整行为监控测试完成")
	fmt.Println("═══════════════════════════════════════════════════════════════")
}

func discoverEntrypoints(dir string) []string {
	var eps []string
	prefix := "/home/analyst/skill"
	for _, c := range []string{"main.py", "app.py", "main.js", "app.js", "main.go", "bootstrap.sh", "start.sh", "run.sh"} {
		if _, err := os.Stat(filepath.Join(dir, c)); err == nil {
			full := prefix + "/" + c
			switch filepath.Ext(c) {
			case ".py":
				eps = append(eps, "python3 "+full)
			case ".js":
				eps = append(eps, "node "+full)
			case ".go":
				eps = append(eps, "go run "+full)
			case ".sh":
				eps = append(eps, "bash "+full)
			}
		}
	}
	scriptDir := filepath.Join(dir, "scripts")
	if entries, err := os.ReadDir(scriptDir); err == nil {
		for _, e := range entries {
			if !e.IsDir() && (filepath.Ext(e.Name()) == ".py" || filepath.Ext(e.Name()) == ".sh" || filepath.Ext(e.Name()) == ".js") {
				eps = append(eps, prefix+"/scripts/"+e.Name())
			}
		}
	}
	return eps
}

func getBridge(network string) string {
	out, err := exec.Command("docker", "network", "inspect", network, "-f",
		"{{index .Options \"com.docker.network.bridge.name\"}}").CombinedOutput()
	if err == nil {
		if b := strings.TrimSpace(string(out)); b != "" {
			return b
		}
	}
	out, err = exec.Command("docker", "network", "inspect", network, "-f", "{{.Id}}").CombinedOutput()
	if err == nil {
		if id := strings.TrimSpace(string(out)); len(id) >= 12 {
			return "br-" + id[:12]
		}
	}
	return ""
}

func snapshotProcs(container string) map[string]bool {
	m := make(map[string]bool)
	out, _ := exec.Command("docker", "exec", "--user", "analyst", container, "ps", "aux").CombinedOutput()
	for _, l := range strings.Split(string(out), "\n")[1:] {
		if t := strings.TrimSpace(l); t != "" {
			m[t] = true
		}
	}
	return m
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

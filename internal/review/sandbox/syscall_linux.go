package sandbox

import (
	"os/exec"
	"strings"
	"syscall"
)

// setPgid 设置进程组 ID（用于杀死整个进程树）
func setPgid() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup 杀死进程组
func killProcessGroup(pid int) {
	syscall.Kill(-pid, syscall.SIGTERM)
}

// getDockerBridge 获取 Docker 桥接接口名（无需 sudo）
func getDockerBridge(networkName string) string {
	out, err := exec.Command("docker", "network", "inspect", networkName, "-f",
		"{{index .Options \"com.docker.network.bridge.name\"}}").CombinedOutput()
	if err == nil {
		if b := strings.TrimSpace(string(out)); b != "" {
			return b
		}
	}
	out, err = exec.Command("docker", "network", "inspect", networkName, "-f", "{{.Id}}").CombinedOutput()
	if err == nil {
		if id := strings.TrimSpace(string(out)); len(id) >= 12 {
			return "br-" + id[:12]
		}
	}
	return ""
}

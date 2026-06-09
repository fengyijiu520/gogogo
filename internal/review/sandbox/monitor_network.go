package sandbox

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"syscall"
	"time"

	"skill-scanner/internal/logx"
)

// networkMonitor 网络行为监控器
type networkMonitor struct {
	containerName string
	networkName   string
	pcapFile      string
}

// networkResult 网络监控结果
type networkResult struct {
	// DNS 查询
	DNSQueries []DNSEvent `json:"dns_queries"`
	// TCP 连接
	TCPConnections []TCPEvent `json:"tcp_connections"`
	// HTTP 请求
	HTTPRequests []HTTPEvent `json:"http_requests"`
	// 所有外联目标（IP + 域名）
	OutboundTargets []OutboundTarget `json:"outbound_targets"`
	// pcap 文件路径
	PcapFile string `json:"pcap_file"`
}

// DNSEvent DNS 查询事件
type DNSEvent struct {
	Timestamp string `json:"timestamp"`
	Domain    string `json:"domain"`
	Type      string `json:"type"` // A/AAAA/CNAME/MX
	Server    string `json:"server"`
}

// TCPEvent TCP 连接事件
type TCPEvent struct {
	Timestamp string `json:"timestamp"`
	Local     string `json:"local"`
	Remote    string `json:"remote"`
	State     string `json:"state"`
}

// HTTPEvent HTTP 请求事件
type HTTPEvent struct {
	Timestamp string `json:"timestamp"`
	Method    string `json:"method"`
	URL       string `json:"url"`
	Host      string `json:"host"`
}

// OutboundTarget 外联目标
type OutboundTarget struct {
	Type   string `json:"type"` // ip/domain
	Value  string `json:"value"`
	Port   int    `json:"port,omitempty"`
	Source string `json:"source"` // dns/tcp/http
}

// startNetworkMonitor 启动网络监控
func startNetworkMonitor(ctx context.Context, containerName, networkName string) *networkMonitor {
	monitor := &networkMonitor{
		containerName: containerName,
		networkName:   networkName,
	}

	// 获取桥接接口
	bridgeName := getDockerBridge(networkName)
	if bridgeName == "" {
		logx.With("component", "network_monitor").Warn("no bridge interface found")
		return monitor
	}

	// 启动 tcpdump
	pcapFile := fmt.Sprintf("/tmp/sandbox-net-%d.pcap", time.Now().UnixNano())
	monitor.pcapFile = pcapFile

	go func() {
		// tcpdump 已通过 setcap 赋予权限，无需 sudo
		cmd := exec.CommandContext(ctx, "tcpdump", "-i", bridgeName, "-w", pcapFile, "-n", "-s", "0")
		cmd.SysProcAttr = setPgid()
		if err := cmd.Start(); err != nil {
			logx.With("component", "network_monitor").Warn("tcpdump failed", "error", err.Error())
			return
		}
		logx.With("component", "network_monitor").Info("tcpdump started", "interface", bridgeName, "pcap", pcapFile)

		// 等待 context 结束
		<-ctx.Done()
		if cmd.Process != nil {
			// 发送 SIGINT 让 tcpdump 优雅退出（刷新缓冲区写入文件）
			cmd.Process.Signal(syscall.SIGINT)
			time.Sleep(1 * time.Second)
			// 如果还没退出，强制杀死
			cmd.Process.Kill()
		}
	}()

	return monitor
}

// collectNetworkResult 收集网络监控结果
func (m *networkMonitor) collectNetworkResult(ctx context.Context) *networkResult {
	result := &networkResult{
		PcapFile: m.pcapFile,
	}

	// 1. 从 pcap 解析 DNS 查询
	result.DNSQueries = m.parseDNSFromPcap(ctx)

	// 2. 从 pcap 解析 TCP 连接
	result.TCPConnections = m.parseTCPFromPcap(ctx)

	// 3. 从容器内解析 /proc/net/tcp
	result.TCPConnections = append(result.TCPConnections, m.parseProcNetTCP(ctx)...)

	// 4. 收集所有外联目标
	result.OutboundTargets = m.collectOutboundTargets(result)

	return result
}

// parseDNSFromPcap 从 pcap 解析 DNS 查询
func (m *networkMonitor) parseDNSFromPcap(ctx context.Context) []DNSEvent {
	if m.pcapFile == "" {
		return nil
	}

	var events []DNSEvent
	cmd := exec.Command("tcpdump", "-r", m.pcapFile, "-n", "port 53", "-l")
	out, _ := cmd.CombinedOutput()

	dnsRe := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+):\s+(\d+)\+\s+(\w+)\?\s+(\S+)`)

	for _, line := range strings.Split(string(out), "\n") {
		if m := dnsRe.FindStringSubmatch(line); m != nil {
			events = append(events, DNSEvent{
				Server: m[2],
				Type:   m[4],
				Domain: strings.TrimSuffix(m[5], "."),
			})
		}
	}

	return events
}

// parseTCPFromPcap 从 pcap 解析 TCP 连接
func (m *networkMonitor) parseTCPFromPcap(ctx context.Context) []TCPEvent {
	if m.pcapFile == "" {
		return nil
	}

	var events []TCPEvent
	cmd := exec.Command("tcpdump", "-r", m.pcapFile, "-n", "tcp", "-l")
	out, _ := cmd.CombinedOutput()

	tcpRe := regexp.MustCompile(`IP\s+(\d+\.\d+\.\d+\.\d+)\.(\d+)\s+>\s+(\d+\.\d+\.\d+\.\d+)\.(\d+):`)

	for _, line := range strings.Split(string(out), "\n") {
		if m := tcpRe.FindStringSubmatch(line); m != nil {
			events = append(events, TCPEvent{
				Local:  fmt.Sprintf("%s:%s", m[1], m[2]),
				Remote: fmt.Sprintf("%s:%s", m[3], m[4]),
			})
		}
	}

	return events
}

// parseProcNetTCP 从容器内读取 /proc/net/tcp
func (m *networkMonitor) parseProcNetTCP(ctx context.Context) []TCPEvent {
	var events []TCPEvent

	cmd := exec.CommandContext(ctx, "docker", "exec", "--user", "analyst", m.containerName,
		"/bin/bash", "-c", "cat /proc/net/tcp 2>/dev/null || echo ''")
	out, _ := cmd.CombinedOutput()

	for _, line := range strings.Split(string(out), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 || fields[0] == "sl" {
			continue
		}
		state := fields[3]
		if state == "01" { // ESTABLISHED
			local := parseNetTCPAddr(fields[1])
			remote := parseNetTCPAddr(fields[2])
			events = append(events, TCPEvent{
				Local:  local,
				Remote: remote,
				State:  "ESTABLISHED",
			})
		}
	}

	return events
}

// parseNetTCPAddr 解析 /proc/net/tcp 地址
func parseNetTCPAddr(hex string) string {
	parts := strings.Split(hex, ":")
	if len(parts) != 2 {
		return hex
	}
	// 解析 IP（小端序）
	ipHex := parts[0]
	portHex := parts[1]

	var a, b, c, d byte
	fmt.Sscanf(ipHex, "%02x%02x%02x%02x", &d, &c, &b, &a)
	var port int
	fmt.Sscanf(portHex, "%x", &port)

	return fmt.Sprintf("%d.%d.%d.%d:%d", a, b, c, d, port)
}

// collectOutboundTargets 收集所有外联目标
func (m *networkMonitor) collectOutboundTargets(result *networkResult) []OutboundTarget {
	var targets []OutboundTarget
	seen := make(map[string]bool)

	// 从 DNS 查询提取域名
	for _, dns := range result.DNSQueries {
		key := "domain:" + dns.Domain
		if !seen[key] {
			seen[key] = true
			targets = append(targets, OutboundTarget{
				Type:   "domain",
				Value:  dns.Domain,
				Source: "dns",
			})
		}
	}

	// 从 TCP 连接提取 IP
	for _, tcp := range result.TCPConnections {
		parts := strings.Split(tcp.Remote, ":")
		if len(parts) == 2 {
			ip := parts[0]
			port := 0
			fmt.Sscanf(parts[1], "%d", &port)
			key := fmt.Sprintf("ip:%s:%d", ip, port)
			if !seen[key] && ip != "0.0.0.0" {
				seen[key] = true
				targets = append(targets, OutboundTarget{
					Type:   "ip",
					Value:  ip,
					Port:   port,
					Source: "tcp",
				})
			}
		}
	}

	return targets
}

// formatNetworkReport 格式化网络报告
func formatNetworkReport(result *networkResult) string {
	var lines []string

	if len(result.DNSQueries) > 0 {
		lines = append(lines, "DNS 查询:")
		for _, dns := range result.DNSQueries {
			lines = append(lines, fmt.Sprintf("  %s [%s] → %s", dns.Domain, dns.Type, dns.Server))
		}
	}

	if len(result.TCPConnections) > 0 {
		lines = append(lines, "TCP 连接:")
		for _, tcp := range result.TCPConnections {
			lines = append(lines, fmt.Sprintf("  %s → %s [%s]", tcp.Local, tcp.Remote, tcp.State))
		}
	}

	if len(result.OutboundTargets) > 0 {
		lines = append(lines, "外联目标:")
		for _, t := range result.OutboundTargets {
			portStr := ""
			if t.Port > 0 {
				portStr = fmt.Sprintf(":%d", t.Port)
			}
			lines = append(lines, fmt.Sprintf("  [%s] %s%s (来源: %s)", t.Type, t.Value, portStr, t.Source))
		}
	}

	return strings.Join(lines, "\n")
}

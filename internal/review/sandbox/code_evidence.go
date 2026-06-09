package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// CodeEvidence 代码级证据：具体到文件、行号、代码内容
type CodeEvidence struct {
	File       string `json:"file"`        // 文件路径
	Line       int    `json:"line"`        // 行号
	Code       string `json:"code"`        // 代码内容
	Behavior   string `json:"behavior"`    // 触发的行为类型
	Detail     string `json:"detail"`      // 详细描述
	SyscallPID int    `json:"syscall_pid"` // 触发该行为的进程 PID
}

// CollectCodeEvidence 从 strace 结果和技能源码中提取代码级证据。
// 原理：strace 记录了哪些进程(PID)执行了哪些系统调用，
// 通过 execve 可以知道每个 PID 运行的是哪个脚本，
// 再通过文件操作和网络操作关联到具体的代码行。
func CollectCodeEvidence(skillPath string, strace *straceResult, net *networkResult) []CodeEvidence {
	var evidence []CodeEvidence

	// 构建 PID → 命令 映射
	pidCommand := make(map[int]string)
	if strace != nil {
		for _, proc := range strace.ProcessOps {
			if proc.Command != "" {
				pidCommand[proc.PID] = proc.Command
			}
		}
	}

	// 读取技能源码文件，用于代码行匹配
	sourceFiles := readSourceFiles(skillPath)

	// 1. 从 strace 网络操作提取证据（有 PID，可关联到具体进程）
	if strace != nil {
		for _, nop := range strace.NetOps {
			// 过滤无害的本地网络通信
			if isBenignLocalNet(nop.Addr, nop.Port) {
				continue
			}

			cmd := pidCommand[nop.PID]
			if cmd == "" {
				cmd = fmt.Sprintf("PID %d", nop.PID)
			}

			behavior := classifyNetworkBehavior(nop)
			code := findCodeForNetworkOp(sourceFiles, nop.Addr, nop.Port)
			evidence = append(evidence, CodeEvidence{
				File:       code.File,
				Line:       code.Line,
				Code:       code.Code,
				Behavior:   behavior,
				Detail:     fmt.Sprintf("进程 %s %s %s %s:%d", cmd, nop.Op, nop.Protocol, nop.Addr, nop.Port),
				SyscallPID: nop.PID,
			})
		}
	}

	// 2. 从网络监控补充（tcpdump 捕获的实际流量，用于补充 strace 未覆盖的）
	if net != nil {
		for _, target := range net.OutboundTargets {
			if isBenignLocalNet(target.Value, target.Port) {
				continue
			}
			code := findCodeForNetworkOp(sourceFiles, target.Value, target.Port)
			evidence = append(evidence, CodeEvidence{
				File:     code.File,
				Line:     code.Line,
				Code:     code.Code,
				Behavior: "网络流量",
				Detail:   fmt.Sprintf("tcpdump 捕获到 %s %s:%d", target.Source, target.Value, target.Port),
			})
		}
	}

	// 2. 从文件操作提取证据
	if strace != nil {
		for _, fop := range strace.FileOps {
			cmd := pidCommand[fop.PID]
			if cmd == "" {
				cmd = fmt.Sprintf("PID %d", fop.PID)
			}

			// 关注高风险文件操作
			behavior := ""
			switch fop.Op {
			case "write", "create":
				if isSuspiciousFilePath(fop.Path) {
					behavior = "可疑文件写入"
				}
			case "unlink", "rename":
				if isSuspiciousFilePath(fop.Path) {
					behavior = "可疑文件删除/重命名"
				}
			case "chmod":
				behavior = "权限变更"
			}

			if behavior != "" {
				code := findCodeForFileOp(sourceFiles, fop.Path, fop.Op)
				evidence = append(evidence, CodeEvidence{
					File:       code.File,
					Line:       code.Line,
					Code:       code.Code,
					Behavior:   behavior,
					Detail:     fmt.Sprintf("进程 %s 对 %s 执行 %s", cmd, fop.Path, fop.Op),
					SyscallPID: fop.PID,
				})
			}
		}

		// 3. 从进程创建提取证据
		for _, proc := range strace.ProcessOps {
			if proc.Op == "execve" && proc.Command != "" {
				cmd := proc.Command
				// 检查是否执行了可疑命令
				if isSuspiciousCommand(cmd) {
					code := findCodeForCommand(sourceFiles, cmd)
					evidence = append(evidence, CodeEvidence{
						File:       code.File,
						Line:       code.Line,
						Code:       code.Code,
						Behavior:   "可疑命令执行",
						Detail:     fmt.Sprintf("PID %d 执行: %s", proc.PID, cmd),
						SyscallPID: proc.PID,
					})
				}
			}
		}
	}

	// 去重并按文件和行号排序
	evidence = deduplicateEvidence(evidence)
	sort.Slice(evidence, func(i, j int) bool {
		if evidence[i].File != evidence[j].File {
			return evidence[i].File < evidence[j].File
		}
		return evidence[i].Line < evidence[j].Line
	})

	return evidence
}

// sourceFile 缓存的源码文件内容
type sourceFile struct {
	path  string
	lines []string
}

// readSourceFiles 读取技能目录中的所有源码文件
func readSourceFiles(skillPath string) []sourceFile {
	extensions := map[string]bool{
		".py": true, ".js": true, ".mjs": true, ".ts": true,
		".sh": true, ".bash": true, ".java": true, ".go": true,
		".rb": true, ".pl": true, ".php": true, ".lua": true,
		".rs": true, ".c": true, ".cpp": true, ".h": true,
		".r": true, ".R": true, ".scala": true, ".kt": true,
	}

	var files []sourceFile
	filepath.Walk(skillPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || info.Size() > 100000 {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if !extensions[ext] {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		relPath, _ := filepath.Rel(skillPath, path)
		files = append(files, sourceFile{
			path:  relPath,
			lines: strings.Split(string(data), "\n"),
		})
		return nil
	})
	return files
}

// codeMatch 代码匹配结果
type codeMatch struct {
	File string
	Line int
	Code string
}

// findCodeForNetworkOp 在源码中查找发起网络连接的代码
func findCodeForNetworkOp(files []sourceFile, host string, port int) codeMatch {
	keywords := []string{host, fmt.Sprintf(":%d", port), "connect", "urllib", "requests", "fetch", "http", "socket", "axios"}
	return findCodeWithKeywords(files, keywords)
}

// findCodeForDNSOp 在源码中查找 DNS 查询相关代码
func findCodeForDNSOp(files []sourceFile, domain string) codeMatch {
	keywords := []string{domain, "dns", "resolve", "getaddrinfo", "nslookup"}
	return findCodeWithKeywords(files, keywords)
}

// findCodeForHTTPOp 在源码中查找 HTTP 请求相关代码
func findCodeForHTTPOp(files []sourceFile, method, host, url string) codeMatch {
	keywords := []string{host, url, strings.ToLower(method), "request", "fetch", "curl", "wget", "http", "urlopen"}
	return findCodeWithKeywords(files, keywords)
}

// findCodeForFileOp 在源码中查找文件操作相关代码
func findCodeForFileOp(files []sourceFile, path, op string) codeMatch {
	// 提取文件名作为关键词
	base := filepath.Base(path)
	keywords := []string{base, op, "write", "open", "encrypt", "base64", "rename", "remove", "unlink", "chmod"}
	// 如果是 .encrypted 后缀，关键词更精确
	if strings.HasSuffix(path, ".encrypted") {
		keywords = append([]string{".encrypted", "encrypt", "base64", path}, keywords...)
	}
	return findCodeWithKeywords(files, keywords)
}

// findCodeForCommand 在源码中查找执行特定命令的代码
func findCodeForCommand(files []sourceFile, cmd string) codeMatch {
	keywords := []string{cmd, "subprocess", "exec", "system", "os.popen", "child_process", "Runtime.exec"}
	return findCodeWithKeywords(files, keywords)
}

// findCodeWithKeywords 在源码中查找包含关键词的代码行
func findCodeWithKeywords(files []sourceFile, keywords []string) codeMatch {
	for _, f := range files {
		for lineNum, line := range f.lines {
			lower := strings.ToLower(line)
			for _, kw := range keywords {
				if strings.Contains(lower, strings.ToLower(kw)) {
					// 返回包含关键词的代码行及其上下文（前后各 1 行）
					code := extractCodeContext(f.lines, lineNum)
					return codeMatch{
						File: f.path,
						Line: lineNum + 1,
						Code: code,
					}
				}
			}
		}
	}
	return codeMatch{}
}

// extractCodeContext 提取代码行及其上下文
func extractCodeContext(lines []string, center int) string {
	start := center - 1
	if start < 0 {
		start = 0
	}
	end := center + 2
	if end > len(lines) {
		end = len(lines)
	}
	var context []string
	for i := start; i < end; i++ {
		prefix := "  "
		if i == center {
			prefix = "→ "
		}
		context = append(context, fmt.Sprintf("%s%d: %s", prefix, i+1, lines[i]))
	}
	return strings.Join(context, "\n")
}

// ReviewCodeEvidenceWithLLM 将网络行为证据提交给 LLM 复核，过滤误报。
// LLM 会综合考虑技能描述、源码上下文和网络行为，判断哪些是正常行为。
// 返回过滤后的证据列表（只保留 LLM 认为真正可疑的）。
func ReviewCodeEvidenceWithLLM(ctx context.Context, client llmClient, skillName string, skillInfo string, evidence []CodeEvidence) []CodeEvidence {
	if len(evidence) == 0 || client == nil {
		return evidence
	}

	// 构建复核 prompt
	prompt := buildEvidenceReviewPrompt(skillName, skillInfo, evidence)

	response, err := client.Complete(ctx, evidenceReviewSystemPrompt(), prompt)
	if err != nil {
		// LLM 调用失败，返回原始证据（不丢弃）
		return evidence
	}

	// 解析 LLM 返回的保留索引
	keepIndices := parseEvidenceReviewResponse(response, len(evidence))
	if len(keepIndices) == 0 {
		// 解析失败，返回原始证据
		return evidence
	}

	var reviewed []CodeEvidence
	for _, idx := range keepIndices {
		if idx >= 0 && idx < len(evidence) {
			reviewed = append(reviewed, evidence[idx])
		}
	}
	return reviewed
}

// evidenceReviewSystemPrompt 返回证据复核的系统 prompt
func evidenceReviewSystemPrompt() string {
	return `你是一名安全分析师。你的任务是审查网络行为证据，判断哪些是真正的安全风险。

判断标准：
- 连接到包管理器（pypi.org、npmjs.org、crates.io、maven central 等）是正常行为
- 连接到代码托管平台（github.com、gitlab.com 等下载依赖）是正常行为
- 连接到 localhost/127.0.0.1 上的数据库（Redis 6379、MySQL 3306、PostgreSQL 5432）是正常行为
- 连接到云服务 API（AWS、Azure、GCP 的已知端点）可能是正常行为
- 连接到未知域名的高端口（4444、5555 等）是可疑行为
- 大量数据外发到未知服务器是可疑行为
- 连接到已知 C2/恶意基础设施是高风险行为
- 与技能声明功能无关的网络行为是可疑行为

输出格式：
对于每条证据，输出 KEEP（保留，认为可疑）或 SKIP（跳过，认为正常），每行一个，按证据编号顺序。
示例：
SKIP
KEEP
SKIP
KEEP`
}

// buildEvidenceReviewPrompt 构建证据复核 prompt
func buildEvidenceReviewPrompt(skillName string, skillInfo string, evidence []CodeEvidence) string {
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("技能名称: %s\n\n", skillName))
	sb.WriteString(fmt.Sprintf("技能描述:\n%s\n\n", skillInfo))
	sb.WriteString("以下是在该技能运行过程中观察到的网络行为证据：\n\n")

	for i, e := range evidence {
		sb.WriteString(fmt.Sprintf("【证据 %d】\n", i+1))
		sb.WriteString(fmt.Sprintf("  行为: %s\n", e.Behavior))
		sb.WriteString(fmt.Sprintf("  详情: %s\n", e.Detail))
		if e.File != "" {
			sb.WriteString(fmt.Sprintf("  文件: %s (第 %d 行)\n", e.File, e.Line))
		}
		if e.Code != "" {
			sb.WriteString(fmt.Sprintf("  代码:\n%s\n", e.Code))
		}
		sb.WriteString("\n")
	}

	sb.WriteString("请逐一判断每条证据是 SKIP（正常行为）还是 KEEP（需要关注的风险行为）。每行输出一个 SKIP 或 KEEP，按编号顺序。")
	return sb.String()
}

// parseEvidenceReviewResponse 解析 LLM 的复核响应，返回应保留的证据索引
func parseEvidenceReviewResponse(response string, totalEvidence int) []int {
	lines := strings.Split(strings.TrimSpace(response), "\n")
	var keepIndices []int
	for i, line := range lines {
		if i >= totalEvidence {
			break
		}
		trimmed := strings.ToUpper(strings.TrimSpace(line))
		// 去掉可能的编号前缀（如 "1. KEEP" 或 "- KEEP"）
		if idx := strings.Index(trimmed, "KEEP"); idx >= 0 {
			trimmed = "KEEP"
		} else if idx := strings.Index(trimmed, "SKIP"); idx >= 0 {
			trimmed = "SKIP"
		}

		if trimmed == "KEEP" {
			keepIndices = append(keepIndices, i)
		}
		// SKIP 的不加入列表
	}
	return keepIndices
}

// isBenignLocalNet 判断本地网络连接是否属于正常行为
// 返回 true 表示无害，应跳过；返回 false 表示需要关注
func isBenignLocalNet(addr string, port int) bool {
	// Docker 内部 DNS（127.0.0.11:53）
	if addr == "127.0.0.11" && port == 53 {
		return true
	}
	// 本地回环的 DNS 查询（127.0.0.1:53 或 127.0.0.53:53）
	if (addr == "127.0.0.1" || addr == "127.0.0.53") && port == 53 {
		return true
	}
	// nscd socket（名称服务缓存）
	if addr == "/var/run/nscd/socket" {
		return true
	}
	return false
}

// classifyNetworkBehavior 根据网络操作特征分类行为风险
func classifyNetworkBehavior(nop NetOperation) string {
	addr := nop.Addr
	port := nop.Port

	// 本地回环上的监听/连接
	if isLocalhost(addr) {
		// 高端口本地监听 — 可能是本地服务，低风险
		if nop.Op == "bind" || nop.Op == "listen" {
			return "本地监听"
		}
		// 本地回环上的大量数据传输 — 可能是本地代理/隧道
		if nop.Op == "sendto" || nop.Op == "sendmsg" {
			return "本地数据传输"
		}
		return "本地连接"
	}

	// 外部网络连接
	if nop.Op == "connect" {
		// 已知端口分类
		switch port {
		case 443:
			return "HTTPS外联"
		case 80, 8080, 8000, 3000, 5000:
			return "HTTP外联"
		case 4444, 5555, 6666, 7777, 8888, 9999:
			return "可疑端口外联（常见后门端口）"
		case 22:
			return "SSH外联"
		case 21:
			return "FTP外联"
		case 25, 465, 587:
			return "SMTP外联（邮件）"
		default:
			return "外联"
		}
	}

	if nop.Op == "sendto" || nop.Op == "sendmsg" {
		return "外发数据"
	}

	return "网络连接"
}

// isLocalhost 判断地址是否为本地回环
func isLocalhost(addr string) bool {
	return addr == "127.0.0.1" || addr == "::1" || addr == "localhost" ||
		addr == "127.0.0.11" || addr == "127.0.0.53" ||
		strings.HasPrefix(addr, "127.")
}

// isSuspiciousFilePath 判断文件路径是否可疑
func isSuspiciousFilePath(path string) bool {
	lower := strings.ToLower(path)
	suspicious := []string{
		".encrypted", ".locked", ".crypto", ".enc",
		"/etc/passwd", "/etc/shadow", "/root/",
		".ssh/", ".gnupg/", ".aws/", ".env",
		"password", "secret", "token", "key",
	}
	for _, s := range suspicious {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// isSuspiciousCommand 判断命令是否可疑
func isSuspiciousCommand(cmd string) bool {
	lower := strings.ToLower(cmd)
	suspicious := []string{
		"curl", "wget", "nc", "ncat", "netcat",
		"chmod 777", "chown root",
		"rm -rf /", "mkfs", "dd if=",
		"iptables", "nmap",
		"python -c", "python3 -c", "node -e",
		"base64", "openssl enc",
	}
	for _, s := range suspicious {
		if strings.Contains(lower, s) {
			return true
		}
	}
	return false
}

// deduplicateEvidence 去重证据
func deduplicateEvidence(evidence []CodeEvidence) []CodeEvidence {
	seen := make(map[string]bool)
	var result []CodeEvidence
	for _, e := range evidence {
		key := fmt.Sprintf("%s:%d:%s", e.File, e.Line, e.Behavior)
		if !seen[key] {
			seen[key] = true
			result = append(result, e)
		}
	}
	return result
}

package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"skill-scanner/internal/review"
)

type Runner struct{}

var dockerInfoFormatRunner = runDockerInfoFormatCommand

type dockerRuntimeCheck struct {
	Name     string
	Runtimes []string
	Default  string
	Message  string
}

type ExecuteOptions struct {
	DifferentialEnabled bool
	DelayThresholdSecs  int
}

type probeReport struct {
	FileCount          int      `json:"file_count"`
	Samples            []string `json:"samples"`
	DownloadIOCs       []string `json:"download_iocs"`
	DropIOCs           []string `json:"drop_iocs"`
	ExecuteIOCs        []string `json:"execute_iocs"`
	OutboundIOCs       []string `json:"outbound_iocs"`
	PersistenceIOCs    []string `json:"persistence_iocs"`
	PrivEscIOCs        []string `json:"priv_esc_iocs"`
	CredentialIOCs     []string `json:"credential_iocs"`
	DefenseEvasionIOCs []string `json:"defense_evasion_iocs"`
	LateralMoveIOCs    []string `json:"lateral_move_iocs"`
	CollectionIOCs     []string `json:"collection_iocs"`
	C2BeaconIOCs       []string `json:"c2_beacon_iocs"`
	ProbeWarnings      []string `json:"probe_warnings"`
}

func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) Prepare() error {
	if strings.EqualFold(strings.TrimSpace(os.Getenv("REVIEW_ENABLE_SANDBOX")), "false") {
		return fmt.Errorf("sandbox 功能未启用，请检查 REVIEW_ENABLE_SANDBOX")
	}

	runtime := strings.ToLower(strings.TrimSpace(os.Getenv("REVIEW_SANDBOX_RUNTIME")))
	if runtime == "" {
		runtime = "gvisor"
	}

	bin := ""
	switch runtime {
	case "gvisor":
		bin = "runsc"
	case "firecracker":
		bin = "firecracker"
	case "nsjail":
		bin = "nsjail"
	default:
		return fmt.Errorf("不支持的 sandbox runtime: %s", runtime)
	}

	if _, err := exec.LookPath(bin); err != nil {
		return fmt.Errorf("sandbox runtime %s 不可用，请检查 %s", runtime, bin)
	}

	if strings.EqualFold(readSandboxExecMode(), "container") {
		if runtime != "gvisor" {
			return fmt.Errorf("container 执行模式当前仅支持 gvisor runtime")
		}
		if _, err := exec.LookPath("docker"); err != nil {
			return fmt.Errorf("container 执行模式需要 docker，请先安装并加入 PATH")
		}
		dockerRuntime, err := resolveDockerRuntime(runtime)
		if err != nil {
			return err
		}
		image := readSandboxImage()
		inspect := exec.Command("docker", "image", "inspect", image)
		if out, err := inspect.CombinedOutput(); err != nil {
			return fmt.Errorf("未找到沙箱镜像 %s，请先执行 docker load -i <skill-sandbox.tar>；详情: %s", image, strings.TrimSpace(string(out)))
		}
		if dockerRuntime.Name != "" {
			probeArgs := []string{"run", "--rm", "--runtime=" + dockerRuntime.Name, "--network=none", image, "/bin/sh", "-lc", "true"}
			probe := exec.Command("docker", probeArgs...)
			if out, err := probe.CombinedOutput(); err != nil {
				return fmt.Errorf("Docker 未能使用 sandbox runtime %s 启动容器，请将 gVisor 注册到 Docker daemon，或设置 REVIEW_SANDBOX_DOCKER_RUNTIME 为实际 runtime 名称；详情: %s", dockerRuntime.Name, strings.TrimSpace(string(out)))
			}
		}
	}
	return nil
}

func (r *Runner) Execute(scanPath string, opts ExecuteOptions) (review.BehaviorProfile, []string, error) {
	opts = normalizeExecuteOptions(opts)
	profile := review.BehaviorProfile{}
	iocSet := make(map[string]struct{})
	evasionSet := make(map[string]struct{})
	downloadSet := make(map[string]struct{})
	dropSet := make(map[string]struct{})
	executeSet := make(map[string]struct{})
	outboundSet := make(map[string]struct{})
	persistenceSet := make(map[string]struct{})
	privEscSet := make(map[string]struct{})
	credentialSet := make(map[string]struct{})
	defenseEvasionSet := make(map[string]struct{})
	lateralMoveSet := make(map[string]struct{})
	collectionSet := make(map[string]struct{})
	c2BeaconSet := make(map[string]struct{})

	if strings.EqualFold(readSandboxExecMode(), "container") {
		rep, err := r.runContainerProbe(scanPath)
		if err != nil {
			return profile, nil, err
		}
		profile.ExecTargets = append(profile.ExecTargets, fmt.Sprintf("[sandbox] 隔离容器探针执行完成，扫描文件数=%d", rep.FileCount))
		mergeProbeEvidence(downloadSet, rep.DownloadIOCs)
		mergeProbeEvidence(dropSet, rep.DropIOCs)
		mergeProbeEvidence(executeSet, rep.ExecuteIOCs)
		mergeProbeEvidence(outboundSet, rep.OutboundIOCs)
		mergeProbeEvidence(persistenceSet, rep.PersistenceIOCs)
		mergeProbeEvidence(privEscSet, rep.PrivEscIOCs)
		mergeProbeEvidence(credentialSet, rep.CredentialIOCs)
		mergeProbeEvidence(defenseEvasionSet, rep.DefenseEvasionIOCs)
		mergeProbeEvidence(lateralMoveSet, rep.LateralMoveIOCs)
		mergeProbeEvidence(collectionSet, rep.CollectionIOCs)
		mergeProbeEvidence(c2BeaconSet, rep.C2BeaconIOCs)
		if len(rep.ProbeWarnings) > 0 {
			profile.ProbeWarnings = append(profile.ProbeWarnings, rep.ProbeWarnings...)
			profile.ExecTargets = append(profile.ExecTargets, "[sandbox] 探针告警: "+strings.Join(rep.ProbeWarnings, "；"))
		}
		profile.ExecTargets = append(profile.ExecTargets,
			fmt.Sprintf("[sandbox] 行为证据提取: 下载=%d, 落地=%d, 执行=%d, 外联=%d, 持久化=%d, 提权=%d, 凭据访问=%d, 防御规避=%d, 横向移动=%d, 收集打包=%d, C2信标=%d", len(rep.DownloadIOCs), len(rep.DropIOCs), len(rep.ExecuteIOCs), len(rep.OutboundIOCs), len(rep.PersistenceIOCs), len(rep.PrivEscIOCs), len(rep.CredentialIOCs), len(rep.DefenseEvasionIOCs), len(rep.LateralMoveIOCs), len(rep.CollectionIOCs), len(rep.C2BeaconIOCs)),
		)
	}

	urlRe := regexp.MustCompile(`https?://[A-Za-z0-9._:/?=&%-]+`)
	ipRe := regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	cmdRe := regexp.MustCompile(`\b(exec\.Command|os\.RemoveAll|syscall\.Exec|subprocess\.Popen|child_process)\b`)
	downloadCmdRe := regexp.MustCompile(`(?i)\b(curl\s+|wget\s+|invoke-webrequest\b|http\.get\b|requests\.get\b|urllib\.request\.urlretrieve\b|fetch\(|axios\.get\b|got\.get\b|request\.get\b)`)
	fileDropRe := regexp.MustCompile(`(?i)\b(os\.writefile|ioutil\.writefile|writefile\(|fopen\([^\)]*,\s*"w|open\([^\)]*,\s*"w|chmod\s+\+x|chmod\()`)
	outboundCallRe := regexp.MustCompile(`(?i)\b(http\.(post|get|newrequest)\b|net\.dial\b|websocket|grpc\.|axios\.|requests\.(post|get)|urllib\.request\.|fetch\(|got\.|request\.|socket\.|httpclient|http\.client|urlopen\b)`)
	persistenceRe := regexp.MustCompile(`(?i)\b(crontab\b|/etc/cron\.|systemctl\s+enable\b|startup|autorun|runonce|schtasks\b|launchctl\b|~/.bashrc|~/.profile|/etc/profile)`)
	privEscRe := regexp.MustCompile(`(?i)\b(sudo\b|setuid\b|setcap\b|chmod\s+4777\b|chmod\s+777\b|token::elevate|SeDebugPrivilege|runas\b)`)
	credentialPathRe := regexp.MustCompile(`(?i)(/etc/shadow|/root/\.netrc|~/.ssh|id_rsa|credentials?\.(json|ya?ml)|\.env\b|secret_access_key|aws_access_key_id|authorization:)`)
	credentialAccessRe := regexp.MustCompile(`(?i)(os\.environ|getenv\(|os\.getenv\(|process\.env|readfile|read_text\(|open\()`)
	credentialSecretRe := regexp.MustCompile(`(?i)(token|secret|password|api[_-]?key|credential|auth)`)
	defenseEvasionRe := regexp.MustCompile(`(?i)\b(disable(defender|security)|set-mppreference|kill\s+-9\s+(auditd|falco)|history\s+-c|wevtutil\s+cl\b|auditctl\s+-D\b|iptables\s+-F\b)`)
	lateralMoveRe := regexp.MustCompile(`(?i)\b(ssh\s+[^\n]*@|scp\s+|psexec\b|wmic\s+/node|winrm\b|net\s+use\\\\|smbclient\b|mstsc\b|rdp\b)`)
	collectionRe := regexp.MustCompile(`(?i)\b(zip\s+-r\b|tar\s+-czf\b|7z\s+a\b|rar\s+a\b|find\s+/\b|dir\s+/s\b|ls\s+-la\b|cat\s+/etc/passwd\b|db dump|mysqldump\b|pg_dump\b)`)
	c2BeaconRe := regexp.MustCompile(`(?i)(beacon\b|heartbeat\b|callback\b|polling\b|sleep\([^\)]{0,12}\)|/api/checkin|/api/beacon|\bc2\b|command-and-control)`)
	delayPattern := regexp.MustCompile(`(?i)(?:time\.)?sleep\((\d+)\)`)
	evasionPatterns := []struct {
		re   *regexp.Regexp
		tag  string
		desc string
	}{
		{regexp.MustCompile(`(?i)\.dockerenv|/proc/1/cgroup|docker`), "V7-008-DOCKER", "检测容器环境指纹"},
		{regexp.MustCompile(`(?i)systemd-detect-virt|dmidecode|hypervisor|qemu|vbox|vmware`), "V7-008-VM", "检测虚拟机环境指纹"},
		{regexp.MustCompile(`(?i)cpuid|rdtsc|isdebuggerpresent|ptrace|unshare|capset|/proc/self/ns|mount|setuid|setgid`), "V7-008-EVASION", "检测调试、分析环境、命名空间或提权相关行为"},
	}

	_ = filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		if !isSandboxSignalFile(path) {
			return nil
		}
		f, openErr := os.Open(path)
		if openErr != nil {
			return nil
		}
		defer f.Close()

		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		lineNo := 0
		for scanner.Scan() {
			lineNo++
			line := scanner.Text()
			trimmedLine := strings.TrimSpace(line)
			if trimmedLine == "" || isSandboxCommentLikeLine(trimmedLine) {
				continue
			}
			lowerLine := strings.ToLower(line)
			for _, m := range urlRe.FindAllString(line, -1) {
				iocSet[m] = struct{}{}
				profile.NetworkTargets = append(profile.NetworkTargets, m)
				appendEvidence(outboundSet, path, lineNo, m)
			}
			for _, m := range ipRe.FindAllString(line, -1) {
				iocSet[m] = struct{}{}
				profile.NetworkTargets = append(profile.NetworkTargets, m)
				appendEvidence(outboundSet, path, lineNo, m)
			}
			if strings.Contains(line, "open(") || strings.Contains(line, "os.ReadFile") || strings.Contains(line, "os.WriteFile") {
				profile.FileTargets = append(profile.FileTargets, path)
			}
			if cmdRe.MatchString(line) {
				profile.ExecTargets = append(profile.ExecTargets, line)
				appendEvidence(executeSet, path, lineNo, line)
			}
			if downloadCmdRe.MatchString(line) {
				appendEvidence(downloadSet, path, lineNo, line)
			}
			if fileDropRe.MatchString(line) {
				appendEvidence(dropSet, path, lineNo, line)
			}
			if outboundCallRe.MatchString(line) {
				appendEvidence(outboundSet, path, lineNo, line)
			}
			if persistenceRe.MatchString(line) {
				appendEvidence(persistenceSet, path, lineNo, line)
			}
			if privEscRe.MatchString(line) {
				appendEvidence(privEscSet, path, lineNo, line)
			}
			if credentialPathRe.MatchString(line) || (credentialAccessRe.MatchString(line) && credentialSecretRe.MatchString(line)) {
				appendEvidence(credentialSet, path, lineNo, line)
			}
			if defenseEvasionRe.MatchString(line) {
				appendEvidence(defenseEvasionSet, path, lineNo, line)
			}
			if lateralMoveRe.MatchString(line) {
				appendEvidence(lateralMoveSet, path, lineNo, line)
			}
			if collectionRe.MatchString(line) {
				appendEvidence(collectionSet, path, lineNo, line)
			}
			if c2BeaconRe.MatchString(line) {
				appendEvidence(c2BeaconSet, path, lineNo, line)
			}

			for _, p := range evasionPatterns {
				if p.re.MatchString(line) {
					evasionSet[p.tag+": "+p.desc] = struct{}{}
				}
			}

			if hit, seconds := detectDelayEvasion(delayPattern, line, opts.DelayThresholdSecs); hit {
				evasionSet[fmt.Sprintf("V7-008-DELAY: 检测长延时反分析逻辑（阈值 %ds，命中 %ds）", opts.DelayThresholdSecs, seconds)] = struct{}{}
			}

			if (strings.Contains(lowerLine, "if") || strings.Contains(lowerLine, "switch")) &&
				(strings.Contains(lowerLine, "docker") || strings.Contains(lowerLine, "vm") || strings.Contains(lowerLine, "sandbox")) &&
				(strings.Contains(lowerLine, "exec") || strings.Contains(lowerLine, "powershell") || strings.Contains(lowerLine, "curl") || strings.Contains(lowerLine, "wget")) {
				evasionSet["V7-008-BEHAVIOR: 条件分支中存在环境识别与危险执行组合"] = struct{}{}
			}
		}
		return nil
	})

	if len(evasionSet) > 0 {
		profile.EvasionSignals = mapSetKeys(evasionSet)
	}
	profile.DownloadIOCs = mapSetKeys(downloadSet)
	profile.DropIOCs = mapSetKeys(dropSet)
	profile.ExecuteIOCs = mapSetKeys(executeSet)
	profile.OutboundIOCs = mapSetKeys(outboundSet)
	profile.PersistenceIOCs = mapSetKeys(persistenceSet)
	profile.PrivEscIOCs = mapSetKeys(privEscSet)
	profile.CredentialIOCs = mapSetKeys(credentialSet)
	profile.DefenseEvasionIOCs = mapSetKeys(defenseEvasionSet)
	profile.LateralMoveIOCs = mapSetKeys(lateralMoveSet)
	profile.CollectionIOCs = mapSetKeys(collectionSet)
	profile.C2BeaconIOCs = mapSetKeys(c2BeaconSet)
	segments := collectBehaviorSegments(downloadSet, dropSet, executeSet, outboundSet, persistenceSet, privEscSet, credentialSet, defenseEvasionSet, lateralMoveSet, collectionSet, c2BeaconSet)
	profile.BehaviorChains = buildBehaviorChainsFromSegments(segments)
	profile.BehaviorTimelines = buildBehaviorTimelinesFromSegments(segments)
	profile.SequenceAlerts = buildSequenceAlerts(segments)
	if opts.DifferentialEnabled {
		profile.Differentials = buildDifferentialProbes(profile.EvasionSignals, profile.ExecTargets)
	}

	iocs := make([]string, 0, len(iocSet))
	for ioc := range iocSet {
		iocs = append(iocs, ioc)
	}

	return profile, iocs, nil
}

func appendEvidence(set map[string]struct{}, filePath string, lineNo int, content string) {
	trimmed := strings.TrimSpace(content)
	if trimmed == "" {
		return
	}
	if len(trimmed) > 240 {
		trimmed = trimmed[:240] + "..."
	}
	set[fmt.Sprintf("%s:%d | %s", filePath, lineNo, trimmed)] = struct{}{}
}

func isSandboxSignalFile(path string) bool {
	normalized := strings.ToLower(filepath.ToSlash(path))
	for _, part := range strings.Split(normalized, "/") {
		switch part {
		case "docs", "doc", "examples", "example", "fixtures", "fixture", "testdata", "samples", "sample", "tests", "test", "__tests__", "spec":
			return false
		}
	}
	ext := strings.ToLower(filepath.Ext(normalized))
	switch ext {
	case ".go", ".py", ".js", ".ts", ".tsx", ".jsx", ".sh", ".bash", ".zsh", ".rb", ".php", ".java", ".cs", ".rs", ".ps1", ".mjs", ".cjs", ".json", ".yaml", ".yml", ".toml":
		return true
	default:
		return ext == ""
	}
}

func isSandboxCommentLikeLine(line string) bool {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return false
	}
	return strings.HasPrefix(trimmed, "#") ||
		strings.HasPrefix(trimmed, "//") ||
		strings.HasPrefix(trimmed, "/*") ||
		strings.HasPrefix(trimmed, "*") ||
		strings.HasPrefix(trimmed, "--")
}

func mergeProbeEvidence(set map[string]struct{}, items []string) {
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if len(trimmed) > 320 {
			trimmed = trimmed[:320] + "..."
		}
		set[trimmed] = struct{}{}
	}
}

type behaviorChainStat struct {
	Source              string
	RangeStart          int
	RangeEnd            int
	CategoryFirstLine   map[string]int
	CategoryLastLine    map[string]int
	DownloadCount       int
	DropCount           int
	ExecuteCount        int
	OutboundCount       int
	PersistenceCount    int
	PrivEscCount        int
	CredentialCount     int
	DefenseEvasionCount int
	LateralMoveCount    int
	CollectionCount     int
	C2BeaconCount       int
}

type behaviorEvidencePoint struct {
	category string
	line     int
	evidence string
}

const behaviorClusterLineGap = 12

var behaviorCategoryOrder = []string{"下载", "落地", "执行", "外联", "持久化", "提权", "凭据访问", "防御规避", "横向移动", "收集打包", "C2信标"}

func buildBehaviorChains(downloadSet, dropSet, executeSet, outboundSet, persistenceSet, privEscSet, credentialSet, defenseEvasionSet, lateralMoveSet, collectionSet, c2BeaconSet map[string]struct{}) []string {
	return buildBehaviorChainsFromSegments(collectBehaviorSegments(downloadSet, dropSet, executeSet, outboundSet, persistenceSet, privEscSet, credentialSet, defenseEvasionSet, lateralMoveSet, collectionSet, c2BeaconSet))
}

func buildBehaviorChainsFromSegments(all []*behaviorChainStat) []string {
	filtered := make([]*behaviorChainStat, 0, len(all))
	for _, st := range all {
		categoryHit := 0
		if st.DownloadCount > 0 {
			categoryHit++
		}
		if st.DropCount > 0 {
			categoryHit++
		}
		if st.ExecuteCount > 0 {
			categoryHit++
		}
		if st.OutboundCount > 0 {
			categoryHit++
		}
		if st.PersistenceCount > 0 {
			categoryHit++
		}
		if st.PrivEscCount > 0 {
			categoryHit++
		}
		if st.CredentialCount > 0 {
			categoryHit++
		}
		if st.DefenseEvasionCount > 0 {
			categoryHit++
		}
		if st.LateralMoveCount > 0 {
			categoryHit++
		}
		if st.CollectionCount > 0 {
			categoryHit++
		}
		if st.C2BeaconCount > 0 {
			categoryHit++
		}
		if categoryHit >= 2 {
			filtered = append(filtered, st)
		}
	}

	sort.Slice(filtered, func(i, j int) bool {
		score := func(s *behaviorChainStat) int {
			cat := 0
			if s.DownloadCount > 0 {
				cat++
			}
			if s.DropCount > 0 {
				cat++
			}
			if s.ExecuteCount > 0 {
				cat++
			}
			if s.OutboundCount > 0 {
				cat++
			}
			if s.PersistenceCount > 0 {
				cat++
			}
			if s.PrivEscCount > 0 {
				cat++
			}
			if s.CredentialCount > 0 {
				cat++
			}
			if s.DefenseEvasionCount > 0 {
				cat++
			}
			if s.LateralMoveCount > 0 {
				cat++
			}
			if s.CollectionCount > 0 {
				cat++
			}
			if s.C2BeaconCount > 0 {
				cat++
			}
			return cat*100 + s.DownloadCount + s.DropCount + s.ExecuteCount + s.OutboundCount + s.PersistenceCount + s.PrivEscCount + s.CredentialCount + s.DefenseEvasionCount + s.LateralMoveCount + s.CollectionCount + s.C2BeaconCount
		}
		si, sj := score(filtered[i]), score(filtered[j])
		if si != sj {
			return si > sj
		}
		if filtered[i].Source != filtered[j].Source {
			return filtered[i].Source < filtered[j].Source
		}
		return filtered[i].RangeStart < filtered[j].RangeStart
	})

	max := len(filtered)
	if max > 12 {
		max = 12
	}
	out := make([]string, 0, max)
	for i := 0; i < max; i++ {
		st := filtered[i]
		rangeLabel := formatBehaviorRange(st.RangeStart, st.RangeEnd)
		out = append(out, fmt.Sprintf("%s%s | 下载=%d, 落地=%d, 执行=%d, 外联=%d, 持久化=%d, 提权=%d, 凭据访问=%d, 防御规避=%d, 横向移动=%d, 收集打包=%d, C2信标=%d", st.Source, rangeLabel, st.DownloadCount, st.DropCount, st.ExecuteCount, st.OutboundCount, st.PersistenceCount, st.PrivEscCount, st.CredentialCount, st.DefenseEvasionCount, st.LateralMoveCount, st.CollectionCount, st.C2BeaconCount))
	}
	return out
}

type sequenceMetric struct {
	count int
	line  int
}

func buildBehaviorTimelines(downloadSet, dropSet, executeSet, outboundSet, persistenceSet, privEscSet, credentialSet, defenseEvasionSet, lateralMoveSet, collectionSet, c2BeaconSet map[string]struct{}) []string {
	return buildBehaviorTimelinesFromSegments(collectBehaviorSegments(downloadSet, dropSet, executeSet, outboundSet, persistenceSet, privEscSet, credentialSet, defenseEvasionSet, lateralMoveSet, collectionSet, c2BeaconSet))
}

func buildBehaviorTimelinesFromSegments(segments []*behaviorChainStat) []string {
	categoryNames := []string{"下载", "落地", "执行", "外联", "持久化", "提权", "凭据访问", "防御规避", "横向移动", "收集打包", "C2信标"}

	metrics := map[string]map[string]sequenceMetric{}
	for _, segment := range segments {
		metrics[fmt.Sprintf("%s%s", segment.Source, formatBehaviorRange(segment.RangeStart, segment.RangeEnd))] = map[string]sequenceMetric{}
		key := fmt.Sprintf("%s%s", segment.Source, formatBehaviorRange(segment.RangeStart, segment.RangeEnd))
		for _, name := range categoryNames {
			count, line := behaviorCategoryStat(segment, name)
			if count == 0 {
				continue
			}
			metrics[key][name] = sequenceMetric{count: count, line: line}
		}
	}

	out := make([]string, 0, len(metrics))
	for source, perCategory := range metrics {
		if len(perCategory) < 2 {
			continue
		}
		ordered := make([]string, 0, len(perCategory))
		for name := range perCategory {
			ordered = append(ordered, name)
		}
		sort.Slice(ordered, func(i, j int) bool {
			mi := perCategory[ordered[i]]
			mj := perCategory[ordered[j]]
			if mi.line == 0 && mj.line == 0 {
				return ordered[i] < ordered[j]
			}
			if mi.line == 0 {
				return false
			}
			if mj.line == 0 {
				return true
			}
			if mi.line != mj.line {
				return mi.line < mj.line
			}
			return ordered[i] < ordered[j]
		})

		steps := make([]string, 0, len(ordered))
		for _, name := range ordered {
			m := perCategory[name]
			if m.line > 0 {
				steps = append(steps, fmt.Sprintf("%s(L%d,x%d)", name, m.line, m.count))
			} else {
				steps = append(steps, fmt.Sprintf("%s(x%d)", name, m.count))
			}
		}
		out = append(out, fmt.Sprintf("%s | 时序: %s", source, strings.Join(steps, " -> ")))
	}

	sort.Strings(out)
	if len(out) > 12 {
		return out[:12]
	}
	return out
}

func collectBehaviorSegments(downloadSet, dropSet, executeSet, outboundSet, persistenceSet, privEscSet, credentialSet, defenseEvasionSet, lateralMoveSet, collectionSet, c2BeaconSet map[string]struct{}) []*behaviorChainStat {
	pointsBySource := map[string][]behaviorEvidencePoint{}
	add := func(set map[string]struct{}, category string) {
		for evidence := range set {
			source, line := parseEvidenceSourceAndLine(evidence)
			pointsBySource[source] = append(pointsBySource[source], behaviorEvidencePoint{category: category, line: line, evidence: evidence})
		}
	}
	add(downloadSet, "下载")
	add(dropSet, "落地")
	add(executeSet, "执行")
	add(outboundSet, "外联")
	add(persistenceSet, "持久化")
	add(privEscSet, "提权")
	add(credentialSet, "凭据访问")
	add(defenseEvasionSet, "防御规避")
	add(lateralMoveSet, "横向移动")
	add(collectionSet, "收集打包")
	add(c2BeaconSet, "C2信标")

	segments := make([]*behaviorChainStat, 0, len(pointsBySource))
	for source, points := range pointsBySource {
		sort.Slice(points, func(i, j int) bool {
			if points[i].line == 0 || points[j].line == 0 {
				if points[i].line != points[j].line {
					return points[i].line < points[j].line
				}
				return points[i].category < points[j].category
			}
			if points[i].line != points[j].line {
				return points[i].line < points[j].line
			}
			return points[i].category < points[j].category
		})
		current := &behaviorChainStat{Source: source}
		for i, point := range points {
			if i == 0 {
				applyBehaviorPoint(current, point)
				continue
			}
			prevLine := points[i-1].line
			if point.line > 0 && prevLine > 0 && point.line-prevLine > behaviorClusterLineGap {
				segments = append(segments, current)
				current = &behaviorChainStat{Source: source}
			}
			applyBehaviorPoint(current, point)
		}
		if current.RangeStart != 0 || current.RangeEnd != 0 || behaviorCategoryCount(current) > 0 {
			segments = append(segments, current)
		}
	}
	return segments
}

func applyBehaviorPoint(st *behaviorChainStat, point behaviorEvidencePoint) {
	if point.line > 0 {
		if st.RangeStart == 0 || point.line < st.RangeStart {
			st.RangeStart = point.line
		}
		if point.line > st.RangeEnd {
			st.RangeEnd = point.line
		}
		if st.CategoryFirstLine == nil {
			st.CategoryFirstLine = make(map[string]int)
		}
		if st.CategoryLastLine == nil {
			st.CategoryLastLine = make(map[string]int)
		}
		if first := st.CategoryFirstLine[point.category]; first == 0 || point.line < first {
			st.CategoryFirstLine[point.category] = point.line
		}
		if point.line > st.CategoryLastLine[point.category] {
			st.CategoryLastLine[point.category] = point.line
		}
	}
	switch point.category {
	case "下载":
		st.DownloadCount++
	case "落地":
		st.DropCount++
	case "执行":
		st.ExecuteCount++
	case "外联":
		st.OutboundCount++
	case "持久化":
		st.PersistenceCount++
	case "提权":
		st.PrivEscCount++
	case "凭据访问":
		st.CredentialCount++
	case "防御规避":
		st.DefenseEvasionCount++
	case "横向移动":
		st.LateralMoveCount++
	case "收集打包":
		st.CollectionCount++
	case "C2信标":
		st.C2BeaconCount++
	}
}

func behaviorCategoryCount(st *behaviorChainStat) int {
	count := 0
	for _, item := range []int{st.DownloadCount, st.DropCount, st.ExecuteCount, st.OutboundCount, st.PersistenceCount, st.PrivEscCount, st.CredentialCount, st.DefenseEvasionCount, st.LateralMoveCount, st.CollectionCount, st.C2BeaconCount} {
		if item > 0 {
			count++
		}
	}
	return count
}

func behaviorCategoryStat(st *behaviorChainStat, category string) (int, int) {
	line := st.RangeStart
	if st.CategoryFirstLine != nil {
		if first := st.CategoryFirstLine[category]; first > 0 {
			line = first
		}
	}
	switch category {
	case "下载":
		return st.DownloadCount, line
	case "落地":
		return st.DropCount, line
	case "执行":
		return st.ExecuteCount, line
	case "外联":
		return st.OutboundCount, line
	case "持久化":
		return st.PersistenceCount, line
	case "提权":
		return st.PrivEscCount, line
	case "凭据访问":
		return st.CredentialCount, line
	case "防御规避":
		return st.DefenseEvasionCount, line
	case "横向移动":
		return st.LateralMoveCount, line
	case "收集打包":
		return st.CollectionCount, line
	case "C2信标":
		return st.C2BeaconCount, line
	default:
		return 0, 0
	}
}

func formatBehaviorRange(start, end int) string {
	if start <= 0 && end <= 0 {
		return ""
	}
	if start <= 0 || start == end {
		return fmt.Sprintf(":%d", maxBehaviorLine(start, end))
	}
	return fmt.Sprintf(":%d-%d", start, end)
}

func maxBehaviorLine(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func buildSequenceAlerts(segments []*behaviorChainStat) []string {
	if len(segments) == 0 {
		return nil
	}
	set := map[string]struct{}{}
	for _, segment := range segments {
		if segmentHasOrderedCategories(segment, "下载", "执行") {
			set["命中下载后执行时序"] = struct{}{}
		}
		if segmentHasOrderedCategories(segment, "收集打包", "外联") {
			set["命中收集后外联时序"] = struct{}{}
		}
		if segmentHasOrderedCategories(segment, "凭据访问", "外联") {
			set["命中凭据访问后外联时序"] = struct{}{}
		}
		if segmentHasOrderedCategories(segment, "防御规避", "执行") {
			set["命中防御规避后执行时序"] = struct{}{}
		}
		if segmentHasOrderedCategories(segment, "横向移动", "执行") || segmentHasOrderedCategories(segment, "横向移动", "C2信标") {
			set["命中横向移动联动控制时序"] = struct{}{}
		}
	}
	return mapSetKeys(set)
}

func segmentHasOrderedCategories(segment *behaviorChainStat, first string, second string) bool {
	if segment == nil || segment.CategoryFirstLine == nil || segment.CategoryLastLine == nil {
		return false
	}
	firstLine := segment.CategoryFirstLine[first]
	secondLine := segment.CategoryLastLine[second]
	return firstLine > 0 && secondLine > 0 && firstLine < secondLine
}

func parseEvidenceSourceAndLine(item string) (string, int) {
	raw := strings.TrimSpace(strings.TrimPrefix(item, "[sandbox-runtime]"))
	if raw == "" {
		return "unknown", 0
	}
	left := raw
	if idx := strings.Index(raw, "|"); idx >= 0 {
		left = strings.TrimSpace(raw[:idx])
	}
	line := 0
	if idx := strings.LastIndex(left, ":"); idx > 0 {
		_, _ = fmt.Sscanf(strings.TrimSpace(left[idx+1:]), "%d", &line)
		left = strings.TrimSpace(left[:idx])
	}
	if left == "" {
		left = "unknown"
	}
	return left, line
}

func evidenceSourceKey(item string) string {
	raw := strings.TrimSpace(strings.TrimPrefix(item, "[sandbox-runtime]"))
	if raw == "" {
		return "unknown"
	}
	left := raw
	if idx := strings.Index(raw, "|"); idx >= 0 {
		left = strings.TrimSpace(raw[:idx])
	}
	if idx := strings.LastIndex(left, ":"); idx > 0 {
		left = left[:idx]
	}
	left = strings.TrimSpace(left)
	if left == "" {
		return "unknown"
	}
	return left
}

func (r *Runner) runContainerProbe(scanPath string) (probeReport, error) {
	rep := probeReport{}
	image := readSandboxImage()
	timeoutSecs := readPositiveIntEnv("REVIEW_SANDBOX_TIMEOUT_SECS", 45)
	dockerRuntime, err := resolveDockerRuntime("gvisor")
	if err != nil {
		return rep, err
	}

	absScan, err := filepath.Abs(scanPath)
	if err != nil {
		return rep, err
	}
	outDir, err := os.MkdirTemp("", "sandbox-probe-*")
	if err != nil {
		return rep, err
	}
	defer os.RemoveAll(outDir)

	probeScript := "python3 - <<'PY'\n" +
		"import json\n" +
		"import re\n" +
		"from pathlib import Path\n" +
		"root = Path('/scan')\n" +
		"count = 0\n" +
		"samples = []\n" +
		"download_iocs = []\n" +
		"drop_iocs = []\n" +
		"execute_iocs = []\n" +
		"outbound_iocs = []\n" +
		"persistence_iocs = []\n" +
		"priv_esc_iocs = []\n" +
		"credential_iocs = []\n" +
		"defense_evasion_iocs = []\n" +
		"lateral_move_iocs = []\n" +
		"collection_iocs = []\n" +
		"c2_beacon_iocs = []\n" +
		"probe_warnings = []\n" +
		"download_re = re.compile(r'(?i)(curl\\s+|wget\\s+|invoke-webrequest\\b|http\\.get\\b|requests\\.get\\b|urllib\\.request\\.urlretrieve\\b|fetch\\(|axios\\.get\\b|got\\.get\\b|request\\.get\\b)')\n" +
		"drop_re = re.compile(r'(?i)(os\\.writefile|ioutil\\.writefile|writefile\\(|fopen\\([^\\)]*,\\s*\\\"w|open\\([^\\)]*,\\s*\\\"w|chmod\\s+\\+x|chmod\\()')\n" +
		"execute_re = re.compile(r'(?i)(exec\\.command|syscall\\.exec|subprocess\\.popen|child_process|powershell|/bin/sh\\s+-c|bash\\s+-c)')\n" +
		"outbound_re = re.compile(r'(?i)(http\\.(post|get|newrequest)\\b|net\\.dial\\b|websocket|grpc\\.|axios\\.|requests\\.(post|get)|urllib\\.request\\.|fetch\\(|got\\.|request\\.|socket\\.|httpclient|http\\.client|urlopen\\b|https?://|(?:\\b\\d{1,3}(?:\\.\\d{1,3}){3}\\b))')\n" +
		"persistence_re = re.compile(r'(?i)(crontab\\b|/etc/cron\\.|systemctl\\s+enable\\b|startup|autorun|runonce|schtasks\\b|launchctl\\b|~/.bashrc|~/.profile|/etc/profile)')\n" +
		"priv_esc_re = re.compile(r'(?i)(sudo\\b|setuid\\b|setcap\\b|chmod\\s+4777\\b|chmod\\s+777\\b|token::elevate|sedebugprivilege|runas\\b)')\n" +
		"credential_path_re = re.compile(r'(?i)(/etc/shadow|/root/\\.netrc|~/.ssh|id_rsa|credentials?\\.(json|ya?ml)|\\.env\\b|secret_access_key|aws_access_key_id|authorization:)')\n" +
		"credential_access_re = re.compile(r'(?i)(os\\.environ|getenv\\(|os\\.getenv\\(|process\\.env|readfile|read_text\\(|open\\()')\n" +
		"credential_secret_re = re.compile(r'(?i)(token|secret|password|api[_-]?key|credential|auth)')\n" +
		"defense_evasion_re = re.compile(r'(?i)(disable(defender|security)|set-mppreference|kill\\s+-9\\s+(auditd|falco)|history\\s+-c|wevtutil\\s+cl\\b|auditctl\\s+-D\\b|iptables\\s+-F\\b)')\n" +
		"lateral_move_re = re.compile(r'(?i)(ssh\\s+[^\\n]*@|scp\\s+|psexec\\b|wmic\\s+/node|winrm\\b|net\\s+use\\\\\\\\|smbclient\\b|mstsc\\b|rdp\\b)')\n" +
		"collection_re = re.compile(r'(?i)(zip\\s+-r\\b|tar\\s+-czf\\b|7z\\s+a\\b|rar\\s+a\\b|find\\s+/\\b|dir\\s+/s\\b|ls\\s+-la\\b|cat\\s+/etc/passwd\\b|db dump|mysqldump\\b|pg_dump\\b)')\n" +
		"c2_beacon_re = re.compile(r'(?i)(beacon\\b|heartbeat\\b|callback\\b|polling\\b|sleep\\([^\\)]{0,12}\\)|/api/checkin|/api/beacon|\\bc2\\b|command-and-control)')\n" +
		"def add_evidence(dst, item, cap=200):\n" +
		"    if item and len(dst) < cap and item not in dst:\n" +
		"        dst.append(item)\n" +
		"def is_comment_like(line):\n" +
		"    s = line.strip()\n" +
		"    return s.startswith('#') or s.startswith('//') or s.startswith('/*') or s.startswith('*') or s.startswith('--')\n" +
		"def is_signal_file(path):\n" +
		"    parts = [p.lower() for p in path.parts]\n" +
		"    for part in parts:\n" +
		"        if part in {'docs','doc','examples','example','fixtures','fixture','testdata','samples','sample','tests','test','__tests__','spec'}:\n" +
		"            return False\n" +
		"    ext = path.suffix.lower()\n" +
		"    return ext in {'','.go','.py','.js','.ts','.tsx','.jsx','.sh','.bash','.zsh','.rb','.php','.java','.cs','.rs','.ps1','.mjs','.cjs','.json','.yaml','.yml','.toml'}\n" +
		"for p in root.rglob('*'):\n" +
		"    if p.is_file():\n" +
		"        count += 1\n" +
		"        if len(samples) < 10:\n" +
		"            samples.append(str(p.relative_to(root)))\n" +
		"        if not is_signal_file(p.relative_to(root)):\n" +
		"            continue\n" +
		"        try:\n" +
		"            if p.stat().st_size > 1024 * 1024:\n" +
		"                continue\n" +
		"            text = p.read_text(encoding='utf-8', errors='ignore')\n" +
		"        except Exception as e:\n" +
		"            if len(probe_warnings) < 8:\n" +
		"                probe_warnings.append(f'{p.relative_to(root)} 读取失败: {e}')\n" +
		"            continue\n" +
		"        rel = str(p.relative_to(root))\n" +
		"        for idx, line in enumerate(text.splitlines(), start=1):\n" +
		"            s = line.strip()\n" +
		"            if not s or is_comment_like(s):\n" +
		"                continue\n" +
		"            if len(s) > 240:\n" +
		"                s = s[:240] + '...'\n" +
		"            evidence = f'[sandbox-runtime] {rel}:{idx} | {s}'\n" +
		"            if download_re.search(line):\n" +
		"                add_evidence(download_iocs, evidence)\n" +
		"            if drop_re.search(line):\n" +
		"                add_evidence(drop_iocs, evidence)\n" +
		"            if execute_re.search(line):\n" +
		"                add_evidence(execute_iocs, evidence)\n" +
		"            if outbound_re.search(line):\n" +
		"                add_evidence(outbound_iocs, evidence)\n" +
		"            if persistence_re.search(line):\n" +
		"                add_evidence(persistence_iocs, evidence)\n" +
		"            if priv_esc_re.search(line):\n" +
		"                add_evidence(priv_esc_iocs, evidence)\n" +
		"            if credential_path_re.search(line) or (credential_access_re.search(line) and credential_secret_re.search(line)):\n" +
		"                add_evidence(credential_iocs, evidence)\n" +
		"            if defense_evasion_re.search(line):\n" +
		"                add_evidence(defense_evasion_iocs, evidence)\n" +
		"            if lateral_move_re.search(line):\n" +
		"                add_evidence(lateral_move_iocs, evidence)\n" +
		"            if collection_re.search(line):\n" +
		"                add_evidence(collection_iocs, evidence)\n" +
		"            if c2_beacon_re.search(line):\n" +
		"                add_evidence(c2_beacon_iocs, evidence)\n" +
		"Path('/out').mkdir(parents=True, exist_ok=True)\n" +
		"with open('/out/probe.json', 'w', encoding='utf-8') as f:\n" +
		"    json.dump({'file_count': count, 'samples': samples, 'download_iocs': download_iocs, 'drop_iocs': drop_iocs, 'execute_iocs': execute_iocs, 'outbound_iocs': outbound_iocs, 'persistence_iocs': persistence_iocs, 'priv_esc_iocs': priv_esc_iocs, 'credential_iocs': credential_iocs, 'defense_evasion_iocs': defense_evasion_iocs, 'lateral_move_iocs': lateral_move_iocs, 'collection_iocs': collection_iocs, 'c2_beacon_iocs': c2_beacon_iocs, 'probe_warnings': probe_warnings}, f, ensure_ascii=False)\n" +
		"PY"

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSecs)*time.Second)
	defer cancel()

	args := []string{
		"run", "--rm",
	}
	if strings.TrimSpace(dockerRuntime.Name) != "" {
		args = append(args, "--runtime="+dockerRuntime.Name)
	}
	args = append(args,
		"--network=none",
		"-v", absScan+":/scan:ro",
		"-v", outDir+":/out",
		image,
		"/bin/sh", "-lc", probeScript,
	)

	cmd := exec.CommandContext(ctx, "docker", args...)
	out, err := cmd.CombinedOutput()
	if ctx.Err() == context.DeadlineExceeded {
		return rep, fmt.Errorf("sandbox 容器探针超时（%ds）", timeoutSecs)
	}
	if err != nil {
		return rep, fmt.Errorf("sandbox 容器探针失败: %v, output: %s", err, strings.TrimSpace(string(out)))
	}

	probePath := filepath.Join(outDir, "probe.json")
	data, err := os.ReadFile(probePath)
	if err != nil {
		return rep, fmt.Errorf("sandbox 容器探针输出缺失: %v", err)
	}
	if err := json.Unmarshal(data, &rep); err != nil {
		return rep, fmt.Errorf("sandbox 容器探针输出解析失败: %v", err)
	}
	return rep, nil
}

func mapSetKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func buildDifferentialProbes(signals []string, execTargets []string) []review.DifferentialProbe {
	hasDangerousExec := false
	for _, t := range execTargets {
		l := strings.ToLower(t)
		if strings.Contains(l, "curl") || strings.Contains(l, "wget") || strings.Contains(l, "powershell") || strings.Contains(l, "bash -i") {
			hasDangerousExec = true
			break
		}
	}

	containerProbe := review.DifferentialProbe{
		Scenario:  "容器环境画像",
		Summary:   "比较容器环境与基线环境下的分支差异",
		Triggered: false,
	}
	vmProbe := review.DifferentialProbe{
		Scenario:  "虚拟机环境画像",
		Summary:   "比较虚拟机环境与基线环境下的分支差异",
		Triggered: false,
	}
	baselineProbe := review.DifferentialProbe{
		Scenario:  "基线环境画像",
		Summary:   "在无明显沙箱指纹提示下观察行为基线",
		Triggered: false,
	}

	for _, s := range signals {
		lower := strings.ToLower(s)
		if strings.Contains(lower, "docker") {
			containerProbe.Triggered = true
			containerProbe.Indicators = append(containerProbe.Indicators, s)
		}
		if strings.Contains(lower, "vm") || strings.Contains(lower, "hypervisor") {
			vmProbe.Triggered = true
			vmProbe.Indicators = append(vmProbe.Indicators, s)
		}
		if strings.Contains(lower, "debug") || strings.Contains(lower, "delay") {
			baselineProbe.Triggered = true
			baselineProbe.Indicators = append(baselineProbe.Indicators, s)
		}
	}

	if hasDangerousExec {
		containerProbe.Indicators = append(containerProbe.Indicators, "检测到危险执行命令，需确认是否在非沙箱环境触发")
		vmProbe.Indicators = append(vmProbe.Indicators, "检测到危险执行命令，需确认是否在非虚拟机环境触发")
		baselineProbe.Indicators = append(baselineProbe.Indicators, "检测到危险执行命令，需与环境识别逻辑联动审计")
	}

	return []review.DifferentialProbe{containerProbe, vmProbe, baselineProbe}
}

func normalizeExecuteOptions(opts ExecuteOptions) ExecuteOptions {
	if opts.DelayThresholdSecs <= 0 {
		opts.DelayThresholdSecs = 300
	}
	return opts
}

func detectDelayEvasion(delayPattern *regexp.Regexp, line string, threshold int) (bool, int) {
	matches := delayPattern.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		secs := 0
		_, _ = fmt.Sscanf(m[1], "%d", &secs)
		if secs >= threshold {
			return true, secs
		}
	}
	return false, 0
}

func readSandboxExecMode() string {
	v := strings.ToLower(strings.TrimSpace(os.Getenv("REVIEW_SANDBOX_EXEC_MODE")))
	if v == "" {
		return "container"
	}
	if v != "container" && v != "local" {
		return "container"
	}
	return v
}

func readSandboxImage() string {
	v := strings.TrimSpace(os.Getenv("REVIEW_SANDBOX_IMAGE"))
	if v == "" {
		return "skill-sandbox:latest"
	}
	return v
}

func resolveDockerRuntime(sandboxRuntime string) (dockerRuntimeCheck, error) {
	configured := strings.TrimSpace(os.Getenv("REVIEW_SANDBOX_DOCKER_RUNTIME"))
	if configured == "default" || configured == "runc" || configured == "none" {
		return dockerRuntimeCheck{Name: "", Message: "使用 Docker 默认 runtime"}, nil
	}

	runtimes, defaultRuntime, infoErr := dockerRuntimeInfo()
	if infoErr != nil {
		return dockerRuntimeCheck{}, fmt.Errorf("无法读取 Docker runtime 信息，不能确认容器沙箱是否真实可用: %w", infoErr)
	}

	if configured != "" {
		if stringSliceContains(runtimes, configured) {
			return dockerRuntimeCheck{Name: configured, Runtimes: runtimes, Default: defaultRuntime, Message: "使用显式配置的 Docker runtime"}, nil
		}
		return dockerRuntimeCheck{}, fmt.Errorf("Docker 未注册 REVIEW_SANDBOX_DOCKER_RUNTIME=%s；已注册 runtime: %s", configured, strings.Join(runtimes, ", "))
	}

	if sandboxRuntime == "gvisor" {
		for _, candidate := range []string{"runsc", "gvisor"} {
			if stringSliceContains(runtimes, candidate) {
				return dockerRuntimeCheck{Name: candidate, Runtimes: runtimes, Default: defaultRuntime, Message: "自动选择 Docker gVisor runtime"}, nil
			}
		}
		if defaultRuntime == "runsc" || defaultRuntime == "gvisor" {
			return dockerRuntimeCheck{Name: "", Runtimes: runtimes, Default: defaultRuntime, Message: "Docker 默认 runtime 已是 gVisor"}, nil
		}
		return dockerRuntimeCheck{}, fmt.Errorf("gVisor 二进制存在不代表 Docker 可用；Docker daemon 未注册 runsc/gvisor runtime，已注册 runtime: %s。请在 Docker daemon.json 注册 runsc，或设置 REVIEW_SANDBOX_DOCKER_RUNTIME 为实际名称", strings.Join(runtimes, ", "))
	}

	return dockerRuntimeCheck{Name: "", Runtimes: runtimes, Default: defaultRuntime, Message: "使用 Docker 默认 runtime"}, nil
}

func dockerRuntimeInfo() ([]string, string, error) {
	defaultRuntime := strings.TrimSpace(runDockerInfoFormat("{{.DefaultRuntime}}"))
	raw := strings.TrimSpace(runDockerInfoFormat("{{range $name, $_ := .Runtimes}}{{$name}}\n{{end}}"))
	if raw == "" {
		return nil, defaultRuntime, fmt.Errorf("docker info 未返回 runtime 列表")
	}
	set := map[string]struct{}{}
	for _, line := range strings.Split(raw, "\n") {
		name := strings.TrimSpace(line)
		if name != "" {
			set[name] = struct{}{}
		}
	}
	if defaultRuntime != "" {
		set[defaultRuntime] = struct{}{}
	}
	runtimes := make([]string, 0, len(set))
	for name := range set {
		runtimes = append(runtimes, name)
	}
	sort.Strings(runtimes)
	return runtimes, defaultRuntime, nil
}

func runDockerInfoFormat(format string) string {
	return dockerInfoFormatRunner(format)
}

func runDockerInfoFormatCommand(format string) string {
	cmd := exec.Command("docker", "info", "--format", format)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return ""
	}
	return string(out)
}

func stringSliceContains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func readPositiveIntEnv(key string, fallback int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	v := fallback
	_, _ = fmt.Sscanf(raw, "%d", &v)
	if v <= 0 {
		return fallback
	}
	return v
}

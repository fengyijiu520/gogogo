package sandbox

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"skill-scanner/internal/logx"
	"skill-scanner/internal/review"
)

type Runner struct{}

type ExecutionScenario struct {
	Name            string
	Command         string
	Args            []string
	Env             map[string]string
	HTTPPaths       []string
	HTTPPorts       []int
	HTTPMethods     []string
	HTTPPathMethods map[string][]string
	Workdir         string
	InputFiles      []string
	TimeoutSecs     int
	TriggerReason   string
}

type ExecutionPlan struct {
	Scenarios []ExecutionScenario
}

type entrypointCandidate struct {
	path       string
	name       string
	command    string
	args       []string
	signalPath string
}

type routeMount struct {
	Parent string
	Child  string
	Prefix string
}

type ExecuteOptions struct {
	Context             context.Context
	RequestID           string
	DifferentialEnabled bool
	DelayThresholdSecs  int
	RetryReason         string
}

type probeReport struct {
	FileCount          int      `json:"file_count"`
	Samples            []string `json:"samples"`
	ExecCommand        string   `json:"exec_command"`
	ExecExitCode       int      `json:"exec_exit_code"`
	ExecOutput         []string `json:"exec_output"`
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

	rt := newZeroclawRuntime()
	if err := rt.Prepare(); err != nil {
		return fmt.Errorf("zeroclaw 沙箱不可用: %w", err)
	}
	return nil
}

func (r *Runner) Execute(scanPath string, opts ExecuteOptions) (review.BehaviorProfile, []string, error) {
	return r.executeScenario(scanPath, opts, ExecutionScenario{Name: "default"})
}

func (r *Runner) ExecutePlan(scanPath string, plan ExecutionPlan, opts ExecuteOptions) (review.BehaviorProfile, []string, error) {
	if len(plan.Scenarios) == 0 {
		return r.Execute(scanPath, opts)
	}
	mergedProfile := review.BehaviorProfile{SandboxSource: "multi-entry-probe", SandboxVerdict: "clean"}
	iocSet := make(map[string]struct{})
	for _, scenario := range plan.Scenarios {
		profile, iocs, err := r.executeScenario(scanPath, opts, scenario)
		if err != nil {
			mergedProfile.ProbeWarnings = appendUniqueWarning(mergedProfile.ProbeWarnings, fmt.Sprintf("多入口场景 %s 执行失败: %v", scenario.Name, err))
			continue
		}
		mergedProfile = mergeScenarioProfile(mergedProfile, profile)
		for _, ioc := range iocs {
			trimmed := strings.TrimSpace(ioc)
			if trimmed != "" {
				iocSet[trimmed] = struct{}{}
			}
		}
	}
	if len(mergedProfile.ExecutionScenarios) == 0 {
		return r.Execute(scanPath, opts)
	}
	iocs := make([]string, 0, len(iocSet))
	for ioc := range iocSet {
		iocs = append(iocs, ioc)
	}
	sort.Strings(iocs)
	if mergedProfile.SandboxScore >= 8 {
		mergedProfile.SandboxVerdict = "malicious"
	} else if mergedProfile.SandboxScore >= 4 {
		mergedProfile.SandboxVerdict = "suspicious"
	} else if mergedProfile.SandboxFallback {
		mergedProfile.SandboxVerdict = "degraded"
	}
	return mergedProfile, iocs, nil
}

func (r *Runner) BuildExecutionPlan(scanPath string, opts ExecuteOptions) ExecutionPlan {
	timeout := maxInt(readPositiveIntEnv("REVIEW_SANDBOX_TIMEOUT_SECS", 45), 15)
	scenarios := []ExecutionScenario{{Name: "default", TimeoutSecs: timeout, TriggerReason: strings.TrimSpace(opts.RetryReason)}}
	detector := newReplaySignalDetector(scanPath)
	for _, candidate := range discoverExecutionEntrypoints(scanPath) {
		if pathExists(filepath.Join(scanPath, candidate.path)) {
			signalPath := candidate.path
			if strings.TrimSpace(candidate.signalPath) != "" {
				signalPath = candidate.signalPath
			}
			signals := detector.detect(signalPath)
			scenario := ExecutionScenario{Name: candidate.name, TimeoutSecs: timeout, TriggerReason: strings.TrimSpace(opts.RetryReason)}
			scenarioExt := filepath.Ext(candidate.path)
			if strings.TrimSpace(candidate.signalPath) != "" {
				scenarioExt = filepath.Ext(candidate.signalPath)
			}
			switch scenarioExt {
			case ".py":
				scenario.Command = "python3"
				scenario.Args = []string{candidate.path}
				scenario.Env = map[string]string{"CLI_MODE": "1", "PYTHONUNBUFFERED": "1"}
				if signals.EnvInput {
					scenario.Env["INPUT_MODE"] = "env"
				}
			case ".sh":
				scenario.Command = "/bin/sh"
				scenario.Args = []string{candidate.path}
				scenario.Env = map[string]string{"CLI_MODE": "1"}
				if signals.EnvInput {
					scenario.Env["INPUT_MODE"] = "env"
				}
			case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts":
				scenario.Command = "node"
				scenario.Args = []string{candidate.path}
				scenario.Env = map[string]string{"CLI_MODE": "1"}
			default:
				scenario.Command = candidate.path
			}
			if candidate.command != "" {
				scenario.Command = candidate.command
				scenario.Args = append([]string{}, candidate.args...)
				scenario.Env = map[string]string{"CLI_MODE": "1"}
			}
			scenarios = append(scenarios, scenario)
			scenarios = append(scenarios, buildReplayVariants(candidate, signals, timeout, strings.TrimSpace(opts.RetryReason))...)
		}
	}
	scenarios = append(scenarios,
		ExecutionScenario{Name: "env-debug", Env: map[string]string{"DEBUG": "1", "ENABLE_EXEC": "1"}, TimeoutSecs: timeout, TriggerReason: strings.TrimSpace(opts.RetryReason)},
		ExecutionScenario{Name: "input-sample", InputFiles: []string{"input.json"}, TimeoutSecs: timeout, TriggerReason: strings.TrimSpace(opts.RetryReason)},
	)
	return ExecutionPlan{Scenarios: uniqueScenarioPlan(scenarios)}
}

func discoverExecutionEntrypoints(scanPath string) []entrypointCandidate {
	files := []string{"main.py", "app.py", "api.py", "web.py", "server.py", "app.js", "server.js", "index.js", "api.js", "web.js", "app.mjs", "server.mjs", "index.mjs", "api.mjs", "web.mjs", "app.cjs", "server.cjs", "index.cjs", "api.cjs", "web.cjs", "app.ts", "server.ts", "index.ts", "api.ts", "web.ts", "bootstrap.sh", "start.sh"}
	candidates := make([]entrypointCandidate, 0, len(files)*3)
	for _, file := range files {
		candidates = append(candidates, entrypointCandidate{path: file, name: buildEntrypointScenarioName(file)})
	}
	for _, dir := range shallowEntrypointDirs(scanPath) {
		for _, file := range files {
			rel := filepath.ToSlash(filepath.Join(dir, file))
			candidates = append(candidates, entrypointCandidate{path: rel, name: buildEntrypointScenarioName(rel)})
		}
		for _, nestedDir := range shallowEntrypointDirs(filepath.Join(scanPath, dir)) {
			for _, file := range files {
				rel := filepath.ToSlash(filepath.Join(dir, nestedDir, file))
				candidates = append(candidates, entrypointCandidate{path: rel, name: buildEntrypointScenarioName(rel)})
			}
		}
	}
	candidates = append(candidates, discoverPackageJSONEntrypoints(scanPath)...)
	return uniqueEntrypointCandidates(candidates)
}

func discoverPackageJSONEntrypoints(scanPath string) []entrypointCandidate {
	data, err := os.ReadFile(filepath.Join(scanPath, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Scripts map[string]string `json:"scripts"`
		Main    string            `json:"main"`
		Module  string            `json:"module"`
		Bin     json.RawMessage   `json:"bin"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	candidates := make([]entrypointCandidate, 0, 8)
	for _, scriptName := range []string{"start", "dev", "serve", "preview"} {
		command, args := parsePackageJSONNodeScript(pkg.Scripts[scriptName])
		if command == "" {
			continue
		}
		candidates = append(candidates, entrypointCandidate{path: "package.json", name: "node-package-" + sanitizeScenarioName(scriptName), command: command, args: args, signalPath: firstNodeScriptPath(args)})
	}
	for _, rel := range packageJSONEntrypointPaths(pkg.Main, pkg.Module, pkg.Bin) {
		candidates = append(candidates, entrypointCandidate{path: rel, name: buildEntrypointScenarioName(rel)})
	}
	return candidates
}

func packageJSONEntrypointPaths(mainPath, modulePath string, binRaw json.RawMessage) []string {
	paths := make([]string, 0, 4)
	paths = appendPackageEntrypointPath(paths, mainPath)
	paths = appendPackageEntrypointPath(paths, modulePath)
	if len(binRaw) > 0 {
		var single string
		if err := json.Unmarshal(binRaw, &single); err == nil {
			paths = appendPackageEntrypointPath(paths, single)
		} else {
			var bins map[string]string
			if err := json.Unmarshal(binRaw, &bins); err == nil {
				keys := make([]string, 0, len(bins))
				for key := range bins {
					keys = append(keys, key)
				}
				sort.Strings(keys)
				for _, key := range keys {
					paths = appendPackageEntrypointPath(paths, bins[key])
				}
			}
		}
	}
	return uniqueStrings(paths)
}

func appendPackageEntrypointPath(paths []string, rel string) []string {
	rel = cleanPackageEntrypointPath(rel)
	if rel == "" || !isNodeScriptPath(rel) {
		return paths
	}
	return append(paths, rel)
}

func cleanPackageEntrypointPath(rel string) string {
	rel = strings.TrimSpace(rel)
	if rel == "" || strings.Contains(rel, "://") || filepath.IsAbs(rel) {
		return ""
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	rel = strings.TrimPrefix(rel, "./")
	if rel == "." || strings.HasPrefix(rel, "../") {
		return ""
	}
	return rel
}

func firstNodeScriptPath(args []string) string {
	for _, arg := range args {
		trimmed := cleanPackageEntrypointPath(arg)
		if isNodeScriptPath(trimmed) {
			return filepath.ToSlash(trimmed)
		}
	}
	return ""
}

func isNodeScriptPath(path string) bool {
	switch strings.ToLower(filepath.Ext(strings.TrimSpace(path))) {
	case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts":
		return true
	default:
		return false
	}
}

func parsePackageJSONNodeScript(script string) (string, []string) {
	fields := strings.Fields(strings.TrimSpace(script))
	if len(fields) == 0 {
		return "", nil
	}
	if len(fields) >= 2 && isNodePackageRunner(fields[0]) && fields[1] == "run" {
		return "", nil
	}
	if len(fields) >= 2 && isNodePackageRunner(fields[0]) {
		return fields[0], limitStringSlice(fields[1:], 8)
	}
	if fields[0] == "npx" && len(fields) >= 2 {
		return "npx", limitStringSlice(fields[1:], 8)
	}
	for i, field := range fields {
		switch field {
		case "node", "nodejs":
			if i+1 >= len(fields) {
				return "", nil
			}
			args := append([]string{}, fields[i+1:]...)
			if len(args) > 8 {
				args = args[:8]
			}
			return "node", args
		}
	}
	if isKnownNodeServerCommand(fields[0]) {
		return fields[0], limitStringSlice(fields[1:], 8)
	}
	return "", nil
}

func isNodePackageRunner(command string) bool {
	switch strings.TrimSpace(command) {
	case "npm", "pnpm", "yarn", "bun":
		return true
	default:
		return false
	}
}

func isKnownNodeServerCommand(command string) bool {
	switch strings.TrimSpace(command) {
	case "vite", "next", "nuxt", "astro", "remix", "svelte-kit", "tsx", "ts-node", "nodemon":
		return true
	case "next dev", "nuxt dev":
		return true
	default:
		return false
	}
}

func shallowEntrypointDirs(scanPath string) []string {
	entries, err := os.ReadDir(scanPath)
	if err != nil {
		return nil
	}
	dirs := make([]string, 0, 8)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := strings.TrimSpace(entry.Name())
		if isShallowEntrypointDir(name) {
			dirs = append(dirs, name)
		}
	}
	sort.Strings(dirs)
	return dirs
}

func isShallowEntrypointDir(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "src", "app", "api", "backend", "server", "service", "services", "web", "frontend", "cmd":
		return true
	default:
		return false
	}
}

func buildEntrypointScenarioName(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.TrimSuffix(filepath.ToSlash(path), ext)
	base = strings.Trim(strings.ReplaceAll(base, "/", "-"), "-")
	base = sanitizeScenarioName(base)
	switch ext {
	case ".py":
		return "python-" + base
	case ".sh":
		return "shell-" + base
	case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts":
		return "node-" + base
	default:
		return base
	}
}

func sanitizeScenarioName(raw string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(raw)) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "entrypoint"
	}
	return out
}

func uniqueEntrypointCandidates(items []entrypointCandidate) []entrypointCandidate {
	seen := make(map[string]struct{}, len(items))
	out := make([]entrypointCandidate, 0, len(items))
	for _, item := range items {
		path := strings.TrimSpace(filepath.ToSlash(item.path))
		name := strings.TrimSpace(item.name)
		if path == "" || name == "" {
			continue
		}
		signalPath := strings.TrimSpace(filepath.ToSlash(item.signalPath))
		key := path + "\x00" + name + "\x00" + item.command + "\x00" + strings.Join(item.args, "\x00") + "\x00" + signalPath
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, entrypointCandidate{path: path, name: name, command: strings.TrimSpace(item.command), args: append([]string{}, item.args...), signalPath: signalPath})
	}
	return out
}

func buildReplayVariants(candidate entrypointCandidate, signals replaySignalSet, timeout int, retryReason string) []ExecutionScenario {
	variants := make([]ExecutionScenario, 0, 3)
	ext := filepath.Ext(candidate.path)
	if candidate.command != "" {
		if scriptPath := firstNodeScriptPath(candidate.args); scriptPath != "" {
			ext = filepath.Ext(scriptPath)
		}
	}
	switch ext {
	case ".py":
		baseEnv := map[string]string{"CLI_MODE": "1", "PYTHONUNBUFFERED": "1"}
		if signals.CLIArgv || signals.StdinInput || signals.EnvInput {
			variants = append(variants, ExecutionScenario{
				Name:          candidate.name + "-input-sample",
				Command:       "python3",
				Args:          []string{candidate.path},
				Env:           cloneScenarioEnv(baseEnv),
				InputFiles:    []string{"input.json"},
				TimeoutSecs:   timeout,
				TriggerReason: retryReason,
			})
		}
		if signals.StdinInput {
			variants = append(variants, ExecutionScenario{
				Name:          candidate.name + "-stdin-sample",
				Command:       "python3",
				Args:          []string{candidate.path},
				Env:           cloneScenarioEnv(baseEnv),
				InputFiles:    []string{"stdin.txt"},
				TimeoutSecs:   timeout,
				TriggerReason: retryReason,
			})
		}
		if signals.EnvInput {
			variants = append(variants, ExecutionScenario{
				Name:          candidate.name + "-env-input",
				Command:       "python3",
				Args:          []string{candidate.path},
				Env:           map[string]string{"CLI_MODE": "1", "PYTHONUNBUFFERED": "1", "INPUT_MODE": "env"},
				InputFiles:    []string{"input.json"},
				TimeoutSecs:   timeout,
				TriggerReason: retryReason,
			})
		}
		if signals.WebServer {
			httpPorts := defaultHTTPProbePorts(signals.WebPorts)
			httpEnv := buildHTTPProbeEnv(httpPorts)
			variants = append(variants, ExecutionScenario{
				Name:            candidate.name + "-http-probe",
				Command:         "python3",
				Args:            []string{candidate.path},
				Env:             httpEnv,
				HTTPPaths:       append([]string{}, signals.WebRoutes...),
				HTTPPorts:       append([]int{}, httpPorts...),
				HTTPMethods:     append([]string{}, signals.WebMethods...),
				HTTPPathMethods: cloneStringSliceMap(signals.WebPathMethods),
				TimeoutSecs:     timeout,
				TriggerReason:   retryReason,
			})
			moduleName := strings.TrimSuffix(filepath.ToSlash(candidate.path), filepath.Ext(candidate.path))
			if strings.Contains(moduleName, "/") {
				moduleName = strings.ReplaceAll(moduleName, "/", ".")
			}
			for _, appRef := range signals.WebAppRefs {
				port := firstHTTPProbePort(httpPorts)
				variants = append(variants, ExecutionScenario{
					Name:            candidate.name + "-uvicorn-" + appRef,
					Command:         "python3",
					Args:            []string{"-m", "uvicorn", moduleName + ":" + appRef, "--host", "0.0.0.0", "--port", strconv.Itoa(port)},
					Env:             buildHTTPProbeEnv(httpPorts),
					HTTPPaths:       append([]string{}, signals.WebRoutes...),
					HTTPPorts:       append([]int{}, httpPorts...),
					HTTPMethods:     append([]string{}, signals.WebMethods...),
					HTTPPathMethods: cloneStringSliceMap(signals.WebPathMethods),
					TimeoutSecs:     timeout,
					TriggerReason:   retryReason,
				})
			}
			if strings.Contains(strings.ToLower(candidate.path), ".py") {
				port := firstHTTPProbePort(httpPorts)
				variants = append(variants, ExecutionScenario{
					Name:            candidate.name + "-flask-cli",
					Command:         "python3",
					Args:            []string{"-m", "flask", "--app", moduleName, "run", "--host", "0.0.0.0", "--port", strconv.Itoa(port)},
					Env:             buildHTTPProbeEnv(httpPorts),
					HTTPPaths:       append([]string{}, signals.WebRoutes...),
					HTTPPorts:       append([]int{}, httpPorts...),
					HTTPMethods:     append([]string{}, signals.WebMethods...),
					HTTPPathMethods: cloneStringSliceMap(signals.WebPathMethods),
					TimeoutSecs:     timeout,
					TriggerReason:   retryReason,
				})
			}
		}
	case ".sh":
		baseEnv := map[string]string{"CLI_MODE": "1"}
		if signals.CLIArgv || signals.StdinInput || signals.EnvInput {
			variants = append(variants, ExecutionScenario{
				Name:          candidate.name + "-input-sample",
				Command:       "/bin/sh",
				Args:          []string{candidate.path},
				Env:           cloneScenarioEnv(baseEnv),
				InputFiles:    []string{"input.json"},
				TimeoutSecs:   timeout,
				TriggerReason: retryReason,
			})
		}
		if signals.EnvInput {
			variants = append(variants, ExecutionScenario{
				Name:          candidate.name + "-env-input",
				Command:       "/bin/sh",
				Args:          []string{candidate.path},
				Env:           map[string]string{"CLI_MODE": "1", "INPUT_MODE": "env"},
				InputFiles:    []string{"input.json"},
				TimeoutSecs:   timeout,
				TriggerReason: retryReason,
			})
		}
	case ".js", ".mjs", ".cjs", ".ts", ".mts", ".cts":
		baseEnv := map[string]string{"CLI_MODE": "1"}
		command := "node"
		args := []string{candidate.path}
		if candidate.command != "" {
			command = candidate.command
			args = append([]string{}, candidate.args...)
		}
		if signals.CLIArgv || signals.StdinInput || signals.EnvInput {
			variants = append(variants, ExecutionScenario{
				Name:          candidate.name + "-input-sample",
				Command:       command,
				Args:          append([]string{}, args...),
				Env:           cloneScenarioEnv(baseEnv),
				InputFiles:    []string{"input.json"},
				TimeoutSecs:   timeout,
				TriggerReason: retryReason,
			})
		}
		if signals.EnvInput {
			variants = append(variants, ExecutionScenario{
				Name:          candidate.name + "-env-input",
				Command:       command,
				Args:          append([]string{}, args...),
				Env:           map[string]string{"CLI_MODE": "1", "INPUT_MODE": "env"},
				InputFiles:    []string{"input.json"},
				TimeoutSecs:   timeout,
				TriggerReason: retryReason,
			})
		}
		if signals.WebServer {
			httpPorts := defaultHTTPProbePorts(signals.WebPorts)
			variants = append(variants, ExecutionScenario{
				Name:            candidate.name + "-http-probe",
				Command:         command,
				Args:            args,
				Env:             buildHTTPProbeEnv(httpPorts),
				HTTPPaths:       append([]string{}, signals.WebRoutes...),
				HTTPPorts:       append([]int{}, httpPorts...),
				HTTPMethods:     append([]string{}, signals.WebMethods...),
				HTTPPathMethods: cloneStringSliceMap(signals.WebPathMethods),
				TimeoutSecs:     timeout,
				TriggerReason:   retryReason,
			})
		}
	}
	return variants
}

func cloneScenarioEnv(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func (r *Runner) executeScenario(scanPath string, opts ExecuteOptions, scenario ExecutionScenario) (review.BehaviorProfile, []string, error) {
	opts = normalizeExecuteOptions(opts)
	logger := logx.FromContext(opts.Context).With("component", "sandbox_runner")
	if strings.TrimSpace(opts.RequestID) != "" {
		logger = logger.With("request_id", strings.TrimSpace(opts.RequestID))
	}
	if strings.TrimSpace(opts.RetryReason) != "" {
		logger = logger.With("retry_reason", strings.TrimSpace(opts.RetryReason))
	}
	scenarioName := strings.TrimSpace(scenario.Name)
	if scenarioName == "" {
		scenarioName = "default"
	}
	logger = logger.With("scenario", scenarioName)
	logger.Info("start sandbox execute", "scan_path", scanPath, "differential_enabled", opts.DifferentialEnabled, "delay_threshold_secs", opts.DelayThresholdSecs)
	profile := review.BehaviorProfile{}
	startedAt := time.Now()
	defer func() {
		profile.SandboxDurationMs = time.Since(startedAt).Milliseconds()
		logger.Info("finish sandbox execute", "sandbox_source", profile.SandboxSource, "sandbox_verdict", profile.SandboxVerdict, "sandbox_score", profile.SandboxScore, "probe_warnings", len(profile.ProbeWarnings), "duration_ms", profile.SandboxDurationMs)
	}()
	profile.ExecutionScenarios = append(profile.ExecutionScenarios, buildScenarioSummary(scenario))
	profile.SandboxSource = "static-probe"
	profile.SandboxVerdict = "clean"
	profile.SandboxScore = 0
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

	{
		singlePlan := ExecutionPlan{Scenarios: []ExecutionScenario{scenario}}
		zResult, zErr := r.zeroclawExecute(opts.Context, scanPath, singlePlan, opts)
		if zErr != nil {
			profile.SandboxFallback = true
			profile.SandboxVerdict = "degraded"
			profile.ProbeWarnings = append(profile.ProbeWarnings, "zeroclaw 沙箱执行失败，已回退静态探针: "+zErr.Error())
		} else {
			profile.SandboxSource = "zeroclaw"
			for _, zScenario := range zResult.Scenarios {
				output := zScenario.Output
				for _, warning := range inferMissingModuleWarnings(output, scenarioName) {
					profile.ProbeWarnings = appendUniqueWarning(profile.ProbeWarnings, warning)
				}
				for _, warning := range inferDependencyManifestWarnings(scanPath, output, scenarioName) {
					profile.ProbeWarnings = appendUniqueWarning(profile.ProbeWarnings, warning)
				}
				envKeys := make([]string, 0, len(scenario.Env))
				for key := range scenario.Env {
					envKeys = append(envKeys, key)
				}
				sort.Strings(envKeys)
				profile.ScenarioExecutions = append(profile.ScenarioExecutions, review.ScenarioExecution{
					Name:            zScenario.Name,
					Command:         strings.TrimSpace(zScenario.Command),
					ExitCode:        zScenario.ExitCode,
					HTTPPorts:       append([]int{}, scenario.HTTPPorts...),
					HTTPPaths:       append([]string{}, scenario.HTTPPaths...),
					HTTPPathMethods: cloneStringSliceMap(scenario.HTTPPathMethods),
					Output:          append([]string{}, output...),
					InputFiles:      append([]string{}, scenario.InputFiles...),
					EnvKeys:         envKeys,
				})
				iocs := extractIOCFromZeroclawOutput(output)
				mergeProbeEvidence(downloadSet, iocs["download"])
				mergeProbeEvidence(dropSet, iocs["drop"])
				mergeProbeEvidence(executeSet, iocs["execute"])
				mergeProbeEvidence(outboundSet, iocs["outbound"])
				mergeProbeEvidence(persistenceSet, iocs["persistence"])
				mergeProbeEvidence(privEscSet, iocs["priv_esc"])
				mergeProbeEvidence(credentialSet, iocs["credential"])
				mergeProbeEvidence(defenseEvasionSet, iocs["defense_evasion"])
				mergeProbeEvidence(collectionSet, iocs["c2_beacon"])
			}
			if zResult.PcapFile != "" {
				pcapIOCs := parsePcapFile(zResult.PcapFile)
				mergeProbeEvidence(outboundSet, pcapIOCs)
			}
			profile.ExecTargets = append(profile.ExecTargets,
				fmt.Sprintf("[sandbox] zeroclaw 沙箱执行完成，场景数=%d，耗时=%dms", len(zResult.Scenarios), zResult.TotalDurationMs),
			)
			profile.ExecTargets = append(profile.ExecTargets,
				fmt.Sprintf("[sandbox] 行为证据提取: 下载=%d, 落地=%d, 执行=%d, 外联=%d, 持久化=%d, 提权=%d, 凭据访问=%d, 防御规避=%d, C2信标=%d", len(downloadSet), len(dropSet), len(executeSet), len(outboundSet), len(persistenceSet), len(privEscSet), len(credentialSet), len(defenseEvasionSet), len(c2BeaconSet)),
			)
		}
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
	obfuscationRe := regexp.MustCompile(`(?i)(base64\.|b64decode\(|fromcharcode\(|eval\(|new\s+function\(|charcodeat\(|atob\(|xor\s|gzinflate\(|decodeURIComponent\()`)
	stage2ChainRe := regexp.MustCompile(`(?i)(curl\s+[^\n]+(sh|bash|zsh)|wget\s+[^\n]+(sh|bash|zsh)|requests\.get\([^\)]*\)\s*\.text\s*\)|fetch\([^\)]*\)\s*\.then\([^\)]*eval|subprocess\.(run|popen)\([^\)]*(curl|wget))`)
	envGuardRe := regexp.MustCompile(`(?i)(if\s+.*(docker|vm|sandbox|debug|hypervisor)|systemd-detect-virt|isdebuggerpresent|/proc/1/cgroup|\.dockerenv)`)
	inputGateRe := regexp.MustCompile(`(?i)(if\s+.*(argv|args|input\(|os\.getenv\(|getenv\(|process\.env|request\.|headers\[|time\.now\(|datetime\.now\())`)
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

	if len(downloadSet) > 0 && len(executeSet) > 0 {
		profile.ProbeWarnings = appendUniqueWarning(profile.ProbeWarnings, "检测到下载与执行信号但未形成时序告警，可能存在条件触发或运行入口覆盖不足")
	}
	if matchCodePattern(scanPath, obfuscationRe) && len(executeSet) == 0 {
		profile.ProbeWarnings = appendUniqueWarning(profile.ProbeWarnings, "检测到混淆/编码执行特征但未观测到执行IOC，建议启用多入口动态执行复测")
	}
	if matchCodePattern(scanPath, stage2ChainRe) && len(downloadSet) > 0 && len(executeSet) == 0 {
		profile.ProbeWarnings = appendUniqueWarning(profile.ProbeWarnings, "疑似二阶段载荷链路（下载后执行）未完全触发，需补充运行时探针与网络回放")
	}
	if matchCodePattern(scanPath, envGuardRe) && len(profile.EvasionSignals) == 0 {
		profile.ProbeWarnings = appendUniqueWarning(profile.ProbeWarnings, "检测到环境感知分支代码但未捕获差异行为信号，可能存在沙箱识别后静默路径")
	}
	if matchCodePattern(scanPath, inputGateRe) {
		profile.ProbeWarnings = appendUniqueWarning(profile.ProbeWarnings, "检测到输入/时间门控分支，当前动态结果可能遗漏特定触发条件下的行为")
	}

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

	profile.SandboxScore = computeSandboxScore(profile)
	if profile.SandboxScore >= 8 {
		profile.SandboxVerdict = "malicious"
	} else if profile.SandboxScore >= 4 {
		profile.SandboxVerdict = "suspicious"
	} else if profile.SandboxFallback {
		profile.SandboxVerdict = "degraded"
	}

	iocs := make([]string, 0, len(iocSet))
	for ioc := range iocSet {
		iocs = append(iocs, ioc)
	}

	return profile, iocs, nil
}

func mergeScenarioProfile(primary, secondary review.BehaviorProfile) review.BehaviorProfile {
	merged := primary
	merged.NetworkTargets = uniqueStrings(append(primary.NetworkTargets, secondary.NetworkTargets...))
	merged.FileTargets = uniqueStrings(append(primary.FileTargets, secondary.FileTargets...))
	merged.ExecTargets = uniqueStrings(append(primary.ExecTargets, secondary.ExecTargets...))
	merged.ExecutionScenarios = uniqueStrings(append(primary.ExecutionScenarios, secondary.ExecutionScenarios...))
	merged.DownloadIOCs = uniqueStrings(append(primary.DownloadIOCs, secondary.DownloadIOCs...))
	merged.DropIOCs = uniqueStrings(append(primary.DropIOCs, secondary.DropIOCs...))
	merged.ExecuteIOCs = uniqueStrings(append(primary.ExecuteIOCs, secondary.ExecuteIOCs...))
	merged.OutboundIOCs = uniqueStrings(append(primary.OutboundIOCs, secondary.OutboundIOCs...))
	merged.PersistenceIOCs = uniqueStrings(append(primary.PersistenceIOCs, secondary.PersistenceIOCs...))
	merged.PrivEscIOCs = uniqueStrings(append(primary.PrivEscIOCs, secondary.PrivEscIOCs...))
	merged.CredentialIOCs = uniqueStrings(append(primary.CredentialIOCs, secondary.CredentialIOCs...))
	merged.DefenseEvasionIOCs = uniqueStrings(append(primary.DefenseEvasionIOCs, secondary.DefenseEvasionIOCs...))
	merged.LateralMoveIOCs = uniqueStrings(append(primary.LateralMoveIOCs, secondary.LateralMoveIOCs...))
	merged.CollectionIOCs = uniqueStrings(append(primary.CollectionIOCs, secondary.CollectionIOCs...))
	merged.C2BeaconIOCs = uniqueStrings(append(primary.C2BeaconIOCs, secondary.C2BeaconIOCs...))
	merged.BehaviorChains = uniqueStrings(append(primary.BehaviorChains, secondary.BehaviorChains...))
	merged.BehaviorTimelines = uniqueStrings(append(primary.BehaviorTimelines, secondary.BehaviorTimelines...))
	merged.SequenceAlerts = uniqueStrings(append(primary.SequenceAlerts, secondary.SequenceAlerts...))
	merged.ProbeWarnings = uniqueStrings(append(primary.ProbeWarnings, secondary.ProbeWarnings...))
	merged.EvasionSignals = uniqueStrings(append(primary.EvasionSignals, secondary.EvasionSignals...))
	merged.Differentials = mergeScenarioDifferentials(primary.Differentials, secondary.Differentials)
	if secondary.SandboxScore > merged.SandboxScore {
		merged.SandboxScore = secondary.SandboxScore
	}
	merged.SandboxDurationMs += secondary.SandboxDurationMs
	if secondary.SandboxVerdict == "suspicious" || secondary.SandboxVerdict == "malicious" {
		merged.SandboxVerdict = secondary.SandboxVerdict
	}
	merged.SandboxFallback = primary.SandboxFallback || secondary.SandboxFallback
	if merged.SandboxSource == "" {
		merged.SandboxSource = secondary.SandboxSource
	}
	return merged
}

func mergeScenarioDifferentials(left, right []review.DifferentialProbe) []review.DifferentialProbe {
	if len(left) == 0 {
		return append([]review.DifferentialProbe{}, right...)
	}
	out := append([]review.DifferentialProbe{}, left...)
	index := make(map[string]int, len(out))
	for i, item := range out {
		index[item.Scenario] = i
	}
	for _, item := range right {
		if idx, ok := index[item.Scenario]; ok {
			out[idx].Triggered = out[idx].Triggered || item.Triggered
			out[idx].Indicators = uniqueStrings(append(out[idx].Indicators, item.Indicators...))
			if strings.TrimSpace(out[idx].Summary) == "" {
				out[idx].Summary = item.Summary
			}
			continue
		}
		out = append(out, item)
		index[item.Scenario] = len(out) - 1
	}
	return out
}

func uniqueScenarioPlan(items []ExecutionScenario) []ExecutionScenario {
	seen := make(map[string]struct{}, len(items))
	out := make([]ExecutionScenario, 0, len(items))
	for _, item := range items {
		name := strings.TrimSpace(item.Name)
		if name == "" {
			continue
		}
		fingerprint := fingerprintScenario(item)
		if _, ok := seen[fingerprint]; ok {
			continue
		}
		seen[fingerprint] = struct{}{}
		out = append(out, item)
	}
	return out
}

func buildScenarioSummary(scenario ExecutionScenario) string {
	parts := []string{fmt.Sprintf("scenario=%s", strings.TrimSpace(scenario.Name))}
	if strings.TrimSpace(scenario.Command) != "" {
		parts = append(parts, "command="+strings.TrimSpace(scenario.Command))
	}
	if len(scenario.Env) > 0 {
		keys := make([]string, 0, len(scenario.Env))
		for key := range scenario.Env {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts = append(parts, "env="+strings.Join(keys, ","))
	}
	if len(scenario.InputFiles) > 0 {
		parts = append(parts, "inputs="+strings.Join(scenario.InputFiles, ","))
	}
	if len(scenario.HTTPPaths) > 0 {
		parts = append(parts, "http_paths="+strings.Join(limitStringSlice(uniqueStrings(append([]string{}, scenario.HTTPPaths...)), 4), ","))
	}
	if len(scenario.HTTPPorts) > 0 {
		parts = append(parts, "http_ports="+strings.Join(intSliceToStrings(limitIntSlice(uniqueInts(append([]int{}, scenario.HTTPPorts...)), 4)), ","))
	}
	if len(scenario.HTTPMethods) > 0 {
		parts = append(parts, "http_methods="+strings.Join(limitStringSlice(uniqueStrings(append([]string{}, scenario.HTTPMethods...)), 4), ","))
	}
	if strings.TrimSpace(scenario.TriggerReason) != "" {
		parts = append(parts, "reason="+strings.TrimSpace(scenario.TriggerReason))
	}
	return strings.Join(parts, " | ")
}

func fingerprintScenario(scenario ExecutionScenario) string {
	parts := []string{
		strings.TrimSpace(scenario.Name),
		strings.TrimSpace(scenario.Command),
		strings.Join(scenario.Args, ","),
		strings.Join(scenario.InputFiles, ","),
		strings.Join(uniqueStrings(append([]string{}, scenario.HTTPPaths...)), ","),
		strings.Join(intSliceToStrings(uniqueInts(append([]int{}, scenario.HTTPPorts...))), ","),
		strings.Join(uniqueStrings(append([]string{}, scenario.HTTPMethods...)), ","),
	}
	if len(scenario.Env) > 0 {
		keys := make([]string, 0, len(scenario.Env))
		for key, value := range scenario.Env {
			keys = append(keys, key+"="+value)
		}
		sort.Strings(keys)
		parts = append(parts, strings.Join(keys, ","))
	}
	return strings.Join(parts, "|")
}

func pathExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func limitStringSlice(items []string, max int) []string {
	if max <= 0 || len(items) <= max {
		return append([]string{}, items...)
	}
	return append([]string{}, items[:max]...)
}

func limitIntSlice(items []int, max int) []int {
	if max <= 0 || len(items) <= max {
		return append([]int{}, items...)
	}
	return append([]int{}, items[:max]...)
}

func extractWebRoutes(source string) []string {
	routes := make([]string, 0)
	addMatches := func(pattern *regexp.Regexp) {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 2 {
				continue
			}
			route := normalizeRoutePath(match[1])
			if route != "" {
				routes = append(routes, route)
			}
		}
	}
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)@app\.(?:get|post|put|delete|patch|route)\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)app\.(?:get|post|put|delete|patch|all)\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)app\[(?:["'](?:get|post|put|delete|patch|all)["']|[A-Za-z_][A-Za-z0-9_]*)\]\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)app\.add_api_route\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)app\.route\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)app\.route\(["']([^"']+)["']\)\.(?:get|post|put|delete|patch|all)\(`),
		regexp.MustCompile(`(?i)add_url_rule\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)@app\.api_route\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)@(?:[A-Za-z_][A-Za-z0-9_]*)\.(?:get|post|put|delete|patch|route)\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\[(?:["'](?:get|post|put|delete|patch|all)["']|[A-Za-z_][A-Za-z0-9_]*)\]\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\.route\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\.route\(["']([^"']+)["']\)\.(?:get|post|put|delete|patch|all)\(`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\.add_url_rule\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\.add_api_route\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)@(?:[A-Za-z_][A-Za-z0-9_]*)\.api_route\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\.(?:get|post|put|delete|patch|all)\(["']([^"']+)["']`),
	} {
		addMatches(pattern)
	}

	localRoutes := extractNamedLocalRoutes(source)
	declaredPrefixes := extractNamedRoutePrefixes(source,
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*Blueprint\([^\n]*url_prefix\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*APIRouter\([^\n]*prefix\s*=\s*["']([^"']+)["']`),
	)
	for name, prefix := range declaredPrefixes {
		localPattern := regexp.MustCompile(`(?i)(?:@` + regexp.QuoteMeta(name) + `\.(?:get|post|put|delete|patch|route|api_route)|` + regexp.QuoteMeta(name) + `\.(?:get|post|put|delete|patch|all|add_api_route))\(["']([^"']+)["']`)
		for _, match := range localPattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 2 {
				continue
			}
			route := joinRoutePaths(prefix, match[1])
			if route != "" {
				routes = append(routes, route)
			}
		}
	}
	mounts := extractRouteMounts(source)
	for _, mount := range mounts {
		for _, localRoute := range localRoutes[mount.Child] {
			route := joinRoutePaths(mount.Prefix, joinRoutePaths(declaredPrefixes[mount.Child], localRoute))
			if route != "" {
				routes = append(routes, route)
			}
		}
	}
	allNames := make(map[string]struct{})
	for name := range localRoutes {
		allNames[name] = struct{}{}
	}
	for name := range declaredPrefixes {
		allNames[name] = struct{}{}
	}
	for _, mount := range mounts {
		allNames[mount.Parent] = struct{}{}
		allNames[mount.Child] = struct{}{}
	}

	var resolveScopes func(name string, seen map[string]struct{}) []string
	resolveScopes = func(name string, seen map[string]struct{}) []string {
		name = strings.TrimSpace(name)
		if name == "" || strings.EqualFold(name, "app") {
			return []string{""}
		}
		if _, ok := seen[name]; ok {
			return nil
		}
		nextSeen := make(map[string]struct{}, len(seen)+1)
		for key := range seen {
			nextSeen[key] = struct{}{}
		}
		nextSeen[name] = struct{}{}
		scopes := []string{""}
		for _, mount := range mounts {
			if mount.Child != name {
				continue
			}
			for _, parentScope := range resolveScopes(mount.Parent, nextSeen) {
				scope := joinRoutePaths(parentScope, declaredPrefixes[mount.Parent])
				scope = joinRoutePaths(scope, mount.Prefix)
				scopes = append(scopes, scope)
			}
		}
		return uniqueStrings(scopes)
	}

	for name := range allNames {
		for _, localRoute := range localRoutes[name] {
			baseRoute := joinRoutePaths(declaredPrefixes[name], localRoute)
			for _, scope := range resolveScopes(name, nil) {
				route := joinRoutePaths(scope, baseRoute)
				if route != "" {
					routes = append(routes, route)
				}
			}
		}
	}
	return uniqueStrings(routes)
}

func extractNamedLocalRoutes(source string) map[string][]string {
	out := make(map[string][]string)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)@([A-Za-z_][A-Za-z0-9_]*)\.(?:get|post|put|delete|patch|route)\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)@([A-Za-z_][A-Za-z0-9_]*)\.api_route\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\[(?:["'](?:get|post|put|delete|patch|all)["']|[A-Za-z_][A-Za-z0-9_]*)\]\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.route\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.route\(["']([^"']+)["']\)\.(?:get|post|put|delete|patch|all)\(`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.add_url_rule\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.add_api_route\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.(?:get|post|put|delete|patch|all)\(["']([^"']+)["']`),
	}
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 3 {
				continue
			}
			name := strings.TrimSpace(match[1])
			route := normalizeRoutePath(match[2])
			if name == "" || route == "" {
				continue
			}
			out[name] = append(out[name], route)
		}
	}
	for name, routes := range out {
		out[name] = uniqueStrings(routes)
	}
	return out
}

func extractRouteMounts(source string) []routeMount {
	mounts := make([]routeMount, 0)
	appendMounts := func(pattern *regexp.Regexp, parentIdx, childIdx, prefixIdx int) {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			maxIndex := maxInt(parentIdx, childIdx)
			if prefixIdx > 0 {
				maxIndex = maxInt(maxIndex, prefixIdx)
			}
			if len(match) <= maxIndex {
				continue
			}
			parent := strings.TrimSpace(match[parentIdx])
			child := strings.TrimSpace(match[childIdx])
			prefix := ""
			if prefixIdx > 0 {
				prefix = normalizeRoutePath(match[prefixIdx])
			}
			if parent == "" || child == "" {
				continue
			}
			mounts = append(mounts, routeMount{Parent: parent, Child: child, Prefix: prefix})
		}
	}
	appendMounts(regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.use\(["']([^"']+)["']\s*,\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)`), 1, 3, 2)
	appendMounts(regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.include_router\(\s*([A-Za-z_][A-Za-z0-9_]*)[^\n]*prefix\s*=\s*["']([^"']+)["']`), 1, 2, 3)
	appendMounts(regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.include_router\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)`), 1, 2, -1)
	appendMounts(regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.include_router\([^\n]*router\s*=\s*([A-Za-z_][A-Za-z0-9_]*)[^\n]*prefix\s*=\s*["']([^"']+)["']`), 1, 2, 3)
	appendMounts(regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.include_router\([^\n]*prefix\s*=\s*["']([^"']+)["'][^\n]*router\s*=\s*([A-Za-z_][A-Za-z0-9_]*)`), 1, 3, 2)
	appendMounts(regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.include_router\([^\n]*router\s*=\s*([A-Za-z_][A-Za-z0-9_]*)[^\n]*\)`), 1, 2, -1)
	appendMounts(regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.register_blueprint\(\s*([A-Za-z_][A-Za-z0-9_]*)[^\n]*url_prefix\s*=\s*["']([^"']+)["']`), 1, 2, 3)
	appendMounts(regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.register_blueprint\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*(?:,|\))`), 1, 2, -1)
	appendMounts(regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.register_blueprint\([^\n]*blueprint\s*=\s*([A-Za-z_][A-Za-z0-9_]*)[^\n]*url_prefix\s*=\s*["']([^"']+)["']`), 1, 2, 3)
	appendMounts(regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.register_blueprint\([^\n]*blueprint\s*=\s*([A-Za-z_][A-Za-z0-9_]*)[^\n]*\)`), 1, 2, -1)
	for i := range mounts {
		if mounts[i].Prefix == "" {
			mounts[i].Prefix = "/"
		}
	}
	return mounts
}

func extractWebPorts(source string) []int {
	ports := make([]int, 0)
	portVars := extractPortVariableAssignments(source)
	portConfigFields := extractPortConfigFields(source)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)app\.run\([^\n]*port\s*=\s*(\d{2,5})`),
		regexp.MustCompile(`(?i)uvicorn\.run\([^\n]*port\s*=\s*(\d{2,5})`),
		regexp.MustCompile(`(?i)listen\(\s*(\d{2,5})\s*[,) ]`),
	}
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 2 {
				continue
			}
			port, err := strconv.Atoi(strings.TrimSpace(match[1]))
			if err != nil || port <= 0 || port > 65535 {
				continue
			}
			ports = append(ports, port)
		}
	}
	refPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)app\.run\([^\n]*port\s*=\s*([A-Za-z_][A-Za-z0-9_\.]*)`),
		regexp.MustCompile(`(?i)uvicorn\.run\([^\n]*port\s*=\s*([A-Za-z_][A-Za-z0-9_\.]*)`),
		regexp.MustCompile(`(?i)listen\(\s*([A-Za-z_][A-Za-z0-9_\.]*)\s*[,) ]`),
	}
	for _, pattern := range refPatterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 2 {
				continue
			}
			ref := strings.TrimSpace(match[1])
			if ref == "" {
				continue
			}
			if port, ok := portVars[ref]; ok {
				ports = append(ports, port)
				continue
			}
			if port, ok := portConfigFields[ref]; ok {
				ports = append(ports, port)
			}
		}
	}
	for _, line := range strings.Split(source, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "app.run(") || strings.Contains(line, "uvicorn.run(") {
			if expr := extractKeywordArgExpression(line, "port"); expr != "" {
				if port, ok := resolvePortExpression(expr, portVars, portConfigFields); ok {
					ports = append(ports, port)
				}
			}
		}
		if strings.Contains(line, "listen(") {
			if expr := extractFirstCallArgExpression(line, "listen("); expr != "" {
				if port, ok := resolvePortExpression(expr, portVars, portConfigFields); ok {
					ports = append(ports, port)
				}
			}
		}
	}
	return uniqueInts(ports)
}

func extractWebMethods(source string) []string {
	methods := make([]string, 0)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)@(?:[A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|delete|patch)\(["'][^"']+["']`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|delete|patch|all)\(["'][^"']+["']`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\[(?:["'](get|post|put|delete|patch|all)["']|[A-Za-z_][A-Za-z0-9_]*)\]\(["'][^"']+["']`),
		regexp.MustCompile(`(?i)methods\s*=\s*\[([^\]]+)\]`),
	}
	for i, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 2 {
				continue
			}
			if i == len(patterns)-1 {
				for _, methodMatch := range regexp.MustCompile(`["']([A-Za-z]+)["']`).FindAllStringSubmatch(match[1], -1) {
					if len(methodMatch) >= 2 {
						methods = appendHTTPMethod(methods, methodMatch[1])
					}
				}
				continue
			}
			methods = appendHTTPMethod(methods, match[1])
		}
	}
	return methods
}

func extractWebRouteMethods(source string) map[string][]string {
	out := make(map[string][]string)
	named := make(map[string]map[string][]string)
	appendOne := func(route, method string) {
		route = normalizeRoutePath(route)
		if route == "" {
			return
		}
		out[route] = appendHTTPMethod(out[route], method)
	}
	appendNamedOne := func(name, route, method string) {
		name = strings.TrimSpace(name)
		route = normalizeRoutePath(route)
		if name == "" || route == "" {
			return
		}
		if named[name] == nil {
			named[name] = map[string][]string{}
		}
		named[name][route] = appendHTTPMethod(named[name][route], method)
	}
	appendList := func(route, rawMethods string) {
		route = normalizeRoutePath(route)
		if route == "" {
			return
		}
		for _, methodMatch := range regexp.MustCompile(`["']([A-Za-z]+)["']`).FindAllStringSubmatch(rawMethods, -1) {
			if len(methodMatch) >= 2 {
				out[route] = appendHTTPMethod(out[route], methodMatch[1])
			}
		}
	}
	appendNamedList := func(name, route, rawMethods string) {
		for _, methodMatch := range regexp.MustCompile(`["']([A-Za-z]+)["']`).FindAllStringSubmatch(rawMethods, -1) {
			if len(methodMatch) >= 2 {
				appendNamedOne(name, route, methodMatch[1])
			}
		}
	}
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)@(?:[A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|delete|patch)\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|delete|patch|all)\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\[(?:["'](get|post|put|delete|patch|all)["']|[A-Za-z_][A-Za-z0-9_]*)\]\(["']([^"']+)["']`),
	} {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) >= 3 {
				appendOne(match[2], match[1])
			}
		}
	}
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)@([A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|delete|patch)\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.(get|post|put|delete|patch|all)\(["']([^"']+)["']`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\[(?:["'](get|post|put|delete|patch|all)["']|[A-Za-z_][A-Za-z0-9_]*)\]\(["']([^"']+)["']`),
	} {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) >= 4 {
				appendNamedOne(match[1], match[3], match[2])
			}
		}
	}
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)@(?:[A-Za-z_][A-Za-z0-9_]*)\.api_route\(["']([^"']+)["'][^\n]*methods\s*=\s*\[([^\]]+)\]`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\.add_api_route\(["']([^"']+)["'][^\n]*methods\s*=\s*\[([^\]]+)\]`),
		regexp.MustCompile(`(?i)(?:[A-Za-z_][A-Za-z0-9_]*)\.route\(["']([^"']+)["'][^\n]*methods\s*=\s*\[([^\]]+)\]`),
	} {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) >= 3 {
				appendList(match[1], match[2])
			}
		}
	}
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)@([A-Za-z_][A-Za-z0-9_]*)\.api_route\(["']([^"']+)["'][^\n]*methods\s*=\s*\[([^\]]+)\]`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.add_api_route\(["']([^"']+)["'][^\n]*methods\s*=\s*\[([^\]]+)\]`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\.route\(["']([^"']+)["'][^\n]*methods\s*=\s*\[([^\]]+)\]`),
	} {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) >= 4 {
				appendNamedList(match[1], match[2], match[3])
			}
		}
	}
	mergeStringSliceMap(out, extractNextStyleRoutes(source))
	declaredPrefixes := extractNamedRoutePrefixes(source,
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*Blueprint\([^\n]*url_prefix\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*APIRouter\([^\n]*prefix\s*=\s*["']([^"']+)["']`),
	)
	mounts := extractRouteMounts(source)
	allNames := make(map[string]struct{})
	for name := range named {
		allNames[name] = struct{}{}
	}
	for name := range declaredPrefixes {
		allNames[name] = struct{}{}
	}
	for _, mount := range mounts {
		allNames[mount.Parent] = struct{}{}
		allNames[mount.Child] = struct{}{}
	}
	var resolveScopes func(name string, seen map[string]struct{}) []string
	resolveScopes = func(name string, seen map[string]struct{}) []string {
		name = strings.TrimSpace(name)
		if name == "" || strings.EqualFold(name, "app") {
			return []string{""}
		}
		if _, ok := seen[name]; ok {
			return nil
		}
		nextSeen := make(map[string]struct{}, len(seen)+1)
		for key := range seen {
			nextSeen[key] = struct{}{}
		}
		nextSeen[name] = struct{}{}
		scopes := []string{""}
		for _, mount := range mounts {
			if mount.Child != name {
				continue
			}
			for _, parentScope := range resolveScopes(mount.Parent, nextSeen) {
				scope := joinRoutePaths(parentScope, declaredPrefixes[mount.Parent])
				scope = joinRoutePaths(scope, mount.Prefix)
				scopes = append(scopes, scope)
			}
		}
		return uniqueStrings(scopes)
	}
	for name := range allNames {
		for localRoute, methods := range named[name] {
			baseRoute := joinRoutePaths(declaredPrefixes[name], localRoute)
			for _, scope := range resolveScopes(name, nil) {
				joined := joinRoutePaths(scope, baseRoute)
				if joined != "" {
					for _, method := range methods {
						out[joined] = appendHTTPMethod(out[joined], method)
					}
				}
			}
		}
	}
	return normalizeRouteMethods(out)
}

func extractWebQueryParams(source string) []string {
	params := make([]string, 0)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)request\.args\.get\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)request\.query_params\.get\(\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)req\.query\.([A-Za-z_][A-Za-z0-9_]*)`),
		regexp.MustCompile(`(?i)req\.query\[["']([^"']+)["']\]`),
		regexp.MustCompile(`(?i)URLSearchParams\([^\n]*\)\.get\(\s*["']([^"']+)["']`),
	}
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 2 {
				continue
			}
			param := sanitizeQueryParamName(match[1])
			if param != "" && !stringSliceContains(params, param) {
				params = append(params, param)
			}
		}
	}
	return params
}

func appendPathMethods(routeMethods map[string][]string, path string, methods ...string) {
	if routeMethods == nil {
		return
	}
	path = normalizeRoutePath(path)
	if path == "" {
		return
	}
	for _, method := range methods {
		routeMethods[path] = appendHTTPMethod(routeMethods[path], method)
	}
}

func extractPythonWebAppRefs(source string) []string {
	refs := make([]string, 0)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:FastAPI|Flask)\s*\(`),
		regexp.MustCompile(`(?m)^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*create_app\s*\(`),
	}
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 2 {
				continue
			}
			name := strings.TrimSpace(match[1])
			if name != "" {
				refs = append(refs, name)
			}
		}
	}
	if strings.Contains(strings.ToLower(source), "from fastapi import") || strings.Contains(strings.ToLower(source), "fastapi(") {
		refs = append(refs, "app")
	}
	return uniqueStrings(refs)
}

func extractPortVariableAssignments(source string) map[string]int {
	resolved := make(map[string]int)
	refs := make(map[string]string)
	exprs := make(map[string]string)
	configFields := extractPortConfigFields(source)
	assignPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d{2,5})\b`),
		regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\d{2,5})\b`),
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*os\.getenv\([^\n]*?,\s*["']?(\d{2,5})["']?\s*\)`),
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*os\.environ\.get\([^\n]*?,\s*["']?(\d{2,5})["']?\s*\)`),
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*getenv\([^\n]*?,\s*["']?(\d{2,5})["']?\s*\)`),
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*int\(\s*os\.getenv\([^\n]*?,\s*["']?(\d{2,5})["']?\s*\)\s*\)`),
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*int\(\s*os\.environ\.get\([^\n]*?,\s*["']?(\d{2,5})["']?\s*\)\s*\)`),
		regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*process\.env\.[A-Za-z_][A-Za-z0-9_]*\s*\|\|\s*(\d{2,5})\b`),
		regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*process\.env\.[A-Za-z_][A-Za-z0-9_]*\s*\?\?\s*(\d{2,5})\b`),
		regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*parseInt\(process\.env\.[A-Za-z_][A-Za-z0-9_]*\s*\|\|\s*["'](\d{2,5})["']`),
		regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*parseInt\(process\.env\.[A-Za-z_][A-Za-z0-9_]*\s*\?\?\s*["'](\d{2,5})["']`),
		regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*Number\(process\.env\.[A-Za-z_][A-Za-z0-9_]*\s*\|\|\s*["']?(\d{2,5})["']?\)`),
	}
	for _, pattern := range assignPatterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 3 {
				continue
			}
			port, err := strconv.Atoi(strings.TrimSpace(match[2]))
			if err != nil || port <= 0 || port > 65535 {
				continue
			}
			resolved[strings.TrimSpace(match[1])] = port
		}
	}
	assignmentExprPattern := regexp.MustCompile(`(?m)^(?:(?:const|let|var)\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$`)
	for _, match := range assignmentExprPattern.FindAllStringSubmatch(source, -1) {
		if len(match) < 3 {
			continue
		}
		left := strings.TrimSpace(match[1])
		right := strings.TrimSpace(match[2])
		if left == "" || right == "" {
			continue
		}
		right = strings.TrimSpace(strings.TrimSuffix(right, ";"))
		if port, ok := resolvePortExpression(right, resolved, configFields); ok {
			resolved[left] = port
			continue
		}
		exprs[left] = right
	}
	refPatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_\.]*)\b`),
		regexp.MustCompile(`(?m)(?:const|let|var)\s+([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_\.]*)\b`),
	}
	for _, pattern := range refPatterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 3 {
				continue
			}
			left := strings.TrimSpace(match[1])
			right := strings.TrimSpace(match[2])
			if left == "" || right == "" || left == right {
				continue
			}
			refs[left] = right
		}
	}
	for i := 0; i < 4; i++ {
		changed := false
		for left, right := range exprs {
			if _, ok := resolved[left]; ok {
				continue
			}
			if port, ok := resolvePortExpression(right, resolved, configFields); ok {
				resolved[left] = port
				changed = true
			}
		}
		for left, right := range refs {
			if _, ok := resolved[left]; ok {
				continue
			}
			if port, ok := resolved[right]; ok {
				resolved[left] = port
				changed = true
				continue
			}
			if port, ok := configFields[right]; ok {
				resolved[left] = port
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return resolved
}

func resolvePortExpression(expr string, portVars map[string]int, portConfigFields map[string]int) (int, bool) {
	expr = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(expr), ";"))
	if expr == "" {
		return 0, false
	}
	if port, err := strconv.Atoi(strings.Trim(expr, `"'`)); err == nil && port > 0 && port <= 65535 {
		return port, true
	}
	if port, ok := portVars[expr]; ok {
		return port, true
	}
	if port, ok := portConfigFields[expr]; ok {
		return port, true
	}
	for _, pattern := range []*regexp.Regexp{
		regexp.MustCompile(`(?i)^(?:int|Number|parseInt)\((.+)\)$`),
		regexp.MustCompile(`(?i)^[A-Za-z_][A-Za-z0-9_\.]*\.get\(\s*["'][^"']+["']\s*,\s*(.+)\)$`),
		regexp.MustCompile(`(?i)^os\.getenv\([^\n]*?,\s*(.+)\)$`),
		regexp.MustCompile(`(?i)^os\.environ\.get\([^\n]*?,\s*(.+)\)$`),
		regexp.MustCompile(`(?i)^getenv\([^\n]*?,\s*(.+)\)$`),
		regexp.MustCompile(`(?i)^process\.env\.[A-Za-z_][A-Za-z0-9_]*\s*(?:\|\||\?\?)\s*(.+)$`),
	} {
		if match := pattern.FindStringSubmatch(expr); len(match) >= 2 {
			inner := strings.TrimSpace(match[1])
			if idx := strings.LastIndex(inner, ","); strings.Contains(pattern.String(), `parseInt`) && idx >= 0 {
				inner = strings.TrimSpace(inner[:idx])
			}
			return resolvePortExpression(inner, portVars, portConfigFields)
		}
	}
	if parts := strings.SplitN(expr, "??", 2); len(parts) == 2 {
		return resolvePortExpression(strings.TrimSpace(parts[1]), portVars, portConfigFields)
	}
	if parts := strings.SplitN(expr, "||", 2); len(parts) == 2 {
		return resolvePortExpression(strings.TrimSpace(parts[1]), portVars, portConfigFields)
	}
	return 0, false
}

func extractKeywordArgExpression(line string, key string) string {
	idx := strings.Index(line, key+"=")
	if idx < 0 {
		return ""
	}
	return extractDelimitedExpression(line[idx+len(key)+1:])
}

func extractFirstCallArgExpression(line string, call string) string {
	idx := strings.Index(line, call)
	if idx < 0 {
		return ""
	}
	return extractDelimitedExpression(line[idx+len(call):])
}

func extractDelimitedExpression(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	depth := 0
	inSingle := false
	inDouble := false
	for i, r := range raw {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '(':
			if !inSingle && !inDouble {
				depth++
			}
		case ')':
			if !inSingle && !inDouble {
				if depth == 0 {
					return strings.TrimSpace(raw[:i])
				}
				depth--
			}
		case ',':
			if !inSingle && !inDouble && depth == 0 {
				return strings.TrimSpace(raw[:i])
			}
		}
	}
	return strings.TrimSpace(raw)
}

func extractPortConfigFields(source string) map[string]int {
	out := make(map[string]int)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{[^\n]*port\s*:\s*(\d{2,5})`),
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{[^\n]*["']port["']\s*:\s*(\d{2,5})`),
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{[^\n]*port\s*:\s*process\.env\.[A-Za-z_][A-Za-z0-9_]*\s*\|\|\s*(\d{2,5})`),
		regexp.MustCompile(`(?s)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{.*?server\s*:\s*\{.*?port\s*:\s*(\d{2,5})`),
		regexp.MustCompile(`(?s)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*\{.*?server\s*:\s*\{.*?["']port["']\s*:\s*(\d{2,5})`),
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\.server\.port\s*=\s*(\d{2,5})\b`),
		regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\.port\s*=\s*(\d{2,5})\b`),
	}
	for _, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 3 {
				continue
			}
			port, err := strconv.Atoi(strings.TrimSpace(match[2]))
			if err != nil || port <= 0 || port > 65535 {
				continue
			}
			name := strings.TrimSpace(match[1])
			if name == "" {
				continue
			}
			out[name+".port"] = port
			if strings.Contains(pattern.String(), `server`) {
				out[name+".server.port"] = port
			}
		}
	}
	aliasPattern := regexp.MustCompile(`(?m)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\b`)
	aliases := make(map[string]string)
	for _, match := range aliasPattern.FindAllStringSubmatch(source, -1) {
		if len(match) < 3 {
			continue
		}
		left := strings.TrimSpace(match[1])
		right := strings.TrimSpace(match[2])
		if left == "" || right == "" || left == right {
			continue
		}
		aliases[left] = right
	}
	for i := 0; i < 4; i++ {
		changed := false
		for left, right := range aliases {
			for key, port := range out {
				prefix := right + "."
				if !strings.HasPrefix(key, prefix) {
					continue
				}
				aliasKey := left + "." + strings.TrimPrefix(key, prefix)
				if _, ok := out[aliasKey]; ok {
					continue
				}
				out[aliasKey] = port
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	return out
}

func uniqueInts(items []int) []int {
	seen := make(map[int]struct{}, len(items))
	out := make([]int, 0, len(items))
	for _, item := range items {
		if item <= 0 {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	return out
}

func intSliceToStrings(items []int) []string {
	out := make([]string, 0, len(items))
	for _, item := range items {
		out = append(out, strconv.Itoa(item))
	}
	return out
}

func computeSandboxScore(profile review.BehaviorProfile) int {
	score := 0
	score += minInt(3, len(profile.ExecuteIOCs))
	score += minInt(2, len(profile.OutboundIOCs))
	score += minInt(2, len(profile.CredentialIOCs))
	score += minInt(2, len(profile.PersistenceIOCs))
	if len(profile.DefenseEvasionIOCs) > 0 || len(profile.C2BeaconIOCs) > 0 {
		score += 2
	}
	if score > 10 {
		return 10
	}
	return score
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
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

func appendUniqueWarning(warnings []string, msg string) []string {
	msg = strings.TrimSpace(msg)
	if msg == "" {
		return warnings
	}
	for _, item := range warnings {
		if strings.TrimSpace(item) == msg {
			return warnings
		}
	}
	return append(warnings, msg)
}

func inferMissingModuleWarnings(lines []string, scenarioName string) []string {
	modules := missingPythonModulesFromLines(lines)
	if len(modules) == 0 {
		return nil
	}
	warnings := make([]string, 0, len(modules))
	for _, module := range modules {
		pkg := pythonModuleInstallPackage(module)
		if pkg == "" {
			warnings = append(warnings, fmt.Sprintf("场景 %s 缺少 Python 模块 %s，HTTP 探针可能无法启动服务", scenarioName, module))
			continue
		}
		warnings = append(warnings, fmt.Sprintf("场景 %s 缺少 Python 模块 %s，建议在沙箱镜像或依赖文件中提供 pip 包 %s", scenarioName, module, pkg))
	}
	return warnings
}

func missingPythonModulesFromLines(lines []string) []string {
	modules := make([]string, 0)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)No module named ['"]([^'"]+)['"]`),
		regexp.MustCompile(`(?i)ModuleNotFoundError:\s*No module named ['"]([^'"]+)['"]`),
	}
	for _, line := range lines {
		for _, pattern := range patterns {
			for _, match := range pattern.FindAllStringSubmatch(line, -1) {
				if len(match) < 2 {
					continue
				}
				module := normalizePythonModuleName(match[1])
				if module != "" && !stringSliceContains(modules, module) {
					modules = append(modules, module)
				}
			}
		}
	}
	return modules
}

func inferDependencyManifestWarnings(scanPath string, lines []string, scenarioName string) []string {
	modules := missingPythonModulesFromLines(lines)
	if len(modules) == 0 {
		return nil
	}
	pythonDeps := readPythonDependencyManifestPackages(scanPath)
	nodeDeps := readNodeDependencyManifestPackages(scanPath)
	warnings := make([]string, 0, len(modules))
	for _, module := range modules {
		pkg := pythonModuleInstallPackage(module)
		if stringSliceContainsFold(pythonDeps, pkg) || stringSliceContainsFold(pythonDeps, module) {
			warnings = append(warnings, fmt.Sprintf("场景 %s 依赖文件声明了 %s 但沙箱运行缺少模块 %s，建议检查镜像依赖安装步骤", scenarioName, pkg, module))
		} else {
			warnings = append(warnings, fmt.Sprintf("场景 %s 依赖文件未声明 %s，建议补齐 requirements.txt 或 pyproject.toml 后复测", scenarioName, pkg))
		}
	}
	if hasNodeDependencyManifest(scanPath) && len(nodeDeps) > 0 && len(pythonDeps) == 0 {
		warnings = appendUniqueWarning(warnings, fmt.Sprintf("场景 %s 检测到 package.json 依赖声明，当前缺失为 Python 模块，建议确认入口语言或依赖文件匹配", scenarioName))
	}
	return warnings
}

func readPythonDependencyManifestPackages(scanPath string) []string {
	packages := make([]string, 0)
	for _, rel := range []string{"requirements.txt", "pyproject.toml"} {
		data, err := os.ReadFile(filepath.Join(scanPath, rel))
		if err != nil {
			continue
		}
		packages = append(packages, extractDependencyNamesFromManifest(string(data))...)
	}
	return uniqueStrings(packages)
}

func readNodeDependencyManifestPackages(scanPath string) []string {
	data, err := os.ReadFile(filepath.Join(scanPath, "package.json"))
	if err != nil {
		return nil
	}
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return nil
	}
	packages := make([]string, 0, len(pkg.Dependencies)+len(pkg.DevDependencies)+len(pkg.OptionalDependencies))
	for name := range pkg.Dependencies {
		packages = append(packages, name)
	}
	for name := range pkg.DevDependencies {
		packages = append(packages, name)
	}
	for name := range pkg.OptionalDependencies {
		packages = append(packages, name)
	}
	return uniqueStrings(packages)
}

func hasNodeDependencyManifest(scanPath string) bool {
	_, err := os.Stat(filepath.Join(scanPath, "package.json"))
	return err == nil
}

func extractDependencyNamesFromManifest(text string) []string {
	packages := make([]string, 0)
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "[") {
			continue
		}
		if strings.Contains(line, "=") && !strings.Contains(line, "==") && !strings.Contains(line, ">=") && !strings.Contains(line, "<=") {
			parts := strings.SplitN(line, "=", 2)
			line = strings.Trim(strings.TrimSpace(parts[0]), `"'`)
		}
		line = strings.Trim(strings.TrimSpace(line), `"',`)
		if idx := strings.IndexAny(line, "<>=!~[ ;"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		line = strings.Trim(strings.TrimSpace(line), `"',`)
		if line != "" && regexp.MustCompile(`^[A-Za-z0-9_.-]+$`).MatchString(line) {
			packages = append(packages, strings.ToLower(line))
		}
	}
	return uniqueStrings(packages)
}

func stringSliceContainsFold(items []string, target string) bool {
	target = strings.ToLower(strings.TrimSpace(target))
	if target == "" {
		return false
	}
	for _, item := range items {
		if strings.ToLower(strings.TrimSpace(item)) == target {
			return true
		}
	}
	return false
}

func normalizePythonModuleName(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parts := strings.Split(raw, ".")
	return strings.TrimSpace(parts[0])
}

func pythonModuleInstallPackage(module string) string {
	switch strings.ToLower(strings.TrimSpace(module)) {
	case "flask":
		return "flask"
	case "fastapi":
		return "fastapi"
	case "uvicorn":
		return "uvicorn"
	case "starlette":
		return "starlette"
	case "pydantic":
		return "pydantic"
	case "requests":
		return "requests"
	default:
		return module
	}
}

func matchCodePattern(scanPath string, pattern *regexp.Regexp) bool {
	if pattern == nil {
		return false
	}
	hit := false
	_ = filepath.Walk(scanPath, func(path string, info os.FileInfo, err error) error {
		if hit || err != nil || info == nil || info.IsDir() || !isSandboxSignalFile(path) {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if pattern.Match(data) {
			hit = true
		}
		return nil
	})
	return hit
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
	if opts.Context == nil {
		opts.Context = context.Background()
	}
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

func stringSliceContains(items []string, target string) bool {
	for _, item := range items {
		if item == target {
			return true
		}
	}
	return false
}

func intSliceContains(items []int, target int) bool {
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

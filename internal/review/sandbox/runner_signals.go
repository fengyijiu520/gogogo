package sandbox

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

type replaySignalSet struct {
	CLIArgv        bool
	StdinInput     bool
	EnvInput       bool
	WebServer      bool
	WebRoutes      []string
	WebPorts       []int
	WebAppRefs     []string
	WebMethods     []string
	WebQueries     []string
	WebPathMethods map[string][]string
}

type replaySignalDetector struct {
	scanPath    string
	sourceCache map[string]string
	signalCache map[string]replaySignalSet
	webCache    map[string]cachedWebSignals

	SourceReads int
	SignalHits  int
	SignalMiss  int
	WebHits     int
	WebMiss     int
}

type cachedWebSignals struct {
	Routes       []string
	Ports        []int
	AppRefs      []string
	Methods      []string
	Queries      []string
	NamedRoutes  map[string][]string
	RouteMethods map[string][]string
}

type neighborPythonSource struct {
	Name   string
	Source string
}

type entrypointMount struct {
	Target     string
	Prefix     string
	ImportHint string
}

func newReplaySignalDetector(scanPath string) *replaySignalDetector {
	return &replaySignalDetector{scanPath: scanPath, sourceCache: map[string]string{}, signalCache: map[string]replaySignalSet{}, webCache: map[string]cachedWebSignals{}}
}

func detectEntrypointReplaySignals(scanPath string, relPath string) replaySignalSet {
	return newReplaySignalDetector(scanPath).detect(relPath)
}

func (d *replaySignalDetector) detect(relPath string) replaySignalSet {
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	if relPath == "" {
		return replaySignalSet{}
	}
	if cached, ok := d.signalCache[relPath]; ok {
		d.SignalHits++
		return cloneReplaySignalSet(cached)
	}
	d.SignalMiss++
	source, ok := d.readSource(relPath)
	if !ok {
		return replaySignalSet{}
	}
	text := strings.ToLower(source)
	webSignals := d.webSignals(relPath, source)
	signals := replaySignalSet{
		CLIArgv:        strings.Contains(text, "argparse") || strings.Contains(text, "click") || strings.Contains(text, "process.argv") || strings.Contains(text, "$1") || strings.Contains(text, "$@") == true,
		StdinInput:     strings.Contains(text, "sys.stdin") || strings.Contains(text, "process.stdin") || strings.Contains(text, "input(") || strings.Contains(text, "read ") || strings.Contains(text, "read -r"),
		EnvInput:       strings.Contains(text, "os.getenv") || strings.Contains(text, "getenv(") || strings.Contains(text, "process.env") || strings.Contains(text, "input_file") || strings.Contains(text, "$input_file") || strings.Contains(text, "${input_file}"),
		WebServer:      strings.Contains(text, "flask(") || strings.Contains(text, "from flask import") || strings.Contains(text, "fastapi(") || strings.Contains(text, "from fastapi import") || strings.Contains(text, "express(") || strings.Contains(text, "require('express')") || strings.Contains(text, "from http.server import") || strings.Contains(text, "http.server"),
		WebRoutes:      append([]string{}, webSignals.Routes...),
		WebPorts:       append([]int{}, webSignals.Ports...),
		WebAppRefs:     append([]string{}, webSignals.AppRefs...),
		WebMethods:     append([]string{}, webSignals.Methods...),
		WebQueries:     append([]string{}, webSignals.Queries...),
		WebPathMethods: cloneStringSliceMap(webSignals.RouteMethods),
	}
	if filepath.Ext(relPath) == ".py" && signals.WebServer {
		neighbors := d.collectNeighborPythonSources(relPath, 8)
		mounts := extractEntrypointMounts(source)
		for _, neighbor := range neighbors {
			neighborSignals := d.webSignals(neighbor.Name, neighbor.Source)
			signals.WebRoutes = uniqueStrings(append(signals.WebRoutes, neighborSignals.Routes...))
			for _, mount := range mounts {
				routes := neighborSignals.NamedRoutes[mount.Target]
				if len(routes) == 0 && mount.ImportHint != "" && strings.EqualFold(strings.TrimSuffix(filepath.Base(neighbor.Name), filepath.Ext(neighbor.Name)), mount.ImportHint) {
					routes = neighborSignals.Routes
				}
				for _, route := range routes {
					joined := joinRoutePaths(mount.Prefix, route)
					if joined != "" {
						signals.WebRoutes = append(signals.WebRoutes, joined)
					}
				}
			}
			signals.WebRoutes = uniqueStrings(signals.WebRoutes)
			signals.WebPorts = uniqueInts(append(signals.WebPorts, neighborSignals.Ports...))
			signals.WebAppRefs = uniqueStrings(append(signals.WebAppRefs, neighborSignals.AppRefs...))
			signals.WebMethods = uniqueStrings(append(signals.WebMethods, neighborSignals.Methods...))
			signals.WebQueries = uniqueStrings(append(signals.WebQueries, neighborSignals.Queries...))
			mergeStringSliceMap(signals.WebPathMethods, neighborSignals.RouteMethods)
			for _, mount := range mounts {
				for _, route := range neighborSignals.NamedRoutes[mount.Target] {
					joined := joinRoutePaths(mount.Prefix, route)
					if joined != "" {
						appendPathMethods(signals.WebPathMethods, joined, neighborSignals.RouteMethods[route]...)
					}
				}
			}
		}
	}
	signals.WebRoutes = expandRoutesWithQueryParams(signals.WebRoutes, signals.WebQueries)
	signals.WebPathMethods = expandRouteMethodsWithQueryParams(signals.WebPathMethods, signals.WebQueries)
	d.signalCache[relPath] = cloneReplaySignalSet(signals)
	return signals
}

func (d *replaySignalDetector) readSource(relPath string) (string, bool) {
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	if cached, ok := d.sourceCache[relPath]; ok {
		return cached, true
	}
	data, err := os.ReadFile(filepath.Join(d.scanPath, relPath))
	if err != nil {
		return "", false
	}
	source := string(data)
	d.sourceCache[relPath] = source
	d.SourceReads++
	return source, true
}

func (d *replaySignalDetector) webSignals(relPath string, source string) cachedWebSignals {
	relPath = filepath.ToSlash(strings.TrimSpace(relPath))
	if cached, ok := d.webCache[relPath]; ok {
		d.WebHits++
		return cloneCachedWebSignals(cached)
	}
	d.WebMiss++
	signals := cachedWebSignals{Routes: extractWebRoutes(source), Ports: extractWebPorts(source), AppRefs: extractPythonWebAppRefs(source), Methods: extractWebMethods(source), Queries: extractWebQueryParams(source), NamedRoutes: extractNamedLocalRoutes(source), RouteMethods: extractWebRouteMethods(source)}
	fileRoute := routePathFromFile(relPath)
	if fileRoute != "" && strings.Contains(strings.ToLower(relPath), "/api/") {
		signals.Routes = uniqueStrings(append(signals.Routes, fileRoute))
		for _, methods := range extractNextStyleRoutes(source) {
			for _, method := range methods {
				appendPathMethods(signals.RouteMethods, fileRoute, method)
			}
		}
	}
	d.webCache[relPath] = cloneCachedWebSignals(signals)
	return signals
}

func cloneReplaySignalSet(in replaySignalSet) replaySignalSet {
	return replaySignalSet{CLIArgv: in.CLIArgv, StdinInput: in.StdinInput, EnvInput: in.EnvInput, WebServer: in.WebServer, WebRoutes: append([]string{}, in.WebRoutes...), WebPorts: append([]int{}, in.WebPorts...), WebAppRefs: append([]string{}, in.WebAppRefs...), WebMethods: append([]string{}, in.WebMethods...), WebQueries: append([]string{}, in.WebQueries...), WebPathMethods: cloneStringSliceMap(in.WebPathMethods)}
}

func cloneCachedWebSignals(in cachedWebSignals) cachedWebSignals {
	out := cachedWebSignals{Routes: append([]string{}, in.Routes...), Ports: append([]int{}, in.Ports...), AppRefs: append([]string{}, in.AppRefs...), Methods: append([]string{}, in.Methods...), Queries: append([]string{}, in.Queries...), NamedRoutes: map[string][]string{}, RouteMethods: cloneStringSliceMap(in.RouteMethods)}
	for key, routes := range in.NamedRoutes {
		out.NamedRoutes[key] = append([]string{}, routes...)
	}
	return out
}

func extractEntrypointMounts(source string) []entrypointMount {
	mounts := make([]entrypointMount, 0)
	importHints := extractPythonImportHints(source)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)include_router\(\s*([A-Za-z_][A-Za-z0-9_]*)[^\n]*prefix\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)include_router\([^\n]*router\s*=\s*([A-Za-z_][A-Za-z0-9_]*)[^\n]*prefix\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)include_router\([^\n]*prefix\s*=\s*["']([^"']+)["'][^\n]*router\s*=\s*([A-Za-z_][A-Za-z0-9_]*)`),
		regexp.MustCompile(`(?i)register_blueprint\(\s*([A-Za-z_][A-Za-z0-9_]*)[^\n]*url_prefix\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)register_blueprint\([^\n]*blueprint\s*=\s*([A-Za-z_][A-Za-z0-9_]*)[^\n]*url_prefix\s*=\s*["']([^"']+)["']`),
		regexp.MustCompile(`(?i)register_blueprint\([^\n]*url_prefix\s*=\s*["']([^"']+)["'][^\n]*blueprint\s*=\s*([A-Za-z_][A-Za-z0-9_]*)`),
	}
	for i, pattern := range patterns {
		for _, match := range pattern.FindAllStringSubmatch(source, -1) {
			if len(match) < 3 {
				continue
			}
			target := strings.TrimSpace(match[1])
			prefix := normalizeRoutePath(match[2])
			if i == 2 || i == 5 {
				target = strings.TrimSpace(match[2])
				prefix = normalizeRoutePath(match[1])
			}
			if target != "" && prefix != "" {
				mounts = append(mounts, entrypointMount{Target: target, Prefix: prefix, ImportHint: importHints[target]})
			}
		}
	}
	return uniqueEntrypointMounts(mounts)
}

func extractPythonImportHints(source string) map[string]string {
	hints := make(map[string]string)
	patterns := []*regexp.Regexp{
		regexp.MustCompile(`(?m)^\s*from\s+\.?([A-Za-z_][A-Za-z0-9_]*)\s+import\s+([^\n]+)$`),
		regexp.MustCompile(`(?m)^\s*import\s+\.?([A-Za-z_][A-Za-z0-9_]*)(?:\s+as\s+([A-Za-z_][A-Za-z0-9_]*))?\s*$`),
	}
	for _, match := range patterns[0].FindAllStringSubmatch(source, -1) {
		if len(match) < 3 {
			continue
		}
		module := strings.TrimSpace(match[1])
		for _, part := range strings.Split(match[2], ",") {
			name := strings.TrimSpace(part)
			if pieces := strings.Split(name, " as "); len(pieces) == 2 {
				name = strings.TrimSpace(pieces[1])
			}
			if module != "" && name != "" {
				hints[name] = module
			}
		}
	}
	for _, match := range patterns[1].FindAllStringSubmatch(source, -1) {
		if len(match) < 2 {
			continue
		}
		module := strings.TrimSpace(match[1])
		name := module
		if len(match) >= 3 && strings.TrimSpace(match[2]) != "" {
			name = strings.TrimSpace(match[2])
		}
		if module != "" && name != "" {
			hints[name] = module
		}
	}
	return hints
}

func uniqueEntrypointMounts(items []entrypointMount) []entrypointMount {
	seen := make(map[string]struct{}, len(items))
	out := make([]entrypointMount, 0, len(items))
	for _, item := range items {
		key := item.Target + "\x00" + item.Prefix + "\x00" + item.ImportHint
		if strings.TrimSpace(item.Target) == "" || strings.TrimSpace(item.Prefix) == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	return out
}

func collectNeighborPythonSources(scanPath string, relPath string, maxFiles int) []neighborPythonSource {
	return newReplaySignalDetector(scanPath).collectNeighborPythonSources(relPath, maxFiles)
}

func (d *replaySignalDetector) collectNeighborPythonSources(relPath string, maxFiles int) []neighborPythonSource {
	if maxFiles <= 0 {
		return nil
	}
	dirRel := filepath.ToSlash(filepath.Dir(filepath.ToSlash(relPath)))
	dir := filepath.Join(d.scanPath, dirRel)
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	sources := make([]neighborPythonSource, 0, maxFiles)
	current := filepath.Base(relPath)
	for _, entry := range entries {
		if entry.IsDir() || strings.EqualFold(entry.Name(), current) || filepath.Ext(entry.Name()) != ".py" {
			continue
		}
		if strings.HasSuffix(strings.ToLower(entry.Name()), "_test.py") || strings.HasPrefix(strings.ToLower(entry.Name()), "test_") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.Size() > 512*1024 {
			continue
		}
		relNeighbor := filepath.ToSlash(filepath.Join(dirRel, entry.Name()))
		source, ok := d.readSource(relNeighbor)
		if !ok {
			continue
		}
		sources = append(sources, neighborPythonSource{Name: relNeighbor, Source: source})
		if len(sources) >= maxFiles {
			break
		}
	}
	return sources
}

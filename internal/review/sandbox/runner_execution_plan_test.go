package sandbox

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildExecutionPlanIncludesScenarioVariants(t *testing.T) {
	dir := t.TempDir()
	fixtures := map[string]string{
		"main.py":      "import argparse\nprint(input())\n",
		"bootstrap.sh": "read payload\necho $1\necho $INPUT_FILE\n",
	}
	for file, content := range fixtures {
		path := dir + "/" + file
		if err := os.WriteFile(path, []byte(content), 0600); err != nil {
			t.Fatalf("write fixture %s: %v", file, err)
		}
	}
	r := NewRunner()
	plan := r.BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "probe warning"})
	if len(plan.Scenarios) < 4 {
		t.Fatalf("expected multiple scenarios, got %+v", plan.Scenarios)
	}
	names := make([]string, 0, len(plan.Scenarios))
	for _, scenario := range plan.Scenarios {
		names = append(names, scenario.Name)
	}
	joined := strings.Join(names, ",")
	for _, want := range []string{"default", "python-main", "shell-bootstrap", "python-main-input-sample", "python-main-stdin-sample", "shell-bootstrap-input-sample", "shell-bootstrap-env-input", "env-debug", "input-sample"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected scenario %s in %s", want, joined)
		}
	}
}

func TestUniqueScenarioPlanKeepsDistinctCommandVariants(t *testing.T) {
	items := []ExecutionScenario{
		{Name: "python-main", Command: "python3", Args: []string{"main.py"}},
		{Name: "python-main", Command: "python3", Args: []string{"main.py"}},
		{Name: "python-main", Command: "python3", Args: []string{"main.py", "--debug"}},
	}
	got := uniqueScenarioPlan(items)
	if len(got) != 2 {
		t.Fatalf("expected 2 distinct scenarios, got %d: %+v", len(got), got)
	}
}

func TestBuildExecutionPlanUsesInterpreterCommands(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(dir+"/main.py", []byte("import argparse\nprint('ok')\n"), 0600); err != nil {
		t.Fatalf("write python fixture: %v", err)
	}
	if err := os.WriteFile(dir+"/start.sh", []byte("echo $1\n"), 0600); err != nil {
		t.Fatalf("write shell fixture: %v", err)
	}
	r := NewRunner()
	plan := r.BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "retry"})
	seen := map[string]ExecutionScenario{}
	for _, scenario := range plan.Scenarios {
		seen[scenario.Name] = scenario
	}
	if got := seen["python-main"]; got.Command != "python3" || len(got.Args) != 1 || got.Args[0] != "main.py" {
		t.Fatalf("unexpected python-main scenario: %+v", got)
	}
	if got := seen["shell-start"]; got.Command != "/bin/sh" || len(got.Args) != 1 || got.Args[0] != "start.sh" {
		t.Fatalf("unexpected shell-start scenario: %+v", got)
	}
	if got := seen["python-main"]; got.Env["CLI_MODE"] != "1" || got.Env["PYTHONUNBUFFERED"] != "1" {
		t.Fatalf("expected python-main cli env, got %+v", got)
	}
}

func TestDetectEntrypointReplaySignals(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "main.py"), []byte("import argparse\nimport os\nprint(input())\nprint(os.getenv('INPUT_FILE'))\n"), 0600); err != nil {
		t.Fatalf("write python signal fixture: %v", err)
	}
	signals := detectEntrypointReplaySignals(dir, "main.py")
	if !signals.CLIArgv || !signals.StdinInput || !signals.EnvInput {
		t.Fatalf("unexpected replay signals: %+v", signals)
	}
}

func TestDetectEntrypointReplaySignalsRecognizesWebServer(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("from flask import Flask\napp = Flask(__name__)\n@app.get('/health')\ndef health():\n    return 'ok'\napp.run(port=5001)\n"), 0600); err != nil {
		t.Fatalf("write web signal fixture: %v", err)
	}
	signals := detectEntrypointReplaySignals(dir, "app.py")
	if !signals.WebServer {
		t.Fatalf("expected web server signal, got %+v", signals)
	}
	if len(signals.WebRoutes) != 1 || signals.WebRoutes[0] != "/health" {
		t.Fatalf("expected extracted web route, got %+v", signals.WebRoutes)
	}
	if len(signals.WebPorts) != 1 || signals.WebPorts[0] != 5001 {
		t.Fatalf("expected extracted web port, got %+v", signals.WebPorts)
	}
}

func TestBuildExecutionPlanAddsHTTPProbeVariant(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("from flask import Flask\napp = Flask(__name__)\n@app.get('/health')\ndef health():\n    return 'ok'\napp.run(port=5001)\n"), 0600); err != nil {
		t.Fatalf("write flask fixture: %v", err)
	}
	r := NewRunner()
	plan := r.BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "retry"})
	found := false
	for _, scenario := range plan.Scenarios {
		if scenario.Name == "python-app-http-probe" {
			found = true
			if scenario.Env["SERVER_MODE"] != "1" || scenario.Env["HTTP_PROBE"] != "1" {
				t.Fatalf("expected http probe env, got %+v", scenario)
			}
			if len(scenario.HTTPPaths) != 1 || scenario.HTTPPaths[0] != "/health" {
				t.Fatalf("expected extracted http paths, got %+v", scenario.HTTPPaths)
			}
			if len(scenario.HTTPPorts) == 0 || scenario.HTTPPorts[0] != 5001 {
				t.Fatalf("expected extracted http ports, got %+v", scenario.HTTPPorts)
			}
			if scenario.Command != "python3" || len(scenario.Args) != 1 || scenario.Args[0] != "app.py" {
				t.Fatalf("expected http probe command, got %+v", scenario)
			}
		}
	}
	if !found {
		t.Fatalf("expected http probe variant in %+v", plan.Scenarios)
	}
}

func TestBuildExecutionPlanAddsFrameworkServerVariantsAndDefaultPorts(t *testing.T) {
	dir := t.TempDir()
	source := "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef health():\n    return {'ok': True}\n"
	if err := os.WriteFile(filepath.Join(dir, "api.py"), []byte(source), 0600); err != nil {
		t.Fatalf("write fastapi fixture: %v", err)
	}
	r := NewRunner()
	plan := r.BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "retry"})
	seen := map[string]ExecutionScenario{}
	for _, scenario := range plan.Scenarios {
		seen[scenario.Name] = scenario
	}
	probe, ok := seen["python-api-http-probe"]
	if !ok {
		t.Fatalf("expected python-api-http-probe in %+v", plan.Scenarios)
	}
	if len(probe.HTTPPorts) == 0 || probe.HTTPPorts[0] != 8000 {
		t.Fatalf("expected default http ports, got %+v", probe.HTTPPorts)
	}
	if probe.Env["PORT"] != "8000" || probe.Env["FLASK_RUN_PORT"] != "8000" {
		t.Fatalf("expected web env ports, got %+v", probe.Env)
	}
	uvicorn, ok := seen["python-api-uvicorn-app"]
	if !ok {
		t.Fatalf("expected uvicorn variant in %+v", plan.Scenarios)
	}
	if strings.Join(uvicorn.Args, " ") != "-m uvicorn api:app --host 0.0.0.0 --port 8000" {
		t.Fatalf("unexpected uvicorn args: %+v", uvicorn.Args)
	}
	flask, ok := seen["python-api-flask-cli"]
	if !ok {
		t.Fatalf("expected flask cli variant in %+v", plan.Scenarios)
	}
	if strings.Join(flask.Args, " ") != "-m flask --app api run --host 0.0.0.0 --port 8000" {
		t.Fatalf("unexpected flask cli args: %+v", flask.Args)
	}
}

func TestBuildExecutionPlanDiscoversShallowNestedEntrypoints(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "backend"), 0700); err != nil {
		t.Fatalf("create backend dir: %v", err)
	}
	source := "from flask import Flask\napp = Flask(__name__)\n@app.get('/ready')\ndef ready():\n    return 'ok'\napp.run(port=5100)\n"
	if err := os.WriteFile(filepath.Join(dir, "backend", "server.py"), []byte(source), 0600); err != nil {
		t.Fatalf("write nested server fixture: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "tests"), 0700); err != nil {
		t.Fatalf("create tests dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "tests", "app.py"), []byte("from flask import Flask\napp = Flask(__name__)\n"), 0600); err != nil {
		t.Fatalf("write ignored test fixture: %v", err)
	}
	plan := NewRunner().BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "retry"})
	seen := map[string]ExecutionScenario{}
	for _, scenario := range plan.Scenarios {
		seen[scenario.Name] = scenario
	}
	scenario, ok := seen["python-backend-server-http-probe"]
	if !ok {
		t.Fatalf("expected nested http probe variant in %+v", plan.Scenarios)
	}
	if len(scenario.Args) != 1 || scenario.Args[0] != "backend/server.py" {
		t.Fatalf("expected nested python args, got %+v", scenario.Args)
	}
	if len(scenario.HTTPPorts) == 0 || scenario.HTTPPorts[0] != 5100 {
		t.Fatalf("expected nested extracted port, got %+v", scenario.HTTPPorts)
	}
	if _, ok := seen["python-tests-app-http-probe"]; ok {
		t.Fatalf("expected tests entrypoint ignored, got %+v", plan.Scenarios)
	}
}

func TestBuildExecutionPlanDiscoversSecondLevelPackageEntrypoints(t *testing.T) {
	dir := t.TempDir()
	apiDir := filepath.Join(dir, "src", "api")
	if err := os.MkdirAll(apiDir, 0700); err != nil {
		t.Fatalf("create api dir: %v", err)
	}
	source := "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/health')\ndef health():\n    return {'ok': True}\nuvicorn.run(app, port=8200)\n"
	if err := os.WriteFile(filepath.Join(apiDir, "main.py"), []byte(source), 0600); err != nil {
		t.Fatalf("write second-level fixture: %v", err)
	}
	ignoredDir := filepath.Join(dir, "src", "tests")
	if err := os.MkdirAll(ignoredDir, 0700); err != nil {
		t.Fatalf("create ignored dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(ignoredDir, "main.py"), []byte("from fastapi import FastAPI\napp = FastAPI()\n"), 0600); err != nil {
		t.Fatalf("write ignored fixture: %v", err)
	}
	plan := NewRunner().BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "retry"})
	seen := map[string]ExecutionScenario{}
	for _, scenario := range plan.Scenarios {
		seen[scenario.Name] = scenario
	}
	scenario, ok := seen["python-src-api-main-http-probe"]
	if !ok {
		t.Fatalf("expected second-level http probe variant in %+v", plan.Scenarios)
	}
	if len(scenario.Args) != 1 || scenario.Args[0] != "src/api/main.py" {
		t.Fatalf("expected second-level python args, got %+v", scenario.Args)
	}
	if len(scenario.HTTPPorts) == 0 || scenario.HTTPPorts[0] != 8200 {
		t.Fatalf("expected second-level extracted port, got %+v", scenario.HTTPPorts)
	}
	if _, ok := seen["python-src-tests-main-http-probe"]; ok {
		t.Fatalf("expected second-level tests entrypoint ignored, got %+v", plan.Scenarios)
	}
}

func TestBuildExecutionPlanDiscoversShallowNodeTypeScriptEntrypoints(t *testing.T) {
	dir := t.TempDir()
	apiDir := filepath.Join(dir, "src", "api")
	if err := os.MkdirAll(apiDir, 0700); err != nil {
		t.Fatalf("create api dir: %v", err)
	}
	source := "import express from 'express'\nconst app = express()\napp.post('/scan', (req, res) => res.send('ok'))\napp.listen(5055)\n"
	if err := os.WriteFile(filepath.Join(apiDir, "server.ts"), []byte(source), 0600); err != nil {
		t.Fatalf("write typescript server fixture: %v", err)
	}
	plan := NewRunner().BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "retry"})
	seen := map[string]ExecutionScenario{}
	for _, scenario := range plan.Scenarios {
		seen[scenario.Name] = scenario
	}
	probe, ok := seen["node-src-api-server-http-probe"]
	if !ok {
		t.Fatalf("expected typescript http probe variant in %+v", plan.Scenarios)
	}
	if probe.Command != "node" || strings.Join(probe.Args, " ") != "src/api/server.ts" {
		t.Fatalf("unexpected typescript probe command: %+v", probe)
	}
	if len(probe.HTTPPorts) == 0 || probe.HTTPPorts[0] != 5055 {
		t.Fatalf("expected extracted typescript port, got %+v", probe.HTTPPorts)
	}
	if !strings.Contains(strings.Join(probe.HTTPPaths, ","), "/scan") {
		t.Fatalf("expected typescript route, got %+v", probe.HTTPPaths)
	}
	if !strings.Contains(strings.Join(probe.HTTPMethods, ","), "POST") {
		t.Fatalf("expected typescript POST method, got %+v", probe.HTTPMethods)
	}
}

func TestDetectEntrypointReplaySignalsAggregatesNeighborPythonRoutes(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "api"), 0700); err != nil {
		t.Fatalf("create api dir: %v", err)
	}
	appSource := "from fastapi import FastAPI\nfrom .routes import router as user_router\nfrom .admin import router as admin_router\napp = FastAPI()\napp.include_router(user_router, prefix='/api')\napp.include_router(admin_router, prefix='/admin')\n"
	if err := os.WriteFile(filepath.Join(dir, "api", "app.py"), []byte(appSource), 0600); err != nil {
		t.Fatalf("write app fixture: %v", err)
	}
	routeSource := "from fastapi import APIRouter\nimport uvicorn\nrouter = APIRouter()\n@router.post('/submit')\ndef submit():\n    return {'ok': True}\nPORT = 8120\nuvicorn.run(router, port=PORT)\n"
	if err := os.WriteFile(filepath.Join(dir, "api", "routes.py"), []byte(routeSource), 0600); err != nil {
		t.Fatalf("write route fixture: %v", err)
	}
	adminSource := "from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/stats')\ndef stats():\n    return {'ok': True}\n"
	if err := os.WriteFile(filepath.Join(dir, "api", "admin.py"), []byte(adminSource), 0600); err != nil {
		t.Fatalf("write admin route fixture: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "api", "test_routes.py"), []byte("@router.get('/ignored')\ndef ignored(): pass\n"), 0600); err != nil {
		t.Fatalf("write ignored route fixture: %v", err)
	}
	signals := detectEntrypointReplaySignals(dir, "api/app.py")
	joinedRoutes := strings.Join(signals.WebRoutes, ",")
	if !strings.Contains(joinedRoutes, "/api/submit") {
		t.Fatalf("expected neighbor route with mount prefix, got %+v", signals.WebRoutes)
	}
	if !strings.Contains(joinedRoutes, "/admin/stats") {
		t.Fatalf("expected matched admin route with mount prefix, got %+v", signals.WebRoutes)
	}
	if strings.Contains(joinedRoutes, "/admin/submit") || strings.Contains(joinedRoutes, "/api/stats") {
		t.Fatalf("expected prefixes matched by router import, got %+v", signals.WebRoutes)
	}
	if strings.Contains(joinedRoutes, "/ignored") {
		t.Fatalf("expected test route ignored, got %+v", signals.WebRoutes)
	}
	joinedPorts := strings.Join(intSliceToStrings(signals.WebPorts), ",")
	if !strings.Contains(joinedPorts, "8120") {
		t.Fatalf("expected neighbor port, got %+v", signals.WebPorts)
	}
}

func TestReplaySignalDetectorCachesEntrypointAndWebSignals(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "api"), 0700); err != nil {
		t.Fatalf("create api dir: %v", err)
	}
	appSource := "from fastapi import FastAPI\nfrom .routes import router as user_router\napp = FastAPI()\napp.include_router(user_router, prefix='/api')\n"
	if err := os.WriteFile(filepath.Join(dir, "api", "app.py"), []byte(appSource), 0600); err != nil {
		t.Fatalf("write app fixture: %v", err)
	}
	routeSource := "from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/submit')\ndef submit():\n    return {'ok': True}\nPORT = 8120\n"
	if err := os.WriteFile(filepath.Join(dir, "api", "routes.py"), []byte(routeSource), 0600); err != nil {
		t.Fatalf("write route fixture: %v", err)
	}
	detector := newReplaySignalDetector(dir)
	first := detector.detect("api/app.py")
	second := detector.detect("api/app.py")
	if detector.SignalHits == 0 || detector.SignalMiss == 0 {
		t.Fatalf("expected signal cache hit and miss counters, got hits=%d miss=%d", detector.SignalHits, detector.SignalMiss)
	}
	if detector.SourceReads != 2 {
		t.Fatalf("expected each source file read once, got %d", detector.SourceReads)
	}
	if !strings.Contains(strings.Join(first.WebRoutes, ","), "/api/submit") || !strings.Contains(strings.Join(second.WebRoutes, ","), "/api/submit") {
		t.Fatalf("expected cached detector to preserve mounted routes, first=%+v second=%+v", first.WebRoutes, second.WebRoutes)
	}
	second.WebRoutes = append(second.WebRoutes, "/mutated")
	third := detector.detect("api/app.py")
	if strings.Contains(strings.Join(third.WebRoutes, ","), "/mutated") {
		t.Fatalf("expected cached signals cloned defensively, got %+v", third.WebRoutes)
	}
	if detector.WebMiss == 0 {
		t.Fatalf("expected initial web extraction miss, got hits=%d miss=%d", detector.WebHits, detector.WebMiss)
	}
	webFirst := detector.webSignals("api/routes.py", routeSource)
	webSecond := detector.webSignals("api/routes.py", routeSource)
	if detector.WebHits == 0 {
		t.Fatalf("expected direct web signal cache hit, got hits=%d miss=%d", detector.WebHits, detector.WebMiss)
	}
	webSecond.Routes = append(webSecond.Routes, "/mutated")
	webThird := detector.webSignals("api/routes.py", routeSource)
	if !strings.Contains(strings.Join(webFirst.Routes, ","), "/submit") || strings.Contains(strings.Join(webThird.Routes, ","), "/mutated") {
		t.Fatalf("expected web signals cloned defensively, first=%+v third=%+v", webFirst.Routes, webThird.Routes)
	}
}

func TestExtractWebRoutes(t *testing.T) {
	routes := extractWebRoutes("from flask import Flask\napp = Flask(__name__)\n@app.get('/health')\n@app.route('/status')\napp.get('/api/health', handler)\n@app.api_route('/submit', methods=['POST'])\n")
	joined := strings.Join(routes, ",")
	for _, want := range []string{"/health", "/status", "/api/health", "/submit"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected route %s in %v", want, routes)
		}
	}
}

func TestExtractWebRoutesNormalizesDynamicParameters(t *testing.T) {
	routes := extractWebRoutes("from fastapi import APIRouter\nrouter = APIRouter()\n@router.get('/items/{item_id}')\ndef item(): pass\n@router.get('/users/<int:user_id>')\ndef user(): pass\napp.get('/teams/:name', handler)\n")
	joined := strings.Join(routes, ",")
	for _, want := range []string{"/items/1", "/users/1", "/teams/sample"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected normalized route %s in %v", want, routes)
		}
	}
}

func TestExtractWebMethods(t *testing.T) {
	methods := extractWebMethods("from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/submit')\ndef submit(): pass\n@router.api_route('/bulk', methods=['PUT', 'PATCH'])\ndef bulk(): pass\napp.delete('/items', handler)\n")
	joined := strings.Join(methods, ",")
	for _, want := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected method %s in %v", want, methods)
		}
	}
}

func TestExtractWebRouteMethodsBindsMethodsToPaths(t *testing.T) {
	routeMethods := extractWebRouteMethods("from fastapi import APIRouter\nrouter = APIRouter()\n@router.post('/submit')\ndef submit(): pass\n@router.api_route('/bulk', methods=['PUT', 'PATCH'])\ndef bulk(): pass\napp.delete('/items', handler)\n")
	for path, want := range map[string][]string{
		"/submit": {"POST"},
		"/bulk":   {"PUT", "PATCH"},
		"/items":  {"DELETE"},
	} {
		joined := strings.Join(routeMethods[path], ",")
		for _, method := range want {
			if !strings.Contains(joined, method) {
				t.Fatalf("expected %s method %s in %+v", path, method, routeMethods)
			}
		}
	}
}

func TestExtractWebRouteMethodsAppliesRouterPrefixesAndMounts(t *testing.T) {
	source := "from fastapi import FastAPI, APIRouter\napp = FastAPI()\nrouter = APIRouter(prefix='/api')\n@router.post('/submit')\ndef submit(): pass\napp.include_router(router, prefix='/v1')\nfrom flask import Blueprint\nbp = Blueprint('bp', __name__, url_prefix='/admin')\n@bp.delete('/users/<int:user_id>')\ndef delete_user(): pass\napp.register_blueprint(bp, url_prefix='/ops')\nconst expressRouter = express.Router()\nexpressRouter.patch('/items/:id', handler)\napp.use('/svc', expressRouter)\n"
	routeMethods := extractWebRouteMethods(source)
	for path, want := range map[string]string{
		"/v1/api/submit":     "POST",
		"/ops/admin/users/1": "DELETE",
		"/svc/items/1":       "PATCH",
	} {
		joined := strings.Join(routeMethods[path], ",")
		if !strings.Contains(joined, want) {
			t.Fatalf("expected %s method %s in %+v", path, want, routeMethods)
		}
	}
}

func TestExtractWebRouteMethodsDetectsNextStyleHandlers(t *testing.T) {
	routeMethods := extractWebRouteMethods("export async function POST(request) { return Response.json({ok:true}) }\nexport function GET() { return Response.json({ok:true}) }\nexport const actions = { default: async () => ({ ok: true }) }\nexport function load() { return { ok: true } }\n")
	methods := strings.Join(routeMethods["/"], ",")
	for _, want := range []string{"GET", "POST"} {
		if !strings.Contains(methods, want) {
			t.Fatalf("expected file-routed method %s in %+v", want, routeMethods)
		}
	}
}

func TestDetectEntrypointReplaySignalsDerivesFileSystemAPIRoute(t *testing.T) {
	dir := t.TempDir()
	apiDir := filepath.Join(dir, "app", "api", "users", "[id]")
	if err := os.MkdirAll(apiDir, 0700); err != nil {
		t.Fatalf("create api dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(apiDir, "route.ts"), []byte("export async function GET(request) { return Response.json({ok:true}) }\nexport const POST = async () => Response.json({ok:true})\n"), 0600); err != nil {
		t.Fatalf("write route fixture: %v", err)
	}
	signals := detectEntrypointReplaySignals(dir, "app/api/users/[id]/route.ts")
	if !strings.Contains(strings.Join(signals.WebRoutes, ","), "/app/api/users/1") {
		t.Fatalf("expected file-system api route, got %+v", signals.WebRoutes)
	}
	joinedMethods := strings.Join(signals.WebPathMethods["/app/api/users/1"], ",")
	for _, want := range []string{"GET", "POST"} {
		if !strings.Contains(joinedMethods, want) {
			t.Fatalf("expected file-system route method %s, got %+v", want, signals.WebPathMethods)
		}
	}
}

func TestExtractWebQueryParamsAndExpandRoutes(t *testing.T) {
	source := "url = request.args.get('url')\ntarget = request.query_params.get(\"target\")\nconst id = req.query.id\nconst file = req.query['file']\n"
	params := extractWebQueryParams(source)
	joinedParams := strings.Join(params, ",")
	for _, want := range []string{"url", "target", "id", "file"} {
		if !strings.Contains(joinedParams, want) {
			t.Fatalf("expected query param %s in %v", want, params)
		}
	}
	routes := expandRoutesWithQueryParams([]string{"/scan"}, params)
	joinedRoutes := strings.Join(routes, ",")
	if !strings.Contains(joinedRoutes, "/scan?url=http%3A%2F%2Fexample.com&target=http%3A%2F%2Fexample.com&id=1&file=sample.txt") {
		t.Fatalf("expected expanded query route in %v", routes)
	}
}

func TestBuildHTTPProbeAttemptsUsesExplicitMethodsFirst(t *testing.T) {
	attempts := buildHTTPProbeAttempts([]string{"/health"}, []string{"PUT", "GET"})
	if len(attempts) < 3 {
		t.Fatalf("expected multiple attempts, got %+v", attempts)
	}
	if attempts[0].Method != "PUT" || attempts[0].ContentType != "application/json" {
		t.Fatalf("expected PUT json first, got %+v", attempts)
	}
	if attempts[1].Method != "PUT" || attempts[1].ContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("expected PUT form second, got %+v", attempts)
	}
	if attempts[2].Method != "GET" {
		t.Fatalf("expected GET fallback third, got %+v", attempts)
	}
}

func TestBuildHTTPProbeAttemptsAddsSemanticPayloads(t *testing.T) {
	attempts := buildHTTPProbeAttempts([]string{"/api/scan", "/api/webhook", "/api/submit"}, []string{"POST"})
	joined := ""
	for _, attempt := range attempts {
		joined += attempt.Body + "\n"
	}
	for _, want := range []string{"target", "event", "filename", "sandbox=true"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected semantic payload token %s in attempts %+v", want, attempts)
		}
	}
	if attempts[0].Method != "POST" || attempts[0].ContentType != "application/json" || !strings.Contains(attempts[0].Body, "target") {
		t.Fatalf("expected scan json payload first, got %+v", attempts[0])
	}
}

func TestInferMissingModuleWarnings(t *testing.T) {
	warnings := inferMissingModuleWarnings([]string{
		`ModuleNotFoundError: No module named 'fastapi'`,
		`ImportError: No module named "uvicorn.main"`,
		`ModuleNotFoundError: No module named 'fastapi'`,
	}, "python-api-http-probe")
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"fastapi", "uvicorn", "python-api-http-probe"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected warning token %s in %v", want, warnings)
		}
	}
	if strings.Count(joined, "fastapi") != 2 {
		t.Fatalf("expected one fastapi warning mentioning module and package, got %v", warnings)
	}
}

func TestInferDependencyManifestWarnings(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte("fastapi==0.110.0\nuvicorn>=0.29\n"), 0600); err != nil {
		t.Fatalf("write requirements fixture: %v", err)
	}
	warnings := inferDependencyManifestWarnings(dir, []string{
		`ModuleNotFoundError: No module named 'fastapi'`,
		`ImportError: No module named "uvicorn.main"`,
	}, "python-api-http-probe")
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"依赖文件声明了 fastapi", "依赖文件声明了 uvicorn", "镜像依赖安装步骤"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected dependency manifest warning token %s in %v", want, warnings)
		}
	}
}

func TestInferDependencyManifestWarningsSuggestsMissingManifest(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"dependencies":{"express":"latest"}}`), 0600); err != nil {
		t.Fatalf("write package fixture: %v", err)
	}
	warnings := inferDependencyManifestWarnings(dir, []string{`ModuleNotFoundError: No module named 'fastapi'`}, "python-api-http-probe")
	joined := strings.Join(warnings, "\n")
	for _, want := range []string{"依赖文件未声明 fastapi", "requirements.txt", "入口语言或依赖文件匹配"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected missing manifest warning token %s in %v", want, warnings)
		}
	}
}

func TestExtractWebRoutesFromBlueprintAndAPIRouterAndExpressPrefix(t *testing.T) {
	source := "from flask import Blueprint\napi = Blueprint('api', __name__, url_prefix='/v1')\n@api.get('/health')\ndef health():\n    return 'ok'\n\nfrom fastapi import APIRouter\nrouter = APIRouter(prefix='/api')\n@router.get('/status')\ndef status():\n    return 'ok'\n\nconst router2 = express.Router()\nrouter2.get('/healthz', handler)\napp.use('/service', router2)\n"
	routes := extractWebRoutes(source)
	joined := strings.Join(routes, ",")
	for _, want := range []string{"/v1/health", "/api/status", "/service/healthz"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected route %s in %v", want, routes)
		}
	}
}

func TestExtractWebPorts(t *testing.T) {
	ports := extractWebPorts("app.run(port=5001)\nuvicorn.run(app, host='0.0.0.0', port=8001)\napp.listen(3001, () => {})\n")
	joined := strings.Join(intSliceToStrings(ports), ",")
	for _, want := range []string{"5001", "8001", "3001"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected port %s in %v", want, ports)
		}
	}
}

func TestBuildExecutionPlanAddsNodeHTTPProbeVariant(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "server.js"), []byte("const express = require('express')\nconst app = express()\napp.get('/health', (req, res) => res.send('ok'))\napp.post('/submit', (req, res) => res.json({ok:true}))\napp.listen(3030)\n"), 0600); err != nil {
		t.Fatalf("write node server fixture: %v", err)
	}
	plan := NewRunner().BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "retry"})
	seen := map[string]ExecutionScenario{}
	for _, scenario := range plan.Scenarios {
		seen[scenario.Name] = scenario
	}
	base, ok := seen["node-server"]
	if !ok || base.Command != "node" || strings.Join(base.Args, " ") != "server.js" {
		t.Fatalf("expected node-server base scenario, got %+v", seen["node-server"])
	}
	probe, ok := seen["node-server-http-probe"]
	if !ok {
		t.Fatalf("expected node http probe variant in %+v", plan.Scenarios)
	}
	if probe.Command != "node" || strings.Join(probe.Args, " ") != "server.js" {
		t.Fatalf("unexpected node http command: %+v", probe)
	}
	joinedRoutes := strings.Join(probe.HTTPPaths, ",")
	for _, want := range []string{"/health", "/submit"} {
		if !strings.Contains(joinedRoutes, want) {
			t.Fatalf("expected route %s in %+v", want, probe.HTTPPaths)
		}
	}
	if len(probe.HTTPPorts) == 0 || probe.HTTPPorts[0] != 3030 {
		t.Fatalf("expected extracted node port first, got %+v", probe.HTTPPorts)
	}
	joinedMethods := strings.Join(probe.HTTPMethods, ",")
	for _, want := range []string{"GET", "POST"} {
		if !strings.Contains(joinedMethods, want) {
			t.Fatalf("expected method %s in %+v", want, probe.HTTPMethods)
		}
	}
}

func TestBuildExecutionPlanAddsPackageJSONNodeScriptHTTPProbe(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"scripts":{"start":"node src/custom.js","dev":"vite --host 0.0.0.0"}}`), 0600); err != nil {
		t.Fatalf("write package fixture: %v", err)
	}
	if err := os.Mkdir(filepath.Join(dir, "src"), 0700); err != nil {
		t.Fatalf("create src dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "src", "custom.js"), []byte("const express = require('express')\nconst app = express()\napp.get('/ready', (req, res) => res.send('ok'))\napp.listen(4040)\n"), 0600); err != nil {
		t.Fatalf("write custom node fixture: %v", err)
	}
	plan := NewRunner().BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "retry"})
	seen := map[string]ExecutionScenario{}
	for _, scenario := range plan.Scenarios {
		seen[scenario.Name] = scenario
	}
	base, ok := seen["node-package-start"]
	if !ok || base.Command != "node" || strings.Join(base.Args, " ") != "src/custom.js" {
		t.Fatalf("expected package start node scenario, got %+v", seen["node-package-start"])
	}
	probe, ok := seen["node-package-start-http-probe"]
	if !ok {
		t.Fatalf("expected package start http probe in %+v", plan.Scenarios)
	}
	if probe.Command != "node" || strings.Join(probe.Args, " ") != "src/custom.js" {
		t.Fatalf("unexpected package http probe command: %+v", probe)
	}
	if len(probe.HTTPPorts) == 0 || probe.HTTPPorts[0] != 4040 {
		t.Fatalf("expected extracted package script port, got %+v", probe.HTTPPorts)
	}
	if !strings.Contains(strings.Join(probe.HTTPPaths, ","), "/ready") {
		t.Fatalf("expected package script route, got %+v", probe.HTTPPaths)
	}
}

func TestBuildExecutionPlanAddsPackageJSONMainModuleAndBinEntrypoints(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"main":"./src/server.ts","module":"dist/index.mjs","bin":{"tool":"bin/cli.cjs"}}`), 0600); err != nil {
		t.Fatalf("write package fixture: %v", err)
	}
	for _, rel := range []string{"src/server.ts", "dist/index.mjs", "bin/cli.cjs"} {
		if err := os.MkdirAll(filepath.Join(dir, filepath.Dir(rel)), 0700); err != nil {
			t.Fatalf("create %s dir: %v", rel, err)
		}
		if err := os.WriteFile(filepath.Join(dir, rel), []byte("const express = require('express')\nconst app = express()\napp.get('/ready', (req, res) => res.send('ok'))\napp.listen(6060)\n"), 0600); err != nil {
			t.Fatalf("write %s fixture: %v", rel, err)
		}
	}
	plan := NewRunner().BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "retry"})
	seen := map[string]ExecutionScenario{}
	for _, scenario := range plan.Scenarios {
		seen[scenario.Name] = scenario
	}
	for _, name := range []string{"node-src-server-http-probe", "node-dist-index-http-probe", "node-bin-cli-http-probe"} {
		probe, ok := seen[name]
		if !ok {
			t.Fatalf("expected %s in %+v", name, plan.Scenarios)
		}
		if len(probe.HTTPPorts) == 0 || probe.HTTPPorts[0] != 6060 {
			t.Fatalf("expected extracted package entrypoint port for %s, got %+v", name, probe.HTTPPorts)
		}
	}
}

func TestBuildExecutionPlanUsesPackageScriptTypeScriptSignalPath(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "src"), 0700); err != nil {
		t.Fatalf("create src dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"scripts":{"start":"tsx src/server.ts"}}`), 0600); err != nil {
		t.Fatalf("write package fixture: %v", err)
	}
	source := "import express from 'express'\nconst app = express()\napp.get('/probe', (req, res) => res.send('ok'))\napp.listen(7070)\n"
	if err := os.WriteFile(filepath.Join(dir, "src", "server.ts"), []byte(source), 0600); err != nil {
		t.Fatalf("write typescript fixture: %v", err)
	}
	plan := NewRunner().BuildExecutionPlan(dir, ExecuteOptions{RetryReason: "retry"})
	seen := map[string]ExecutionScenario{}
	for _, scenario := range plan.Scenarios {
		seen[scenario.Name] = scenario
	}
	probe, ok := seen["node-package-start-http-probe"]
	if !ok {
		t.Fatalf("expected package script http probe in %+v", plan.Scenarios)
	}
	if probe.Command != "tsx" || strings.Join(probe.Args, " ") != "src/server.ts" {
		t.Fatalf("unexpected package script probe command: %+v", probe)
	}
	if len(probe.HTTPPorts) == 0 || probe.HTTPPorts[0] != 7070 {
		t.Fatalf("expected extracted package script typescript port, got %+v", probe.HTTPPorts)
	}
	if !strings.Contains(strings.Join(probe.HTTPPaths, ","), "/probe") {
		t.Fatalf("expected package script typescript route, got %+v", probe.HTTPPaths)
	}
}

func TestParsePackageJSONNodeScriptSupportsCommonServerCommands(t *testing.T) {
	cases := []struct {
		script      string
		wantCommand string
		wantArgs    string
	}{
		{script: "pnpm vite --host 0.0.0.0", wantCommand: "pnpm", wantArgs: "vite --host 0.0.0.0"},
		{script: "npx tsx src/server.ts", wantCommand: "npx", wantArgs: "tsx src/server.ts"},
		{script: "next dev -H 0.0.0.0", wantCommand: "next", wantArgs: "dev -H 0.0.0.0"},
		{script: "nodemon src/app.js", wantCommand: "nodemon", wantArgs: "src/app.js"},
	}
	for _, tc := range cases {
		command, args := parsePackageJSONNodeScript(tc.script)
		if command != tc.wantCommand || strings.Join(args, " ") != tc.wantArgs {
			t.Fatalf("parse %q: expected %s %q, got %s %q", tc.script, tc.wantCommand, tc.wantArgs, command, strings.Join(args, " "))
		}
	}
	command, args := parsePackageJSONNodeScript("npm run start")
	if command != "" || len(args) != 0 {
		t.Fatalf("expected recursive package runner ignored, got %s %+v", command, args)
	}
}

func TestDefaultHTTPProbePortsAddsCommonFallbacks(t *testing.T) {
	ports := defaultHTTPProbePorts([]int{5001})
	joined := strings.Join(intSliceToStrings(ports), ",")
	for _, want := range []string{"5001", "8000", "8080", "5000", "3000"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected port %s in %v", want, ports)
		}
	}
	if ports[0] != 5001 {
		t.Fatalf("expected discovered port first, got %v", ports)
	}
}

func TestDefaultHTTPProbePortsPrioritizesDiscoveredPortsAndCapsCandidates(t *testing.T) {
	ports := defaultHTTPProbePorts([]int{9001, 9002, 9003, 9004, 9005, 9006, 8000})
	if len(ports) > maxHTTPProbePorts {
		t.Fatalf("expected capped ports, got %d: %v", len(ports), ports)
	}
	for idx, want := range []int{9001, 9002, 9003, 9004} {
		if ports[idx] != want {
			t.Fatalf("expected discovered port %d at index %d, got %v", want, idx, ports)
		}
	}
	joined := strings.Join(intSliceToStrings(ports), ",")
	for _, want := range []string{"8000", "8080"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected fallback port %s retained, got %v", want, ports)
		}
	}
}

func TestExtractPythonWebAppRefs(t *testing.T) {
	refs := extractPythonWebAppRefs("from fastapi import FastAPI\napi = FastAPI()\napp = create_app()\n")
	joined := strings.Join(refs, ",")
	for _, want := range []string{"api", "app"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected app ref %s in %v", want, refs)
		}
	}
}

func TestExtractWebPortsFromVariablesEnvAndConfig(t *testing.T) {
	source := "PORT = 5002\napp.run(port=PORT)\nconst serverPort = process.env.PORT || 8002\napp.listen(serverPort, () => {})\nconfig = { port: 7002 }\nuvicorn.run(app, port=config.port)\nsettings = { 'port': 6102 }\nlisten(settings.port)\n"
	ports := extractWebPorts(source)
	joined := strings.Join(intSliceToStrings(ports), ",")
	for _, want := range []string{"5002", "8002", "7002", "6102"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected port %s in %v", want, ports)
		}
	}
}

func TestExtractWebPortsFromEnvDefaultAssignments(t *testing.T) {
	source := "port = os.getenv('PORT', 5050)\napp.run(port=port)\nconst uiPort = parseInt(process.env.UI_PORT || '6060', 10)\nlisten(uiPort)\n"
	ports := extractWebPorts(source)
	joined := strings.Join(intSliceToStrings(ports), ",")
	for _, want := range []string{"5050", "6060"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected port %s in %v", want, ports)
		}
	}
}

func TestExtractWebPortsFromWrappedEnvNestedConfigAndTwoHopRefs(t *testing.T) {
	source := "settings = { server: { port: 7102 } }\nconfig = settings\nportRef = config.server.port\napp.run(port=portRef)\nserver.port = 7202\nuvicorn.run(app, port=server.port)\nport = int(os.environ.get('PORT', '7302'))\nlisten(port)\nconst basePort = Number(process.env.BASE_PORT || '7402')\nconst resolvedPort = basePort\napp.listen(resolvedPort, () => {})\n"
	ports := extractWebPorts(source)
	joined := strings.Join(intSliceToStrings(ports), ",")
	for _, want := range []string{"7102", "7202", "7302", "7402"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected port %s in %v", want, ports)
		}
	}
}

func TestExtractWebPortsSupportsSettingsGetAndWrappedDefaultRefs(t *testing.T) {
	source := "defaultPort = 8050\nsettings = {}\nuvicorn.run(app, port=settings.get('port', defaultPort))\nconst fallbackPort = 8123\nconst serverPort = Number(process.env.PORT ?? fallbackPort)\napp.listen(serverPort, () => {})\n"
	ports := extractWebPorts(source)
	joined := strings.Join(intSliceToStrings(ports), ",")
	for _, want := range []string{"8050", "8123"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected port %s in %v", want, ports)
		}
	}
}

func TestExtractWebPortsSupportsServerListenChains(t *testing.T) {
	source := "const port = 8222\nconst server = createServer(app)\nserver.listen(port)\nconst nextPort = 8333\ncreateServer(app).listen(nextPort)\n"
	ports := extractWebPorts(source)
	joined := strings.Join(intSliceToStrings(ports), ",")
	for _, want := range []string{"8222", "8333"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected port %s in %v", want, ports)
		}
	}
}

func TestExtractWebRoutesFromIncludeRouterRegisterBlueprintAndNestedUse(t *testing.T) {
	source := "from fastapi import FastAPI, APIRouter\napp = FastAPI()\napi = APIRouter(prefix='/v1')\ninner = APIRouter()\n@inner.get('/metrics')\ndef metrics():\n    return 'ok'\napi.include_router(inner, prefix='/admin')\napp.include_router(api, prefix='/api')\n\nfrom flask import Flask, Blueprint\nflask_app = Flask(__name__)\nbp = Blueprint('bp', __name__)\n@bp.get('/health')\ndef health():\n    return 'ok'\nflask_app.register_blueprint(bp, url_prefix='/ops')\n\nconst adminRouter = express.Router()\nconst apiRouter = express.Router()\nadminRouter.get('/users', handler)\napiRouter.use('/admin', adminRouter)\napp.use('/api', apiRouter)\n"
	routes := extractWebRoutes(source)
	joined := strings.Join(routes, ",")
	for _, want := range []string{"/api/v1/admin/metrics", "/ops/health", "/api/admin/users"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected route %s in %v", want, routes)
		}
	}
}

func TestExtractWebRoutesSupportsAPIRouteAndPostHandlers(t *testing.T) {
	source := "from fastapi import APIRouter\nrouter = APIRouter(prefix='/api')\n@router.api_route('/submit', methods=['POST'])\ndef submit():\n    return {'ok': True}\nrouter.add_api_route('/bulk', bulk_handler, methods=['POST'])\n\nconst webhookRouter = express.Router()\nwebhookRouter.post('/ingest', handler)\napp.use('/hooks', webhookRouter)\n"
	routes := extractWebRoutes(source)
	joined := strings.Join(routes, ",")
	for _, want := range []string{"/api/submit", "/api/bulk", "/hooks/ingest"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected route %s in %v", want, routes)
		}
	}
}

func TestExtractWebRoutesSupportsAddURLRuleAndRouteChains(t *testing.T) {
	source := "from flask import Flask\napp = Flask(__name__)\napp.add_url_rule('/ops/ping', view_func=ping)\napp.route('/chain').get(handler).post(handler)\n"
	routes := extractWebRoutes(source)
	joined := strings.Join(routes, ",")
	for _, want := range []string{"/ops/ping", "/chain"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected route %s in %v", want, routes)
		}
	}
}

func TestExtractWebRoutesSupportsMethodViewKeywordMountsAndDynamicMethods(t *testing.T) {
	source := "from flask import Flask, Blueprint\nfrom flask.views import MethodView\napp = Flask(__name__)\nbp = Blueprint('bp', __name__)\nclass ItemView(MethodView):\n    pass\napp.route('/items')(ItemView.as_view('items'))\nbp.add_url_rule('/orders', view_func=ItemView.as_view('orders'))\napp.register_blueprint(blueprint=bp, url_prefix='/api')\n\nconst method = 'get'\nconst router = express.Router()\nrouter[method]('/reports', handler)\napp.use('/v1', router)\n"
	routes := extractWebRoutes(source)
	joined := strings.Join(routes, ",")
	for _, want := range []string{"/items", "/api/orders", "/v1/reports"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected route %s in %v", want, routes)
		}
	}
}

func TestExtractWebRoutesSupportsIncludeRouterKeywordArguments(t *testing.T) {
	source := "from fastapi import FastAPI, APIRouter\napp = FastAPI()\ninner = APIRouter()\n@inner.get('/metrics')\ndef metrics():\n    return 'ok'\napp.include_router(prefix='/ops', router=inner, tags=['system'])\n"
	routes := extractWebRoutes(source)
	joined := strings.Join(routes, ",")
	if !strings.Contains(joined, "/ops/metrics") {
		t.Fatalf("expected route %s in %v", "/ops/metrics", routes)
	}
}

func TestBuildHTTPProbeAttemptsPrioritizesMutationRoutes(t *testing.T) {
	attempts := buildHTTPProbeAttempts([]string{"/health", "/api/webhook"}, nil)
	if len(attempts) < 3 {
		t.Fatalf("expected multiple probe attempts, got %+v", attempts)
	}
	if attempts[0].Method != "POST" || attempts[0].ContentType != "application/json" {
		t.Fatalf("expected POST json first for mutation route, got %+v", attempts)
	}
	if attempts[1].Method != "POST" || attempts[1].ContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("expected POST form second for mutation route, got %+v", attempts)
	}
	foundGET := false
	for _, attempt := range attempts {
		if attempt.Method == "GET" {
			foundGET = true
			break
		}
	}
	if !foundGET {
		t.Fatalf("expected GET fallback for mutation route, got %+v", attempts)
	}
}

func TestBuildHTTPProbeAttemptsKeepsGETFirstForHealthRoutes(t *testing.T) {
	attempts := buildHTTPProbeAttempts([]string{"/health", "/status"}, nil)
	if len(attempts) < 3 {
		t.Fatalf("expected multiple probe attempts, got %+v", attempts)
	}
	if attempts[0].Method != "GET" {
		t.Fatalf("expected GET first for health routes, got %+v", attempts)
	}
	if attempts[1].Method != "POST" || attempts[1].ContentType != "application/json" {
		t.Fatalf("expected POST json second for health routes, got %+v", attempts)
	}
	if attempts[2].Method != "POST" || attempts[2].ContentType != "application/x-www-form-urlencoded" {
		t.Fatalf("expected POST form third for health routes, got %+v", attempts)
	}
}

func TestBuildHTTPProbeAttemptsByPathUsesRouteSpecificMethods(t *testing.T) {
	attemptsByPath := buildHTTPProbeAttemptsByPath([]string{"/health", "/submit"}, []string{"POST"}, map[string][]string{
		"/health": {"GET"},
		"/submit": {"POST"},
	})
	if attemptsByPath["/health"][0].Method != "GET" {
		t.Fatalf("expected health GET first, got %+v", attemptsByPath["/health"])
	}
	if attemptsByPath["/submit"][0].Method != "POST" || attemptsByPath["/submit"][0].ContentType != "application/json" {
		t.Fatalf("expected submit POST json first, got %+v", attemptsByPath["/submit"])
	}
}

func TestBuildHTTPProbeAttemptsDeduplicatesAndCapsCombinations(t *testing.T) {
	paths := []string{
		"/api/scan", "/api/analyze", "/api/webhook", "/api/callback", "/api/upload", "/api/submit",
	}
	attempts := buildHTTPProbeAttempts(paths, []string{"POST", "PUT", "PATCH", "GET", "POST"})
	if len(attempts) > maxHTTPProbeAttempts {
		t.Fatalf("expected capped probe attempts, got %d: %+v", len(attempts), attempts)
	}
	seen := map[string]struct{}{}
	for _, attempt := range attempts {
		key := attempt.Method + "\x00" + attempt.ContentType + "\x00" + attempt.Body
		if _, ok := seen[key]; ok {
			t.Fatalf("expected unique probe attempt, duplicate %q in %+v", key, attempts)
		}
		seen[key] = struct{}{}
	}
	if attempts[0].Method != "POST" || attempts[0].ContentType != "application/json" {
		t.Fatalf("expected high-value POST json first, got %+v", attempts)
	}
}

func TestDefaultHTTPProbePathsAddsExtendedFallbacks(t *testing.T) {
	paths := defaultHTTPProbePaths([]string{"/custom", "/health"})
	joined := strings.Join(paths, ",")
	for _, want := range []string{"/custom", "/health", "/metrics", "/ready", "/webhook", "/callback"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected fallback path %s in %v", want, paths)
		}
	}
}

func TestDefaultHTTPProbePathsPrioritizesAndLimitsCandidates(t *testing.T) {
	input := make([]string, 0, 40)
	for i := 0; i < 40; i++ {
		input = append(input, fmt.Sprintf("/misc/%d", i))
	}
	input = append(input, "/api/scan?url=http%3A%2F%2Fexample.com", "/api/webhook", "/health")
	paths := defaultHTTPProbePaths(input)
	if len(paths) > 24 {
		t.Fatalf("expected capped paths, got %d: %v", len(paths), paths)
	}
	joined := strings.Join(paths[:minInt(len(paths), 4)], ",")
	for _, want := range []string{"/api/scan?url=http%3A%2F%2Fexample.com", "/health"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("expected high-value path %s near front, got %v", want, paths[:minInt(len(paths), 6)])
		}
	}
	if !strings.Contains(strings.Join(paths, ","), "/api/webhook") {
		t.Fatalf("expected webhook path retained after cap, got %v", paths)
	}
}

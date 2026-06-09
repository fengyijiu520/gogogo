package plugins

import (
	"context"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
)

// DangerousCallDetector scans Go source files for dangerous function calls
// such as exec, eval, and os.Command that may indicate command injection risks.
type DangerousCallDetector struct{}

// NewDangerousCallDetector returns a new DangerousCallDetector.
func NewDangerousCallDetector() *DangerousCallDetector {
	return &DangerousCallDetector{}
}

// Name implements Plugin.
func (p *DangerousCallDetector) Name() string {
	return "DangerousCallDetector"
}

func (p *DangerousCallDetector) Metadata() Metadata {
	return Metadata{
		ID:           "dangerous",
		Name:         p.Name(),
		Description:  "危险调用检测",
		Type:         PluginTypeDetector,
		Capabilities: []string{"ast-scan", "dangerous-call-detection"},
		HotSwappable: true,
	}
}

// Execute implements Plugin.
func (p *DangerousCallDetector) Execute(ctx context.Context, req ExecuteRequest) (ExecuteResponse, error) {
	scanPath := req.ScanPath
	var findings []Finding

	err := filepath.Walk(scanPath, func(path string, info fs.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}

		if filepath.Ext(path) != ".go" {
			return nil
		}

		fset := token.NewFileSet()
		node, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil
		}

		ast.Inspect(node, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}

			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			funcName := sel.Sel.Name
			if !isDangerousFunc(funcName) {
				return true
			}

			findings = append(findings, Finding{
				PluginName:  p.Name(),
				RuleID:      "DAN-001",
				Severity:    "高风险",
				Title:       "调用危险函数",
				Description: "检测到 " + funcName + " 调用，可能导致命令执行",
				Location:    path,
			})

			return true
		})

		return nil
	})

	if err != nil && !errors.Is(err, context.Canceled) {
		return ExecuteResponse{Findings: findings}, err
	}

	return ExecuteResponse{Findings: findings}, nil
}

func isDangerousFunc(name string) bool {
	switch name {
	case "exec", "System", "eval", "Command":
		return true
	default:
		return false
	}
}

package handler

import (
	"os"
	"path/filepath"
	"testing"
)

func createRealisticSkillFixtureTree(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, subdir := range []string{"scripts", "docs", "web", "examples"} {
		if err := os.MkdirAll(filepath.Join(dir, subdir), 0755); err != nil {
			t.Fatalf("mkdir %s: %v", subdir, err)
		}
	}
	files := map[string]string{
		"SKILL.md":          "# Skill\n用于审查代码安全风险，并按需读取仓库文件。\n",
		"README.md":         "# README\n这是更低优先级的项目说明。\n",
		"docs/guide.md":     "# Guide\n示例文档，不应覆盖主声明。\n",
		"scripts/run.py":    "import subprocess\nsubprocess.run(['python', '--version'])\n",
		"web/package.json":  `{"dependencies":{"axios":"^1.6.0"}}`,
		"go.mod":            "module demo\n\nrequire github.com/example/lib v1.2.3\n",
		"examples/demo.txt": "example fixture\n",
	}
	for rel, body := range files {
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(body), 0644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return dir
}

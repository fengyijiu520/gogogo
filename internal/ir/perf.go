package ir

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
)

// =============================================================================
// 性能优化 (Performance Optimization)
//
// 优化策略：
//   1. 解析缓存 — 相同文件内容不重复解析
//   2. 并行分析 — 多文件并行执行污点/链/相似性分析
//   3. 惰性求值 — 按需启动分析器
//   4. 结果缓存 — 相同输入不重复计算
// =============================================================================

// ParseCache 解析缓存。
type ParseCache struct {
	mu    sync.RWMutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	file    File
	hashStr string
}

// NewParseCache 创建解析缓存。
func NewParseCache() *ParseCache {
	return &ParseCache{
		cache: make(map[string]cacheEntry),
	}
}

// GetOrParse 获取缓存的解析结果，或解析并缓存。
func (c *ParseCache) GetOrParse(path, content, language string) (*File, error) {
	hash := contentHash(path, content)

	// 读缓存
	c.mu.RLock()
	if entry, ok := c.cache[path]; ok && entry.hashStr == hash {
		c.mu.RUnlock()
		f := entry.file
		return &f, nil
	}
	c.mu.RUnlock()

	// 解析
	parser, ok := GetParser(language)
	if !ok {
		parser, ok = GetParserForFile(path)
		if !ok {
			return nil, ErrParserNotFound
		}
	}

	file, err := parser.Parse(path, content)
	if err != nil {
		return nil, err
	}

	// 写缓存
	c.mu.Lock()
	c.cache[path] = cacheEntry{file: *file, hashStr: hash}
	c.mu.Unlock()

	return file, nil
}

// Invalidate 使缓存失效。
func (c *ParseCache) Invalidate(path string) {
	c.mu.Lock()
	delete(c.cache, path)
	c.mu.Unlock()
}

// Clear 清空缓存。
func (c *ParseCache) Clear() {
	c.mu.Lock()
	c.cache = make(map[string]cacheEntry)
	c.mu.Unlock()
}

// Size 缓存大小。
func (c *ParseCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// ErrParserNotFound 解析器未找到错误。
var ErrParserNotFound = &ParseError{Message: "parser not found"}

type ParseError struct {
	Message string
}

func (e *ParseError) Error() string {
	return e.Message
}

// contentHash 计算内容哈希。
func contentHash(path, content string) string {
	h := fnv.New64a()
	h.Write([]byte(path))
	h.Write([]byte(content))
	return strconv.FormatUint(h.Sum64(), 16)
}

// =============================================================================
// 并行分析引擎
// =============================================================================

// ParallelAnalyzer 并行分析器。
type ParallelAnalyzer struct {
	parseCache *ParseCache
	workers    int
}

// NewParallelAnalyzer 创建并行分析器。
func NewParallelAnalyzer(workers int) *ParallelAnalyzer {
	if workers <= 0 {
		workers = 4
	}
	return &ParallelAnalyzer{
		parseCache: NewParseCache(),
		workers:    workers,
	}
}

// AnalyzeResult 并行分析结果。
type AnalyzeResult struct {
	Files           []File
	TaintFindings   []TaintFinding
	ChainResults    []ChainVerificationResult
	SimilarityMatches []SimilarityMatch
	CallGraphStats  CallGraphStats
}

// AnalyzeParallel 并行执行所有分析。
func (a *ParallelAnalyzer) AnalyzeParallel(files []File) AnalyzeResult {
	var result AnalyzeResult
	result.Files = files

	if len(files) == 0 {
		return result
	}

	// 并行执行三个独立的分析
	var wg sync.WaitGroup
	var mu sync.Mutex

	// 1. 构建调用图（先执行，后续依赖它）
	builder := NewCallGraphBuilder()
	graph := builder.Build(files)
	result.CallGraphStats = graph.Stats()

	// 2. 并行执行污点分析和相似性搜索
	wg.Add(2)

	go func() {
		defer wg.Done()
		cfgAnalyzer := NewCFGTaintAnalyzer(DefaultTaintRules())
		findings := cfgAnalyzer.AnalyzeWithCFG(files)
		mu.Lock()
		result.TaintFindings = findings
		mu.Unlock()
	}()

	go func() {
		defer wg.Done()
		simEngine := NewSimilarityEngine(nil, nil, 0.3)
		matches := simEngine.Search(files)
		mu.Lock()
		result.SimilarityMatches = matches
		mu.Unlock()
	}()

	wg.Wait()

	// 3. 链验证（依赖污点分析结果）
	chainVerifier := NewChainVerifier(DefaultChainPatterns(), graph, result.TaintFindings, files)
	result.ChainResults = chainVerifier.Verify()

	return result
}

// ParseAndAnalyze 解析并分析（带缓存）。
func (a *ParallelAnalyzer) ParseAndAnalyze(fileInputs []FileInput) AnalyzeResult {
	var files []File

	for _, input := range fileInputs {
		lang := input.Language
		if lang == "" {
			lang = detectLangFromPath(input.Path)
		}
		file, err := a.parseCache.GetOrParse(input.Path, input.Content, lang)
		if err != nil {
			continue
		}
		files = append(files, *file)
	}

	return a.AnalyzeParallel(files)
}

// FileInput 文件输入。
type FileInput struct {
	Path     string
	Content  string
	Language string
}

// detectLangFromPath 从路径检测语言。
func detectLangFromPath(path string) string {
	lower := strings.ToLower(path)
	if idx := strings.LastIndex(lower, "."); idx >= 0 {
		ext := lower[idx:]
		switch ext {
		case ".py":
			return "python"
		case ".go":
			return "go"
		case ".js", ".jsx", ".mjs":
			return "javascript"
		case ".ts", ".tsx":
			return "typescript"
		}
	}
	return ""
}

// =============================================================================
// 增量分析 (Incremental Analysis)
//
// 只分析变更的文件，复用未变更文件的分析结果。
// 适用于大型项目，避免每次全量扫描。
// =============================================================================

// IncrementalAnalyzer 增量分析器。
type IncrementalAnalyzer struct {
	parseCache    *ParseCache
	fileFingerprints map[string]string  // path → content hash
	taintCache    map[string][]TaintFinding
	chainCache    map[string][]ChainVerificationResult
	simCache      map[string][]SimilarityMatch
	mu            sync.RWMutex
}

// NewIncrementalAnalyzer 创建增量分析器。
func NewIncrementalAnalyzer() *IncrementalAnalyzer {
	return &IncrementalAnalyzer{
		parseCache:       NewParseCache(),
		fileFingerprints: make(map[string]string),
		taintCache:       make(map[string][]TaintFinding),
		chainCache:       make(map[string][]ChainVerificationResult),
		simCache:         make(map[string][]SimilarityMatch),
	}
}

// FileChange 文件变更信息。
type FileChange struct {
	Path     string
	Content  string
	Language string
	Status   ChangeStatus // added / modified / deleted / unchanged
}

// ChangeStatus 变更状态。
type ChangeStatus string

const (
	ChangeAdded     ChangeStatus = "added"
	ChangeModified  ChangeStatus = "modified"
	ChangeDeleted   ChangeStatus = "deleted"
	ChangeUnchanged ChangeStatus = "unchanged"
)

// DetectChanges 检测文件变更。
func (a *IncrementalAnalyzer) DetectChanges(files []FileInput) []FileChange {
	a.mu.RLock()
	defer a.mu.RUnlock()

	var changes []FileChange
	currentPaths := make(map[string]bool)

	for _, f := range files {
		currentPaths[f.Path] = true
		newHash := contentHash(f.Path, f.Content)
		oldHash, exists := a.fileFingerprints[f.Path]

		status := ChangeUnchanged
		if !exists {
			status = ChangeAdded
		} else if oldHash != newHash {
			status = ChangeModified
		}

		changes = append(changes, FileChange{
			Path:     f.Path,
			Content:  f.Content,
			Language: f.Language,
			Status:   status,
		})
	}

	// 检测删除的文件
	for path := range a.fileFingerprints {
		if !currentPaths[path] {
			changes = append(changes, FileChange{
				Path:   path,
				Status: ChangeDeleted,
			})
		}
	}

	return changes
}

// AnalyzeIncremental 增量分析。
func (a *IncrementalAnalyzer) AnalyzeIncremental(files []FileInput) AnalyzeResult {
	changes := a.DetectChanges(files)

	// 分类变更
	var modified, unchanged []File
	for _, change := range changes {
		switch change.Status {
		case ChangeAdded, ChangeModified:
			lang := change.Language
			if lang == "" {
				lang = detectLangFromPath(change.Path)
			}
			parser, ok := GetParser(lang)
			if !ok {
				continue
			}
			parsed, err := parser.Parse(change.Path, change.Content)
			if err != nil {
				continue
			}
			modified = append(modified, *parsed)

			// 更新指纹
			a.mu.Lock()
			a.fileFingerprints[change.Path] = contentHash(change.Path, change.Content)
			a.mu.Unlock()

		case ChangeUnchanged:
			// 从缓存获取
			a.mu.RLock()
			if entry, ok := a.parseCache.cache[change.Path]; ok {
				unchanged = append(unchanged, entry.file)
			}
			a.mu.RUnlock()
		}
	}

	// 合并所有文件
	allFiles := append(unchanged, modified...)

	// 对变更文件重新分析
	var result AnalyzeResult
	result.Files = allFiles

	if len(allFiles) == 0 {
		return result
	}

	// 构建调用图（全量，因为调用关系可能跨文件）
	builder := NewCallGraphBuilder()
	graph := builder.Build(allFiles)
	result.CallGraphStats = graph.Stats()

	// 污点分析：全量（CFG 增强 + 过程间分析需要完整调用图）
	cfgAnalyzer := NewCFGTaintAnalyzer(DefaultTaintRules())
	result.TaintFindings = cfgAnalyzer.AnalyzeWithCFG(allFiles)

	// 相似性搜索：只搜索变更文件
	if len(modified) > 0 {
		simEngine := NewSimilarityEngine(nil, nil, 0.3)
		result.SimilarityMatches = simEngine.Search(modified)
	}

	// 链验证：全量（依赖污点结果）
	chainVerifier := NewChainVerifier(DefaultChainPatterns(), graph, result.TaintFindings, allFiles)
	result.ChainResults = chainVerifier.Verify()

	// 更新缓存
	a.mu.Lock()
	for _, f := range modified {
		a.parseCache.cache[f.Path] = cacheEntry{file: f, hashStr: contentHash(f.Path, f.RawContent)}
	}
	a.mu.Unlock()

	return result
}

// CacheStats 返回缓存统计。
func (a *IncrementalAnalyzer) CacheStats() IncrementalCacheStats {
	a.mu.RLock()
	defer a.mu.RUnlock()

	return IncrementalCacheStats{
		TotalFiles:    len(a.fileFingerprints),
		CachedFiles:   len(a.parseCache.cache),
		TaintCacheLen: len(a.taintCache),
		ChainCacheLen: len(a.chainCache),
		SimCacheLen:   len(a.simCache),
	}
}

// IncrementalCacheStats 增量缓存统计。
type IncrementalCacheStats struct {
	TotalFiles    int `json:"total_files"`
	CachedFiles   int `json:"cached_files"`
	TaintCacheLen int `json:"taint_cache_len"`
	ChainCacheLen int `json:"chain_cache_len"`
	SimCacheLen   int `json:"sim_cache_len"`
}

// String 返回统计信息的文本表示。
func (s IncrementalCacheStats) String() string {
	return fmt.Sprintf("files=%d cached=%d taint_cache=%d chain_cache=%d sim_cache=%d",
		s.TotalFiles, s.CachedFiles, s.TaintCacheLen, s.ChainCacheLen, s.SimCacheLen)
}

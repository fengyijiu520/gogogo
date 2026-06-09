package embedder

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	ort "github.com/yalue/onnxruntime_go"
	"github.com/sugarme/tokenizer"
	"github.com/sugarme/tokenizer/pretrained"
	"skill-scanner/internal/config"
	"skill-scanner/internal/logx"
)
// BgeOnnxEmbedder 基于本地 ONNX 模型的 BGE 嵌入器
type BgeOnnxEmbedder struct {
	tokenizer *tokenizer.Tokenizer
	session   *ort.DynamicAdvancedSession
}

const (
	bgePrefixText = "为这个句子生成表示以用于检索相关文章："
	maxSeqLen     = 512
)
// NewBgeOnnxEmbedder 创建新的 BGE 嵌入器
func NewBgeOnnxEmbedder() (*BgeOnnxEmbedder, error) {
	// 定位模型目录
	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("获取可执行路径失败: %w", err)
	}
	rootDir := filepath.Dir(exePath)
	modelDirs := make([]string, 0, 4)
	for _, candidate := range config.BGEModelDirCandidates() {
		if filepath.IsAbs(candidate) {
			modelDirs = append(modelDirs, candidate)
			continue
		}
		modelDirs = append(modelDirs,
			filepath.Join(rootDir, candidate),
			candidate,
		)
	}
	var modelDir string
	for _, d := range modelDirs {
		if _, err := os.Stat(filepath.Join(d, "model.onnx")); err == nil {
			modelDir = d
			break
		}
	}
	if modelDir == "" {
		return nil, fmt.Errorf("未找到 BGE 模型文件，请确保 %s/model.onnx 存在", strings.Join(config.BGEModelDirCandidates(), " 或 "))
	}
	modelPath := filepath.Join(modelDir, "model.onnx")
	tokenizerPath := filepath.Join(modelDir, "tokenizer.json")
	// 加载 Tokenizer
	tk, err := pretrained.FromFile(tokenizerPath)
	if err != nil {
		return nil, fmt.Errorf("加载 Tokenizer 失败: %w", err)
	}
	// ----- 关键：初始化 ONNX Runtime 环境 -----
	// 设置动态库路径（与系统安装位置一致）
	ort.SetSharedLibraryPath(config.ONNXRuntimeLibPath())
	// 初始化 ORT 环境
	err = ort.InitializeEnvironment()
	if err != nil {
		return nil, fmt.Errorf("初始化 ONNX Runtime 环境失败: %w", err)
	}
	logx.With("component", "embedder").Info("ONNX runtime environment initialized")
	// 创建 SessionOptions
	opts, err := ort.NewSessionOptions()
	if err != nil {
		return nil, fmt.Errorf("创建 SessionOptions 失败: %w", err)
	}
	defer opts.Destroy()
	// 输入输出名称
	inputNames := []string{"input_ids", "attention_mask", "token_type_ids"}
	outputNames := []string{"last_hidden_state"}
	session, err := ort.NewDynamicAdvancedSession(modelPath, inputNames, outputNames, opts)
	if err != nil {
		return nil, fmt.Errorf("加载 ONNX 模型失败: %w", err)
	}
	logx.With("component", "embedder", "model_path", modelPath).Info("BGE model loaded")
	return &BgeOnnxEmbedder{
		tokenizer: tk,
		session:   session,
	}, nil
}
// Embed 将单个文本转换为向量
func (e *BgeOnnxEmbedder) Embed(text string) ([]float64, error) {
	processedText := bgePrefixText + text
	encoding, err := e.tokenizer.EncodeSingle(processedText)
	if err != nil {
		return nil, fmt.Errorf("Tokenize 失败: %w", err)
	}
	if len(encoding.Ids) > maxSeqLen {
		logx.With("component", "embedder", "tokens", len(encoding.Ids)).Warn("input too long for single pass, using chunked embedding")
		return e.embedLongText(text, len(encoding.Ids))
	}
	vec, _, err := e.embedEncoding(encoding)
	if err != nil {
		return nil, err
	}
	return vec, nil
}

func (e *BgeOnnxEmbedder) embedLongText(text string, tokenLen int) ([]float64, error) {
	runes := []rune(text)
	if len(runes) == 0 {
		return e.Embed("")
	}

	tokensPerRune := float64(tokenLen) / float64(len(runes))
	if tokensPerRune < 0.2 {
		tokensPerRune = 0.2
	}
	chunkRunes := int(float64(maxSeqLen-64) / tokensPerRune)
	if chunkRunes < 80 {
		chunkRunes = 80
	}
	overlap := chunkRunes / 5
	if overlap < 20 {
		overlap = 20
	}
	step := chunkRunes - overlap
	if step <= 0 {
		step = chunkRunes
	}

	var agg []float64
	var totalWeight float64
	for start := 0; start < len(runes); start += step {
		end := start + chunkRunes
		if end > len(runes) {
			end = len(runes)
		}
		chunk := string(runes[start:end])
		encoding, err := e.tokenizer.EncodeSingle(bgePrefixText + chunk)
		if err != nil {
			return nil, fmt.Errorf("长文本分块 Tokenize 失败: %w", err)
		}
		vec, validTokens, err := e.embedEncoding(encoding)
		if err != nil {
			return nil, err
		}
		if agg == nil {
			agg = make([]float64, len(vec))
		}
		weight := float64(validTokens)
		if weight <= 0 {
			weight = 1
		}
		for i := range vec {
			agg[i] += vec[i] * weight
		}
		totalWeight += weight
		if end == len(runes) {
			break
		}
	}
	if totalWeight == 0 || len(agg) == 0 {
		return nil, fmt.Errorf("长文本分块嵌入失败: 未生成有效向量")
	}
	for i := range agg {
		agg[i] /= totalWeight
	}
	normalizeL2(agg)
	return agg, nil
}

func (e *BgeOnnxEmbedder) embedEncoding(encoding *tokenizer.Encoding) ([]float64, int64, error) {
	if len(encoding.Ids) > maxSeqLen {
		encoding.Ids = encoding.Ids[:maxSeqLen]
		if len(encoding.AttentionMask) > maxSeqLen {
			encoding.AttentionMask = encoding.AttentionMask[:maxSeqLen]
		}
		if len(encoding.TypeIds) > maxSeqLen {
			encoding.TypeIds = encoding.TypeIds[:maxSeqLen]
		}
	}
	seqLen := len(encoding.Ids)
	inputIds := make([]int64, seqLen)
	attentionMask := make([]int64, seqLen)
	tokenTypeIds := make([]int64, seqLen)
	for i := 0; i < seqLen; i++ {
		inputIds[i] = int64(encoding.Ids[i])
		attentionMask[i] = int64(encoding.AttentionMask[i])
		tokenTypeIds[i] = int64(encoding.TypeIds[i])
	}
	shape := ort.NewShape(1, int64(seqLen))
	inputIdsTensor, err := ort.NewTensor(shape, inputIds)
	if err != nil {
		return nil, 0, err
	}
	defer inputIdsTensor.Destroy()
	maskTensor, err := ort.NewTensor(shape, attentionMask)
	if err != nil {
		return nil, 0, err
	}
	defer maskTensor.Destroy()
	typeIdsTensor, err := ort.NewTensor(shape, tokenTypeIds)
	if err != nil {
		return nil, 0, err
	}
	defer typeIdsTensor.Destroy()
	hiddenSize := 1024 // BGE-large-zh-v1.5 隐藏层维度
	outputShape := ort.NewShape(1, int64(seqLen), int64(hiddenSize))
	outputTensor, err := ort.NewEmptyTensor[float32](outputShape)
	if err != nil {
		return nil, 0, err
	}
	defer outputTensor.Destroy()
	inputs := []ort.Value{inputIdsTensor, maskTensor, typeIdsTensor}
	outputs := []ort.Value{outputTensor}
	err = e.session.Run(inputs, outputs)
	if err != nil {
		return nil, 0, fmt.Errorf("模型推理失败: %w", err)
	}
	outputData := outputTensor.GetData()
	if len(outputData) != seqLen*hiddenSize {
		hiddenSize = len(outputData) / seqLen
	}
	vec := make([]float64, hiddenSize)
	var sumMask int64
	for i := 0; i < seqLen; i++ {
		mask := attentionMask[i]
		if mask == 0 {
			continue
		}
		sumMask++
		for j := 0; j < hiddenSize; j++ {
			vec[j] += float64(outputData[i*hiddenSize+j])
		}
	}
	if sumMask > 0 {
		for j := 0; j < hiddenSize; j++ {
			vec[j] /= float64(sumMask)
		}
	}
	normalizeL2(vec)
	return vec, sumMask, nil
}
// BatchEmbed 批量处理
func (e *BgeOnnxEmbedder) BatchEmbed(texts []string) ([][]float64, error) {
	result := make([][]float64, len(texts))
	for i, text := range texts {
		vec, err := e.Embed(text)
		if err != nil {
			return nil, fmt.Errorf("第 %d 条文本处理失败: %w", i, err)
		}
		result[i] = vec
	}
	return result, nil
}

func normalizeL2(vec []float64) {
	var norm float64
	for _, v := range vec {
		norm += v * v
	}
	if norm > 0 {
		norm = 1.0 / math.Sqrt(norm)
		for i := range vec {
			vec[i] *= norm
		}
	}
}
// Close 释放资源
func (e *BgeOnnxEmbedder) Close() error {
	if e.session != nil {
		return e.session.Destroy()
	}
	return nil
}

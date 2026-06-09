package embedder
// Embedder 是可插拔的 Embedding 接口，用于文本向量化
type Embedder interface {
	// Embed 将单个文本转换为向量
	Embed(text string) ([]float64, error)
	// BatchEmbed 批量处理多个文本，提升效率
	BatchEmbed(texts []string) ([][]float64, error)
}

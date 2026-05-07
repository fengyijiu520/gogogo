package similarity
import "math"
// CosineSimilarity 计算两个向量的余弦相似度
func CosineSimilarity(a, b []float64) float64 {
if len(a) != len(b) {
return -1 // 向量长度不匹配，返回-1表示无效值，避免误判
}
var dotProduct, normA, normB float64
for i := range a {
dotProduct += a[i] * b[i]
normA += a[i] * a[i]
normB += b[i] * b[i]
}
if normA == 0 || normB == 0 {
return 0
}
return dotProduct / (math.Sqrt(normA) * math.Sqrt(normB))
}
// DotProduct 点积（部分场景用）
func DotProduct(a, b []float64) float64 {
var sum float64
for i := range a {
sum += a[i] * b[i]
}
return sum
}
// EuclideanDistance 欧氏距离（越小越相似）
func EuclideanDistance(a, b []float64) float64 {
if len(a) != len(b) {
return math.Inf(1)
}
var sum float64
for i := range a {
diff := a[i] - b[i]
sum += diff * diff
}
return math.Sqrt(sum)
}

package config

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	defaultRulesConfigPath                = "config/rules_access.yaml"
	defaultBGEModelDir                    = "models/bge-large-zh-v1.5"
	defaultONNXRuntimeLibPath             = "/usr/local/lib/libonnxruntime.so"
	defaultServerListenAddr               = ":8880"
	defaultEvasionDelaySecs               = 300
	defaultMaxActiveTasksPerUser          = 2
	defaultMaxActiveTasksGlobal           = 6
	defaultSimilarityLow                  = 0.5
	defaultSimilarityHigh                 = 0.75
	defaultIncrementalScanCacheEnabled    = true
	defaultIncrementalScanCacheMaxEntries = 2000
	defaultChainVerifyHighThreshold       = 3
	defaultChainVerifyMediumThreshold     = 2
	defaultSemanticChainMinSkills         = 3
	defaultSemanticChainMinPhases         = 3
	defaultSemanticChainMinEvidence       = 2
	defaultPluginsConfigPath              = "config/plugins.json"
	defaultEvidenceContextConfigPath      = "config/evidence_context.yaml"
	defaultReviewPolicyConfigPath         = "config/review_policies.yaml"
	defaultEvaluatorCacheMaxEntries       = 10000
	defaultEvaluatorCacheTTLSecs          = 86400
	defaultLLMRequestTimeoutSecs          = 120
)

var defaultPDFCJKFontCandidates = []string{
	"web/assets/fonts/NotoSansCJKsc-Regular.otf",
	"web/assets/fonts/skill-scanner-cjk.ttf",
	"AI-Infra-Guard-main/common/websocket/static/fonts/Tencentsans.ttf",
	"/usr/share/fonts/truetype/wqy/wqy-microhei.ttf",
	"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc",
	"/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.otf",
	"/usr/share/fonts/truetype/arphic/uming.ttc",
	"/usr/share/fonts/truetype/arphic/uming.ttf",
}

func RulesConfigPath() string {
	return envOrDefault("SKILL_SCANNER_RULES_PATH", defaultRulesConfigPath)
}

func BGEModelDirCandidates() []string {
	configured := strings.TrimSpace(os.Getenv("SKILL_SCANNER_BGE_MODEL_DIR"))
	items := make([]string, 0, 4)
	if configured != "" {
		items = append(items, configured)
	}
	items = append(items,
		defaultBGEModelDir,
		filepath.Join("..", defaultBGEModelDir),
	)
	return uniqueStrings(items)
}

func ONNXRuntimeLibPath() string {
	return envOrDefault("SKILL_SCANNER_ONNX_RUNTIME_LIB", defaultONNXRuntimeLibPath)
}

func ServerListenAddr() string {
	return envOrDefault("SKILL_SCANNER_LISTEN_ADDR", defaultServerListenAddr)
}

func PDFCJKFontCandidates() []string {
	items := make([]string, 0, len(defaultPDFCJKFontCandidates)+1)
	if value := strings.TrimSpace(os.Getenv("REVIEW_REPORT_CJK_FONT_FILE")); value != "" {
		items = append(items, value)
	}
	items = append(items, defaultPDFCJKFontCandidates...)
	return uniqueStrings(items)
}

func EvasionDelayThresholdSecs() int {
	return positiveIntEnvOrDefault("REVIEW_EVASION_DELAY_THRESHOLD_SECS", defaultEvasionDelaySecs)
}

func MaxActiveTasksPerUser() int {
	return positiveIntEnvOrDefault("SKILL_SCANNER_MAX_ACTIVE_TASKS_PER_USER", defaultMaxActiveTasksPerUser)
}

func MaxActiveTasksGlobal() int {
	return positiveIntEnvOrDefault("SKILL_SCANNER_MAX_ACTIVE_TASKS_GLOBAL", defaultMaxActiveTasksGlobal)
}

func SimilarityThresholdLow() float64 {
	return positiveFloatEnvOrDefault("SKILL_SCANNER_SIMILARITY_LOW", defaultSimilarityLow)
}

func SimilarityThresholdHigh() float64 {
	return positiveFloatEnvOrDefault("SKILL_SCANNER_SIMILARITY_HIGH", defaultSimilarityHigh)
}

func IncrementalScanCacheEnabled() bool {
	return boolEnvOrDefault("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE", defaultIncrementalScanCacheEnabled)
}

func IncrementalScanCacheMaxEntries() int {
	return positiveIntEnvOrDefault("SKILL_SCANNER_INCREMENTAL_SCAN_CACHE_MAX_ENTRIES", defaultIncrementalScanCacheMaxEntries)
}

func BehaviorChainVerifyHighThreshold() int {
	v := positiveIntEnvOrDefault("SKILL_SCANNER_BEHAVIOR_CHAIN_VERIFY_HIGH_THRESHOLD", defaultChainVerifyHighThreshold)
	if v > 3 {
		return 3
	}
	return v
}

func BehaviorChainVerifyMediumThreshold() int {
	v := positiveIntEnvOrDefault("SKILL_SCANNER_BEHAVIOR_CHAIN_VERIFY_MEDIUM_THRESHOLD", defaultChainVerifyMediumThreshold)
	if v > 3 {
		return 3
	}
	return v
}

func SemanticChainMinSkills() int {
	return positiveIntEnvOrDefault("SKILL_SCANNER_SEMANTIC_CHAIN_MIN_SKILLS", defaultSemanticChainMinSkills)
}

func SemanticChainMinPhases() int {
	return positiveIntEnvOrDefault("SKILL_SCANNER_SEMANTIC_CHAIN_MIN_PHASES", defaultSemanticChainMinPhases)
}

func SemanticChainMinEvidence() int {
	return positiveIntEnvOrDefault("SKILL_SCANNER_SEMANTIC_CHAIN_MIN_EVIDENCE", defaultSemanticChainMinEvidence)
}

func EnabledPlugins() []string {
	return parseCSVEnv("SKILL_SCANNER_ENABLED_PLUGINS")
}

func DisabledPlugins() []string {
	return parseCSVEnv("SKILL_SCANNER_DISABLED_PLUGINS")
}

func PluginsConfigPath() string {
	return envOrDefault("SKILL_SCANNER_PLUGINS_CONFIG", defaultPluginsConfigPath)
}

func EvidenceContextConfigPath() string {
	return envOrDefault("SKILL_SCANNER_EVIDENCE_CONTEXT_CONFIG", defaultEvidenceContextConfigPath)
}

func ReviewPolicyConfigPath() string {
	return envOrDefault("SKILL_SCANNER_REVIEW_POLICY_CONFIG", defaultReviewPolicyConfigPath)
}

func EvaluatorCacheMaxEntries() int {
	return positiveIntEnvOrDefault("SKILL_SCANNER_EVALUATOR_CACHE_MAX_ENTRIES", defaultEvaluatorCacheMaxEntries)
}

func EvaluatorCacheTTLSecs() int {
	return positiveIntEnvOrDefault("SKILL_SCANNER_EVALUATOR_CACHE_TTL_SECS", defaultEvaluatorCacheTTLSecs)
}

func LLMRequestTimeoutSecs() int {
	return positiveIntEnvOrDefault("REVIEW_LLM_REQUEST_TIMEOUT_SECS", defaultLLMRequestTimeoutSecs)
}

func LLMDebugEnabled() bool {
	return boolEnvOrDefault("SKILL_SCANNER_LLM_DEBUG", false)
}

func envOrDefault(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func positiveIntEnvOrDefault(key string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	v, err := strconv.Atoi(value)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func positiveFloatEnvOrDefault(key string, fallback float64) float64 {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	v, err := strconv.ParseFloat(value, 64)
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}

func uniqueStrings(items []string) []string {
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
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

func boolEnvOrDefault(key string, fallback bool) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(key)))
	if value == "" {
		return fallback
	}
	switch value {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return fallback
	}
}

func parseCSVEnv(key string) []string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		item := strings.ToLower(strings.TrimSpace(part))
		if item == "" {
			continue
		}
		out = append(out, item)
	}
	return uniqueStrings(out)
}

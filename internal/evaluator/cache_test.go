package evaluator

import (
	"fmt"
	"testing"
	"time"
)

func TestEvaluatorCacheHasCapacityLimit(t *testing.T) {
	t.Setenv("SKILL_SCANNER_EVALUATOR_CACHE_MAX_ENTRIES", "10000")
	e := NewEvaluator(nil, nil, nil)
	for i := 0; i < defaultEvaluatorCacheMaxEntries+100; i++ {
		e.cacheResult(fmt.Sprintf("k-%d", i), &EvaluationResult{Score: float64(i)})
	}

	e.cacheMutex.RLock()
	defer e.cacheMutex.RUnlock()
	if got := e.cache.Len(); got != defaultEvaluatorCacheMaxEntries {
		t.Fatalf("expected cache len %d, got %d", defaultEvaluatorCacheMaxEntries, got)
	}
}

func TestEvaluatorCacheRemovesExpiredItemOnRead(t *testing.T) {
	e := NewEvaluator(nil, nil, nil)
	key := "expired-key"

	e.cacheMutex.Lock()
	e.cache.Add(key, CacheItem{Result: &EvaluationResult{Score: 1}, ExpireAt: time.Now().Add(-time.Minute)})
	e.cacheMutex.Unlock()

	if _, ok := e.getCachedResult(key); ok {
		t.Fatal("expected expired cache item to miss")
	}

	e.cacheMutex.RLock()
	_, exists := e.cache.Get(key)
	e.cacheMutex.RUnlock()
	if exists {
		t.Fatal("expected expired cache item removed")
	}
}

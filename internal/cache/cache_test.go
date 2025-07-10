package cache

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/kyxap1/geoip-server/internal/types"

	"github.com/sirupsen/logrus"
)

func TestCache_Basic(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCache(time.Minute, 10, logger)
	defer cache.Close()

	// Test basic set and get
	testData := &types.GeoIPInfo{
		IP:          "8.8.8.8",
		Country:     "United States",
		CountryCode: "US",
		City:        "Mountain View",
	}

	cache.Set("8.8.8.8", testData)

	result, found := cache.Get("8.8.8.8")
	if !found {
		t.Error("Expected to find cached value")
	}

	if result.IP != testData.IP {
		t.Errorf("Expected IP %s, got %s", testData.IP, result.IP)
	}

	if result.Country != testData.Country {
		t.Errorf("Expected Country %s, got %s", testData.Country, result.Country)
	}
}

func TestCache_Miss(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCache(time.Minute, 10, logger)
	defer cache.Close()

	// Test cache miss
	_, found := cache.Get("nonexistent")
	if found {
		t.Error("Expected cache miss for nonexistent key")
	}
}

func TestCache_TTL(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCache(50*time.Millisecond, 10, logger)
	defer cache.Close()

	testData := &types.GeoIPInfo{
		IP:      "1.1.1.1",
		Country: "Australia",
	}

	cache.Set("1.1.1.1", testData)

	// Should be available immediately
	_, found := cache.Get("1.1.1.1")
	if !found {
		t.Error("Expected to find cached value immediately")
	}

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Should be expired now
	_, found = cache.Get("1.1.1.1")
	if found {
		t.Error("Expected cache miss after TTL expiration")
	}
}

func TestCache_MaxEntries(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCache(time.Minute, 3, logger)
	defer cache.Close()

	// Add entries up to max
	for i := 0; i < 5; i++ {
		testData := &types.GeoIPInfo{
			IP:      fmt.Sprintf("192.168.1.%d", i),
			Country: "TestCountry",
		}
		cache.Set(fmt.Sprintf("192.168.1.%d", i), testData)
	}

	// Should only have 3 entries (LRU eviction)
	stats := cache.GetStats()
	if stats["entries"].(int) != 3 {
		t.Errorf("Expected 3 entries, got %d", stats["entries"].(int))
	}

	if stats["evictions"].(int64) != 2 {
		t.Errorf("Expected 2 evictions, got %d", stats["evictions"].(int64))
	}
}

func TestCache_Eviction(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCache(time.Minute, 2, logger)
	defer cache.Close()

	// Add two entries to fill cache
	cache.Set("first", &types.GeoIPInfo{IP: "1.1.1.1"})
	cache.Set("second", &types.GeoIPInfo{IP: "2.2.2.2"})

	// Cache should have 2 entries
	stats := cache.GetStats()
	if stats["entries"].(int) != 2 {
		t.Errorf("Expected 2 entries, got %d", stats["entries"].(int))
	}

	// Add third entry (should trigger eviction)
	cache.Set("third", &types.GeoIPInfo{IP: "3.3.3.3"})

	// Should still have 2 entries due to max limit
	stats = cache.GetStats()
	if stats["entries"].(int) != 2 {
		t.Errorf("Expected 2 entries after eviction, got %d", stats["entries"].(int))
	}

	// Should have 1 eviction
	if stats["evictions"].(int64) != 1 {
		t.Errorf("Expected 1 eviction, got %d", stats["evictions"].(int64))
	}
}

func TestCache_Stats(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCache(time.Minute, 10, logger)
	defer cache.Close()

	// Initial stats
	stats := cache.GetStats()
	if stats["hits"].(int64) != 0 || stats["misses"].(int64) != 0 || stats["entries"].(int) != 0 {
		t.Error("Initial stats should be zero")
	}

	// Test hit
	cache.Set("test", &types.GeoIPInfo{IP: "1.1.1.1"})
	cache.Get("test")

	stats = cache.GetStats()
	if stats["hits"].(int64) != 1 {
		t.Errorf("Expected 1 hit, got %d", stats["hits"].(int64))
	}

	if stats["entries"].(int) != 1 {
		t.Errorf("Expected 1 entry, got %d", stats["entries"].(int))
	}

	// Test miss
	cache.Get("nonexistent")

	stats = cache.GetStats()
	if stats["misses"].(int64) != 1 {
		t.Errorf("Expected 1 miss, got %d", stats["misses"].(int64))
	}

	// Test hit rate
	expectedHitRate := float64(1) / float64(2) * 100 // 1 hit out of 2 total
	if stats["hit_rate"].(float64) != expectedHitRate {
		t.Errorf("Expected hit rate %.2f, got %.2f", expectedHitRate, stats["hit_rate"].(float64))
	}
}

func TestCache_Concurrent(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCache(time.Minute, 100, logger)
	defer cache.Close()

	var wg sync.WaitGroup
	numGoroutines := 10
	numOperations := 100

	// Concurrent writes
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("key-%d-%d", base, j)
				value := &types.GeoIPInfo{
					IP:      fmt.Sprintf("192.168.%d.%d", base, j),
					Country: "TestCountry",
				}
				cache.Set(key, value)
			}
		}(i)
	}

	wg.Wait()

	// Concurrent reads
	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func(base int) {
			defer wg.Done()
			for j := 0; j < numOperations; j++ {
				key := fmt.Sprintf("key-%d-%d", base, j)
				_, _ = cache.Get(key)
			}
		}(i)
	}

	wg.Wait()

	// Verify cache is still functional
	cache.Set("test", &types.GeoIPInfo{IP: "test"})
	result, found := cache.Get("test")
	if !found || result.IP != "test" {
		t.Error("Cache should still be functional after concurrent operations")
	}
}

func TestCache_Clear(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCache(time.Minute, 10, logger)
	defer cache.Close()

	// Add some entries
	cache.Set("test1", &types.GeoIPInfo{IP: "1.1.1.1"})
	cache.Set("test2", &types.GeoIPInfo{IP: "2.2.2.2"})

	stats := cache.GetStats()
	if stats["entries"].(int) != 2 {
		t.Errorf("Expected 2 entries before clear, got %d", stats["entries"].(int))
	}

	// Clear cache
	cache.Clear()

	stats = cache.GetStats()
	if stats["entries"].(int) != 0 {
		t.Errorf("Expected 0 entries after clear, got %d", stats["entries"].(int))
	}

	// Verify entries are gone
	_, found := cache.Get("test1")
	if found {
		t.Error("Expected cache miss after clear")
	}
}

func TestCache_Size(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCache(time.Minute, 10, logger)
	defer cache.Close()

	// Add some entries
	cache.Set("test", &types.GeoIPInfo{IP: "1.1.1.1"})

	// Test size
	size := cache.Size()
	if size != 1 {
		t.Errorf("Expected size 1, got %d", size)
	}
}

func TestCache_Cleanup(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCache(100*time.Millisecond, 10, logger)
	defer cache.Close()

	// Add entries with short TTL
	cache.Set("test1", &types.GeoIPInfo{IP: "1.1.1.1"})
	cache.Set("test2", &types.GeoIPInfo{IP: "2.2.2.2"})

	// Verify entries are there initially
	stats := cache.GetStats()
	if stats["entries"].(int) != 2 {
		t.Errorf("Expected 2 entries initially, got %d", stats["entries"].(int))
	}

	// Wait for TTL to expire
	time.Sleep(200 * time.Millisecond)

	// Entries should be expired (not accessible)
	_, found1 := cache.Get("test1")
	_, found2 := cache.Get("test2")
	if found1 || found2 {
		t.Error("Expected entries to be expired and not accessible")
	}
}

func BenchmarkCache_Set(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCacheNoCleanup(time.Minute, 10000, logger)

	testData := &types.GeoIPInfo{
		IP:      "8.8.8.8",
		Country: "United States",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Set(fmt.Sprintf("key-%d", i%1000), testData)
	}
}

func BenchmarkCache_Get(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCacheNoCleanup(time.Minute, 10000, logger)

	testData := &types.GeoIPInfo{
		IP:      "8.8.8.8",
		Country: "United States",
	}

	// Pre-populate cache
	for i := 0; i < 100; i++ {
		cache.Set(fmt.Sprintf("key-%d", i), testData)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cache.Get(fmt.Sprintf("key-%d", i%100))
	}
}

func BenchmarkCache_Concurrent(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	cache := NewIPCacheNoCleanup(time.Minute, 1000, logger)

	testData := &types.GeoIPInfo{
		IP:      "8.8.8.8",
		Country: "United States",
	}

	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			if i%2 == 0 {
				cache.Set(fmt.Sprintf("key-%d", i%100), testData)
			} else {
				cache.Get(fmt.Sprintf("key-%d", i%100))
			}
			i++
		}
	})
}

// Test NewIPCacheNoCleanup function
func TestNewIPCacheNoCleanup(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cache := NewIPCacheNoCleanup(time.Minute, 10, logger)

	// Verify cache was created correctly
	if cache == nil {
		t.Fatal("NewIPCacheNoCleanup should not return nil")
	}

	// Test basic functionality
	testData := &types.GeoIPInfo{
		IP:      "192.168.1.1",
		Country: "Test Country",
	}

	cache.Set("test", testData)

	result, found := cache.Get("test")
	if !found {
		t.Error("Expected to find cached value in NoCleanup cache")
	}

	if result.IP != testData.IP {
		t.Errorf("Expected IP %s, got %s", testData.IP, result.IP)
	}

	// Verify no cleanup ticker was started (this is the key difference)
	// The cache should still work but without automatic cleanup
	stats := cache.GetStats()
	if stats["entries"].(int) != 1 {
		t.Errorf("Expected 1 entry, got %d", stats["entries"].(int))
	}

	// Test that expired entries remain in cache without cleanup
	shortTTLCache := NewIPCacheNoCleanup(50*time.Millisecond, 10, logger)
	shortTTLCache.Set("expired", testData)

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Entry should be considered expired when accessed but remain in internal map
	_, found = shortTTLCache.Get("expired")
	if found {
		t.Error("Expected cache miss for expired entry")
	}

	// Close cache properly
	cache.Close()
	shortTTLCache.Close()
}

// Test cleanupExpired function indirectly
func TestCache_CleanupExpired(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create cache with very short TTL and cleanup interval
	cache := NewIPCache(50*time.Millisecond, 10, logger)
	defer cache.Close()

	// Add multiple entries
	testData1 := &types.GeoIPInfo{IP: "1.1.1.1", Country: "Country1"}
	testData2 := &types.GeoIPInfo{IP: "2.2.2.2", Country: "Country2"}
	testData3 := &types.GeoIPInfo{IP: "3.3.3.3", Country: "Country3"}

	cache.Set("key1", testData1)
	cache.Set("key2", testData2)
	cache.Set("key3", testData3)

	// Verify all entries are there initially
	stats := cache.GetStats()
	if stats["entries"].(int) != 3 {
		t.Errorf("Expected 3 entries initially, got %d", stats["entries"].(int))
	}

	// Wait for TTL to expire
	time.Sleep(100 * time.Millisecond)

	// Give cleanup ticker time to run (cleanup runs every 1 minute by default)
	// Since we can't directly control the cleanup timing, we'll trigger it indirectly
	// by performing operations that might trigger cleanup

	// Try to access expired entries (this should trigger cleanup check)
	for i := 0; i < 10; i++ {
		cache.Get("key1")
		cache.Get("key2")
		cache.Get("key3")
		cache.Set("new-key", testData1) // This might trigger cleanup
		time.Sleep(10 * time.Millisecond)
	}

	// After some time and operations, expired entries should be inaccessible
	_, found1 := cache.Get("key1")
	_, found2 := cache.Get("key2")
	_, found3 := cache.Get("key3")

	if found1 || found2 || found3 {
		t.Error("Expected all entries to be expired and not accessible")
	}
}

// Test cache behavior with very short cleanup intervals
func TestCache_CleanupBehavior(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Test with extremely short TTL
	cache := NewIPCache(10*time.Millisecond, 100, logger)
	defer cache.Close()

	// Add many entries quickly
	for i := 0; i < 20; i++ {
		testData := &types.GeoIPInfo{
			IP:      fmt.Sprintf("192.168.1.%d", i),
			Country: "TestCountry",
		}
		cache.Set(fmt.Sprintf("key-%d", i), testData)
		time.Sleep(1 * time.Millisecond) // Small delay between insertions
	}

	// Wait for entries to expire
	time.Sleep(50 * time.Millisecond)

	// Verify that entries are properly expired
	foundCount := 0
	for i := 0; i < 20; i++ {
		if _, found := cache.Get(fmt.Sprintf("key-%d", i)); found {
			foundCount++
		}
	}

	if foundCount > 0 {
		t.Errorf("Expected 0 accessible entries after expiration, found %d", foundCount)
	}

	// Verify cache still works for new entries
	cache.Set("new-entry", &types.GeoIPInfo{IP: "10.0.0.1"})
	if _, found := cache.Get("new-entry"); !found {
		t.Error("Cache should still work for new entries after cleanup")
	}
}

// Test concurrent access during cleanup
func TestCache_ConcurrentCleanup(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cache := NewIPCache(100*time.Millisecond, 50, logger)
	defer cache.Close()

	var wg sync.WaitGroup

	// Start goroutine that continuously adds entries
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			testData := &types.GeoIPInfo{
				IP:      fmt.Sprintf("192.168.100.%d", i),
				Country: "ConcurrentTest",
			}
			cache.Set(fmt.Sprintf("concurrent-%d", i), testData)
			time.Sleep(2 * time.Millisecond)
		}
	}()

	// Start goroutine that continuously reads entries
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			cache.Get(fmt.Sprintf("concurrent-%d", i%50))
			time.Sleep(3 * time.Millisecond)
		}
	}()

	// Start goroutine that gets stats (this might trigger internal cleanup)
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 50; i++ {
			cache.GetStats()
			time.Sleep(5 * time.Millisecond)
		}
	}()

	wg.Wait()

	// Cache should still be functional after concurrent operations
	cache.Set("final-test", &types.GeoIPInfo{IP: "192.168.255.1"})
	if _, found := cache.Get("final-test"); !found {
		t.Error("Cache should remain functional after concurrent operations with cleanup")
	}
}

// Test edge cases for cleanup
func TestCache_CleanupEdgeCases(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Run("Empty cache cleanup", func(t *testing.T) {
		cache := NewIPCache(time.Minute, 10, logger)
		defer cache.Close()

		// Get stats on empty cache (should not cause issues)
		stats := cache.GetStats()
		if stats["entries"].(int) != 0 {
			t.Error("Empty cache should have 0 entries")
		}

		// Clear empty cache (should not cause issues)
		cache.Clear()

		// Size of empty cache
		if cache.Size() != 0 {
			t.Error("Empty cache size should be 0")
		}
	})

	t.Run("Single entry cleanup", func(t *testing.T) {
		cache := NewIPCache(50*time.Millisecond, 10, logger)
		defer cache.Close()

		cache.Set("single", &types.GeoIPInfo{IP: "1.1.1.1"})

		// Wait for expiration
		time.Sleep(100 * time.Millisecond)

		// Entry should be expired
		if _, found := cache.Get("single"); found {
			t.Error("Single entry should be expired")
		}
	})
}

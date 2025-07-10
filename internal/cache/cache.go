package cache

import (
	"sync"
	"sync/atomic"
	"time"

	"geoip-server/internal/types"

	"github.com/sirupsen/logrus"
)

// CacheEntry represents a cached GeoIP result
type CacheEntry struct {
	Data      *types.GeoIPInfo
	ExpiresAt time.Time
}

// IPCache provides in-memory caching for GeoIP lookups
type IPCache struct {
	cache      map[string]*CacheEntry
	mu         sync.RWMutex
	ttl        time.Duration
	maxEntries int
	logger     *logrus.Logger
	// Statistics
	hits      int64
	misses    int64
	evictions int64
	// Control
	stopCh chan struct{}
}

// NewIPCache creates a new IP cache with specified TTL and max entries
func NewIPCache(ttl time.Duration, maxEntries int, logger *logrus.Logger) *IPCache {
	cache := &IPCache{
		cache:      make(map[string]*CacheEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}

	// Start cleanup goroutine
	go cache.cleanup()

	return cache
}

// NewIPCacheNoCleanup creates a new IP cache without cleanup goroutine (for testing)
func NewIPCacheNoCleanup(ttl time.Duration, maxEntries int, logger *logrus.Logger) *IPCache {
	return &IPCache{
		cache:      make(map[string]*CacheEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
		logger:     logger,
		stopCh:     make(chan struct{}),
	}
}

// Get retrieves a cached entry for the given IP
func (c *IPCache) Get(ip string) (*types.GeoIPInfo, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, exists := c.cache[ip]
	if !exists {
		atomic.AddInt64(&c.misses, 1)
		return nil, false
	}

	// Check if entry has expired
	if time.Now().After(entry.ExpiresAt) {
		atomic.AddInt64(&c.misses, 1)
		// Don't delete here, let cleanup handle it
		return nil, false
	}

	atomic.AddInt64(&c.hits, 1)
	return entry.Data, true
}

// Set stores a GeoIP result in the cache
func (c *IPCache) Set(ip string, data *types.GeoIPInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Check if we need to evict entries
	if len(c.cache) >= c.maxEntries {
		c.evictOldest()
	}

	c.cache[ip] = &CacheEntry{
		Data:      data,
		ExpiresAt: time.Now().Add(c.ttl),
	}
}

// evictOldest removes the oldest entries when cache is full
func (c *IPCache) evictOldest() {
	if len(c.cache) == 0 {
		return
	}

	// Find entries to evict (10% of max capacity)
	evictCount := c.maxEntries / 10
	if evictCount < 1 {
		evictCount = 1
	}

	// Collect entries with their expiration times
	type entryWithKey struct {
		key       string
		expiresAt time.Time
	}

	var entries []entryWithKey
	for key, entry := range c.cache {
		entries = append(entries, entryWithKey{
			key:       key,
			expiresAt: entry.ExpiresAt,
		})
	}

	// Sort by expiration time (oldest first)
	for i := 0; i < len(entries)-1; i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[i].expiresAt.After(entries[j].expiresAt) {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Remove oldest entries
	for i := 0; i < evictCount && i < len(entries); i++ {
		delete(c.cache, entries[i].key)
		atomic.AddInt64(&c.evictions, 1)
	}
}

// cleanup removes expired entries periodically
func (c *IPCache) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.cleanupExpired()
		case <-c.stopCh:
			return
		}
	}
}

// cleanupExpired removes all expired entries
func (c *IPCache) cleanupExpired() {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := time.Now()
	expiredKeys := make([]string, 0)

	for key, entry := range c.cache {
		if now.After(entry.ExpiresAt) {
			expiredKeys = append(expiredKeys, key)
		}
	}

	for _, key := range expiredKeys {
		delete(c.cache, key)
	}

	if len(expiredKeys) > 0 {
		c.logger.Debugf("Cleaned up %d expired cache entries", len(expiredKeys))
	}
}

// GetStats returns cache statistics
func (c *IPCache) GetStats() map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()

	hits := atomic.LoadInt64(&c.hits)
	misses := atomic.LoadInt64(&c.misses)
	evictions := atomic.LoadInt64(&c.evictions)

	total := hits + misses
	var hitRate float64
	if total > 0 {
		hitRate = float64(hits) / float64(total) * 100
	}

	return map[string]interface{}{
		"entries":     len(c.cache),
		"hits":        hits,
		"misses":      misses,
		"evictions":   evictions,
		"hit_rate":    hitRate,
		"ttl_seconds": c.ttl.Seconds(),
		"max_entries": c.maxEntries,
	}
}

// Clear removes all entries from the cache
func (c *IPCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cache = make(map[string]*CacheEntry)
	atomic.StoreInt64(&c.hits, 0)
	atomic.StoreInt64(&c.misses, 0)
	atomic.StoreInt64(&c.evictions, 0)

	c.logger.Info("Cache cleared")
}

// Size returns the current number of entries in the cache
func (c *IPCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.cache)
}

// Close stops the cleanup goroutine
func (c *IPCache) Close() {
	if c.stopCh != nil {
		select {
		case <-c.stopCh:
			// Already closed
			return
		default:
			close(c.stopCh)
		}
	}
}

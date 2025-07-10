package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang-geoip/internal/config"
	"golang-geoip/internal/geoip"
	"golang-geoip/internal/handlers"
	"golang-geoip/internal/types"

	"github.com/sirupsen/logrus"
)

// Integration tests for the full GeoIP service
func TestGeoIPServiceIntegration(t *testing.T) {
	// Skip integration tests if not running with integration tag
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	// Create temporary directory for test databases
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise during tests

	t.Run("HTTP API Integration", func(t *testing.T) {
		// Create database manager (will fail to load real databases, but that's ok for API testing)
		dbManager := geoip.NewDatabaseManager(tempDir, "test-license", logger, true, time.Hour, 1000)
		defer func() {
			if err := dbManager.Close(); err != nil {
				t.Logf("Failed to close database manager: %v", err)
			}
		}()

		// Create API handler
		apiHandler := handlers.NewAPIHandler(dbManager, logger)
		router := apiHandler.SetupRoutes()

		// Create test server
		server := httptest.NewServer(router)
		defer server.Close()

		// Test JSON endpoint
		t.Run("JSON API", func(t *testing.T) {
			// Test with valid IP (should fail gracefully without real databases)
			resp, err := http.Get(server.URL + "/json/8.8.8.8")
			if err != nil {
				t.Fatalf("Failed to make JSON request: %v", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()

			// Should return some response structure even without databases
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("Expected 200 or 500, got %d", resp.StatusCode)
			}

			// Check content type
			contentType := resp.Header.Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("Expected JSON content type, got %s", contentType)
			}
		})

		// Test XML endpoint
		t.Run("XML API", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/xml/8.8.8.8")
			if err != nil {
				t.Fatalf("Failed to make XML request: %v", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()

			// Should return some response structure
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("Expected 200 or 500, got %d", resp.StatusCode)
			}

			// Check content type
			contentType := resp.Header.Get("Content-Type")
			if contentType != "application/xml" {
				t.Errorf("Expected XML content type, got %s", contentType)
			}
		})

		// Test CSV endpoint
		t.Run("CSV API", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/csv/1.1.1.1")
			if err != nil {
				t.Fatalf("Failed to make CSV request: %v", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()

			// Should return some response structure
			if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("Expected 200 or 500, got %d", resp.StatusCode)
			}

			// Check content type
			contentType := resp.Header.Get("Content-Type")
			if contentType != "text/csv" {
				t.Errorf("Expected CSV content type, got %s", contentType)
			}
		})

		// Test health endpoint
		t.Run("Health Check", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/health")
			if err != nil {
				t.Fatalf("Failed to make health request: %v", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Health check should return 200, got %d", resp.StatusCode)
			}

			var healthResponse map[string]string
			if err := json.NewDecoder(resp.Body).Decode(&healthResponse); err != nil {
				t.Errorf("Failed to decode health response: %v", err)
			}

			if healthResponse["status"] != "healthy" {
				t.Errorf("Expected healthy status, got %s", healthResponse["status"])
			}
		})

		// Test stats endpoint
		t.Run("Stats Endpoint", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/stats")
			if err != nil {
				t.Fatalf("Failed to make stats request: %v", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()

			if resp.StatusCode != http.StatusOK {
				t.Errorf("Stats should return 200, got %d", resp.StatusCode)
			}

			var statsResponse map[string]interface{}
			if err := json.NewDecoder(resp.Body).Decode(&statsResponse); err != nil {
				t.Errorf("Failed to decode stats response: %v", err)
			}

			// Should have enabled field
			if _, ok := statsResponse["enabled"]; !ok {
				t.Error("Stats response should contain 'enabled' field")
			}
		})

		// Test error handling
		t.Run("Error Handling", func(t *testing.T) {
			// Test invalid IP
			resp, err := http.Get(server.URL + "/json/invalid-ip")
			if err != nil {
				t.Fatalf("Failed to make invalid IP request: %v", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()

			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("Invalid IP should return 400, got %d", resp.StatusCode)
			}
		})

		// Test CORS headers
		t.Run("CORS Headers", func(t *testing.T) {
			resp, err := http.Get(server.URL + "/json/8.8.8.8")
			if err != nil {
				t.Fatalf("Failed to make CORS request: %v", err)
			}
			defer func() {
				if err := resp.Body.Close(); err != nil {
					t.Logf("Failed to close response body: %v", err)
				}
			}()

			// Check CORS headers
			corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
			if corsOrigin != "*" {
				t.Errorf("Expected CORS origin *, got %s", corsOrigin)
			}

			corsMethod := resp.Header.Get("Access-Control-Allow-Methods")
			if corsMethod == "" {
				t.Error("Expected CORS methods header")
			}
		})
	})

	t.Run("Database Manager Integration", func(t *testing.T) {
		// Test database manager functionality
		dbManager := geoip.NewDatabaseManager(tempDir, "test-license", logger, true, time.Minute, 100)
		defer func() {
			if err := dbManager.Close(); err != nil {
				t.Logf("Failed to close database manager: %v", err)
			}
		}()

		// Test GetDatabaseStatus
		status := dbManager.GetDatabaseStatus()
		if len(status) == 0 {
			t.Error("Database status should not be empty")
		}

		expectedDatabases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}
		for _, dbName := range expectedDatabases {
			if _, exists := status[dbName]; !exists {
				t.Errorf("Database %s should be in status", dbName)
			}
		}

		// Test GetCacheStats
		cacheStats := dbManager.GetCacheStats()
		if cacheStats == nil {
			t.Error("Cache stats should not be nil")
		}

		if enabled, ok := cacheStats["enabled"]; !ok || !enabled.(bool) {
			t.Error("Cache should be enabled in this test")
		}

		// Test CheckForUpdates
		hasUpdates, err := dbManager.CheckForUpdates()
		if err != nil {
			t.Errorf("CheckForUpdates should not error: %v", err)
		}
		// Result doesn't matter, just check it doesn't crash
		_ = hasUpdates
	})

	t.Run("Configuration Integration", func(t *testing.T) {
		// Test configuration loading and validation
		tempConfigFile := filepath.Join(tempDir, "test-config.yaml")

		configContent := `
server:
  host: "127.0.0.1"
  port: 8080
  read_timeout: "30s"
  write_timeout: "30s"
  idle_timeout: "120s"

database:
  path: "./data"
  maxmind_license: "test_license_key"

cache:
  enabled: true
  ttl: "1h"
  max_entries: 10000

logging:
  level: "info"
  format: "json"
`

		if err := os.WriteFile(tempConfigFile, []byte(configContent), 0644); err != nil {
			t.Fatalf("Failed to write test config: %v", err)
		}

		// Test config loading (from environment variables)
		cfg := config.LoadConfig()

		// Validate config values (these are loaded from environment variables)
		if cfg.Port == 0 {
			t.Error("Port should be set")
		}

		if cfg.DBPath == "" {
			t.Error("DB path should be set")
		}

		if cfg.LogLevel == "" {
			t.Error("Log level should be set")
		}

		// Test that config structure exists
		_ = cfg.CacheEnabled
		_ = cfg.CacheTTL
		_ = cfg.MaxMindLicense
	})

	t.Run("Mock GeoIP Data Flow", func(t *testing.T) {
		// Test the data flow with mock data
		dbManager := geoip.NewDatabaseManager(tempDir, "test-license", logger, true, time.Minute, 10)
		defer func() {
			if err := dbManager.Close(); err != nil {
				t.Logf("Failed to close database manager: %v", err)
			}
		}()

		// Test that GetGeoIPInfo returns proper structure
		info, err := dbManager.GetGeoIPInfo("8.8.8.8")

		// Should return a GeoIPInfo structure (even if empty due to no real databases)
		if info == nil && err == nil {
			t.Error("GetGeoIPInfo should return either info or error")
		}

		if info != nil {
			// Should have IP field set
			if info.IP != "8.8.8.8" {
				t.Errorf("Expected IP 8.8.8.8, got %s", info.IP)
			}

			// Test that structure has all expected fields
			checkGeoIPInfoStructure(t, info)
		}

		// Test cache behavior
		stats1 := dbManager.GetCacheStats()

		// Make another call to same IP (should exercise cache)
		_, _ = dbManager.GetGeoIPInfo("8.8.8.8")

		stats2 := dbManager.GetCacheStats()

		// Cache stats should exist
		if stats1 == nil || stats2 == nil {
			t.Error("Cache stats should not be nil")
		}
	})

	t.Run("Concurrent Access Integration", func(t *testing.T) {
		// Test concurrent access to the system
		dbManager := geoip.NewDatabaseManager(tempDir, "test-license", logger, true, time.Minute, 100)
		defer func() {
			if err := dbManager.Close(); err != nil {
				t.Logf("Failed to close database manager: %v", err)
			}
		}()

		apiHandler := handlers.NewAPIHandler(dbManager, logger)
		router := apiHandler.SetupRoutes()
		server := httptest.NewServer(router)
		defer server.Close()

		// Start multiple goroutines making requests
		done := make(chan bool, 3)

		// JSON requests
		go func() {
			defer func() { done <- true }()
			for i := 0; i < 10; i++ {
				resp, err := http.Get(fmt.Sprintf("%s/json/192.168.1.%d", server.URL, i%5+1))
				if err == nil {
					if cerr := resp.Body.Close(); cerr != nil {
						// Note: logging in goroutines can be problematic, just ignore error
						_ = cerr
					}
				}
			}
		}()

		// XML requests
		go func() {
			defer func() { done <- true }()
			for i := 0; i < 10; i++ {
				resp, err := http.Get(fmt.Sprintf("%s/xml/10.0.0.%d", server.URL, i%5+1))
				if err == nil {
					if cerr := resp.Body.Close(); cerr != nil {
						// Note: logging in goroutines can be problematic, just ignore error
						_ = cerr
					}
				}
			}
		}()

		// Health checks
		go func() {
			defer func() { done <- true }()
			for i := 0; i < 5; i++ {
				resp, err := http.Get(server.URL + "/health")
				if err == nil {
					if cerr := resp.Body.Close(); cerr != nil {
						// Note: logging in goroutines can be problematic, just ignore error
						_ = cerr
					}
				}
			}
		}()

		// Wait for all goroutines
		for i := 0; i < 3; i++ {
			<-done
		}

		// Verify system is still responsive
		resp, err := http.Get(server.URL + "/health")
		if err != nil {
			t.Fatalf("System should be responsive after concurrent access: %v", err)
		}
		defer func() {
			if err := resp.Body.Close(); err != nil {
				t.Logf("Failed to close response body: %v", err)
			}
		}()

		if resp.StatusCode != http.StatusOK {
			t.Error("System should return 200 for health check after concurrent access")
		}
	})
}

// Helper function to check GeoIPInfo structure
func checkGeoIPInfoStructure(t *testing.T, info *types.GeoIPInfo) {
	// Check that all fields exist (even if empty)
	if info.IP == "" {
		t.Error("IP field should not be empty")
	}

	// Other fields can be empty if no database is loaded, just check they exist
	_ = info.Country
	_ = info.CountryCode
	_ = info.Region
	_ = info.RegionCode
	_ = info.City
	_ = info.Latitude
	_ = info.Longitude
	_ = info.PostalCode
	_ = info.TimeZone
	_ = info.ASN
	_ = info.ASNOrg
	_ = info.ISP
}

// Benchmark integration test
func BenchmarkIntegrationAPI(b *testing.B) {
	if testing.Short() {
		b.Skip("Skipping integration benchmarks in short mode")
	}

	tempDir := b.TempDir()
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	dbManager := geoip.NewDatabaseManager(tempDir, "test-license", logger, true, time.Hour, 1000)
	defer func() {
		if err := dbManager.Close(); err != nil {
			b.Logf("Failed to close database manager: %v", err)
		}
	}()

	apiHandler := handlers.NewAPIHandler(dbManager, logger)
	router := apiHandler.SetupRoutes()
	server := httptest.NewServer(router)
	defer server.Close()

	testIPs := []string{
		"8.8.8.8",
		"1.1.1.1",
		"192.168.1.1",
		"10.0.0.1",
		"172.16.0.1",
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			ip := testIPs[i%len(testIPs)]
			resp, err := http.Get(server.URL + "/json/" + ip)
			if err == nil {
				if cerr := resp.Body.Close(); cerr != nil {
					// Ignore error in benchmark
					_ = cerr
				}
			}
			i++
		}
	})
}

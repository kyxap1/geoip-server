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

	"github.com/kyxap1/geoip-server/internal/config"
	"github.com/kyxap1/geoip-server/internal/geoip"
	"github.com/kyxap1/geoip-server/internal/handlers"
	"github.com/kyxap1/geoip-server/internal/types"

	"github.com/sirupsen/logrus"
)

// Integration tests for the full GeoIP service
// setupIntegrationTest creates common test dependencies
func setupIntegrationTest(t *testing.T) (string, *logrus.Logger) {
	if testing.Short() {
		t.Skip("Skipping integration tests in short mode")
	}

	tempDir := t.TempDir()
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	return tempDir, logger
}

func TestHTTPAPIIntegration(t *testing.T) {
	tempDir, logger := setupIntegrationTest(t)

	dbManager := geoip.NewDatabaseManager(tempDir, "test-license", logger, true, time.Hour, 1000)
	defer closeWithLog(t, dbManager)

	apiHandler := handlers.NewAPIHandler(dbManager, logger)
	router := apiHandler.SetupRoutes()
	server := httptest.NewServer(router)
	defer server.Close()

	t.Run("JSON API", func(t *testing.T) {
		testJSONAPI(t, server.URL)
	})

	t.Run("XML API", func(t *testing.T) {
		testXMLAPI(t, server.URL)
	})

	t.Run("CSV API", func(t *testing.T) {
		testCSVAPI(t, server.URL)
	})

	t.Run("Health Check", func(t *testing.T) {
		testHealthEndpoint(t, server.URL)
	})

	t.Run("Stats Endpoint", func(t *testing.T) {
		testStatsEndpoint(t, server.URL)
	})

	t.Run("Error Handling", func(t *testing.T) {
		testErrorHandling(t, server.URL)
	})

	t.Run("CORS Headers", func(t *testing.T) {
		testCORSHeaders(t, server.URL)
	})
}

func TestDatabaseManagerIntegration(t *testing.T) {
	tempDir, logger := setupIntegrationTest(t)

	dbManager := geoip.NewDatabaseManager(tempDir, "test-license", logger, true, time.Minute, 100)
	defer closeWithLog(t, dbManager)

	testDatabaseStatus(t, dbManager)
	testCacheStats(t, dbManager)
	testCheckForUpdates(t, dbManager)
}

func TestConfigurationIntegration(t *testing.T) {
	tempDir, _ := setupIntegrationTest(t)

	testConfigLoading(t, tempDir)
}

func TestMockGeoIPDataFlow(t *testing.T) {
	tempDir, logger := setupIntegrationTest(t)

	dbManager := geoip.NewDatabaseManager(tempDir, "test-license", logger, true, time.Minute, 10)
	defer closeWithLog(t, dbManager)

	testGeoIPDataFlow(t, dbManager)
	testCacheBehavior(t, dbManager)
}

func TestConcurrentAccessIntegration(t *testing.T) {
	tempDir, logger := setupIntegrationTest(t)

	dbManager := geoip.NewDatabaseManager(tempDir, "test-license", logger, true, time.Minute, 100)
	defer closeWithLog(t, dbManager)

	apiHandler := handlers.NewAPIHandler(dbManager, logger)
	router := apiHandler.SetupRoutes()
	server := httptest.NewServer(router)
	defer server.Close()

	testConcurrentAccess(t, server.URL)
}

// Helper functions

func closeWithLog(t *testing.T, dbManager *geoip.DatabaseManager) {
	if err := dbManager.Close(); err != nil {
		t.Logf("Failed to close database manager: %v", err)
	}
}

func testJSONAPI(t *testing.T, serverURL string) {
	resp, err := http.Get(serverURL + "/json/8.8.8.8")
	if err != nil {
		t.Fatalf("Failed to make JSON request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected 200 or 500, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected JSON content type, got %s", contentType)
	}
}

func testXMLAPI(t *testing.T, serverURL string) {
	resp, err := http.Get(serverURL + "/xml/8.8.8.8")
	if err != nil {
		t.Fatalf("Failed to make XML request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected 200 or 500, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/xml" {
		t.Errorf("Expected XML content type, got %s", contentType)
	}
}

func testCSVAPI(t *testing.T, serverURL string) {
	resp, err := http.Get(serverURL + "/csv/1.1.1.1")
	if err != nil {
		t.Fatalf("Failed to make CSV request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Failed to close response body: %v", err)
		}
	}()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("Expected 200 or 500, got %d", resp.StatusCode)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType != "text/csv" {
		t.Errorf("Expected CSV content type, got %s", contentType)
	}
}

func testHealthEndpoint(t *testing.T, serverURL string) {
	resp, err := http.Get(serverURL + "/health")
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
}

func testStatsEndpoint(t *testing.T, serverURL string) {
	resp, err := http.Get(serverURL + "/stats")
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

	if _, ok := statsResponse["enabled"]; !ok {
		t.Error("Stats response should contain 'enabled' field")
	}
}

func testErrorHandling(t *testing.T, serverURL string) {
	resp, err := http.Get(serverURL + "/json/invalid-ip")
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
}

func testCORSHeaders(t *testing.T, serverURL string) {
	resp, err := http.Get(serverURL + "/json/8.8.8.8")
	if err != nil {
		t.Fatalf("Failed to make CORS request: %v", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			t.Logf("Failed to close response body: %v", err)
		}
	}()

	corsOrigin := resp.Header.Get("Access-Control-Allow-Origin")
	if corsOrigin != "*" {
		t.Errorf("Expected CORS origin *, got %s", corsOrigin)
	}

	corsMethod := resp.Header.Get("Access-Control-Allow-Methods")
	if corsMethod == "" {
		t.Error("Expected CORS methods header")
	}
}

func testDatabaseStatus(t *testing.T, dbManager *geoip.DatabaseManager) {
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
}

func testCacheStats(t *testing.T, dbManager *geoip.DatabaseManager) {
	cacheStats := dbManager.GetCacheStats()
	if cacheStats == nil {
		t.Error("Cache stats should not be nil")
	}

	if enabled, ok := cacheStats["enabled"]; !ok || !enabled.(bool) {
		t.Error("Cache should be enabled in this test")
	}
}

func testCheckForUpdates(t *testing.T, dbManager *geoip.DatabaseManager) {
	hasUpdates, err := dbManager.CheckForUpdates()
	if err != nil {
		t.Errorf("CheckForUpdates should not error: %v", err)
	}
	_ = hasUpdates // Result doesn't matter, just check it doesn't crash
}

func testConfigLoading(t *testing.T, tempDir string) {
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

	cfg := config.LoadConfig()

	if cfg.Port == 0 {
		t.Error("Port should be set")
	}

	if cfg.DBPath == "" {
		t.Error("DB path should be set")
	}

	if cfg.LogLevel == "" {
		t.Error("Log level should be set")
	}

	_ = cfg.CacheEnabled
	_ = cfg.CacheTTL
	_ = cfg.MaxMindLicense
}

func testGeoIPDataFlow(t *testing.T, dbManager *geoip.DatabaseManager) {
	info, err := dbManager.GetGeoIPInfo("8.8.8.8")

	if info == nil && err == nil {
		t.Error("GetGeoIPInfo should return either info or error")
	}

	if info != nil {
		if info.IP != "8.8.8.8" {
			t.Errorf("Expected IP 8.8.8.8, got %s", info.IP)
		}
		checkGeoIPInfoStructure(t, info)
	}
}

func testCacheBehavior(t *testing.T, dbManager *geoip.DatabaseManager) {
	stats1 := dbManager.GetCacheStats()
	_, _ = dbManager.GetGeoIPInfo("8.8.8.8")
	stats2 := dbManager.GetCacheStats()

	if stats1 == nil || stats2 == nil {
		t.Error("Cache stats should not be nil")
	}
}

func testConcurrentAccess(t *testing.T, serverURL string) {
	done := make(chan bool, 3)

	// JSON requests
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 10; i++ {
			resp, err := http.Get(fmt.Sprintf("%s/json/192.168.1.%d", serverURL, i%5+1))
			if err == nil {
				_ = resp.Body.Close()
			}
		}
	}()

	// XML requests
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 10; i++ {
			resp, err := http.Get(fmt.Sprintf("%s/xml/10.0.0.%d", serverURL, i%5+1))
			if err == nil {
				_ = resp.Body.Close()
			}
		}
	}()

	// Health checks
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 5; i++ {
			resp, err := http.Get(serverURL + "/health")
			if err == nil {
				_ = resp.Body.Close()
			}
		}
	}()

	// Wait for all goroutines
	for i := 0; i < 3; i++ {
		<-done
	}

	// Verify system is still responsive
	resp, err := http.Get(serverURL + "/health")
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

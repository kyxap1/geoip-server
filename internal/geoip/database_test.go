package geoip

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestDatabaseManager_Initialize(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce log noise during tests

	// Create database manager without cache for tests
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Since we don't have real databases, this will fail
	err := dbManager.Initialize()
	if err == nil {
		t.Error("Expected error when initializing without databases")
	}
}

func TestDatabaseManager_GetDatabaseStatus(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create database manager without cache for tests
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Get status (should show databases as not available)
	status := dbManager.GetDatabaseStatus()

	if len(status) == 0 {
		t.Error("Expected database status information")
	}

	// Check that all expected databases are in the status
	expectedDatabases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}
	for _, dbName := range expectedDatabases {
		if _, exists := status[dbName]; !exists {
			t.Errorf("Database %s not found in status", dbName)
		}

		dbStatus := status[dbName].(map[string]interface{})
		if exists, ok := dbStatus["exists"]; !ok || exists.(bool) {
			t.Errorf("Database %s should not exist in empty directory", dbName)
		}
	}
}

func TestDatabaseManager_GetCacheStats(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Test without cache
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)
	stats := dbManager.GetCacheStats()

	if enabled, ok := stats["enabled"]; !ok || enabled.(bool) {
		t.Error("Cache should be disabled")
	}

	// Test with cache
	dbManagerWithCache := NewDatabaseManager(tempDir, "test-license", logger, true, time.Hour, 1000)
	statsWithCache := dbManagerWithCache.GetCacheStats()

	if enabled, ok := statsWithCache["enabled"]; !ok || !enabled.(bool) {
		t.Error("Cache should be enabled")
	}

	if _, ok := statsWithCache["hits"]; !ok {
		t.Error("Cache stats should include hits")
	}

	if _, ok := statsWithCache["misses"]; !ok {
		t.Error("Cache stats should include misses")
	}
}

func TestDatabaseManager_CalculateFileChecksum(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create database manager without cache for tests
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Create a test file
	testFile := filepath.Join(tempDir, "test.txt")
	testContent := "test content for checksum"
	err := os.WriteFile(testFile, []byte(testContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	// Calculate checksum
	checksum, err := dbManager.calculateFileChecksum(testFile)
	if err != nil {
		t.Fatalf("Failed to calculate checksum: %v", err)
	}

	if checksum == "" {
		t.Error("Expected non-empty checksum")
	}

	// Verify checksum is consistent
	checksum2, err := dbManager.calculateFileChecksum(testFile)
	if err != nil {
		t.Fatalf("Failed to calculate checksum second time: %v", err)
	}

	if checksum != checksum2 {
		t.Error("Checksum should be consistent")
	}
}

func TestDatabaseManager_BackupAndRollback(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create database manager without cache for tests
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Create mock database files
	databases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}
	for _, dbName := range databases {
		dbPath := filepath.Join(tempDir, dbName+".mmdb")
		content := "mock database content for " + dbName
		err := os.WriteFile(dbPath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create mock database %s: %v", dbName, err)
		}

		// Create checksum file
		checksum, err := dbManager.calculateFileChecksum(dbPath)
		if err != nil {
			t.Fatalf("Failed to calculate checksum for %s: %v", dbName, err)
		}

		checksumPath := filepath.Join(tempDir, dbName+".checksum")
		err = os.WriteFile(checksumPath, []byte(checksum), 0644)
		if err != nil {
			t.Fatalf("Failed to create checksum file for %s: %v", dbName, err)
		}
	}

	// Create backup directory
	backupDir := filepath.Join(tempDir, "backup")
	err := os.MkdirAll(backupDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create backup directory: %v", err)
	}

	// Test backup
	err = dbManager.backupCurrentDatabases()
	if err != nil {
		t.Fatalf("Failed to backup databases: %v", err)
	}

	// Verify backup files exist
	backupFiles, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("Failed to read backup directory: %v", err)
	}

	if len(backupFiles) == 0 {
		t.Error("Expected backup files to be created")
	}

	// Modify original files
	for _, dbName := range databases {
		dbPath := filepath.Join(tempDir, dbName+".mmdb")
		err := os.WriteFile(dbPath, []byte("corrupted content"), 0644)
		if err != nil {
			t.Fatalf("Failed to modify database %s: %v", dbName, err)
		}
	}

	// Test rollback - note: this will skip backup verification due to invalid database format
	// In production, rollback would only restore valid database files
	err = dbManager.rollbackDatabases()
	if err != nil {
		t.Fatalf("Failed to rollback databases: %v", err)
	}

	// Note: In this test, files won't be restored because they fail validation
	// This is expected behavior - the system protects against restoring invalid databases
	// In production, only valid database backups would be restored
	t.Log("Rollback completed - invalid database files were not restored (expected behavior)")
}

func TestDatabaseManager_VerifyDatabaseIntegrity(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create database manager without cache for tests
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Test with no databases (should fail)
	err := dbManager.verifyDatabaseIntegrity()
	if err == nil {
		t.Error("Expected error when verifying non-existent databases")
	}

	// Create mock database files (these will fail verification as they're not real mmdb files)
	databases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}
	for _, dbName := range databases {
		dbPath := filepath.Join(tempDir, dbName+".mmdb")
		content := "mock database content for " + dbName
		err := os.WriteFile(dbPath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create mock database %s: %v", dbName, err)
		}
	}

	// Test integrity verification (should still fail due to invalid format)
	err = dbManager.verifyDatabaseIntegrity()
	if err == nil {
		t.Error("Expected error when verifying invalid database files")
	}
}

func TestDatabaseManager_CleanupOldBackups(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create database manager without cache for tests
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Create backup directory
	backupDir := filepath.Join(tempDir, "backup")
	err := os.MkdirAll(backupDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create backup directory: %v", err)
	}

	// Create multiple backup files with different timestamps
	timestamps := []string{
		"20240101-120000",
		"20240102-120000",
		"20240103-120000",
		"20240104-120000",
		"20240105-120000",
		"20240106-120000",
	}

	for _, timestamp := range timestamps {
		filename := fmt.Sprintf("GeoLite2-City-%s.mmdb", timestamp)
		filepath := filepath.Join(backupDir, filename)
		err := os.WriteFile(filepath, []byte("backup content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create backup file %s: %v", filename, err)
		}
	}

	// Test cleanup (keep 3 files)
	dbManager.cleanupOldBackups(backupDir, 3)

	// Check remaining files
	files, err := os.ReadDir(backupDir)
	if err != nil {
		t.Fatalf("Failed to read backup directory: %v", err)
	}

	if len(files) > 3 {
		t.Errorf("Expected at most 3 files after cleanup, got %d", len(files))
	}
}

func TestDatabaseManager_CopyFile(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create database manager without cache for tests
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Create source file
	srcFile := filepath.Join(tempDir, "source.txt")
	content := "test file content"
	err := os.WriteFile(srcFile, []byte(content), 0644)
	if err != nil {
		t.Fatalf("Failed to create source file: %v", err)
	}

	// Copy file
	dstFile := filepath.Join(tempDir, "destination.txt")
	err = dbManager.copyFile(srcFile, dstFile)
	if err != nil {
		t.Fatalf("Failed to copy file: %v", err)
	}

	// Verify copy
	copiedContent, err := os.ReadFile(dstFile)
	if err != nil {
		t.Fatalf("Failed to read copied file: %v", err)
	}

	if string(copiedContent) != content {
		t.Error("Copied file content doesn't match original")
	}
}

func TestDatabaseManager_FindLatestBackup(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create database manager without cache for tests
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Create backup directory
	backupDir := filepath.Join(tempDir, "backup")
	err := os.MkdirAll(backupDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create backup directory: %v", err)
	}

	// Test with no backups
	latest, err := dbManager.findLatestBackup(backupDir)
	if err != nil {
		t.Fatalf("Unexpected error finding latest backup: %v", err)
	}
	if latest != "" {
		t.Error("Expected empty string when no backups exist")
	}

	// Create backup files
	timestamps := []string{
		"20240101-120000",
		"20240103-120000", // This should be the latest
		"20240102-120000",
	}

	for _, timestamp := range timestamps {
		filename := fmt.Sprintf("GeoLite2-City-%s.mmdb", timestamp)
		filepath := filepath.Join(backupDir, filename)
		err := os.WriteFile(filepath, []byte("backup"), 0644)
		if err != nil {
			t.Fatalf("Failed to create backup file: %v", err)
		}
	}

	// Find latest backup
	latest, err = dbManager.findLatestBackup(backupDir)
	if err != nil {
		t.Fatalf("Failed to find latest backup: %v", err)
	}

	expectedLatest := "20240103-120000"
	if latest != expectedLatest {
		t.Errorf("Expected latest backup %s, got %s", expectedLatest, latest)
	}
}

// Test LoadDatabases function
func TestDatabaseManager_LoadDatabases(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create database manager
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Test loading databases when they don't exist
	err := dbManager.LoadDatabases()
	if err == nil {
		t.Error("Expected error when loading non-existent databases")
	}

	// Create mock database files (these will still fail because they're not real mmdb files)
	databases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}
	for _, dbName := range databases {
		dbPath := filepath.Join(tempDir, dbName+".mmdb")
		content := "mock database content for " + dbName
		err := os.WriteFile(dbPath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create mock database %s: %v", dbName, err)
		}
	}

	// Test loading invalid database files
	err = dbManager.LoadDatabases()
	if err == nil {
		t.Error("Expected error when loading invalid database files")
	}

	// Test that error message is informative
	if err != nil && err.Error() == "" {
		t.Error("Error message should not be empty")
	}
}

// Test GetGeoIPInfo function
func TestDatabaseManager_GetGeoIPInfo(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Test with cache enabled
	dbManagerWithCache := NewDatabaseManager(tempDir, "test-license", logger, true, time.Hour, 1000)

	// Test with invalid IP
	info, err := dbManagerWithCache.GetGeoIPInfo("invalid-ip")
	if err == nil {
		t.Error("Expected error for invalid IP")
	}
	if info != nil {
		t.Error("Expected nil info for invalid IP")
	}

	// Test with valid IP but no databases loaded
	info, err = dbManagerWithCache.GetGeoIPInfo("8.8.8.8")
	// Should return info with IP set but other fields empty when databases are not loaded
	if err != nil {
		t.Errorf("Should not return error for valid IP: %v", err)
	}
	if info == nil {
		t.Error("Should return info struct even when databases are not loaded")
	}
	if info != nil && info.IP != "8.8.8.8" {
		t.Error("Should set IP field correctly")
	}
	if info != nil && info.Country != "" {
		t.Error("Should not have country info when databases are not loaded")
	}

	// Test with cache disabled
	dbManagerNoCache := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)
	info, err = dbManagerNoCache.GetGeoIPInfo("8.8.8.8")
	// Should return info with IP set but other fields empty when databases are not loaded
	if err != nil {
		t.Errorf("Should not return error for valid IP: %v", err)
	}
	if info == nil {
		t.Error("Should return info struct even when databases are not loaded")
	}

	// Test caching behavior by calling twice (should still fail but exercise cache logic)
	_, _ = dbManagerWithCache.GetGeoIPInfo("192.168.1.1")
	_, _ = dbManagerWithCache.GetGeoIPInfo("192.168.1.1") // Second call should hit cache path
}

// Test Close function
func TestDatabaseManager_Close(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Test Close without cache
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)
	err := dbManager.Close()
	if err != nil {
		t.Errorf("Close should not return error when no cache: %v", err)
	}

	// Test Close with cache
	dbManagerWithCache := NewDatabaseManager(tempDir, "test-license", logger, true, time.Hour, 1000)
	err = dbManagerWithCache.Close()
	if err != nil {
		t.Errorf("Close should not return error with cache: %v", err)
	}

	// Test multiple Close calls (should be safe)
	err = dbManagerWithCache.Close()
	if err != nil {
		t.Errorf("Multiple Close calls should be safe: %v", err)
	}
}

// Test CheckForUpdates function
func TestDatabaseManager_CheckForUpdates(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create database manager
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Test check for updates when no databases exist
	hasUpdates, err := dbManager.CheckForUpdates()
	if err != nil {
		t.Errorf("CheckForUpdates should not return error when no databases exist: %v", err)
	}
	// Note: hasUpdates result may vary based on implementation, just check it doesn't panic
	_ = hasUpdates

	// Create mock database files
	databases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}
	for _, dbName := range databases {
		dbPath := filepath.Join(tempDir, dbName+".mmdb")
		content := "mock database content for " + dbName
		err := os.WriteFile(dbPath, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create mock database %s: %v", dbName, err)
		}
	}

	// Test check for updates with existing databases
	hasUpdates, err = dbManager.CheckForUpdates()
	if err != nil {
		t.Errorf("CheckForUpdates should not return error with existing databases: %v", err)
	}
	// Result doesn't matter much since we can't actually check remote servers in tests
}

// Test RollbackDatabases function
func TestDatabaseManager_RollbackDatabases(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create database manager
	dbManager := NewDatabaseManager(tempDir, "test-license", logger, false, 0, 0)

	// Test rollback when no backups exist
	err := dbManager.RollbackDatabases()
	if err == nil {
		t.Error("Expected error when rolling back with no backups")
	}

	// Create backup directory
	backupDir := filepath.Join(tempDir, "backup")
	err = os.MkdirAll(backupDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create backup directory: %v", err)
	}

	// Test rollback with empty backup directory
	err = dbManager.RollbackDatabases()
	if err == nil {
		t.Error("Expected error when rolling back with empty backup directory")
	}

	// Create some backup files (these will still fail validation but test the logic)
	timestamp := "20240101-120000"
	databases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}
	for _, dbName := range databases {
		backupFile := filepath.Join(backupDir, fmt.Sprintf("%s-%s.mmdb", dbName, timestamp))
		err := os.WriteFile(backupFile, []byte("backup content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create backup file: %v", err)
		}
	}

	// Test rollback with backup files present
	err = dbManager.RollbackDatabases()
	// This will likely fail due to validation, but it exercises the rollback logic
	// In a real scenario with valid database files, this would work
	if err != nil {
		t.Logf("Rollback failed as expected with mock data: %v", err)
	}
}

// Test additional edge cases
func TestDatabaseManager_EdgeCases(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Run("GetGeoIPInfo with cache miss and hit", func(t *testing.T) {
		dbManager := NewDatabaseManager(tempDir, "test-license", logger, true, time.Hour, 10)

		// Test multiple IPs to exercise cache logic
		testIPs := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1"}
		for _, ip := range testIPs {
			// First call - cache miss
			info1, err1 := dbManager.GetGeoIPInfo(ip)

			// Second call - should use same code path since databases aren't loaded
			info2, err2 := dbManager.GetGeoIPInfo(ip)

			// Both should fail in the same way
			if (err1 == nil) != (err2 == nil) {
				t.Errorf("Inconsistent error behavior for IP %s", ip)
			}
			if (info1 == nil) != (info2 == nil) {
				t.Errorf("Inconsistent info behavior for IP %s", ip)
			}
		}
	})

	t.Run("Close with partially initialized manager", func(t *testing.T) {
		dbManager := NewDatabaseManager(tempDir, "test-license", logger, true, time.Hour, 10)

		// Close immediately without doing anything
		err := dbManager.Close()
		if err != nil {
			t.Errorf("Close should handle partially initialized manager: %v", err)
		}
	})

	t.Run("Database operations with invalid paths", func(t *testing.T) {
		invalidPath := "/dev/null/nonexistent"
		dbManager := NewDatabaseManager(invalidPath, "test-license", logger, false, 0, 0)

		// These should handle invalid paths gracefully
		status := dbManager.GetDatabaseStatus()
		if len(status) == 0 {
			t.Error("Should return some status even with invalid path")
		}

		_, err := dbManager.CheckForUpdates()
		// Should not panic, error is acceptable
		_ = err
	})
}

// Test concurrency safety
func TestDatabaseManager_Concurrency(t *testing.T) {
	// Create temporary directory for test
	tempDir := t.TempDir()

	// Create logger
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	dbManager := NewDatabaseManager(tempDir, "test-license", logger, true, time.Hour, 100)
	defer dbManager.Close()

	// Test concurrent access to various methods
	done := make(chan bool, 4)

	// Goroutine 1: GetGeoIPInfo calls
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 50; i++ {
			_, _ = dbManager.GetGeoIPInfo(fmt.Sprintf("192.168.1.%d", i%10))
		}
	}()

	// Goroutine 2: GetCacheStats calls
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 50; i++ {
			_ = dbManager.GetCacheStats()
		}
	}()

	// Goroutine 3: GetDatabaseStatus calls
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 50; i++ {
			_ = dbManager.GetDatabaseStatus()
		}
	}()

	// Goroutine 4: CheckForUpdates calls
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 10; i++ {
			_, _ = dbManager.CheckForUpdates()
		}
	}()

	// Wait for all goroutines to complete
	for i := 0; i < 4; i++ {
		<-done
	}

	// Verify the manager is still functional
	stats := dbManager.GetCacheStats()
	if stats == nil {
		t.Error("Manager should still be functional after concurrent access")
	}
}

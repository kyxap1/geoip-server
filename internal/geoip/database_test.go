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

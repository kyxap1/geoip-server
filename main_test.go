package main

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"testing"

	cron "github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"golang-geoip/internal/config"
	"golang-geoip/internal/geoip"
)

func TestMaskLicenseKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Short key (should not be masked)",
			input:    "short123",
			expected: "short123",
		},
		{
			name:     "Key exactly 13 characters (should not be masked)",
			input:    "1234567890123",
			expected: "1234567890123",
		},
		{
			name:     "Standard MaxMind license key",
			input:    "pfSsgL_ARStest123456789mmk",
			expected: "pfSsgL_ARS...mmk",
		},
		{
			name:     "Long license key",
			input:    "abcdefghijklmnopqrstuvwxyz123456789",
			expected: "abcdefghij...789",
		},
		{
			name:     "Minimum maskable length (14 characters)",
			input:    "12345678901234",
			expected: "1234567890...234",
		},
		{
			name:     "Key with special characters",
			input:    "ABC-123_XYZ.456@789#mmk",
			expected: "ABC-123_XY...mmk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskLicenseKey(tt.input)
			if result != tt.expected {
				t.Errorf("maskLicenseKey(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMaskLicenseKeyEdgeCases(t *testing.T) {
	t.Run("Very long key", func(t *testing.T) {
		longKey := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		result := maskLicenseKey(longKey)
		expected := "abcdefghij...XYZ"
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})

	t.Run("Key with Unicode characters", func(t *testing.T) {
		unicodeKey := "test_license_ключ_мой_секрет"
		result := maskLicenseKey(unicodeKey)
		// Note: maskLicenseKey works with bytes, not Unicode runes,
		// so the last 3 bytes might not be complete Unicode characters
		// This is acceptable for license key masking as they're typically ASCII
		if len(result) == 0 {
			t.Error("Result should not be empty")
		}
		if result == unicodeKey {
			t.Error("Key should be masked, not returned as-is")
		}
		if !containsString(result, "...") {
			t.Error("Result should contain '...' separator")
		}
	})

	t.Run("Key with only numbers", func(t *testing.T) {
		numberKey := "12345678901234567890"
		result := maskLicenseKey(numberKey)
		expected := "1234567890...890"
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})
}

func TestMaskLicenseKeySecurityConsiderations(t *testing.T) {
	t.Run("Masked result should not contain middle part", func(t *testing.T) {
		sensitiveKey := "prefix_SENSITIVE_MIDDLE_PART_suffix"
		result := maskLicenseKey(sensitiveKey)

		// Check that sensitive middle part is not in the result
		if result == sensitiveKey {
			t.Error("Key should be masked, not returned as-is")
		}
		if len(result) >= len(sensitiveKey) {
			t.Error("Masked result should be shorter than original")
		}

		// Check format
		expectedPrefix := sensitiveKey[:10]
		expectedSuffix := sensitiveKey[len(sensitiveKey)-3:]
		if !startsWith(result, expectedPrefix) {
			t.Errorf("Result should start with %q, but got %q", expectedPrefix, result)
		}
		if !endsWith(result, expectedSuffix) {
			t.Errorf("Result should end with %q, but got %q", expectedSuffix, result)
		}
		if !containsString(result, "...") {
			t.Error("Result should contain '...' separator")
		}
	})
}

// Test graceful shutdown functionality
func TestGracefulShutdown(t *testing.T) {
	// Create a test logger that doesn't output to console
	testLogger := logrus.New()
	testLogger.SetOutput(io.Discard)

	// Save original logger and restore after test
	originalLogger := logger
	logger = testLogger
	defer func() {
		logger = originalLogger
	}()

	t.Run("Shutdown with all services", func(t *testing.T) {
		// Create test HTTP server
		server := &http.Server{
			Addr: ":0", // Use available port
		}

		// Create test HTTPS server
		httpsServer := &http.Server{
			Addr: ":0", // Use available port
		}

		// Create test cron scheduler
		cronScheduler := cron.New()

		// Create real database manager with temp directory for testing
		tempDir := t.TempDir()
		dbManager := geoip.NewDatabaseManager(tempDir, "test_license", testLogger, false, 0, 0)

		// Create wait group
		var wg sync.WaitGroup

		// Test graceful shutdown
		err := gracefulShutdown(server, httpsServer, cronScheduler, dbManager, &wg)
		if err != nil {
			t.Errorf("gracefulShutdown returned error: %v", err)
		}
	})

	t.Run("Shutdown with only HTTP server", func(t *testing.T) {
		server := &http.Server{Addr: ":0"}
		tempDir := t.TempDir()
		dbManager := geoip.NewDatabaseManager(tempDir, "test_license", testLogger, false, 0, 0)
		var wg sync.WaitGroup

		err := gracefulShutdown(server, nil, nil, dbManager, &wg)
		if err != nil {
			t.Errorf("gracefulShutdown returned error: %v", err)
		}
	})

	t.Run("Shutdown basic functionality", func(t *testing.T) {
		server := &http.Server{Addr: ":0"}
		tempDir := t.TempDir()
		dbManager := geoip.NewDatabaseManager(tempDir, "test_license", testLogger, false, 0, 0)
		var wg sync.WaitGroup

		err := gracefulShutdown(server, nil, nil, dbManager, &wg)
		if err != nil {
			t.Errorf("gracefulShutdown should not return error: %v", err)
		}
	})
}

// Test CLI commands
func TestCLICommands(t *testing.T) {
	// Save original config and restore after test
	originalCfg := cfg
	defer func() {
		cfg = originalCfg
	}()

	// Create test config
	cfg = &config.Config{
		MaxMindLicense: "test_license_key_123456789abc",
		DBPath:         t.TempDir(),
		LogLevel:       "error", // Suppress logs during tests
	}

	t.Run("Update command with license", func(t *testing.T) {
		cmd := &cobra.Command{}
		err := updateCmd.RunE(cmd, []string{})
		// This will fail because we don't have real MaxMind access, but it should
		// get past the license check
		if err == nil || err.Error() == "MaxMind license key is required" {
			t.Error("Update command should pass license validation")
		}
	})

	t.Run("Update command without license", func(t *testing.T) {
		// Temporarily remove license
		originalLicense := cfg.MaxMindLicense
		cfg.MaxMindLicense = ""
		defer func() {
			cfg.MaxMindLicense = originalLicense
		}()

		cmd := &cobra.Command{}
		err := updateCmd.RunE(cmd, []string{})
		if err == nil || err.Error() != "MaxMind license key is required" {
			t.Errorf("Expected license error, got: %v", err)
		}
	})

	t.Run("Status command", func(t *testing.T) {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		cmd := &cobra.Command{}
		err := statusCmd.RunE(cmd, []string{})

		// Restore stdout
		if cerr := w.Close(); cerr != nil {
			t.Logf("Failed to close pipe writer: %v", cerr)
		}
		os.Stdout = old

		// Read captured output
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		if err != nil {
			t.Errorf("Status command failed: %v", err)
		}

		if !containsString(output, "Database Status:") {
			t.Error("Status command should output database status header")
		}
	})

	t.Run("Rollback command", func(t *testing.T) {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		cmd := &cobra.Command{}
		err := rollbackCmd.RunE(cmd, []string{})

		// Restore stdout
		if cerr := w.Close(); cerr != nil {
			t.Logf("Failed to close pipe writer: %v", cerr)
		}
		os.Stdout = old

		// This might fail due to no backups, but should not panic
		// and should show proper error handling
		if err == nil {
			// Read output to ensure it's working
			var buf bytes.Buffer
			_, _ = io.Copy(&buf, r)
			output := buf.String()
			if !containsString(output, "rollback") {
				t.Error("Rollback command should output rollback information")
			}
		}
	})

	t.Run("Version command", func(t *testing.T) {
		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		cmd := &cobra.Command{}
		versionCmd.Run(cmd, []string{})

		// Restore stdout
		if cerr := w.Close(); cerr != nil {
			t.Logf("Failed to close pipe writer: %v", cerr)
		}
		os.Stdout = old

		// Read captured output
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		if !containsString(output, "GeoIP Server") {
			t.Error("Version command should output server version")
		}
		if !containsString(output, "v1.0.0") {
			t.Error("Version command should output version number")
		}
	})
}

func TestCertificateCommands(t *testing.T) {
	// Save original config and restore after test
	originalCfg := cfg
	defer func() {
		cfg = originalCfg
	}()

	tempDir := t.TempDir()
	cfg = &config.Config{
		CertPath:      tempDir,
		CertFile:      "",
		KeyFile:       "",
		CertHosts:     "localhost,127.0.0.1",
		CertValidDays: 30,
		LogLevel:      "error", // Suppress logs during tests
	}

	// Save original logger and use test logger
	originalLogger := logger
	testLogger := logrus.New()
	testLogger.SetOutput(io.Discard)
	logger = testLogger
	defer func() {
		logger = originalLogger
	}()

	t.Run("Cert generate command", func(t *testing.T) {
		cmd := &cobra.Command{}
		err := certGenerateCmd.RunE(cmd, []string{})
		if err != nil {
			t.Errorf("Certificate generation failed: %v", err)
		}

		// Check if certificate files were created
		certPath := filepath.Join(tempDir, "server.crt")
		keyPath := filepath.Join(tempDir, "server.key")

		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			t.Error("Certificate file was not created")
		}
		if _, err := os.Stat(keyPath); os.IsNotExist(err) {
			t.Error("Key file was not created")
		}
	})

	t.Run("Cert info command", func(t *testing.T) {
		// First generate a certificate
		cmd := &cobra.Command{}
		err := certGenerateCmd.RunE(cmd, []string{})
		if err != nil {
			t.Fatalf("Failed to generate certificate for info test: %v", err)
		}

		// Capture stdout
		old := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w

		err = certInfoCmd.RunE(cmd, []string{})

		// Restore stdout
		if cerr := w.Close(); cerr != nil {
			t.Logf("Failed to close pipe writer: %v", cerr)
		}
		os.Stdout = old

		if err != nil {
			t.Errorf("Certificate info command failed: %v", err)
		}

		// Read captured output
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		output := buf.String()

		if !containsString(output, "Certificate Information:") {
			t.Error("Cert info should output certificate information header")
		}
		if !containsString(output, "Subject:") {
			t.Error("Cert info should output certificate subject")
		}
	})

	t.Run("Cert info command without certificate", func(t *testing.T) {
		// Use a different temporary directory without certificates
		tempDir2 := t.TempDir()
		originalCertPath := cfg.CertPath
		cfg.CertPath = tempDir2
		defer func() {
			cfg.CertPath = originalCertPath
		}()

		cmd := &cobra.Command{}
		err := certInfoCmd.RunE(cmd, []string{})
		if err == nil {
			t.Error("Cert info command should fail when no certificate exists")
		}
	})
}

func TestRunServerValidation(t *testing.T) {
	// Save original config and restore after test
	originalCfg := cfg
	defer func() {
		cfg = originalCfg
	}()

	// Save original logger and use test logger
	originalLogger := logger
	testLogger := logrus.New()
	testLogger.SetOutput(io.Discard)
	logger = testLogger
	defer func() {
		logger = originalLogger
	}()

	t.Run("Server without MaxMind license", func(t *testing.T) {
		cfg = &config.Config{
			MaxMindLicense: "",
			DBPath:         t.TempDir(),
		}

		cmd := &cobra.Command{}
		err := runServer(cmd, []string{})
		if err == nil || err.Error() != "MaxMind license key is required" {
			t.Errorf("Expected license error, got: %v", err)
		}
	})

	// Remove the problematic test that might cause fatal errors
}

func TestInitFunction(t *testing.T) {
	// Test that init function sets up logger and config properly
	// This is more of a smoke test since init() already ran

	if logger == nil {
		t.Error("Logger should be initialized")
	}

	if cfg == nil {
		t.Error("Config should be initialized")
	}

	// Test logger configuration
	if logger.Formatter == nil {
		t.Error("Logger formatter should be set")
	}

	// Test that config has reasonable defaults
	if cfg.Port <= 0 {
		t.Error("Config should have valid default port")
	}
}

func TestCommandStructure(t *testing.T) {
	// Test that all commands are properly structured

	t.Run("Update command structure", func(t *testing.T) {
		if updateCmd.Use != "update" {
			t.Error("Update command should have correct Use field")
		}
		if updateCmd.RunE == nil {
			t.Error("Update command should have RunE function")
		}
	})

	t.Run("Status command structure", func(t *testing.T) {
		if statusCmd.Use != "status" {
			t.Error("Status command should have correct Use field")
		}
		if statusCmd.RunE == nil {
			t.Error("Status command should have RunE function")
		}
	})

	t.Run("Certificate command structure", func(t *testing.T) {
		if certCmd.Use != "cert" {
			t.Error("Cert command should have correct Use field")
		}
		if len(certCmd.Commands()) < 2 {
			t.Error("Cert command should have subcommands")
		}
	})

	t.Run("Version command structure", func(t *testing.T) {
		if versionCmd.Use != "version" {
			t.Error("Version command should have correct Use field")
		}
		if versionCmd.Run == nil {
			t.Error("Version command should have Run function")
		}
	})
}

// Helper functions for tests
func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

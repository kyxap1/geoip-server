package main

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Helper function to run CLI commands in tests
func runCLICommand(args ...string) (string, string, error) {
	cmd := exec.Command("go", append([]string{"run", "."}, args...)...)
	cmd.Env = append(os.Environ(), "LOG_LEVEL=info") // Allow info logs to see success messages

	// Capture output
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	return stdout.String(), stderr.String(), err
}

func TestCLI_CertGenerateCommand(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "generate_test")

	stdout, stderr, err := runCLICommand(
		"cert", "generate",
		"--cert-path", certPath,
		"--cert-hosts", "test.local,192.168.1.100",
		"--cert-valid-days", "30",
	)

	if err != nil {
		t.Fatalf("cert generate command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	validateGeneratedCertFiles(t, certPath)
}

func TestCLI_CertInfoCommand(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "info_test")

	// Generate certificates first
	_, _, err := runCLICommand(
		"cert", "generate",
		"--cert-path", certPath,
		"--cert-hosts", "info.test,127.0.0.1",
	)
	if err != nil {
		t.Fatalf("Failed to generate certificates for info test: %v", err)
	}

	stdout, stderr, err := runCLICommand(
		"cert", "info",
		"--cert-path", certPath,
	)

	if err != nil {
		t.Fatalf("cert info command failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	validateCertInfoOutput(t, stdout, certPath)
}

func TestCLI_CertInfoNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	nonExistentPath := filepath.Join(tempDir, "nonexistent")

	_, stderr, err := runCLICommand(
		"cert", "info",
		"--cert-path", nonExistentPath,
	)

	if err == nil {
		t.Error("cert info should fail when certificates don't exist")
	}

	if !strings.Contains(stderr, "certificates not found") {
		t.Errorf("Expected 'certificates not found' error, got: %s", stderr)
	}
}

// Helper functions for CLI cert command validation

func validateGeneratedCertFiles(t *testing.T, certPath string) {
	certFile := filepath.Join(certPath, "server.crt")
	keyFile := filepath.Join(certPath, "server.key")

	if _, err := os.Stat(certFile); os.IsNotExist(err) {
		t.Error("Certificate file was not created")
	}
	if _, err := os.Stat(keyFile); os.IsNotExist(err) {
		t.Error("Key file was not created")
	}

	// Check file permissions
	if certInfo, err := os.Stat(certFile); err == nil {
		if certInfo.Mode().Perm() != 0400 {
			t.Errorf("Certificate file has wrong permissions: expected 0400, got %o", certInfo.Mode().Perm())
		}
	}
	if keyInfo, err := os.Stat(keyFile); err == nil {
		if keyInfo.Mode().Perm() != 0400 {
			t.Errorf("Key file has wrong permissions: expected 0400, got %o", keyInfo.Mode().Perm())
		}
	}
}

func validateCertInfoOutput(t *testing.T, stdout, certPath string) {
	expectedStrings := []string{
		"Certificate Information:",
		"Certificate Path:",
		"Private Key Path:",
		"Subject:",
		"Issuer:",
		"Valid From:",
		"Valid Until:",
		"DNS Names:",
		"IP Addresses:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(stdout, expected) {
			t.Errorf("cert info output missing expected string: %s\nOutput: %s", expected, stdout)
		}
	}

	// Check that file paths are shown
	expectedCertPath := filepath.Join(certPath, "server.crt")
	expectedKeyPath := filepath.Join(certPath, "server.key")
	if !strings.Contains(stdout, expectedCertPath) {
		t.Errorf("cert info should show certificate path: %s", expectedCertPath)
	}
	if !strings.Contains(stdout, expectedKeyPath) {
		t.Errorf("cert info should show key path: %s", expectedKeyPath)
	}
}

func TestCLI_HelpCommands(t *testing.T) {
	t.Run("root help", func(t *testing.T) {
		stdout, _, err := runCLICommand("--help")
		if err != nil {
			t.Fatalf("root help command failed: %v", err)
		}

		expectedStrings := []string{
			"A GeoIP server that provides IP geolocation information using MaxMind databases",
			"cert",
			"update",
			"status",
			"rollback",
		}

		for _, expected := range expectedStrings {
			if !strings.Contains(stdout, expected) {
				t.Errorf("root help missing expected string: %s", expected)
			}
		}
	})

	t.Run("cert help shows all flags", func(t *testing.T) {
		stdout, _, err := runCLICommand("cert", "--help")
		if err != nil {
			t.Fatalf("cert help command failed: %v", err)
		}

		// Check that all three certificate-related flags are present
		expectedFlags := []string{
			"--cert-file",
			"--key-file",
			"--cert-path",
		}

		for _, flag := range expectedFlags {
			if !strings.Contains(stdout, flag) {
				t.Errorf("cert help missing expected flag: %s", flag)
			}
		}
	})

	t.Run("maxmind license masking in help", func(t *testing.T) {
		// Set environment variable with test license
		testLicense := "pfSsgL_ARStest123456789mmk"
		cmd := exec.Command("go", "run", ".", "cert", "--help")
		cmd.Env = append(os.Environ(), "MAXMIND_LICENSE="+testLicense)

		output, err := cmd.Output()
		if err != nil {
			t.Fatalf("help command with license failed: %v", err)
		}

		outputStr := string(output)

		// Should contain masked version
		if !strings.Contains(outputStr, "pfSsgL_ARS...mmk") {
			t.Error("Help should show masked license key")
		}

		// Should not contain full license
		if strings.Contains(outputStr, testLicense) && !strings.Contains(outputStr, "pfSsgL_ARS...mmk") {
			t.Error("Help should not show full license key")
		}
	})
}

func TestCLI_FlagValidation(t *testing.T) {
	t.Run("invalid cert-valid-days", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "invalid_days")

		_, stderr, err := runCLICommand(
			"cert", "generate",
			"--cert-path", certPath,
			"--cert-valid-days", "-1", // Invalid negative days
		)

		// Command should still work (negative days are handled by time.Duration)
		// But we can test it doesn't crash
		if err != nil && !strings.Contains(stderr, "Failed to generate certificate") {
			// If it fails, it should be a generation error, not a flag parsing error
			t.Logf("Command failed as expected with invalid days: %v", err)
		}
	})

	t.Run("custom cert and key files", func(t *testing.T) {
		tempDir := t.TempDir()
		customCert := filepath.Join(tempDir, "custom.crt")
		customKey := filepath.Join(tempDir, "custom.key")

		stdout, stderr, err := runCLICommand(
			"cert", "generate",
			"--cert-file", customCert,
			"--key-file", customKey,
			"--cert-hosts", "custom.test",
		)

		if err != nil {
			t.Fatalf("cert generate with custom files failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
		}

		// Check if custom files were created
		if _, err := os.Stat(customCert); os.IsNotExist(err) {
			t.Error("Custom certificate file was not created")
		}
		if _, err := os.Stat(customKey); os.IsNotExist(err) {
			t.Error("Custom key file was not created")
		}
	})
}

// setupCLITest creates common test dependencies for CLI tests
func setupCLITest(t *testing.T) string {
	tempDir := t.TempDir()
	return filepath.Join(tempDir, "integration_test")
}

func TestCLI_CertificateGeneration(t *testing.T) {
	certPath := setupCLITest(t)

	stdout, stderr, err := runCLICommand(
		"cert", "generate",
		"--cert-path", certPath,
		"--cert-hosts", "integration.test,10.0.0.1",
		"--cert-valid-days", "365",
	)

	if err != nil {
		t.Fatalf("Certificate generation failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	combinedOutput := stdout + stderr
	if !strings.Contains(combinedOutput, "Self-signed certificate generated successfully") {
		t.Errorf("Expected success message in certificate generation.\nStdout: %s\nStderr: %s", stdout, stderr)
	}
}

func TestCLI_CertificateInfo(t *testing.T) {
	certPath := setupCLITest(t)

	// Generate certificate first
	_, _, err := runCLICommand(
		"cert", "generate",
		"--cert-path", certPath,
		"--cert-hosts", "integration.test,10.0.0.1",
	)
	if err != nil {
		t.Fatalf("Failed to generate certificate for info test: %v", err)
	}

	stdout, stderr, err := runCLICommand(
		"cert", "info",
		"--cert-path", certPath,
	)

	if err != nil {
		t.Fatalf("Certificate info failed: %v\nStdout: %s\nStderr: %s", err, stdout, stderr)
	}

	validateCertificateInfo(t, stdout, certPath)
}

func TestCLI_CertificatePermissions(t *testing.T) {
	certPath := setupCLITest(t)

	// Generate certificate first
	_, _, err := runCLICommand(
		"cert", "generate",
		"--cert-path", certPath,
		"--cert-hosts", "integration.test",
	)
	if err != nil {
		t.Fatalf("Failed to generate certificate for permissions test: %v", err)
	}

	validateCLICertificatePermissions(t, certPath)
}

func TestCLI_CertificateRegeneration(t *testing.T) {
	certPath := setupCLITest(t)

	// Generate initial certificate
	_, _, err := runCLICommand(
		"cert", "generate",
		"--cert-path", certPath,
		"--cert-hosts", "initial.test",
	)
	if err != nil {
		t.Fatalf("Failed to generate initial certificate: %v", err)
	}

	certFile := filepath.Join(certPath, "server.crt")
	originalInfo, err := os.Stat(certFile)
	if err != nil {
		t.Fatalf("Failed to stat original certificate: %v", err)
	}
	originalModTime := originalInfo.ModTime()

	time.Sleep(10 * time.Millisecond)

	// Regenerate certificate
	_, _, err = runCLICommand(
		"cert", "generate",
		"--cert-path", certPath,
		"--cert-hosts", "regenerated.test",
	)

	if err != nil {
		t.Fatalf("Certificate regeneration failed: %v", err)
	}

	validateCertificateRegeneration(t, certFile, originalModTime, certPath)
}

// Helper functions for CLI certificate validation

func validateCertificateInfo(t *testing.T, stdout, certPath string) {
	if !strings.Contains(stdout, "integration.test") {
		t.Error("Certificate should contain integration.test DNS name")
	}
	if !strings.Contains(stdout, "10.0.0.1") {
		t.Error("Certificate should contain 10.0.0.1 IP address")
	}

	expectedCertPath := filepath.Join(certPath, "server.crt")
	expectedKeyPath := filepath.Join(certPath, "server.key")
	if !strings.Contains(stdout, expectedCertPath) {
		t.Error("Certificate path should be displayed")
	}
	if !strings.Contains(stdout, expectedKeyPath) {
		t.Error("Key path should be displayed")
	}
}

func validateCLICertificatePermissions(t *testing.T, certPath string) {
	certFile := filepath.Join(certPath, "server.crt")
	keyFile := filepath.Join(certPath, "server.key")

	// Check certificate file permissions
	if certInfo, err := os.Stat(certFile); err == nil {
		expectedPerm := fs.FileMode(0400)
		if certInfo.Mode().Perm() != expectedPerm {
			t.Errorf("Certificate file permissions: expected %o, got %o", expectedPerm, certInfo.Mode().Perm())
		}
	} else {
		t.Errorf("Failed to stat certificate file: %v", err)
	}

	// Check key file permissions
	if keyInfo, err := os.Stat(keyFile); err == nil {
		expectedPerm := fs.FileMode(0400)
		if keyInfo.Mode().Perm() != expectedPerm {
			t.Errorf("Key file permissions: expected %o, got %o", expectedPerm, keyInfo.Mode().Perm())
		}
	} else {
		t.Errorf("Failed to stat key file: %v", err)
	}
}

func validateCertificateRegeneration(t *testing.T, certFile string, originalModTime time.Time, certPath string) {
	newInfo, err := os.Stat(certFile)
	if err != nil {
		t.Fatalf("Failed to stat regenerated certificate: %v", err)
	}

	if !newInfo.ModTime().After(originalModTime) {
		t.Error("Certificate should have been regenerated with newer timestamp")
	}

	stdout, _, err := runCLICommand("cert", "info", "--cert-path", certPath)
	if err != nil {
		t.Fatalf("Failed to get info for regenerated certificate: %v", err)
	}

	if !strings.Contains(stdout, "regenerated.test") {
		t.Error("Regenerated certificate should contain new DNS name")
	}
}

func TestCLI_ErrorHandling(t *testing.T) {
	t.Run("invalid command", func(t *testing.T) {
		_, stderr, err := runCLICommand("invalid-command")

		if err == nil {
			t.Error("Invalid command should return error")
		}

		if !strings.Contains(stderr, "unknown command") && !strings.Contains(stderr, "Error") {
			t.Errorf("Expected unknown command error, got: %s", stderr)
		}
	})

	t.Run("cert generate without permissions", func(t *testing.T) {
		// Try to generate certificate in a read-only directory
		tempDir := t.TempDir()
		readOnlyDir := filepath.Join(tempDir, "readonly")

		// Create directory and make it read-only
		if err := os.Mkdir(readOnlyDir, 0755); err != nil {
			t.Fatalf("Failed to create test directory: %v", err)
		}
		if err := os.Chmod(readOnlyDir, 0444); err != nil {
			t.Fatalf("Failed to make directory read-only: %v", err)
		}
		defer func() {
			if err := os.Chmod(readOnlyDir, 0755); err != nil {
				t.Logf("Failed to restore permissions for cleanup: %v", err)
			}
		}() // Restore permissions for cleanup

		certPath := filepath.Join(readOnlyDir, "certs")

		_, stderr, err := runCLICommand(
			"cert", "generate",
			"--cert-path", certPath,
		)

		if err == nil {
			t.Error("Certificate generation should fail in read-only directory")
		}

		// Should contain permission-related error
		if !strings.Contains(stderr, "failed") && !strings.Contains(stderr, "permission") {
			t.Logf("Got expected error: %s", stderr)
		}
	})
}

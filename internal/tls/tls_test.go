package tls

import (
	"crypto/tls"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

func TestNewCertManager(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(os.Stderr) // Suppress output during tests

	certPath := "/tmp/test.crt"
	keyPath := "/tmp/test.key"

	cm := NewCertManager(certPath, keyPath, logger)

	if cm.certPath != certPath {
		t.Errorf("Expected certPath %s, got %s", certPath, cm.certPath)
	}
	if cm.keyPath != keyPath {
		t.Errorf("Expected keyPath %s, got %s", keyPath, cm.keyPath)
	}
	if cm.logger != logger {
		t.Error("Logger not set correctly")
	}
}

func TestCertificatesExist(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Suppress output during tests

	// Test when certificates don't exist
	t.Run("Certificates don't exist", func(t *testing.T) {
		cm := NewCertManager("/nonexistent/cert.crt", "/nonexistent/key.key", logger)
		if cm.CertificatesExist() {
			t.Error("Expected CertificatesExist to return false for nonexistent files")
		}
	})

	// Test when only cert exists
	t.Run("Only cert exists", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "cert.crt")
		keyPath := filepath.Join(tempDir, "key.key")

		// Create only cert file
		if err := os.WriteFile(certPath, []byte("dummy cert"), 0600); err != nil {
			t.Fatalf("Failed to create cert file: %v", err)
		}

		cm := NewCertManager(certPath, keyPath, logger)
		if cm.CertificatesExist() {
			t.Error("Expected CertificatesExist to return false when only cert exists")
		}
	})

	// Test when both certificates exist
	t.Run("Both certificates exist", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "cert.crt")
		keyPath := filepath.Join(tempDir, "key.key")

		// Create both files
		if err := os.WriteFile(certPath, []byte("dummy cert"), 0600); err != nil {
			t.Fatalf("Failed to create cert file: %v", err)
		}
		if err := os.WriteFile(keyPath, []byte("dummy key"), 0600); err != nil {
			t.Fatalf("Failed to create key file: %v", err)
		}

		cm := NewCertManager(certPath, keyPath, logger)
		if !cm.CertificatesExist() {
			t.Error("Expected CertificatesExist to return true when both files exist")
		}
	})
}

// setupTLSTest creates common test dependencies
func setupTLSTest(t *testing.T) (*logrus.Logger, string, string, string) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.crt")
	keyPath := filepath.Join(tempDir, "key.key")

	return logger, tempDir, certPath, keyPath
}

func TestGenerateSelfSignedCertSingleHost(t *testing.T) {
	logger, _, certPath, keyPath := setupTLSTest(t)
	cm := NewCertManager(certPath, keyPath, logger)

	err := cm.GenerateSelfSignedCert("localhost", 365)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	validateCertificateFiles(t, cm, certPath, keyPath)
	validateSingleHostCertificate(t, cm)
}

func TestGenerateSelfSignedCertMultipleHosts(t *testing.T) {
	logger, _, certPath, keyPath := setupTLSTest(t)
	cm := NewCertManager(certPath, keyPath, logger)

	hosts := "localhost,example.com,127.0.0.1,192.168.1.1"
	err := cm.GenerateSelfSignedCert(hosts, 30)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	validateMultipleHostsCertificate(t, cm)
}

func TestGenerateSelfSignedCertEmptyHosts(t *testing.T) {
	logger, _, certPath, keyPath := setupTLSTest(t)
	cm := NewCertManager(certPath, keyPath, logger)

	err := cm.GenerateSelfSignedCert("", 365)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if !cm.CertificatesExist() {
		t.Error("Generated certificates don't exist")
	}
}

func TestGenerateSelfSignedCertNestedDirectory(t *testing.T) {
	logger, tempDir, _, _ := setupTLSTest(t)

	certDir := filepath.Join(tempDir, "nested", "dir")
	certPath := filepath.Join(certDir, "cert.crt")
	keyPath := filepath.Join(certDir, "key.key")

	cm := NewCertManager(certPath, keyPath, logger)

	err := cm.GenerateSelfSignedCert("localhost", 365)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	if _, err := os.Stat(certDir); os.IsNotExist(err) {
		t.Error("Certificate directory was not created")
	}

	if !cm.CertificatesExist() {
		t.Error("Generated certificates don't exist")
	}
}

// Helper functions for certificate validation

func validateCertificateFiles(t *testing.T, cm *CertManager, certPath, keyPath string) {
	if !cm.CertificatesExist() {
		t.Error("Generated certificates don't exist")
	}

	// Check cert file permissions
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("Failed to stat cert file: %v", err)
	}
	if certInfo.Mode().Perm() != 0400 {
		t.Errorf("Expected cert file permissions 0400, got %o", certInfo.Mode().Perm())
	}

	// Check key file permissions
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}
	if keyInfo.Mode().Perm() != 0400 {
		t.Errorf("Expected key file permissions 0400, got %o", keyInfo.Mode().Perm())
	}
}

func validateSingleHostCertificate(t *testing.T, cm *CertManager) {
	info, err := cm.GetCertificateInfo()
	if err != nil {
		t.Fatalf("Failed to get certificate info: %v", err)
	}

	dnsNames := info["dns_names"].([]string)
	if len(dnsNames) != 1 || dnsNames[0] != "localhost" {
		t.Errorf("Expected DNS names [localhost], got %v", dnsNames)
	}
}

func validateMultipleHostsCertificate(t *testing.T, cm *CertManager) {
	info, err := cm.GetCertificateInfo()
	if err != nil {
		t.Fatalf("Failed to get certificate info: %v", err)
	}

	dnsNames := info["dns_names"].([]string)
	expectedDNS := []string{"localhost", "example.com"}
	if len(dnsNames) != len(expectedDNS) {
		t.Errorf("Expected %d DNS names, got %d", len(expectedDNS), len(dnsNames))
	}

	ipAddresses := info["ip_addresses"].([]net.IP)
	if len(ipAddresses) != 2 {
		t.Errorf("Expected 2 IP addresses, got %d", len(ipAddresses))
	}
}

func TestLoadTLSConfig(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Run("Load TLS config with valid certificates", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "cert.crt")
		keyPath := filepath.Join(tempDir, "key.key")

		cm := NewCertManager(certPath, keyPath, logger)

		// Generate certificates first
		err := cm.GenerateSelfSignedCert("localhost", 365)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Load TLS config
		tlsConfig, err := cm.LoadTLSConfig()
		if err != nil {
			t.Fatalf("Failed to load TLS config: %v", err)
		}

		// Verify TLS config properties
		if tlsConfig.MinVersion != tls.VersionTLS12 {
			t.Errorf("Expected MinVersion TLS 1.2, got %x", tlsConfig.MinVersion)
		}
		if tlsConfig.MaxVersion != tls.VersionTLS13 {
			t.Errorf("Expected MaxVersion TLS 1.3, got %x", tlsConfig.MaxVersion)
		}
		if len(tlsConfig.Certificates) != 1 {
			t.Errorf("Expected 1 certificate, got %d", len(tlsConfig.Certificates))
		}
		// Note: PreferServerCipherSuites is deprecated since Go 1.18 and ignored
		// The server cipher suite preferences are now automatically used when needed
	})

	t.Run("Load TLS config without certificates", func(t *testing.T) {
		cm := NewCertManager("/nonexistent/cert.crt", "/nonexistent/key.key", logger)

		_, err := cm.LoadTLSConfig()
		if err == nil {
			t.Error("Expected error when loading TLS config without certificates")
		}
		if !strings.Contains(err.Error(), "certificates not found") {
			t.Errorf("Expected 'certificates not found' error, got: %v", err)
		}
	})
}

func TestValidateCertificates(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Run("Validate valid certificates", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "cert.crt")
		keyPath := filepath.Join(tempDir, "key.key")

		cm := NewCertManager(certPath, keyPath, logger)

		// Generate certificates first
		err := cm.GenerateSelfSignedCert("localhost", 365)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Validate certificates
		err = cm.ValidateCertificates()
		if err != nil {
			t.Errorf("Failed to validate valid certificates: %v", err)
		}
	})

	t.Run("Validate nonexistent certificates", func(t *testing.T) {
		cm := NewCertManager("/nonexistent/cert.crt", "/nonexistent/key.key", logger)

		err := cm.ValidateCertificates()
		if err == nil {
			t.Error("Expected error when validating nonexistent certificates")
		}
	})

	t.Run("Validate expired certificates", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "cert.crt")
		keyPath := filepath.Join(tempDir, "key.key")

		cm := NewCertManager(certPath, keyPath, logger)

		// Generate certificate that expires immediately (0 days)
		err := cm.GenerateSelfSignedCert("localhost", 0)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Wait a moment to ensure expiration
		time.Sleep(10 * time.Millisecond)

		// Validate should fail for expired certificate
		err = cm.ValidateCertificates()
		if err == nil {
			t.Error("Expected error when validating expired certificates")
		}
	})

	t.Run("Validate invalid certificate file", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "cert.crt")
		keyPath := filepath.Join(tempDir, "key.key")

		// Create invalid certificate file
		if err := os.WriteFile(certPath, []byte("invalid cert data"), 0600); err != nil {
			t.Fatalf("Failed to create invalid cert file: %v", err)
		}
		if err := os.WriteFile(keyPath, []byte("invalid key data"), 0600); err != nil {
			t.Fatalf("Failed to create invalid key file: %v", err)
		}

		cm := NewCertManager(certPath, keyPath, logger)

		err := cm.ValidateCertificates()
		if err == nil {
			t.Error("Expected error when validating invalid certificate")
		}
	})
}

// Helper function to validate certificate info fields
func validateCertificateInfoFields(t *testing.T, info map[string]interface{}) {
	requiredFields := []string{"subject", "issuer", "not_before", "not_after", "dns_names", "ip_addresses", "is_ca"}
	for _, field := range requiredFields {
		if _, exists := info[field]; !exists {
			t.Errorf("Missing required field: %s", field)
		}
	}
}

// Helper function to validate certificate subject
func validateCertificateSubject(t *testing.T, info map[string]interface{}) {
	subject := info["subject"].(string)
	if !strings.Contains(subject, "GeoIP Service") {
		t.Errorf("Expected subject to contain 'GeoIP Service', got: %s", subject)
	}
}

// Helper function to validate certificate hosts
func validateCertificateHosts(t *testing.T, info map[string]interface{}) {
	dnsNames := info["dns_names"].([]string)
	expectedDNS := []string{"localhost", "example.com"}
	if len(dnsNames) != len(expectedDNS) {
		t.Errorf("Expected %d DNS names, got %d", len(expectedDNS), len(dnsNames))
	}

	ipAddresses := info["ip_addresses"].([]net.IP)
	if len(ipAddresses) != 1 {
		t.Errorf("Expected 1 IP address, got %d", len(ipAddresses))
	}
}

// Helper function to validate certificate validity period
func validateCertificateValidity(t *testing.T, info map[string]interface{}) {
	isCA := info["is_ca"].(bool)
	if isCA {
		t.Error("Expected certificate to not be a CA certificate")
	}

	notBefore := info["not_before"].(time.Time)
	notAfter := info["not_after"].(time.Time)
	if notAfter.Before(notBefore) {
		t.Error("Certificate expiry date is before start date")
	}

	duration := notAfter.Sub(notBefore)
	expectedDuration := 365 * 24 * time.Hour
	if duration < expectedDuration-time.Hour || duration > expectedDuration+time.Hour {
		t.Errorf("Expected certificate duration ~%v, got %v", expectedDuration, duration)
	}
}

func TestGetCertificateInfo_ValidCertificate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.crt")
	keyPath := filepath.Join(tempDir, "key.key")

	cm := NewCertManager(certPath, keyPath, logger)

	// Generate certificate
	hosts := "localhost,example.com,127.0.0.1"
	err := cm.GenerateSelfSignedCert(hosts, 365)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Get certificate info
	info, err := cm.GetCertificateInfo()
	if err != nil {
		t.Fatalf("Failed to get certificate info: %v", err)
	}

	validateCertificateInfoFields(t, info)
	validateCertificateSubject(t, info)
	validateCertificateHosts(t, info)
	validateCertificateValidity(t, info)
}

func TestGetCertificateInfo_NonexistentCertificate(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cm := NewCertManager("/nonexistent/cert.crt", "/nonexistent/key.key", logger)

	_, err := cm.GetCertificateInfo()
	if err == nil {
		t.Error("Expected error when getting info for nonexistent certificate")
	}
	if !strings.Contains(err.Error(), "certificates not found") {
		t.Errorf("Expected 'certificates not found' error, got: %v", err)
	}
}

// Test file permissions specifically (critical for security)
func TestCertificatePermissions(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.crt")
	keyPath := filepath.Join(tempDir, "key.key")

	cm := NewCertManager(certPath, keyPath, logger)

	err := cm.GenerateSelfSignedCert("localhost", 365)
	if err != nil {
		t.Fatalf("Failed to generate certificate: %v", err)
	}

	// Test certificate file permissions
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("Failed to stat certificate file: %v", err)
	}

	expectedPerm := fs.FileMode(0400)
	if certInfo.Mode().Perm() != expectedPerm {
		t.Errorf("Certificate file has wrong permissions. Expected %o, got %o", expectedPerm, certInfo.Mode().Perm())
	}

	// Test key file permissions
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Failed to stat key file: %v", err)
	}

	if keyInfo.Mode().Perm() != expectedPerm {
		t.Errorf("Key file has wrong permissions. Expected %o, got %o", expectedPerm, keyInfo.Mode().Perm())
	}
}

func TestCertificateRegeneration(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cm := NewCertManager(certPath, keyPath, logger)

	// Generate initial certificate
	err := cm.GenerateSelfSignedCert("initial.test", 365)
	if err != nil {
		t.Fatalf("Failed to generate initial certificate: %v", err)
	}

	originalCertTime, originalKeyTime := validateInitialCertificate(t, certPath, keyPath)
	regenerateAndVerify(t, cm, originalCertTime, originalKeyTime, certPath, keyPath)
}

// Helper function to validate initial certificate
func validateInitialCertificate(t *testing.T, certPath, keyPath string) (time.Time, time.Time) {
	certInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("Certificate file doesn't exist: %v", err)
	}
	if certInfo.Mode().Perm() != 0400 {
		t.Errorf("Expected certificate permissions 0400, got %o", certInfo.Mode().Perm())
	}

	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Key file doesn't exist: %v", err)
	}
	if keyInfo.Mode().Perm() != 0400 {
		t.Errorf("Expected key permissions 0400, got %o", keyInfo.Mode().Perm())
	}

	return certInfo.ModTime(), keyInfo.ModTime()
}

// Helper function to regenerate certificate and verify
func regenerateAndVerify(t *testing.T, cm *CertManager, originalCertTime, originalKeyTime time.Time, certPath, keyPath string) {
	// Wait to ensure different mod times
	time.Sleep(10 * time.Millisecond)

	// Regenerate certificate
	err := cm.GenerateSelfSignedCert("regenerated.test", 365)
	if err != nil {
		t.Fatalf("Failed to regenerate certificate: %v", err)
	}

	verifyRegeneratedFiles(t, certPath, keyPath, originalCertTime, originalKeyTime)
	verifyRegeneratedContent(t, cm)
}

// Helper function to verify regenerated files
func verifyRegeneratedFiles(t *testing.T, certPath, keyPath string, originalCertTime, originalKeyTime time.Time) {
	newCertInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("Regenerated certificate file doesn't exist: %v", err)
	}
	if !newCertInfo.ModTime().After(originalCertTime) {
		t.Error("Certificate file should have been regenerated with newer timestamp")
	}

	newKeyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Regenerated key file doesn't exist: %v", err)
	}
	if !newKeyInfo.ModTime().After(originalKeyTime) {
		t.Error("Key file should have been regenerated with newer timestamp")
	}

	// Verify permissions are still 400
	if newCertInfo.Mode().Perm() != 0400 {
		t.Errorf("Expected regenerated certificate permissions 0400, got %o", newCertInfo.Mode().Perm())
	}
	if newKeyInfo.Mode().Perm() != 0400 {
		t.Errorf("Expected regenerated key permissions 0400, got %o", newKeyInfo.Mode().Perm())
	}
}

// Helper function to verify regenerated certificate content
func verifyRegeneratedContent(t *testing.T, cm *CertManager) {
	info, err := cm.GetCertificateInfo()
	if err != nil {
		t.Fatalf("Failed to get certificate info: %v", err)
	}

	dnsNames, ok := info["dns_names"].([]string)
	if !ok {
		t.Fatal("DNS names should be a string slice")
	}

	found := false
	for _, name := range dnsNames {
		if name == "regenerated.test" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Regenerated certificate should contain 'regenerated.test' DNS name")
	}
}

func TestCertManager_SpecialCases(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cm := NewCertManager(certPath, keyPath, logger)

	// Test ValidateCertificates when certificates don't exist
	t.Run("ValidateCertificates_NoCerts", func(t *testing.T) {
		err := cm.ValidateCertificates()
		if err == nil {
			t.Error("Expected error when certificates don't exist")
		}
	})

	// Test GetCertificateInfo when certificates don't exist
	t.Run("GetCertificateInfo_NoCerts", func(t *testing.T) {
		_, err := cm.GetCertificateInfo()
		if err == nil {
			t.Error("Expected error when certificates don't exist")
		}
	})

	// Test LoadTLSConfig when certificates don't exist
	t.Run("LoadTLSConfig_NoCerts", func(t *testing.T) {
		_, err := cm.LoadTLSConfig()
		if err == nil {
			t.Error("Expected error when certificates don't exist")
		}
	})
}

func TestCertManager_FilesystemErrors(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Run("InvalidPaths", func(t *testing.T) {
		// Test with invalid certificate path
		invalidCertPath := "/invalid/path/cert.pem"
		validKeyPath := "/tmp/key.pem"
		cm := NewCertManager(invalidCertPath, validKeyPath, logger)

		err := cm.GenerateSelfSignedCert("localhost", 365)
		if err == nil {
			t.Error("Expected error with invalid certificate path")
		}
	})

	t.Run("ReadOnlyDirectory", func(t *testing.T) {
		// Create a temporary directory
		tempDir := t.TempDir()

		// Create paths in a subdirectory that we'll make read-only
		readOnlyDir := filepath.Join(tempDir, "readonly")
		err := os.MkdirAll(readOnlyDir, 0755)
		if err != nil {
			t.Fatalf("Failed to create readonly directory: %v", err)
		}

		certPath := filepath.Join(readOnlyDir, "cert.pem")
		keyPath := filepath.Join(readOnlyDir, "key.pem")

		// Make the directory read-only
		err = os.Chmod(readOnlyDir, 0444)
		if err != nil {
			t.Fatalf("Failed to make directory read-only: %v", err)
		}

		// Restore permissions at the end for cleanup
		defer func() {
			if err := os.Chmod(readOnlyDir, 0755); err != nil {
				t.Logf("Failed to restore directory permissions: %v", err)
			}
		}()

		cm := NewCertManager(certPath, keyPath, logger)

		err = cm.GenerateSelfSignedCert("localhost", 365)
		if err == nil {
			t.Error("Expected error when writing to read-only directory")
		}
	})
}

func TestCertManager_InvalidCertificateContent(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cm := NewCertManager(certPath, keyPath, logger)

	t.Run("InvalidPEMCertificate", func(t *testing.T) {
		// Create an invalid PEM certificate file
		err := os.WriteFile(certPath, []byte("invalid pem content"), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid cert file: %v", err)
		}

		// Create a valid key file to pass CertificatesExist check
		err = os.WriteFile(keyPath, []byte("dummy key"), 0644)
		if err != nil {
			t.Fatalf("Failed to write dummy key file: %v", err)
		}

		err = cm.ValidateCertificates()
		if err == nil {
			t.Error("Expected error with invalid PEM certificate")
		}

		_, err = cm.GetCertificateInfo()
		if err == nil {
			t.Error("Expected error with invalid PEM certificate")
		}
	})

	t.Run("ValidPEMInvalidCertificate", func(t *testing.T) {
		// Create a valid PEM block with invalid certificate data
		invalidCertPEM := `-----BEGIN CERTIFICATE-----
aW52YWxpZCBjZXJ0aWZpY2F0ZSBkYXRh
-----END CERTIFICATE-----`

		err := os.WriteFile(certPath, []byte(invalidCertPEM), 0644)
		if err != nil {
			t.Fatalf("Failed to write invalid cert PEM: %v", err)
		}

		err = cm.ValidateCertificates()
		if err == nil {
			t.Error("Expected error with invalid certificate data")
		}

		_, err = cm.GetCertificateInfo()
		if err == nil {
			t.Error("Expected error with invalid certificate data")
		}
	})
}

func TestCertManager_RemoveExistingFile(t *testing.T) {
	tempDir := t.TempDir()
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	testFilePath := filepath.Join(tempDir, "testfile.txt")
	cm := NewCertManager("dummy", "dummy", logger)

	t.Run("RemoveNonExistentFile", func(t *testing.T) {
		// Test removing a file that doesn't exist (should not error)
		err := cm.removeExistingFile(testFilePath)
		if err != nil {
			t.Errorf("removeExistingFile should not error on non-existent file: %v", err)
		}
	})

	t.Run("RemoveExistingFile", func(t *testing.T) {
		// Create a file
		err := os.WriteFile(testFilePath, []byte("test content"), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		// Remove it
		err = cm.removeExistingFile(testFilePath)
		if err != nil {
			t.Errorf("removeExistingFile failed: %v", err)
		}

		// Verify it's gone
		if _, err := os.Stat(testFilePath); !os.IsNotExist(err) {
			t.Error("File should have been removed")
		}
	})

	t.Run("RemoveReadOnlyFile", func(t *testing.T) {
		// Create a read-only file
		err := os.WriteFile(testFilePath, []byte("read-only content"), 0400)
		if err != nil {
			t.Fatalf("Failed to create read-only file: %v", err)
		}

		// Remove it (should work because removeExistingFile changes permissions)
		err = cm.removeExistingFile(testFilePath)
		if err != nil {
			t.Errorf("removeExistingFile should handle read-only files: %v", err)
		}

		// Verify it's gone
		if _, err := os.Stat(testFilePath); !os.IsNotExist(err) {
			t.Error("Read-only file should have been removed")
		}
	})
}

func TestCertManager_LoadTLSConfigValidCerts(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cm := NewCertManager(certPath, keyPath, logger)

	// Generate valid certificates
	err := cm.GenerateSelfSignedCert("localhost", 365)
	if err != nil {
		t.Fatalf("Failed to generate certificates: %v", err)
	}

	// Test LoadTLSConfig with valid certificates
	tlsConfig, err := cm.LoadTLSConfig()
	if err != nil {
		t.Fatalf("LoadTLSConfig failed with valid certs: %v", err)
	}

	if tlsConfig == nil {
		t.Error("Expected non-nil TLS config")
		return
	}

	// Verify TLS configuration security settings
	if tlsConfig.MinVersion != tls.VersionTLS12 {
		t.Errorf("Expected MinVersion TLS 1.2, got %x", tlsConfig.MinVersion)
	}

	if tlsConfig.MaxVersion != tls.VersionTLS13 {
		t.Errorf("Expected MaxVersion TLS 1.3, got %x", tlsConfig.MaxVersion)
	}

	if len(tlsConfig.Certificates) != 1 {
		t.Errorf("Expected 1 certificate, got %d", len(tlsConfig.Certificates))
	}

	if len(tlsConfig.CipherSuites) == 0 {
		t.Error("Expected cipher suites to be configured")
	}

	if len(tlsConfig.CurvePreferences) == 0 {
		t.Error("Expected curve preferences to be configured")
	}
}

func TestCertManager_LoadTLSConfigInvalidCerts(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cm := NewCertManager(certPath, keyPath, logger)

	// Create invalid certificate and key files
	err := os.WriteFile(certPath, []byte("invalid cert"), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid cert file: %v", err)
	}

	err = os.WriteFile(keyPath, []byte("invalid key"), 0644)
	if err != nil {
		t.Fatalf("Failed to create invalid key file: %v", err)
	}

	// Test LoadTLSConfig with invalid certificates
	_, err = cm.LoadTLSConfig()
	if err == nil {
		t.Error("Expected error when loading invalid certificates")
	}
}

func TestCertManager_GenerateKeyErrors(t *testing.T) {
	// This test is challenging because generatePrivateKey uses crypto/rand,
	// but we can test that it generally works by calling it directly
	tempDir := t.TempDir()
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cm := NewCertManager(filepath.Join(tempDir, "cert.pem"), filepath.Join(tempDir, "key.pem"), logger)

	// Test generatePrivateKey function
	key, err := cm.generatePrivateKey()
	if err != nil {
		t.Errorf("generatePrivateKey failed: %v", err)
	}

	if key == nil {
		t.Error("Expected non-nil private key")
		return
	}

	// Verify key size is 2048 bits
	if key.N.BitLen() != 2048 {
		t.Errorf("Expected 2048-bit key, got %d bits", key.N.BitLen())
	}
}

func TestCertManager_ExpiredCertificate(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	cm := NewCertManager(certPath, keyPath, logger)

	// Generate certificate that's already expired (negative validity period)
	err := cm.GenerateSelfSignedCert("localhost", -1)
	if err != nil {
		t.Fatalf("Failed to generate expired certificate: %v", err)
	}

	// Test ValidateCertificates with expired certificate
	err = cm.ValidateCertificates()
	if err == nil {
		t.Error("Expected error when validating expired certificate")
	}

	// GetCertificateInfo should still work even with expired certs
	info, err := cm.GetCertificateInfo()
	if err != nil {
		t.Errorf("GetCertificateInfo should work with expired certs: %v", err)
	}

	if info == nil {
		t.Error("Expected certificate info for expired cert")
	}

	// Verify that info contains expected fields
	expectedFields := []string{"subject", "issuer", "not_before", "not_after", "dns_names", "ip_addresses", "is_ca"}
	for _, field := range expectedFields {
		if _, exists := info[field]; !exists {
			t.Errorf("Expected field %s in certificate info", field)
		}
	}
}

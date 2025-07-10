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

func TestGenerateSelfSignedCert(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Suppress output during tests

	t.Run("Generate certificate with single host", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "cert.crt")
		keyPath := filepath.Join(tempDir, "key.key")

		cm := NewCertManager(certPath, keyPath, logger)

		err := cm.GenerateSelfSignedCert("localhost", 365)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Check if files exist
		if !cm.CertificatesExist() {
			t.Error("Generated certificates don't exist")
		}

		// Check file permissions (critical test for new functionality)
		certInfo, err := os.Stat(certPath)
		if err != nil {
			t.Fatalf("Failed to stat cert file: %v", err)
		}
		if certInfo.Mode().Perm() != 0400 {
			t.Errorf("Expected cert file permissions 0400, got %o", certInfo.Mode().Perm())
		}

		keyInfo, err := os.Stat(keyPath)
		if err != nil {
			t.Fatalf("Failed to stat key file: %v", err)
		}
		if keyInfo.Mode().Perm() != 0400 {
			t.Errorf("Expected key file permissions 0400, got %o", keyInfo.Mode().Perm())
		}

		// Verify certificate content
		info, err := cm.GetCertificateInfo()
		if err != nil {
			t.Fatalf("Failed to get certificate info: %v", err)
		}

		dnsNames := info["dns_names"].([]string)
		if len(dnsNames) != 1 || dnsNames[0] != "localhost" {
			t.Errorf("Expected DNS names [localhost], got %v", dnsNames)
		}
	})

	t.Run("Generate certificate with multiple hosts", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "cert.crt")
		keyPath := filepath.Join(tempDir, "key.key")

		cm := NewCertManager(certPath, keyPath, logger)

		hosts := "localhost,example.com,127.0.0.1,192.168.1.1"
		err := cm.GenerateSelfSignedCert(hosts, 30)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Verify certificate content
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
	})

	t.Run("Generate certificate with empty hosts", func(t *testing.T) {
		tempDir := t.TempDir()
		certPath := filepath.Join(tempDir, "cert.crt")
		keyPath := filepath.Join(tempDir, "key.key")

		cm := NewCertManager(certPath, keyPath, logger)

		err := cm.GenerateSelfSignedCert("", 365)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Should still create valid certificate
		if !cm.CertificatesExist() {
			t.Error("Generated certificates don't exist")
		}
	})

	t.Run("Generate certificate in nested directory", func(t *testing.T) {
		tempDir := t.TempDir()
		certDir := filepath.Join(tempDir, "nested", "dir")
		certPath := filepath.Join(certDir, "cert.crt")
		keyPath := filepath.Join(certDir, "key.key")

		cm := NewCertManager(certPath, keyPath, logger)

		err := cm.GenerateSelfSignedCert("localhost", 365)
		if err != nil {
			t.Fatalf("Failed to generate certificate: %v", err)
		}

		// Check if directory was created
		if _, err := os.Stat(certDir); os.IsNotExist(err) {
			t.Error("Certificate directory was not created")
		}

		// Check if files exist with correct permissions
		if !cm.CertificatesExist() {
			t.Error("Generated certificates don't exist")
		}
	})
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

func TestGetCertificateInfo(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	t.Run("Get certificate info for valid certificate", func(t *testing.T) {
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

		// Verify required fields exist
		requiredFields := []string{"subject", "issuer", "not_before", "not_after", "dns_names", "ip_addresses", "is_ca"}
		for _, field := range requiredFields {
			if _, exists := info[field]; !exists {
				t.Errorf("Missing required field: %s", field)
			}
		}

		// Verify subject contains GeoIP Service
		subject := info["subject"].(string)
		if !strings.Contains(subject, "GeoIP Service") {
			t.Errorf("Expected subject to contain 'GeoIP Service', got: %s", subject)
		}

		// Verify DNS names
		dnsNames := info["dns_names"].([]string)
		expectedDNS := []string{"localhost", "example.com"}
		if len(dnsNames) != len(expectedDNS) {
			t.Errorf("Expected %d DNS names, got %d", len(expectedDNS), len(dnsNames))
		}

		// Verify IP addresses
		ipAddresses := info["ip_addresses"].([]net.IP)
		if len(ipAddresses) != 1 {
			t.Errorf("Expected 1 IP address, got %d", len(ipAddresses))
		}

		// Verify it's not a CA certificate
		isCA := info["is_ca"].(bool)
		if isCA {
			t.Error("Expected certificate to not be a CA certificate")
		}

		// Verify dates
		notBefore := info["not_before"].(time.Time)
		notAfter := info["not_after"].(time.Time)
		if notAfter.Before(notBefore) {
			t.Error("Certificate expiry date is before start date")
		}

		// Verify certificate is valid for approximately 365 days
		duration := notAfter.Sub(notBefore)
		expectedDuration := 365 * 24 * time.Hour
		if duration < expectedDuration-time.Hour || duration > expectedDuration+time.Hour {
			t.Errorf("Expected certificate duration ~%v, got %v", expectedDuration, duration)
		}
	})

	t.Run("Get certificate info for nonexistent certificate", func(t *testing.T) {
		cm := NewCertManager("/nonexistent/cert.crt", "/nonexistent/key.key", logger)

		_, err := cm.GetCertificateInfo()
		if err == nil {
			t.Error("Expected error when getting info for nonexistent certificate")
		}
		if !strings.Contains(err.Error(), "certificates not found") {
			t.Errorf("Expected 'certificates not found' error, got: %v", err)
		}
	})
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
	// Test certificate regeneration when files have 400 permissions
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")

	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Suppress logs during tests

	cm := NewCertManager(certPath, keyPath, logger)

	// Generate initial certificate
	err := cm.GenerateSelfSignedCert("initial.test", 365)
	if err != nil {
		t.Fatalf("Failed to generate initial certificate: %v", err)
	}

	// Verify files exist with 400 permissions
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

	// Get original modification times
	originalCertModTime := certInfo.ModTime()
	originalKeyModTime := keyInfo.ModTime()

	// Wait a moment to ensure different mod times
	time.Sleep(10 * time.Millisecond)

	// Regenerate certificate (should overwrite despite 400 permissions)
	err = cm.GenerateSelfSignedCert("regenerated.test", 365)
	if err != nil {
		t.Fatalf("Failed to regenerate certificate: %v", err)
	}

	// Verify files were regenerated
	newCertInfo, err := os.Stat(certPath)
	if err != nil {
		t.Fatalf("Regenerated certificate file doesn't exist: %v", err)
	}
	if !newCertInfo.ModTime().After(originalCertModTime) {
		t.Error("Certificate file should have been regenerated with newer timestamp")
	}

	newKeyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("Regenerated key file doesn't exist: %v", err)
	}
	if !newKeyInfo.ModTime().After(originalKeyModTime) {
		t.Error("Key file should have been regenerated with newer timestamp")
	}

	// Verify permissions are still 400
	if newCertInfo.Mode().Perm() != 0400 {
		t.Errorf("Expected regenerated certificate permissions 0400, got %o", newCertInfo.Mode().Perm())
	}
	if newKeyInfo.Mode().Perm() != 0400 {
		t.Errorf("Expected regenerated key permissions 0400, got %o", newKeyInfo.Mode().Perm())
	}

	// Verify certificate content was updated
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

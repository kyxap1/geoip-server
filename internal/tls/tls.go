package tls

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// CertManager handles TLS certificate operations
type CertManager struct {
	certPath string
	keyPath  string
	logger   *logrus.Logger
}

// NewCertManager creates a new certificate manager
func NewCertManager(certPath, keyPath string, logger *logrus.Logger) *CertManager {
	return &CertManager{
		certPath: certPath,
		keyPath:  keyPath,
		logger:   logger,
	}
}

// GenerateSelfSignedCert generates a self-signed certificate
func (cm *CertManager) GenerateSelfSignedCert(hosts string, validDays int) error {
	cm.logger.Info("Generating self-signed certificate...")

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"GeoIP Service"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Duration(validDays) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Add hosts to certificate
	hostList := strings.Split(hosts, ",")
	for _, host := range hostList {
		host = strings.TrimSpace(host)
		if host == "" {
			continue
		}

		// Check if host is an IP address
		if ip := net.ParseIP(host); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}

	// Generate certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Create directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(cm.certPath), 0755); err != nil {
		return fmt.Errorf("failed to create cert directory: %w", err)
	}

	// Remove existing certificate file if it exists (it might have 400 permissions)
	if _, err := os.Stat(cm.certPath); err == nil {
		// Change permissions to allow deletion
		os.Chmod(cm.certPath, 0600)
		if err := os.Remove(cm.certPath); err != nil {
			return fmt.Errorf("failed to remove existing cert file: %w", err)
		}
	}

	// Write certificate to file
	certFile, err := os.Create(cm.certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certFile.Close()

	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return fmt.Errorf("failed to write certificate: %w", err)
	}

	// Set certificate file permissions to 400
	if err := os.Chmod(cm.certPath, 0400); err != nil {
		return fmt.Errorf("failed to set certificate file permissions: %w", err)
	}

	// Remove existing key file if it exists (it might have 400 permissions)
	if _, err := os.Stat(cm.keyPath); err == nil {
		// Change permissions to allow deletion
		os.Chmod(cm.keyPath, 0600)
		if err := os.Remove(cm.keyPath); err != nil {
			return fmt.Errorf("failed to remove existing key file: %w", err)
		}
	}

	// Write private key to file
	keyFile, err := os.Create(cm.keyPath)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyFile.Close()

	privateKeyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal private key: %w", err)
	}

	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privateKeyDER}); err != nil {
		return fmt.Errorf("failed to write private key: %w", err)
	}

	// Set private key file permissions to 400
	if err := os.Chmod(cm.keyPath, 0400); err != nil {
		return fmt.Errorf("failed to set private key file permissions: %w", err)
	}

	cm.logger.Infof("Self-signed certificate generated successfully: %s", cm.certPath)
	return nil
}

// CertificatesExist checks if both certificate and key files exist
func (cm *CertManager) CertificatesExist() bool {
	if _, err := os.Stat(cm.certPath); os.IsNotExist(err) {
		return false
	}
	if _, err := os.Stat(cm.keyPath); os.IsNotExist(err) {
		return false
	}
	return true
}

// LoadTLSConfig loads TLS configuration with security hardening
func (cm *CertManager) LoadTLSConfig() (*tls.Config, error) {
	if !cm.CertificatesExist() {
		return nil, fmt.Errorf("certificates not found")
	}

	cert, err := tls.LoadX509KeyPair(cm.certPath, cm.keyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load certificate: %w", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13, // Allow TLS 1.3
		CipherSuites: []uint16{
			// TLS 1.3 cipher suites (preferred)
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,

			// TLS 1.2 cipher suites (fallback)
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
		},
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
			tls.CurveP384,
		},
		PreferServerCipherSuites: true,
	}, nil
}

// ValidateCertificates validates existing certificates
func (cm *CertManager) ValidateCertificates() error {
	if !cm.CertificatesExist() {
		return fmt.Errorf("certificates not found")
	}

	// Load certificate
	certData, err := os.ReadFile(cm.certPath)
	if err != nil {
		return fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid")
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired")
	}

	cm.logger.Info("Certificate validation successful")
	return nil
}

// GetCertificateInfo returns information about the certificate
func (cm *CertManager) GetCertificateInfo() (map[string]interface{}, error) {
	if !cm.CertificatesExist() {
		return nil, fmt.Errorf("certificates not found")
	}

	// Load certificate
	certData, err := os.ReadFile(cm.certPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read certificate: %w", err)
	}

	block, _ := pem.Decode(certData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return map[string]interface{}{
		"subject":      cert.Subject.String(),
		"issuer":       cert.Issuer.String(),
		"not_before":   cert.NotBefore,
		"not_after":    cert.NotAfter,
		"dns_names":    cert.DNSNames,
		"ip_addresses": cert.IPAddresses,
		"is_ca":        cert.IsCA,
	}, nil
}

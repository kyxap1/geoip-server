package config

import (
	"os"
	"testing"
	"time"
)

func TestLoadConfig_Defaults(t *testing.T) {
	// Clear all environment variables that could affect the config
	clearConfigEnvVars()

	cfg := LoadConfig()

	// Test default values
	tests := []struct {
		name     string
		actual   interface{}
		expected interface{}
	}{
		{"Port", cfg.Port, 80},
		{"HTTPSPort", cfg.HTTPSPort, 443},
		{"EnableTLS", cfg.EnableTLS, false},
		{"CertFile", cfg.CertFile, ""},
		{"KeyFile", cfg.KeyFile, ""},
		{"CertPath", cfg.CertPath, "./certs"}, // NEW FIELD
		{"DBPath", cfg.DBPath, "./data"},
		{"UpdateInterval", cfg.UpdateInterval, "0 0 */2 * *"},
		{"AutoUpdate", cfg.AutoUpdate, true},
		{"MaxMindLicense", cfg.MaxMindLicense, ""},
		{"CacheEnabled", cfg.CacheEnabled, true},
		{"CacheTTL", cfg.CacheTTL, 1 * time.Hour},
		{"CacheMaxEntries", cfg.CacheMaxEntries, 10000},
		{"LogLevel", cfg.LogLevel, "info"},
		{"GenerateCerts", cfg.GenerateCerts, false},
		{"CertValidDays", cfg.CertValidDays, 3650},
		{"CertHosts", cfg.CertHosts, "localhost,127.0.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.actual != tt.expected {
				t.Errorf("Expected %s to be %v, got %v", tt.name, tt.expected, tt.actual)
			}
		})
	}
}

func TestLoadConfig_WithEnvironmentVariables(t *testing.T) {
	// Clear environment first
	clearConfigEnvVars()

	// Set test environment variables
	envVars := map[string]string{
		"PORT":              "8080",
		"HTTPS_PORT":        "8443",
		"ENABLE_TLS":        "true",
		"CERT_FILE":         "/custom/cert.pem",
		"KEY_FILE":          "/custom/key.pem",
		"CERT_PATH":         "/custom/certs", // NEW ENV VAR
		"DB_PATH":           "/custom/data",
		"UPDATE_INTERVAL":   "0 0 */3 * *",
		"AUTO_UPDATE":       "false",
		"MAXMIND_LICENSE":   "test_license_key",
		"CACHE_ENABLED":     "false",
		"CACHE_TTL":         "2h",
		"CACHE_MAX_ENTRIES": "5000",
		"LOG_LEVEL":         "debug",
		"GENERATE_CERTS":    "true",
		"CERT_VALID_DAYS":   "365",
		"CERT_HOSTS":        "example.com,192.168.1.1",
	}

	// Set environment variables
	for key, value := range envVars {
		if err := os.Setenv(key, value); err != nil {
			t.Fatalf("Failed to set environment variable %s: %v", key, err)
		}
	}
	defer clearConfigEnvVars()

	cfg := LoadConfig()

	// Test environment variable values
	tests := []struct {
		name     string
		actual   interface{}
		expected interface{}
	}{
		{"Port", cfg.Port, 8080},
		{"HTTPSPort", cfg.HTTPSPort, 8443},
		{"EnableTLS", cfg.EnableTLS, true},
		{"CertFile", cfg.CertFile, "/custom/cert.pem"},
		{"KeyFile", cfg.KeyFile, "/custom/key.pem"},
		{"CertPath", cfg.CertPath, "/custom/certs"}, // NEW FIELD TEST
		{"DBPath", cfg.DBPath, "/custom/data"},
		{"UpdateInterval", cfg.UpdateInterval, "0 0 */3 * *"},
		{"AutoUpdate", cfg.AutoUpdate, false},
		{"MaxMindLicense", cfg.MaxMindLicense, "test_license_key"},
		{"CacheEnabled", cfg.CacheEnabled, false},
		{"CacheTTL", cfg.CacheTTL, 2 * time.Hour},
		{"CacheMaxEntries", cfg.CacheMaxEntries, 5000},
		{"LogLevel", cfg.LogLevel, "debug"},
		{"GenerateCerts", cfg.GenerateCerts, true},
		{"CertValidDays", cfg.CertValidDays, 365},
		{"CertHosts", cfg.CertHosts, "example.com,192.168.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.actual != tt.expected {
				t.Errorf("Expected %s to be %v, got %v", tt.name, tt.expected, tt.actual)
			}
		})
	}
}

func TestGetEnvStr(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue string
		expected     string
	}{
		{
			name:         "Environment variable exists",
			envKey:       "TEST_STRING",
			envValue:     "custom_value",
			defaultValue: "default_value",
			expected:     "custom_value",
		},
		{
			name:         "Environment variable empty",
			envKey:       "TEST_STRING_EMPTY",
			envValue:     "",
			defaultValue: "default_value",
			expected:     "default_value",
		},
		{
			name:         "Environment variable not set",
			envKey:       "TEST_STRING_NOTSET",
			envValue:     "",
			defaultValue: "default_value",
			expected:     "default_value",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clean up environment
			if err := os.Unsetenv(tt.envKey); err != nil {
				t.Fatalf("Failed to unset environment variable %s: %v", tt.envKey, err)
			}

			if tt.envValue != "" {
				if err := os.Setenv(tt.envKey, tt.envValue); err != nil {
					t.Fatalf("Failed to set environment variable %s: %v", tt.envKey, err)
				}
				defer func() {
					if err := os.Unsetenv(tt.envKey); err != nil {
						t.Logf("Failed to unset environment variable %s: %v", tt.envKey, err)
					}
				}()
			}

			result := getEnvStr(tt.envKey, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue int
		expected     int
	}{
		{
			name:         "Valid integer",
			envKey:       "TEST_INT",
			envValue:     "42",
			defaultValue: 10,
			expected:     42,
		},
		{
			name:         "Invalid integer",
			envKey:       "TEST_INT_INVALID",
			envValue:     "not_a_number",
			defaultValue: 10,
			expected:     10,
		},
		{
			name:         "Empty string",
			envKey:       "TEST_INT_EMPTY",
			envValue:     "",
			defaultValue: 10,
			expected:     10,
		},
		{
			name:         "Negative integer",
			envKey:       "TEST_INT_NEGATIVE",
			envValue:     "-5",
			defaultValue: 10,
			expected:     -5,
		},
		{
			name:         "Zero",
			envKey:       "TEST_INT_ZERO",
			envValue:     "0",
			defaultValue: 10,
			expected:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.Unsetenv(tt.envKey); err != nil {
				t.Fatalf("Failed to unset environment variable %s: %v", tt.envKey, err)
			}

			if tt.envValue != "" {
				if err := os.Setenv(tt.envKey, tt.envValue); err != nil {
					t.Fatalf("Failed to set environment variable %s: %v", tt.envKey, err)
				}
			}

			result := getEnvInt(tt.envKey, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %d, got %d", tt.expected, result)
			}
		})
	}
}

func TestGetEnvBool(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue bool
		expected     bool
	}{
		{
			name:         "True value",
			envKey:       "TEST_BOOL_TRUE",
			envValue:     "true",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "False value",
			envKey:       "TEST_BOOL_FALSE",
			envValue:     "false",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "1 as true",
			envKey:       "TEST_BOOL_1",
			envValue:     "1",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "0 as false",
			envKey:       "TEST_BOOL_0",
			envValue:     "0",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "Invalid boolean",
			envKey:       "TEST_BOOL_INVALID",
			envValue:     "maybe",
			defaultValue: true,
			expected:     true,
		},
		{
			name:         "Empty string",
			envKey:       "TEST_BOOL_EMPTY",
			envValue:     "",
			defaultValue: true,
			expected:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.Unsetenv(tt.envKey); err != nil {
				t.Fatalf("Failed to unset environment variable %s: %v", tt.envKey, err)
			}

			if tt.envValue != "" {
				if err := os.Setenv(tt.envKey, tt.envValue); err != nil {
					t.Fatalf("Failed to set environment variable %s: %v", tt.envKey, err)
				}
			}

			result := getEnvBool(tt.envKey, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %t, got %t", tt.expected, result)
			}
		})
	}
}

func TestGetEnvDuration(t *testing.T) {
	tests := []struct {
		name         string
		envKey       string
		envValue     string
		defaultValue time.Duration
		expected     time.Duration
	}{
		{
			name:         "Valid duration - hours",
			envKey:       "TEST_DURATION_HOURS",
			envValue:     "2h",
			defaultValue: 1 * time.Hour,
			expected:     2 * time.Hour,
		},
		{
			name:         "Valid duration - minutes",
			envKey:       "TEST_DURATION_MINUTES",
			envValue:     "30m",
			defaultValue: 1 * time.Hour,
			expected:     30 * time.Minute,
		},
		{
			name:         "Valid duration - seconds",
			envKey:       "TEST_DURATION_SECONDS",
			envValue:     "45s",
			defaultValue: 1 * time.Hour,
			expected:     45 * time.Second,
		},
		{
			name:         "Invalid duration",
			envKey:       "TEST_DURATION_INVALID",
			envValue:     "invalid_duration",
			defaultValue: 1 * time.Hour,
			expected:     1 * time.Hour,
		},
		{
			name:         "Empty string",
			envKey:       "TEST_DURATION_EMPTY",
			envValue:     "",
			defaultValue: 1 * time.Hour,
			expected:     1 * time.Hour,
		},
		{
			name:         "Complex duration",
			envKey:       "TEST_DURATION_COMPLEX",
			envValue:     "1h30m45s",
			defaultValue: 1 * time.Hour,
			expected:     1*time.Hour + 30*time.Minute + 45*time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.Unsetenv(tt.envKey); err != nil {
				t.Fatalf("Failed to unset environment variable %s: %v", tt.envKey, err)
			}

			if tt.envValue != "" {
				if err := os.Setenv(tt.envKey, tt.envValue); err != nil {
					t.Fatalf("Failed to set environment variable %s: %v", tt.envKey, err)
				}
			}

			result := getEnvDuration(tt.envKey, tt.defaultValue)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

func TestCertPathFieldSpecifically(t *testing.T) {
	// Test the new CertPath field specifically
	clearConfigEnvVars()

	t.Run("CertPath default value", func(t *testing.T) {
		cfg := LoadConfig()
		if cfg.CertPath != "./certs" {
			t.Errorf("Expected CertPath default to be './certs', got '%s'", cfg.CertPath)
		}
	})

	t.Run("CertPath from environment", func(t *testing.T) {
		if err := os.Setenv("CERT_PATH", "/my/custom/cert/path"); err != nil {
			t.Fatalf("Failed to set environment variable CERT_PATH: %v", err)
		}
		defer func() {
			if err := os.Unsetenv("CERT_PATH"); err != nil {
				t.Logf("Failed to unset environment variable CERT_PATH: %v", err)
			}
		}()

		cfg := LoadConfig()
		if cfg.CertPath != "/my/custom/cert/path" {
			t.Errorf("Expected CertPath to be '/my/custom/cert/path', got '%s'", cfg.CertPath)
		}
	})

	t.Run("CertPath empty environment variable", func(t *testing.T) {
		if err := os.Setenv("CERT_PATH", ""); err != nil {
			t.Fatalf("Failed to set environment variable CERT_PATH: %v", err)
		}
		defer func() {
			if err := os.Unsetenv("CERT_PATH"); err != nil {
				t.Logf("Failed to unset environment variable CERT_PATH: %v", err)
			}
		}()

		cfg := LoadConfig()
		if cfg.CertPath != "./certs" {
			t.Errorf("Expected CertPath to fallback to default './certs', got '%s'", cfg.CertPath)
		}
	})
}

func TestConfigStruct(t *testing.T) {
	// Test that Config struct has all expected fields with correct types
	cfg := &Config{}

	// Test that we can set all fields (this catches missing fields during compilation)
	cfg.Port = 80
	cfg.HTTPSPort = 443
	cfg.EnableTLS = false
	cfg.CertFile = "cert.pem"
	cfg.KeyFile = "key.pem"
	cfg.CertPath = "./certs" // NEW FIELD
	cfg.DBPath = "./data"
	cfg.UpdateInterval = "0 0 */2 * *"
	cfg.AutoUpdate = true
	cfg.MaxMindLicense = "license"
	cfg.CacheEnabled = true
	cfg.CacheTTL = time.Hour
	cfg.CacheMaxEntries = 10000
	cfg.LogLevel = "info"
	cfg.GenerateCerts = false
	cfg.CertValidDays = 3650
	cfg.CertHosts = "localhost"

	// If we got here without compilation errors, all fields exist
	t.Log("All Config struct fields are accessible")
}

// Helper function to clear all config-related environment variables
func clearConfigEnvVars() {
	envVars := []string{
		"PORT", "HTTPS_PORT", "ENABLE_TLS", "CERT_FILE", "KEY_FILE", "CERT_PATH",
		"DB_PATH", "UPDATE_INTERVAL", "AUTO_UPDATE", "MAXMIND_LICENSE",
		"CACHE_ENABLED", "CACHE_TTL", "CACHE_MAX_ENTRIES", "LOG_LEVEL",
		"GENERATE_CERTS", "CERT_VALID_DAYS", "CERT_HOSTS",
	}

	for _, envVar := range envVars {
		// Ignore errors for cleanup as environment variables might not have been set
		_ = os.Unsetenv(envVar)
	}
}

// Benchmarks for performance testing
func BenchmarkLoadConfig(b *testing.B) {
	clearConfigEnvVars()

	for i := 0; i < b.N; i++ {
		LoadConfig()
	}
}

func BenchmarkGetEnvStr(b *testing.B) {
	if err := os.Setenv("BENCH_TEST", "test_value"); err != nil {
		b.Fatalf("Failed to set environment variable BENCH_TEST: %v", err)
	}
	defer func() {
		if err := os.Unsetenv("BENCH_TEST"); err != nil {
			b.Logf("Failed to unset environment variable BENCH_TEST: %v", err)
		}
	}()

	for i := 0; i < b.N; i++ {
		getEnvStr("BENCH_TEST", "default")
	}
}

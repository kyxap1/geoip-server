package config

import (
	"os"
	"strconv"
	"time"
)

// Config holds all application configuration
type Config struct {
	// Server configuration
	Port      int    `json:"port"`
	HTTPSPort int    `json:"https_port"`
	EnableTLS bool   `json:"enable_tls"`
	CertFile  string `json:"cert_file"`
	KeyFile   string `json:"key_file"`
	CertPath  string `json:"cert_path"`

	// Database configuration
	DBPath         string `json:"db_path"`
	UpdateInterval string `json:"update_interval"`
	AutoUpdate     bool   `json:"auto_update"`
	MaxMindLicense string `json:"maxmind_license"`

	// Cache configuration
	CacheEnabled    bool          `json:"cache_enabled"`
	CacheTTL        time.Duration `json:"cache_ttl"`
	CacheMaxEntries int           `json:"cache_max_entries"`

	// Logging configuration
	LogLevel string `json:"log_level"`

	// TLS configuration
	GenerateCerts bool   `json:"generate_certs"`
	CertValidDays int    `json:"cert_valid_days"`
	CertHosts     string `json:"cert_hosts"`
}

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	cfg := &Config{
		Port:            getEnvInt("HTTP_PORT", 80),
		HTTPSPort:       getEnvInt("HTTPS_PORT", 443),
		EnableTLS:       getEnvBool("ENABLE_TLS", false),
		CertFile:        getEnvStr("CERT_FILE", ""),
		KeyFile:         getEnvStr("KEY_FILE", ""),
		CertPath:        getEnvStr("CERT_PATH", "./certs"),
		DBPath:          getEnvStr("DB_PATH", "./data"),
		UpdateInterval:  getEnvStr("UPDATE_INTERVAL", "0 0 */2 * *"), // Every 2 days
		AutoUpdate:      getEnvBool("AUTO_UPDATE", true),
		MaxMindLicense:  getEnvStr("MAXMIND_LICENSE", ""),
		CacheEnabled:    getEnvBool("CACHE_ENABLED", true),
		CacheTTL:        getEnvDuration("CACHE_TTL", 1*time.Hour),
		CacheMaxEntries: getEnvInt("CACHE_MAX_ENTRIES", 10000),
		LogLevel:        getEnvStr("LOG_LEVEL", "info"),
		GenerateCerts:   getEnvBool("GENERATE_CERTS", false),
		CertValidDays:   getEnvInt("CERT_VALID_DAYS", 3650), // 10 years
		CertHosts:       getEnvStr("CERT_HOSTS", "localhost,127.0.0.1"),
	}

	return cfg
}

// getEnvStr gets string value from environment variable with default
func getEnvStr(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvInt gets integer value from environment variable with default
func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

// getEnvBool gets boolean value from environment variable with default
func getEnvBool(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// getEnvDuration gets duration value from environment variable with default
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	if value := os.Getenv(key); value != "" {
		if duration, err := time.ParseDuration(value); err == nil {
			return duration
		}
	}
	return defaultValue
}

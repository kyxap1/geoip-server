package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	cron "github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"geoip-server/internal/config"
	"geoip-server/internal/geoip"
	"geoip-server/internal/handlers"
	tlsmanager "geoip-server/internal/tls"
)

var (
	cfg    *config.Config
	logger *logrus.Logger
)

// maskLicenseKey masks a license key showing only first 10 and last 3 characters
func maskLicenseKey(key string) string {
	if key == "" {
		return ""
	}
	if len(key) <= 13 {
		return key // Don't mask short keys
	}
	return key[:10] + "..." + key[len(key)-3:]
}

func init() {
	// Initialize logger
	logger = logrus.New()
	logger.SetFormatter(&logrus.TextFormatter{
		FullTimestamp: true,
	})

	// Load configuration
	cfg = config.LoadConfig()

	// Set log level
	level, err := logrus.ParseLevel(cfg.LogLevel)
	if err != nil {
		logger.Warn("Invalid log level, using info")
		level = logrus.InfoLevel
	}
	logger.SetLevel(level)
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "geoip-server",
		Short: "GeoIP server with MaxMind database support",
		Long:  `A GeoIP server that provides IP geolocation information using MaxMind databases.`,
		RunE:  runServer,
	}

	// Add CLI flags
	rootCmd.PersistentFlags().IntVarP(&cfg.Port, "http-port", "p", cfg.Port, "HTTP port to listen on")
	rootCmd.PersistentFlags().IntVar(&cfg.HTTPSPort, "https-port", cfg.HTTPSPort, "HTTPS port to listen on")
	rootCmd.PersistentFlags().BoolVar(&cfg.EnableTLS, "enable-tls", cfg.EnableTLS, "Enable TLS/HTTPS")
	rootCmd.PersistentFlags().StringVar(&cfg.CertFile, "cert-file", cfg.CertFile, "Path to TLS certificate file")
	rootCmd.PersistentFlags().StringVar(&cfg.KeyFile, "key-file", cfg.KeyFile, "Path to TLS private key file")
	rootCmd.PersistentFlags().StringVar(&cfg.CertPath, "cert-path", cfg.CertPath, "Path to store generated certificates")
	rootCmd.PersistentFlags().StringVar(&cfg.DBPath, "db-path", cfg.DBPath, "Path to GeoIP database directory")
	// Create masked description for MaxMind license
	maskedLicense := maskLicenseKey(cfg.MaxMindLicense)
	var licenseDesc string
	if maskedLicense == "" {
		licenseDesc = "MaxMind license key"
	} else {
		licenseDesc = fmt.Sprintf("MaxMind license key (default \"%s\")", maskedLicense)
	}

	// Create a temporary variable for the flag
	var maxmindLicenseFlag string
	rootCmd.PersistentFlags().StringVar(&maxmindLicenseFlag, "maxmind-license", "", licenseDesc)

	// Use a PreRun hook to set the actual value if flag wasn't provided
	originalPreRun := rootCmd.PersistentPreRun
	rootCmd.PersistentPreRun = func(cmd *cobra.Command, args []string) {
		if maxmindLicenseFlag != "" {
			cfg.MaxMindLicense = maxmindLicenseFlag
		}
		if originalPreRun != nil {
			originalPreRun(cmd, args)
		}
	}
	rootCmd.PersistentFlags().BoolVar(&cfg.AutoUpdate, "auto-update", cfg.AutoUpdate, "Enable automatic database updates")
	rootCmd.PersistentFlags().StringVar(&cfg.UpdateInterval, "update-interval", cfg.UpdateInterval, "Database update interval (cron format)")
	rootCmd.PersistentFlags().StringVar(&cfg.LogLevel, "log-level", cfg.LogLevel, "Log level (debug, info, warn, error)")
	rootCmd.PersistentFlags().BoolVar(&cfg.GenerateCerts, "generate-certs", cfg.GenerateCerts, "Generate self-signed certificates")
	rootCmd.PersistentFlags().IntVar(&cfg.CertValidDays, "cert-valid-days", cfg.CertValidDays, "Certificate validity period in days")
	rootCmd.PersistentFlags().StringVar(&cfg.CertHosts, "cert-hosts", cfg.CertHosts, "Certificate hosts (comma-separated)")

	// Cache flags
	rootCmd.PersistentFlags().BoolVar(&cfg.CacheEnabled, "cache-enabled", cfg.CacheEnabled, "Enable IP caching")
	rootCmd.PersistentFlags().DurationVar(&cfg.CacheTTL, "cache-ttl", cfg.CacheTTL, "Cache TTL duration")
	rootCmd.PersistentFlags().IntVar(&cfg.CacheMaxEntries, "cache-max-entries", cfg.CacheMaxEntries, "Maximum cache entries")

	// Add subcommands
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(rollbackCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(certCmd)

	if err := rootCmd.Execute(); err != nil {
		logger.Fatal(err)
	}
}

func runServer(cmd *cobra.Command, args []string) error {
	logger.Info("Starting GeoIP server...")

	// Validate MaxMind license key
	if cfg.MaxMindLicense == "" {
		logger.Warn("MaxMind license key not provided. Please set MAXMIND_LICENSE environment variable or use --maxmind-license flag.")
		return fmt.Errorf("MaxMind license key is required")
	}

	// Setup database manager
	dbManager, err := setupDatabase()
	if err != nil {
		return err
	}
	defer func() {
		if err := dbManager.Close(); err != nil {
			logger.Errorf("Failed to close database manager: %v", err)
		}
	}()

	// Setup TLS configuration
	tlsConfig, err := setupTLS()
	if err != nil {
		return err
	}

	// Create HTTP/HTTPS servers
	server, httpsServer := createServers(dbManager, tlsConfig)

	// Setup automatic database updates scheduler
	cronScheduler := setupScheduler(dbManager)

	// Start servers and wait for shutdown
	return startServersAndWait(server, httpsServer, cronScheduler, dbManager)
}

// setupDatabase initializes the database manager with caching
func setupDatabase() (*geoip.DatabaseManager, error) {
	dbManager := geoip.NewDatabaseManager(cfg.DBPath, cfg.MaxMindLicense, logger, cfg.CacheEnabled, cfg.CacheTTL, cfg.CacheMaxEntries)
	if err := dbManager.Initialize(); err != nil {
		logger.Fatalf("Failed to initialize database manager: %v", err)
		return nil, err
	}

	// Log cache configuration
	if cfg.CacheEnabled {
		logger.Infof("Cache enabled - TTL: %v, Max entries: %d", cfg.CacheTTL, cfg.CacheMaxEntries)
	} else {
		logger.Info("Cache disabled")
	}

	return dbManager, nil
}

// setupTLS configures TLS settings if enabled
func setupTLS() (*tls.Config, error) {
	if !cfg.EnableTLS {
		return nil, nil
	}

	certPath := cfg.CertFile
	keyPath := cfg.KeyFile

	// Use default paths if not specified
	if certPath == "" {
		certPath = filepath.Join(cfg.CertPath, "server.crt")
	}
	if keyPath == "" {
		keyPath = filepath.Join(cfg.CertPath, "server.key")
	}

	certManager := tlsmanager.NewCertManager(certPath, keyPath, logger)

	// Generate certificates if required
	if cfg.GenerateCerts || !certManager.CertificatesExist() {
		if err := certManager.GenerateSelfSignedCert(cfg.CertHosts, cfg.CertValidDays); err != nil {
			logger.Fatalf("Failed to generate certificates: %v", err)
			return nil, err
		}
	}

	// Load TLS config
	tlsConfig, err := certManager.LoadTLSConfig()
	if err != nil {
		logger.Fatalf("Failed to load TLS config: %v", err)
		return nil, err
	}

	return tlsConfig, nil
}

// createServers creates HTTP and HTTPS servers
func createServers(dbManager *geoip.DatabaseManager, tlsConfig *tls.Config) (*http.Server, *http.Server) {
	// Setup HTTP handlers
	apiHandler := handlers.NewAPIHandler(dbManager, logger)
	router := apiHandler.SetupRoutes()

	// Create HTTP server with improved configuration
	server := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Create HTTPS server if TLS is enabled
	var httpsServer *http.Server
	if cfg.EnableTLS {
		httpsServer = &http.Server{
			Addr:         fmt.Sprintf(":%d", cfg.HTTPSPort),
			Handler:      router,
			TLSConfig:    tlsConfig,
			ReadTimeout:  30 * time.Second,
			WriteTimeout: 30 * time.Second,
			IdleTimeout:  60 * time.Second,
		}
	}

	return server, httpsServer
}

// setupScheduler configures automatic database updates
func setupScheduler(dbManager *geoip.DatabaseManager) *cron.Cron {
	if !cfg.AutoUpdate {
		return nil
	}

	cronScheduler := cron.New()
	_, err := cronScheduler.AddFunc(cfg.UpdateInterval, func() {
		logger.Info("Running scheduled database update...")
		if err := dbManager.UpdateDatabases(); err != nil {
			logger.Errorf("Failed to update databases: %v", err)
		} else {
			logger.Info("Database update completed successfully")
		}
	})
	if err != nil {
		logger.Errorf("Failed to setup cron scheduler: %v", err)
		return nil
	}

	cronScheduler.Start()
	logger.Infof("Scheduled database updates every: %s", cfg.UpdateInterval)
	return cronScheduler
}

// startServersAndWait starts servers and waits for shutdown signal
func startServersAndWait(server, httpsServer *http.Server, cronScheduler *cron.Cron, dbManager *geoip.DatabaseManager) error {
	var wg sync.WaitGroup
	serverErrChan := make(chan error, 2)

	// Start HTTP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting HTTP server on port %d", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErrChan <- fmt.Errorf("HTTP server error: %w", err)
		}
	}()

	// Start HTTPS server if enabled
	if cfg.EnableTLS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Infof("Starting HTTPS server on port %d", cfg.HTTPSPort)
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				serverErrChan <- fmt.Errorf("HTTPS server error: %w", err)
			}
		}()
	}

	// Wait for interrupt signal or server error
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	select {
	case <-quit:
		logger.Info("Received shutdown signal, shutting down gracefully...")
	case err := <-serverErrChan:
		logger.Errorf("Server error: %v", err)
		return err
	}

	// Graceful shutdown
	return gracefulShutdown(server, httpsServer, cronScheduler, dbManager, &wg)
}

// gracefulShutdown handles graceful shutdown of all services
func gracefulShutdown(server, httpsServer *http.Server, cronScheduler *cron.Cron, dbManager *geoip.DatabaseManager, wg *sync.WaitGroup) error {
	logger.Info("Starting graceful shutdown...")

	// Stop accepting new requests
	if cronScheduler != nil {
		logger.Info("Stopping cron scheduler...")
		cronScheduler.Stop()
	}

	// Create context with timeout for shutdown
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Shutdown HTTP server
	if err := server.Shutdown(ctx); err != nil {
		logger.Errorf("HTTP server shutdown error: %v", err)
		if err := server.Close(); err != nil {
			logger.Errorf("Failed to force close HTTP server: %v", err)
		}
	} else {
		logger.Info("HTTP server shut down gracefully")
	}

	// Shutdown HTTPS server if running
	if httpsServer != nil {
		if err := httpsServer.Shutdown(ctx); err != nil {
			logger.Errorf("HTTPS server shutdown error: %v", err)
			if err := httpsServer.Close(); err != nil {
				logger.Errorf("Failed to force close HTTPS server: %v", err)
			}
		} else {
			logger.Info("HTTPS server shut down gracefully")
		}
	}

	// Wait for all goroutines to finish with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Info("All server goroutines finished")
	case <-ctx.Done():
		logger.Warn("Timeout waiting for server goroutines to finish")
	}

	// Close database connections
	if err := dbManager.Close(); err != nil {
		logger.Errorf("Database manager close error: %v", err)
	} else {
		logger.Info("Database connections closed")
	}

	logger.Info("Graceful shutdown completed")
	return nil
}

// Update command
var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update GeoIP databases",
	Long:  `Download and update GeoIP databases from MaxMind.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if cfg.MaxMindLicense == "" {
			return fmt.Errorf("MaxMind license key is required")
		}

		dbManager := geoip.NewDatabaseManager(cfg.DBPath, cfg.MaxMindLicense, logger, false, 0, 0)
		return dbManager.UpdateDatabases()
	},
}

// Status command
var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Check database status and integrity",
	Long:  `Check the status and integrity of all GeoIP databases.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dbManager := geoip.NewDatabaseManager(cfg.DBPath, cfg.MaxMindLicense, logger, false, 0, 0)

		// Get database status
		status := dbManager.GetDatabaseStatus()

		fmt.Println("Database Status:")
		fmt.Println("================")

		for name, info := range status {
			statusInfo := info.(map[string]interface{})
			fmt.Printf("\n%s:\n", name)

			if exists, ok := statusInfo["exists"]; ok && exists.(bool) {
				fmt.Printf("  Status: Available\n")

				if size, ok := statusInfo["size"]; ok {
					fmt.Printf("  Size: %d bytes\n", size.(int64))
				}

				if modified, ok := statusInfo["modified"]; ok {
					fmt.Printf("  Modified: %v\n", modified.(time.Time).Format("2006-01-02 15:04:05"))
				}

				if valid, ok := statusInfo["valid"]; ok {
					if valid.(bool) {
						fmt.Printf("  Integrity: Valid\n")
					} else {
						fmt.Printf("  Integrity: Invalid\n")
						if err, ok := statusInfo["error"]; ok {
							fmt.Printf("  Error: %v\n", err)
						}
					}
				}

				if checksum, ok := statusInfo["checksum"]; ok {
					fmt.Printf("  Checksum: %s\n", checksum.(string))
				}
			} else {
				fmt.Printf("  Status: Not Available\n")
				if err, ok := statusInfo["error"]; ok {
					fmt.Printf("  Error: %v\n", err)
				}
			}
		}

		return nil
	},
}

// Rollback command
var rollbackCmd = &cobra.Command{
	Use:   "rollback",
	Short: "Rollback databases to previous backup",
	Long:  `Rollback all GeoIP databases to the most recent backup.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		dbManager := geoip.NewDatabaseManager(cfg.DBPath, cfg.MaxMindLicense, logger, false, 0, 0)

		fmt.Println("Initiating database rollback...")

		if err := dbManager.RollbackDatabases(); err != nil {
			return fmt.Errorf("rollback failed: %w", err)
		}

		fmt.Println("Database rollback completed successfully")
		return nil
	},
}

// Version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Show version information",
	Long:  `Display version and build information.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("GeoIP Server v1.0.0")
		fmt.Println("Build with Go and MaxMind GeoIP databases")
		fmt.Printf("Cache support: %v\n", cfg.CacheEnabled)
		fmt.Printf("TLS support: %v\n", cfg.EnableTLS)
	},
}

// Certificate command
var certCmd = &cobra.Command{
	Use:   "cert",
	Short: "Certificate management",
	Long:  `Generate and manage TLS certificates.`,
}

func init() {
	// Add certificate subcommands
	certCmd.AddCommand(certGenerateCmd)
	certCmd.AddCommand(certInfoCmd)
}

var certGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate self-signed certificate",
	Long:  `Generate a self-signed TLS certificate for the server.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath := cfg.CertFile
		keyPath := cfg.KeyFile

		if certPath == "" {
			certPath = filepath.Join(cfg.CertPath, "server.crt")
		}
		if keyPath == "" {
			keyPath = filepath.Join(cfg.CertPath, "server.key")
		}

		certManager := tlsmanager.NewCertManager(certPath, keyPath, logger)
		return certManager.GenerateSelfSignedCert(cfg.CertHosts, cfg.CertValidDays)
	},
}

var certInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Show certificate information",
	Long:  `Display information about the current TLS certificate.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		certPath := cfg.CertFile
		keyPath := cfg.KeyFile

		if certPath == "" {
			certPath = filepath.Join(cfg.CertPath, "server.crt")
		}
		if keyPath == "" {
			keyPath = filepath.Join(cfg.CertPath, "server.key")
		}

		certManager := tlsmanager.NewCertManager(certPath, keyPath, logger)
		info, err := certManager.GetCertificateInfo()
		if err != nil {
			return err
		}

		fmt.Printf("Certificate Information:\n")
		fmt.Printf("  Certificate Path: %s\n", certPath)
		fmt.Printf("  Private Key Path: %s\n", keyPath)
		fmt.Printf("  Subject: %s\n", info["subject"])
		fmt.Printf("  Issuer: %s\n", info["issuer"])
		fmt.Printf("  Valid From: %s\n", info["not_before"])
		fmt.Printf("  Valid Until: %s\n", info["not_after"])
		fmt.Printf("  DNS Names: %v\n", info["dns_names"])
		fmt.Printf("  IP Addresses: %v\n", info["ip_addresses"])

		return nil
	},
}

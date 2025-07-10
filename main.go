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

	"github.com/robfig/cron/v3"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"golang-geoip/internal/config"
	"golang-geoip/internal/geoip"
	"golang-geoip/internal/handlers"
	tlsmanager "golang-geoip/internal/tls"
)

var (
	cfg    *config.Config
	logger *logrus.Logger
)

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
	rootCmd.PersistentFlags().IntVarP(&cfg.Port, "port", "p", cfg.Port, "HTTP port to listen on")
	rootCmd.PersistentFlags().IntVar(&cfg.HTTPSPort, "https-port", cfg.HTTPSPort, "HTTPS port to listen on")
	rootCmd.PersistentFlags().BoolVar(&cfg.EnableTLS, "enable-tls", cfg.EnableTLS, "Enable TLS/HTTPS")
	rootCmd.PersistentFlags().StringVar(&cfg.CertFile, "cert-file", cfg.CertFile, "Path to TLS certificate file")
	rootCmd.PersistentFlags().StringVar(&cfg.KeyFile, "key-file", cfg.KeyFile, "Path to TLS private key file")
	rootCmd.PersistentFlags().StringVar(&cfg.DBPath, "db-path", cfg.DBPath, "Path to GeoIP database directory")
	rootCmd.PersistentFlags().StringVar(&cfg.MaxMindLicense, "maxmind-license", cfg.MaxMindLicense, "MaxMind license key")
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

	// Initialize database manager with caching
	dbManager := geoip.NewDatabaseManager(cfg.DBPath, cfg.MaxMindLicense, logger, cfg.CacheEnabled, cfg.CacheTTL, cfg.CacheMaxEntries)
	if err := dbManager.Initialize(); err != nil {
		logger.Fatalf("Failed to initialize database manager: %v", err)
	}
	defer dbManager.Close()

	// Log cache configuration
	if cfg.CacheEnabled {
		logger.Infof("Cache enabled - TTL: %v, Max entries: %d", cfg.CacheTTL, cfg.CacheMaxEntries)
	} else {
		logger.Info("Cache disabled")
	}

	// Setup TLS if enabled
	var tlsConfig *tls.Config
	if cfg.EnableTLS {
		certPath := cfg.CertFile
		keyPath := cfg.KeyFile

		// Use default paths if not specified
		if certPath == "" {
			certPath = filepath.Join(cfg.DBPath, "server.crt")
		}
		if keyPath == "" {
			keyPath = filepath.Join(cfg.DBPath, "server.key")
		}

		certManager := tlsmanager.NewCertManager(certPath, keyPath, logger)

		// Generate certificates if required
		if cfg.GenerateCerts || !certManager.CertificatesExist() {
			if err := certManager.GenerateSelfSignedCert(cfg.CertHosts, cfg.CertValidDays); err != nil {
				logger.Fatalf("Failed to generate certificates: %v", err)
			}
		}

		// Load TLS config
		var err error
		tlsConfig, err = certManager.LoadTLSConfig()
		if err != nil {
			logger.Fatalf("Failed to load TLS config: %v", err)
		}
	}

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

	// Setup automatic database updates
	var cronScheduler *cron.Cron
	if cfg.AutoUpdate {
		cronScheduler = cron.New()
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
		} else {
			cronScheduler.Start()
			logger.Infof("Scheduled database updates every: %s", cfg.UpdateInterval)
		}
	}

	// Start servers with improved error handling
	var wg sync.WaitGroup
	var serverErr error
	serverErrChan := make(chan error, 2)

	// Start HTTP server
	wg.Add(1)
	go func() {
		defer wg.Done()
		logger.Infof("Starting HTTP server on port %d", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			serverErr = fmt.Errorf("HTTP server error: %w", err)
			serverErrChan <- serverErr
		}
	}()

	// Start HTTPS server if enabled
	if cfg.EnableTLS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			logger.Infof("Starting HTTPS server on port %d", cfg.HTTPSPort)
			if err := httpsServer.ListenAndServeTLS("", ""); err != nil && err != http.ErrServerClosed {
				serverErr = fmt.Errorf("HTTPS server error: %w", err)
				serverErrChan <- serverErr
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
		server.Close() // Force close if graceful shutdown fails
	} else {
		logger.Info("HTTP server shut down gracefully")
	}

	// Shutdown HTTPS server if running
	if httpsServer != nil {
		if err := httpsServer.Shutdown(ctx); err != nil {
			logger.Errorf("HTTPS server shutdown error: %v", err)
			httpsServer.Close() // Force close if graceful shutdown fails
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
			certPath = filepath.Join(cfg.DBPath, "server.crt")
		}
		if keyPath == "" {
			keyPath = filepath.Join(cfg.DBPath, "server.key")
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
			certPath = filepath.Join(cfg.DBPath, "server.crt")
		}
		if keyPath == "" {
			keyPath = filepath.Join(cfg.DBPath, "server.key")
		}

		certManager := tlsmanager.NewCertManager(certPath, keyPath, logger)
		info, err := certManager.GetCertificateInfo()
		if err != nil {
			return err
		}

		fmt.Printf("Certificate Information:\n")
		fmt.Printf("  Subject: %s\n", info["subject"])
		fmt.Printf("  Issuer: %s\n", info["issuer"])
		fmt.Printf("  Valid From: %s\n", info["not_before"])
		fmt.Printf("  Valid Until: %s\n", info["not_after"])
		fmt.Printf("  DNS Names: %v\n", info["dns_names"])
		fmt.Printf("  IP Addresses: %v\n", info["ip_addresses"])

		return nil
	},
}

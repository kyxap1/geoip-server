package geoip

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang-geoip/internal/cache"
	"golang-geoip/internal/types"

	geoip2 "github.com/oschwald/geoip2-golang"
	"github.com/sirupsen/logrus"
)

// DatabaseManager handles GeoIP database operations with caching and connection pooling
type DatabaseManager struct {
	dbPath     string
	licenseKey string
	cityDB     *geoip2.Reader
	countryDB  *geoip2.Reader
	asnDB      *geoip2.Reader
	logger     *logrus.Logger
	cache      *cache.IPCache
	mu         sync.RWMutex // Protects database readers
}

// DatabaseInfo holds metadata about a database
type DatabaseInfo struct {
	Name         string
	Path         string
	BackupPath   string
	ChecksumPath string
	Size         int64
	ModTime      time.Time
	Checksum     string
}

// GeoIPInfo represents comprehensive GeoIP information
type GeoIPInfo = types.GeoIPInfo

// NewDatabaseManager creates a new database manager with optional caching
func NewDatabaseManager(dbPath, licenseKey string, logger *logrus.Logger, cacheEnabled bool, cacheTTL time.Duration, cacheMaxEntries int) *DatabaseManager {
	dm := &DatabaseManager{
		dbPath:     dbPath,
		licenseKey: licenseKey,
		logger:     logger,
	}

	// Initialize cache if enabled
	if cacheEnabled {
		dm.cache = cache.NewIPCache(cacheTTL, cacheMaxEntries, logger)
		logger.Infof("IP cache initialized with TTL: %v, Max entries: %d", cacheTTL, cacheMaxEntries)
	}

	return dm
}

// Initialize initializes the database manager
func (dm *DatabaseManager) Initialize() error {
	// Create database directory if it doesn't exist
	if err := os.MkdirAll(dm.dbPath, 0755); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	// Create backup directory
	backupDir := filepath.Join(dm.dbPath, "backup")
	if err := os.MkdirAll(backupDir, 0755); err != nil {
		return fmt.Errorf("failed to create backup directory: %w", err)
	}

	// Check if databases exist, if not download them
	if !dm.databasesExist() {
		dm.logger.Info("Databases not found, downloading...")
		if err := dm.UpdateDatabases(); err != nil {
			return fmt.Errorf("failed to download databases: %w", err)
		}
	}

	// Verify database integrity
	if err := dm.verifyDatabaseIntegrity(); err != nil {
		dm.logger.Warnf("Database integrity check failed: %v", err)
		if err := dm.rollbackDatabases(); err != nil {
			return fmt.Errorf("failed to rollback databases: %w", err)
		}
	}

	// Load databases
	return dm.LoadDatabases()
}

// databasesExist checks if all required databases exist
func (dm *DatabaseManager) databasesExist() bool {
	databases := []string{
		"GeoLite2-City.mmdb",
		"GeoLite2-Country.mmdb",
		"GeoLite2-ASN.mmdb",
	}

	for _, db := range databases {
		if _, err := os.Stat(filepath.Join(dm.dbPath, db)); os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// LoadDatabases loads all GeoIP databases with improved error handling
func (dm *DatabaseManager) LoadDatabases() error {
	var err error

	// Close existing connections
	dm.closeConnections()

	// Use write lock for loading
	dm.mu.Lock()
	defer dm.mu.Unlock()

	// Load City database
	cityPath := filepath.Join(dm.dbPath, "GeoLite2-City.mmdb")
	dm.cityDB, err = geoip2.Open(cityPath)
	if err != nil {
		dm.closeConnectionsUnsafe() // Clean up any partially opened connections
		return fmt.Errorf("failed to open city database: %w", err)
	}

	// Load Country database
	countryPath := filepath.Join(dm.dbPath, "GeoLite2-Country.mmdb")
	dm.countryDB, err = geoip2.Open(countryPath)
	if err != nil {
		dm.closeConnectionsUnsafe() // Clean up any partially opened connections
		return fmt.Errorf("failed to open country database: %w", err)
	}

	// Load ASN database
	asnPath := filepath.Join(dm.dbPath, "GeoLite2-ASN.mmdb")
	dm.asnDB, err = geoip2.Open(asnPath)
	if err != nil {
		dm.closeConnectionsUnsafe() // Clean up any partially opened connections
		return fmt.Errorf("failed to open ASN database: %w", err)
	}

	dm.logger.Info("All GeoIP databases loaded successfully")
	return nil
}

// closeConnections closes all database connections (thread-safe)
func (dm *DatabaseManager) closeConnections() {
	dm.mu.Lock()
	defer dm.mu.Unlock()
	dm.closeConnectionsUnsafe()
}

// closeConnectionsUnsafe closes all database connections (not thread-safe)
func (dm *DatabaseManager) closeConnectionsUnsafe() {
	if dm.cityDB != nil {
		if err := dm.cityDB.Close(); err != nil {
			dm.logger.Warnf("Failed to close city database: %v", err)
		}
		dm.cityDB = nil
	}
	if dm.countryDB != nil {
		if err := dm.countryDB.Close(); err != nil {
			dm.logger.Warnf("Failed to close country database: %v", err)
		}
		dm.countryDB = nil
	}
	if dm.asnDB != nil {
		if err := dm.asnDB.Close(); err != nil {
			dm.logger.Warnf("Failed to close ASN database: %v", err)
		}
		dm.asnDB = nil
	}
}

// UpdateDatabases downloads and updates all GeoIP databases with integrity checks
func (dm *DatabaseManager) UpdateDatabases() error {
	dm.logger.Info("Starting database update...")

	databases := map[string]string{
		"GeoLite2-City":    "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=%s&suffix=tar.gz",
		"GeoLite2-Country": "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key=%s&suffix=tar.gz",
		"GeoLite2-ASN":     "https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-ASN&license_key=%s&suffix=tar.gz",
	}

	// Create temporary directory for new databases
	tempDir := filepath.Join(dm.dbPath, "temp")
	if err := os.RemoveAll(tempDir); err != nil {
		dm.logger.Warnf("Failed to remove temp directory: %v", err)
	}
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}
	defer func() {
		if err := os.RemoveAll(tempDir); err != nil {
			dm.logger.Warnf("Failed to remove temp directory during cleanup: %v", err)
		}
	}()

	// Download and verify all databases first
	var newDatabases []DatabaseInfo
	for name, urlTemplate := range databases {
		dm.logger.Infof("Downloading %s database...", name)

		url := fmt.Sprintf(urlTemplate, dm.licenseKey)
		dbInfo, err := dm.downloadAndVerifyDatabase(url, name, tempDir)
		if err != nil {
			return fmt.Errorf("failed to download %s: %w", name, err)
		}
		newDatabases = append(newDatabases, *dbInfo)
	}

	// All downloads successful, now backup current databases and replace them
	if err := dm.backupCurrentDatabases(); err != nil {
		dm.logger.Warnf("Failed to backup current databases: %v", err)
	}

	// Move new databases to production location
	for _, dbInfo := range newDatabases {
		tempPath := dbInfo.Path
		prodPath := filepath.Join(dm.dbPath, filepath.Base(dbInfo.Path))

		if err := os.Rename(tempPath, prodPath); err != nil {
			dm.logger.Errorf("Failed to move %s to production: %v", dbInfo.Name, err)
			// Try to rollback
			if rollbackErr := dm.rollbackDatabases(); rollbackErr != nil {
				dm.logger.Errorf("Failed to rollback after move error: %v", rollbackErr)
			}
			return fmt.Errorf("failed to move %s to production: %w", dbInfo.Name, err)
		}

		// Save checksum
		checksumPath := filepath.Join(dm.dbPath, dbInfo.Name+".checksum")
		if err := os.WriteFile(checksumPath, []byte(dbInfo.Checksum), 0644); err != nil {
			dm.logger.Warnf("Failed to save checksum for %s: %v", dbInfo.Name, err)
		}

		dm.logger.Infof("Successfully updated %s database", dbInfo.Name)
	}

	// Verify integrity of new databases
	if err := dm.verifyDatabaseIntegrity(); err != nil {
		dm.logger.Errorf("New database integrity check failed: %v", err)
		if rollbackErr := dm.rollbackDatabases(); rollbackErr != nil {
			return fmt.Errorf("failed to rollback after integrity check failure: %w", rollbackErr)
		}
		return fmt.Errorf("database integrity check failed after update: %w", err)
	}

	// Clear cache after update
	if dm.cache != nil {
		dm.cache.Clear()
	}

	// Reload databases
	return dm.LoadDatabases()
}

// downloadAndVerifyDatabase downloads and verifies a single database
func (dm *DatabaseManager) downloadAndVerifyDatabase(url, name, tempDir string) (*DatabaseInfo, error) {
	// Download the tar.gz file
	dm.logger.Debugf("Downloading from URL: %s", url)

	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download database: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			dm.logger.Warnf("Failed to close response body: %v", err)
		}
	}()

	dm.logger.Debugf("HTTP response status: %d %s", resp.StatusCode, resp.Status)
	dm.logger.Debugf("HTTP response headers: %v", resp.Header)

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download database: HTTP %d", resp.StatusCode)
	}

	// Create a gzip reader
	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer func() {
		if err := gzReader.Close(); err != nil {
			dm.logger.Warnf("Failed to close gzip reader: %v", err)
		}
	}()

	// Create a tar reader
	tarReader := tar.NewReader(gzReader)

	// Extract the .mmdb file
	tempPath := filepath.Join(tempDir, name+".mmdb")
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar file: %w", err)
		}

		if strings.HasSuffix(header.Name, ".mmdb") {
			// Extract the database file
			outFile, err := os.Create(tempPath)
			if err != nil {
				return nil, fmt.Errorf("failed to create database file: %w", err)
			}
			defer func() {
				if err := outFile.Close(); err != nil {
					dm.logger.Warnf("Failed to close database file: %v", err)
				}
			}()

			if _, err := io.Copy(outFile, tarReader); err != nil {
				return nil, fmt.Errorf("failed to extract database: %w", err)
			}

			// Calculate checksum
			checksum, err := dm.calculateFileChecksum(tempPath)
			if err != nil {
				return nil, fmt.Errorf("failed to calculate checksum: %w", err)
			}

			// Verify database can be opened
			if err := dm.verifyDatabaseFile(tempPath); err != nil {
				return nil, fmt.Errorf("database verification failed: %w", err)
			}

			// Get file info
			fileInfo, err := os.Stat(tempPath)
			if err != nil {
				return nil, fmt.Errorf("failed to get file info: %w", err)
			}

			dbInfo := &DatabaseInfo{
				Name:     name,
				Path:     tempPath,
				Size:     fileInfo.Size(),
				ModTime:  fileInfo.ModTime(),
				Checksum: checksum,
			}

			dm.logger.Infof("Successfully downloaded and verified %s database (size: %d bytes, checksum: %s)",
				name, dbInfo.Size, dbInfo.Checksum[:8]+"...")
			return dbInfo, nil
		}
	}

	return nil, fmt.Errorf("no .mmdb file found in archive")
}

// calculateFileChecksum calculates SHA256 checksum of a file
func (dm *DatabaseManager) calculateFileChecksum(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := file.Close(); err != nil {
			dm.logger.Warnf("Failed to close file %s: %v", filePath, err)
		}
	}()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return hex.EncodeToString(hash.Sum(nil)), nil
}

// verifyDatabaseFile verifies that a database file can be opened and is valid
func (dm *DatabaseManager) verifyDatabaseFile(filePath string) error {
	db, err := geoip2.Open(filePath)
	if err != nil {
		return err
	}
	defer func() {
		if err := db.Close(); err != nil {
			dm.logger.Warnf("Failed to close database file %s: %v", filePath, err)
		}
	}()

	// Try a basic lookup to ensure the database is functional
	testIP := net.ParseIP("8.8.8.8")
	if testIP == nil {
		return fmt.Errorf("failed to parse test IP")
	}

	if strings.Contains(filePath, "City") {
		_, err = db.City(testIP)
	} else if strings.Contains(filePath, "Country") {
		_, err = db.Country(testIP)
	} else if strings.Contains(filePath, "ASN") {
		_, err = db.ASN(testIP)
	}

	if err != nil {
		return fmt.Errorf("database functional test failed: %w", err)
	}

	return nil
}

// verifyDatabaseIntegrity verifies integrity of all current databases
func (dm *DatabaseManager) verifyDatabaseIntegrity() error {
	databases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}

	for _, name := range databases {
		dbPath := filepath.Join(dm.dbPath, name+".mmdb")
		checksumPath := filepath.Join(dm.dbPath, name+".checksum")

		// Check if database file exists
		if _, err := os.Stat(dbPath); os.IsNotExist(err) {
			return fmt.Errorf("database file %s does not exist", name)
		}

		// Verify database can be opened
		if err := dm.verifyDatabaseFile(dbPath); err != nil {
			return fmt.Errorf("database %s verification failed: %w", name, err)
		}

		// Check checksum if available
		if _, err := os.Stat(checksumPath); err == nil {
			savedChecksum, err := os.ReadFile(checksumPath)
			if err != nil {
				dm.logger.Warnf("Failed to read saved checksum for %s: %v", name, err)
				continue
			}

			currentChecksum, err := dm.calculateFileChecksum(dbPath)
			if err != nil {
				dm.logger.Warnf("Failed to calculate current checksum for %s: %v", name, err)
				continue
			}

			if string(savedChecksum) != currentChecksum {
				return fmt.Errorf("checksum mismatch for %s: expected %s, got %s",
					name, string(savedChecksum)[:8]+"...", currentChecksum[:8]+"...")
			}

			dm.logger.Debugf("Checksum verified for %s", name)
		}
	}

	return nil
}

// backupCurrentDatabases creates backups of current databases
func (dm *DatabaseManager) backupCurrentDatabases() error {
	databases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}
	backupDir := filepath.Join(dm.dbPath, "backup")

	timestamp := time.Now().Format("20060102-150405")

	for _, name := range databases {
		srcPath := filepath.Join(dm.dbPath, name+".mmdb")
		backupPath := filepath.Join(backupDir, fmt.Sprintf("%s-%s.mmdb", name, timestamp))

		if _, err := os.Stat(srcPath); os.IsNotExist(err) {
			continue // Skip if file doesn't exist
		}

		if err := dm.copyFile(srcPath, backupPath); err != nil {
			return fmt.Errorf("failed to backup %s: %w", name, err)
		}

		// Also backup checksum if it exists
		checksumSrc := filepath.Join(dm.dbPath, name+".checksum")
		checksumBackup := filepath.Join(backupDir, fmt.Sprintf("%s-%s.checksum", name, timestamp))
		if _, err := os.Stat(checksumSrc); err == nil {
			if err := dm.copyFile(checksumSrc, checksumBackup); err != nil {
				return fmt.Errorf("failed to backup checksum for %s: %w", name, err)
			}
		}

		dm.logger.Infof("Backed up %s to %s", name, backupPath)
	}

	// Clean up old backups (keep last 5)
	dm.cleanupOldBackups(backupDir, 5)

	return nil
}

// rollbackDatabases restores databases from the most recent backup
func (dm *DatabaseManager) rollbackDatabases() error {
	dm.logger.Warn("Initiating database rollback...")

	backupDir := filepath.Join(dm.dbPath, "backup")
	databases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}

	// Find the most recent backup
	latestBackup, err := dm.findLatestBackup(backupDir)
	if err != nil {
		return fmt.Errorf("failed to find backup: %w", err)
	}

	if latestBackup == "" {
		return fmt.Errorf("no backup found for rollback")
	}

	dm.logger.Infof("Rolling back to backup: %s", latestBackup)

	// Close current database connections
	dm.closeConnections()

	// Restore each database
	for _, name := range databases {
		backupPath := filepath.Join(backupDir, fmt.Sprintf("%s-%s.mmdb", name, latestBackup))
		prodPath := filepath.Join(dm.dbPath, name+".mmdb")

		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			dm.logger.Warnf("Backup file %s not found, skipping", backupPath)
			continue
		}

		// Verify backup file before restoring
		if err := dm.verifyDatabaseFile(backupPath); err != nil {
			dm.logger.Errorf("Backup verification failed for %s: %v", name, err)
			continue
		}

		if err := dm.copyFile(backupPath, prodPath); err != nil {
			return fmt.Errorf("failed to restore %s: %w", name, err)
		}

		// Restore checksum if available
		checksumBackup := filepath.Join(backupDir, fmt.Sprintf("%s-%s.checksum", name, latestBackup))
		checksumProd := filepath.Join(dm.dbPath, name+".checksum")
		if _, err := os.Stat(checksumBackup); err == nil {
			if err := dm.copyFile(checksumBackup, checksumProd); err != nil {
				return fmt.Errorf("failed to restore checksum for %s: %w", name, err)
			}
		}

		dm.logger.Infof("Restored %s from backup", name)
	}

	dm.logger.Info("Database rollback completed")
	return nil
}

// findLatestBackup finds the timestamp of the most recent backup
func (dm *DatabaseManager) findLatestBackup(backupDir string) (string, error) {
	files, err := os.ReadDir(backupDir)
	if err != nil {
		return "", err
	}

	var latestTimestamp string
	var latestTime time.Time

	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".mmdb") {
			continue
		}

		// Extract timestamp from filename (format: DatabaseName-YYYYMMDD-HHMMSS.mmdb)
		parts := strings.Split(file.Name(), "-")
		if len(parts) < 3 {
			continue
		}

		timestamp := parts[len(parts)-2] + "-" + strings.TrimSuffix(parts[len(parts)-1], ".mmdb")

		t, err := time.Parse("20060102-150405", timestamp)
		if err != nil {
			continue
		}

		if t.After(latestTime) {
			latestTime = t
			latestTimestamp = timestamp
		}
	}

	return latestTimestamp, nil
}

// cleanupOldBackups removes old backup files, keeping only the specified number
func (dm *DatabaseManager) cleanupOldBackups(backupDir string, keepCount int) {
	files, err := os.ReadDir(backupDir)
	if err != nil {
		dm.logger.Warnf("Failed to read backup directory: %v", err)
		return
	}

	// Group files by timestamp
	backupGroups := make(map[string][]string)
	for _, file := range files {
		if strings.Contains(file.Name(), "-") {
			parts := strings.Split(file.Name(), "-")
			if len(parts) >= 3 {
				timestamp := parts[len(parts)-2] + "-" + strings.Split(parts[len(parts)-1], ".")[0]
				backupGroups[timestamp] = append(backupGroups[timestamp], file.Name())
			}
		}
	}

	// Sort timestamps and remove old ones
	var timestamps []string
	for timestamp := range backupGroups {
		timestamps = append(timestamps, timestamp)
	}

	if len(timestamps) <= keepCount {
		return
	}

	// Remove oldest backups
	for i := 0; i < len(timestamps)-keepCount; i++ {
		timestamp := timestamps[i]
		for _, fileName := range backupGroups[timestamp] {
			filePath := filepath.Join(backupDir, fileName)
			if err := os.Remove(filePath); err != nil {
				dm.logger.Warnf("Failed to remove old backup %s: %v", fileName, err)
			} else {
				dm.logger.Debugf("Removed old backup: %s", fileName)
			}
		}
	}
}

// copyFile copies a file from src to dst
func (dm *DatabaseManager) copyFile(src, dst string) error {
	srcFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer func() {
		if err := srcFile.Close(); err != nil {
			dm.logger.Warnf("Failed to close source file %s: %v", src, err)
		}
	}()

	dstFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer func() {
		if err := dstFile.Close(); err != nil {
			dm.logger.Warnf("Failed to close destination file %s: %v", dst, err)
		}
	}()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// GetGeoIPInfo retrieves comprehensive GeoIP information for an IP address with caching
func (dm *DatabaseManager) GetGeoIPInfo(ip string) (*GeoIPInfo, error) {
	// Check cache first
	if dm.cache != nil {
		if cachedInfo, found := dm.cache.Get(ip); found {
			return cachedInfo, nil
		}
	}

	// Parse IP
	ipAddr := net.ParseIP(ip)
	if ipAddr == nil {
		return nil, fmt.Errorf("invalid IP address: %s", ip)
	}

	info := &GeoIPInfo{IP: ip}

	// Use read lock for database access
	dm.mu.RLock()
	defer dm.mu.RUnlock()

	// Get city information
	if dm.cityDB != nil {
		city, err := dm.cityDB.City(ipAddr)
		if err == nil {
			info.Country = city.Country.Names["en"]
			info.CountryCode = city.Country.IsoCode
			if len(city.Subdivisions) > 0 {
				info.Region = city.Subdivisions[0].Names["en"]
				info.RegionCode = city.Subdivisions[0].IsoCode
			}
			info.City = city.City.Names["en"]
			info.Latitude = city.Location.Latitude
			info.Longitude = city.Location.Longitude
			info.PostalCode = city.Postal.Code
			info.TimeZone = city.Location.TimeZone
		}
	}

	// Get country information if city lookup failed
	if info.Country == "" && dm.countryDB != nil {
		country, err := dm.countryDB.Country(ipAddr)
		if err == nil {
			info.Country = country.Country.Names["en"]
			info.CountryCode = country.Country.IsoCode
		}
	}

	// Get ASN information
	if dm.asnDB != nil {
		asn, err := dm.asnDB.ASN(ipAddr)
		if err == nil {
			info.ASN = asn.AutonomousSystemNumber
			info.ASNOrg = asn.AutonomousSystemOrganization
			info.ISP = asn.AutonomousSystemOrganization
		}
	}

	// Cache the result
	if dm.cache != nil {
		dm.cache.Set(ip, info)
	}

	return info, nil
}

// GetCacheStats returns cache statistics
func (dm *DatabaseManager) GetCacheStats() map[string]interface{} {
	if dm.cache == nil {
		return map[string]interface{}{
			"enabled": false,
		}
	}

	stats := dm.cache.GetStats()
	stats["enabled"] = true
	return stats
}

// Close closes all database connections
func (dm *DatabaseManager) Close() error {
	var errors []error

	if dm.cityDB != nil {
		if err := dm.cityDB.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if dm.countryDB != nil {
		if err := dm.countryDB.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if dm.asnDB != nil {
		if err := dm.asnDB.Close(); err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		return fmt.Errorf("failed to close databases: %v", errors)
	}

	return nil
}

// CheckForUpdates checks if database updates are available
func (dm *DatabaseManager) CheckForUpdates() (bool, error) {
	// For simplicity, we'll check the last modification time
	// In a real implementation, you might want to check MD5 hashes
	databases := []string{
		"GeoLite2-City.mmdb",
		"GeoLite2-Country.mmdb",
		"GeoLite2-ASN.mmdb",
	}

	for _, db := range databases {
		dbPath := filepath.Join(dm.dbPath, db)
		if info, err := os.Stat(dbPath); err == nil {
			// If database is older than 7 days, consider it outdated
			if time.Since(info.ModTime()) > 7*24*time.Hour {
				return true, nil
			}
		}
	}

	return false, nil
}

// GetDatabaseStatus returns status information about the databases
func (dm *DatabaseManager) GetDatabaseStatus() map[string]interface{} {
	status := make(map[string]interface{})
	databases := []string{"GeoLite2-City", "GeoLite2-Country", "GeoLite2-ASN"}

	for _, name := range databases {
		dbPath := filepath.Join(dm.dbPath, name+".mmdb")
		dbStatus := make(map[string]interface{})

		if info, err := os.Stat(dbPath); err == nil {
			dbStatus["size"] = info.Size()
			dbStatus["modified"] = info.ModTime()
			dbStatus["exists"] = true

			// Check if database can be opened
			if err := dm.verifyDatabaseFile(dbPath); err == nil {
				dbStatus["valid"] = true
			} else {
				dbStatus["valid"] = false
				dbStatus["error"] = err.Error()
			}

			// Check checksum
			checksumPath := filepath.Join(dm.dbPath, name+".checksum")
			if checksumData, err := os.ReadFile(checksumPath); err == nil {
				dbStatus["checksum"] = string(checksumData)[:8] + "..."
			}
		} else {
			dbStatus["exists"] = false
			dbStatus["error"] = err.Error()
		}

		status[name] = dbStatus
	}

	return status
}

// RollbackDatabases is a public wrapper for rollbackDatabases
func (dm *DatabaseManager) RollbackDatabases() error {
	return dm.rollbackDatabases()
}

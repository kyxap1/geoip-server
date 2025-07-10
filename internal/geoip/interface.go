package geoip

import "golang-geoip/internal/types"

// DatabaseManagerInterface defines the interface for GeoIP database operations
type DatabaseManagerInterface interface {
	GetGeoIPInfo(ip string) (*types.GeoIPInfo, error)
	GetCacheStats() map[string]interface{}
	Close() error
}

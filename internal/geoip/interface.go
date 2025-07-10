package geoip

import "geoip-server/internal/types"

// DatabaseManagerInterface defines the interface for GeoIP database operations
type DatabaseManagerInterface interface {
	GetGeoIPInfo(ip string) (*types.GeoIPInfo, error)
	GetCacheStats() map[string]interface{}
	Close() error
}

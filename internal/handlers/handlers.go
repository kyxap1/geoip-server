package handlers

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang-geoip/internal/geoip"
	"golang-geoip/internal/types"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// APIHandler handles HTTP requests
type APIHandler struct {
	dbManager geoip.DatabaseManagerInterface
	logger    *logrus.Logger
}

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error     string `json:"error" xml:"error"`
	Message   string `json:"message" xml:"message"`
	Timestamp string `json:"timestamp" xml:"timestamp"`
	Status    int    `json:"status" xml:"status"`
}

// NewAPIHandler creates a new API handler
func NewAPIHandler(dbManager geoip.DatabaseManagerInterface, logger *logrus.Logger) *APIHandler {
	return &APIHandler{
		dbManager: dbManager,
		logger:    logger,
	}
}

// sendJSONError sends a standardized JSON error response
func (h *APIHandler) sendJSONError(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)

	errorResponse := ErrorResponse{
		Error:     http.StatusText(statusCode),
		Message:   errorMsg,
		Timestamp: time.Now().Format(time.RFC3339),
		Status:    statusCode,
	}

	json.NewEncoder(w).Encode(errorResponse)
}

// sendXMLError sends a standardized XML error response
func (h *APIHandler) sendXMLError(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(statusCode)

	errorResponse := ErrorResponse{
		Error:     http.StatusText(statusCode),
		Message:   errorMsg,
		Timestamp: time.Now().Format(time.RFC3339),
		Status:    statusCode,
	}

	w.Write([]byte(xml.Header))
	xml.NewEncoder(w).Encode(errorResponse)
}

// sendCSVError sends a standardized CSV error response
func (h *APIHandler) sendCSVError(w http.ResponseWriter, statusCode int, errorMsg string) {
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(statusCode)

	errorResponse := fmt.Sprintf("Error: %s\nMessage: %s\nStatus: %d\nTimestamp: %s\n",
		http.StatusText(statusCode),
		errorMsg,
		statusCode,
		time.Now().Format(time.RFC3339),
	)

	w.Write([]byte(errorResponse))
}

// validateIP validates if the given string is a valid IP address
func (h *APIHandler) validateIP(ip string) error {
	if net.ParseIP(ip) == nil {
		return fmt.Errorf("invalid IP address: %s", ip)
	}
	return nil
}

// getClientIP extracts the client IP from the request
func (h *APIHandler) getClientIP(r *http.Request) string {
	// Check X-Forwarded-For header first
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// Take the first IP in the list
		if ips := strings.Split(xff, ","); len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Check X-Real-IP header
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to remote address
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// logStructuredRequest logs the request with structured data
func (h *APIHandler) logStructuredRequest(r *http.Request, status int, duration time.Duration, ip string, responseSize int64) {
	h.logger.WithFields(logrus.Fields{
		"method":        r.Method,
		"path":          r.URL.Path,
		"query":         r.URL.RawQuery,
		"status":        status,
		"duration_ms":   duration.Milliseconds(),
		"client_ip":     ip,
		"lookup_ip":     ip,
		"user_agent":    r.UserAgent(),
		"referer":       r.Referer(),
		"content_type":  r.Header.Get("Content-Type"),
		"response_size": responseSize,
		"remote_addr":   r.RemoteAddr,
		"host":          r.Host,
	}).Info("request_processed")
}

// middleware wraps handlers with logging and security headers
func (h *APIHandler) middleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()

		// Add security headers
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-XSS-Protection", "1; mode=block")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'self'")

		// CORS headers for cross-origin requests
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "86400")

		// Handle preflight requests
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		// Create a response writer wrapper to capture status and size
		wrapped := &responseWriter{
			ResponseWriter: w,
			statusCode:     http.StatusOK,
			size:           0,
		}

		next(wrapped, r)

		// Log structured request
		clientIP := h.getClientIP(r)
		duration := time.Since(startTime)
		h.logStructuredRequest(r, wrapped.statusCode, duration, clientIP, wrapped.size)
	}
}

// responseWriter wraps http.ResponseWriter to capture status and body size
type responseWriter struct {
	http.ResponseWriter
	statusCode int
	size       int64
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.statusCode = code
	rw.ResponseWriter.WriteHeader(code)
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	size, err := rw.ResponseWriter.Write(b)
	rw.size += int64(size)
	return size, err
}

// JSONHandler handles JSON requests
func (h *APIHandler) JSONHandler(w http.ResponseWriter, r *http.Request) {
	var ip string

	// Get IP from URL path or use client IP
	vars := mux.Vars(r)
	if ipParam, exists := vars["ip"]; exists {
		ip = ipParam
	} else {
		ip = h.getClientIP(r)
	}

	// Validate IP address
	if err := h.validateIP(ip); err != nil {
		h.sendJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get GeoIP info
	info, err := h.dbManager.GetGeoIPInfo(ip)
	if err != nil {
		h.sendJSONError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get GeoIP info: %v", err))
		return
	}

	// Set content type and encode JSON
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(info); err != nil {
		h.sendJSONError(w, http.StatusInternalServerError, "Failed to encode JSON response")
		return
	}
}

// XMLHandler handles XML requests
func (h *APIHandler) XMLHandler(w http.ResponseWriter, r *http.Request) {
	var ip string

	// Get IP from URL path or use client IP
	vars := mux.Vars(r)
	if ipParam, exists := vars["ip"]; exists {
		ip = ipParam
	} else {
		ip = h.getClientIP(r)
	}

	// Validate IP address
	if err := h.validateIP(ip); err != nil {
		h.sendXMLError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get GeoIP info
	info, err := h.dbManager.GetGeoIPInfo(ip)
	if err != nil {
		h.sendXMLError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get GeoIP info: %v", err))
		return
	}

	// Create XML wrapper
	type XMLResponse struct {
		XMLName xml.Name `xml:"geoip"`
		*types.GeoIPInfo
	}

	response := XMLResponse{GeoIPInfo: info}

	// Set content type and encode XML
	w.Header().Set("Content-Type", "application/xml")
	w.Write([]byte(xml.Header))
	if err := xml.NewEncoder(w).Encode(response); err != nil {
		h.sendXMLError(w, http.StatusInternalServerError, "Failed to encode XML response")
		return
	}
}

// CSVHandler handles CSV requests
func (h *APIHandler) CSVHandler(w http.ResponseWriter, r *http.Request) {
	var ip string

	// Get IP from URL path or use client IP
	vars := mux.Vars(r)
	if ipParam, exists := vars["ip"]; exists {
		ip = ipParam
	} else {
		ip = h.getClientIP(r)
	}

	// Validate IP address
	if err := h.validateIP(ip); err != nil {
		h.sendCSVError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Get GeoIP info
	info, err := h.dbManager.GetGeoIPInfo(ip)
	if err != nil {
		h.sendCSVError(w, http.StatusInternalServerError, fmt.Sprintf("Failed to get GeoIP info: %v", err))
		return
	}

	// Set content type
	w.Header().Set("Content-Type", "text/csv")

	// Create CSV writer
	writer := csv.NewWriter(w)
	defer writer.Flush()

	// Write header
	headers := []string{
		"ip", "country", "country_code", "region", "region_code",
		"city", "latitude", "longitude", "postal_code", "timezone",
		"asn", "asn_org", "isp",
	}
	if err := writer.Write(headers); err != nil {
		h.sendCSVError(w, http.StatusInternalServerError, "Failed to write CSV header")
		return
	}

	// Write data
	record := []string{
		info.IP,
		info.Country,
		info.CountryCode,
		info.Region,
		info.RegionCode,
		info.City,
		strconv.FormatFloat(info.Latitude, 'f', 6, 64),
		strconv.FormatFloat(info.Longitude, 'f', 6, 64),
		info.PostalCode,
		info.TimeZone,
		strconv.FormatUint(uint64(info.ASN), 10),
		info.ASNOrg,
		info.ISP,
	}

	if err := writer.Write(record); err != nil {
		h.sendCSVError(w, http.StatusInternalServerError, "Failed to write CSV data")
		return
	}
}

// HealthHandler handles health check requests
func (h *APIHandler) HealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"status": "healthy",
		"time":   time.Now().Format(time.RFC3339),
	})
}

// StatsHandler handles cache statistics requests
func (h *APIHandler) StatsHandler(w http.ResponseWriter, r *http.Request) {
	stats := h.dbManager.GetCacheStats()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(stats)
}

// SetupRoutes configures all HTTP routes
func (h *APIHandler) SetupRoutes() *mux.Router {
	router := mux.NewRouter()

	// JSON endpoints (both with and without trailing slash)
	router.HandleFunc("/", h.middleware(h.JSONHandler)).Methods("GET")
	router.HandleFunc("/json", h.middleware(h.JSONHandler)).Methods("GET")
	router.HandleFunc("/json/", h.middleware(h.JSONHandler)).Methods("GET")
	router.HandleFunc("/json/{ip}", h.middleware(h.JSONHandler)).Methods("GET")
	router.HandleFunc("/{ip}", h.middleware(h.JSONHandler)).Methods("GET")

	// XML endpoints (both with and without trailing slash)
	router.HandleFunc("/xml", h.middleware(h.XMLHandler)).Methods("GET")
	router.HandleFunc("/xml/", h.middleware(h.XMLHandler)).Methods("GET")
	router.HandleFunc("/xml/{ip}", h.middleware(h.XMLHandler)).Methods("GET")

	// CSV endpoints (both with and without trailing slash)
	router.HandleFunc("/csv", h.middleware(h.CSVHandler)).Methods("GET")
	router.HandleFunc("/csv/", h.middleware(h.CSVHandler)).Methods("GET")
	router.HandleFunc("/csv/{ip}", h.middleware(h.CSVHandler)).Methods("GET")

	// Health check and stats
	router.HandleFunc("/health", h.middleware(h.HealthHandler)).Methods("GET")
	router.HandleFunc("/stats", h.middleware(h.StatsHandler)).Methods("GET")

	// OPTIONS method for CORS
	router.HandleFunc("/{path:.*}", h.middleware(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})).Methods("OPTIONS")

	return router
}

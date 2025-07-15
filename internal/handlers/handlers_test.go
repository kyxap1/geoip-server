package handlers

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/kyxap1/geoip-server/internal/types"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// MockDatabaseManager implements a mock database manager for testing
type MockDatabaseManager struct {
	logger            *logrus.Logger
	ShouldReturnError bool
}

func (m *MockDatabaseManager) GetGeoIPInfo(ip string) (*types.GeoIPInfo, error) {
	if m.ShouldReturnError {
		return nil, fmt.Errorf("mock database error")
	}
	return &types.GeoIPInfo{
		IP:          ip,
		Country:     "United States",
		CountryCode: "US",
		Region:      "California",
		RegionCode:  "CA",
		City:        "Mountain View",
		Latitude:    37.4056,
		Longitude:   -122.0775,
		PostalCode:  "94043",
		TimeZone:    "America/Los_Angeles",
		ASN:         15169,
		ASNOrg:      "Google LLC",
		ISP:         "Google LLC",
	}, nil
}

func (m *MockDatabaseManager) GetCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled":     false,
		"hits":        int64(0),
		"misses":      int64(0),
		"hit_rate":    float64(0),
		"entries":     0,
		"evictions":   int64(0),
		"ttl_seconds": float64(0),
		"max_entries": 0,
	}
}

func (m *MockDatabaseManager) Close() error {
	return nil
}

// Helper function to setup JSON handler router
func setupJSONRouter(handler *APIHandler) *mux.Router {
	router := mux.NewRouter()
	router.HandleFunc("/", handler.middleware(handler.JSONHandler)).Methods("GET")
	router.HandleFunc("/json", handler.middleware(handler.JSONHandler)).Methods("GET")
	router.HandleFunc("/json/", handler.middleware(handler.JSONHandler)).Methods("GET")
	router.HandleFunc("/json/{ip}", handler.middleware(handler.JSONHandler)).Methods("GET")
	router.HandleFunc("/{ip}", handler.middleware(handler.JSONHandler)).Methods("GET")
	return router
}

// Helper function to validate JSON response
func validateJSONResponse(t *testing.T, rr *httptest.ResponseRecorder, expectedIP string) {
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want application/json", contentType)
	}

	var response types.GeoIPInfo
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode JSON response: %v", err)
	}

	if response.IP != expectedIP {
		t.Errorf("handler returned wrong IP: got %v want %v", response.IP, expectedIP)
	}

	if response.Country == "" {
		t.Error("Country field is empty")
	}
	if response.CountryCode == "" {
		t.Error("CountryCode field is empty")
	}
}

// Helper function to validate JSON error response
func validateJSONErrorResponse(t *testing.T, rr *httptest.ResponseRecorder) {
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("error response should be JSON: got %v", contentType)
	}
}

func TestJSONHandler_ValidEndpoints(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)
	router := setupJSONRouter(handler)

	tests := []struct {
		name       string
		path       string
		expectedIP string
	}{
		{"JSON root endpoint", "/", "192.0.2.1"},
		{"JSON endpoint with IP", "/json/8.8.8.8", "8.8.8.8"},
		{"JSON endpoint root with slash", "/json/", "192.0.2.1"},
		{"JSON endpoint root without slash", "/json", "192.0.2.1"},
		{"Specific IP endpoint", "/1.1.1.1", "1.1.1.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}
			req.RemoteAddr = "192.0.2.1:12345"

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if status := rr.Code; status != http.StatusOK {
				t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
			}

			validateJSONResponse(t, rr, tt.expectedIP)
		})
	}
}

func TestJSONHandler_InvalidIP(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)
	router := setupJSONRouter(handler)

	req, err := http.NewRequest("GET", "/invalid-ip", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.RemoteAddr = "192.0.2.1:12345"

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusBadRequest)
	}

	validateJSONErrorResponse(t, rr)
}

func TestXMLHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectedIP     string
	}{
		{
			name:           "XML root endpoint with slash",
			method:         "GET",
			path:           "/xml/",
			expectedStatus: 200,
			expectedIP:     "192.0.2.1",
		},
		{
			name:           "XML root endpoint without slash",
			method:         "GET",
			path:           "/xml",
			expectedStatus: 200,
			expectedIP:     "192.0.2.1",
		},
		{
			name:           "XML endpoint with IP",
			method:         "GET",
			path:           "/xml/8.8.8.8",
			expectedStatus: 200,
			expectedIP:     "8.8.8.8",
		},
		{
			name:           "Invalid IP in XML",
			method:         "GET",
			path:           "/xml/invalid-ip",
			expectedStatus: 400,
			expectedIP:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.RemoteAddr = "192.0.2.1:12345"

			rr := httptest.NewRecorder()
			router := mux.NewRouter()

			router.HandleFunc("/xml", handler.middleware(handler.XMLHandler)).Methods("GET")
			router.HandleFunc("/xml/", handler.middleware(handler.XMLHandler)).Methods("GET")
			router.HandleFunc("/xml/{ip}", handler.middleware(handler.XMLHandler)).Methods("GET")

			router.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			if tt.expectedStatus == 200 {
				// Check content type
				contentType := rr.Header().Get("Content-Type")
				if contentType != "application/xml" {
					t.Errorf("handler returned wrong content type: got %v want application/xml", contentType)
				}

				// Parse XML response
				type XMLResponse struct {
					XMLName xml.Name `xml:"geoip"`
					*types.GeoIPInfo
				}

				var response XMLResponse
				if err := xml.NewDecoder(rr.Body).Decode(&response); err != nil {
					t.Errorf("Failed to decode XML response: %v", err)
				}

				// Check if IP matches expected
				if response.IP != tt.expectedIP {
					t.Errorf("handler returned wrong IP: got %v want %v", response.IP, tt.expectedIP)
				}

				// Check if required fields are present
				if response.Country == "" {
					t.Error("Country field is empty")
				}
			}
		})
	}
}

func TestCSVHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)

	tests := []struct {
		name           string
		method         string
		path           string
		expectedStatus int
		expectedIP     string
	}{
		{
			name:           "CSV root endpoint with slash",
			method:         "GET",
			path:           "/csv/",
			expectedStatus: 200,
			expectedIP:     "192.0.2.1",
		},
		{
			name:           "CSV root endpoint without slash",
			method:         "GET",
			path:           "/csv",
			expectedStatus: 200,
			expectedIP:     "192.0.2.1",
		},
		{
			name:           "CSV endpoint with IP",
			method:         "GET",
			path:           "/csv/8.8.8.8",
			expectedStatus: 200,
			expectedIP:     "8.8.8.8",
		},
		{
			name:           "Invalid IP in CSV",
			method:         "GET",
			path:           "/csv/invalid-ip",
			expectedStatus: 400,
			expectedIP:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.RemoteAddr = "192.0.2.1:12345"

			rr := httptest.NewRecorder()
			router := mux.NewRouter()

			router.HandleFunc("/csv", handler.middleware(handler.CSVHandler)).Methods("GET")
			router.HandleFunc("/csv/", handler.middleware(handler.CSVHandler)).Methods("GET")
			router.HandleFunc("/csv/{ip}", handler.middleware(handler.CSVHandler)).Methods("GET")

			router.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			if tt.expectedStatus == 200 {
				// Check content type
				contentType := rr.Header().Get("Content-Type")
				if contentType != "text/csv" {
					t.Errorf("handler returned wrong content type: got %v want text/csv", contentType)
				}

				// Check if response contains expected IP
				body := rr.Body.String()
				if !strings.Contains(body, tt.expectedIP) {
					t.Errorf("CSV response should contain IP %s", tt.expectedIP)
				}

				// Check if CSV has header
				if !strings.Contains(body, "ip,country") {
					t.Error("CSV response should contain headers")
				}
			}
		})
	}
}

func TestHealthHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)

	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	middlewareHandler := handler.middleware(handler.HealthHandler)
	middlewareHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check content type
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want application/json", contentType)
	}

	// Parse JSON response
	var response map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode JSON response: %v", err)
	}

	// Check if status is healthy
	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", response["status"])
	}

	// Check if timestamp field exists
	if response["timestamp"] == "" {
		t.Error("Timestamp field should not be empty")
	}
}

func TestStatsHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)

	req, err := http.NewRequest("GET", "/stats", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	middlewareHandler := handler.middleware(handler.StatsHandler)
	middlewareHandler(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Errorf("handler returned wrong status code: got %v want %v", status, http.StatusOK)
	}

	// Check content type
	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("handler returned wrong content type: got %v want application/json", contentType)
	}

	// Parse JSON response
	var response map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode JSON response: %v", err)
	}

	// Check if enabled field exists
	if _, ok := response["enabled"]; !ok {
		t.Error("Stats response should contain 'enabled' field")
	}
}

func TestGetClientIP(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)

	tests := []struct {
		name        string
		remoteAddr  string
		xForwardFor string
		xRealIP     string
		expectedIP  string
	}{
		{
			name:       "RemoteAddr only",
			remoteAddr: "192.168.1.1:12345",
			expectedIP: "192.168.1.1",
		},
		{
			name:        "X-Forwarded-For header",
			remoteAddr:  "192.168.1.1:12345",
			xForwardFor: "203.0.113.1, 192.168.1.1",
			expectedIP:  "203.0.113.1",
		},
		{
			name:       "X-Real-IP header",
			remoteAddr: "192.168.1.1:12345",
			xRealIP:    "203.0.113.2",
			expectedIP: "203.0.113.2",
		},
		{
			name:        "X-Forwarded-For takes precedence",
			remoteAddr:  "192.168.1.1:12345",
			xForwardFor: "203.0.113.1",
			xRealIP:     "203.0.113.2",
			expectedIP:  "203.0.113.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest("GET", "/", nil)
			if err != nil {
				t.Fatal(err)
			}

			req.RemoteAddr = tt.remoteAddr
			if tt.xForwardFor != "" {
				req.Header.Set("X-Forwarded-For", tt.xForwardFor)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			ip := handler.getClientIP(req)
			if ip != tt.expectedIP {
				t.Errorf("Expected IP %s, got %s", tt.expectedIP, ip)
			}
		})
	}
}

func TestMiddleware(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("test")); err != nil {
			t.Errorf("Failed to write response: %v", err)
		}
	})

	req, err := http.NewRequest("GET", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	middlewareHandler := handler.middleware(testHandler)
	middlewareHandler(rr, req)

	// Check security headers
	headers := map[string]string{
		"X-Content-Type-Options":      "nosniff",
		"X-Frame-Options":             "DENY",
		"X-XSS-Protection":            "1; mode=block",
		"Access-Control-Allow-Origin": "*",
	}

	for header, expectedValue := range headers {
		if value := rr.Header().Get(header); value != expectedValue {
			t.Errorf("Expected header %s: %s, got: %s", header, expectedValue, value)
		}
	}

	// Test OPTIONS request
	optionsReq, err := http.NewRequest("OPTIONS", "/test", nil)
	if err != nil {
		t.Fatal(err)
	}

	optionsRR := httptest.NewRecorder()
	middlewareHandler(optionsRR, optionsReq)

	if status := optionsRR.Code; status != http.StatusOK {
		t.Errorf("OPTIONS request should return 200, got %v", status)
	}
}

func BenchmarkJSONHandler(b *testing.B) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)

	req, err := http.NewRequest("GET", "/json/8.8.8.8", nil)
	if err != nil {
		b.Fatal(err)
	}

	middlewareHandler := handler.middleware(handler.JSONHandler)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rr := httptest.NewRecorder()
		middlewareHandler(rr, req)
	}
}

// Test SetupRoutes function
func TestSetupRoutes(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)

	// Test that SetupRoutes returns a router
	router := handler.SetupRoutes()
	if router == nil {
		t.Error("SetupRoutes should return a non-nil router")
	}

	// Test that all expected routes are registered by making requests
	testRoutes := []struct {
		method   string
		path     string
		expected int
	}{
		{"GET", "/json/8.8.8.8", 200},
		{"GET", "/xml/8.8.8.8", 200},
		{"GET", "/csv/8.8.8.8", 200},
		{"GET", "/health", 200},
		{"GET", "/stats", 200},
		{"GET", "/8.8.8.8", 200},
		{"POST", "/", 405}, // Method not allowed
	}

	for _, route := range testRoutes {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			req, err := http.NewRequest(route.method, route.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			// Set a test IP for requests
			req.RemoteAddr = "192.0.2.1:12345"

			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if status := rr.Code; status != route.expected {
				t.Errorf("Route %s %s returned wrong status code: got %v want %v",
					route.method, route.path, status, route.expected)
			}
		})
	}
}

// Test error handling functions
// Helper function to setup handler for error tests
func setupErrorTestHandler() (*APIHandler, *logrus.Logger) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	mockDB := &MockDatabaseManager{logger: logger}
	return NewAPIHandler(mockDB, logger), logger
}

func TestSendJSONError(t *testing.T) {
	handler, _ := setupErrorTestHandler()

	rr := httptest.NewRecorder()
	handler.sendJSONError(rr, http.StatusBadRequest, "test error")

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, status)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected content type application/json, got %s", contentType)
	}

	var errorResponse struct {
		Error     string `json:"error"`
		Message   string `json:"message"`
		Timestamp string `json:"timestamp"`
		Status    int    `json:"status"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&errorResponse); err != nil {
		t.Errorf("Failed to decode JSON error response: %v", err)
	}

	if errorResponse.Message != "test error" {
		t.Errorf("Expected error message 'test error', got '%s'", errorResponse.Message)
	}
}

func TestSendXMLError(t *testing.T) {
	handler, _ := setupErrorTestHandler()

	rr := httptest.NewRecorder()
	handler.sendXMLError(rr, http.StatusBadRequest, "test xml error")

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, status)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "application/xml" {
		t.Errorf("Expected content type application/xml, got %s", contentType)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "test xml error") {
		t.Error("XML error response should contain error message")
	}
	if !strings.Contains(body, "<error>") {
		t.Error("XML error response should contain error tags")
	}
}

func TestSendCSVError(t *testing.T) {
	handler, _ := setupErrorTestHandler()

	rr := httptest.NewRecorder()
	handler.sendCSVError(rr, http.StatusBadRequest, "test csv error")

	if status := rr.Code; status != http.StatusBadRequest {
		t.Errorf("Expected status %d, got %d", http.StatusBadRequest, status)
	}

	contentType := rr.Header().Get("Content-Type")
	if contentType != "text/plain" {
		t.Errorf("Expected content type text/plain, got %s", contentType)
	}

	body := rr.Body.String()
	if !strings.Contains(body, "test csv error") {
		t.Error("CSV error response should contain error message")
	}
}

// Test validateIP function
func TestValidateIP(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)

	tests := []struct {
		ip      string
		isValid bool
	}{
		{"8.8.8.8", true},
		{"192.168.1.1", true},
		{"2001:db8::1", true},
		{"::1", true},
		{"invalid-ip", false},
		{"999.999.999.999", false},
		{"", false},
		{"192.168.1", false},
		{"192.168.1.1.1", false},
	}

	for _, test := range tests {
		t.Run(test.ip, func(t *testing.T) {
			err := handler.validateIP(test.ip)
			isValid := err == nil
			if isValid != test.isValid {
				t.Errorf("validateIP(%s) error = %v, want valid = %v", test.ip, err, test.isValid)
			}
		})
	}
}

// Test handlers with database errors
func TestHandlersWithDatabaseErrors(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Create mock that returns errors
	errorMock := &ErrorMockDatabaseManager{logger: logger}
	handler := NewAPIHandler(errorMock, logger)

	t.Run("JSONHandler with database error", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/json/8.8.8.8", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router := mux.NewRouter()
		router.HandleFunc("/json/{ip}", handler.middleware(handler.JSONHandler)).Methods("GET")
		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", status)
		}

		contentType := rr.Header().Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("Expected JSON content type, got %s", contentType)
		}
	})

	t.Run("XMLHandler with database error", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/xml/8.8.8.8", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router := mux.NewRouter()
		router.HandleFunc("/xml/{ip}", handler.middleware(handler.XMLHandler)).Methods("GET")
		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", status)
		}

		contentType := rr.Header().Get("Content-Type")
		if contentType != "application/xml" {
			t.Errorf("Expected XML content type, got %s", contentType)
		}
	})

	t.Run("CSVHandler with database error", func(t *testing.T) {
		req, err := http.NewRequest("GET", "/csv/8.8.8.8", nil)
		if err != nil {
			t.Fatal(err)
		}

		rr := httptest.NewRecorder()
		router := mux.NewRouter()
		router.HandleFunc("/csv/{ip}", handler.middleware(handler.CSVHandler)).Methods("GET")
		router.ServeHTTP(rr, req)

		if status := rr.Code; status != http.StatusInternalServerError {
			t.Errorf("Expected status 500, got %d", status)
		}

		contentType := rr.Header().Get("Content-Type")
		if contentType != "text/plain" {
			t.Errorf("Expected text/plain content type, got %s", contentType)
		}
	})
}

// Test health handler edge cases
func TestHealthHandlerEdgeCases(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	// Test with database that has Close error
	errorMock := &ErrorMockDatabaseManager{logger: logger}
	handler := NewAPIHandler(errorMock, logger)

	req, err := http.NewRequest("GET", "/health", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	middlewareHandler := handler.middleware(handler.HealthHandler)
	middlewareHandler(rr, req)

	// Should still return 200 even if database has issues
	if status := rr.Code; status != http.StatusOK {
		t.Errorf("Health handler should return 200 even with db issues, got %d", status)
	}

	var response map[string]string
	if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
		t.Errorf("Failed to decode JSON response: %v", err)
	}

	if response["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got '%s'", response["status"])
	}
}

// Test response writer wrapper
func TestResponseWriterWrapper(t *testing.T) {
	rr := httptest.NewRecorder()
	wrapper := &responseWriter{ResponseWriter: rr}

	// Test WriteHeader
	wrapper.WriteHeader(http.StatusNotFound)
	if wrapper.statusCode != http.StatusNotFound {
		t.Errorf("Expected status code 404, got %d", wrapper.statusCode)
	}

	// Test Write
	testData := []byte("test data")
	n, err := wrapper.Write(testData)
	if err != nil {
		t.Errorf("Write should not return error: %v", err)
	}
	if n != len(testData) {
		t.Errorf("Expected to write %d bytes, wrote %d", len(testData), n)
	}
	if wrapper.size != int64(n) {
		t.Errorf("Expected size %d, got %d", n, wrapper.size)
	}

	// Verify data was written to underlying recorder
	if rr.Body.String() != string(testData) {
		t.Errorf("Expected body '%s', got '%s'", string(testData), rr.Body.String())
	}
}

// Test concurrent access
func TestConcurrentAccess(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)
	router := handler.SetupRoutes()

	// Test concurrent requests to different endpoints
	done := make(chan bool, 3)

	// JSON requests
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 50; i++ {
			req, _ := http.NewRequest("GET", "/json/8.8.8.8", nil)
			req.RemoteAddr = "192.0.2.1:12345"
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
		}
	}()

	// XML requests
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 50; i++ {
			req, _ := http.NewRequest("GET", "/xml/1.1.1.1", nil)
			req.RemoteAddr = "192.0.2.2:12345"
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
		}
	}()

	// Stats requests
	go func() {
		defer func() { done <- true }()
		for i := 0; i < 50; i++ {
			req, _ := http.NewRequest("GET", "/stats", nil)
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)
		}
	}()

	// Wait for all goroutines to complete
	for i := 0; i < 3; i++ {
		<-done
	}

	// Verify handler is still functional
	req, _ := http.NewRequest("GET", "/health", nil)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	if status := rr.Code; status != http.StatusOK {
		t.Error("Handler should still be functional after concurrent access")
	}
}

// Test favicon handling
func TestFaviconHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)
	router := handler.SetupRoutes()

	req, err := http.NewRequest("GET", "/favicon.ico", nil)
	if err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	// Should return 204 No Content for favicon requests
	if status := rr.Code; status != http.StatusNoContent {
		t.Errorf("Favicon handler should return 204, got %d", status)
	}

	// Body should be empty
	if body := rr.Body.String(); body != "" {
		t.Errorf("Favicon response body should be empty, got %s", body)
	}
}

// Test route precedence
func TestRoutePrecedence(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)

	mockDB := &MockDatabaseManager{logger: logger}
	handler := NewAPIHandler(mockDB, logger)
	router := handler.SetupRoutes()

	tests := []struct {
		path           string
		expectedStatus int
		description    string
	}{
		{"/health", 200, "Health endpoint should work"},
		{"/stats", 200, "Stats endpoint should work"},
		{"/favicon.ico", 204, "Favicon should return 204"},
		{"/8.8.8.8", 200, "IP endpoint should work"},
		{"/invalid-path", 400, "Invalid IP should return 400"},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			req, err := http.NewRequest("GET", test.path, nil)
			if err != nil {
				t.Fatal(err)
			}

			req.RemoteAddr = "192.0.2.1:12345"
			rr := httptest.NewRecorder()
			router.ServeHTTP(rr, req)

			if status := rr.Code; status != test.expectedStatus {
				t.Errorf("Path %s returned status %d, expected %d", test.path, status, test.expectedStatus)
			}
		})
	}
}

// ErrorMockDatabaseManager for testing error scenarios
type ErrorMockDatabaseManager struct {
	logger *logrus.Logger
}

func (m *ErrorMockDatabaseManager) GetGeoIPInfo(ip string) (*types.GeoIPInfo, error) {
	return nil, fmt.Errorf("database error for IP %s", ip)
}

func (m *ErrorMockDatabaseManager) GetCacheStats() map[string]interface{} {
	return map[string]interface{}{
		"enabled": false,
		"error":   "cache error",
	}
}

func (m *ErrorMockDatabaseManager) Close() error {
	return fmt.Errorf("close error")
}

// Test error handling in sendJSONError, sendXMLError, sendCSVError
func TestAPIHandler_ErrorResponses(t *testing.T) {
	mockDB := &MockDatabaseManager{}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewAPIHandler(mockDB, logger)

	t.Run("sendJSONError", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler.sendJSONError(w, http.StatusBadRequest, "test error message")

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}

		if w.Header().Get("Content-Type") != "application/json" {
			t.Error("Expected Content-Type: application/json")
		}

		var errorResp ErrorResponse
		if err := json.Unmarshal(w.Body.Bytes(), &errorResp); err != nil {
			t.Fatalf("Failed to unmarshal error response: %v", err)
		}

		if errorResp.Status != http.StatusBadRequest {
			t.Errorf("Expected status %d in response, got %d", http.StatusBadRequest, errorResp.Status)
		}

		if errorResp.Message != "test error message" {
			t.Errorf("Expected message 'test error message', got '%s'", errorResp.Message)
		}

		if errorResp.Error != http.StatusText(http.StatusBadRequest) {
			t.Errorf("Expected error '%s', got '%s'", http.StatusText(http.StatusBadRequest), errorResp.Error)
		}
	})

	t.Run("sendXMLError", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler.sendXMLError(w, http.StatusInternalServerError, "internal error")

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}

		if w.Header().Get("Content-Type") != "application/xml" {
			t.Error("Expected Content-Type: application/xml")
		}

		body := w.Body.String()
		if !strings.Contains(body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>") {
			t.Error("Expected XML header in response")
		}

		if !strings.Contains(body, "internal error") {
			t.Error("Expected error message in XML response")
		}

		if !strings.Contains(body, "<status>500</status>") {
			t.Error("Expected status code in XML response")
		}
	})

	t.Run("sendCSVError", func(t *testing.T) {
		w := httptest.NewRecorder()
		handler.sendCSVError(w, http.StatusNotFound, "resource not found")

		if w.Code != http.StatusNotFound {
			t.Errorf("Expected status %d, got %d", http.StatusNotFound, w.Code)
		}

		if w.Header().Get("Content-Type") != "text/plain" {
			t.Error("Expected Content-Type: text/plain")
		}

		body := w.Body.String()
		if !strings.Contains(body, "Error: Not Found") {
			t.Error("Expected 'Error: Not Found' in CSV response")
		}

		if !strings.Contains(body, "Message: resource not found") {
			t.Error("Expected error message in CSV response")
		}

		if !strings.Contains(body, "Status: 404") {
			t.Error("Expected status code in CSV response")
		}
	})
}

// Test HealthHandler error scenarios
func TestAPIHandler_HealthHandlerErrors(t *testing.T) {
	mockDB := &MockDatabaseManager{}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewAPIHandler(mockDB, logger)

	// Test normal health check
	t.Run("Normal health check", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/health", nil)
		w := httptest.NewRecorder()

		handler.HealthHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		if w.Header().Get("Content-Type") != "application/json" {
			t.Error("Expected Content-Type: application/json")
		}

		var response map[string]string
		if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
			t.Fatalf("Failed to unmarshal health response: %v", err)
		}

		if response["status"] != "healthy" {
			t.Errorf("Expected status 'healthy', got '%s'", response["status"])
		}

		if response["timestamp"] == "" {
			t.Error("Expected timestamp in health response")
		}
	})
}

// Test StatsHandler error scenarios
func TestAPIHandler_StatsHandlerErrors(t *testing.T) {
	mockDB := &MockDatabaseManager{}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewAPIHandler(mockDB, logger)

	// Test normal stats request
	t.Run("Normal stats request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/stats", nil)
		w := httptest.NewRecorder()

		handler.StatsHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		if w.Header().Get("Content-Type") != "application/json" {
			t.Error("Expected Content-Type: application/json")
		}

		var stats map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &stats); err != nil {
			t.Fatalf("Failed to unmarshal stats response: %v", err)
		}

		// Check if stats contain expected fields from mock
		if _, exists := stats["enabled"]; !exists {
			t.Error("Expected 'enabled' field in stats response")
		}
	})
}

// Test XMLHandler error scenarios
func TestAPIHandler_XMLHandlerErrors(t *testing.T) {
	mockDB := &MockDatabaseManager{}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewAPIHandler(mockDB, logger)

	t.Run("XMLHandler with invalid IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/xml/invalid-ip", nil)
		req = mux.SetURLVars(req, map[string]string{"ip": "invalid-ip"})
		w := httptest.NewRecorder()

		handler.XMLHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}

		if w.Header().Get("Content-Type") != "application/xml" {
			t.Error("Expected Content-Type: application/xml")
		}

		body := w.Body.String()
		if !strings.Contains(body, "invalid IP address") {
			t.Error("Expected invalid IP error message in XML response")
		}
	})

	t.Run("XMLHandler with database error", func(t *testing.T) {
		mockDB.ShouldReturnError = true
		defer func() { mockDB.ShouldReturnError = false }()

		req := httptest.NewRequest("GET", "/xml/8.8.8.8", nil)
		req = mux.SetURLVars(req, map[string]string{"ip": "8.8.8.8"})
		w := httptest.NewRecorder()

		handler.XMLHandler(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Failed to get GeoIP info") {
			t.Error("Expected database error message in XML response")
		}
	})

	t.Run("XMLHandler successful response", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/xml/8.8.8.8", nil)
		req = mux.SetURLVars(req, map[string]string{"ip": "8.8.8.8"})
		w := httptest.NewRecorder()

		handler.XMLHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		if w.Header().Get("Content-Type") != "application/xml" {
			t.Error("Expected Content-Type: application/xml")
		}

		body := w.Body.String()
		if !strings.Contains(body, "<?xml version=\"1.0\" encoding=\"UTF-8\"?>") {
			t.Error("Expected XML header in response")
		}

		if !strings.Contains(body, "<geoip>") {
			t.Error("Expected geoip XML root element")
		}

		if !strings.Contains(body, "8.8.8.8") {
			t.Error("Expected IP address in XML response")
		}
	})
}

// Test CSVHandler error scenarios
func TestAPIHandler_CSVHandlerErrors(t *testing.T) {
	mockDB := &MockDatabaseManager{}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewAPIHandler(mockDB, logger)

	t.Run("CSVHandler with invalid IP", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/csv/invalid-ip", nil)
		req = mux.SetURLVars(req, map[string]string{"ip": "invalid-ip"})
		w := httptest.NewRecorder()

		handler.CSVHandler(w, req)

		if w.Code != http.StatusBadRequest {
			t.Errorf("Expected status %d, got %d", http.StatusBadRequest, w.Code)
		}

		if w.Header().Get("Content-Type") != "text/plain" {
			t.Error("Expected Content-Type: text/plain")
		}

		body := w.Body.String()
		if !strings.Contains(body, "invalid IP address") {
			t.Error("Expected invalid IP error message in CSV response")
		}
	})

	t.Run("CSVHandler with database error", func(t *testing.T) {
		mockDB.ShouldReturnError = true
		defer func() { mockDB.ShouldReturnError = false }()

		req := httptest.NewRequest("GET", "/csv/8.8.8.8", nil)
		req = mux.SetURLVars(req, map[string]string{"ip": "8.8.8.8"})
		w := httptest.NewRecorder()

		handler.CSVHandler(w, req)

		if w.Code != http.StatusInternalServerError {
			t.Errorf("Expected status %d, got %d", http.StatusInternalServerError, w.Code)
		}

		body := w.Body.String()
		if !strings.Contains(body, "Failed to get GeoIP info") {
			t.Error("Expected database error message in CSV response")
		}
	})

	t.Run("CSVHandler successful response", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/csv/8.8.8.8", nil)
		req = mux.SetURLVars(req, map[string]string{"ip": "8.8.8.8"})
		w := httptest.NewRecorder()

		handler.CSVHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d, got %d", http.StatusOK, w.Code)
		}

		if w.Header().Get("Content-Type") != "text/csv" {
			t.Error("Expected Content-Type: text/csv")
		}

		body := w.Body.String()
		lines := strings.Split(strings.TrimSpace(body), "\n")
		if len(lines) < 2 {
			t.Error("Expected at least header and data rows in CSV response")
		}

		// Check header
		if !strings.Contains(lines[0], "ip,country,country_code") {
			t.Error("Expected CSV headers in first line")
		}

		// Check data
		if !strings.Contains(lines[1], "8.8.8.8") {
			t.Error("Expected IP address in CSV data")
		}
	})
}

// Test middleware with different request types
func TestAPIHandler_MiddlewareEdgeCases(t *testing.T) {
	mockDB := &MockDatabaseManager{}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewAPIHandler(mockDB, logger)

	t.Run("OPTIONS request", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/", nil)
		w := httptest.NewRecorder()

		testHandler := handler.middleware(func(w http.ResponseWriter, r *http.Request) {
			t.Error("Handler should not be called for OPTIONS request")
		})

		testHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected status %d for OPTIONS request, got %d", http.StatusOK, w.Code)
		}

		// Check CORS headers
		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Error("Expected CORS allow origin header")
		}

		if w.Header().Get("Access-Control-Allow-Methods") != "GET, OPTIONS" {
			t.Error("Expected CORS allow methods header")
		}
	})

	t.Run("Security headers", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		testHandler := handler.middleware(func(w http.ResponseWriter, r *http.Request) {
			// Handler does nothing, we just check headers
		})

		testHandler(w, req)

		expectedHeaders := map[string]string{
			"X-Content-Type-Options":      "nosniff",
			"X-Frame-Options":             "DENY",
			"X-XSS-Protection":            "1; mode=block",
			"Referrer-Policy":             "strict-origin-when-cross-origin",
			"Content-Security-Policy":     "default-src 'self'",
			"Access-Control-Allow-Origin": "*",
		}

		for header, expectedValue := range expectedHeaders {
			if w.Header().Get(header) != expectedValue {
				t.Errorf("Expected header %s: %s, got %s", header, expectedValue, w.Header().Get(header))
			}
		}
	})
}

// Test getClientIP with various header combinations
func TestAPIHandler_GetClientIPVariations(t *testing.T) {
	mockDB := &MockDatabaseManager{}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewAPIHandler(mockDB, logger)

	t.Run("X-Forwarded-For with multiple IPs", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3")
		req.RemoteAddr = "4.4.4.4:1234"

		ip := handler.getClientIP(req)
		if ip != "1.1.1.1" {
			t.Errorf("Expected first IP from X-Forwarded-For, got %s", ip)
		}
	})

	t.Run("X-Real-IP header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("X-Real-IP", "5.5.5.5")
		req.RemoteAddr = "6.6.6.6:1234"

		ip := handler.getClientIP(req)
		if ip != "5.5.5.5" {
			t.Errorf("Expected IP from X-Real-IP, got %s", ip)
		}
	})

	t.Run("RemoteAddr without port", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "7.7.7.7"

		ip := handler.getClientIP(req)
		if ip != "7.7.7.7" {
			t.Errorf("Expected IP from RemoteAddr, got %s", ip)
		}
	})

	t.Run("RemoteAddr with port", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "8.8.8.8:5678"

		ip := handler.getClientIP(req)
		if ip != "8.8.8.8" {
			t.Errorf("Expected IP from RemoteAddr without port, got %s", ip)
		}
	})
}

// Test SetupRoutes more thoroughly
func TestAPIHandler_SetupRoutesRoutes(t *testing.T) {
	mockDB := &MockDatabaseManager{}
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel)
	handler := NewAPIHandler(mockDB, logger)

	router := handler.SetupRoutes()

	testCases := []struct {
		method   string
		path     string
		expected int
	}{
		{"GET", "/", http.StatusOK},
		{"GET", "/health", http.StatusOK},
		{"GET", "/stats", http.StatusOK},
		{"GET", "/json", http.StatusOK},
		{"GET", "/json/", http.StatusOK},
		{"GET", "/json/8.8.8.8", http.StatusOK},
		{"GET", "/xml", http.StatusOK},
		{"GET", "/xml/", http.StatusOK},
		{"GET", "/xml/8.8.8.8", http.StatusOK},
		{"GET", "/csv", http.StatusOK},
		{"GET", "/csv/", http.StatusOK},
		{"GET", "/csv/8.8.8.8", http.StatusOK},
		{"GET", "/favicon.ico", http.StatusNoContent},
		{"GET", "/8.8.8.8", http.StatusOK}, // Catch-all IP route
		{"OPTIONS", "/anything", http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(fmt.Sprintf("%s %s", tc.method, tc.path), func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			if w.Code != tc.expected {
				t.Errorf("Expected status %d for %s %s, got %d", tc.expected, tc.method, tc.path, w.Code)
			}
		})
	}
}

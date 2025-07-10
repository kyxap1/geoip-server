package handlers

import (
	"encoding/json"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"golang-geoip/internal/types"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
)

// MockDatabaseManager implements a mock database manager for testing
type MockDatabaseManager struct {
	logger *logrus.Logger
}

func (m *MockDatabaseManager) GetGeoIPInfo(ip string) (*types.GeoIPInfo, error) {
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

func TestJSONHandler(t *testing.T) {
	logger := logrus.New()
	logger.SetLevel(logrus.ErrorLevel) // Reduce noise in tests

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
			name:           "JSON root endpoint",
			method:         "GET",
			path:           "/",
			expectedStatus: 200,
			expectedIP:     "192.0.2.1", // Test IP from request
		},
		{
			name:           "JSON endpoint with IP",
			method:         "GET",
			path:           "/json/8.8.8.8",
			expectedStatus: 200,
			expectedIP:     "8.8.8.8",
		},
		{
			name:           "JSON endpoint root with slash",
			method:         "GET",
			path:           "/json/",
			expectedStatus: 200,
			expectedIP:     "192.0.2.1",
		},
		{
			name:           "JSON endpoint root without slash",
			method:         "GET",
			path:           "/json",
			expectedStatus: 200,
			expectedIP:     "192.0.2.1",
		},
		{
			name:           "Specific IP endpoint",
			method:         "GET",
			path:           "/1.1.1.1",
			expectedStatus: 200,
			expectedIP:     "1.1.1.1",
		},
		{
			name:           "Invalid IP endpoint",
			method:         "GET",
			path:           "/invalid-ip",
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

			// Set a test IP for requests without IP in path
			req.RemoteAddr = "192.0.2.1:12345"

			rr := httptest.NewRecorder()
			router := mux.NewRouter()

			// Setup routes
			router.HandleFunc("/", handler.middleware(handler.JSONHandler)).Methods("GET")
			router.HandleFunc("/json", handler.middleware(handler.JSONHandler)).Methods("GET")
			router.HandleFunc("/json/", handler.middleware(handler.JSONHandler)).Methods("GET")
			router.HandleFunc("/json/{ip}", handler.middleware(handler.JSONHandler)).Methods("GET")
			router.HandleFunc("/{ip}", handler.middleware(handler.JSONHandler)).Methods("GET")

			router.ServeHTTP(rr, req)

			if status := rr.Code; status != tt.expectedStatus {
				t.Errorf("handler returned wrong status code: got %v want %v", status, tt.expectedStatus)
			}

			switch tt.expectedStatus {
			case 200:
				// Check content type
				contentType := rr.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("handler returned wrong content type: got %v want application/json", contentType)
				}

				// Parse JSON response
				var response types.GeoIPInfo
				if err := json.NewDecoder(rr.Body).Decode(&response); err != nil {
					t.Errorf("Failed to decode JSON response: %v", err)
				}

				// Check if IP matches expected
				if response.IP != tt.expectedIP {
					t.Errorf("handler returned wrong IP: got %v want %v", response.IP, tt.expectedIP)
				}

				// Check if required fields are present
				if response.Country == "" {
					t.Error("Country field is empty")
				}
				if response.CountryCode == "" {
					t.Error("CountryCode field is empty")
				}
			case 400:
				// Check that error response is JSON
				contentType := rr.Header().Get("Content-Type")
				if contentType != "application/json" {
					t.Errorf("error response should be JSON: got %v", contentType)
				}
			}
		})
	}
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

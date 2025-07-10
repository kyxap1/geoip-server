package types

import (
	"encoding/csv"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestGeoIPInfo_JSONSerialization(t *testing.T) {
	tests := []struct {
		name     string
		geoInfo  GeoIPInfo
		expected string
	}{
		{
			name: "Complete GeoIP data",
			geoInfo: GeoIPInfo{
				IP:          "8.8.8.8",
				Country:     "United States",
				CountryCode: "US",
				Region:      "California",
				RegionCode:  "CA",
				City:        "Mountain View",
				Latitude:    37.386,
				Longitude:   -122.0838,
				PostalCode:  "94035",
				TimeZone:    "America/Los_Angeles",
				ASN:         15169,
				ASNOrg:      "Google LLC",
				ISP:         "Google LLC",
			},
			expected: `{"ip":"8.8.8.8","country":"United States","country_code":"US","region":"California","region_code":"CA","city":"Mountain View","latitude":37.386,"longitude":-122.0838,"postal_code":"94035","timezone":"America/Los_Angeles","asn":15169,"asn_org":"Google LLC","isp":"Google LLC"}`,
		},
		{
			name: "Minimal GeoIP data",
			geoInfo: GeoIPInfo{
				IP:          "192.168.1.1",
				Country:     "",
				CountryCode: "",
			},
			expected: `{"ip":"192.168.1.1","country":"","country_code":"","region":"","region_code":"","city":"","latitude":0,"longitude":0,"postal_code":"","timezone":"","asn":0,"asn_org":"","isp":""}`,
		},
		{
			name:     "Zero values",
			geoInfo:  GeoIPInfo{},
			expected: `{"ip":"","country":"","country_code":"","region":"","region_code":"","city":"","latitude":0,"longitude":0,"postal_code":"","timezone":"","asn":0,"asn_org":"","isp":""}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			jsonData, err := json.Marshal(tt.geoInfo)
			if err != nil {
				t.Fatalf("Failed to marshal to JSON: %v", err)
			}

			if string(jsonData) != tt.expected {
				t.Errorf("JSON serialization mismatch.\nExpected: %s\nGot: %s", tt.expected, string(jsonData))
			}

			// Test unmarshaling
			var decoded GeoIPInfo
			err = json.Unmarshal(jsonData, &decoded)
			if err != nil {
				t.Fatalf("Failed to unmarshal from JSON: %v", err)
			}

			if !reflect.DeepEqual(decoded, tt.geoInfo) {
				t.Errorf("JSON round-trip failed.\nOriginal: %+v\nDecoded: %+v", tt.geoInfo, decoded)
			}
		})
	}
}

func TestGeoIPInfo_XMLSerialization(t *testing.T) {
	tests := []struct {
		name    string
		geoInfo GeoIPInfo
	}{
		{
			name: "Complete GeoIP data",
			geoInfo: GeoIPInfo{
				IP:          "1.1.1.1",
				Country:     "Australia",
				CountryCode: "AU",
				Region:      "Queensland",
				RegionCode:  "QLD",
				City:        "Brisbane",
				Latitude:    -27.4698,
				Longitude:   153.0251,
				PostalCode:  "4000",
				TimeZone:    "Australia/Brisbane",
				ASN:         13335,
				ASNOrg:      "Cloudflare Inc",
				ISP:         "Cloudflare Inc",
			},
		},
		{
			name: "Special characters in data",
			geoInfo: GeoIPInfo{
				IP:      "192.168.0.1",
				Country: "Test & <XML> \"Country\"",
				City:    "Test <City> & \"Quotes\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test marshaling
			xmlData, err := xml.Marshal(tt.geoInfo)
			if err != nil {
				t.Fatalf("Failed to marshal to XML: %v", err)
			}

			// Test unmarshaling
			var decoded GeoIPInfo
			err = xml.Unmarshal(xmlData, &decoded)
			if err != nil {
				t.Fatalf("Failed to unmarshal from XML: %v", err)
			}

			if !reflect.DeepEqual(decoded, tt.geoInfo) {
				t.Errorf("XML round-trip failed.\nOriginal: %+v\nDecoded: %+v", tt.geoInfo, decoded)
			}
		})
	}
}

func TestGeoIPInfo_CSVSerialization(t *testing.T) {
	tests := []struct {
		name    string
		geoInfo GeoIPInfo
	}{
		{
			name: "Complete GeoIP data",
			geoInfo: GeoIPInfo{
				IP:          "203.0.113.1",
				Country:     "Example Country",
				CountryCode: "EX",
				Region:      "Example Region",
				RegionCode:  "ER",
				City:        "Example City",
				Latitude:    40.7128,
				Longitude:   -74.0060,
				PostalCode:  "10001",
				TimeZone:    "America/New_York",
				ASN:         64496,
				ASNOrg:      "Example Organization",
				ISP:         "Example ISP",
			},
		},
		{
			name: "Data with commas and quotes",
			geoInfo: GeoIPInfo{
				IP:      "10.0.0.1",
				Country: "Country, with commas",
				City:    "City \"with quotes\"",
				ASNOrg:  "Org, with \"commas and quotes\"",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Manually create CSV representation for testing
			var buf strings.Builder
			writer := csv.NewWriter(&buf)

			// Write header
			header := []string{"ip", "country", "country_code", "region", "region_code", "city", "latitude", "longitude", "postal_code", "timezone", "asn", "asn_org", "isp"}
			err := writer.Write(header)
			if err != nil {
				t.Fatalf("Failed to write CSV header: %v", err)
			}

			// Write data
			record := []string{
				tt.geoInfo.IP,
				tt.geoInfo.Country,
				tt.geoInfo.CountryCode,
				tt.geoInfo.Region,
				tt.geoInfo.RegionCode,
				tt.geoInfo.City,
				fmt.Sprintf("%g", tt.geoInfo.Latitude),
				fmt.Sprintf("%g", tt.geoInfo.Longitude),
				tt.geoInfo.PostalCode,
				tt.geoInfo.TimeZone,
				fmt.Sprintf("%d", tt.geoInfo.ASN),
				tt.geoInfo.ASNOrg,
				tt.geoInfo.ISP,
			}
			err = writer.Write(record)
			if err != nil {
				t.Fatalf("Failed to write CSV record: %v", err)
			}

			writer.Flush()
			csvData := buf.String()

			// Verify CSV can be parsed back
			reader := csv.NewReader(strings.NewReader(csvData))
			records, err := reader.ReadAll()
			if err != nil {
				t.Fatalf("Failed to parse CSV: %v", err)
			}

			if len(records) != 2 {
				t.Errorf("Expected 2 records (header + data), got %d", len(records))
			}

			if len(records) >= 2 {
				dataRecord := records[1]
				if dataRecord[0] != tt.geoInfo.IP {
					t.Errorf("IP mismatch: expected %s, got %s", tt.geoInfo.IP, dataRecord[0])
				}
				if dataRecord[1] != tt.geoInfo.Country {
					t.Errorf("Country mismatch: expected %s, got %s", tt.geoInfo.Country, dataRecord[1])
				}
			}
		})
	}
}

func TestGeoIPInfo_FieldTags(t *testing.T) {
	// Test that all struct fields have proper JSON, XML, and CSV tags
	geoType := reflect.TypeOf(GeoIPInfo{})

	expectedFields := map[string]struct {
		jsonTag string
		xmlTag  string
		csvTag  string
	}{
		"IP":          {"ip", "ip", "ip"},
		"Country":     {"country", "country", "country"},
		"CountryCode": {"country_code", "country_code", "country_code"},
		"Region":      {"region", "region", "region"},
		"RegionCode":  {"region_code", "region_code", "region_code"},
		"City":        {"city", "city", "city"},
		"Latitude":    {"latitude", "latitude", "latitude"},
		"Longitude":   {"longitude", "longitude", "longitude"},
		"PostalCode":  {"postal_code", "postal_code", "postal_code"},
		"TimeZone":    {"timezone", "timezone", "timezone"},
		"ASN":         {"asn", "asn", "asn"},
		"ASNOrg":      {"asn_org", "asn_org", "asn_org"},
		"ISP":         {"isp", "isp", "isp"},
	}

	for i := 0; i < geoType.NumField(); i++ {
		field := geoType.Field(i)
		expected, exists := expectedFields[field.Name]

		if !exists {
			t.Errorf("Unexpected field %s in GeoIPInfo struct", field.Name)
			continue
		}

		// Check JSON tag
		jsonTag := field.Tag.Get("json")
		if jsonTag != expected.jsonTag {
			t.Errorf("Field %s: expected JSON tag %s, got %s", field.Name, expected.jsonTag, jsonTag)
		}

		// Check XML tag
		xmlTag := field.Tag.Get("xml")
		if xmlTag != expected.xmlTag {
			t.Errorf("Field %s: expected XML tag %s, got %s", field.Name, expected.xmlTag, xmlTag)
		}

		// Check CSV tag
		csvTag := field.Tag.Get("csv")
		if csvTag != expected.csvTag {
			t.Errorf("Field %s: expected CSV tag %s, got %s", field.Name, expected.csvTag, csvTag)
		}

		delete(expectedFields, field.Name)
	}

	// Check if all expected fields were found
	for fieldName := range expectedFields {
		t.Errorf("Expected field %s not found in GeoIPInfo struct", fieldName)
	}
}

func TestGeoIPInfo_NumericTypes(t *testing.T) {
	// Test numeric field types and edge cases
	geoInfo := GeoIPInfo{
		Latitude:  90.0,       // Max latitude
		Longitude: 180.0,      // Max longitude
		ASN:       4294967295, // Max uint32
	}

	// Test JSON serialization with extreme values
	jsonData, err := json.Marshal(geoInfo)
	if err != nil {
		t.Fatalf("Failed to marshal extreme values to JSON: %v", err)
	}

	var decoded GeoIPInfo
	err = json.Unmarshal(jsonData, &decoded)
	if err != nil {
		t.Fatalf("Failed to unmarshal extreme values from JSON: %v", err)
	}

	if decoded.Latitude != geoInfo.Latitude {
		t.Errorf("Latitude mismatch: expected %f, got %f", geoInfo.Latitude, decoded.Latitude)
	}
	if decoded.Longitude != geoInfo.Longitude {
		t.Errorf("Longitude mismatch: expected %f, got %f", geoInfo.Longitude, decoded.Longitude)
	}
	if decoded.ASN != geoInfo.ASN {
		t.Errorf("ASN mismatch: expected %d, got %d", geoInfo.ASN, decoded.ASN)
	}
}

func TestGeoIPInfo_EmptyAndNilHandling(t *testing.T) {
	tests := []struct {
		name    string
		geoInfo GeoIPInfo
	}{
		{
			name:    "Zero value struct",
			geoInfo: GeoIPInfo{},
		},
		{
			name: "Empty strings",
			geoInfo: GeoIPInfo{
				IP:          "",
				Country:     "",
				CountryCode: "",
				Region:      "",
				RegionCode:  "",
				City:        "",
				PostalCode:  "",
				TimeZone:    "",
				ASNOrg:      "",
				ISP:         "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test JSON
			jsonData, err := json.Marshal(tt.geoInfo)
			if err != nil {
				t.Errorf("JSON marshal failed for %s: %v", tt.name, err)
			}

			var jsonDecoded GeoIPInfo
			err = json.Unmarshal(jsonData, &jsonDecoded)
			if err != nil {
				t.Errorf("JSON unmarshal failed for %s: %v", tt.name, err)
			}

			// Test XML
			xmlData, err := xml.Marshal(tt.geoInfo)
			if err != nil {
				t.Errorf("XML marshal failed for %s: %v", tt.name, err)
			}

			var xmlDecoded GeoIPInfo
			err = xml.Unmarshal(xmlData, &xmlDecoded)
			if err != nil {
				t.Errorf("XML unmarshal failed for %s: %v", tt.name, err)
			}
		})
	}
}

package main

import (
	"testing"
)

func TestMaskLicenseKey(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Short key (should not be masked)",
			input:    "short123",
			expected: "short123",
		},
		{
			name:     "Key exactly 13 characters (should not be masked)",
			input:    "1234567890123",
			expected: "1234567890123",
		},
		{
			name:     "Standard MaxMind license key",
			input:    "pfSsgL_ARStest123456789mmk",
			expected: "pfSsgL_ARS...mmk",
		},
		{
			name:     "Long license key",
			input:    "abcdefghijklmnopqrstuvwxyz123456789",
			expected: "abcdefghij...789",
		},
		{
			name:     "Minimum maskable length (14 characters)",
			input:    "12345678901234",
			expected: "1234567890...234",
		},
		{
			name:     "Key with special characters",
			input:    "ABC-123_XYZ.456@789#mmk",
			expected: "ABC-123_XY...mmk",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := maskLicenseKey(tt.input)
			if result != tt.expected {
				t.Errorf("maskLicenseKey(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

func TestMaskLicenseKeyEdgeCases(t *testing.T) {
	t.Run("Very long key", func(t *testing.T) {
		longKey := "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		result := maskLicenseKey(longKey)
		expected := "abcdefghij...XYZ"
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})

	t.Run("Key with Unicode characters", func(t *testing.T) {
		unicodeKey := "test_license_ключ_мой_секрет"
		result := maskLicenseKey(unicodeKey)
		// Note: maskLicenseKey works with bytes, not Unicode runes,
		// so the last 3 bytes might not be complete Unicode characters
		// This is acceptable for license key masking as they're typically ASCII
		if len(result) == 0 {
			t.Error("Result should not be empty")
		}
		if result == unicodeKey {
			t.Error("Key should be masked, not returned as-is")
		}
		if !containsString(result, "...") {
			t.Error("Result should contain '...' separator")
		}
	})

	t.Run("Key with only numbers", func(t *testing.T) {
		numberKey := "12345678901234567890"
		result := maskLicenseKey(numberKey)
		expected := "1234567890...890"
		if result != expected {
			t.Errorf("Expected %q, got %q", expected, result)
		}
	})
}

func TestMaskLicenseKeySecurityConsiderations(t *testing.T) {
	t.Run("Masked result should not contain middle part", func(t *testing.T) {
		sensitiveKey := "prefix_SENSITIVE_MIDDLE_PART_suffix"
		result := maskLicenseKey(sensitiveKey)

		// Check that sensitive middle part is not in the result
		if result == sensitiveKey {
			t.Error("Key should be masked, not returned as-is")
		}
		if len(result) >= len(sensitiveKey) {
			t.Error("Masked result should be shorter than original")
		}

		// Check format
		expectedPrefix := sensitiveKey[:10]
		expectedSuffix := sensitiveKey[len(sensitiveKey)-3:]
		if !startsWith(result, expectedPrefix) {
			t.Errorf("Result should start with %q, but got %q", expectedPrefix, result)
		}
		if !endsWith(result, expectedSuffix) {
			t.Errorf("Result should end with %q, but got %q", expectedSuffix, result)
		}
		if !containsString(result, "...") {
			t.Error("Result should contain '...' separator")
		}
	})
}

// Helper functions for tests
func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}

func endsWith(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

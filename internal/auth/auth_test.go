package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectedErr error
	}{
		{
			name:        "Valid API key",
			headers:     http.Header{"Authorization": []string{"ApiKey abc123"}},
			expectedKey: "abc123",
			expectedErr: nil,
		},
		{
			name:        "No Authorization header",
			headers:     http.Header{},
			expectedKey: "",
			expectedErr: ErrNoAuthHeaderIncluded,  // Correctly expecting ErrNoAuthHeaderIncluded here
		},
		{
			name:        "Malformed Authorization header",
			headers:     http.Header{"Authorization": []string{"Bearer abc123"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
		{
			name:        "Empty Authorization header",
			headers:     http.Header{"Authorization": []string{""}},
			expectedKey: "",
			expectedErr: errors.New("empty authorization header"),  // Correctly expecting ErrNoAuthHeaderIncluded here
		},
		{
			name:        "Only 'ApiKey' without key",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectedErr: errors.New("malformed authorization header"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			// Check if the returned error matches the expected error
			if err != nil && err.Error() != tt.expectedErr.Error() {
				t.Errorf("expected error %v, got %v", tt.expectedErr, err)
			}

			// Check if the returned API key matches the expected key
			if apiKey != tt.expectedKey {
				t.Errorf("expected API key %v, got %v", tt.expectedKey, apiKey)
			}
		})
	}
}



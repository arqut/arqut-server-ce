package signaling

import (
	"testing"
)

func TestGenerateServiceID(t *testing.T) {
	t.Run("generates ID with correct length", func(t *testing.T) {
		id, err := generateServiceID()
		if err != nil {
			t.Fatalf("Failed to generate service ID: %v", err)
		}

		if len(id) != serviceIDLength {
			t.Errorf("Expected ID length %d, got %d", serviceIDLength, len(id))
		}
	})

	t.Run("generates unique IDs", func(t *testing.T) {
		ids := make(map[string]bool)
		iterations := 1000

		for i := 0; i < iterations; i++ {
			id, err := generateServiceID()
			if err != nil {
				t.Fatalf("Failed to generate service ID: %v", err)
			}

			if ids[id] {
				t.Errorf("Duplicate ID generated: %s", id)
			}
			ids[id] = true
		}

		if len(ids) != iterations {
			t.Errorf("Expected %d unique IDs, got %d", iterations, len(ids))
		}
	})

	t.Run("generates IDs with valid characters", func(t *testing.T) {
		id, err := generateServiceID()
		if err != nil {
			t.Fatalf("Failed to generate service ID: %v", err)
		}

		for _, char := range id {
			found := false
			for _, validChar := range alphabets {
				if char == validChar {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("ID contains invalid character: %c", char)
			}
		}
	})
}

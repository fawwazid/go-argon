package argon

import (
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	password := "correct_horse_battery_staple"

	hash, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	if hash == "" {
		t.Fatal("Hash returned empty string")
	}

	// Verify header
	if !strings.HasPrefix(hash, "$argon2id$v=19$") {
		t.Errorf("Hash does not start with expected prefix $argon2id$v=19$: got %s", hash)
	}

	// Verify correct password
	match, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !match {
		t.Error("Verify returned false for correct password")
	}

	// Verify incorrect password
	match, err = Verify("wrong_password", hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if match {
		t.Error("Verify returned true for incorrect password")
	}
}

func TestHashWithParams(t *testing.T) {
	password := "password"
	params := &Params{
		Memory:      32 * 1024,
		Iterations:  2,
		Parallelism: 2,
		SaltLength:  16,
		KeyLength:   32,
	}

	hash, err := HashWithParams(password, params)
	if err != nil {
		t.Fatalf("HashWithParams failed: %v", err)
	}

	// Check if parameters are encoded correctly in the string
	// Format: $argon2id$v=19$m=32768,t=2,p=2$
	expectedParamStr := "m=32768,t=2,p=2"
	if !strings.Contains(hash, expectedParamStr) {
		t.Errorf("Hash expected to contain params %s, got %s", expectedParamStr, hash)
	}

	match, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
	if !match {
		t.Error("Verify returned false for custom params")
	}
}

func TestVerifyInvalidHash(t *testing.T) {
	_, err := Verify("password", "invalid_hash_string")
	if err != ErrInvalidHash {
		t.Errorf("Expected ErrInvalidHash, got %v", err)
	}
}

func TestDefaultParamsValues(t *testing.T) {
	p := DefaultParams()
	if p.Memory != 64*1024 {
		t.Errorf("Default Memory expected 65536, got %d", p.Memory)
	}
	if p.Iterations != 1 {
		t.Errorf("Default Iterations expected 1, got %d", p.Iterations)
	}
	if p.KeyLength != 32 {
		t.Errorf("Default KeyLength expected 32, got %d", p.KeyLength)
	}
}

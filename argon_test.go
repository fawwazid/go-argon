package argon

import (
	"errors"
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

func TestVerifyEmptyPassword(t *testing.T) {
	// Create a valid hash first
	hash, err := Hash("some_password")
	if err != nil {
		t.Fatalf("Hash failed: %v", err)
	}

	// Verify with empty password should work (empty passwords are valid)
	match, err := Verify("", hash)
	if err != nil {
		t.Fatalf("Verify with empty password failed: %v", err)
	}
	if match {
		t.Error("Empty password should not match hash of non-empty password")
	}
}

func TestVerifyEmptyHash(t *testing.T) {
	_, err := Verify("password", "")
	if err != ErrInvalidHash {
		t.Errorf("Expected ErrInvalidHash for empty hash, got %v", err)
	}
}

func TestVerifyMalformedBase64Salt(t *testing.T) {
	// Valid PHC structure but invalid base64 in salt field
	malformedHash := "$argon2id$v=19$m=65536,t=1,p=4$invalid!!!base64$dGVzdGhhc2g"
	_, err := Verify("password", malformedHash)
	if err == nil {
		t.Error("Expected error for invalid base64 salt, got nil")
	}
}

func TestVerifyMalformedBase64Hash(t *testing.T) {
	// Valid PHC structure but invalid base64 in hash field
	malformedHash := "$argon2id$v=19$m=65536,t=1,p=4$dGVzdHNhbHQ$invalid!!!base64"
	_, err := Verify("password", malformedHash)
	if err == nil {
		t.Error("Expected error for invalid base64 hash, got nil")
	}
}

func TestVerifyIncompatibleVersion(t *testing.T) {
	// Hash with version 18 instead of 19
	incompatibleHash := "$argon2id$v=18$m=65536,t=1,p=4$dGVzdHNhbHQ$dGVzdGhhc2g"
	_, err := Verify("password", incompatibleHash)
	if err != ErrIncompatibleVersion {
		t.Errorf("Expected ErrIncompatibleVersion, got %v", err)
	}
}

func TestVerifyZeroMemory(t *testing.T) {
	// Hash with zero memory parameter
	zeroMemoryHash := "$argon2id$v=19$m=0,t=1,p=4$dGVzdHNhbHQ$dGVzdGhhc2g"
	_, err := Verify("password", zeroMemoryHash)
	if err != ErrInvalidHash {
		t.Errorf("Expected ErrInvalidHash for zero memory, got %v", err)
	}
}

func TestVerifyZeroIterations(t *testing.T) {
	// Hash with zero iterations parameter
	zeroIterHash := "$argon2id$v=19$m=65536,t=0,p=4$dGVzdHNhbHQ$dGVzdGhhc2g"
	_, err := Verify("password", zeroIterHash)
	if err != ErrInvalidHash {
		t.Errorf("Expected ErrInvalidHash for zero iterations, got %v", err)
	}
}

func TestVerifyZeroParallelism(t *testing.T) {
	// Hash with zero parallelism parameter
	zeroParallelHash := "$argon2id$v=19$m=65536,t=1,p=0$dGVzdHNhbHQ$dGVzdGhhc2g"
	_, err := Verify("password", zeroParallelHash)
	if err != ErrInvalidHash {
		t.Errorf("Expected ErrInvalidHash for zero parallelism, got %v", err)
	}
}

func TestVerifyExtremeParameters(t *testing.T) {
	// Test with very large but valid parameters
	// Create a hash with extreme parameters
	extremeParams := &Params{
		Memory:      128 * 1024, // 128 MB - large but CI-friendly
		Iterations:  10,         // Many iterations
		Parallelism: 16,         // High parallelism
		SaltLength:  32,         // Longer salt
		KeyLength:   64,         // Longer key
	}

	password := "test_password"
	hash, err := HashWithParams(password, extremeParams)
	if err != nil {
		t.Fatalf("HashWithParams with extreme params failed: %v", err)
	}

	// Should still verify correctly
	match, err := Verify(password, hash)
	if err != nil {
		t.Fatalf("Verify with extreme params failed: %v", err)
	}
	if !match {
		t.Error("Verify should match with extreme but valid parameters")
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

func TestVerifyUnsupportedMode(t *testing.T) {
	// Hash with unsupported mode
	unsupportedHash := "$argon2d$v=19$m=65536,t=1,p=4$dGVzdHNhbHQ$dGVzdGhhc2g"
	_, err := Verify("password", unsupportedHash)
	if err != ErrUnsupportedMode {
		t.Errorf("Expected ErrUnsupportedMode, got %v", err)
	}
}

func TestHashWithParamsRejectsInvalidParams(t *testing.T) {
	tests := []struct {
		name   string
		params *Params
		want   error
	}{
		{name: "nil", params: nil, want: ErrInvalidParams},
		{name: "zero iterations", params: &Params{Memory: 64 * 1024, Parallelism: 1, SaltLength: 16, KeyLength: 32}, want: ErrInvalidParams},
		{name: "short salt", params: &Params{Memory: 64 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 15, KeyLength: 32}, want: ErrInvalidParams},
		{name: "short key", params: &Params{Memory: 64 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 31}, want: ErrInvalidParams},
		{name: "memory below lanes minimum", params: &Params{Memory: 7, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}, want: ErrInvalidParams},
		{name: "excessive memory", params: &Params{Memory: MaxMemory + 1, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}, want: ErrParamsTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := HashWithParams("password", tt.params)
			if !errors.Is(err, tt.want) {
				t.Fatalf("HashWithParams() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestVerifyRejectsExcessiveCost(t *testing.T) {
	encoded := "$argon2id$v=19$m=262145,t=1,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	_, err := Verify("password", encoded)
	if !errors.Is(err, ErrParamsTooLarge) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrParamsTooLarge)
	}
}

func TestVerifyRejectsNonCanonicalParameters(t *testing.T) {
	tests := []string{
		"$argon2id$v=19$m=65536,t=1,p=1trailing$dGVzdHNhbHQ$dGVzdGhhc2h0ZXN0aGFzaA",
		"$argon2id$v=19$m=065536,t=1,p=1$dGVzdHNhbHQ$dGVzdGhhc2h0ZXN0aGFzaA",
		"$argon2id$v=19$m=65536,t=+1,p=1$dGVzdHNhbHQ$dGVzdGhhc2h0ZXN0aGFzaA",
		"$argon2id$v=19$m=65536,t=1,p=1$dGVzdHNhbHR$dGVzdGhhc2h0ZXN0aGFzaA",
	}

	for _, encoded := range tests {
		_, err := Verify("password", encoded)
		if !errors.Is(err, ErrInvalidHash) {
			t.Fatalf("Verify(%q) error = %v, want %v", encoded, err, ErrInvalidHash)
		}
	}
}

func TestRejectsExcessivelyLongPassword(t *testing.T) {
	password := strings.Repeat("x", MaxPasswordLength+1)

	if _, err := Hash(password); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Hash() error = %v, want %v", err, ErrPasswordTooLong)
	}
	if _, err := Verify(password, "invalid"); !errors.Is(err, ErrPasswordTooLong) {
		t.Fatalf("Verify() error = %v, want %v", err, ErrPasswordTooLong)
	}
}

func TestNeedsRehash(t *testing.T) {
	hash, err := Hash("password")
	if err != nil {
		t.Fatal(err)
	}

	needsRehash, err := NeedsRehash(hash, DefaultParams())
	if err != nil {
		t.Fatal(err)
	}
	if needsRehash {
		t.Fatal("fresh default hash unexpectedly needs rehash")
	}

	target := DefaultParams()
	target.Iterations++
	needsRehash, err = NeedsRehash(hash, target)
	if err != nil {
		t.Fatal(err)
	}
	if !needsRehash {
		t.Fatal("hash with an old work factor should need rehash")
	}
}

func FuzzVerify(f *testing.F) {
	f.Add("password", "$argon2id$v=19$m=65536,t=1,p=1$dGVzdHNhbHQ$dGVzdGhhc2h0ZXN0aGFzaA")
	f.Add("password", "not-a-phc-string")
	f.Fuzz(func(t *testing.T, password, encoded string) {
		_, _ = Verify(password, encoded)
	})
}

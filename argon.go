package argon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
)

var (
	// ErrInvalidHash is returned when the hash is not in the correct format.
	ErrInvalidHash = errors.New("argon: hash is not in the correct format")
	// ErrIncompatibleVersion is returned when the hash version is not supported.
	ErrIncompatibleVersion = errors.New("argon: incompatible version of argon2")
)

// Params describes the input parameters used by the Argon2id algorithm.
// The params are set to satisfy NIST recommendations for password hashing.
type Params struct {
	// The amount of memory used by the algorithm (in kibibytes).
	Memory uint32
	// The number of passes over the memory.
	Iterations uint32
	// The number of threads (or lanes) used by the algorithm.
	Parallelism uint8
	// The length of the random salt. 16 bytes is recommended for password hashing.
	SaltLength uint32
	// The length of the generated key (or password hash). 32 bytes or more is recommended.
	KeyLength uint32
}

// DefaultParams returns the parameters recommended for interactive logins
// according to NIST and OWASP guidelines (2024/2025).
//
// Current defaults:
// - Memory: 64 MB (64 * 1024)
// - Iterations: 1
// - Parallelism: 4 (or runtime.NumCPU() if less than 4, capped at 4 for consistency default)
// - SaltLength: 16 bytes
// - KeyLength: 32 bytes
func DefaultParams() *Params {
	p := uint8(runtime.NumCPU())
	if p < 1 {
		p = 1
	}
	// Cap parallelism at 4 for defaults to avoid excessive resource usage on large machines for simple auth
	if p > 4 {
		p = 4
	}

	return &Params{
		Memory:      64 * 1024,
		Iterations:  1,
		Parallelism: p,
		SaltLength:  16,
		KeyLength:   32,
	}
}

// Hash returns a matchable PHC string using the default configuration.
func Hash(password string) (string, error) {
	return HashWithParams(password, DefaultParams())
}

// HashWithParams returns a matchable PHC string using the provided configuration.
func HashWithParams(password string, p *Params) (string, error) {
	salt := make([]byte, p.SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	// Format: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Hash)

	return encoded, nil
}

// Verify compares a password against a hashed PHC string.
// It returns true if the password matches, false otherwise.
func Verify(password, encodedHash string) (bool, error) {
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	if subtle.ConstantTimeCompare(hash, otherHash) == 1 {
		return true, nil
	}
	return false, nil
}

func decodeHash(encodedHash string) (p *Params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHash
	}

	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	p = &Params{}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	salt, err = base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, err
	}
	p.SaltLength = uint32(len(salt))

	hash, err = base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, err
	}
	p.KeyLength = uint32(len(hash))

	return p, salt, hash, nil
}

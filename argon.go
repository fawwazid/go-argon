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
	// ErrUnsupportedMode is returned when the mode is not supported.
	ErrUnsupportedMode = errors.New("argon: unsupported argon2 mode")
)

const (
	// ModeArgon2id is the default mode, recommended by NIST.
	ModeArgon2id = "argon2id"
	// ModeArgon2i is optimized to resist side-channel attacks.
	ModeArgon2i = "argon2i"
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
	// The mode of Argon2 to use (argon2id or argon2i).
	Mode string
}

const (
	// DefaultMemory is the default memory (in kibibytes) used by the algorithm (64 MB).
	DefaultMemory = 64 * 1024
	// DefaultIterations is the default number of passes over the memory.
	DefaultIterations = 1
	// DefaultParallelism is the default number of threads (or lanes) used by the algorithm.
	DefaultParallelism = 4
	// DefaultSaltLength is the default length of the random salt.
	DefaultSaltLength = 16
	// DefaultKeyLength is the default length of the generated key.
	DefaultKeyLength = 32
)

// DefaultParams returns the parameters recommended for interactive logins
// according to NIST and OWASP guidelines (2024/2025).
//
// Current defaults:
//   - Memory: 64 MB (64 * 1024)
//   - Iterations: 1
//   - Parallelism: up to 4 (uses runtime.NumCPU() if less than 4, but always capped at 4)
//     This cap is intended to avoid excessive resource usage on high-core-count systems
//     for typical authentication scenarios, and to provide consistent default behavior.
//     Note: On systems with more than 4 CPUs, this may result in underutilization of available
//     CPU cores. If higher parallelism is desired, set the Parallelism field manually.
//   - SaltLength: 16 bytes
//   - KeyLength: 32 bytes
//   - Mode: argon2id
func DefaultParams() *Params {
	p := uint8(runtime.NumCPU())
	// Cap parallelism at 4 for defaults to avoid excessive resource usage on large machines for simple auth
	if p > DefaultParallelism {
		p = DefaultParallelism
	}

	return &Params{
		Memory:      DefaultMemory,
		Iterations:  DefaultIterations,
		Parallelism: p,
		SaltLength:  DefaultSaltLength,
		KeyLength:   DefaultKeyLength,
		Mode:        ModeArgon2id,
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

	var hash []byte

	// Default to ModeArgon2id if Mode is not set for backward compatibility
	mode := p.Mode
	if mode == "" {
		mode = ModeArgon2id
	}

	switch mode {
	case ModeArgon2i:
		hash = argon2.Key([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	case ModeArgon2id:
		hash = argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	default:
		return "", ErrUnsupportedMode
	}

	// Format: $argon2id$v=19$m=65536,t=1,p=4$salt$hash
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf("$%s$v=%d$m=%d,t=%d,p=%d$%s$%s",
		mode, argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Hash)

	return encoded, nil
}

// Verify compares a password against a hashed PHC string.
// It returns true if the password matches, false otherwise.
func Verify(password, encodedHash string) (bool, error) {
	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	var otherHash []byte

	// Default to ModeArgon2id if Mode is not set for backward compatibility
	mode := p.Mode
	if mode == "" {
		mode = ModeArgon2id
	}

	switch mode {
	case ModeArgon2i:
		otherHash = argon2.Key([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	case ModeArgon2id:
		otherHash = argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)
	default:
		return false, ErrUnsupportedMode
	}

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

	mode := vals[1]
	if mode != ModeArgon2id && mode != ModeArgon2i {
		return nil, nil, nil, ErrUnsupportedMode
	}

	p = &Params{
		Mode: mode,
	}
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Iterations, &p.Parallelism)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	// Validate Argon2 parameters to prevent unsafe or nonsensical values
	if p.Memory < 1 || p.Iterations < 1 || p.Parallelism < 1 {
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

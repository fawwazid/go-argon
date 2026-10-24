package argon

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strconv"
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
	// ErrInvalidParams is returned when hashing parameters are unsafe or invalid.
	ErrInvalidParams = errors.New("argon: invalid parameters")
	// ErrParamsTooLarge is returned when parameters request excessive resources.
	ErrParamsTooLarge = errors.New("argon: parameters exceed safe limits")
	// ErrPasswordTooLong is returned before hashing an excessively large password.
	ErrPasswordTooLong = errors.New("argon: password exceeds maximum length")
)

// Params describes the input parameters used by the Argon2 algorithm.
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

	// Parameter limits protect applications from resource exhaustion when a PHC
	// string or custom configuration is corrupted or comes from an untrusted source.
	MaxMemory      = 256 * 1024
	MaxIterations  = 20
	MaxParallelism = 64
	MaxSaltLength  = 64
	MaxKeyLength   = 64
	MaxEncodedLen  = 1024
	// MaxPasswordLength limits hashing work for unexpectedly large inputs. It is
	// intentionally far above the minimum length applications should permit.
	MaxPasswordLength = 1024 * 1024
)

var phcBase64 = base64.RawStdEncoding.Strict()

// DefaultParams returns independent Argon2id settings with at most four lanes.
// Benchmark and tune the work factor for the deployment.
func DefaultParams() *Params {
	return &Params{
		Memory:      DefaultMemory,
		Iterations:  DefaultIterations,
		Parallelism: uint8(min(DefaultParallelism, max(1, runtime.NumCPU()))),
		SaltLength:  DefaultSaltLength,
		KeyLength:   DefaultKeyLength,
	}
}

// Hash returns a matchable PHC string using the default configuration.
func Hash(password string) (string, error) {
	return HashWithParams(password, DefaultParams())
}

// HashWithParams returns a matchable PHC string using the provided configuration.
func HashWithParams(password string, p *Params) (string, error) {
	if err := checkNonFIPSOperation(); err != nil {
		return "", err
	}
	if len(password) > MaxPasswordLength {
		return "", ErrPasswordTooLong
	}
	if err := validateParams(p); err != nil {
		return "", err
	}

	salt := make([]byte, p.SaltLength)
	_, err := rand.Read(salt)
	if err != nil {
		return "", err
	}

	hash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	b64Salt := phcBase64.EncodeToString(salt)
	b64Hash := phcBase64.EncodeToString(hash)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Iterations, p.Parallelism, b64Salt, b64Hash), nil
}

// Verify compares a password against a hashed PHC string.
func Verify(password, encodedHash string) (bool, error) {
	if err := checkNonFIPSOperation(); err != nil {
		return false, err
	}
	if len(password) > MaxPasswordLength {
		return false, ErrPasswordTooLong
	}

	p, salt, hash, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	otherHash := argon2.IDKey([]byte(password), salt, p.Iterations, p.Memory, p.Parallelism, p.KeyLength)

	return subtle.ConstantTimeCompare(hash, otherHash) == 1, nil
}

// NeedsRehash reports whether an encoded hash uses different parameters from
// the supplied target. It validates both inputs but does not verify a password.
func NeedsRehash(encodedHash string, target *Params) (bool, error) {
	if err := validateParams(target); err != nil {
		return false, err
	}

	p, _, _, err := decodeHash(encodedHash)
	if err != nil {
		return false, err
	}

	return p.Memory != target.Memory ||
		p.Iterations != target.Iterations ||
		p.Parallelism != target.Parallelism ||
		p.SaltLength != target.SaltLength ||
		p.KeyLength != target.KeyLength, nil
}

func validateParams(p *Params) error {
	if p == nil {
		return ErrInvalidParams
	}

	if p.Memory < 8*uint32(p.Parallelism) || p.Iterations < 1 || p.Parallelism < 1 ||
		p.SaltLength < 16 || p.KeyLength < 32 {
		return ErrInvalidParams
	}
	if p.Memory > MaxMemory || p.Iterations > MaxIterations ||
		p.Parallelism > MaxParallelism || p.SaltLength > MaxSaltLength ||
		p.KeyLength > MaxKeyLength {
		return ErrParamsTooLarge
	}

	return nil
}

func decodeHash(encodedHash string) (p *Params, salt, hash []byte, err error) {
	if len(encodedHash) > MaxEncodedLen {
		return nil, nil, nil, ErrInvalidHash
	}

	vals := strings.Split(encodedHash, "$")
	if len(vals) != 6 || vals[0] != "" {
		return nil, nil, nil, ErrInvalidHash
	}

	versionText, ok := strings.CutPrefix(vals[2], "v=")
	if !ok {
		return nil, nil, nil, ErrInvalidHash
	}
	version, err := strconv.Atoi(versionText)
	if err != nil || strconv.Itoa(version) != versionText {
		return nil, nil, nil, ErrInvalidHash
	}
	if version != argon2.Version {
		return nil, nil, nil, ErrIncompatibleVersion
	}

	if vals[1] != "argon2id" {
		return nil, nil, nil, ErrUnsupportedMode
	}

	parameterParts := strings.Split(vals[3], ",")
	if len(parameterParts) != 3 {
		return nil, nil, nil, ErrInvalidHash
	}
	memory, err := parseUintParameter(parameterParts[0], "m=", 32)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	iterations, err := parseUintParameter(parameterParts[1], "t=", 32)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}
	parallelism, err := parseUintParameter(parameterParts[2], "p=", 8)
	if err != nil {
		return nil, nil, nil, ErrInvalidHash
	}

	p = &Params{
		Memory:      uint32(memory),
		Iterations:  uint32(iterations),
		Parallelism: uint8(parallelism),
	}

	if len(vals[4]) > phcBase64.EncodedLen(MaxSaltLength) ||
		len(vals[5]) > phcBase64.EncodedLen(MaxKeyLength) {
		return nil, nil, nil, ErrParamsTooLarge
	}

	salt, err = phcBase64.DecodeString(vals[4])
	if err != nil || phcBase64.EncodeToString(salt) != vals[4] {
		return nil, nil, nil, ErrInvalidHash
	}
	p.SaltLength = uint32(len(salt))

	hash, err = phcBase64.DecodeString(vals[5])
	if err != nil || phcBase64.EncodeToString(hash) != vals[5] {
		return nil, nil, nil, ErrInvalidHash
	}
	p.KeyLength = uint32(len(hash))

	if err := validateParams(p); err != nil {
		if errors.Is(err, ErrInvalidParams) {
			return nil, nil, nil, ErrInvalidHash
		}
		return nil, nil, nil, err
	}

	return p, salt, hash, nil
}

func parseUintParameter(value, prefix string, bits int) (uint64, error) {
	number, ok := strings.CutPrefix(value, prefix)
	if !ok || number == "" {
		return 0, ErrInvalidHash
	}

	parsed, err := strconv.ParseUint(number, 10, bits)
	if err != nil || strconv.FormatUint(parsed, 10) != number {
		return 0, ErrInvalidHash
	}

	return parsed, nil
}

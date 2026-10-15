# Go - Argon

[![Go Reference](https://pkg.go.dev/badge/github.com/fawwazid/go-argon.svg)](https://pkg.go.dev/github.com/fawwazid/go-argon)

Go library for Argon2 password hashing. Its defaults are designed to support the
salted, cost-factor-based storage requirements in **NIST SP 800-63B-4** and
current password-hashing guidance.

This library provides a simple and secure wrapper around `golang.org/x/crypto/argon2`, supporting both **Argon2id** (default, recommended) and **Argon2i** modes with PHC string formatting.

## Installation

```bash
go get github.com/fawwazid/go-argon
```

## Usage

### Simple Hashing (Secure Defaults)

This uses **Argon2id** with:
- Memory: 64 MB
- Iterations: 1
- Parallelism: min(4, number of CPUs)
- Salt: 16 bytes
- Key: 32 bytes

```go
package main

import (
	"fmt"
	"log"

	"github.com/fawwazid/go-argon"
)

func main() {
	password := "my_secure_password"

	// Hash the password
	hash, err := argon.Hash(password)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Hash:", hash)

	// Verify the password
	match, err := argon.Verify(password, hash)
	if err != nil {
		log.Fatal(err)
	}

	if match {
		fmt.Println("Password verified!")
	} else {
		fmt.Println("Invalid password.")
	}
}
```

### Custom Parameters

You can customize the parameters if you need stricter security or lower resource usage (e.g., for IoT devices).

```go
params := &argon.Params{
    Memory:      32 * 1024, // 32 MB
    Iterations:  3,
    Parallelism: 2,
    SaltLength:  16,
    KeyLength:   32,
    Mode:        argon.ModeArgon2id, // or argon.ModeArgon2i
}

hash, err := argon.HashWithParams("password", params)
```

Custom parameters are validated. To limit denial-of-service risk, hashing and
verification reject values above the exported `Max*` limits. Benchmark on your
production hardware and increase the work factor over time when practical.
Passwords larger than 1 MiB are rejected; applications should normally enforce
a much smaller, documented input limit of at least 64 characters.

Applications must still rate-limit authentication attempts. Do not accept the
stored PHC string directly from an unauthenticated client, and do not expose
parser errors verbatim in login responses.

### Rehashing Existing Passwords

After a successful login, use `NeedsRehash` to migrate older hashes when your
target parameters change:

```go
match, err := argon.Verify(password, storedHash)
if err != nil {
    return err
}
if match {
    needsRehash, err := argon.NeedsRehash(storedHash, argon.DefaultParams())
    if err != nil {
        return err
    }
    if needsRehash {
        storedHash, err = argon.Hash(password)
    }
}
```

### Choosing Between Argon2id and Argon2i

- **Argon2id** (Default): The recommended general-purpose Argon2 variant. It balances resistance to GPU/ASIC attacks and side-channel attacks.
- **Argon2i**: Optimized for maximum resistance to side-channel attacks. Use this in environments where timing attacks are a primary concern.

```go
// Using Argon2i explicitly
params := &argon.Params{
    Memory:      64 * 1024,
    Iterations:  3,
    Parallelism: 4,
    SaltLength:  16,
    KeyLength:   32,
    Mode:        argon.ModeArgon2i,
}

hash, err := argon.HashWithParams("password", params)
```

> **Note**: Argon2d is not supported because its data-dependent memory access is
> unsuitable for general-purpose password hashing where side-channel attacks are
> a concern.

## Standards Compliance

The current publication is
[NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b/authenticators/#passwordver).
This library supports several of its password-verifier storage requirements:

- each hash gets a random 128-bit salt from Go's `crypto/rand`;
- the PHC string records the algorithm, version, salt, and cost factor;
- the default uses a deliberately expensive password-hashing scheme; and
- `NeedsRehash` supports raising the cost factor over time.

This is **not a claim of NIST certification or complete application-level
compliance**. SP 800-63B-4 covers the entire verifier, including password length,
blocklist checks, rate limiting, protected transport, and optionally a separate
keyed operation. NIST also points to approved schemes in SP 800-132; Argon2 is
not currently a FIPS-validated password-hashing primitive. Deployments that
require approved cryptography or FIPS validation must select an appropriate
validated implementation and assess the complete system.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

# Go - Argon

[![Go Reference](https://pkg.go.dev/badge/github.com/fawwazid/go-argon.svg)](https://pkg.go.dev/github.com/fawwazid/go-argon)
[![Go Report Card](https://goreportcard.com/badge/github.com/fawwazid/go-argon)](https://goreportcard.com/report/github.com/fawwazid/go-argon)

Go library for Argon2 password hashing, based on **NIST SP 800-63B** guidelines for password hashing.

This library provides a simple and secure wrapper around `golang.org/x/crypto/argon2`, supporting both **Argon2id** (default, recommended) and **Argon2i** modes with PHC string formatting.

## Installation

```bash
go get github.com/fawwazid/go-argon
```

## Usage

### Simple Hashing (Default NIST Params)

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

### Choosing Between Argon2id and Argon2i

- **Argon2id** (Default): Recommended by NIST. Hybrid mode that provides resistance to both GPU/ASIC attacks and side-channel attacks. Use this for general password hashing.
- **Argon2i**: Optimized for maximum resistance to side-channel attacks. Use this in environments where timing attacks are a primary concern.

```go
// Using Argon2i explicitly
params := &argon.Params{
    Memory:      64 * 1024,
    Iterations:  1,
    Parallelism: 4,
    SaltLength:  16,
    KeyLength:   32,
    Mode:        argon.ModeArgon2i,
}

hash, err := argon.HashWithParams("password", params)
```

> **Note**: Argon2d is not supported as it is vulnerable to side-channel attacks and not recommended for password hashing by NIST.

## Standards Compliance

This library follows **NIST Special Publication 800-63B** guidelines for Password Hashing:

- **Algorithm**: Supports **Argon2id** (default) and **Argon2i** (see [Section 5.1.1.2](https://pages.nist.gov/800-63-3/sp800-63b.html#memsecret)). Argon2id is memory-hard and resistant to both GPU/ASIC attacks and side-channel attacks.
- **Salt**: Automatically generates a 16-byte cryptographically secure random salt (meets the 32-bit minimum, recommending 128-bit/16-byte).
- **Work Factor**: Defaults to 64 MB memory usage, satisfying the requirement for memory-hard functions to make offline attacks expensive.
- **Mode Selection**: Defaults to Argon2id. NIST recommends memory-hardened functions; Argon2id is the primary choice for this.

> **NIST SP 800-63B Section 5.1.1.2**: "Verifiers SHALL store memorized secrets in a form that is resistant to offline attacks. Secrets SHALL be hashed with a salt value using a memory-hard function... The salt value SHALL be at least 32 bits in length... The key derivation function SHALL perform an iteration count to increase the work factor...".

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

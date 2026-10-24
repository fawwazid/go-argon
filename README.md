# go-argon

Install: `go get github.com/fawwazid/go-argon/v2@v2.0.0`.
See [v2 release notes](CHANGELOG.md) for breaking changes.

Argon2id password hashing with bounded parameters and canonical PHC encoding.
Requires Go 1.27.3.

## Usage

```go
package main

import (
 "fmt"
 "log"
 argon "github.com/fawwazid/go-argon/v2"
)

func main() {
 params := argon.DefaultParams()
 params.Iterations = 2
 encoded, err := argon.HashWithParams("example password", params)
 if err != nil { log.Fatal(err) }
 matched, err := argon.Verify("example password", encoded)
 if err != nil { log.Fatal(err) }
 fmt.Println(matched)
}
```

## API and parameters

- `Hash(password)`: hash with a fresh `DefaultParams()` configuration.
- `HashWithParams(password, params)`: hash with explicit parameters.
- `Verify(password, encoded)`: validate the PHC record and compare the password.
- `NeedsRehash(encoded, target)`: inspect whether supported parameters differ.

Defaults: 64 MiB memory, one pass, up to four lanes, 16 salt bytes, and 32 key
bytes. Benchmark work factors for your deployment and bound concurrent hashing.

Both creation and verification require at least 16 salt bytes and 32 key bytes.
Memory must be at least eight KiB per lane. Upper bounds are 256 MiB memory,
20 passes, 64 lanes, and 64 salt/key bytes. Password input is capped at 1 MiB.

## Breaking changes

Only Argon2id version 19 is supported. Argon2i, `Params.Mode`, mode constants,
and the empty-mode fallback have been removed. Noncanonical PHC data and weak
salt/key lengths are rejected rather than processed through another path.

Argon2 is outside Go's validated module. Hashing and verification return
`ErrFIPSUnsupported` in FIPS mode. Use approved PBKDF2 for a FIPS application;
this package provides no conversion or fallback mechanism.

See [SECURITY.md](SECURITY.md). Run `go test ./...` and `go vet ./...`.
License: [MIT](LICENSE).

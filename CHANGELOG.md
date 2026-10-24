# Changelog

## v2.0.0 — 2026-10-24

Support only canonical Argon2id records with bounded parameters.

### Breaking changes

- Module path is now `github.com/fawwazid/go-argon/v2`. Update imports and use Go 1.27.3 or later.
- Remove Argon2i, Params.Mode, mode constants, and empty-mode substitution.
- Require at least 16 salt bytes and 32 derived-key bytes for hashing and verification.
- Argon2 hashing and verification reject FIPS mode.

### Security and maintenance

- Bound encoded records, password input, memory, iterations, and parallelism.
- Reject noncanonical parameters and Base64; cap default lanes before narrowing the CPU count.
- Remove redundant code, obsolete comments, and compatibility paths.
- Add regression tests, current README examples, security guidance, and CI for Linux and Windows.
- FIPS policy tests use the frozen Go module v1.0.0 in both approved and strict assessment modes. This library is not independently FIPS certified; consult SECURITY.md for deployment requirements.

### Install

```sh
go get github.com/fawwazid/go-argon/v2@v2.0.0
```

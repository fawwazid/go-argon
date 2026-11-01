# Changelog

## [3.0.0](https://github.com/fawwazid/go-argon/compare/v2.0.0...v3.0.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* prepare v2 security refactor ([#18](https://github.com/fawwazid/go-argon/issues/18))

### Features

* Add a new Go library for Argon2 password hashing with NIST-reco… ([#1](https://github.com/fawwazid/go-argon/issues/1)) ([49ffc14](https://github.com/fawwazid/go-argon/commit/49ffc1473fce71433aeee60b5a6945a3bd9fddbb))
* harden Argon2 password hashing ([#16](https://github.com/fawwazid/go-argon/issues/16)) ([94f0479](https://github.com/fawwazid/go-argon/commit/94f04795cefd0a332b998c617d83808b1f3cf66c))
* prepare v2 security refactor ([#18](https://github.com/fawwazid/go-argon/issues/18)) ([0752ceb](https://github.com/fawwazid/go-argon/commit/0752ceb97a2f598d4f198c0fa83c41521165be76))

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

## v1.0.2 — 2026-10-14

- Harden Argon2 password hashing and update `golang.org/x/crypto`.

## v1.0.1 — 2025-12-13

- Extract default Argon2 parameters into constants and improve project documentation.

## v1.0.0 — 2025-12-10

- Initial release of the Argon2 password-hashing library.

# Changelog

## [2.0.1](https://github.com/fawwazid/go-argon/compare/v2.0.0...v2.0.1) (2026-11-01)


### Bug Fixes

* **release:** configure semantic versioning ([#21](https://github.com/fawwazid/go-argon/issues/21)) ([1245ca5](https://github.com/fawwazid/go-argon/commit/1245ca5fc28f47314a00920b5aadf8afb8241f05))


### Chores

* configure Google Release Please ([8574fd7](https://github.com/fawwazid/go-argon/commit/8574fd7669a1e1453a1f3ed4fb84e99f9142f005))
* reset Release Please baseline ([de0fa8b](https://github.com/fawwazid/go-argon/commit/de0fa8b57b4d3e00a3344eb94603be5856b88357))
* sync agent skill setup ([83c5252](https://github.com/fawwazid/go-argon/commit/83c5252f025b618d890066fdc0f1d3679b236979))


### Security

* align Argon2id defaults with OWASP ([#20](https://github.com/fawwazid/go-argon/issues/20)) ([802ac94](https://github.com/fawwazid/go-argon/commit/802ac94a45b206623fdc5b81838b333b36dae358))

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

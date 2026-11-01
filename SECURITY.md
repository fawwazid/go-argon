# Security policy

## Current contract

Only Argon2id version 19 is accepted. Defaults match OWASP's baseline profile:
19 MiB memory, two passes, and one lane. Salt length is at least 16 bytes and
key length at least 32 bytes in both creation and verification. PHC encodings
must be canonical. There is no mode selector, Argon2i execution path, or empty
mode fallback. Benchmark the configured cost and bound concurrent hashing.
Argon2 operations return ErrFIPSUnsupported whenever FIPS mode is enabled.
Parameter inspection is not a cryptographic operation.

Review the Breaking changes section in README.md before upgrading. Removed APIs
and unsupported inputs have no compatibility fallback or conversion helper.

## FIPS deployment

This library is not independently FIPS 140-3 certified. Deployment compliance
depends on the validated Go module, its approved operating environment,
security policy, and application controls. A library cannot enable FIPS mode
for its caller.

The baseline is Go 1.27.3. The frozen Go module v1.0.0 corresponds to
[CMVP certificate 5247](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5247),
checked active on 2026-11-01. Review certificate status and operating-environment
coverage before deployment. A consuming application can build with
GOFIPS140=v1.0.0 and must not override it with fips140=off.
The strict only setting below is an assessment aid, not a production setting.

## Verification

Ordinary checks:

```sh
go mod verify
go vet ./...
go test ./...
go run golang.org/x/vuln/cmd/govulncheck@v1.9.0 ./...
```

Dedicated policy tests with the frozen module:

```sh
GOFIPS140=v1.0.0 GODEBUG=fips140=on go test -count=1 -run FIPS ./...
GOFIPS140=v1.0.0 GODEBUG=fips140=only go test -count=1 -run FIPS ./...
```

In PowerShell, set the variables with
`$env:GOFIPS140 = 'v1.0.0'` and `$env:GODEBUG = 'fips140=on'` or
`'fips140=only'`, then run the go test command. Restore the original environment
after checking.

Run these checks on the target operating systems and Go version used for
deployment, and record the environment and results in your project review.

## References

- [Go FIPS documentation](https://go.dev/doc/security/fips140)
- [NIST SP 800-131A Rev. 2](https://csrc.nist.gov/pubs/sp/800/131/a/r2/final)
- [NIST SP 800-132](https://csrc.nist.gov/pubs/sp/800/132/final)
- [NIST SP 800-63B-4](https://pages.nist.gov/800-63-4/sp800-63b.html)
- [NIST SP 800-52 Rev. 2](https://csrc.nist.gov/pubs/sp/800/52/r2/final)

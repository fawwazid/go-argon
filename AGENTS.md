# Agent instructions

This repository is the `go-argon` Go module. Keep changes within this module
unless the task explicitly spans other repositories. Preserve existing user
changes. Do not create or edit changelogs; Release Please generates them.

## Security and API

- Support Argon2id version 19 only; preserve canonical PHC parsing and bounded
  parameters before any expensive derivation.
- Keep password size and memory, iteration, lane, salt, and key limits aligned
  across hashing and verification.
- Argon2 is outside the Go validated module. Return the documented FIPS error
  in FIPS mode; do not silently substitute another algorithm.
- Do not claim this package is independently FIPS-certified. Explain that any
  FIPS deployment needs a separately selected approved scheme and validated
  module/environment.

## Development

- Workspace mail invariant: `go-mail` caps messages at 1,000 recipients, 100
  attachments, and 25 MiB; untrusted attachment bytes use its checked API.
- Workspace MFA invariant: `ConstantTimeCompare` rejects strings longer than
  4,096 UTF-8 bytes before allocating byte slices.

- Target the Go version in `go.mod`; format Go changes with `gofmt`.
- Keep `README.md` and `SECURITY.md` aligned with parameters and error behavior.
- Remove only clearly unused internal code; preserve exported APIs unless a
  breaking change is explicitly requested.
- Add or update regression tests for every code change and run the affected
  module's complete test suite before finishing. Run `go vet ./...` as well.
- Review changes against applicable OWASP password-storage guidance and FIPS
  boundaries. Keep Argon2 outside FIPS mode and fail closed without fallback.
- For every workspace code, test, or security-policy change, review and update
  all eight module-level `AGENTS.md` files in the same change set so their
  constraints and test-coverage notes stay aligned. Keep updates concise; this
  is not a changelog.

## Test coverage notes

- `argon_test.go` asserts the OWASP baseline defaults, including memory,
  iterations, parallelism, salt length, and key length.

## Release workflow

- Use Conventional Commit pull request titles so squash merges produce the
  intended SemVer bump: `fix:` for patch, `feat:` for minor, and `!` or
  `BREAKING CHANGE:` for major. Use `fix(security):` for security fixes;
  `security:` alone does not bump a version.
- `docs:`, `test:`, `chore:`, and `ci:` do not trigger a release. Release
  Please opens or updates a release pull request; merge that generated PR to
  create the version tag and GitHub release.
- Never create or edit changelogs manually; Release Please generates them.
- Keep the temporary `last-release-sha` at the v2 preparation commit during this rollout: the existing v2.0.0 tag is not on `main` history. After the first generated v2.0.1 release PR is merged and tagged, remove this fixed marker in a chore PR so later releases track the latest tag automatically.
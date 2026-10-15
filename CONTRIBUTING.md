# Contributing to Workbench

Thanks for helping make local secret handling simpler and safer.
Bug reports, documentation fixes and focused pull requests are welcome.

## Start with the workflow

For bugs, include `wkb version`, your OS/architecture and a reproducible example
with **synthetic values**. A separate vault keeps experiments away from your
own configuration. Never attach real credentials, identities, passphrases or
decrypted backups. Report vulnerabilities [privately](https://github.com/pedroloch/workbench/security/advisories/new).

For a small fix, open a pull request directly. Discuss larger features in an
issue before implementing them, especially changes to encryption, the vault
format, identity storage or trust boundaries. This keeps incompatible formats
and unnecessary dependencies out of a single-binary, offline tool.

## Run locally

Use Go 1.26.9+, Python 3 and Node.js. Native macOS Keychain builds also need
Apple's Command Line Tools and CGO. Linux uses passphrase-protected identities.

```sh
git clone https://github.com/pedroloch/workbench.git
cd workbench
go build -o /tmp/wkb ./cmd/workbench
go test -race ./...
go vet ./...
node --check internal/ui/web/app.js
python3 scripts/smoke.py /tmp/wkb
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
```

Run `gofmt -w` on changed Go files. Keep changes focused and explain the user
behavior in the PR. Fixes need a regression test that fails on the broken
version; new behavior needs meaningful tests for its important boundaries.
Avoid tests that only repeat implementation details.

The smoke test runs the actual executable in private temporary vaults. It
covers installation, storage, environment injection, temporary encrypted use,
recipient isolation, import and recovery. Unit and HTTP tests exercise malformed
input, permissions, symlinks, classification and UI access controls.

Native Keychain testing is opt-in because it touches your OS keychain. It only
creates and deletes a randomized synthetic entry:

```sh
WORKBENCH_TEST_KEYCHAIN=1 go test ./internal/keyring -run TestNativeKeychainRoundTrip
```

## Review policy

A maintainer reviews contributions before merging. CI must pass on Linux and
macOS. Preserve backwards compatibility where practical; document migration
and security implications when a format or behavior must change. Never weaken
permission checks, authentication or masking just to make a test pass.

Be respectful and specific in reviews. Critique the change, help reproduce the
problem, and keep discussion about the work. Maintainers may moderate abusive
or spam content.

## Releases and licensing

Version tags run the release workflow. It tests and builds native Linux/macOS
archives for amd64 and arm64, with SHA-256 checksums. Releases currently have
no signing/notarization or independent security audit.

Workbench uses the [MIT license](LICENSE). Contributions are accepted under the
same license; no separate CLA or contributor agreement is required.

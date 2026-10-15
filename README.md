# Workbench

[![CI](https://github.com/pedroloch/workbench/actions/workflows/ci.yml/badge.svg)](https://github.com/pedroloch/workbench/actions/workflows/ci.yml)
[![MIT license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Your keys, close to you. Your agent, free to work.**

A local encrypted vault for people, scripts and coding agents. Save a credential
for later, or hand your agent an encrypted value for one task without storing it.
A single Go binary includes the CLI, a browser interface and an Agent Skill.
No account. No remote server.

![Workbench local UI with synthetic values grouped by object](assets/ui.png)

_Demo vault with fictional data. No real credentials appear in this screenshot._

## Install

On **macOS or Linux**, download the archive for your OS and CPU from
[Releases](https://github.com/pedroloch/workbench/releases/latest), extract it,
then run:

```sh
./wkb install
```

This installs the binary without requiring Go. Archives include `SHA256SUMS`
as a separate release asset so you can verify the download. macOS binaries
include native Keychain support. They are not signed or notarized; if macOS
blocks a download, verify its origin and allow it through System Settings.

To install from a checkout instead:

```sh
go run ./cmd/workbench install
```

This installs `wkb` in `~/.local/bin`. Keep that directory on your PATH. To update
an existing installation, add `--replace`; choose another bin with `--dir DIR`.
The installer preserves existing symlinks and does not touch your vault.

Requires Go 1.26.9+. macOS uses the native Keychain and needs Apple's Command Line
Tools with CGO. Linux uses a passphrase automatically. A macOS build without CGO
can use `wkb init --password`.

Create your vault once, then open the local interface:

```sh
wkb init
wkb ui
```

On Linux, agents run commands without a terminal and cannot type the
passphrase. Unlock the vault in your own terminal before handing work over:

```sh
wkb unlock --ttl 8h
wkb lock
```

Until the ttl expires or you run `lock`, commands without a terminal open the
vault from the kernel keyring. Unlocking again asks for the passphrase.

## Give your agent a key, without saving it

Run this in your own terminal:

```sh
wkb seal
```

Enter the value at the hidden prompt. It stays out of shell history. You get
only encrypted text, addressed to your own Workbench. Paste that text into the
agent conversation and ask it to use the key. No entry is added to your vault.

With the skill installed, the agent knows how to pass the ciphertext to `use`
on stdin, or through an encrypted file:

```sh
wkb use packet.wb --env API_TOKEN -- your-command
```

`your-command` means a program that reads `API_TOKEN` from its environment.
The key is decrypted during execution; `use` does not import it. If you later
want to keep it, explicitly ask the agent to save it, or run:

```sh
wkb import packet.wb --as service.token
```

## Save and use a key

```sh
wkb set service.token
wkb exec service.token=API_TOKEN -- your-command
wkb copy service.token
```

`set` prompts without echo. `exec` hands the value directly to the child process.
`copy` puts it in your system clipboard without printing it.

Paths use dots to organize objects: `cloudflare.api_token`, `bkt.api_token`,
`mysql.dev.password`. The initial `.` is optional when typing a path. New UI
paths normalize to lowercase snake_case or kebab-case; existing paths are kept.

## Find and manage values

```sh
wkb ui
wkb list
wkb get service.token
```

The UI groups paths by object, filters by object or dotted path, and paginates
25 values at a time. Secrets start masked. Revealing asks for confirmation and
hides the value again after 10 seconds. Copy goes directly to the device's
clipboard, without returning the value to browser JavaScript.

New entries are secret by default. For ordinary configuration such as a public
hostname or port, choose **Public** in the UI or use:

```sh
wkb classify service.host --public
```

Click a Secret/Public badge to change classification without retyping the value.
**Public values remain encrypted on disk.** The label only allows commands like
`get` to display them. API keys, passwords and tokens should stay secret.

## Share with someone else

The recipient sends you the public key printed by:

```sh
wkb identity
```

Confirm the `age1...` text belongs to them, then send a new value:

```sh
wkb seal --to age1... --out packet.wb
```

Or send a value already stored:

```sh
wkb share service.token --to age1... --out packet.wb
```

They can use it temporarily with `use`, or save it with `import` under their own
path. To receive something, give the sender **your** public key; they encrypt
for you. A public key is text, not a vault path. Named contacts are not yet
available. Shared packets do not authenticate their sender.

## Teach your agent

```sh
wkb skill install --agent codex
wkb skill install --agent claude-code
```

Installs the bundled [Agent Skill](skills/workbench/SKILL.md) offline in the
current project. Add `--global` for your user account. Also supports OpenCode,
Pi and Cursor, or an explicit skills root with `--dir`. Existing different skills
require `--replace`; symlinks are preserved. Reload your agent after installing.
The agent also needs `wkb` on its PATH.

Compatible with [Vercel Skills](https://github.com/vercel-labs/skills). You can
alternatively install directly from GitHub:

```sh
npx skills add pedroloch/workbench --skill workbench --agent codex
```

## Bring your existing configuration

```sh
wkb migrate /absolute/path/to/config.yaml
```

Imports a private YAML file atomically. Values default to secret; repeat
`--public PATH` to select ordinary configuration. **The original YAML remains
unchanged and still contains plaintext.** Review its consumers and backups
before retiring it. Workbench does not migrate or delete old files implicitly.

## Back up your vault

```sh
wkb backup --out recovery.wb
wkb --dir "$HOME/.config/workbench-restored" restore recovery.wb
```

The backup includes both data and the private receiving identity, encrypted with
a separate passphrase. Keep the passphrase separately. Restore creates a new
vault and preserves your receiving key. `vault.age` alone cannot recover a lost
Keychain identity.

## Security, plainly

- Data, paths and shared packets use authenticated age encryption. Private keys
  use macOS Keychain or passphrase encryption, without a plaintext fallback.
- Values become plaintext during use. A child process, compromised account,
  browser extension or clipboard history can expose them. Workbench is not a
  sandbox and does not guarantee memory zeroization.
- The UI runs on authenticated HTTP at `127.0.0.1`, with Host, Origin and CSRF
  checks. It does not expose a remote port or use TLS.
- Packets can be reused. They do not prove the sender's identity, expire, revoke
  credentials or enforce one-time use. Rotate a key at its service to revoke it.

See [SECURITY.md](SECURITY.md) for the complete boundaries. This initial version
has not had an independent security audit. Report vulnerabilities through
[private security reporting](https://github.com/pedroloch/workbench/security/advisories/new).

<details>
<summary>Advanced options</summary>

- `wkb help` lists commands. Global flags go before the command: `--dir DIR` and
  `--password-file FILE`. Passphrase files must be private regular files.
- `set --stdin` and `seal --stdin` read an exact value, including trailing
  newlines. `--json` accepts a scalar. Values are never accepted in argv.
- `use -` consumes stdin for its packet; choose an encrypted file if the child
  also needs stdin. Programs must read their injected variable internally.
  Packets may be complete age armor, raw age binary, or Base64 without
  BEGIN/END delimiters, on one line or wrapped across lines.
- `import` accepts `--as PATH`, `--yes` and `--replace`. These flags confirm
  operations the user has already authorized.
- `require PATH...` checks presence; `unset PATH` removes an entry or subtree.
  `reveal PATH` requires an interactive terminal and explicit confirmation;
  it currently does not require sudo.
- `ui --no-open` prints a private launcher path. Sessions stop after 15 minutes
  without authenticated API activity; `--timeout` accepts `1m` to `1h`. Close the
  tab when done. After a crash, remove stale `.ui-*.html` files from the vault.
- `backup` and `restore` accept `--backup-password-file FILE`.
- `doctor` checks vault authentication and permissions; `path` shows its file.
- The vault lives in `~/.config/workbench` by default: encrypted `vault.age`,
  public `meta.json`, and encrypted `identity.age` in passphrase mode. Files are
  `0600`, the directory is `0700`, and its parent must not be other-writable.
- Linux clipboard integration needs `wl-copy`, `xclip` or `xsel`; macOS uses
  `pbcopy`. Output files never overwrite existing files.

</details>

## Development

```sh
go test -race ./...
go vet ./...
node --check internal/ui/web/app.js
go build -o /tmp/wkb ./cmd/workbench
python3 scripts/smoke.py /tmp/wkb
go run golang.org/x/vuln/cmd/govulncheck@v1.1.4 ./...
```

Tests use synthetic credentials and isolated vaults. Native Keychain testing is
opt-in and creates/deletes only a randomized synthetic entry:

```sh
WORKBENCH_TEST_KEYCHAIN=1 go test ./internal/keyring -run TestNativeKeychainRoundTrip
WORKBENCH_TEST_KERNEL_KEYRING=1 go test ./internal/keyring -run TestKernelSession
```

## Contribute

Found a bug or have an idea? [Open an issue](https://github.com/pedroloch/workbench/issues/new/choose)
with a synthetic example, or send a focused PR. Read [CONTRIBUTING.md](CONTRIBUTING.md)
for setup, tests and review policy. Security reports belong in private reporting.

Licensed under [MIT](LICENSE).

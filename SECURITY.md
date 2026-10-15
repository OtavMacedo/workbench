# Security

Workbench protects local configuration against exposure from stolen copies of
its encrypted files and against accidental disclosure through normal diagnostic
commands. It supports confidential offline delivery to a known age public key.

## Boundaries

- Secret status is explicit. Names, prefixes and heuristic detection do not
  determine access. All newly created entries default to secret.
- The vault and share payloads use the maintained `filippo.io/age` library and
  its authenticated format. Passphrase-protected identities and recovery backups
  use age's scrypt recipient. Password decoding caps the scrypt work factor.
- The macOS backend uses native Security framework bindings from
  `github.com/keybase/go-keychain`. It stores a device-local identity and does
  not invoke the `security` CLI with secret arguments. Keychain policy is
  enforced by the operating system; Workbench does not promise biometric
  verification on every access.
- File reads reject final symlinks and non-regular files. Vault files and the
  directory must be owner-only and belong to the current user. The immediate
  parent must not be writable by other users. Directory-relative operations,
  private temporary files, atomic replacement and file locking reduce
  substitution and lost-update risks.
- The web server binds only to IPv4 loopback. Its session and CSRF tokens are
  random, and API access requires exact Host/Origin checks where applicable,
  a session cookie and a CSRF header. Static assets contain no vault data.

## Threats this version does not prevent

A compromised account, root, a debugger, malware or an authorized process can
access values during use. In particular, `exec` gives the child process and its
descendants an environment variable containing the secret. The child can log or
transmit it. Workbench is not a sandbox for coding agents or commands.

`seal` encrypts supplied input without persisting it. `use` decrypts a packet
in memory and hands its scalar to a child just like `exec`, without importing
or modifying the vault. Ciphertext may remain in the agent conversation or in
an explicitly created packet file. Temporary use is not one-time use: an
authorized holder of the private identity can decrypt the same packet again.

Go garbage collection does not provide a guarantee of zeroizing all plaintext
copies. Private identities and values are held in process memory while commands
run. The UI holds its unlocked identity until shutdown. Browser forms, explicit
reveals, clipboard history, extensions and screen capture can expose values.

A private passphrase file enables non-interactive use but is itself plaintext
key material. Protect it separately from the vault and avoid committing it.

On Linux, `unlock` keeps the private identity in the kernel user keyring until
its ttl expires or `lock` runs. Meanwhile any process of the same user,
including an agent, can open the vault and read that identity without the
passphrase, as with an unlocked macOS Keychain. The default Docker seccomp
profile and sandboxes with their own user namespace cannot reach this keyring.

Vault authentication detects modification without a key. It does not provide a
trusted monotonic version counter, prevent rollback to an older valid vault, or
protect availability from someone who can delete its files. Permission checks
do not audit ACLs or every ancestor of the vault directory. Use a trusted local
filesystem, not a directory managed by an untrusted synchronization service.

Shares protect confidentiality and integrity. They do not authenticate their
sender, impose reliable offline expiration or one-time use, or revoke a value
already delivered. Verify recipients' public keys through a trusted channel.
Never treat an imported field path or other metadata as a command to execute.

Recovery backups include the private receiving identity. A decrypted backup
can open compatible old shares and encrypted vault files. There is no identity
rotation command in this initial version. Changing an API token with `set`
does not revoke the previous token at its issuer or invalidate older backups.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/pedroloch/workbench/security/advisories/new).
Do not disclose a suspected vulnerability in a public issue. Include the affected
version, workflow, impact and a reproducible example with synthetic values.
Never include real secrets, private identities, passphrases or decrypted backups.

Security fixes target the latest published release. Update older versions before
reporting a problem unless it concerns a regression. This is an early project
without an independent security audit or a guaranteed response-time SLA.

Release archives include SHA-256 checksums. These detect download corruption;
they are not a publisher signature. macOS binaries are not signed or notarized.

## References

- [age format](https://age-encryption.org/v1)
- [age Go library](https://pkg.go.dev/filippo.io/age)
- [Native macOS Keychain bindings](https://github.com/keybase/go-keychain)
- [OWASP cryptographic storage guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html)
- [OWASP CSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html)

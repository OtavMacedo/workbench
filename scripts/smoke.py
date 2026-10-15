#!/usr/bin/env python3
"""Exercise the real CLI using isolated vaults and synthetic values only."""

import base64
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def main():
    binary = Path(sys.argv[1]).resolve(strict=True)
    with tempfile.TemporaryDirectory(prefix="workbench-smoke-") as directory:
        root = Path(directory)
        root.chmod(0o700)
        password = root / "passphrase"
        password.write_text("synthetic-smoke-passphrase-only")
        password.chmod(0o600)
        env = dict(os.environ)

        def run(vault, *args, data=None, code=0):
            result = subprocess.run(
                [str(binary), "--dir", str(root / vault), "--password-file", str(password), *args],
                input=data, capture_output=True, env=env, timeout=45,
            )
            assert result.returncode == code, (args, result.returncode, result.stderr.decode())
            assert b"synthetic-secret" not in result.stdout + result.stderr, "plaintext disclosure"
            return result.stdout

        run("sender", "init", "--password")
        run("recipient", "init", "--password")
        run("sender", "set", "service.token", "--stdin", data=b"synthetic-secret\n")
        run("sender", "set", "service.host", "--stdin", "--public", data=b"api.example.com")
        assert run("sender", "get", "service.token").strip() == b"***"
        assert run("sender", "get", "service.host").strip() == b"api.example.com"
        child = [sys.executable, "-c", "import os,sys; sys.exit(17 if os.environ['SMOKE_TOKEN']=='synthetic-secret\\n' else 1)"]
        run("sender", "exec", "service.token=SMOKE_TOKEN", "--", *child, code=17)

        def snapshot():
            return {p.name: hashlib.sha256(p.read_bytes()).digest() for p in (root / "sender").iterdir()}

        before = snapshot()
        sealed = run("sender", "seal", "--stdin", data=b"synthetic-secret\n")
        assert snapshot() == before, "seal persisted a value"
        body = b"".join(sealed.splitlines()[1:-1])
        assert base64.b64decode(body).startswith(b"age-encryption.org/v1\n")
        run("sender", "use", "-", "--env", "SMOKE_TOKEN", "--", *child, data=body, code=17)
        assert snapshot() == before, "use modified the vault"
        run("recipient", "use", "-", "--env", "SMOKE_TOKEN", "--", *child, data=body, code=1)
        corrupt = bytearray(base64.b64decode(body))
        corrupt[-1] ^= 1
        run("sender", "use", "-", "--env", "SMOKE_TOKEN", "--", *child, data=base64.b64encode(corrupt), code=1)
        run("recipient", "import", "-", "--yes", data=sealed, code=1)
        identity = run("recipient", "identity").decode().strip()
        shared = run("sender", "share", "service.token", "--to", identity)
        run("recipient", "import", "-", "--as", "received.token", "--yes", data=shared)
        run("recipient", "exec", "received.token=SMOKE_TOKEN", "--", *child, code=17)

        recovery = root / "recovery.wb"
        run("sender", "backup", "--out", str(recovery), "--backup-password-file", str(password))
        run("restored", "restore", str(recovery), "--password", "--backup-password-file", str(password))
        assert run("restored", "identity") == run("sender", "identity"), "recovery lost identity"
        run("restored", "exec", "service.token=SMOKE_TOKEN", "--", *child, code=17)
        run("restored", "use", "-", "--env", "SMOKE_TOKEN", "--", *child, data=body, code=17)
        run("sender", "install", "--dir", str(root / "bin"))
        installed = root / "bin" / "wkb"
        assert installed.read_bytes() == binary.read_bytes(), "installer changed the binary"
        run("sender", "skill", "install", "--dir", str(root / "skills"))
        assert (root / "skills" / "workbench" / "SKILL.md").is_file()
        run("sender", "doctor")

        if sys.platform.startswith("linux"):
            def without_terminal(*args, stdin=subprocess.DEVNULL):
                return subprocess.run([str(binary), "--dir", str(root / "sender"), *args],
                                      stdin=stdin, capture_output=True, env=env, timeout=45)

            agent = ["exec", "service.token=SMOKE_TOKEN", "--", *child]
            locked = without_terminal(*agent)
            assert locked.returncode == 1 and b"wkb unlock" in locked.stderr, "locked vault opened"
            primary, secondary = os.openpty()
            try:
                os.write(primary, b"synthetic-smoke-passphrase-only\n")
                unlock = without_terminal("unlock", "--ttl", "1m", stdin=secondary)
            finally:
                os.close(secondary)
                os.close(primary)
            assert unlock.returncode == 0, unlock.stderr.decode()
            assert without_terminal(*agent).returncode == 17, "unlock did not reach another process"
            run("sender", "lock")
            assert without_terminal(*agent).returncode == 1, "lock kept the vault open"
    print("CLI smoke test passed: isolated vaults, transient use, sharing, recovery and installation.")


if __name__ == "__main__":
    main()

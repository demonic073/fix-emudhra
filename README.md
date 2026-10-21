# fix-emudhra.sh

Removes trust in the compromised eMudhra intermediate CA certificates.

**Supported systems:** Ubuntu/Debian · RHEL/CentOS/Rocky/Alma/Fedora · Arch Linux · **macOS**

```
sudo ./fix-emudhra.sh --check | --fix | --revert  --host ubuntu|redhat|arch|macos
```

Advisory: https://emudhra.we-have-a-problem.com/

## What the problem is

On 20 October 2026 it was announced that the private keys of eight eMudhra
intermediate CA certificates can be recovered from the certificates themselves.
Anyone holding those keys can issue a certificate for **any** website.

Browsers (Firefox, Chrome, Safari, Edge) and up-to-date Apple and Microsoft systems already
block them. Many other programs don't: `curl`, `wget`, Python, PHP,
package managers, scripts and other tools that use the operating system's
certificate store. A server with an old `ca-certificates` package will still
accept certificates made with the leaked keys.

The intermediates chain to two roots:

| Root | Path |
|---|---|
| `emSign ECC Root CA - G3` | eMudhra's own root |
| `Comodo AAA Services root` (CN `AAA Certificate Services`) | via a Sectigo cross-sign |

## What the script does

1. **Tests** whether the machine trusts the compromised chains, by connecting
   to 12 test hosts (one per intermediate, for each root). If every connection
   is rejected, the machine is safe and the script stops.
2. **Upgrades** the `ca-certificates` package where that is possible, then tests again.
3. If the machine is still vulnerable, it **distrusts the two roots** in the
   system trust store, following the advisory's workarounds, and tests a final time.

It always takes a backup before changing anything, and `--revert` undoes the change.

## Usage

An action flag is required. Running with no flags only prints the help.

```bash
./fix-emudhra.sh --help                     # explain all flags
./fix-emudhra.sh --check                    # test only, changes nothing, no root needed

sudo ./fix-emudhra.sh --fix --host ubuntu
sudo ./fix-emudhra.sh --fix --host redhat
sudo ./fix-emudhra.sh --fix --host arch
sudo ./fix-emudhra.sh --fix --host macos

sudo ./fix-emudhra.sh --revert --host ubuntu    # undo the workaround
```

### Flags

| Flag | Meaning |
|---|---|
| `--check` | Test only. Exit code `0` = safe, `1` = vulnerable. |
| `--fix` | Upgrade, then apply the workaround if still vulnerable. Needs `--host`. |
| `--revert` | Remove the workaround. Needs `--host`. |
| `--host TYPE` | The kind of machine. Must match the real OS, or the script refuses to run. |
| `-h`, `--help` | Show help. |

### `--host` values

| Value | Systems | Also accepted |
|---|---|---|
| `ubuntu` | Ubuntu, Debian | `debian` |
| `redhat` | RHEL, CentOS, Rocky, Alma, Fedora | `rhel`, `centos`, `rocky`, `alma`, `fedora` |
| `arch` | Arch Linux | `archlinux` |
| `macos` | macOS | `mac`, `osx`, `darwin` |

Only one action is allowed at a time. A wrong or unknown `--host` stops the script
with an error before anything is changed.

## What gets changed on each system

### Ubuntu / Debian
- Upgrade: `apt-get install --only-upgrade ca-certificates`. Patched versions are
  `20260816ubuntu0.*` (Ubuntu) and `20250419~deb12u2` / `+deb13u1` (Debian).
- Workaround: backs up `/etc/ca-certificates.conf` to `.bak-<timestamp>`, puts `!`
  in front of the two roots, runs `update-ca-certificates --fresh`.
- Revert: removes the `!` and rebuilds.

### Red Hat family (RHEL / CentOS / Rocky / Alma / Fedora)
- Upgrade: `dnf` (or `yum`) `upgrade ca-certificates`. CentOS Stream 8 is end-of-life
  and gets no update, so the workaround is applied there.
- Workaround: backs up `/etc/pki/ca-trust/extracted` to `/root/ca-trust-extracted.bak-<timestamp>`,
  writes the two roots to `/etc/pki/ca-trust/source/blocklist/`, runs `update-ca-trust`.
- Revert: deletes the two blocklist files and runs `update-ca-trust`.

### Arch Linux
- Upgrade: **not done automatically.** Upgrading one package with `pacman -Sy` is a
  partial upgrade, which Arch doesn't support. The script checks whether
  `ca-certificates-mozilla` is `3.131.1-1` or newer and, if not, tells you to run
  `pacman -Syu`.
- Workaround: backs up `/etc/ca-certificates/extracted` to `/root/`, writes the two roots to
  `/etc/ca-certificates/trust-source/blocklist/`, runs `update-ca-trust`.
- Revert: deletes the two blocklist files and runs `update-ca-trust`.

### macOS
- macOS itself (Safari, Keychain, most apps) already blocks these on an updated Mac.
  The gap is `/usr/bin/curl` and other tools that read `/etc/ssl/cert.pem`, which Apple
  hasn't updated. The check uses `/usr/bin/curl` for this reason.
- Upgrade: nothing to upgrade. If Homebrew is installed, run
  `brew upgrade ca-certificates curl openssl` as your normal user (not root).
- Workaround: keeps a pristine copy at `/etc/ssl/cert.pem.orig-emudhra` (first run only),
  a backup at `/etc/ssl/cert.pem.bak-<timestamp>`, then removes the two roots from
  `/etc/ssl/cert.pem`. It refuses to write an empty file.
- Revert: restores `/etc/ssl/cert.pem` from the pristine copy.

## Reading the output

```
  dv-g3b       rejected (good)
  dv-g3b-aaa   CONNECTED HTTP 200 (vulnerable)
```

`rejected` means the machine refused the compromised certificate, which is what you want.
`CONNECTED` means it trusted it. After `--fix`, every line should say `rejected`.

## Running it on several machines

```bash
scp fix-emudhra.sh user@host: && ssh -t user@host 'sudo ./fix-emudhra.sh --fix --host ubuntu'
```

## Things to know

- **Side effect:** distrusting `Comodo AAA Services root` may break the occasional site
  whose Sectigo certificate still chains through that old root. Most current Sectigo
  chains go through USERTrust instead and aren't affected. Use `--revert` if something breaks.
- **Remove the workaround later:** once your OS ships a patched `ca-certificates`,
  run `--revert` and then `--check` to confirm the package update covers it.
- **Docker containers are not fixed.** Each image has its own CA store. Rebuild
  containers on updated base images.
- **Other bundled CA stores** (Python `certifi`, Node.js, Go, Java, etc.) have their own
  copies; see the advisory's table of patched versions.
- **Requirements:** `bash` (3.2+ works, so the stock macOS shell is fine), `curl`, root for `--fix`/`--revert`.

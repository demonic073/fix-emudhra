#!/usr/bin/env bash
# fix-emudhra.sh - remove trust in the compromised eMudhra intermediate CAs
# (https://emudhra.we-have-a-problem.com/) on Ubuntu/Debian, RHEL-family, Arch Linux and macOS hosts.
# Run ./fix-emudhra.sh --help for usage.

set -u

HOSTS=(dv-g3b dv-g3c ov-g3b ov-g3c ev-g3b ev-g3c
       dv-g3b-aaa dv-g3c-aaa ov-g3b-aaa ov-g3c-aaa ev-g3b-aaa ev-g3c-aaa)
STAMP=$(date +%Y%m%d-%H%M%S)

log()  { printf '[*] %s\n' "$*"; }
warn() { printf '[!] %s\n' "$*" >&2; }
die()  { printf '[x] %s\n' "$*" >&2; exit 1; }

# Returns 0 if NOT vulnerable (every host rejected), 1 if any host connected.
check() {
    local curl=curl h code bad=0
    [ "$(uname -s)" = Darwin ] && curl=/usr/bin/curl
    command -v "$curl" >/dev/null || die "curl is required for the check"
    for h in "${HOSTS[@]}"; do
        code=$("$curl" -s -o /dev/null -m 10 -w '%{http_code}' "https://$h-emudhra.we-have-a-problem.com/" 2>/dev/null)
        if [ "$code" = "000" ] || [ -z "$code" ]; then
            printf '  %-12s rejected (good)\n' "$h"
        else
            printf '  %-12s CONNECTED HTTP %s (vulnerable)\n' "$h" "$code"
            bad=1
        fi
    done
    if [ $bad -eq 0 ]; then log "Not vulnerable: all compromised chains rejected."; return 0; fi
    warn "Vulnerable: this host still trusts compromised intermediates."
    return 1
}

detect_os() {
    if [ "$(uname -s)" = Darwin ]; then
        OS=macos
    elif [ -f /etc/debian_version ] && [ -f /etc/ca-certificates.conf ]; then
        OS=ubuntu
    elif [ -f /etc/arch-release ]; then
        OS=arch
    elif command -v update-ca-trust >/dev/null && command -v trust >/dev/null; then
        OS=redhat
    else
        die "Unsupported OS (need Ubuntu/Debian, RHEL/CentOS/Rocky/Alma/Fedora, Arch or macOS)"
    fi
}

# ---------- Debian / Ubuntu ----------
ubuntu_update() {
    log "Updating ca-certificates via apt..."
    apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade ca-certificates \
        || warn "apt upgrade failed; continuing with workaround"
}

ubuntu_blocklist() {
    local conf=/etc/ca-certificates.conf
    cp -a "$conf" "$conf.bak-$STAMP"
    log "Backed up $conf to $conf.bak-$STAMP"
    sed -i -e 's|^mozilla/emSign_ECC_Root_CA_-_G3.crt|!&|' \
           -e 's|^mozilla/Comodo_AAA_Services_root.crt|!&|' "$conf"
    update-ca-certificates --fresh >/dev/null
    log "Distrusted roots in $conf:"
    grep -E '^!mozilla/(emSign_ECC_Root_CA_-_G3|Comodo_AAA_Services_root)\.crt' "$conf" | sed 's/^/    /'
}

ubuntu_revert() {
    local conf=/etc/ca-certificates.conf
    cp -a "$conf" "$conf.bak-$STAMP"
    sed -i -e 's|^!\(mozilla/emSign_ECC_Root_CA_-_G3.crt\)|\1|' \
           -e 's|^!\(mozilla/Comodo_AAA_Services_root.crt\)|\1|' "$conf"
    update-ca-certificates --fresh >/dev/null
    log "Workaround reverted."
}

# ---------- RHEL / CentOS / Rocky / Alma / Fedora ----------
rh_blockdir() {
    local d=/etc/pki/ca-trust/source/blocklist
    [ -d "$d" ] || d=/etc/pki/ca-trust/source/blacklist
    echo "$d"
}

redhat_update() {
    local pm=dnf; command -v dnf >/dev/null || pm=yum
    log "Updating ca-certificates via $pm..."
    $pm -y -q upgrade ca-certificates || warn "$pm upgrade failed (EOL repo?); continuing with workaround"
}

# Shared by redhat and arch: both use p11-kit's trust store.
p11_blocklist() {
    local d=$1 extracted=$2 bak
    bak="/root/ca-trust-extracted.bak-$STAMP"
    mkdir -p "$d"
    cp -a "$extracted" "$bak"
    log "Backed up $extracted to $bak"
    trust extract --overwrite --format=pem-bundle \
        --filter='pkcs11:object=Comodo%20AAA%20Services%20root;type=cert' \
        "$d/Comodo_AAA_Services_root.pem" || warn "Comodo AAA Services root not found in store"
    trust extract --overwrite --format=pem-bundle \
        --filter='pkcs11:object=emSign%20ECC%20Root%20CA%20-%20G3;type=cert' \
        "$d/emSign_ECC_Root_CA_-_G3.pem" || warn "emSign ECC Root CA - G3 not found in store"
    update-ca-trust
    log "Blocklist files in $d:"
    ls -1 "$d"/Comodo_AAA_Services_root.pem "$d"/emSign_ECC_Root_CA_-_G3.pem 2>/dev/null | sed 's/^/    /'
}

p11_revert() {
    local d=$1
    rm -f "$d/Comodo_AAA_Services_root.pem" "$d/emSign_ECC_Root_CA_-_G3.pem"
    update-ca-trust
    log "Workaround reverted."
}

redhat_blocklist() { p11_blocklist "$(rh_blockdir)" /etc/pki/ca-trust/extracted; }
redhat_revert()    { p11_revert "$(rh_blockdir)"; }

# ---------- Arch Linux ----------
ARCH_BLOCKDIR=/etc/ca-certificates/trust-source/blocklist
ARCH_FIXED=3.131.1-1

# No automatic upgrade: installing one package with pacman -Sy is a partial
# upgrade, which Arch does not support. Only report whether a full -Syu is needed.
arch_update() {
    local cur
    cur=$(pacman -Q ca-certificates-mozilla 2>/dev/null | awk '{print $2}')
    if [ -n "$cur" ] && [ "$(vercmp "$cur" "$ARCH_FIXED")" -ge 0 ]; then
        log "ca-certificates-mozilla $cur is already the patched version ($ARCH_FIXED or newer)"
    else
        warn "ca-certificates-mozilla ${cur:-not installed} is older than $ARCH_FIXED."
        warn "Run a full system upgrade (pacman -Syu) to get the real fix; applying workaround meanwhile."
    fi
}

arch_blocklist() { p11_blocklist "$ARCH_BLOCKDIR" /etc/ca-certificates/extracted; }
arch_revert()    { p11_revert "$ARCH_BLOCKDIR"; }

# ---------- macOS ----------
# macOS itself (Keychain, Safari, URLSession) already blocks these intermediates via
# OS updates. The built-in /usr/bin/curl and LibreSSL read /etc/ssl/cert.pem without
# checking revocation, and Apple has not updated that file, so strip the two roots from it.
MAC_PEM=/etc/ssl/cert.pem
MAC_ORIG=/etc/ssl/cert.pem.orig-emudhra

macos_update() {
    log "Nothing to auto-upgrade for /etc/ssl/cert.pem; keep macOS current via Software Update."
    command -v brew >/dev/null && \
        warn "Homebrew found: as your normal user, run 'brew upgrade ca-certificates curl openssl' too."
}

macos_blocklist() {
    local before after
    [ -f "$MAC_ORIG" ] || cp -p "$MAC_PEM" "$MAC_ORIG"
    cp -p "$MAC_PEM" "$MAC_PEM.bak-$STAMP"
    log "Backed up $MAC_PEM to $MAC_PEM.bak-$STAMP (pristine copy: $MAC_ORIG)"
    before=$(grep -c 'BEGIN CERTIFICATE' "$MAC_PEM")
    awk '/^(###|===) /{skip=0}
         /^=== .*\/CN=(AAA Certificate Services|emSign ECC Root CA - G3)$/{skip=1}
         !skip' "$MAC_PEM.bak-$STAMP" > "$MAC_PEM.tmp-$STAMP" || die "awk failed; $MAC_PEM unchanged"
    after=$(grep -c 'BEGIN CERTIFICATE' "$MAC_PEM.tmp-$STAMP")
    [ "$after" -gt 0 ] || { rm -f "$MAC_PEM.tmp-$STAMP"; die "Filtered bundle is empty; $MAC_PEM unchanged"; }
    cat "$MAC_PEM.tmp-$STAMP" > "$MAC_PEM" && rm -f "$MAC_PEM.tmp-$STAMP"
    log "Removed $((before - after)) certificate(s) from $MAC_PEM ($before -> $after)"
    [ $((before - after)) -gt 0 ] || warn "No matching roots found (already removed, or the file format changed)"
}

macos_revert() {
    [ -f "$MAC_ORIG" ] || die "No pristine copy at $MAC_ORIG; restore from a $MAC_PEM.bak-* file manually"
    cp -p "$MAC_ORIG" "$MAC_PEM"
    log "Restored $MAC_PEM from $MAC_ORIG. Workaround reverted."
}

usage() {
    cat <<USAGE
Usage: sudo $0 --check | --fix | --revert  --host ubuntu|redhat|arch|macos

Supported systems: Ubuntu/Debian, RHEL/CentOS/Rocky/Alma/Fedora, Arch Linux, macOS

Removes trust in the compromised eMudhra intermediate CAs
(https://emudhra.we-have-a-problem.com/). An action flag is required;
running with no flags prints this help and changes nothing.

Actions (pick one):
  --check           Test whether this host trusts the compromised chains.
                    Read-only, no root or --host needed.
                    Exit 0 = not vulnerable, 1 = vulnerable.
  --fix             Upgrade ca-certificates (ubuntu/redhat; on arch it only
                    tells you if pacman -Syu is needed, on macos there is
                    nothing to upgrade); if still vulnerable,
                    distrust the affected roots and re-test. Requires --host.
  --revert          Undo the distrust workaround. Requires --host.
  -h, --help        Show this help.

Options:
  --host TYPE       Which kind of host this is (must match the machine):
                      ubuntu  Ubuntu / Debian (also: debian)
                      redhat  RHEL / CentOS / Rocky / Alma / Fedora
                              (also: rhel, centos, rocky, alma, fedora)
                      arch    Arch Linux (also: archlinux)
                      macos   macOS (also: mac, osx, darwin)

Examples:
  $0 --check
  sudo $0 --fix --host ubuntu
  sudo $0 --fix --host redhat
  sudo $0 --fix --host arch
  sudo $0 --fix --host macos
  sudo $0 --revert --host redhat

What --fix changes:
  ubuntu  Backs up /etc/ca-certificates.conf, marks the two roots with '!',
          runs update-ca-certificates --fresh.
  redhat  Backs up /etc/pki/ca-trust/extracted to /root/, writes the two roots
          to /etc/pki/ca-trust/source/blocklist/, runs update-ca-trust.
  arch    Backs up /etc/ca-certificates/extracted to /root/, writes the two
          roots to /etc/ca-certificates/trust-source/blocklist/, runs update-ca-trust.
  macos   Backs up /etc/ssl/cert.pem, removes the two roots from it. Only affects
          /usr/bin/curl and other tools using that file; the system Keychain
          already blocks these intermediates. Check uses /usr/bin/curl.

Distrusted roots: "emSign ECC Root CA - G3" and "Comodo AAA Services root".
Some legacy Sectigo chains through the AAA root may stop validating.
Docker containers have their own CA stores and are not changed.
USAGE
}

# ---------- main ----------
ACTION=
HOST=
[ $# -eq 0 ] && { usage; exit 2; }
while [ $# -gt 0 ]; do
    case "$1" in
        --check|--fix|--revert)
            [ -n "$ACTION" ] && die "Only one action allowed (got $ACTION and $1)"
            ACTION=${1#--} ;;
        --host)
            [ $# -ge 2 ] || die "--host needs a value: ubuntu, redhat, arch or macos"
            HOST=$2; shift ;;
        --host=*) HOST=${1#--host=} ;;
        -h|--help) usage; exit 0 ;;
        *) die "Unknown option: $1 (see --help)" ;;
    esac
    shift
done

[ -n "$ACTION" ] || die "No action given: use --check, --fix or --revert (see --help)"

if [ "$ACTION" = check ]; then
    check; exit $?
fi

case "$(printf %s "$HOST" | tr "[:upper:]" "[:lower:]")" in
    ubuntu|debian) HOST=ubuntu ;;
    redhat|rhel|centos|rocky|alma|almalinux|fedora) HOST=redhat ;;
    arch|archlinux) HOST=arch ;;
    macos|mac|osx|macosx|darwin) HOST=macos ;;
    "") die "--$ACTION requires --host ubuntu, redhat, arch or macos" ;;
    *) die "Unknown --host '$HOST' (use ubuntu, redhat, arch or macos)" ;;
esac

[ "$(id -u)" -eq 0 ] || die "Run as root (sudo $0 ...)"
detect_os
[ "$OS" = "$HOST" ] || die "--host $HOST given, but this machine looks like $OS. Refusing to continue."
log "Host type: $HOST (supported: ubuntu, redhat, arch, macos)"

if [ "$ACTION" = revert ]; then
    "${HOST}_revert"; exit 0
fi

log "Initial check:"
if check; then exit 0; fi

"${HOST}_update"
log "Re-checking after package update:"
if check; then log "Package update fixed it; no workaround needed."; exit 0; fi

log "Still vulnerable; applying root blocklist workaround..."
"${HOST}_blocklist"
log "Final check:"
check

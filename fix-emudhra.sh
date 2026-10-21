#!/usr/bin/env bash
# fix-emudhra.sh - remove trust in the compromised eMudhra intermediate CAs
# (https://emudhra.we-have-a-problem.com/) on Ubuntu/Debian, RHEL-family, Arch Linux and macOS hosts,
# and in Docker containers.
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

# ---------- Docker containers ----------
# Each container has its own CA store. Everything goes through `docker cp`, so this also
# works on stopped and distroless containers (no shell or tools needed inside). The check
# is static: it looks for the two roots by SHA-256 fingerprint in every CA file the
# container's TLS libraries read, following symlinks inside the container.
DOCKER=${DOCKER:-docker}
FP_AAA=D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4
FP_EMSIGN=86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B
# Bundle files Go's crypto/x509 looks for (OpenSSL's default CAfile is one of them),
# the OpenSSL/Go hashed cert dirs, and RHEL's other extracted bundles.
CT_FILES="/etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem
          /etc/pki/tls/cacert.pem /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /etc/ssl/cert.pem"
CT_DIRS="/etc/ssl/certs /etc/pki/tls/certs /etc/pki/ca-trust/extracted/pem /etc/pki/ca-trust/extracted/openssl"
CT_BINARY="/etc/ssl/certs/java/cacerts /etc/pki/ca-trust/extracted/java/cacerts /etc/pki/java/cacerts
           /etc/pki/ca-trust/extracted/edk2/cacerts.bin"
CT_FETCH_MAX=67108864
TAB=$(printf '\t')
if [ "$(id -u)" -eq 0 ]; then
    CT_BACKUP=${FIX_EMUDHRA_BACKUP:-/var/backups/fix-emudhra}
else
    CT_BACKUP=${FIX_EMUDHRA_BACKUP:-${XDG_STATE_HOME:-$HOME/.local/state}/fix-emudhra}
fi

file_mode() { stat -c %a "$1" 2>/dev/null || stat -f %Lp "$1"; }

# tar -c with every member owned by root (docker cp keeps the uid/gid from the archive).
tar_root() {
    if tar --version 2>/dev/null | grep -q GNU; then
        tar --owner=0 --group=0 --numeric-owner "$@"
    else
        tar --uid 0 --gid 0 "$@"
    fi
}

# Extracts container path $2 into local dir $3. Refuses archives over CT_FETCH_MAX bytes.
ct_get() {
    "$DOCKER" cp "$1:$2" - 2>/dev/null | head -c "$CT_FETCH_MAX" > "$3.tar"
    [ -s "$3.tar" ] && [ $(($(wc -c < "$3.tar"))) -lt "$CT_FETCH_MAX" ] && tar -xf "$3.tar" -C "$3" 2>/dev/null
    local rc=$?
    rm -f "$3.tar"
    return $rc
}

# Prints "d", "f" or "l TARGET" for a container path, nothing if it is missing.
# docker cp resolves symlinks in all but the last component.
ct_stat() {
    local line
    line=$("$DOCKER" cp "$CT_REF:$1" - 2>/dev/null | tar -tvf - 2>/dev/null | head -n 1)
    case "$line" in
        l*' -> '*) printf 'l %s\n' "${line#* -> }" ;;
        d*) echo d ;;
        ?*) echo f ;;
    esac
}

# Prints the physical path of a container directory. Done by hand because docker cp
# cleans ".." textually, which is wrong after a symlinked directory.
ct_realdir() {
    local rest=$1 p= c st t hops=0
    t=$(awk -F'\t' -v k="$1" '$1 == k { print $2; exit }' "$CW/dirs")
    [ -n "$t" ] && { printf '%s\n' "$t"; return 0; }
    while [ -n "$rest" ] && [ "$rest" != / ]; do
        rest=${rest#/}; c=${rest%%/*}
        case "$rest" in */*) rest=/${rest#*/} ;; *) rest= ;; esac
        case "$c" in ''|.) continue ;; ..) p=${p%/*}; continue ;; esac
        st=$(ct_stat "$p/$c")
        case "$st" in
            d) p="$p/$c" ;;
            "l "*)
                hops=$((hops + 1)); [ $hops -le 40 ] || return 1
                t=${st#l }
                case "$t" in /*) p=; rest="$t$rest" ;; *) rest="/$t$rest" ;; esac ;;
            *) return 1 ;;
        esac
    done
    printf '%s\t%s\n' "$1" "${p:-/}" >> "$CW/dirs"
    printf '%s\n' "${p:-/}"
}

# Fetches a whole physical directory once and prints its local copy.
ct_dir() {
    local L
    L=$(awk -F'\t' -v k="$1" '$1 == k { print $2; exit }' "$CW/fetched")
    if [ -z "$L" ]; then
        L=$(mktemp -d "$CW/d.XXXXXX")
        ct_get "$CT_REF" "${1%/}/." "$L" || return 1
        printf '%s\t%s\n' "$1" "$L" >> "$CW/fetched"
    fi
    printf '%s\n' "$L"
}

# Prints the local copy of container path $1 (its directory part must be physical).
# With $2=1 the whole directory is fetched, which is faster when many entries are needed.
ct_local() {
    local d=${1%/*} L
    [ -n "$d" ] || d=/
    if [ "${2:-0}" = 1 ] || [ -n "$(awk -F'\t' -v k="$d" '$1 == k' "$CW/fetched")" ]; then
        L=$(ct_dir "$d") || return 1
    else
        L=$(mktemp -d "$CW/f.XXXXXX")
        ct_get "$CT_REF" "$1" "$L" || return 1
    fi
    printf '%s\n' "$L/${1##*/}"
}

# Follows symlinks inside the container. Prints "physical path<TAB>local copy" for a regular file.
ct_resolve() {
    local p=$1 d f t hops=0
    while [ $hops -lt 40 ]; do
        hops=$((hops + 1))
        d=$(ct_realdir "$(dirname "$p")") || return 1
        p="${d%/}/$(basename "$p")"
        f=$(ct_local "$p" "${2:-0}") || return 1
        if [ -L "$f" ]; then
            t=$(readlink "$f")
            case "$t" in /*) p=$t ;; *) p="$d/$t" ;; esac
        elif [ -f "$f" ]; then
            printf '%s\t%s\n' "$p" "$f"; return 0
        else
            return 1
        fi
    done
    return 1
}

# Copies PEM file $1 to $2 without the two roots and prints how many were removed.
# Handles both CERTIFICATE and TRUSTED CERTIFICATE blocks; comment lines in front of a
# removed block go with it. Removed roots are saved as $CW/root-<fingerprint>.pem.
# A TRUSTED CERTIFICATE that rejects TLS server auth is a distrust entry (what p11-kit
# writes for blocklisted certs) and is kept.
pem_filter() {
    local line blk= pre= fp n=0 inblk=0
    : > "$2"
    while IFS= read -r line || [ -n "$line" ]; do
        if [ $inblk = 1 ]; then
            blk="$blk$line
"
            case "$line" in
                -----END*)
                    inblk=0
                    fp=$(printf '%s' "$blk" | openssl x509 -noout -fingerprint -sha256 2>/dev/null)
                    fp=${fp#*=}; fp=${fp//:/}
                    if { [ "$fp" = "$FP_AAA" ] || [ "$fp" = "$FP_EMSIGN" ]; } &&
                       ! printf '%s' "$blk" | openssl x509 -noout -text 2>/dev/null |
                         grep -A1 '^ *Rejected Uses:' | grep -q 'TLS Web Server Authentication'; then
                        n=$((n + 1))
                        [ -s "$CW/root-$fp.pem" ] || printf '%s' "$blk" | openssl x509 > "$CW/root-$fp.pem" 2>/dev/null
                    else
                        printf '%s%s' "$pre" "$blk" >> "$2"
                    fi
                    pre= blk= ;;
            esac
        else
            case "$line" in
                -----BEGIN*CERTIFICATE-----) inblk=1; blk="$line
" ;;
                *) pre="$pre$line
" ;;
            esac
        fi
    done < "$1"
    printf '%s%s' "$pre" "$blk" >> "$2"
    echo $n
}

ct_on_mount() {
    local m
    while IFS= read -r m; do
        [ -n "$m" ] && [ "$m" != / ] || continue
        case "$1/" in "${m%/}"/*) return 0 ;; esac
    done < "$CW/mounts"
    return 1
}

# Sets CT_REF/CT_ID/CT_NAME/CT_IMAGE/CT_RO and a fresh work dir CW for container $1.
ct_init() {
    local info
    info=$("$DOCKER" inspect --type container \
        -f '{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.HostConfig.ReadonlyRootfs}}' "$1" 2>/dev/null) \
        || { warn "$1: no such container"; return 1; }
    CT_ID=${info%%|*}; info=${info#*|}
    CT_NAME=${info%%|*}; CT_NAME=${CT_NAME#/}; info=${info#*|}
    CT_IMAGE=${info%%|*}; CT_RO=${info#*|}
    CT_REF=$CT_ID
    CW=$(mktemp -d "$CT_W/c.XXXXXX")
    : > "$CW/dirs"; : > "$CW/fetched"
    "$DOCKER" inspect --type container -f '{{range .Mounts}}{{println .Destination}}{{end}}' "$CT_ID" \
        > "$CW/mounts" 2>/dev/null
}

# Scans the container. Writes "path<TAB>local<TAB>filtered<TAB>count" for each file holding
# a distrusted root to $CW/bad and prints a report. Returns 0 clean, 1 vulnerable, 2 no CA store.
ct_scan() {
    local p d L e real loc n nfiles=0 vuln=0
    {
        for p in $CT_FILES; do ct_resolve "$p" 0; done
        for p in $CT_DIRS; do
            d=$(ct_realdir "$p") && L=$(ct_dir "$d") || continue
            for e in "$L"/* "$L"/.[!.]*; do
                [ -L "$e" ] || [ -f "$e" ] || continue
                ct_resolve "${d%/}/${e##*/}" 1
            done
        done
    } | sort -u -t "$TAB" -k1,1 > "$CW/files"
    : > "$CW/bad"
    log "Container $CT_NAME ($CT_IMAGE, ${CT_ID:0:12}):"
    while IFS="$TAB" read -r real loc; do
        nfiles=$((nfiles + 1))
        n=$(pem_filter "$loc" "$CW/out.$nfiles")
        [ "$n" -gt 0 ] || continue
        vuln=1
        printf '%s\t%s\t%s\t%s\n' "$real" "$loc" "$CW/out.$nfiles" "$n" >> "$CW/bad"
        if ct_on_mount "$real"; then
            printf '    %-60s %s distrusted root(s), on a mount\n' "$real" "$n"
        else
            printf '    %-60s %s distrusted root(s)\n' "$real" "$n"
        fi
    done < "$CW/files"
    for p in $CT_BINARY; do
        ct_resolve "$p" 0 >/dev/null && printf '    note: %s is a binary store; not checked or changed\n' "$p"
    done
    if [ $nfiles -eq 0 ]; then
        log "$CT_NAME: no system CA store found; nothing to do"; return 2
    elif [ $vuln -eq 0 ]; then
        log "$CT_NAME: not vulnerable ($nfiles CA files checked)"; return 0
    fi
    warn "$CT_NAME: vulnerable (trusts the compromised roots)"
    return 1
}

# Uploads local file $1 to container path $2 as root-owned with mode $3.
ct_put() {
    local s
    s=$(mktemp -d "$CW/p.XXXXXX")
    cat "$1" > "$s/${2##*/}" && chmod "$3" "$s/${2##*/}" &&
        tar_root -C "$s" -cf - "${2##*/}" | "$DOCKER" cp - "$CT_REF:${2%/*}/"
}

# Saves the container's current copy of $1 into the backup dir and records how to restore it.
ct_backup() {
    CT_NBAK=$((CT_NBAK + 1))
    "$DOCKER" cp "$CT_REF:$1" - > "$CT_BAK/$CT_NBAK.tar" 2>/dev/null || return 1
    printf 'restore\t%s.tar\t%s\n' "$CT_NBAK" "${1%/*}" >> "$CT_BAK/manifest"
}

ct_fix() {
    local real loc filt n mode src blk fp name rc=0
    ct_scan; [ $? -eq 1 ] || return 0
    if [ "$CT_RO" = true ]; then
        warn "$CT_NAME: read-only root filesystem; skipped. Rebuild it on an updated base image."
        return 1
    fi
    CT_BAK="$CT_BACKUP/$CT_ID/$STAMP"; CT_NBAK=0
    (umask 077; mkdir -p "$CT_BAK") || die "Cannot create backup dir $CT_BAK"
    : > "$CT_BAK/manifest"
    while IFS="$TAB" read -r real loc filt n; do
        if ct_on_mount "$real"; then
            warn "$CT_NAME: $real is on a bind mount or volume; fix it at the source"
            rc=1; continue
        fi
        mode=$(file_mode "$loc")
        if ct_backup "$real" && ct_put "$filt" "$real" "$mode"; then
            log "$CT_NAME: removed $n root(s) from $real"
        else
            warn "$CT_NAME: could not update $real"; rc=1
        fi
    done < "$CW/bad"
    # RHEL family: also blocklist the roots in the p11-kit source, or the next
    # update-ca-trust inside the container would put them back.
    if src=$(ct_realdir /etc/pki/ca-trust/source 2>/dev/null); then
        blk=$src/blocklist
        [ "$(ct_stat "$blk")" = d ] || blk=$src/blacklist
        if [ "$(ct_stat "$blk")" != d ]; then
            warn "$CT_NAME: no p11-kit blocklist dir; update-ca-trust would undo the fix"
        elif ct_on_mount "$blk"; then
            warn "$CT_NAME: $blk is on a mount; not adding blocklist files"
        else
            for fp in $FP_AAA $FP_EMSIGN; do
                [ -s "$CW/root-$fp.pem" ] || continue
                name=Comodo_AAA_Services_root.pem
                [ $fp = $FP_EMSIGN ] && name=emSign_ECC_Root_CA_-_G3.pem
                if [ -n "$(ct_stat "$blk/$name")" ]; then
                    ct_backup "$blk/$name" || { warn "$CT_NAME: cannot back up $blk/$name"; rc=1; continue; }
                else
                    printf 'empty\t-\t%s\n' "$blk/$name" >> "$CT_BAK/manifest"
                fi
                ct_put "$CW/root-$fp.pem" "$blk/$name" 644 && log "$CT_NAME: blocklisted in $blk/$name" \
                    || { warn "$CT_NAME: could not write $blk/$name"; rc=1; }
            done
        fi
    fi
    if [ ! -s "$CT_BAK/manifest" ]; then
        rm -rf "$CT_BAK"; rmdir "$CT_BACKUP/$CT_ID" 2>/dev/null
        return 1
    fi
    log "$CT_NAME: backup in $CT_BAK"
    log "$CT_NAME: re-checking:"
    ct_init "$CT_ID" && ct_scan || rc=1
    ct_restart_hint
    return $rc
}

ct_restart_hint() {
    [ "$("$DOCKER" inspect -f '{{.State.Running}}' "$CT_ID" 2>/dev/null)" = true ] && \
        log "$CT_NAME: restart it so running processes reload their CA store: $DOCKER restart $CT_NAME"
    return 0
}

ct_revert() {
    local dir="$CT_BACKUP/$CT_ID" s kind f dest rc=0
    log "Container $CT_NAME ($CT_IMAGE, ${CT_ID:0:12}):"
    # Newest first, so the oldest backup (the pre-fix state) is applied last.
    for s in $(ls -1 "$dir" 2>/dev/null | grep -v '^reverted-' | sort -r); do
        while IFS="$TAB" read -r kind f dest; do
            case "$kind" in
                restore) "$DOCKER" cp - "$CT_REF:$dest/" < "$dir/$s/$f" || { warn "$CT_NAME: restore into $dest failed"; rc=1; } ;;
                # docker cp cannot delete; an empty file in the blocklist dir is ignored.
                empty) : > "$CW/empty"; ct_put "$CW/empty" "$dest" 644 || { warn "$CT_NAME: cannot empty $dest"; rc=1; } ;;
            esac
        done < "$dir/$s/manifest"
        [ $rc -eq 0 ] || { warn "$CT_NAME: backup $s only partly restored; kept in $dir/$s"; return 1; }
        mv "$dir/$s" "$dir/reverted-$s"
        log "$CT_NAME: restored backup $s"
    done
    [ -n "${s:-}" ] || { log "$CT_NAME: no backups in $dir; nothing to revert"; return 0; }
    log "$CT_NAME: workaround reverted."
    ct_restart_hint
}

docker_main() {
    local c list rc=0
    command -v "$DOCKER" >/dev/null || die "$DOCKER not found"
    command -v openssl >/dev/null || die "openssl is required for --docker"
    "$DOCKER" info >/dev/null 2>&1 || die "Cannot talk to Docker (run as root or a docker group member)"
    if [ ${#CONTAINERS[@]} -gt 0 ]; then
        list="${CONTAINERS[*]}"
    else
        list=$("$DOCKER" ps -q)
        [ -n "$list" ] || { log "No running containers."; exit 0; }
    fi
    CT_W=$(mktemp -d "${TMPDIR:-/tmp}/fix-emudhra.XXXXXX") || die "mktemp failed"
    trap 'chmod -R u+w "$CT_W" 2>/dev/null; rm -rf "$CT_W"' EXIT
    for c in $list; do
        ct_init "$c" || { rc=1; continue; }
        case "$ACTION" in
            check)  ct_scan; [ $? -ne 1 ] || rc=1 ;;
            fix)    ct_fix || rc=1 ;;
            revert) ct_revert || rc=1 ;;
        esac
    done
    exit $rc
}

usage() {
    cat <<USAGE
Usage: sudo $0 --check | --fix | --revert  --host ubuntu|redhat|arch|macos
       sudo $0 --check | --fix | --revert  --docker [CONTAINER...]

Supported systems: Ubuntu/Debian, RHEL/CentOS/Rocky/Alma/Fedora, Arch Linux, macOS,
and Docker containers (any Linux image, including distroless)

Removes trust in the compromised eMudhra intermediate CAs
(https://emudhra.we-have-a-problem.com/). An action flag is required;
running with no flags prints this help and changes nothing.

Actions (pick one):
  --check           Test whether this host (or, with --docker, each container)
                    trusts the compromised chains.
                    Read-only, no root or --host needed.
                    Exit 0 = not vulnerable, 1 = vulnerable.
  --fix             Upgrade ca-certificates (ubuntu/redhat; on arch it only
                    tells you if pacman -Syu is needed, on macos there is
                    nothing to upgrade); if still vulnerable,
                    distrust the affected roots and re-test. Requires --host
                    or --docker.
  --revert          Undo the distrust workaround. Requires --host or --docker.
  -h, --help        Show this help.

Options:
  --host TYPE       Which kind of host this is (must match the machine):
                      ubuntu  Ubuntu / Debian (also: debian)
                      redhat  RHEL / CentOS / Rocky / Alma / Fedora
                              (also: rhel, centos, rocky, alma, fedora)
                      arch    Arch Linux (also: archlinux)
                      macos   macOS (also: mac, osx, darwin)
  --docker [CONTAINER...]
                    Work on Docker containers instead of this host. Names or
                    IDs; with none, all running containers. Cannot be combined
                    with --host. Needs Docker access (root or the docker group)
                    and openssl. --check here is a static scan for the two roots
                    in the container's CA files, not a network test.

Examples:
  $0 --check
  sudo $0 --fix --host ubuntu
  sudo $0 --fix --host redhat
  sudo $0 --fix --host arch
  sudo $0 --fix --host macos
  sudo $0 --revert --host redhat
  sudo $0 --check --docker
  sudo $0 --fix --docker web worker
  sudo $0 --revert --docker web

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
  docker  Using only 'docker cp' (works on stopped and distroless containers),
          removes the two roots from every PEM bundle and cert file the
          container's TLS libraries read, following symlinks. Single-root files
          are left empty, which breaks their hash links. On RHEL-family images
          it also writes the roots to the p11-kit blocklist so update-ca-trust
          keeps them out. Backups go to /var/backups/fix-emudhra/<container-id>/
          (~/.local/state/fix-emudhra/ when not root; override: FIX_EMUDHRA_BACKUP).
          Skips read-only containers and files on bind mounts or volumes.
          Lost when the container is recreated; restart it after the fix.
          Java keystores and app-bundled stores (certifi, Node) are not changed.

Distrusted roots: "emSign ECC Root CA - G3" and "Comodo AAA Services root".
Some legacy Sectigo chains through the AAA root may stop validating.
USAGE
}

# ---------- main ----------
ACTION=
HOST=
USE_DOCKER=
CONTAINERS=()
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
        --docker) USE_DOCKER=1 ;;
        -h|--help) usage; exit 0 ;;
        -*) die "Unknown option: $1 (see --help)" ;;
        *) CONTAINERS+=("$1") ;;
    esac
    shift
done

[ -n "$ACTION" ] || die "No action given: use --check, --fix or --revert (see --help)"

if [ -n "$USE_DOCKER" ]; then
    [ -z "$HOST" ] || die "--docker and --host cannot be combined"
    docker_main
fi
[ ${#CONTAINERS[@]} -eq 0 ] || die "Unexpected argument: ${CONTAINERS[0]} (container names need --docker)"

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

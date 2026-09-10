#!/usr/bin/env bash
# Everything about the .spk that can be checked without a Synology: the shape of
# the archive (part 1), then the real lifecycle scripts driving the real binary
# in a real Linux container (part 2). There is no NAS to install on, so this is
# the package's whole verification - hence the container rather than a stub.
set -euo pipefail
cd "$(dirname "$0")/.."

ok()     { printf 'ok   %s\n' "$*"; }
die()    { printf 'FAIL %s\n' "$*" >&2; exit 1; }
# a <what> <command...>: one line per passing check, or name the failure and stop.
a()      { local w=$1; shift; "$@" || die "$w"; ok "$w"; }
nogrep() { ! grep -q "$@"; }
# hex <file> <offset> <count>: raw bytes as one hex string, so a PNG's IHDR and
# an ELF's e_machine can be read without an image tool or file(1).
hex()    { od -An -tx1 -j"$2" -N"$3" -- "$1" | tr -d ' \n'; }
# CRLF makes DSM fail to exec a script with a confusing "no such file or
# directory", and this repo is developed on Windows. Byte comparison rather than
# a grep for \r: Git Bash's grep quietly turns a lone-CR pattern into an empty
# one, so the obvious spelling of this check silently checks nothing.
lfonly() {
    local f
    for f in "$@"; do tr -d '\r' <"$f" | cmp -s - "$f" || return 1; done
}
# sameport <port> <extracted spk dir>: the HTTP port is a literal in four files
# and nothing reconciles them - DSM's Open button reads INFO, the main-menu icon
# reads ui/config, the firewall reads scan2graph.sc, and only postinst decides
# what actually listens. A port change that misses one of them fails silently.
sameport() {
    [ -n "$1" ] &&
        grep -q "\"port\": $1," "$2/payload/ui/config" &&
        grep -q "dst.ports=\"$1/tcp\"" "$2/payload/conf/scan2graph.sc" &&
        grep -qx "S2G_HTTP_ADDR=:$1" "$2/scripts/postinst"
}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

structural() {
    local spk=$1 n d arch em sum binmode m s port
    n=$(basename "$spk")
    d=$work/$n
    mkdir -p "$d/payload"
    tar -xf "$spk" -C "$d"
    tar -tf "$spk" >"$d.members"
    tar -tvf "$spk" >"$d.membersv"
    # Split from the pipeline above: under set -o pipefail, an SPK with no
    # scripts/ members would make grep's exit 1 kill the whole script with no
    # FAIL line, rather than let the "lifecycle scripts are there" check below
    # name the failure.
    grep -E ' scripts/[^/]+$' "$d.membersv" >"$d.scripts" || true
    tar -xzf "$d/package.tgz" -C "$d/payload"
    arch=${n#scan2graph_}
    arch=${arch%%-dsm7_*}

    a "$n: outer tar is uncompressed" test "$(head -c 262 "$spk" | tail -c 5)" = ustar
    a "$n: INFO is the first member" test "$(head -1 "$d.members")" = INFO
    for m in INFO package.tgz scripts/ conf/privilege conf/resource PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG; do
        a "$n: member $m is present" grep -qxF "$m" "$d.members"
    done

    # 72x72 was the DSM 6 size; shipping it on DSM 7 is a documented install failure.
    a "$n: PACKAGE_ICON.PNG is 64x64" test "$(hex "$d/PACKAGE_ICON.PNG" 16 8)" = 0000004000000040
    a "$n: PACKAGE_ICON_256.PNG is 256x256" test "$(hex "$d/PACKAGE_ICON_256.PNG" 16 8)" = 0000010000000100

    a "$n: every INFO line is key=\"value\"" nogrep -Ev '^[a-z_]+=".*"$' "$d/INFO"
    a "$n: os_min_ver is 7.0-40000" grep -qx 'os_min_ver="7.0-40000"' "$d/INFO"
    # Package Center review checks for these by name.
    a "$n: INFO carries no deprecated field" \
        nogrep -E '^(thirdparty|startable|support_conf_folder|firmware)=' "$d/INFO"
    sum=$(md5sum "$d/package.tgz" | cut -d' ' -f1)
    a "$n: INFO checksum is the MD5 of package.tgz" grep -qx "checksum=\"$sum\"" "$d/INFO"

    a "$n: the lifecycle scripts are there" test -s "$d.scripts"
    a "$n: every scripts/* member is mode 0755" nogrep -v '^-rwxr-xr-x' "$d.scripts"
    a "$n: no CR byte in scripts/*, INFO, conf/* or the payload's ui/config" \
        lfonly "$d"/scripts/* "$d/INFO" "$d"/conf/* "$d/payload/ui/config"

    a "$n: privilege runs as the package user" grep -q '"run-as": *"package"' "$d/conf/privilege"

    port=$(sed -n 's/^adminport="\(.*\)"$/\1/p' "$d/INFO")
    a "$n: ui/config, scan2graph.sc and postinst all use adminport $port" sameport "$port" "$d"

    a "$n: package.tgz contains ui/config" test -f "$d/payload/ui/config"
    # conf/resource's protocol-file resolves against target/, so this is the
    # path the firewall registration reads - an outer conf/ copy would not be.
    a "$n: package.tgz contains conf/scan2graph.sc" test -f "$d/payload/conf/scan2graph.sc"
    for s in 16 24 32 48 64 72 256; do
        a "$n: package.tgz contains ui/images/icon_$s.png" test -f "$d/payload/ui/images/icon_$s.png"
    done

    case $arch in
        x86_64) em=3e00 ;; # EM_X86_64
        armv8) em=b700 ;;  # EM_AARCH64
        armv7) em=2800 ;;  # EM_ARM
        *) die "$n: unknown arch '$arch' in the filename" ;;
    esac
    binmode=$(tar -tzvf "$d/package.tgz" | grep -E ' bin/scan2graph$' | cut -c1-10)
    a "$n: bin/scan2graph is mode 0755 inside package.tgz" test "$binmode" = -rwxr-xr-x
    a "$n: bin/scan2graph is a linux/$arch ELF" \
        test "$(hex "$d/payload/bin/scan2graph" 0 4)$(hex "$d/payload/bin/scan2graph" 18 2)" = "7f454c46$em"
}

# The container gets the .spk itself plus the script below, over stdin, and
# unpacks it with a real Linux tar: modes and CRLF then reach the scripts
# exactly as they would on the NAS, which a detour through an NTFS checkout
# would quietly launder away.
lifecycle() {
    local stage=$work/dsm
    mkdir -p "$stage"
    cp "$1" "$stage/pkg.spk"
    cat >"$stage/run.sh" <<'SH'
set -euo pipefail
P=/var/packages/scan2graph
S=/spk/scripts
CONFIG=$P/etc/scan2graph.env
# Only what postuninst still reads (SYNOPKG_PKG_STATUS) plus the package
# name; SYNOPKG_PKGVAR/_PKGTMP/_PKGDEST are deliberately not exported, which
# is what proves the scripts no longer depend on them - the boot case where
# DSM may not have set them, and which this container is otherwise unable to
# reach.
export SYNOPKG_PKGNAME=scan2graph SYNOPKG_PKG_STATUS=INSTALL
ok()  { printf 'ok   lifecycle: %s\n' "$*"; }
die() { printf 'FAIL lifecycle: %s\n' "$*" >&2; exit 1; }
# DSM reads start-stop-status by exit code, so assert the code, not the output.
expect() {
    local want=$1 what=$2 got=0
    shift 2
    "$@" >&2 || got=$?
    [ "$got" = "$want" ] || die "$what: exit $got, want $want"
    ok "$what"
}
# DSM creates the FHS dirs as root and hands the tree to the package user;
# everything the package itself does runs unprivileged, so so does all of this.
AS="setpriv --reuid=1000 --regid=1000 --clear-groups"

mkdir -p /spk "$P/var" "$P/tmp" "$P/target"
tar -xf /in/pkg.spk -C /spk
tar -xzf /spk/package.tgz -C "$P/target"
chown -R 1000:1000 "$P"

$AS "$S/postinst" || die "postinst exited non-zero; DSM would leave the package corrupted"
[ "$(stat -c %a "$CONFIG")" = 600 ] || die "$CONFIG is missing or not mode 0600"
for v in S2G_HTTP_ADDR=:2526 S2G_SMTP_ADDR=:2525 S2G_TEMP_DIR=/var/packages/scan2graph/tmp; do
    grep -qx "$v" "$CONFIG" || die "postinst did not seed $v into $CONFIG"
done
ok "postinst writes $CONFIG 0600 with the three seeded settings"

printf '# operator edit\n' >>"$CONFIG"
$AS "$S/postinst" || die "second postinst exited non-zero"
grep -qx '# operator edit' "$CONFIG" ||
    die "postinst rewrote an existing config; every upgrade would clobber the operator's settings"
ok "a second postinst leaves an existing config alone"

expect 3 "status before start exits 3" $AS "$S/start-stop-status" status
# A timeout rather than a stopwatch: a start that blocks is the documented DSM
# failure - the package hangs in "Starting" forever - and 124 says exactly that.
expect 0 "start forks and returns promptly" timeout 10 $AS "$S/start-stop-status" start
expect 0 "status after start exits 0" $AS "$S/start-stop-status" status

pid=$(cat "$P/var/scan2graph.pid")
expect 0 "start again is idempotent" timeout 10 $AS "$S/start-stop-status" start
pid2=$(cat "$P/var/scan2graph.pid")
[ "$pid2" = "$pid" ] || die "starting twice changed the pid ($pid -> $pid2); the first process is now orphaned"
kill -0 "$pid" 2>/dev/null || die "pid $pid from the pid file is not alive after starting twice"
ok "starting twice leaves the original process running under the same pid"

# No curl in debian:stable-slim, and installing one would mean a network fetch
# per run; bash's /dev/tcp is already here and one GET is all this needs.
get() {
    exec 3<>/dev/tcp/127.0.0.1/2526 || return 1
    printf 'GET /setup HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n' >&3
    timeout 5 cat <&3
    exec 3>&-
}
page=
for _ in $(seq 40); do
    page=$(get 2>/dev/null) || page=
    case $page in *"Set up scan2graph"*) break ;; esac
    sleep 0.25
done
case $page in
    *"Set up scan2graph"*) ok "GET /setup serves scan2graph's setup wizard" ;;
    *) die "GET /setup on 127.0.0.1:2526 did not return the setup wizard" ;;
esac

# The start script's redirect is the only reason the operator can diagnose anything.
[ -s "$P/var/scan2graph.log" ] || die "$P/var/scan2graph.log is missing or empty"
# 0600 because stderr lands here, and stderr is where the appliance prints the
# one-shot setup URL and any generated SMTP password.
[ "$(stat -c %a "$P/var/scan2graph.log")" = 600 ] || die "$P/var/scan2graph.log is not mode 0600"
ok "the service log lands in $P/var/scan2graph.log, mode 0600"

expect 0 "stop exits 0" $AS "$S/start-stop-status" stop
! kill -0 "$pid" 2>/dev/null || die "pid $pid is still alive after stop"
ok "the service process is gone after stop"
expect 3 "status after stop exits 3" $AS "$S/start-stop-status" status

# Obviously-fake Entra identity and email profile, same constants the e2e
# fixtures use (e2e/fakes/main.go, playwright.config.mjs): enough for
# config.Load to succeed via the email capability, without S2G_PUBLIC_BASE_URL
# - that would enable the web UI, which does synchronous OIDC discovery
# against the real login.microsoftonline.com and would make start fail here,
# offline, for a reason that has nothing to do with what this proves.
cat >>"$CONFIG" <<'EOF'
S2G_ENTRA_TENANT_ID=00000000-0000-0000-0000-0000000000aa
S2G_ENTRA_CLIENT_ID=00000000-0000-0000-0000-000000000001
S2G_ENTRA_CLIENT_SECRET=fixture-not-a-real-secret
S2G_GRAPH_SENDER=scanner@corp.example
S2G_ALLOWED_RECIPIENT_DOMAINS=corp.example
EOF
expect 0 "start (appliance mode) forks and returns promptly" timeout 10 $AS "$S/start-stop-status" start
for _ in $(seq 40); do
    (exec 3<>/dev/tcp/127.0.0.1/2525) 2>/dev/null && break
    sleep 0.25
done
(exec 3<>/dev/tcp/127.0.0.1/2525) 2>/dev/null || die "2525 refused a TCP connection under the seeded appliance config"
ok "2525 accepts a TCP connection under the seeded appliance config"
expect 0 "status exits 0 under the seeded appliance config" $AS "$S/start-stop-status" status
expect 0 "stop exits 0 (appliance mode)" $AS "$S/start-stop-status" stop

# Backwards, this wipes the operator's Entra client secret on every update.
export SYNOPKG_PKG_STATUS=UPGRADE
$AS "$S/postuninst" || die "postuninst exited non-zero on UPGRADE"
[ -f "$CONFIG" ] || die "postuninst deleted the config on UPGRADE"
ok "postuninst keeps the config on UPGRADE"
export SYNOPKG_PKG_STATUS=UNINSTALL
$AS "$S/postuninst" || die "postuninst exited non-zero on UNINSTALL"
[ ! -f "$CONFIG" ] || die "postuninst left the config behind on UNINSTALL"
ok "postuninst removes the config on UNINSTALL"
SH
    # --init so an orphaned service process is reaped rather than lingering as a
    # zombie that "is it gone after stop?" would still see.
    tar -cf - -C "$stage" . |
        docker run --rm -i --init debian:stable-slim \
            bash -c 'mkdir /in && tar -xf - -C /in && exec bash /in/run.sh' ||
        die "lifecycle checks did not pass (container output above)"
}

spks=(dist/*.spk)
[ -f "${spks[0]}" ] || die "no .spk found; run ./spk/build.sh --version vX.Y.Z first"
for s in "${spks[@]}"; do structural "$s"; done

x86=$(printf '%s\n' "${spks[@]}" | grep x86_64 | head -1 || true)
if ! command -v docker >/dev/null; then
    echo "SKIP lifecycle checks: docker is not on PATH, so only the structural checks above ran"
elif [ -z "$x86" ]; then
    # A --arch armv8 build leaves dist/ without one, and the container cannot
    # exec an arm binary without emulation.
    echo "SKIP lifecycle checks: no x86_64 .spk in dist/, so only the structural checks above ran"
else
    lifecycle "$x86"
fi

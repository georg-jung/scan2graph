#!/usr/bin/env bash
# Builds one .spk per architecture: the static Go binary plus the DSM
# lifecycle glue in this directory, tarred exactly the way DSM 7 expects.
# Assembles everything in a temp dir - never in the source tree - so a
# failed or interrupted build can't leave stray files for git to pick up.
set -euo pipefail

cd "$(dirname "$0")/.." # repo root, regardless of where this is invoked from

VERSION=""
ARCHES=()

usage() { echo "usage: $0 --version vX.Y.Z [--arch x86_64|armv8|armv7]..." >&2; }

while [ $# -gt 0 ]; do
    case "$1" in
        --version)
            [ $# -ge 2 ] || { usage; exit 1; }
            VERSION=$2
            shift 2
            ;;
        --arch)
            [ $# -ge 2 ] || { usage; exit 1; }
            ARCHES+=("$2")
            shift 2
            ;;
        *)
            usage
            exit 1
            ;;
    esac
done

# Two version-less local builds would otherwise both stamp INFO with the same
# fake "0.0.0-1", and Package Center compares that build number to decide
# whether to offer an upgrade.
if [ -z "$VERSION" ]; then
    usage
    exit 1
fi

if [ ${#ARCHES[@]} -eq 0 ]; then
    ARCHES=(x86_64 armv8 armv7)
fi

# The feature part of INFO's version is the tag with its leading "v" stripped
# ("v0.2.0" -> "0.2.0"); the build number is a constant because this package
# has no separate release cadence from the tag it's built from.
FEATURE=${VERSION#v}
PKG_VERSION="${FEATURE}-1"

TAR_OPTS=(--owner=root:0 --group=root:0 --numeric-owner --sort=name --mtime=@0 --format=gnu)

# One invocation owns dist/: a --arch armv8 build that left an x86_64 package
# from an earlier commit behind would have check.sh run its lifecycle test
# against that stale payload and report green for scripts it never ran.
mkdir -p dist
rm -f dist/scan2graph_*-dsm7_*.spk

build_one() {
    local arch=$1 goarch goarm work stage spk
    case "$arch" in
        x86_64) goarch=amd64; goarm="" ;;
        armv8)  goarch=arm64; goarm="" ;;
        armv7)  goarch=arm;   goarm=7 ;;
        *)
            echo "unknown --arch '$arch' (want x86_64, armv8 or armv7)" >&2
            exit 1
            ;;
    esac

    work=$(mktemp -d)
    trap 'rm -rf "$work"' RETURN
    stage="$work/stage" # -> package.tgz
    spk="$work/spk"     # -> outer archive members

    mkdir -p "$stage/bin" "$stage/conf" "$stage/ui/images"
    mkdir -p "$spk/scripts" "$spk/conf"

    echo "==> $arch: GOOS=linux GOARCH=$goarch${goarm:+ GOARM=$goarm}" >&2
    env CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" ${goarm:+GOARM="$goarm"} \
        go build -trimpath \
        -ldflags="-s -w -X github.com/georg-jung/scan2graph/internal/version.Stamp=${VERSION}" \
        -o "$stage/bin/scan2graph" ./cmd/scan2graph

    cp spk/conf/scan2graph.sc "$stage/conf/scan2graph.sc"
    cp spk/ui/config "$stage/ui/config"
    for s in 16 24 32 48 64 72 256; do
        cp "spk/icons/icon_$s.png" "$stage/ui/images/icon_$s.png"
    done

    # --mode=0755 forces bin/scan2graph executable in the archive: Git
    # Bash's stat() infers the exec bit from a PE header or a "#!" shebang
    # and ignores chmod, so a cross-compiled Linux ELF can't be made
    # executable on disk directly.
    tar "${TAR_OPTS[@]}" --mode=0755 -czf "$spk/package.tgz" -C "$stage" bin conf ui

    cp spk/scripts/* "$spk/scripts/"
    cp spk/conf/privilege spk/conf/resource "$spk/conf/"
    cp spk/icons/icon_64.png "$spk/PACKAGE_ICON.PNG"
    cp spk/icons/icon_256.png "$spk/PACKAGE_ICON_256.PNG"

    # checksum is the MD5 of the finished package.tgz, computed after it's
    # written; extractsize is du -sk of the staging dir that became it - both
    # must describe the payload DSM will actually extract.
    local extractsize checksum create_time
    extractsize=$(du -sk "$stage" | cut -f1)
    checksum=$(md5sum "$spk/package.tgz" | cut -d' ' -f1)
    create_time=$(date -u +%Y%m%d-%H:%M:%S)

    # checkport is left at its default of "yes" on purpose: this package owns
    # adminport, and a conflict on it has to stop the install rather than be
    # worked around later. adminport and ui/config are baked in here at build
    # time, so an operator who moves S2G_HTTP_ADDR afterwards gets a service
    # that runs while the main-menu icon and the Open button still point at
    # 8080 - i.e. at whatever else is answering there.
    cat >"$spk/INFO" <<EOF
package="scan2graph"
version="$PKG_VERSION"
os_min_ver="7.0-40000"
arch="$arch"
maintainer="Georg Jung"
maintainer_url="https://github.com/georg-jung"
support_url="https://github.com/georg-jung/scan2graph/issues"
description="LAN SMTP gateway that turns scan-to-email from a printer into OCRed PDFs delivered by Microsoft Graph or a small Entra-authenticated web UI."
adminport="8080"
dsmuidir="ui"
dsmappname="SYNO.SDS._ThirdParty.App.scan2graph"
support_move="yes"
extractsize="$extractsize"
checksum="$checksum"
create_time="$create_time"
EOF

    # Outer archive is uncompressed (DSM cannot read a compressed outer
    # tar); ui/ is not a member here - it lives inside package.tgz, and DSM
    # symlinks it out via dsmuidir.
    local out="dist/scan2graph_${arch}-dsm7_${PKG_VERSION}.spk"
    tar "${TAR_OPTS[@]}" --mode=0755 -cf "$out" -C "$spk" INFO package.tgz scripts conf PACKAGE_ICON.PNG PACKAGE_ICON_256.PNG
    echo "$out"
}

for a in "${ARCHES[@]}"; do
    build_one "$a"
done

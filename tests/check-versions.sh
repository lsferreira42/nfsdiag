#!/bin/sh
# Fail if any file that carries the nfsdiag version disagrees with VERSION.
# Run from the repository root: sh tests/check-versions.sh
set -eu

VER=$(cat VERSION)
fail=0

expect() {
    # expect <description> <actual>
    desc=$1
    actual=$2
    if [ "$actual" != "$VER" ]; then
        echo "[FAIL] $desc: '$actual' != VERSION '$VER'"
        fail=1
    fi
}

expect "src/nfsdiag.h NFSDIAG_VERSION" \
    "$(sed -n 's/^#define NFSDIAG_VERSION "\(.*\)"/\1/p' src/nfsdiag.h)"

expect "packaging/nfsdiag.control Version" \
    "$(sed -n 's/^Version: //p' packaging/nfsdiag.control)"

expect "packaging/nfsdiag.spec Version" \
    "$(sed -n 's/^Version:[[:space:]]*//p' packaging/nfsdiag.spec)"

expect "packaging/aur/PKGBUILD pkgver" \
    "$(sed -n 's/^pkgver=//p' packaging/aur/PKGBUILD)"

expect "flake.nix version" \
    "$(sed -n 's/.*version = "\(.*\)";.*/\1/p' flake.nix | head -1)"

expect "packaging/homebrew/nfsdiag.rb version" \
    "$(sed -n 's/^  version "\(.*\)"/\1/p' packaging/homebrew/nfsdiag.rb)"

expect "packaging/Dockerfile.apk ARG VERSION" \
    "$(sed -n 's/^ARG VERSION=//p' packaging/Dockerfile.apk)"

expect "docs/nfsdiag.8 header" \
    "$(sed -n 's/.*"nfsdiag \([0-9][0-9.]*\)".*/\1/p' docs/nfsdiag.8 | head -1)"

expect "website/index.html softwareVersion" \
    "$(sed -n 's/.*"softwareVersion": "\(.*\)".*/\1/p' website/index.html)"

expect "website/index.html 'Current version'" \
    "$(sed -n 's/.*Current version: <strong>\([^<]*\)<\/strong>.*/\1/p' website/index.html)"

expect "website/index.html footer" \
    "$(sed -n 's/.*nfsdiag <strong>v\([^<]*\)<\/strong>.*/\1/p' website/index.html | head -1)"

expect "website/docs.html header" \
    "$(sed -n 's/.*<strong>nfsdiag<\/strong> v\([0-9][0-9.]*\).*/\1/p' website/docs.html | head -1)"

expect "website/docs.html footer" \
    "$(sed -n 's/.*nfsdiag <strong>v\([^<]*\)<\/strong>.*/\1/p' website/docs.html | head -1)"

expect "website/author.html footer" \
    "$(sed -n 's/.*nfsdiag <strong>v\([^<]*\)<\/strong>.*/\1/p' website/author.html | head -1)"

expect "website/docs.html NFSDIAG_VERSION row" \
    "$(sed -n 's/.*NFSDIAG_VERSION<\/td><td colspan="3">"\([^"]*\)".*/\1/p' website/docs.html)"

if [ -x ./nfsdiag ]; then
    expect "./nfsdiag --version" "$(./nfsdiag --version | awk '{print $2}')"
fi

if ! grep -q "^## \[$VER\]" CHANGELOG.md && ! grep -q "^## \[Unreleased\]" CHANGELOG.md; then
    echo "[FAIL] CHANGELOG.md has neither a [$VER] entry nor an [Unreleased] section"
    fail=1
fi

if [ "$fail" -eq 0 ]; then
    echo "[OK] all version strings agree on $VER"
fi
exit "$fail"

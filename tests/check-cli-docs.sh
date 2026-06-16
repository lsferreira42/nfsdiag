#!/bin/sh
# Verify that every long option printed by `nfsdiag --help` is documented in
# the README, the man page, the website CLI reference, and all three shell
# completions. `--help` is the source of truth.
# Run from the repository root with a built ./nfsdiag: sh tests/check-cli-docs.sh
set -eu

NFS_DIAG=${NFS_DIAG:-./nfsdiag}
fail=0

opts=$("$NFS_DIAG" --help | grep -o -- '--[a-z0-9-]*' | sort -u)
[ -n "$opts" ] || { echo "[FAIL] could not extract options from --help"; exit 1; }

check() {
    # check <surface> <file> <pattern>
    surface=$1
    file=$2
    pattern=$3
    if ! grep -qF -- "$pattern" "$file"; then
        echo "[FAIL] $surface ($file): missing $opt"
        fail=1
    fi
}

for opt in $opts; do
    bare=${opt#--}
    # groff escapes hyphens: --mount-options -> \-\-mount\-options
    groff=$(printf '%s' "$opt" | sed 's/-/\\-/g')

    check "README"          README.md                 "$opt"
    check "man page"        docs/nfsdiag.8            "$groff"
    check "website docs"    website/docs.html         "$opt"
    check "bash completion" completions/nfsdiag.bash  "$opt"
    check "zsh completion"  completions/nfsdiag.zsh   "$opt"
    check "fish completion" completions/nfsdiag.fish  "-l $bare"
done

if [ "$fail" -eq 0 ]; then
    echo "[OK] all $(printf '%s\n' "$opts" | wc -l) options documented in README, man, website, and completions"
fi
exit "$fail"

#!/bin/sh
# Verify that every long option printed by `nfsdiag client --help` and
# `nfsdiag server --help` is documented in the README, the man page, the
# website CLI reference, and all three shell completions. `--help` is the
# source of truth.
# Run from the repository root with a built ./nfsdiag: sh tests/check-cli-docs.sh
set -eu

NFS_DIAG=${NFS_DIAG:-./nfsdiag}
fail=0

client_opts=$("$NFS_DIAG" client --help | grep -o -- '--[a-z0-9-]*' | sort -u)
server_opts=$("$NFS_DIAG" server --help | grep -o -- '--[a-z0-9-]*' | sort -u)
[ -n "$client_opts" ] || { echo "[FAIL] could not extract options from client --help"; exit 1; }
[ -n "$server_opts" ] || { echo "[FAIL] could not extract options from server --help"; exit 1; }

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

# The website reference is split by namespace; README, man page and the
# completions document both namespaces in one file.
check_namespace() {
    # check_namespace <opts> <website-file>
    website_file=$2
    for opt in $1; do
        bare=${opt#--}
        # groff escapes hyphens: --mount-options -> \-\-mount\-options
        groff=$(printf '%s' "$opt" | sed 's/-/\\-/g')

        check "README"          README.md                 "$opt"
        check "man page"        docs/nfsdiag.8            "$groff"
        check "website docs"    "$website_file"           "$opt"
        check "bash completion" completions/nfsdiag.bash  "$opt"
        check "zsh completion"  completions/nfsdiag.zsh   "$opt"
        check "fish completion" completions/nfsdiag.fish  "-l $bare"
    done
}

check_namespace "$client_opts" website/docs.html
check_namespace "$server_opts" website/docs-server.html

if [ "$fail" -eq 0 ]; then
    total=$(printf '%s\n%s\n' "$client_opts" "$server_opts" | sort -u | wc -l)
    echo "[OK] all $total options documented in README, man, website, and completions"
fi
exit "$fail"

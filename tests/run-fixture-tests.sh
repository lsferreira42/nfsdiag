#!/bin/sh
set -eu

DOCKER=${DOCKER:-docker}
TAG_PREFIX=${DOCKER_TAG_PREFIX:-nfs-doctor-fixture}
NFS_DIAG=${NFS_DIAG:-./nfsdiag}
TEST_TIMEOUT=${TEST_TIMEOUT:-120}

ALL_FIXTURES="rpcbind-unreachable nfs-port-unreachable rpc-map-missing-nfs mountd-unavailable locking-missing read-only-export root-squash identity-denied permission-denied"

if [ "${1:-}" = "--list" ]; then
    printf '%s\n' ${ALL_FIXTURES}
    exit 0
fi

FIXTURES=${*:-${ALL_FIXTURES}}

need_root_for_live() {
    case "$1" in
        locking-missing|read-only-export|root-squash|identity-denied|permission-denied) return 0 ;;
        *) return 1 ;;
    esac
}

expected_pattern() {
    case "$1" in
        rpcbind-unreachable) printf '%s\n' 'rpcbind TCP port 111 unreachable' ;;
        nfs-port-unreachable) printf '%s\n' 'NFS TCP port 2049 unreachable' ;;
        rpc-map-missing-nfs) printf '%s\n' 'NFS v4 not detected' ;;
        mountd-unavailable) printf '%s\n' 'cannot contact mountd' ;;
        locking-missing) printf '%s\n' 'NSM/statd not registered' ;;
        read-only-export) printf '%s\n' 'cannot create test file' ;;
        root-squash) printf '%s\n' 'root_squash practical signal' ;;
        identity-denied) printf '%s\n' 'cannot traverse/read export root' ;;
        permission-denied) printf '%s\n' 'directory read/traverse access denied' ;;
        *) printf '%s\n' '[SUMMARY]' ;;
    esac
}

run_nfsdiag() {
    fixture=$1
    ip=$2
    case "$fixture" in
        read-only-export|root-squash|permission-denied)
            "$NFS_DIAG" --export /export --command-timeout 10 --bench-bytes 1024 --bench-iterations 1 --stale-iterations 1 "$ip" ;;
        identity-denied)
            "$NFS_DIAG" --export /export --command-timeout 10 --bench-bytes 1024 --bench-iterations 1 --stale-iterations 1 --uid 65534 --gid 65534 "$ip" ;;
        *)
            "$NFS_DIAG" --no-mount --command-timeout 10 --timeout 3 "$ip" ;;
    esac
}

build_fixture() {
    fixture=$1
    "$DOCKER" build -f "dockerfiles/Dockerfile.${fixture}" -t "${TAG_PREFIX}:${fixture}" dockerfiles >/dev/null
}

container_ip() {
    name=$1
    "$DOCKER" inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$name"
}

cleanup_container() {
    name=$1
    "$DOCKER" rm -f "$name" >/dev/null 2>&1 || true
}

pass=0
fail=0
skip=0

for fixture in ${FIXTURES}; do
    if need_root_for_live "$fixture" && [ "$(id -u)" != "0" ]; then
        echo "[SKIP] ${fixture}: live mount fixture requires root on the host"
        skip=$((skip + 1))
        continue
    fi

    image="${TAG_PREFIX}:${fixture}"
    name="nfsdoctor-test-${fixture}-$$"
    output="/tmp/nfsdoctor-${fixture}-$$.out"

    echo "[TEST] ${fixture}"
    build_fixture "$fixture"
    cleanup_container "$name"

    run_args="--rm -d --name ${name}"
    if need_root_for_live "$fixture"; then
        run_args="${run_args} --privileged"
    fi

    # shellcheck disable=SC2086
    if ! "$DOCKER" run ${run_args} "$image" >/dev/null; then
        echo "[SKIP] ${fixture}: container could not be started on this host"
        skip=$((skip + 1))
        continue
    fi
    trap 'cleanup_container "$name"' EXIT INT TERM
    sleep 3
    running=$($DOCKER inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)
    if [ "$running" != "true" ]; then
        echo "[SKIP] ${fixture}: container exited early; host probably lacks required NFS/kernel privileges"
        cleanup_container "$name"
        skip=$((skip + 1))
        trap - EXIT INT TERM
        continue
    fi
    ip=$(container_ip "$name")
    if [ -z "$ip" ]; then
        echo "[SKIP] ${fixture}: could not determine container IP"
        cleanup_container "$name"
        skip=$((skip + 1))
        trap - EXIT INT TERM
        continue
    fi

    set +e
    run_nfsdiag "$fixture" "$ip" >"$output" 2>&1
    rc=$?
    set -e

    pattern=$(expected_pattern "$fixture")
    if grep -F "$pattern" "$output" >/dev/null 2>&1; then
        echo "[PASS] ${fixture}: matched '${pattern}' (nfsdiag rc=${rc})"
        pass=$((pass + 1))
    else
        echo "[FAIL] ${fixture}: expected '${pattern}'"
        echo "----- output -----"
        cat "$output"
        echo "------------------"
        fail=$((fail + 1))
    fi

    rm -f "$output"
    cleanup_container "$name"
    trap - EXIT INT TERM
done

echo "[RESULT] pass=${pass} fail=${fail} skip=${skip}"
[ "$fail" -eq 0 ]

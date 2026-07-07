# bash completion for nfsdiag
_nfsdiag() {
    local cur prev words cword
    _init_completion || return

    local commands="client server diff help version"
    local server_opts="--all --daemons --exports-audit --ports-firewall \
        --storage-health --sysctl-advisor --version-matrix \
        --security-audit --idmap-check --krb5-server --acl-check \
        --squash-check --audit-trail \
        --rpc-stats --locks --clients --client-states \
        --log-intel --rmtab-audit --memory-pressure \
        --latency-profile --per-client-trace --backend-bench --capture --duration \
        --ha-check --ganesha-check \
        --exports-file --root --json --html --output-format --output-dir \
        --watch --listen \
        --verbose --quiet --version --help"
    local client_opts="--export --mount-options --no-mount --dry-run --read-only \
        --uid --gid --groups --krb5 --udp --ipv4-only --ipv6-only \
        --no-nfs4-discovery --mount-namespace --no-mount-namespace \
        --dangerous-fs-tests --deep --allow-risky-mount-options \
        --profile --hosts-file --peer --watch \
        --on-fail-exec --config --timeout --command-timeout --fs-timeout \
        --delay-ms --bench-bytes --bench-iterations --bench-type \
        --stale-iterations --json --html --output-dir --output-format --keep-temp \
        --parallel --sweep --diff-baseline --listen \
        --self-test --verbose --quiet --version --help"

    if [ "$cword" -eq 1 ]; then
        COMPREPLY=($(compgen -W "$commands" -- "$cur"))
        return
    fi

    case "${words[1]}" in
        server)
            case "$prev" in
                --exports-file|--json|--html) _filedir; return ;;
                --root|--output-dir) _filedir -d; return ;;
                --output-format)
                    COMPREPLY=($(compgen -W "text table ndjson prometheus junit" -- "$cur"))
                    return ;;
            esac
            COMPREPLY=($(compgen -W "$server_opts" -- "$cur"))
            return ;;
        diff)
            _filedir json
            return ;;
        client|*) : ;;   # fall through: client namespace or deprecated legacy alias
    esac

    case "$prev" in
        --bench-type)
            COMPREPLY=($(compgen -W "internal fio" -- "$cur"))
            return ;;
        --output-format)
            COMPREPLY=($(compgen -W "text table ndjson prometheus junit" -- "$cur"))
            return ;;
        --profile)
            COMPREPLY=($(compgen -W "quick safe full performance security readonly" -- "$cur"))
            return ;;
        --export|-e|--mount-options|-o|--groups)
            return ;;
        --uid|--gid|--timeout|--command-timeout|--fs-timeout|--delay-ms|\
        --bench-bytes|--bench-iterations|--stale-iterations|--watch|\
        --parallel|--listen)
            return ;;
        --hosts-file|--on-fail-exec|--config|--json|--html|--output-dir)
            _filedir
            return ;;
    esac

    if [[ "$cur" == -* ]]; then
        COMPREPLY=($(compgen -W "$client_opts" -- "$cur"))
    else
        _known_hosts_real "$cur"
    fi
}

complete -F _nfsdiag nfsdiag

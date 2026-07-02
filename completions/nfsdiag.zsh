#compdef nfsdiag
# zsh completion for nfsdiag

_nfsdiag() {
    local -a client_opts server_opts

    client_opts=(
        '*'{-e,--export}'[test only this export path (repeatable)]:export path:'
        '(-o --mount-options)'{-o,--mount-options}'[extra mount options]:mount options:'
        '--no-mount[run network/RPC checks only; skip all mounts]'
        '--dry-run[print what would be done; skip mounts and fs tests]'
        '--read-only[do not create or write test files]'
        '--uid[simulate access as UID]:uid:'
        '--gid[GID paired with last --uid]:gid:'
        '--groups[supplemental GIDs]:gids (comma-separated):'
        '--krb5[check Kerberos prerequisites and test sec=krb5* mounts]'
        '--parallel[test up to N exports concurrently]:workers:'
        '--sweep[benchmark rsize/wsize/nconnect combos and suggest mount options]'
        '--diff-baseline[compare with last saved run and update baseline]'
        '--listen[serve Prometheus metrics over HTTP on PORT]:port:'
        '--udp[also probe RPC NULLPROC over UDP]'
        '--ipv4-only[force IPv4 for direct TCP checks]'
        '--ipv6-only[force IPv6 for direct TCP checks]'
        '--no-nfs4-discovery[disable NFSv4 pseudo-root fallback]'
        '--mount-namespace[use private mount namespace]'
        '--no-mount-namespace[disable automatic private mount namespace]'
        '--dangerous-fs-tests[enable symlink/hardlink/FIFO/device-node probes]'
        '--deep[alias for --dangerous-fs-tests]'
        '--allow-risky-mount-options[permit risky mount options]'
        '--profile[apply diagnostic preset]:profile:(quick safe full performance security readonly)'
        '--hosts-file[read hosts from file]:file:_files'
        '--watch[re-run every N seconds]:seconds:'
        '--on-fail-exec[exec script on failure]:script:_files'
        '--config[load options from config file]:file:_files'
        '--timeout[network/RPC timeout in seconds]:seconds:'
        '--command-timeout[mount/umount command timeout]:seconds:'
        '--fs-timeout[filesystem test timeout]:seconds:'
        '--delay-ms[delay between exports in ms]:milliseconds:'
        '--bench-bytes[bytes for read/write benchmark]:bytes:'
        '--bench-iterations[metadata latency iterations]:count:'
        '--bench-type[benchmark engine]:engine:(internal fio)'
        '--stale-iterations[ESTALE probe iterations]:count:'
        '--json[emit JSON report]:path:_files'
        '--html[emit HTML report]:path:_files'
        '--output-dir[write JSON, HTML, evidence and checksums]:dir:_files -/'
        '--output-format[terminal output format]:format:(text table ndjson prometheus junit)'
        '--keep-temp[keep temp workspace after tests]'
        '--self-test[validate local dependencies and helper checks]'
        '(-v --verbose)'{-v,--verbose}'[show all diagnostic steps]'
        '(-q --quiet)'{-q,--quiet}'[suppress stdout]'
        '(-V --version)'{-V,--version}'[print version and exit]'
        '(-h --help)'{-h,--help}'[show help]'
        ':server:_hosts'
    )

    server_opts=(
        '--exports-audit[audit /etc/exports and the live export table]'
        '--exports-file[exports file to audit]:file:_files'
        '(-v --verbose)'{-v,--verbose}'[show all diagnostic steps]'
        '(-q --quiet)'{-q,--quiet}'[suppress stdout]'
        '(-V --version)'{-V,--version}'[print version and exit]'
        '(-h --help)'{-h,--help}'[show help]'
    )

    if (( CURRENT == 2 )); then
        local -a commands
        commands=(
            'client:diagnose an NFS server from the client side'
            'server:diagnose the local NFS server'
            'diff:compare two JSON reports'
            'help:show help'
            'version:print version and exit'
        )
        _describe -t commands 'nfsdiag command' commands
        # deprecated legacy alias: bare `nfsdiag [opts] <host>` still works
        _arguments -s $client_opts
        return
    fi

    case $words[2] in
        client)
            words=("${words[@]:1}")
            (( CURRENT-- ))
            _arguments -s $client_opts
            ;;
        server)
            words=("${words[@]:1}")
            (( CURRENT-- ))
            _arguments -s $server_opts
            ;;
        diff)
            _files -g '*.json'
            ;;
        *)
            # deprecated legacy alias for `client`
            _arguments -s $client_opts
            ;;
    esac
}

_nfsdiag "$@"

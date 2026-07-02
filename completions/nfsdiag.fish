# fish completion for nfsdiag

# Subcommands (position 1)
complete -c nfsdiag -n '__fish_use_subcommand' -a 'client'  -d 'Diagnose an NFS server from the client side'
complete -c nfsdiag -n '__fish_use_subcommand' -a 'server'  -d 'Diagnose the local NFS server'
complete -c nfsdiag -n '__fish_use_subcommand' -a 'diff'    -d 'Compare two JSON reports'
complete -c nfsdiag -n '__fish_use_subcommand' -a 'help'    -d 'Show help'
complete -c nfsdiag -n '__fish_use_subcommand' -a 'version' -d 'Print version and exit'

# `nfsdiag server` namespace
set -l srv '__fish_seen_subcommand_from server'
complete -c nfsdiag -n "$srv" -l exports-audit -d 'Audit /etc/exports and the live export table'
complete -c nfsdiag -n "$srv" -l exports-file  -d 'Exports file to audit'          -r -F
complete -c nfsdiag -n "$srv" -s v -l verbose  -d 'Show all diagnostic steps'
complete -c nfsdiag -n "$srv" -s q -l quiet    -d 'Suppress stdout'
complete -c nfsdiag -n "$srv" -s V -l version  -d 'Print version and exit'
complete -c nfsdiag -n "$srv" -s h -l help     -d 'Show help'

# `nfsdiag diff` takes JSON report files
complete -c nfsdiag -n '__fish_seen_subcommand_from diff' -k -a '(__fish_complete_suffix .json)'

# `nfsdiag client` namespace; the same flags also apply to the deprecated
# legacy alias (`nfsdiag [OPTIONS] <host>` without a subcommand).
set -l cli 'not __fish_seen_subcommand_from server diff help version'
complete -c nfsdiag -n "$cli" -s e -l export         -d 'Test only this export path'        -r
complete -c nfsdiag -n "$cli" -s o -l mount-options  -d 'Extra mount options'                -r
complete -c nfsdiag -n "$cli"      -l no-mount       -d 'Run network/RPC checks only'
complete -c nfsdiag -n "$cli"      -l dry-run        -d 'Print what would be done; skip mounts'
complete -c nfsdiag -n "$cli"      -l read-only      -d 'Do not create or write test files'
complete -c nfsdiag -n "$cli"      -l uid            -d 'Simulate access as UID'             -r
complete -c nfsdiag -n "$cli"      -l gid            -d 'GID paired with last --uid'          -r
complete -c nfsdiag -n "$cli"      -l groups         -d 'Supplemental GIDs (comma-separated)' -r
complete -c nfsdiag -n "$cli"      -l krb5           -d 'Check Kerberos prerequisites and test sec=krb5* mounts'
complete -c nfsdiag -n "$cli"      -l parallel       -d 'Test up to N exports concurrently'  -r
complete -c nfsdiag -n "$cli"      -l sweep          -d 'Benchmark rsize/wsize/nconnect combos'
complete -c nfsdiag -n "$cli"      -l diff-baseline  -d 'Compare with last saved run and update baseline'
complete -c nfsdiag -n "$cli"      -l listen         -d 'Serve Prometheus metrics over HTTP on PORT' -r
complete -c nfsdiag -n "$cli"      -l udp            -d 'Also probe RPC NULLPROC over UDP'
complete -c nfsdiag -n "$cli"      -l ipv4-only      -d 'Force IPv4'
complete -c nfsdiag -n "$cli"      -l ipv6-only      -d 'Force IPv6'
complete -c nfsdiag -n "$cli"      -l no-nfs4-discovery -d 'Disable NFSv4 pseudo-root fallback'
complete -c nfsdiag -n "$cli"      -l mount-namespace -d 'Use private mount namespace'
complete -c nfsdiag -n "$cli"      -l no-mount-namespace -d 'Disable automatic private mount namespace'
complete -c nfsdiag -n "$cli"      -l dangerous-fs-tests -d 'Enable symlink/hardlink/FIFO/device-node probes'
complete -c nfsdiag -n "$cli"      -l deep -d 'Alias for --dangerous-fs-tests'
complete -c nfsdiag -n "$cli"      -l allow-risky-mount-options -d 'Permit risky mount options'
complete -c nfsdiag -n "$cli"      -l profile -d 'Diagnostic preset' -r -a "quick safe full performance security readonly"
complete -c nfsdiag -n "$cli"      -l hosts-file     -d 'Read hosts from file'               -r -F
complete -c nfsdiag -n "$cli"      -l watch          -d 'Re-run diagnostics every N seconds' -r
complete -c nfsdiag -n "$cli"      -l on-fail-exec   -d 'Script to exec on failure'          -r -F
complete -c nfsdiag -n "$cli"      -l config         -d 'Load options from config file'       -r -F
complete -c nfsdiag -n "$cli"      -l timeout        -d 'Network/RPC connect timeout'        -r
complete -c nfsdiag -n "$cli"      -l command-timeout -d 'Mount/umount timeout'              -r
complete -c nfsdiag -n "$cli"      -l fs-timeout     -d 'Filesystem test timeout'            -r
complete -c nfsdiag -n "$cli"      -l delay-ms       -d 'Delay between exports (ms)'         -r
complete -c nfsdiag -n "$cli"      -l bench-bytes    -d 'Bytes for read/write benchmark'     -r
complete -c nfsdiag -n "$cli"      -l bench-iterations -d 'Metadata latency iterations'      -r
complete -c nfsdiag -n "$cli"      -l bench-type     -d 'Benchmark engine'                   -r -a "internal fio"
complete -c nfsdiag -n "$cli"      -l stale-iterations -d 'ESTALE probe iterations'          -r
complete -c nfsdiag -n "$cli"      -l json           -d 'Emit JSON report'                   -r -F
complete -c nfsdiag -n "$cli"      -l html           -d 'Emit HTML report'                   -r -F
complete -c nfsdiag -n "$cli"      -l output-dir     -d 'Write JSON, HTML, evidence and checksums' -r -F
complete -c nfsdiag -n "$cli"      -l output-format  -d 'Terminal output format'             -r -a "text table ndjson prometheus junit"
complete -c nfsdiag -n "$cli"      -l keep-temp      -d 'Keep temp workspace after tests'
complete -c nfsdiag -n "$cli"      -l self-test      -d 'Validate local dependencies and helper checks'
complete -c nfsdiag -n "$cli" -s v -l verbose        -d 'Show all diagnostic steps'
complete -c nfsdiag -n "$cli" -s q -l quiet          -d 'Suppress stdout'
complete -c nfsdiag -n "$cli" -s V -l version        -d 'Print version and exit'
complete -c nfsdiag -n "$cli" -s h -l help           -d 'Show help'

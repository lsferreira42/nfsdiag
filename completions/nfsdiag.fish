# fish completion for nfsdiag

complete -c nfsdiag -s e -l export         -d 'Test only this export path'        -r
complete -c nfsdiag -s o -l mount-options  -d 'Extra mount options'                -r
complete -c nfsdiag      -l no-mount       -d 'Run network/RPC checks only'
complete -c nfsdiag      -l dry-run        -d 'Print what would be done; skip mounts'
complete -c nfsdiag      -l read-only      -d 'Do not create or write test files'
complete -c nfsdiag      -l uid            -d 'Simulate access as UID'             -r
complete -c nfsdiag      -l gid            -d 'GID paired with last --uid'          -r
complete -c nfsdiag      -l groups         -d 'Supplemental GIDs (comma-separated)' -r
complete -c nfsdiag      -l krb5           -d 'Check Kerberos prerequisites'
complete -c nfsdiag      -l udp            -d 'Also probe RPC NULLPROC over UDP'
complete -c nfsdiag      -l ipv4-only      -d 'Force IPv4'
complete -c nfsdiag      -l ipv6-only      -d 'Force IPv6'
complete -c nfsdiag      -l no-nfs4-discovery -d 'Disable NFSv4 pseudo-root fallback'
complete -c nfsdiag      -l mount-namespace -d 'Use private mount namespace'
complete -c nfsdiag      -l no-mount-namespace -d 'Disable automatic private mount namespace'
complete -c nfsdiag      -l dangerous-fs-tests -d 'Enable symlink/hardlink/FIFO/device-node probes'
complete -c nfsdiag      -l deep -d 'Alias for --dangerous-fs-tests'
complete -c nfsdiag      -l allow-risky-mount-options -d 'Permit risky mount options'
complete -c nfsdiag      -l profile -d 'Diagnostic preset' -r -a "quick safe full performance security readonly"
complete -c nfsdiag      -l hosts-file     -d 'Read hosts from file'               -r -F
complete -c nfsdiag      -l watch          -d 'Re-run diagnostics every N seconds' -r
complete -c nfsdiag      -l on-fail-exec   -d 'Script to exec on failure'          -r -F
complete -c nfsdiag      -l config         -d 'Load options from config file'       -r -F
complete -c nfsdiag      -l timeout        -d 'Network/RPC connect timeout'        -r
complete -c nfsdiag      -l command-timeout -d 'Mount/umount timeout'              -r
complete -c nfsdiag      -l fs-timeout     -d 'Filesystem test timeout'            -r
complete -c nfsdiag      -l delay-ms       -d 'Delay between exports (ms)'         -r
complete -c nfsdiag      -l bench-bytes    -d 'Bytes for read/write benchmark'     -r
complete -c nfsdiag      -l bench-iterations -d 'Metadata latency iterations'      -r
complete -c nfsdiag      -l bench-type     -d 'Benchmark engine'                   -r -a "internal fio"
complete -c nfsdiag      -l stale-iterations -d 'ESTALE probe iterations'          -r
complete -c nfsdiag      -l json           -d 'Emit JSON report'                   -r -F
complete -c nfsdiag      -l html           -d 'Emit HTML report'                   -r -F
complete -c nfsdiag      -l output-dir     -d 'Write JSON, HTML, evidence and checksums' -r -F
complete -c nfsdiag      -l output-format  -d 'Terminal output format'             -r -a "text table ndjson prometheus"
complete -c nfsdiag      -l keep-temp      -d 'Keep temp workspace after tests'
complete -c nfsdiag      -l self-test      -d 'Validate local dependencies and helper checks'
complete -c nfsdiag -s v -l verbose        -d 'Show all diagnostic steps'
complete -c nfsdiag -s q -l quiet          -d 'Suppress stdout'
complete -c nfsdiag -s V -l version        -d 'Print version and exit'
complete -c nfsdiag -s h -l help           -d 'Show help'

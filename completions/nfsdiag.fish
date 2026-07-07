# fish completion for nfsdiag

# Subcommands (position 1)
complete -c nfsdiag -n '__fish_use_subcommand' -a 'client'  -d 'Diagnose an NFS server from the client side'
complete -c nfsdiag -n '__fish_use_subcommand' -a 'server'  -d 'Diagnose the local NFS server'
complete -c nfsdiag -n '__fish_use_subcommand' -a 'diff'    -d 'Compare two JSON reports'
complete -c nfsdiag -n '__fish_use_subcommand' -a 'help'    -d 'Show help'
complete -c nfsdiag -n '__fish_use_subcommand' -a 'version' -d 'Print version and exit'

# `nfsdiag server` namespace
set -l srv '__fish_seen_subcommand_from server'
complete -c nfsdiag -n "$srv" -l all            -d 'Run every server check'
complete -c nfsdiag -n "$srv" -l daemons        -d 'Check nfsd, rpcbind, mountd, statd, idmapd and gss daemons'
complete -c nfsdiag -n "$srv" -l exports-audit -d 'Audit /etc/exports and the live export table'
complete -c nfsdiag -n "$srv" -l ports-firewall -d 'Check NFS listeners and firewall rules'
complete -c nfsdiag -n "$srv" -l storage-health -d 'Inspect the filesystem under each export'
complete -c nfsdiag -n "$srv" -l sysctl-advisor -d 'Inspect nfsd thread starvation and network tunables'
complete -c nfsdiag -n "$srv" -l version-matrix -d 'Report enabled NFS versions and lease/grace times'
complete -c nfsdiag -n "$srv" -l security-audit -d 'Deep exports analysis: legacy/risky options, duplicates, nesting'
complete -c nfsdiag -n "$srv" -l idmap-check    -d 'Validate idmapd.conf domain and nobody mapping'
complete -c nfsdiag -n "$srv" -l krb5-server    -d 'Validate server-side Kerberos: keytab, realm, gss daemons, clock'
complete -c nfsdiag -n "$srv" -l acl-check      -d 'Verify POSIX ACL support under each export'
complete -c nfsdiag -n "$srv" -l squash-check   -d 'Mount each export from localhost and verify root squashing'
complete -c nfsdiag -n "$srv" -l audit-trail    -d 'Capture config snapshots into --output-dir'
complete -c nfsdiag -n "$srv" -l rpc-stats      -d 'Analyze /proc/net/rpc/nfsd: reply cache, bad calls, traffic'
complete -c nfsdiag -n "$srv" -l locks          -d 'Summarize held locks, NFSv4 lease/grace, NLM/NSM registration'
complete -c nfsdiag -n "$srv" -l clients        -d 'Inventory connected NFSv4 clients and their callback state'
complete -c nfsdiag -n "$srv" -l client-states  -d 'Count NFSv4 opens/locks/delegations/layouts per client'
complete -c nfsdiag -n "$srv" -l log-intel       -d 'Correlate nfsd/mountd/statd log messages with known issues'
complete -c nfsdiag -n "$srv" -l rmtab-audit     -d 'Detect stale rmtab/NSM entries that bloat sm-notify'
complete -c nfsdiag -n "$srv" -l memory-pressure -d 'Assess memory pressure on the DRC and dentry/inode caches'
complete -c nfsdiag -n "$srv" -l latency-profile  -d 'eBPF per-op nfsd latency histogram'
complete -c nfsdiag -n "$srv" -l per-client-trace -d 'eBPF per-client nfsd ops and average latency'
complete -c nfsdiag -n "$srv" -l backend-bench    -d 'Benchmark the storage under each export'
complete -c nfsdiag -n "$srv" -l capture          -d 'Capture NFS traffic on port 2049 with tcpdump'
complete -c nfsdiag -n "$srv" -l duration         -d 'Sampling window in seconds' -r
complete -c nfsdiag -n "$srv" -l ha-check         -d 'Validate HA: fsid, shared NFS state, pacemaker'
complete -c nfsdiag -n "$srv" -l ganesha-check    -d 'Detect nfs-ganesha vs kernel nfsd and container context'
complete -c nfsdiag -n "$srv" -l exports-file  -d 'Exports file to audit'          -r -F
complete -c nfsdiag -n "$srv" -l root           -d 'Read /proc and /etc under DIR'  -r -F
complete -c nfsdiag -n "$srv" -l json           -d 'Emit JSON report'               -r -F
complete -c nfsdiag -n "$srv" -l html           -d 'Emit HTML report'               -r -F
complete -c nfsdiag -n "$srv" -l output-format  -d 'Terminal output format'         -r -a "text table ndjson prometheus junit"
complete -c nfsdiag -n "$srv" -l output-dir     -d 'Write JSON, HTML, evidence and checksums' -r -F
complete -c nfsdiag -n "$srv" -l watch          -d 'Re-run the selected checks every SEC seconds' -r
complete -c nfsdiag -n "$srv" -l listen         -d 'Serve Prometheus server metrics over HTTP' -r
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
complete -c nfsdiag -n "$cli"      -l peer           -d 'Correlate with a peer server --listen exporter' -r
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

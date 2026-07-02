/* server.c - `nfsdiag server`: diagnose the local NFS server.
 *
 * This namespace runs on the NFS server itself. Each check reports through
 * report.c so JSON/HTML/exit-code behaviour matches the client namespace.
 * Feature catalogue: features_server.md at the repository root.
 */
#include "nfsdiag.h"
#include <errno.h>
#include <getopt.h>

struct server_options server_opt = {
    .exports_audit = 0,
    .exports_file  = "/etc/exports",
    .verbose       = 0,
    .quiet         = 0,
};

static void server_usage(FILE *f) {
    fprintf(f, "Usage: nfsdiag server [OPTIONS]\n");
    fprintf(f, "\nRuns diagnostics on the local NFS server. At least one check is required.\n");
    fprintf(f, "\nChecks:\n");
    fprintf(f, "      --exports-audit        Audit /etc/exports and the live export table\n");
    fprintf(f, "\nCheck options:\n");
    fprintf(f, "      --exports-file FILE    Exports file to audit. Default: /etc/exports\n");
    fprintf(f, "\nOutput options:\n");
    fprintf(f, "  -v, --verbose              Show all diagnostic steps\n");
    fprintf(f, "  -q, --quiet                Suppress human stdout\n");
    fprintf(f, "  -V, --version              Print version and exit\n");
    fprintf(f, "  -h, --help                 Show this help\n");
    fprintf(f, "\nExit codes: 0=pass  1=warn/fail  2=usage/runtime error\n");
}

static int server_run_exports_audit(void) {
    FILE *f = fopen(server_opt.exports_file, "r");
    if (!f) {
        fprintf(stderr, "nfsdiag server: cannot open %s: %s\n",
                server_opt.exports_file, strerror(errno));
        return 2;
    }

    if (!server_opt.quiet)
        printf("nfsdiag %s: exports audit of %s\n",
               NFSDIAG_VERSION, server_opt.exports_file);

    int findings = 0, entries = 0;
    char line[1024], err[256], why[256];
    struct export_line e;
    int lineno = 0;

    while (fgets(line, sizeof(line), f)) {
        lineno++;
        int r = exports_parse_line(line, lineno, &e, err, sizeof(err));
        if (r == 0)
            continue;
        if (r == -1) {
            report_fail("exports: %s", err);
            findings++;
            continue;
        }
        entries++;
        for (int i = 0; i < e.client_count; i++) {
            int risk = exports_client_risk(e.clients[i], why, sizeof(why));
            if (risk == 1) {
                report_warn("exports %s: %s", e.path, why);
                findings++;
            } else if (risk == -1) {
                report_fail("exports %s line %d: %s", e.path, e.lineno, why);
                findings++;
            } else if (server_opt.verbose) {
                report_info("exports %s: %s ok", e.path, e.clients[i]);
            }
        }
    }
    fclose(f);

    if (entries == 0 && findings == 0)
        report_warn("exports: %s defines no exports", server_opt.exports_file);
    else if (findings == 0)
        report_ok("exports: %d entr%s audited, no findings",
                  entries, entries == 1 ? "y" : "ies");

    if (!server_opt.quiet)
        printf("summary: ok=%d warn=%d fail=%d\n",
               summary_ok, summary_warn, summary_fail);
    return (summary_warn + summary_fail) > 0 ? 1 : 0;
}

int server_main(int argc, char **argv) {
    static struct option long_opts[] = {
        {"exports-audit", no_argument,       0, 2000},
        {"exports-file",  required_argument, 0, 2001},
        {"verbose",       no_argument,       0, 'v'},
        {"quiet",         no_argument,       0, 'q'},
        {"version",       no_argument,       0, 'V'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    int c;
    optind = 1;   /* argv was shifted by the dispatcher */
    while ((c = getopt_long(argc, argv, "vqVh", long_opts, NULL)) != -1) {
        switch (c) {
        case 2000: server_opt.exports_audit = 1; break;
        case 2001: server_opt.exports_file = optarg; break;
        case 'v': server_opt.verbose = 1; break;
        case 'q': server_opt.quiet = 1; break;
        case 'V': printf("nfsdiag %s\n", NFSDIAG_VERSION); return 0;
        case 'h': server_usage(stdout); return 0;
        default: return 2;
        }
    }
    if (optind < argc) {
        fprintf(stderr, "nfsdiag server: unexpected argument '%s'\n", argv[optind]);
        return 2;
    }
    if (!server_opt.exports_audit) {
        fprintf(stderr, "nfsdiag server: no check selected (try --exports-audit)\n\n");
        server_usage(stderr);
        return 2;
    }

    /* The report layer (report.c) prints through the client opt globals;
     * mirror the server flags so quiet/verbose behave identically here. */
    opt.quiet = server_opt.quiet;
    opt.verbose = server_opt.verbose;

    return server_run_exports_audit();
}

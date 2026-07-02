/* main.c - subcommand dispatcher.
 *
 * nfsdiag client [...]  -> client_main()   (the original CLI)
 * nfsdiag server [...]  -> server_main()
 * nfsdiag diff A B      -> diff_reports()
 * nfsdiag [opts] <host> -> deprecated alias for `client`, warns on stderr.
 */
#include "nfsdiag.h"

/* Which namespace this process runs as; the legacy alias is still "client". */
const char *nfsdiag_mode = "client";

static void top_usage(FILE *f) {
    fprintf(f, "Usage: nfsdiag <command> [options]\n\n");
    fprintf(f, "Commands:\n");
    fprintf(f, "  client [OPTIONS] <host>        Diagnose an NFS server from the client side\n");
    fprintf(f, "  server [OPTIONS]               Diagnose the local NFS server\n");
    fprintf(f, "  diff <before.json> <after.json>  Compare two JSON reports\n");
    fprintf(f, "  version                        Print version and exit\n");
    fprintf(f, "  help                           Show this help\n");
    fprintf(f, "\nRun 'nfsdiag client --help' or 'nfsdiag server --help' for options.\n");
    fprintf(f, "\nDeprecated: 'nfsdiag [OPTIONS] <host>' (without a command) still runs the\n");
    fprintf(f, "client diagnostics but will be removed in 1.0. Use 'nfsdiag client'.\n");
}

static int argv_has_quiet(int argc, char **argv) {
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "-q") == 0 || strcmp(argv[i], "--quiet") == 0)
            return 1;
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        top_usage(stderr);
        return 2;
    }

    const char *cmd = argv[1];

    if (strcmp(cmd, "client") == 0) {
        argv[1] = (char *)"nfsdiag client";      /* argv[0] for getopt errors */
        return client_main(argc - 1, argv + 1);
    }
    if (strcmp(cmd, "server") == 0) {
        argv[1] = (char *)"nfsdiag server";
        nfsdiag_mode = "server";
        return server_main(argc - 1, argv + 1);
    }
    if (strcmp(cmd, "diff") == 0) {
        if (argc != 4) {
            fprintf(stderr, "usage: nfsdiag diff <before.json> <after.json>\n");
            return 2;
        }
        return diff_reports(argv[2], argv[3]);
    }
    if (strcmp(cmd, "help") == 0 || strcmp(cmd, "-h") == 0 || strcmp(cmd, "--help") == 0) {
        top_usage(stdout);
        return 0;
    }
    if (strcmp(cmd, "version") == 0 || strcmp(cmd, "-V") == 0 || strcmp(cmd, "--version") == 0) {
        printf("nfsdiag %s\n", NFSDIAG_VERSION);
        return 0;
    }

    /* Anything starting with '-' or containing a '.'/':' looks like the old
     * option/host syntax: keep it working as a deprecated alias for `client`.
     * A bare word that matches none of the commands is a typo'd subcommand. */
    if (cmd[0] != '-' && strchr(cmd, '.') == NULL && strchr(cmd, ':') == NULL) {
        fprintf(stderr, "nfsdiag: unknown command '%s'\n\n", cmd);
        top_usage(stderr);
        return 2;
    }

    if (!argv_has_quiet(argc, argv))
        fprintf(stderr, "nfsdiag: warning: calling nfsdiag without a subcommand is "
                        "deprecated; use 'nfsdiag client'. This alias will be removed in 1.0.\n");
    return client_main(argc, argv);
}

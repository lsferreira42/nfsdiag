CLANG ?= clang

# Knobs:
#   FUZZ_SANITIZERS  sanitizers linked into every target (default address).
#                    Set to "address,undefined" locally, or "" under ptrace/
#                    sandboxes where LeakSanitizer aborts.
#   FUZZ_RUNS        per-target budget for `run-all` (default a 5s smoke run).
FUZZ_SANITIZERS ?= address
FUZZ_RUNS ?= -max_total_time=5

ifeq ($(strip $(FUZZ_SANITIZERS)),)
SAN_FLAGS := -fsanitize=fuzzer
else
SAN_FLAGS := -fsanitize=fuzzer,$(FUZZ_SANITIZERS)
endif

FUZZ_CFLAGS := -O1 -g $(SAN_FLAGS)
TIRPC_CFLAGS := $(shell pkg-config --cflags libtirpc 2>/dev/null || echo -I/usr/include/tirpc)
TIRPC_LIBS   := $(shell pkg-config --libs   libtirpc 2>/dev/null || echo -ltirpc)
COMMON_CFLAGS := $(FUZZ_CFLAGS) -I../../src $(TIRPC_CFLAGS) -D_GNU_SOURCE

TARGETS := fuzz_xdr_exports fuzz_mountstats fuzz_mountinfo fuzz_rpcstats

.PHONY: all clean run-all

all: $(TARGETS)

# Each target includes the real production .c it fuzzes; the harness file stubs
# the report/option symbols those modules import from the rest of the tree.
# validation.c is linked for fuzz_xdr_exports' validate_export_path.
fuzz_xdr_exports: fuzz_xdr_exports.c ../../src/rpc.c ../../src/validation.c
	$(CLANG) $(COMMON_CFLAGS) $< ../../src/validation.c -o $@ $(TIRPC_LIBS)

# stats.c (included by the harness) now calls util.c helpers (avg_per_op_ms,
# mountinfo_unescape); util.c's parse_bounded_int in turn needs validation.c's
# parse_ulong_arg, so both are linked in. report_* are stubbed by the harness.
fuzz_mountstats: fuzz_mountstats.c ../../src/stats.c ../../src/util.c ../../src/validation.c
	$(CLANG) $(COMMON_CFLAGS) $< ../../src/util.c ../../src/validation.c -o $@ $(TIRPC_LIBS)

fuzz_mountinfo: fuzz_mountinfo.c ../../src/stats.c ../../src/util.c ../../src/validation.c
	$(CLANG) $(COMMON_CFLAGS) $< ../../src/util.c ../../src/validation.c -o $@ $(TIRPC_LIBS)

fuzz_rpcstats: fuzz_rpcstats.c ../../src/stats.c ../../src/util.c ../../src/validation.c
	$(CLANG) $(COMMON_CFLAGS) $< ../../src/util.c ../../src/validation.c -o $@ $(TIRPC_LIBS)

# Smoke run: each target for FUZZ_RUNS (a short budget by default).
run-all: $(TARGETS)
	mkdir -p corpus
	for t in $(TARGETS); do \
		echo "=== $$t ==="; \
		./$$t $(FUZZ_RUNS) corpus/ || exit 1; \
	done

clean:
	rm -f $(TARGETS)

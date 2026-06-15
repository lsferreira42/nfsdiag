CLANG ?= clang
FUZZ_CFLAGS := -O1 -g -fsanitize=fuzzer,address
TIRPC_CFLAGS := $(shell pkg-config --cflags libtirpc 2>/dev/null || echo -I/usr/include/tirpc)
TIRPC_LIBS   := $(shell pkg-config --libs   libtirpc 2>/dev/null || echo -ltirpc)

TARGETS := fuzz_xdr_exports fuzz_mountstats fuzz_mountinfo fuzz_rpcstats

.PHONY: all clean run-all

all: $(TARGETS)

# Includes src/rpc.c to fuzz the real decoder; validation.c provides
# validate_export_path for the included code.
fuzz_xdr_exports: fuzz_xdr_exports.c ../../src/rpc.c ../../src/validation.c
	$(CLANG) $(FUZZ_CFLAGS) $(TIRPC_CFLAGS) -D_GNU_SOURCE $< ../../src/validation.c -o $@ $(TIRPC_LIBS)

fuzz_mountstats: fuzz_mountstats.c
	$(CLANG) $(FUZZ_CFLAGS) $< -o $@

fuzz_mountinfo: fuzz_mountinfo.c
	$(CLANG) $(FUZZ_CFLAGS) $< -o $@

fuzz_rpcstats: fuzz_rpcstats.c
	$(CLANG) $(FUZZ_CFLAGS) $< -o $@

# Run each target for 5 seconds (CI smoke run)
run-all: $(TARGETS)
	mkdir -p corpus
	for t in $(TARGETS); do \
		echo "=== $$t ==="; \
		./$$t -max_total_time=5 corpus/ || exit 1; \
	done

clean:
	rm -f $(TARGETS)

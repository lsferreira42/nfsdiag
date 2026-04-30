SHELL := /bin/sh

CC ?= gcc
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DESTDIR ?=

TARGET := nfsdiag
SRC := nfsdiag.c

TIRPC_CFLAGS := $(shell $(PKG_CONFIG) --cflags libtirpc 2>/dev/null)
TIRPC_LIBS := $(shell $(PKG_CONFIG) --libs libtirpc 2>/dev/null)

ifeq ($(strip $(TIRPC_CFLAGS)),)
TIRPC_CFLAGS := -I/usr/include/tirpc
endif
ifeq ($(strip $(TIRPC_LIBS)),)
TIRPC_LIBS := -ltirpc
endif

CPPFLAGS ?=
CFLAGS ?= -O2 -Wall -Wextra
LDFLAGS ?=
LDLIBS ?=

CPPFLAGS += $(TIRPC_CFLAGS)
LDLIBS += $(TIRPC_LIBS)

DOCKER ?= docker
DOCKERFILES := $(sort $(wildcard dockerfiles/Dockerfile.*))
DOCKER_TAG_PREFIX ?= nfs-doctor-fixture

.PHONY: all clean distclean rebuild check help install uninstall docker-list docker-build-all test-fixtures test-fixtures-list test-fixture-% $(DOCKERFILES:dockerfiles/Dockerfile.%=docker-build-%)

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $< $(LDLIBS) -o $@

rebuild: clean all

check: $(TARGET)
	./$(TARGET) --help >/dev/null
	@echo "self-check passed"

install: $(TARGET)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 $(TARGET) "$(DESTDIR)$(BINDIR)/$(TARGET)"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"

clean:
	rm -f $(TARGET) *.o

distclean: clean
	rm -rf .cache

help:
	@echo "Targets:"
	@echo "  all              Build $(TARGET)"
	@echo "  rebuild          Clean and build"
	@echo "  check            Run a minimal CLI self-check"
	@echo "  install          Install to DESTDIR/PREFIX, default $(PREFIX)"
	@echo "  uninstall        Remove installed binary"
	@echo "  clean            Remove build artifacts"
	@echo "  distclean        Remove build/cache artifacts"
	@echo "  docker-list      List available failure fixture Dockerfiles"
	@echo "  docker-build-X   Build dockerfiles/Dockerfile.X as $(DOCKER_TAG_PREFIX):X"
	@echo "  docker-build-all Build all fixture images"
	@echo "  test-fixtures    Run automated Docker fixture tests"
	@echo "  test-fixture-X   Run one automated Docker fixture test"


docker-list:
	@for f in $(DOCKERFILES); do basename "$$f" | sed 's/^Dockerfile\.//'; done

docker-build-%: dockerfiles/Dockerfile.%
	$(DOCKER) build -f $< -t $(DOCKER_TAG_PREFIX):$* dockerfiles

docker-build-all:
	@set -e; \
	for f in $(DOCKERFILES); do \
		name=$$(basename "$$f" | sed 's/^Dockerfile\.//'); \
		$(DOCKER) build -f "$$f" -t "$(DOCKER_TAG_PREFIX):$$name" dockerfiles; \
	done

test-fixtures: $(TARGET)
	DOCKER="$(DOCKER)" DOCKER_TAG_PREFIX="$(DOCKER_TAG_PREFIX)" NFS_DIAG="./$(TARGET)" tests/run-fixture-tests.sh

test-fixtures-list:
	tests/run-fixture-tests.sh --list

test-fixture-%: $(TARGET)
	DOCKER="$(DOCKER)" DOCKER_TAG_PREFIX="$(DOCKER_TAG_PREFIX)" NFS_DIAG="./$(TARGET)" tests/run-fixture-tests.sh $*

SHELL := /bin/sh

VERSION := $(shell cat VERSION)
PKG_NAME := nfsdiag
DEB_ARCH := $(shell dpkg --print-architecture 2>/dev/null || uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
RPM_ARCH := $(shell uname -m)
BIN_DIST := $(PKG_NAME)-$(VERSION)-linux-$(RPM_ARCH)

CC ?= gcc
PKG_CONFIG ?= pkg-config
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
MANDIR ?= $(PREFIX)/share/man/man8
BASHCOMPDIR ?= $(PREFIX)/share/bash-completion/completions
ZSHCOMPDIR ?= $(PREFIX)/share/zsh/site-functions
FISHCOMPDIR ?= $(PREFIX)/share/fish/vendor_completions.d
DESTDIR ?=

TARGET := nfsdiag
SRCDIR := src
SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(SRCS:.c=.o)

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

CPPFLAGS += -D_GNU_SOURCE $(TIRPC_CFLAGS)
LDLIBS += $(TIRPC_LIBS)

DOCKER ?= docker
DOCKERFILES := $(sort $(wildcard dockerfiles/Dockerfile.*))
DOCKER_TAG_PREFIX ?= nfsdiag-fixture

# Static analysis: cppcheck. Suppressions cover only false positives:
#   *:*/tirpc/*  -> findings inside the libtirpc system headers (not our code)
#   staticFunction -> functions declared in nfsdiag.h and used cross-TU; --force
#                     analyses each .c in isolation and cannot see the usage
#   normalCheckLevelMaxBranches / checkersReport -> informational notes only
#   readdirCalled -> suggests readdir_r, which is deprecated by glibc; nfsdiag
#                    is single-threaded so readdir is safe
#   unmatchedSuppression -> different cppcheck versions emit different finding
#                           sets, so some suppressions are unmatched on any
#                           given version; without this the CI and local runs
#                           need version-specific suppression lists
CPPCHECK ?= cppcheck
CPPCHECK_FLAGS := -q --enable=all --inconclusive --std=c11 --library=posix \
	--platform=unix64 --force --inline-suppr --error-exitcode=1 \
	--suppress=missingIncludeSystem \
	--suppress=normalCheckLevelMaxBranches \
	--suppress=checkersReport \
	--suppress='*:*/tirpc/*' \
	--suppress=staticFunction \
	--suppress=readdirCalled \
	--suppress=unmatchedSuppression \
	-D_GNU_SOURCE $(TIRPC_CFLAGS)

.PHONY: all clean distclean rebuild check test-unit cppcheck sbom help install uninstall coverage docker-list docker-build-all test-fixtures test-fixtures-list test-fixture-% $(DOCKERFILES:dockerfiles/Dockerfile.%=docker-build-%) deb rpm apk binary-dist packages release bump-packaging bump-version-bugfix bump-version-minor bump-version-major

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(SRCDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/nfsdiag.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

rebuild: clean all

check: $(TARGET) test-unit
	./$(TARGET) --help >/dev/null
	./$(TARGET) --self-test >/dev/null
	@echo "self-check passed"

test-unit:
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit-tests.c src/validation.c -o build-unit-tests $(LDLIBS)
	./build-unit-tests
	rm -f build-unit-tests

cppcheck:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(SRCDIR)

sbom:
	mkdir -p build
	@{ \
	  echo '{'; \
	  echo '  "spdxVersion": "SPDX-2.3",'; \
	  echo '  "name": "$(PKG_NAME)-$(VERSION)",'; \
	  echo '  "files": ['; \
	  first=1; \
	  for f in $$(git ls-files 2>/dev/null || find . -type f | sed 's#^\./##'); do \
	    [ "$$first" = 1 ] || echo ','; \
	    first=0; \
	    printf '    {"fileName": "%s"}' "$$f"; \
	  done; \
	  echo ''; \
	  echo '  ]'; \
	  echo '}'; \
	} > build/$(PKG_NAME)-$(VERSION).spdx.json
	@echo "SBOM: build/$(PKG_NAME)-$(VERSION).spdx.json"

install: $(TARGET)
	install -d "$(DESTDIR)$(BINDIR)"
	install -m 0755 $(TARGET) "$(DESTDIR)$(BINDIR)/$(TARGET)"
	install -d "$(DESTDIR)$(MANDIR)"
	install -m 0644 docs/nfsdiag.8 "$(DESTDIR)$(MANDIR)/nfsdiag.8"
	install -d "$(DESTDIR)$(BASHCOMPDIR)"
	install -m 0644 completions/nfsdiag.bash "$(DESTDIR)$(BASHCOMPDIR)/nfsdiag"
	install -d "$(DESTDIR)$(ZSHCOMPDIR)"
	install -m 0644 completions/nfsdiag.zsh "$(DESTDIR)$(ZSHCOMPDIR)/_nfsdiag"
	install -d "$(DESTDIR)$(FISHCOMPDIR)"
	install -m 0644 completions/nfsdiag.fish "$(DESTDIR)$(FISHCOMPDIR)/nfsdiag.fish"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"
	rm -f "$(DESTDIR)$(MANDIR)/nfsdiag.8"
	rm -f "$(DESTDIR)$(BASHCOMPDIR)/nfsdiag"
	rm -f "$(DESTDIR)$(ZSHCOMPDIR)/_nfsdiag"
	rm -f "$(DESTDIR)$(FISHCOMPDIR)/nfsdiag.fish"

# ---- Code coverage (gcov/lcov) ----
coverage:
	$(MAKE) "CFLAGS=-O0 -g --coverage" "LDFLAGS=--coverage" rebuild
	@echo "Run tests to generate coverage data, then:"
	@echo "  lcov --capture --directory src --output-file coverage.info"
	@echo "  genhtml coverage.info --output-directory coverage-html"
	@echo "  open coverage-html/index.html"

clean:
	rm -f $(TARGET) $(SRCDIR)/*.o build-unit-tests VERSION.tmp
	rm -rf build/

distclean: clean
	rm -rf .cache coverage-html coverage.info
	find src -name '*.gcda' -o -name '*.gcno' | xargs rm -f 2>/dev/null || true

help:
	@echo "Targets:"
	@echo "  all                  Build $(TARGET)"
	@echo "  rebuild              Clean and build"
	@echo "  check                Run a minimal CLI self-check"
	@echo "  test-unit            Run pure helper unit tests"
	@echo "  cppcheck             Run cppcheck static analysis (fails on findings)"
	@echo "  sbom                 Generate a minimal SPDX-style SBOM in build/"
	@echo "  install              Install binary, man page, and shell completions to DESTDIR/PREFIX, default $(PREFIX)"
	@echo "  uninstall            Remove installed files"
	@echo "  coverage             Build with gcov/lcov coverage instrumentation"
	@echo "  clean                Remove build artifacts"
	@echo "  distclean            Remove build/cache artifacts"
	@echo "  docker-list          List available failure fixture Dockerfiles"
	@echo "  docker-build-X       Build dockerfiles/Dockerfile.X as $(DOCKER_TAG_PREFIX):X"
	@echo "  docker-build-all     Build all fixture images"
	@echo "  test-fixtures        Run automated Docker fixture tests"
	@echo "  test-fixture-X       Run one automated Docker fixture test"
	@echo ""
	@echo "Packaging:"
	@echo "  deb                  Build Debian package (.deb) in build/"
	@echo "  rpm                  Build RPM package (.rpm) in build/"
	@echo "  apk                  Build Alpine package (.apk) via Docker in build/"
	@echo "  binary-dist          Stage a standalone versioned binary in build/"
	@echo "  packages             Build all packages plus the standalone binary and SBOM"
	@echo "  release              Tag, push, and create GitHub release with packages, binary, SBOM, and checksums"
	@echo ""
	@echo "Version bumping:"
	@echo "  bump-version-bugfix  Bump patch version (x.y.Z+1)"
	@echo "  bump-version-minor   Bump minor version (x.Y+1.0)"
	@echo "  bump-version-major   Bump major version (X+1.0.0)"


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

# --------------------------------------------------------------------------
# Packaging
# --------------------------------------------------------------------------

deb: $(TARGET)
	@echo "Building DEB package..."
	mkdir -p build/deb/$(PKG_NAME)_$(VERSION)_$(DEB_ARCH)/DEBIAN
	mkdir -p build/deb/$(PKG_NAME)_$(VERSION)_$(DEB_ARCH)/usr/bin
	install -m 0755 $(TARGET) build/deb/$(PKG_NAME)_$(VERSION)_$(DEB_ARCH)/usr/bin/$(TARGET)
	sed -e "s/^Version: .*/Version: $(VERSION)/" \
	    -e "s/^Architecture: .*/Architecture: $(DEB_ARCH)/" \
	    packaging/nfsdiag.control > build/deb/$(PKG_NAME)_$(VERSION)_$(DEB_ARCH)/DEBIAN/control
	dpkg-deb --root-owner-group --build build/deb/$(PKG_NAME)_$(VERSION)_$(DEB_ARCH)
	mv build/deb/$(PKG_NAME)_$(VERSION)_$(DEB_ARCH).deb build/
	@echo "DEB: build/$(PKG_NAME)_$(VERSION)_$(DEB_ARCH).deb"

rpm: $(TARGET)
	@echo "Building RPM package..."
	mkdir -p build/rpm/BUILD build/rpm/RPMS build/rpm/SOURCES build/rpm/SPECS build/rpm/SRPMS
	sed "s/^Version:[[:space:]]*.*/Version:        $(VERSION)/" \
	    packaging/nfsdiag.spec > build/rpm/SPECS/nfsdiag.spec
	rpmbuild -bb \
	    --define "_topdir $$(pwd)/build/rpm" \
	    --define "srcdir $$(pwd)" \
	    build/rpm/SPECS/nfsdiag.spec
	find build/rpm/RPMS -name "*.rpm" -exec cp {} build/ \;
	@echo "RPM: build/$(PKG_NAME)-$(VERSION)-1.$(RPM_ARCH).rpm"

apk:
	@echo "Building APK package via Docker..."
	DOCKER_BUILDKIT=0 docker build \
	    --build-arg VERSION=$(VERSION) \
	    --target builder \
	    -t $(PKG_NAME)-apk-builder \
	    -f packaging/Dockerfile.apk .
	mkdir -p build/apk
	docker run --rm \
	    -v $$(pwd)/build/apk:/out \
	    $(PKG_NAME)-apk-builder \
	    sh -c 'find /home/builder/packages -name "*.apk" -exec cp {} /out/ \;'
	cp build/apk/*.apk build/ || true
	@echo "APK: build/$(PKG_NAME)-$(VERSION)-r0.apk (approx name)"

# Standalone, versioned, arch-named binary for direct download from releases.
binary-dist: $(TARGET)
	mkdir -p build
	install -m 0755 $(TARGET) build/$(BIN_DIST)
	@echo "Binary: build/$(BIN_DIST)"

packages: $(TARGET) sbom binary-dist
	mkdir -p build
	-$(MAKE) deb
	-$(MAKE) rpm
	-$(MAKE) apk
	@echo "Package build phase completed (see above for any failures)."

release: packages
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "Error: working directory is not clean. Commit or stash changes first."; \
		exit 1; \
	fi
	@echo "Creating GitHub release v$(VERSION)..."
	@if git rev-parse v$(VERSION) >/dev/null 2>&1; then \
		echo "Tag v$(VERSION) already exists, skipping tag creation."; \
	else \
		git tag -a v$(VERSION) -m "Release v$(VERSION)"; \
		git push origin v$(VERSION); \
	fi
	@echo "Generating SHA256SUMS for all artifacts..."
	@( cd build && rm -f SHA256SUMS; \
	   for f in *.deb *.rpm *.apk $(BIN_DIST) *.spdx.json; do \
	       [ -f "$$f" ] && sha256sum "$$f" >> SHA256SUMS; \
	   done; true )
	@assets=""; \
	for f in build/*.deb build/*.rpm build/*.apk build/$(BIN_DIST) build/*.spdx.json build/SHA256SUMS; do \
		[ -f "$$f" ] && assets="$$assets $$f"; \
	done; \
	if [ -n "$$assets" ]; then \
		echo "Uploading:$$assets"; \
		gh release create v$(VERSION) $$assets \
		    --title "v$(VERSION)" \
		    --notes "Release v$(VERSION)" 2>/dev/null || \
		gh release upload v$(VERSION) $$assets --clobber; \
	else \
		echo "No artifacts found; creating empty release."; \
		gh release create v$(VERSION) \
		    --title "v$(VERSION)" \
		    --notes "Release v$(VERSION)" 2>/dev/null || true; \
	fi
	@echo "Release v$(VERSION) done."

# --------------------------------------------------------------------------
# Version bumping
# --------------------------------------------------------------------------

bump-packaging:
	@ver=$$(cat VERSION); \
	sed -i "s/#define NFSDIAG_VERSION \"[^\"]*\"/#define NFSDIAG_VERSION \"$$ver\"/" src/nfsdiag.h; \
	sed -i "s/^Version: .*/Version: $$ver/" packaging/nfsdiag.control; \
	sed -i "s/^Version:[[:space:]]*.*/Version:        $$ver/" packaging/nfsdiag.spec; \
	sed -i "s/^ARG VERSION=.*/ARG VERSION=$$ver/" packaging/Dockerfile.apk; \
	sed -i "s/^pkgver=.*/pkgver=$$ver/" packaging/aur/PKGBUILD; \
	sed -i "s/version = \"[^\"]*\";/version = \"$$ver\";/" packaging/nix/flake.nix; \
	sed -i "s|/v[0-9][0-9.]*\.tar\.gz|/v$$ver.tar.gz|; s/version \"[^\"]*\"/version \"$$ver\"/" packaging/homebrew/nfsdiag.rb; \
	sed -i "s/\"nfsdiag [^\"]*\"/\"nfsdiag $$ver\"/" docs/nfsdiag.8; \
	sed -i "s|Current version: <strong>[^<]*</strong>|Current version: <strong>$$ver</strong>|" website/index.html; \
	sed -i "s|<strong>nfsdiag</strong> v[0-9][0-9.]*|<strong>nfsdiag</strong> v$$ver|" website/docs.html; \
	sed -i "s/nfsdiag [0-9][0-9.]*: /nfsdiag $$ver: /g" website/index.html website/docs.html; \
	sed -i "s|nfsdiag <strong>v[^<]*</strong>|nfsdiag <strong>v$$ver</strong>|g" website/index.html website/docs.html website/author.html; \
	sed -i "s|\(NFSDIAG_VERSION.*\)\"[0-9][^\"]*\"|\1\"$$ver\"|" website/docs.html; \
	sed -i "s/^Current version: \*\*[^*]*\*\*/Current version: **$$ver**/" CLAUDE.md; \
	sed -i "s/NFSDIAG_VERSION \"[^\"]*\"/NFSDIAG_VERSION \"$$ver\"/" CLAUDE.md

bump-version-bugfix:
	@awk -F. '{print $$1"."$$2"."$$3+1}' VERSION > VERSION.tmp && mv VERSION.tmp VERSION
	@$(MAKE) bump-packaging
	@echo "Bumped to $$(cat VERSION)"

bump-version-minor:
	@awk -F. '{print $$1"."$$2+1".0"}' VERSION > VERSION.tmp && mv VERSION.tmp VERSION
	@$(MAKE) bump-packaging
	@echo "Bumped to $$(cat VERSION)"

bump-version-major:
	@awk -F. '{print $$1+1".0.0"}' VERSION > VERSION.tmp && mv VERSION.tmp VERSION
	@$(MAKE) bump-packaging
	@echo "Bumped to $$(cat VERSION)"

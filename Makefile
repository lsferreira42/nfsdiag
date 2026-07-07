SHELL := /bin/sh

-include config.mk

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
DOCDIR ?= $(PREFIX)/share/doc/$(PKG_NAME)
DESTDIR ?=

TARGET := nfsdiag
SRCDIR := src
SRCS := $(wildcard $(SRCDIR)/*.c)
OBJS := $(SRCS:.c=.o)

ifeq ($(strip $(TIRPC_CFLAGS)),)
TIRPC_CFLAGS := $(shell $(PKG_CONFIG) --cflags libtirpc 2>/dev/null)
endif
ifeq ($(strip $(TIRPC_CFLAGS)),)
TIRPC_CFLAGS := -I/usr/include/tirpc
endif
ifeq ($(strip $(TIRPC_LIBS)),)
TIRPC_LIBS := $(shell $(PKG_CONFIG) --libs libtirpc 2>/dev/null)
endif
ifeq ($(strip $(TIRPC_LIBS)),)
TIRPC_LIBS := -ltirpc
endif

CPPFLAGS ?=
CFLAGS ?= -O2 -Wall -Wextra
LDFLAGS ?=
LDLIBS ?=

CPPFLAGS += -D_GNU_SOURCE $(TIRPC_CFLAGS) $(EBPF_CPPFLAGS) $(BPF_CFLAGS)
LDLIBS += $(TIRPC_LIBS) $(BPF_LIBS)

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
SHELLCHECK ?= shellcheck
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
	-i src/bpf -i src/ebpf.c -i src/ebpf_latency.c \
	-D_GNU_SOURCE $(TIRPC_CFLAGS)

.PHONY: all clean distclean rebuild strict compile-commands check test-unit check-versions check-json-schema check-output-golden check-cli-docs check-subcommands check-server check-website check-signals shellcheck cppcheck sbom help install uninstall coverage docker-list docker-build-all test-fixtures test-fixtures-list test-fixture-% $(DOCKERFILES:dockerfiles/Dockerfile.%=docker-build-%) deb rpm apk binary-dist packages packages-best-effort release release-check update-release-checksums bump-packaging bump-version-bugfix bump-version-minor bump-version-major

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LDLIBS) -o $@

$(SRCDIR)/%.o: $(SRCDIR)/%.c $(SRCDIR)/nfsdiag.h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

rebuild: clean all

# Stricter local build surface than CI's -Werror; opt-in for contributors.
strict:
	$(MAKE) "CFLAGS=-O2 -Wall -Wextra -Werror -Wshadow -Wconversion -Wpointer-arith" rebuild

# Generate compile_commands.json for clangd/clang-tidy. Requires 'bear'.
compile-commands:
	bear -- $(MAKE) rebuild
	@echo "compile_commands.json generated"

check: $(TARGET) test-unit check-versions check-json-schema check-output-golden check-cli-docs check-subcommands check-server
	./$(TARGET) --help >/dev/null
	./$(TARGET) client --self-test >/dev/null
	@echo "self-check passed"

# Fail if a --help option is undocumented in README/man/website/completions.
check-cli-docs: $(TARGET)
	sh tests/check-cli-docs.sh

# Subcommand dispatch: client/server/diff/help/version + deprecated alias.
check-subcommands: $(TARGET)
	sh tests/check-subcommands.sh

# Server-namespace checks against synthetic fixtures (--root).
check-server: $(TARGET)
	sh tests/check-server.sh

# Assert the four structured renderers agree on counters and are well-formed.
check-output-golden: $(TARGET)
	sh tests/check-output-golden.sh

# Static validation of the website (HTML well-formedness + internal links).
check-website:
	sh tests/check-website.sh

# Signal handling and post-run cleanup on the unprivileged paths.
check-signals: $(TARGET)
	sh tests/check-signals.sh

test-unit:
	$(CC) $(CPPFLAGS) $(CFLAGS) tests/unit-tests.c src/validation.c src/util.c src/server_exports.c src/server_checks.c -o build-unit-tests $(LDLIBS)
	./build-unit-tests
	rm -f build-unit-tests

# Fail if any versioned artifact drifts from VERSION.
check-versions:
	sh tests/check-versions.sh

# Validate that the live JSON report matches the published schema.
check-json-schema: $(TARGET)
	sh tests/check-json-schema.sh

shellcheck:
	$(SHELLCHECK) tests/*.sh dockerfiles/common/*.sh

cppcheck:
	$(CPPCHECK) $(CPPCHECK_FLAGS) $(SRCDIR)

# Aggregate gate to run before tagging a release. Stops on the first failure.
release-check: check cppcheck shellcheck check-website check-signals
	@echo "release-check passed for $(VERSION)"

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
	install -d "$(DESTDIR)$(DOCDIR)"
	install -m 0644 LICENSE "$(DESTDIR)$(DOCDIR)/LICENSE"
	install -m 0644 docs/nfsdiag.schema.json "$(DESTDIR)$(DOCDIR)/nfsdiag.schema.json"

uninstall:
	rm -f "$(DESTDIR)$(BINDIR)/$(TARGET)"
	rm -f "$(DESTDIR)$(MANDIR)/nfsdiag.8"
	rm -f "$(DESTDIR)$(BASHCOMPDIR)/nfsdiag"
	rm -f "$(DESTDIR)$(ZSHCOMPDIR)/_nfsdiag"
	rm -f "$(DESTDIR)$(FISHCOMPDIR)/nfsdiag.fish"
	rm -f "$(DESTDIR)$(DOCDIR)/LICENSE"
	rm -f "$(DESTDIR)$(DOCDIR)/nfsdiag.schema.json"
	-rmdir "$(DESTDIR)$(DOCDIR)" 2>/dev/null || true

# --------------------------------------------------------------------------
# eBPF objects (only when ./configure --enable-ebpf set ENABLE_EBPF=1)
# --------------------------------------------------------------------------
ifeq ($(ENABLE_EBPF),1)
BPF_DIR   := src/bpf
VMLINUX   := $(BPF_DIR)/vmlinux.h
BPF_SRC   := $(BPF_DIR)/nfsdiag.bpf.c
BPF_OBJ   := $(BPF_DIR)/nfsdiag.bpf.o
BPF_SKEL  := $(BPF_DIR)/nfsdiag.skel.h

$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BPF_OBJ): $(BPF_SRC) $(VMLINUX)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(BPF_TARGET_ARCH) -I$(BPF_DIR) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) name nfsdiag_bpf > $@

# These TUs include the generated skeleton, so it must exist first.
$(SRCDIR)/ebpf.o: $(BPF_SKEL)
$(SRCDIR)/ebpf_latency.o: $(BPF_SKEL)
endif

# ---- Code coverage (gcov/lcov) ----
coverage:
	$(MAKE) "CFLAGS=-O0 -g --coverage" "LDFLAGS=--coverage" rebuild
	@echo "Run tests to generate coverage data, then:"
	@echo "  lcov --capture --directory src --output-file coverage.info"
	@echo "  genhtml coverage.info --output-directory coverage-html"
	@echo "  open coverage-html/index.html"

clean:
	rm -f $(TARGET) $(SRCDIR)/*.o build-unit-tests VERSION.tmp compile_commands.json
	rm -f $(SRCDIR)/bpf/*.bpf.o $(SRCDIR)/bpf/nfsdiag.skel.h $(SRCDIR)/bpf/vmlinux.h
	rm -rf build/ coverage-html
	rm -f coverage.info
	find $(SRCDIR) -name '*.gcda' -o -name '*.gcno' | xargs rm -f 2>/dev/null || true

# Also removes everything ./configure generated, leaving only tracked files.
distclean: clean
	rm -rf .cache autom4te.cache
	rm -f config.mk config.log config.status configure~

help:
	@echo "Targets:"
	@echo "  all                  Build $(TARGET)"
	@echo "  rebuild              Clean and build"
	@echo "  strict               Rebuild with extra warnings as errors (-Wconversion etc.)"
	@echo "  compile-commands     Generate compile_commands.json via 'bear' (clangd/clang-tidy)"
	@echo "  check                Run unit tests, version/schema checks and a CLI self-check"
	@echo "  test-unit            Run pure helper unit tests"
	@echo "  check-versions       Fail if any versioned artifact drifts from VERSION"
	@echo "  check-json-schema    Validate the live JSON report against docs/nfsdiag.schema.json"
	@echo "  check-output-golden  Assert JSON/NDJSON/JUnit/Prometheus agree on counters"
	@echo "  check-website        Validate website HTML and internal links"
	@echo "  check-signals        Check SIGINT/SIGTERM handling and post-run cleanup"
	@echo "  shellcheck           Lint the shell scripts (tests and docker entrypoints)"
	@echo "  cppcheck             Run cppcheck static analysis (fails on findings)"
	@echo "  release-check        Run check + cppcheck + shellcheck before tagging"
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
	@echo "  packages             Build all packages plus the standalone binary and SBOM (fails on any package error)"
	@echo "  packages-best-effort Build packages but keep going past failures (local convenience)"
	@echo "  release              Validate tree, tag v\$$VERSION and push; the release workflow publishes artifacts"
	@echo "  update-release-checksums  Refresh tarball sha256 in the Homebrew formula and AUR PKGBUILD"
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
	$(eval DEB_ROOT := build/deb/$(PKG_NAME)_$(VERSION)_$(DEB_ARCH))
	mkdir -p $(DEB_ROOT)/DEBIAN
	mkdir -p $(DEB_ROOT)/usr/bin
	mkdir -p $(DEB_ROOT)/usr/share/man/man8
	mkdir -p $(DEB_ROOT)/usr/share/bash-completion/completions
	mkdir -p $(DEB_ROOT)/usr/share/zsh/vendor-completions
	mkdir -p $(DEB_ROOT)/usr/share/fish/vendor_completions.d
	mkdir -p $(DEB_ROOT)/usr/share/doc/$(PKG_NAME)
	install -m 0755 $(TARGET) $(DEB_ROOT)/usr/bin/$(TARGET)
	gzip -9n < docs/nfsdiag.8 > $(DEB_ROOT)/usr/share/man/man8/nfsdiag.8.gz
	install -m 0644 completions/nfsdiag.bash $(DEB_ROOT)/usr/share/bash-completion/completions/nfsdiag
	install -m 0644 completions/nfsdiag.zsh $(DEB_ROOT)/usr/share/zsh/vendor-completions/_nfsdiag
	install -m 0644 completions/nfsdiag.fish $(DEB_ROOT)/usr/share/fish/vendor_completions.d/nfsdiag.fish
	install -m 0644 LICENSE $(DEB_ROOT)/usr/share/doc/$(PKG_NAME)/copyright
	sed -e "s/^Version: .*/Version: $(VERSION)/" \
	    -e "s/^Architecture: .*/Architecture: $(DEB_ARCH)/" \
	    packaging/nfsdiag.control > $(DEB_ROOT)/DEBIAN/control
	dpkg-deb --root-owner-group --build $(DEB_ROOT)
	mv $(DEB_ROOT).deb build/
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
	mkdir -p build
	docker run --rm \
	    -v $$(pwd)/build:/out \
	    $(PKG_NAME)-apk-builder \
	    sh -c 'find /home/builder/packages -name "*.apk" -exec cp {} /out/ \;'
	@ls build/*.apk >/dev/null 2>&1 || { echo "Error: abuild produced no .apk (see the Docker build log above)"; exit 1; }
	@echo "APK: $$(ls build/*.apk)"

# Standalone, versioned, arch-named binary for direct download from releases.
binary-dist: $(TARGET)
	mkdir -p build
	install -m 0755 $(TARGET) build/$(BIN_DIST)
	@echo "Binary: build/$(BIN_DIST)"

# Release path: any package failure must abort. Do not add '-' prefixes here.
packages: $(TARGET) sbom binary-dist
	mkdir -p build
	$(MAKE) deb
	$(MAKE) rpm
	$(MAKE) apk
	@echo "All packages built under build/."

# Local convenience: keep going past a failing builder (e.g. no docker for APK).
# Not for release — use 'packages' there.
packages-best-effort: $(TARGET) sbom binary-dist
	mkdir -p build
	-$(MAKE) deb
	-$(MAKE) rpm
	-$(MAKE) apk
	@echo "Package build phase completed (failures above were ignored)."

# The tag push triggers .github/workflows/release.yml, which is the single
# canonical builder/publisher of release artifacts. This target only
# validates the tree and pushes the tag — it never uploads artifacts itself.
release:
	@if [ -n "$$(git status --porcelain)" ]; then \
		echo "Error: working directory is not clean. Commit or stash changes first."; \
		exit 1; \
	fi
	@if ! grep -q "NFSDIAG_VERSION \"$(VERSION)\"" src/nfsdiag.h; then \
		echo "Error: VERSION ($(VERSION)) and src/nfsdiag.h disagree. Run 'make bump-packaging'."; \
		exit 1; \
	fi
	@if git rev-parse v$(VERSION) >/dev/null 2>&1; then \
		echo "Tag v$(VERSION) already exists."; \
	else \
		git tag -a v$(VERSION) -m "Release v$(VERSION)"; \
	fi
	git push origin v$(VERSION)
	@echo "Tag v$(VERSION) pushed. The release workflow will build and publish the artifacts."
	@echo "After the release exists, run 'make update-release-checksums' and commit the result."

# Refresh the source-tarball checksums in the Homebrew formula and the AUR
# PKGBUILD. Requires the v$(VERSION) tag to exist on GitHub (run after
# 'make release', then commit the result).
update-release-checksums:
	@url="https://github.com/lsferreira42/nfsdiag/archive/refs/tags/v$(VERSION).tar.gz"; \
	echo "Fetching $$url"; \
	sha=$$(curl -fsSL "$$url" | sha256sum | cut -d' ' -f1); \
	[ -n "$$sha" ] || { echo "Error: could not compute sha256"; exit 1; }; \
	sed -i "s|^  url \".*\"|  url \"$$url\"|; \
	        s/^  sha256 \".*\"/  sha256 \"$$sha\"/; \
	        s/^  version \".*\"/  version \"$(VERSION)\"/" packaging/homebrew/nfsdiag.rb; \
	sed -i "s/^sha256sums=.*/sha256sums=('$$sha')/" packaging/aur/PKGBUILD; \
	echo "homebrew formula and PKGBUILD updated (sha256 $$sha)"

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
	sed -i "s/version = \"[^\"]*\";/version = \"$$ver\";/" flake.nix; \
	sed -i "s|/v[0-9][0-9.]*\.tar\.gz|/v$$ver.tar.gz|; s/version \"[^\"]*\"/version \"$$ver\"/" packaging/homebrew/nfsdiag.rb; \
	sed -i "s/\"nfsdiag [^\"]*\"/\"nfsdiag $$ver\"/" docs/nfsdiag.8; \
	sed -i "s/^\.TH NFSDIAG 8 \"[^\"]*\"/.TH NFSDIAG 8 \"$$(date +%Y-%m-%d)\"/" docs/nfsdiag.8; \
	sed -i "s/\"softwareVersion\": \"[^\"]*\"/\"softwareVersion\": \"$$ver\"/" website/index.html; \
	sed -i "s|<lastmod>[^<]*</lastmod>|<lastmod>$$(date +%Y-%m-%d)</lastmod>|g" website/sitemap.xml; \
	sed -i "s|Current version: <strong>[^<]*</strong>|Current version: <strong>$$ver</strong>|" website/index.html; \
	sed -i "s|<strong>nfsdiag</strong> v[0-9][0-9.]*|<strong>nfsdiag</strong> v$$ver|" website/docs.html website/docs-server.html; \
	sed -i "s/nfsdiag [0-9][0-9.]*: /nfsdiag $$ver: /g" website/index.html website/docs.html website/docs-server.html; \
	sed -i "s|nfsdiag <strong>v[^<]*</strong>|nfsdiag <strong>v$$ver</strong>|g" website/index.html website/docs.html website/docs-server.html website/author.html; \
	sed -i "s|\(NFSDIAG_VERSION.*\)\"[0-9][^\"]*\"|\1\"$$ver\"|" website/docs.html; \
	if ! grep -q -- "- $$ver-1\$$" packaging/nfsdiag.spec; then \
		awk -v ver="$$ver" -v d="$$(LC_ALL=C date '+%a %b %d %Y')" \
		    '{print} /^%changelog/ && !done {print "* " d " Leandro Ferreira <leandrodsferreira@gmail.com> - " ver "-1"; print "- See CHANGELOG.md for details"; done=1}' \
		    packaging/nfsdiag.spec > packaging/nfsdiag.spec.tmp && \
		mv packaging/nfsdiag.spec.tmp packaging/nfsdiag.spec; \
	fi

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

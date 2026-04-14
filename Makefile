CC       ?= cc
# Required flags are in MEMLIMIT_CFLAGS so user/distro CFLAGS are respected.
# Note: _FORTIFY_SOURCE requires -O1 or higher to take effect.
MEMLIMIT_CFLAGS = -std=c11 -Wall -Wextra -Werror -Wpedantic \
                  -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS   ?= -O2
LDFLAGS  ?=
PREFIX   ?= /usr/local
BINDIR   ?= $(PREFIX)/bin

TARGET    = memlimit
SRC       = memlimit.c

# --- Build ---

.PHONY: all test clean install uninstall update-tap

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(MEMLIMIT_CFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

# --- Test ---

test_alloc: test_alloc.c
	$(CC) -Wall -Wextra -Werror $(CFLAGS) -o $@ $<

test: $(TARGET) test_alloc
	@./test.sh ./$(TARGET)

# --- Install / Uninstall ---

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

# --- Homebrew Tap ---

TAP_REPO  = rmk40/homebrew-tap
FORMULA   = Formula/memlimit.rb

# Usage: make update-tap VERSION=1.0.1
# Requires GH_TOKEN with write access to $(TAP_REPO).
update-tap:
ifndef VERSION
	$(error VERSION is required (e.g. make update-tap VERSION=1.0.1))
endif
	@set -e; \
	TMPDIR=$$(mktemp -d); \
	trap 'rm -rf "$$TMPDIR"' EXIT; \
	TARBALL_URL="https://github.com/rmk40/memlimit/archive/refs/tags/v$(VERSION).tar.gz"; \
	curl -sfL "$$TARBALL_URL" -o "$$TMPDIR/src.tar.gz"; \
	SHA256=$$(sha256sum "$$TMPDIR/src.tar.gz" 2>/dev/null \
	         || shasum -a 256 "$$TMPDIR/src.tar.gz"); \
	SHA256=$${SHA256%% *}; \
	printf '%s\n' \
	  'class Memlimit < Formula' \
	  '  desc "Zero-dependency memory limiter using phys_footprint (macOS) and PSS (Linux)"' \
	  '  homepage "https://github.com/rmk40/memlimit"' \
	  '  url "https://github.com/rmk40/memlimit/archive/refs/tags/v$(VERSION).tar.gz"' \
	  "  sha256 \"$$SHA256\"" \
	  '  license "MIT"' \
	  '' \
	  '  def install' \
	  '    system "make", "install", "PREFIX=#{prefix}"' \
	  '  end' \
	  '' \
	  '  test do' \
	  '    assert_match "memlimit #{version}", shell_output("#{bin}/memlimit --version")' \
	  '    system bin/"memlimit", "1G", "--", "true"' \
	  '  end' \
	  'end' > "$$TMPDIR/memlimit.rb"; \
	FORMULA_SHA=$$(gh api "repos/$(TAP_REPO)/contents/$(FORMULA)" --jq '.sha'); \
	CONTENT=$$(base64 < "$$TMPDIR/memlimit.rb" | tr -d '\n'); \
	gh api "repos/$(TAP_REPO)/contents/$(FORMULA)" \
	  --method PUT \
	  --field message="Update memlimit to $(VERSION)" \
	  --field content="$$CONTENT" \
	  --field sha="$$FORMULA_SHA"; \
	echo "Updated $(TAP_REPO) to $(VERSION)"

# --- Clean ---

clean:
	rm -f $(TARGET) memlimit_asan test_alloc

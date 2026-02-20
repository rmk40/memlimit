CC       ?= cc
# Required flags are in MEMLIMIT_CFLAGS so user/distro CFLAGS are respected.
# Note: _FORTIFY_SOURCE requires -O1 or higher to take effect.
MEMLIMIT_CFLAGS = -std=c11 -Wall -Wextra -Werror -Wpedantic \
                  -fstack-protector-strong -D_FORTIFY_SOURCE=2
CFLAGS   ?= -O2
LDFLAGS  ?=
PREFIX    = /usr/local
BINDIR    = $(PREFIX)/bin

TARGET    = memlimit
SRC       = memlimit.c

# --- Build ---

.PHONY: all test clean install uninstall

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(MEMLIMIT_CFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

# --- Test ---

test_alloc: test_alloc.c
	$(CC) -O2 -o $@ $<

test: $(TARGET) test_alloc
	@./test.sh ./$(TARGET)

# --- Install / Uninstall ---

install: $(TARGET)
	install -d $(DESTDIR)$(BINDIR)
	install -m 755 $(TARGET) $(DESTDIR)$(BINDIR)/$(TARGET)

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/$(TARGET)

# --- Clean ---

clean:
	rm -f $(TARGET) test_alloc

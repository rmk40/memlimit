/*
 * test_alloc - allocate memory and sleep.
 *
 * Test helper for memlimit.  Allocates the requested amount of memory,
 * touches every page to ensure it's resident, then sleeps.
 *
 * Usage: test_alloc <SIZE> [SECONDS]
 *
 * SIZE accepts the same suffixes as memlimit: G, M, K, or plain bytes.
 * SECONDS defaults to 30.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int parse_size(const char *str, size_t *out)
{
    char *endptr = NULL;
    unsigned long long val = strtoull(str, &endptr, 10);
    if (endptr == str || val == 0)
        return 0;

    size_t multiplier = 1;
    if (endptr != NULL && *endptr != '\0') {
        switch (*endptr) {
        case 'G': case 'g': multiplier = (size_t)1 << 30; break;
        case 'M': case 'm': multiplier = (size_t)1 << 20; break;
        case 'K': case 'k': multiplier = (size_t)1 << 10; break;
        case 'B': case 'b': multiplier = 1;                break;
        default: return 0;
        }
        if (endptr[1] != '\0')
            return 0;
    }

    *out = (size_t)val * multiplier;
    return 1;
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: test_alloc <SIZE> [SECONDS]\n");
        return 1;
    }

    size_t nbytes = 0;
    if (!parse_size(argv[1], &nbytes)) {
        fprintf(stderr, "test_alloc: invalid size: %s\n", argv[1]);
        return 1;
    }

    int seconds = 30;
    if (argc >= 3)
        seconds = atoi(argv[2]);

    char *buf = malloc(nbytes);
    if (buf == NULL) {
        fprintf(stderr, "test_alloc: malloc(%zu) failed\n", nbytes);
        return 1;
    }

    /*
     * Write unique data into every page.  A uniform fill like
     * memset(buf, 0xAA, n) gets compressed by macOS's memory
     * compressor, so phys_footprint stays tiny despite touching
     * every byte.  Writing the page offset defeats compression and
     * keeps the pages physically resident at their true size.
     *
     * The volatile pointer prevents the compiler from optimizing
     * these writes away as dead stores (nothing reads buf before
     * free, so at -O2 the compiler would otherwise eliminate them).
     */
    volatile char *vbuf = buf;
    for (size_t off = 0; off < nbytes; off += 4096) {
        vbuf[off]     = (char)(off);
        vbuf[off + 1] = (char)(off >> 8);
        vbuf[off + 2] = (char)(off >> 16);
        vbuf[off + 3] = (char)(off >> 24);
    }

    sleep((unsigned)seconds);

    free(buf);
    return 0;
}

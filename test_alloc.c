/*
 * test_alloc - allocate memory and sleep.
 *
 * Test helper for memlimit.  Allocates the requested amount of memory,
 * touches every page to ensure it's resident, then sleeps.
 *
 * Usage: test_alloc <SIZE> [SECONDS]
 *
 * SIZE accepts the same suffixes as memlimit: G, M, K, or plain bytes.
 * Minimum useful size is 4096 (one page).
 * SECONDS defaults to 30.
 */

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int parse_size(const char *str, size_t *out)
{
    if (str == NULL || *str == '\0')
        return 0;

    /* Reject signs/whitespace: size must start with a digit. */
    if (str[0] < '0' || str[0] > '9')
        return 0;

    char *endptr = NULL;
    errno = 0;
    unsigned long long val = strtoull(str, &endptr, 10);
    if (errno == ERANGE || endptr == str || val == 0)
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

    /* overflow check */
    if (multiplier > 1 && val > SIZE_MAX / multiplier)
        return 0;

    *out = (size_t)val * multiplier;
    return *out > 0;
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
    if (argc >= 3) {
        char *endptr = NULL;
        errno = 0;
        long v = strtol(argv[2], &endptr, 10);
        if (errno != 0 || endptr == argv[2] || *endptr != '\0'
            || v <= 0 || v > 3600) {
            fprintf(stderr, "test_alloc: invalid seconds: %s\n", argv[2]);
            return 1;
        }
        seconds = (int)v;
    }

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
        size_t remaining = nbytes - off;
        vbuf[off] = (char)(off);
        if (remaining > 1) vbuf[off + 1] = (char)(off >> 8);
        if (remaining > 2) vbuf[off + 2] = (char)(off >> 16);
        if (remaining > 3) vbuf[off + 3] = (char)(off >> 24);
    }

    sleep((unsigned)seconds);

    free(buf);
    return 0;
}

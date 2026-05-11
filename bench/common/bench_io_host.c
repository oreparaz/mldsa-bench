/* bench_io_host.c — stdout fallback for sanity-checking the bench logic
 * against an x86 build of the same crypto code. */
#include "bench_io.h"
#include <stdio.h>

void bench_emit_hex(const uint8_t *data, size_t n) {
    static const char hexd[16] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        putchar(hexd[data[i] >> 4]);
        putchar(hexd[data[i] & 0xf]);
    }
    putchar('\n');
}

void bench_emit_str(const char *s) {
    fputs(s, stdout);
}

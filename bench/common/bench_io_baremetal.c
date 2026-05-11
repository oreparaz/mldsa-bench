/* bench_io_baremetal.c — emit via ARM Semihosting (BKPT 0xab). */
#include "bench_io.h"
#include "semihost.h"
#include <string.h>

static const char hexd[16] = "0123456789abcdef";

void bench_emit_hex(const uint8_t *data, size_t n) {
    /* Emit one hex pair at a time so we don't need a big stack buffer
     * for ML-DSA sigs which can be >4 KiB. */
    char buf[2];
    for (size_t i = 0; i < n; i++) {
        buf[0] = hexd[data[i] >> 4];
        buf[1] = hexd[data[i] & 0xf];
        bm_write(buf, 2);
    }
    bm_write("\n", 1);
}

void bench_emit_str(const char *s) {
    bm_write(s, strlen(s));
}

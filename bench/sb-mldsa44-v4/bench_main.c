/* sb-mldsa44 v4 — precompute A, t1_ntt, tr_pk. */
#include <stdint.h>
#include <stddef.h>

#include "bench_io.h"
#include "verify_sb.h"
#include "testvec.h"

#ifndef BENCH_ITERS
#  define BENCH_ITERS 1u
#endif

static volatile int g_acc;

int main(void) {
    sb_v4_precompute(sb_pk);

    int rc = 0;
    for (unsigned i = 0; i < BENCH_ITERS; i++) {
        int r = sb_v4_verify(
            sb_sig, SB_SIG_LEN,
            sb_hash, SB_HASH_LEN,
            (const uint8_t *)"", 0,
            sb_pk);
        g_acc ^= r;
        if (r != 0) rc = 1;
    }
    uint8_t out[3];
    out[0] = (uint8_t)0xd4;
    out[1] = (uint8_t)(BENCH_ITERS & 0xff);
    out[2] = (uint8_t)(g_acc & 0xff);
    bench_emit_hex(out, 3);
    return rc;
}

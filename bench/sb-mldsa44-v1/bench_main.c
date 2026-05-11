/* sb-mldsa44-v1 — secure-boot ML-DSA-44 verify, BASELINE.
 *
 * This is the v1 baseline: it calls pqm4's m4f crypto_sign_verify_ctx
 * verbatim, with secure-boot-shaped inputs:
 *   - msg = 32-byte SHA-256("software image")
 *   - ctx = empty
 *   - pk  = fixed (provisioned at first boot)
 *
 * Subsequent versions (v2..vN) progressively specialize away the
 * pk-derived precomputation cost.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bench_io.h"
#include "api.h"           /* pqm4 m4f ml-dsa-44 */
#include "testvec.h"       /* sb_pk, sb_sig, sb_hash */

#ifndef BENCH_ITERS
#  define BENCH_ITERS 1u
#endif

static volatile int g_acc;

int main(void) {
    int rc = 0;
    for (unsigned i = 0; i < BENCH_ITERS; i++) {
        int r = crypto_sign_verify_ctx(
            sb_sig, SB_SIG_LEN,
            sb_hash, SB_HASH_LEN,
            (const uint8_t *)"", 0,
            sb_pk);
        g_acc ^= r;
        if (r != 0) rc = 1;
    }
    uint8_t out[3];
    out[0] = (uint8_t)0xd1;                 /* tag for sb-mldsa44-v1 */
    out[1] = (uint8_t)(BENCH_ITERS & 0xff);
    out[2] = (uint8_t)(g_acc & 0xff);
    bench_emit_hex(out, 3);
    return rc;
}

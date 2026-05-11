/* bench_main.c — measure crypto_sign_verify on a single hard-coded
 * (pk, sig, msg, ctx) tuple. The whole region of interest is between
 * Reset_Handler and bm_exit(), so QEMU's plugin counts iter*verify_cost
 * plus a fixed startup cost. Subtract a 2nd run with a different iter
 * count to cancel startup.
 *
 * Built three ways (mldsa44 / mldsa65 / mldsa87) — only difference is
 * MLD_CONFIG_PARAMETER_SET, which picks the right test vector arm out
 * of expected_test_vectors.h.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bench_io.h"
#include "mldsa_native.h"
#include "expected_test_vectors.h"

#ifndef BENCH_ITERS
#  define BENCH_ITERS 1u
#endif

/* The verify result is XOR'd into this accumulator so the optimizer can't
 * lift the call out of the loop. It also lets us emit a deterministic digest
 * the host build can match. */
static volatile int g_acc;

int main(void) {
    int rc = 0;
    for (unsigned i = 0; i < BENCH_ITERS; i++) {
        int r = crypto_sign_verify(test_vector_sig, sizeof(test_vector_sig),
                                   (const uint8_t *)TEST_VECTOR_MSG,
                                   TEST_VECTOR_MSG_LEN,
                                   (const uint8_t *)TEST_VECTOR_CTX,
                                   TEST_VECTOR_CTX_LEN,
                                   test_vector_pk);
        g_acc ^= r;
        if (r != 0) rc = 1;
    }
    /* Print the parameter set + acc so the digest line is unique per build. */
    uint8_t out[3];
    out[0] = (uint8_t)(MLD_CONFIG_PARAMETER_SET & 0xff);
    out[1] = (uint8_t)((BENCH_ITERS) & 0xff);
    out[2] = (uint8_t)(g_acc & 0xff);
    bench_emit_hex(out, 3);
    return rc;
}

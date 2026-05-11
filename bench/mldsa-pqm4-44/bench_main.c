/* bench_main.c — measure crypto_sign_verify on pqm4's m4f-tuned ML-DSA-44.
 *
 * pqm4's ml-dsa-44/m4f is the Cortex-M4 specialization of the FIPS 204
 * spec (DILITHIUM_MODE=2). Test vectors are the same FIPS-204 bytes as
 * mldsa-native — we reuse mldsa-native's expected_test_vectors.h.
 *
 * The pqm4 API namespaces verify as crypto_sign_verify_ctx, with
 * crypto_sign_verify being a macro for (..., NULL, 0, ...). Both call
 * the same internal verify path; we use crypto_sign_verify_ctx here so
 * the bench matches the mldsa-native flavor (which also passes a ctx).
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bench_io.h"

/* pqm4's own api.h */
#include "api.h"

/* mldsa-native test vectors. We #define MLD_CONFIG_PARAMETER_SET here so
 * the header picks the ML-DSA-44 arm and aliases test_vector_pk / _sig
 * to fixed-size 1312/2420-byte arrays. */
#define MLD_CONFIG_PARAMETER_SET 44
#include "expected_test_vectors.h"

#ifndef BENCH_ITERS
#  define BENCH_ITERS 1u
#endif

static volatile int g_acc;

int main(void) {
    int rc = 0;
    for (unsigned i = 0; i < BENCH_ITERS; i++) {
        int r = crypto_sign_verify_ctx(
            test_vector_sig, sizeof(test_vector_sig),
            (const uint8_t *)TEST_VECTOR_MSG, TEST_VECTOR_MSG_LEN,
            (const uint8_t *)TEST_VECTOR_CTX, TEST_VECTOR_CTX_LEN,
            test_vector_pk);
        g_acc ^= r;
        if (r != 0) rc = 1;
    }
    uint8_t out[3];
    out[0] = (uint8_t)0xc4;  /* tag for mldsa-pqm4-44 */
    out[1] = (uint8_t)(BENCH_ITERS & 0xff);
    out[2] = (uint8_t)(g_acc & 0xff);
    bench_emit_hex(out, 3);
    return rc;
}

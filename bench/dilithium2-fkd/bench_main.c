/* dilithium2-fkd — verify cost of FasterKyberDilithiumM4's m4 Dilithium2.
 *
 * FasterKyberDilithiumM4 (Adomnicai/Tachibana et al.) is a Cortex-M4
 * port of Dilithium and Kyber that postdates pqm4 and ships further
 * NTT/pointwise speedups for the verify hot path (the "new" subdir
 * provides their fully-tuned implementation). The verify API is the
 * round-3 Dilithium2 spec (no ctx parameter, mu = SHAKE256(SHAKE256(pk)
 * || M) without the FIPS 204 prefix), so its byte-level test vectors
 * are NOT interchangeable with mldsa-native's ML-DSA-44 vectors.
 *
 * To keep the bench self-contained and fair, we generate a fresh
 * (pk, sk, sig) tuple at M4 startup with FKD's own keygen+sign code,
 * then time only the verify in the loop. Keygen+sign cost lands in
 * the ITERS=0 baseline and is subtracted out by the standard formula.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "bench_io.h"
#include "api.h"
#include "params.h"

#ifndef BENCH_ITERS
#  define BENCH_ITERS 1u
#endif

/* A deterministic randombytes stub: a fixed-seed Xorshift. FKD's sign path
 * draws bytes for the keygen seed and the per-signature rhoprime; with a
 * deterministic PRNG the (pk, sig) tuple is reproducible across runs. */
static uint32_t prng_state = 0xC0FFEE42u;
int randombytes(uint8_t *buf, size_t n);
int randombytes(uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint32_t x = prng_state;
        x ^= x << 13; x ^= x >> 17; x ^= x << 5;
        prng_state = x;
        buf[i] = (uint8_t)x;
    }
    return 0;
}

/* 32-byte SHA-256-shaped message (we use the same bytes as sb-mldsa44's
 * testvec for parity, though FKD's mu does not include a FIPS 204 prefix). */
static const uint8_t MSG[32] = {
    0x5d, 0x66, 0x70, 0xdc, 0xf3, 0xe2, 0x77, 0x32,
    0x4b, 0xae, 0xeb, 0xb8, 0x70, 0xc2, 0xa2, 0x9a,
    0x6e, 0xa7, 0xa1, 0x6c, 0x10, 0x49, 0xbd, 0x32,
    0xe9, 0xf2, 0x39, 0x37, 0xae, 0xb1, 0x9d, 0xc2,
};

static uint8_t pk[CRYPTO_PUBLICKEYBYTES];
static uint8_t sk[CRYPTO_SECRETKEYBYTES];
static uint8_t sig[CRYPTO_BYTES];
static size_t  siglen;

static volatile int g_acc;

int main(void) {
    /* Setup, paid once (lands in ITERS=0 baseline). */
    crypto_sign_keypair(pk, sk);
    crypto_sign_signature(sig, &siglen, MSG, sizeof MSG, sk);

    int rc = 0;
    for (unsigned i = 0; i < BENCH_ITERS; i++) {
        int r = crypto_sign_verify(sig, siglen, MSG, sizeof MSG, pk);
        g_acc ^= r;
        if (r != 0) rc = 1;
    }
    uint8_t out[3];
    out[0] = (uint8_t)0xfd;                 /* tag for dilithium2-fkd */
    out[1] = (uint8_t)(BENCH_ITERS & 0xff);
    out[2] = (uint8_t)(g_acc & 0xff);
    bench_emit_hex(out, 3);
    return rc;
}

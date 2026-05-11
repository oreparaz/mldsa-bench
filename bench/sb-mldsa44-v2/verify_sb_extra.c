/* sb-mldsa44 v2 — precompute A = ExpandA(rho) once.
 *
 * The matrix A has 16 polynomials (K=L=4), each 256 int32_t coefficients,
 * 16 KB total. For a fixed pk (secure boot), A is constant across boots,
 * so we generate it once at setup time and have the verify hot loop read
 * from RAM instead of running rejection sampling against SHAKE128.
 *
 * Everything else is exactly pqm4's crypto_sign_verify_ctx, edited in
 * place to call sb_v2_verify with the precomputed A.
 *
 * Bound checks against malformed sigs (siglen, ctxlen, chknorm, sig_h
 * encoding) are still performed — the spec requires them. They're cheap.
 */
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "params.h"
#include "poly.h"
#include "polyvec.h"
#include "packing.h"
#include "symmetric.h"
#include "fips202.h"

#include "verify_sb.h"

/* Precomputed A_NTT[K][L]. Linker-allocated in .bss (4 MB RAM, plenty). */
static poly sb_A_NTT[K][L];

/* Need to fwd-declare expand_mat_elem since pqm4 marks it `static`.
 * We inline its body directly here instead — it's literally one call. */
extern void poly_uniform(poly *a,
                         const unsigned char seed[SEEDBYTES],
                         uint16_t nonce);

void sb_v2_precompute_A(const uint8_t *pk) {
    const uint8_t *rho = pk;
    for (size_t i = 0; i < K; i++) {
        for (size_t j = 0; j < L; j++) {
            poly_uniform(&sb_A_NTT[i][j], rho, (uint16_t)((i << 8) + j));
        }
    }
}

int sb_v2_verify(const uint8_t *sig, size_t siglen,
                 const uint8_t *m, size_t mlen,
                 const uint8_t *ctx, size_t ctxlen,
                 const uint8_t *pk)
{
    uint8_t mu[CRHBYTES];
    uint8_t c[CTILDEBYTES];
    uint8_t c2[CTILDEBYTES];
    poly cp;
    polyvecl z;
    shake256incctx state;
    poly tmp_elem, w1_elem;

    if (ctxlen > 255 || siglen != CRYPTO_BYTES) return -1;

    if (unpack_sig_z(&z, sig) != 0) return -1;
    if (polyvecl_chknorm(&z, GAMMA1 - BETA))   return -1;

    /* mu = CRH(H(pk) || 0x00 || ctxlen || ctx || msg) */
    shake256(mu, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, TRBYTES);
    mu[0] = 0;
    mu[1] = (uint8_t)ctxlen;
    shake256_inc_absorb(&state, mu, 2);
    shake256_inc_absorb(&state, ctx, ctxlen);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);

    /* Start the c-tilde-prime stream: absorb mu, then absorb w1 chunks as
     * each row is computed below. */
    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);

    if (unpack_sig_c(c, sig) != 0) return -1;
    poly_challenge(&cp, c);
    poly_ntt(&cp);
    polyvecl_ntt(&z);

    for (size_t k_idx = 0; k_idx < K; k_idx++) {
        /* w_elem = sum_j A[k][j] * z_ntt[j] (Montgomery domain pointwise) */
        poly_pointwise_montgomery(&w1_elem, &sb_A_NTT[k_idx][0], &z.vec[0]);
        for (size_t l_idx = 1; l_idx < L; l_idx++) {
            poly_pointwise_acc_montgomery(&w1_elem, &sb_A_NTT[k_idx][l_idx], &z.vec[l_idx]);
        }

        /* Subtract c * (t1[k] << D) — t1 still unpacked from pk each round. */
        unpack_pk_t1(&tmp_elem, k_idx, pk);
        poly_shiftl(&tmp_elem);
        poly_ntt(&tmp_elem);
        poly_pointwise_montgomery(&tmp_elem, &cp, &tmp_elem);
        poly_sub(&w1_elem, &w1_elem, &tmp_elem);
        poly_reduce(&w1_elem);
        poly_invntt_tomont(&w1_elem);

        /* w1 = HighBits(w - ct·2^d, q, alpha) under hint h */
        poly_caddq(&w1_elem);
        if (unpack_sig_h(&tmp_elem, k_idx, sig) != 0) return -1;
        poly_use_hint(&w1_elem, &w1_elem, &tmp_elem);

        uint8_t w1_packed[POLYW1_PACKEDBYTES];
        polyw1_pack(w1_packed, &w1_elem);
        shake256_inc_absorb(&state, w1_packed, POLYW1_PACKEDBYTES);
    }

    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, CTILDEBYTES, &state);
    for (size_t i = 0; i < CTILDEBYTES; i++) {
        if (c[i] != c2[i]) return -1;
    }
    return 0;
}

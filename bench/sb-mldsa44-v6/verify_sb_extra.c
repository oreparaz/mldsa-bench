/* sb-mldsa44 v6 — unpack the hint polynomials once, not K times.
 *
 * pqm4's unpack_sig_h(h, idx, sig) extracts the hint poly for one row,
 * but to validate the hint encoding's monotone-index requirement it
 * walks all K rows on every call. The inner "zero h" loop also runs
 * K*N iterations even though only N writes happen.
 *
 * For K=4 we end up doing K*K*N ≈ 4096 inner-loop iterations across the
 * four per-row calls instead of K*N = 1024 in a single combined call.
 * v6 replaces them with one sb_v6_unpack_sig_h_all() that fills all
 * K hint polynomials in one sweep.
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

static poly             sb_A_NTT[K][L];
static poly             sb_t1_ntt[K];
static shake256incctx   sb_mu_state_template;

extern void poly_uniform(poly *a,
                         const unsigned char seed[SEEDBYTES],
                         uint16_t nonce);

void sb_v6_precompute(const uint8_t *pk) {
    const uint8_t *rho = pk;
    for (size_t i = 0; i < K; i++) {
        for (size_t j = 0; j < L; j++) {
            poly_uniform(&sb_A_NTT[i][j], rho, (uint16_t)((i << 8) + j));
        }
    }
    for (size_t k_idx = 0; k_idx < K; k_idx++) {
        unpack_pk_t1(&sb_t1_ntt[k_idx], k_idx, pk);
        poly_shiftl(&sb_t1_ntt[k_idx]);
        poly_ntt(&sb_t1_ntt[k_idx]);
    }
    uint8_t tr[TRBYTES];
    shake256(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&sb_mu_state_template);
    shake256_inc_absorb(&sb_mu_state_template, tr, TRBYTES);
    uint8_t domsep[2] = { 0x00, 0x00 };
    shake256_inc_absorb(&sb_mu_state_template, domsep, 2);
}

/* Decode all K hint polynomials in a single sweep over the sig encoding.
 * Returns -1 on a malformed hint encoding.
 *
 * The encoding is: sig + CTILDEBYTES + L*POLYZ_PACKEDBYTES is a packed
 * hint block of OMEGA+K bytes. The first OMEGA bytes hold the per-row
 * coefficient indices (the row boundaries are given by the K cumulative
 * counters in the next K bytes). FIPS 204 requires: cumulative counters
 * are monotone in [0, OMEGA], and within each row the indices are
 * strictly increasing.
 */
static int sb_v6_unpack_sig_h_all(poly hs[K], const uint8_t *sig) {
    const uint8_t *h_enc = sig + CTILDEBYTES + L * POLYZ_PACKEDBYTES;
    /* Zero all K * N coefficients up-front. memset is faster than a loop. */
    for (size_t i = 0; i < K; i++) {
        for (size_t j = 0; j < N; j++) hs[i].coeffs[j] = 0;
    }
    size_t k = 0;
    for (size_t i = 0; i < K; i++) {
        const uint8_t cum = h_enc[OMEGA + i];
        if (cum < k || cum > OMEGA) return -1;
        for (size_t j = k; j < cum; j++) {
            if (j > k && h_enc[j] <= h_enc[j-1]) return -1;
            hs[i].coeffs[h_enc[j]] = 1;
        }
        k = cum;
    }
    /* The remaining OMEGA-k indices must be zero (strong unforgeability). */
    for (size_t j = k; j < OMEGA; j++) {
        if (h_enc[j] != 0) return -1;
    }
    return 0;
}

int sb_v6_verify(const uint8_t *sig, size_t siglen,
                 const uint8_t *m, size_t mlen,
                 const uint8_t *ctx, size_t ctxlen,
                 const uint8_t *pk)
{
    (void)pk; (void)ctx;
    uint8_t mu[CRHBYTES];
    uint8_t c[CTILDEBYTES];
    uint8_t c2[CTILDEBYTES];
    poly cp;
    polyvecl z;
    poly hs[K];                /* hint polys, decoded once */
    shake256incctx state;
    poly tmp_elem, w1_elem;

    if (ctxlen != 0 || siglen != CRYPTO_BYTES) return -1;
    if (unpack_sig_z(&z, sig) != 0) return -1;
    if (polyvecl_chknorm(&z, GAMMA1 - BETA))   return -1;
    if (sb_v6_unpack_sig_h_all(hs, sig) != 0)  return -1;

    /* mu = SHAKE256(tr_pk || 0x00 || 0x00 || msg, 64) via pre-warmed state */
    memcpy(&state, &sb_mu_state_template, sizeof state);
    shake256_inc_absorb(&state, m, mlen);
    shake256_inc_finalize(&state);
    shake256_inc_squeeze(mu, CRHBYTES, &state);

    shake256_inc_init(&state);
    shake256_inc_absorb(&state, mu, CRHBYTES);

    if (unpack_sig_c(c, sig) != 0) return -1;
    poly_challenge(&cp, c);
    poly_ntt(&cp);
    polyvecl_ntt(&z);

    for (size_t k_idx = 0; k_idx < K; k_idx++) {
        poly_pointwise_montgomery(&w1_elem, &sb_A_NTT[k_idx][0], &z.vec[0]);
        for (size_t l_idx = 1; l_idx < L; l_idx++) {
            poly_pointwise_acc_montgomery(&w1_elem, &sb_A_NTT[k_idx][l_idx], &z.vec[l_idx]);
        }

        poly_pointwise_montgomery(&tmp_elem, &cp, &sb_t1_ntt[k_idx]);
        poly_sub(&w1_elem, &w1_elem, &tmp_elem);
        poly_reduce(&w1_elem);
        poly_invntt_tomont(&w1_elem);

        poly_caddq(&w1_elem);
        poly_use_hint(&w1_elem, &w1_elem, &hs[k_idx]);

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

/* sb-mldsa44 v7 — fuse caddq + useHint + polyw1_pack into one pass.
 *
 * Per row of K, the verify tail does (in pqm4):
 *   poly_caddq(w)                  -- pass 1: 256 coeffs, conditional +Q
 *   poly_use_hint(w, w, h)         -- pass 2: 256 coeffs, decompose+hint
 *   polyw1_pack(packed, w)         -- pass 3: 256 coeffs -> 192 bytes
 *
 * Each pass writes back to w_elem and reads h or w again, totalling
 * ~3 KB of redundant load/store traffic per row. We fuse all three into
 * sb_v7_caddq_useHint_pack(packed, w, h) which sweeps the 256 coeffs
 * once and emits the 6-bit-packed bytes.
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

void sb_v7_precompute(const uint8_t *pk) {
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

static int sb_v7_unpack_sig_h_all(poly hs[K], const uint8_t *sig) {
    const uint8_t *h_enc = sig + CTILDEBYTES + L * POLYZ_PACKEDBYTES;
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
    for (size_t j = k; j < OMEGA; j++) {
        if (h_enc[j] != 0) return -1;
    }
    return 0;
}

/* Fused caddq + decompose + apply-hint + polyw1_pack for ML-DSA-44
 * (GAMMA2 == (Q-1)/88, alpha = 2*GAMMA2, a1 in [0, 43]).
 *
 * Input  w[256] : signed int32, post-invNTT, range roughly [-Q, Q].
 * Input  h[256] : 0 or 1 per coefficient.
 * Output r[192] : 6-bit-packed coeffs, 4 coeffs / 3 bytes.
 */
static void sb_v7_caddq_useHint_pack(uint8_t r[POLYW1_PACKEDBYTES],
                                     const int32_t w[N],
                                     const int32_t h[N]) {
    for (size_t i = 0; i < N/4; i++) {
        int32_t a1v[4];
        for (size_t j = 0; j < 4; j++) {
            int32_t a = w[4*i+j];
            a += (a >> 31) & Q;            /* caddq */
            /* decompose: a1 = HighBits(a, 2*GAMMA2) */
            int32_t a1 = (a + 127) >> 7;
            a1 = (a1 * 11275 + (1 << 23)) >> 24;
            a1 ^= ((43 - a1) >> 31) & a1;  /* if a1 > 43, a1 = 0 */
            int32_t a0 = a - a1 * 2 * GAMMA2;
            a0 -= (((Q-1)/2 - a0) >> 31) & Q;
            /* apply hint */
            if (h[4*i+j]) {
                if (a0 > 0) a1 = (a1 == 43) ?  0 : a1 + 1;
                else        a1 = (a1 == 0 ) ? 43 : a1 - 1;
            }
            a1v[j] = a1;
        }
        r[3*i + 0] = (uint8_t)(a1v[0] | (a1v[1] << 6));
        r[3*i + 1] = (uint8_t)((a1v[1] >> 2) | (a1v[2] << 4));
        r[3*i + 2] = (uint8_t)((a1v[2] >> 4) | (a1v[3] << 2));
    }
}

int sb_v7_verify(const uint8_t *sig, size_t siglen,
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
    poly hs[K];
    shake256incctx state;
    poly w1_elem, tmp_elem;

    if (ctxlen != 0 || siglen != CRYPTO_BYTES) return -1;
    if (unpack_sig_z(&z, sig) != 0) return -1;
    if (polyvecl_chknorm(&z, GAMMA1 - BETA))   return -1;
    if (sb_v7_unpack_sig_h_all(hs, sig) != 0)  return -1;

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

        uint8_t w1_packed[POLYW1_PACKEDBYTES];
        sb_v7_caddq_useHint_pack(w1_packed, w1_elem.coeffs, hs[k_idx].coeffs);
        shake256_inc_absorb(&state, w1_packed, POLYW1_PACKEDBYTES);
    }

    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, CTILDEBYTES, &state);
    for (size_t i = 0; i < CTILDEBYTES; i++) {
        if (c[i] != c2[i]) return -1;
    }
    return 0;
}

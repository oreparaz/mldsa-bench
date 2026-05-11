/* sb-mldsa44 v8 — fuse unpack_sig_z and polyvecl_chknorm into one pass.
 *
 * v7's per-verify flow had:
 *   unpack_sig_z(&z, sig)            -- read 4*256 = 1024 coeffs in 18-bit
 *                                        packed form, store as int32
 *   polyvecl_chknorm(&z, GAMMA1-BETA) -- re-read all 1024 coeffs, |c| < B?
 *
 * That's two scans over the same 1024 coefficients with ~9 KB of redundant
 * load/store traffic between them. v8 fuses them: while unpacking each
 * 4-coeff group, we check the bound on the raw 18-bit value directly
 * (avoiding any need to materialize the int32 then re-read it).
 *
 * For ML-DSA-44, GAMMA1=2^17 and BETA=78, so a raw 18-bit value `raw`
 * has |GAMMA1 - raw| >= GAMMA1-BETA iff raw <= 78 or raw >= 2^18 - 78.
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

void sb_v8_precompute(const uint8_t *pk) {
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

/* Unpack z AND check infinity norm in one pass.
 * Returns 0 on success, -1 if any coefficient violates |z| < GAMMA1-BETA.
 *
 * Specialized to GAMMA1 = (1 << 17) for ML-DSA-44.
 * raw is a 18-bit packed value; z[i] = GAMMA1 - raw, so |z[i]| < GAMMA1-BETA
 * iff GAMMA1-BETA < raw < GAMMA1+BETA, i.e. 130994 < raw < 131150
 * (the inverse: bad iff raw <= 78 or raw >= 262066, since 131072-78=130994
 * and 131072+131072-78 = 262066).
 */
#define BAD_LOW   (BETA)              /* 78  : raw <= BAD_LOW  is bad */
#define BAD_HIGH  ((1u << 18) - BETA) /* 2^18-78=262066: raw >= BAD_HIGH is bad */

static int sb_v8_unpack_sig_z_chknorm(polyvecl *z, const uint8_t *sig) {
    const uint8_t *p = sig + CTILDEBYTES;
    for (size_t li = 0; li < L; li++) {
        int32_t *r = z->vec[li].coeffs;
        for (size_t i = 0; i < N/4; i++) {
            uint32_t r0, r1, r2, r3;
            r0  =  (uint32_t)p[9*i+0];
            r0 |= ((uint32_t)p[9*i+1]) << 8;
            r0 |= ((uint32_t)p[9*i+2]) << 16;
            r0 &= 0x3FFFF;

            r1  =  (uint32_t)p[9*i+2] >> 2;
            r1 |= ((uint32_t)p[9*i+3]) << 6;
            r1 |= ((uint32_t)p[9*i+4]) << 14;
            r1 &= 0x3FFFF;

            r2  =  (uint32_t)p[9*i+4] >> 4;
            r2 |= ((uint32_t)p[9*i+5]) << 4;
            r2 |= ((uint32_t)p[9*i+6]) << 12;
            r2 &= 0x3FFFF;

            r3  =  (uint32_t)p[9*i+6] >> 6;
            r3 |= ((uint32_t)p[9*i+7]) << 2;
            r3 |= ((uint32_t)p[9*i+8]) << 10;
            r3 &= 0x3FFFF;

            /* Norm check: bad iff raw <= 78 or raw >= 262066.
             * Combine into one branch via OR. */
            if (r0 <= BAD_LOW || r0 >= BAD_HIGH ||
                r1 <= BAD_LOW || r1 >= BAD_HIGH ||
                r2 <= BAD_LOW || r2 >= BAD_HIGH ||
                r3 <= BAD_LOW || r3 >= BAD_HIGH) {
                return -1;
            }

            r[4*i+0] = (int32_t)((int32_t)GAMMA1 - (int32_t)r0);
            r[4*i+1] = (int32_t)((int32_t)GAMMA1 - (int32_t)r1);
            r[4*i+2] = (int32_t)((int32_t)GAMMA1 - (int32_t)r2);
            r[4*i+3] = (int32_t)((int32_t)GAMMA1 - (int32_t)r3);
        }
        p += POLYZ_PACKEDBYTES;
    }
    return 0;
}

static int sb_v8_unpack_sig_h_all(poly hs[K], const uint8_t *sig) {
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

static void sb_v8_caddq_useHint_pack(uint8_t r[POLYW1_PACKEDBYTES],
                                     const int32_t w[N],
                                     const int32_t h[N]) {
    for (size_t i = 0; i < N/4; i++) {
        int32_t a1v[4];
        for (size_t j = 0; j < 4; j++) {
            int32_t a = w[4*i+j];
            a += (a >> 31) & Q;
            int32_t a1 = (a + 127) >> 7;
            a1 = (a1 * 11275 + (1 << 23)) >> 24;
            a1 ^= ((43 - a1) >> 31) & a1;
            if (h[4*i+j]) {
                int32_t a0 = a - a1 * 2 * GAMMA2;
                a0 -= (((Q-1)/2 - a0) >> 31) & Q;
                if (a0 > 0) a1 = (a1 == 43) ?  0 : a1 + 1;
                else        a1 = (a1 == 0)  ? 43 : a1 - 1;
            }
            a1v[j] = a1;
        }
        r[3*i + 0] = (uint8_t)(a1v[0] | (a1v[1] << 6));
        r[3*i + 1] = (uint8_t)((a1v[1] >> 2) | (a1v[2] << 4));
        r[3*i + 2] = (uint8_t)((a1v[2] >> 4) | (a1v[3] << 2));
    }
}

int sb_v8_verify(const uint8_t *sig, size_t siglen,
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
    if (sb_v8_unpack_sig_z_chknorm(&z, sig) != 0) return -1;
    if (sb_v8_unpack_sig_h_all(hs, sig) != 0)     return -1;

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
        sb_v8_caddq_useHint_pack(w1_packed, w1_elem.coeffs, hs[k_idx].coeffs);
        shake256_inc_absorb(&state, w1_packed, POLYW1_PACKEDBYTES);
    }

    shake256_inc_finalize(&state);
    shake256_inc_squeeze(c2, CTILDEBYTES, &state);
    for (size_t i = 0; i < CTILDEBYTES; i++) {
        if (c[i] != c2[i]) return -1;
    }
    return 0;
}

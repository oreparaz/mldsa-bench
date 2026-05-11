/* sb-mldsa44 v5 — ship a pre-warmed SHAKE256 state with tr_pk + the
 * fixed domsep prefix (0x00, 0x00) already absorbed.
 *
 * In v4 the verify hot path does:
 *   shake256_inc_init(&state)               -- 208-byte zero of state.ctx[]
 *   shake256_inc_absorb(&state, tr_pk, 64)  -- XOR 64 bytes into state
 *   shake256_inc_absorb(&state, domsep, 2)  -- XOR 2 more bytes (= 66/136)
 *   shake256_inc_absorb(&state, ctx, 0)     -- no-op
 *   shake256_inc_absorb(&state, msg, 32)    -- XOR 32 more bytes (= 98/136)
 *   shake256_inc_finalize(&state)           -- pad + permute
 *   shake256_inc_squeeze(mu, 64, &state)
 *
 * The first three calls don't touch any per-verify data. For secure-boot
 * with ctxlen fixed at 0 they're a constant function of pk. We bake the
 * resulting state (208 bytes) into precompute and just memcpy at the
 * start of each verify, then absorb the 32-byte msg and finalize.
 *
 * This saves: one init's zero-fill (208 B), three absorb-API entries with
 * loop+bookkeeping, and ~66 XOR-into-state byte ops. Net: ~300 insns/verify.
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
static shake256incctx   sb_mu_state_template; /* state after absorbing tr_pk||0x00||0x00 */

extern void poly_uniform(poly *a,
                         const unsigned char seed[SEEDBYTES],
                         uint16_t nonce);

void sb_v5_precompute(const uint8_t *pk) {
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
    /* Build sb_mu_state_template by running the prefix on a fresh state. */
    uint8_t tr[TRBYTES];
    shake256(tr, TRBYTES, pk, CRYPTO_PUBLICKEYBYTES);
    shake256_inc_init(&sb_mu_state_template);
    shake256_inc_absorb(&sb_mu_state_template, tr, TRBYTES);
    /* For secure boot ctxlen is fixed at 0, so the two domsep bytes are
     * (0x00, 0x00). Absorb them into the template too. */
    uint8_t domsep[2] = { 0x00, 0x00 };
    shake256_inc_absorb(&sb_mu_state_template, domsep, 2);
}

int sb_v5_verify(const uint8_t *sig, size_t siglen,
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
    shake256incctx state;
    poly tmp_elem, w1_elem;

    /* Reject anything that doesn't match the fixed secure-boot shape. */
    if (ctxlen != 0 || siglen != CRYPTO_BYTES) return -1;
    if (unpack_sig_z(&z, sig) != 0) return -1;
    if (polyvecl_chknorm(&z, GAMMA1 - BETA))   return -1;

    /* Resume mu from the pre-warmed state. */
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

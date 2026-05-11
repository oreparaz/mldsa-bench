/* gen_sb_testvec.c — generate a fresh (pk, sig) tuple for a 32-byte
 * "software hash" input, using mldsa-native's portable C90 ML-DSA-44.
 *
 * Output: bench/sb-mldsa44-v1/testvec.h with three byte arrays:
 *   sb_pk   (1312 bytes)
 *   sb_sig  (2420 bytes)
 *   sb_hash (32 bytes)   -- SHA-256("mldsa-bench secure-boot test image v1\n")
 *                           computed inline here to avoid depending on an
 *                           SHA-256 implementation at host-build time.
 *
 * Build: see tools/Makefile.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "mldsa_native.h"
#include "notrandombytes.h"

/* A tiny pure-C SHA-256 just to produce a deterministic 32-byte hash. */
static const uint32_t K256[64] = {
  0x428a2f98u,0x71374491u,0xb5c0fbcfu,0xe9b5dba5u,0x3956c25bu,0x59f111f1u,0x923f82a4u,0xab1c5ed5u,
  0xd807aa98u,0x12835b01u,0x243185beu,0x550c7dc3u,0x72be5d74u,0x80deb1feu,0x9bdc06a7u,0xc19bf174u,
  0xe49b69c1u,0xefbe4786u,0x0fc19dc6u,0x240ca1ccu,0x2de92c6fu,0x4a7484aau,0x5cb0a9dcu,0x76f988dau,
  0x983e5152u,0xa831c66du,0xb00327c8u,0xbf597fc7u,0xc6e00bf3u,0xd5a79147u,0x06ca6351u,0x14292967u,
  0x27b70a85u,0x2e1b2138u,0x4d2c6dfcu,0x53380d13u,0x650a7354u,0x766a0abbu,0x81c2c92eu,0x92722c85u,
  0xa2bfe8a1u,0xa81a664bu,0xc24b8b70u,0xc76c51a3u,0xd192e819u,0xd6990624u,0xf40e3585u,0x106aa070u,
  0x19a4c116u,0x1e376c08u,0x2748774cu,0x34b0bcb5u,0x391c0cb3u,0x4ed8aa4au,0x5b9cca4fu,0x682e6ff3u,
  0x748f82eeu,0x78a5636fu,0x84c87814u,0x8cc70208u,0x90befffau,0xa4506cebu,0xbef9a3f7u,0xc67178f2u
};
static uint32_t ror32(uint32_t x, unsigned n) { return (x>>n) | (x<<(32-n)); }
static void sha256(uint8_t out[32], const uint8_t *msg, size_t len) {
    uint32_t H[8] = {0x6a09e667u,0xbb67ae85u,0x3c6ef372u,0xa54ff53au,
                     0x510e527fu,0x9b05688cu,0x1f83d9abu,0x5be0cd19u};
    uint8_t buf[64+9 + 8];
    size_t blocks = (len + 9 + 63) / 64;
    uint8_t *full = calloc(blocks*64, 1);
    memcpy(full, msg, len);
    full[len] = 0x80;
    uint64_t bits = (uint64_t)len * 8;
    for (int i = 0; i < 8; i++) full[blocks*64 - 1 - i] = (uint8_t)(bits >> (i*8));
    for (size_t b = 0; b < blocks; b++) {
        uint32_t W[64];
        for (int t = 0; t < 16; t++) {
            W[t] = ((uint32_t)full[b*64 + 4*t] << 24)
                 | ((uint32_t)full[b*64 + 4*t+1] << 16)
                 | ((uint32_t)full[b*64 + 4*t+2] << 8)
                 |  (uint32_t)full[b*64 + 4*t+3];
        }
        for (int t = 16; t < 64; t++) {
            uint32_t s0 = ror32(W[t-15],7) ^ ror32(W[t-15],18) ^ (W[t-15]>>3);
            uint32_t s1 = ror32(W[t-2],17) ^ ror32(W[t-2],19) ^ (W[t-2]>>10);
            W[t] = W[t-16] + s0 + W[t-7] + s1;
        }
        uint32_t a=H[0],c=H[1],d=H[2],e=H[3],f=H[4],g=H[5],h=H[6],i=H[7];
        for (int t = 0; t < 64; t++) {
            uint32_t S1 = ror32(f,6) ^ ror32(f,11) ^ ror32(f,25);
            uint32_t ch = (f & g) ^ (~f & h);
            uint32_t T1 = i + S1 + ch + K256[t] + W[t];
            uint32_t S0 = ror32(a,2) ^ ror32(a,13) ^ ror32(a,22);
            uint32_t mj = (a & c) ^ (a & d) ^ (c & d);
            uint32_t T2 = S0 + mj;
            i = h; h = g; g = f; f = e + T1;
            e = d; d = c; c = a; a = T1 + T2;
        }
        H[0]+=a; H[1]+=c; H[2]+=d; H[3]+=e; H[4]+=f; H[5]+=g; H[6]+=h; H[7]+=i;
    }
    for (int t = 0; t < 8; t++) {
        out[4*t]   = (uint8_t)(H[t]>>24);
        out[4*t+1] = (uint8_t)(H[t]>>16);
        out[4*t+2] = (uint8_t)(H[t]>>8);
        out[4*t+3] = (uint8_t)(H[t]);
    }
    free(full);
    (void)buf;
}

static void emit_array(FILE *f, const char *name, const uint8_t *p, size_t n) {
    fprintf(f, "static const uint8_t %s[%zu] = {\n  ", name, n);
    for (size_t i = 0; i < n; i++) {
        fprintf(f, "0x%02x,", p[i]);
        if ((i & 15) == 15) fprintf(f, "\n  ");
        else fprintf(f, " ");
    }
    fprintf(f, "\n};\n\n");
}

int main(int argc, char **argv) {
    const char *out_path = (argc > 1) ? argv[1] : "bench/sb-mldsa44-v1/testvec.h";

    /* The "software image" we pretend to be hashing. Stable string so the
     * hash and signature are reproducible. */
    static const char IMAGE[] = "mldsa-bench secure-boot test image v1\n";
    uint8_t hash[32];
    sha256(hash, (const uint8_t *)IMAGE, sizeof(IMAGE) - 1);

    /* Generate keypair deterministically. randombytes_reset() seeds the
     * notrandombytes PRNG to zero, so every run produces the same key. */
    uint8_t pk[CRYPTO_PUBLICKEYBYTES];
    uint8_t sk[CRYPTO_SECRETKEYBYTES];
    randombytes_reset();
    if (crypto_sign_keypair(pk, sk) != 0) {
        fprintf(stderr, "keypair failed\n");
        return 1;
    }

    /* Sign the 32-byte hash with an EMPTY context. */
    uint8_t sig[CRYPTO_BYTES];
    size_t siglen = 0;
    randombytes_reset();
    if (crypto_sign_signature(sig, &siglen, hash, sizeof hash,
                              (const uint8_t *)"", 0, sk) != 0) {
        fprintf(stderr, "sign failed\n");
        return 1;
    }
    if (siglen != CRYPTO_BYTES) {
        fprintf(stderr, "unexpected siglen %zu\n", siglen);
        return 1;
    }

    /* Self-verify so we know the tuple is valid. */
    if (crypto_sign_verify(sig, siglen, hash, sizeof hash,
                           (const uint8_t *)"", 0, pk) != 0) {
        fprintf(stderr, "self-verify failed\n");
        return 1;
    }

    FILE *f = fopen(out_path, "w");
    if (!f) { perror(out_path); return 1; }
    fprintf(f,
        "/* Auto-generated by tools/gen_sb_testvec.c -- DO NOT EDIT. */\n"
        "/* ML-DSA-44 secure-boot test vector: 32-byte hash + empty ctx. */\n"
        "#ifndef SB_TESTVEC_H\n#define SB_TESTVEC_H\n\n"
        "#include <stdint.h>\n\n"
        "#define SB_HASH_LEN 32u\n"
        "#define SB_PK_LEN   1312u\n"
        "#define SB_SIG_LEN  2420u\n\n");
    emit_array(f, "sb_hash", hash, sizeof hash);
    emit_array(f, "sb_pk",   pk,   sizeof pk);
    emit_array(f, "sb_sig",  sig,  sizeof sig);
    fprintf(f, "#endif /* SB_TESTVEC_H */\n");
    fclose(f);

    fprintf(stderr, "wrote %s (pk %zu, sig %zu, hash %zu)\n",
            out_path, sizeof pk, sizeof sig, sizeof hash);
    return 0;
}

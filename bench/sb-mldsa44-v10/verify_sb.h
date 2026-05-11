#ifndef VERIFY_SB_H
#define VERIFY_SB_H
#include <stdint.h>
#include <stddef.h>

void sb_v10_precompute(const uint8_t *pk);
int  sb_v10_verify(const uint8_t *sig, size_t siglen,
                   const uint8_t *m, size_t mlen,
                   const uint8_t *ctx, size_t ctxlen,
                   const uint8_t *pk);
#endif

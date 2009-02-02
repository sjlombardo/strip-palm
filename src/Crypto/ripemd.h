#ifndef RIPEMD_H
#define RIPEMD_H

#include "types.h"

#define RIPEMD_DATASIZE    64
#define RIPEMD_DATALEN     16
#define RIPEMD_DIGESTSIZE  20
#define RIPEMD_DIGESTLEN    5    

typedef struct ripemd_ctx {
  word32 digest[RIPEMD_DIGESTLEN];  /* Message digest */
  word32 count_l, count_h;       /* 64-bit block count */
  word8 block[RIPEMD_DATASIZE];     /* RIPEMD data buffer */
  int index;                             /* index into buffer */
} RIPEMD_CTX;

void ripemd_init(struct ripemd_ctx *ctx);
void ripemd_update(struct ripemd_ctx *ctx, word8 *buffer, word32 len);
void ripemd_final(struct ripemd_ctx *ctx);
void ripemd_digest(struct ripemd_ctx *ctx, word8 *s);
void ripemd_copy(struct ripemd_ctx *dest, struct ripemd_ctx *src);

#endif

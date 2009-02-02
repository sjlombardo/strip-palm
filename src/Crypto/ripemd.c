/* ripemd.c - Implementation of the RIPE-MD Hash Algorithm
 *
 * Copyright (C) 2000, Nikos Mavroyanopoulos
 * This implementation is placed under the public domain.
 *
 * Based on the SHA-1 implementation by A.M. Kuchling
 *
 * Here are the quotes of the SHA-1 implementation: 
 */
 
/* Copyright (C) 1995, A.M. Kuchling
 * Adapted to pike and some cleanup by Niels Möller.
 *
 * Based on SHA code originally posted to sci.crypt by Peter Gutmann
 * in message <30ajo5$oe8@ccu2.auckland.ac.nz>.
 * Modified to test for endianness on creation of SHA objects by AMK.
 * Also, the original specification of SHA was found to have a weakness
 * by NSA/NIST.  This code implements the fixed version of SHA.
 */

#ifdef NOPILOT
#include "posix_compat.h"
#include <stdlib.h>
#else
#include <PalmOS.h>
#endif

#include "ripemd.h"

/* 32-bit rotate left - kludged with shifts */
#define ROTL(n,X)  (((X)<<(n))|((X)>>(32-(n))))

#define f0(x,y,z)  (x^y^z)
#define f16(x,y,z) ((x&y)|((~x) & z))
#define f32(x,y,z) ((x|~(y))^z)
#define f48(x,y,z) ((x&z)|(y&(~z)))
#define f64(x,y,z) (x^(y|(~z)))

#define K0  0x00000000
#define K1  0x5A827999
#define K2  0x6ED9EBA1
#define K3  0x8F1BBCDC
#define K4  0xA953FD4E

#define KK0 0x50A28BE6
#define KK1 0x5C4DD124
#define KK2 0x6D703EF3
#define KK3 0x7A6D76E9
#define KK4 0x00000000

#define h0init 0x67452301
#define h1init 0xEFCDAB89
#define h2init 0x98BADCFE
#define h3init 0x10325476
#define h4init 0xC3D2E1F0

void ripemd_copy(struct ripemd_ctx *dest, struct ripemd_ctx *src)
{
	int i;

	dest->count_l = src->count_l;
	dest->count_h = src->count_h;
	for (i = 0; i < RIPEMD_DIGESTLEN; i++)
		dest->digest[i] = src->digest[i];
	for (i = 0; i < src->index; i++)
		dest->block[i] = src->block[i];
	dest->index = src->index;
}


/* Initialize the RIPEMD values */

void ripemd_init(struct ripemd_ctx *ctx)
{
	/* Set the h-vars to their initial values */
	ctx->digest[0] = h0init;
	ctx->digest[1] = h1init;
	ctx->digest[2] = h2init;
	ctx->digest[3] = h3init;
	ctx->digest[4] = h4init;

	/* Initialize bit count */
	ctx->count_l = ctx->count_h = 0;

	/* Initialize buffer */
	ctx->index = 0;
}

#define subRound(a, b, c, d, e, f, k, r, data) \
    ( a = ROTL( r, a + f(b,c,d) + data + k) + e, c = ROTL(10, c) )

static void ripemd_transform(struct ripemd_ctx *ctx, word32 * data)
{
	word32 A, B, C, D, E;	/* Local vars */
	word32 AA, BB, CC, DD, EE;	/* Local vars */
	word32 T;

	/* Set up first buffer and local data buffer */
	A = ctx->digest[0];
	B = ctx->digest[1];
	C = ctx->digest[2];
	D = ctx->digest[3];
	E = ctx->digest[4];

/* j=0...15 */
	subRound(A, B, C, D, E, f0, K0, 11, data[0]);
	subRound(E, A, B, C, D, f0, K0, 14, data[1]);
	subRound(D, E, A, B, C, f0, K0, 15, data[2]);
	subRound(C, D, E, A, B, f0, K0, 12, data[3]);
	subRound(B, C, D, E, A, f0, K0, 5, data[4]);
	subRound(A, B, C, D, E, f0, K0, 8, data[5]);
	subRound(E, A, B, C, D, f0, K0, 7, data[6]);
	subRound(D, E, A, B, C, f0, K0, 9, data[7]);
	subRound(C, D, E, A, B, f0, K0, 11, data[8]);
	subRound(B, C, D, E, A, f0, K0, 13, data[9]);
	subRound(A, B, C, D, E, f0, K0, 14, data[10]);
	subRound(E, A, B, C, D, f0, K0, 15, data[11]);
	subRound(D, E, A, B, C, f0, K0, 6, data[12]);
	subRound(C, D, E, A, B, f0, K0, 7, data[13]);
	subRound(B, C, D, E, A, f0, K0, 9, data[14]);
	subRound(A, B, C, D, E, f0, K0, 8, data[15]);

/* j=16...31 */
	subRound(E, A, B, C, D, f16, K1, 7, data[7]);
	subRound(D, E, A, B, C, f16, K1, 6, data[4]);
	subRound(C, D, E, A, B, f16, K1, 8, data[13]);
	subRound(B, C, D, E, A, f16, K1, 13, data[1]);
	subRound(A, B, C, D, E, f16, K1, 11, data[10]);
	subRound(E, A, B, C, D, f16, K1, 9, data[6]);
	subRound(D, E, A, B, C, f16, K1, 7, data[15]);
	subRound(C, D, E, A, B, f16, K1, 15, data[3]);
	subRound(B, C, D, E, A, f16, K1, 7, data[12]);
	subRound(A, B, C, D, E, f16, K1, 12, data[0]);
	subRound(E, A, B, C, D, f16, K1, 15, data[9]);
	subRound(D, E, A, B, C, f16, K1, 9, data[5]);
	subRound(C, D, E, A, B, f16, K1, 11, data[2]);
	subRound(B, C, D, E, A, f16, K1, 7, data[14]);
	subRound(A, B, C, D, E, f16, K1, 13, data[11]);
	subRound(E, A, B, C, D, f16, K1, 12, data[8]);

/* j=32...47 */
	subRound(D, E, A, B, C, f32, K2, 11, data[3]);
	subRound(C, D, E, A, B, f32, K2, 13, data[10]);
	subRound(B, C, D, E, A, f32, K2, 6, data[14]);
	subRound(A, B, C, D, E, f32, K2, 7, data[4]);
	subRound(E, A, B, C, D, f32, K2, 14, data[9]);
	subRound(D, E, A, B, C, f32, K2, 9, data[15]);
	subRound(C, D, E, A, B, f32, K2, 13, data[8]);
	subRound(B, C, D, E, A, f32, K2, 15, data[1]);
	subRound(A, B, C, D, E, f32, K2, 14, data[2]);
	subRound(E, A, B, C, D, f32, K2, 8, data[7]);
	subRound(D, E, A, B, C, f32, K2, 13, data[0]);
	subRound(C, D, E, A, B, f32, K2, 6, data[6]);
	subRound(B, C, D, E, A, f32, K2, 5, data[13]);
	subRound(A, B, C, D, E, f32, K2, 12, data[11]);
	subRound(E, A, B, C, D, f32, K2, 7, data[5]);
	subRound(D, E, A, B, C, f32, K2, 5, data[12]);

/* j=48...63 */
	subRound(C, D, E, A, B, f48, K3, 11, data[1]);
	subRound(B, C, D, E, A, f48, K3, 12, data[9]);
	subRound(A, B, C, D, E, f48, K3, 14, data[11]);
	subRound(E, A, B, C, D, f48, K3, 15, data[10]);
	subRound(D, E, A, B, C, f48, K3, 14, data[0]);
	subRound(C, D, E, A, B, f48, K3, 15, data[8]);
	subRound(B, C, D, E, A, f48, K3, 9, data[12]);
	subRound(A, B, C, D, E, f48, K3, 8, data[4]);
	subRound(E, A, B, C, D, f48, K3, 9, data[13]);
	subRound(D, E, A, B, C, f48, K3, 14, data[3]);
	subRound(C, D, E, A, B, f48, K3, 5, data[7]);
	subRound(B, C, D, E, A, f48, K3, 6, data[15]);
	subRound(A, B, C, D, E, f48, K3, 8, data[14]);
	subRound(E, A, B, C, D, f48, K3, 6, data[5]);
	subRound(D, E, A, B, C, f48, K3, 5, data[6]);
	subRound(C, D, E, A, B, f48, K3, 12, data[2]);

/* j=64...79 */
	subRound(B, C, D, E, A, f64, K4, 9, data[4]);
	subRound(A, B, C, D, E, f64, K4, 15, data[0]);
	subRound(E, A, B, C, D, f64, K4, 5, data[5]);
	subRound(D, E, A, B, C, f64, K4, 11, data[9]);
	subRound(C, D, E, A, B, f64, K4, 6, data[7]);
	subRound(B, C, D, E, A, f64, K4, 8, data[12]);
	subRound(A, B, C, D, E, f64, K4, 13, data[2]);
	subRound(E, A, B, C, D, f64, K4, 12, data[10]);
	subRound(D, E, A, B, C, f64, K4, 5, data[14]);
	subRound(C, D, E, A, B, f64, K4, 12, data[1]);
	subRound(B, C, D, E, A, f64, K4, 13, data[3]);
	subRound(A, B, C, D, E, f64, K4, 14, data[8]);
	subRound(E, A, B, C, D, f64, K4, 11, data[11]);
	subRound(D, E, A, B, C, f64, K4, 8, data[6]);
	subRound(C, D, E, A, B, f64, K4, 5, data[15]);
	subRound(B, C, D, E, A, f64, K4, 6, data[13]);

	AA = A;
	BB = B;
	CC = C;
	DD = D;
	EE = E;

/* ' */
	A = ctx->digest[0];
	B = ctx->digest[1];
	C = ctx->digest[2];
	D = ctx->digest[3];
	E = ctx->digest[4];

/* j=0...15 */
	subRound(A, B, C, D, E, f64, KK0, 8, data[5]);
	subRound(E, A, B, C, D, f64, KK0, 9, data[14]);
	subRound(D, E, A, B, C, f64, KK0, 9, data[7]);
	subRound(C, D, E, A, B, f64, KK0, 11, data[0]);
	subRound(B, C, D, E, A, f64, KK0, 13, data[9]);
	subRound(A, B, C, D, E, f64, KK0, 15, data[2]);
	subRound(E, A, B, C, D, f64, KK0, 15, data[11]);
	subRound(D, E, A, B, C, f64, KK0, 5, data[4]);
	subRound(C, D, E, A, B, f64, KK0, 7, data[13]);
	subRound(B, C, D, E, A, f64, KK0, 7, data[6]);
	subRound(A, B, C, D, E, f64, KK0, 8, data[15]);
	subRound(E, A, B, C, D, f64, KK0, 11, data[8]);
	subRound(D, E, A, B, C, f64, KK0, 14, data[1]);
	subRound(C, D, E, A, B, f64, KK0, 14, data[10]);
	subRound(B, C, D, E, A, f64, KK0, 12, data[3]);
	subRound(A, B, C, D, E, f64, KK0, 6, data[12]);

/* j=16...31 */
	subRound(E, A, B, C, D, f48, KK1, 9, data[6]);
	subRound(D, E, A, B, C, f48, KK1, 13, data[11]);
	subRound(C, D, E, A, B, f48, KK1, 15, data[3]);
	subRound(B, C, D, E, A, f48, KK1, 7, data[7]);
	subRound(A, B, C, D, E, f48, KK1, 12, data[0]);
	subRound(E, A, B, C, D, f48, KK1, 8, data[13]);
	subRound(D, E, A, B, C, f48, KK1, 9, data[5]);
	subRound(C, D, E, A, B, f48, KK1, 11, data[10]);
	subRound(B, C, D, E, A, f48, KK1, 7, data[14]);
	subRound(A, B, C, D, E, f48, KK1, 7, data[15]);
	subRound(E, A, B, C, D, f48, KK1, 12, data[8]);
	subRound(D, E, A, B, C, f48, KK1, 7, data[12]);
	subRound(C, D, E, A, B, f48, KK1, 6, data[4]);
	subRound(B, C, D, E, A, f48, KK1, 15, data[9]);
	subRound(A, B, C, D, E, f48, KK1, 13, data[1]);
	subRound(E, A, B, C, D, f48, KK1, 11, data[2]);

/* j=32...47 */
	subRound(D, E, A, B, C, f32, KK2, 9, data[15]);
	subRound(C, D, E, A, B, f32, KK2, 7, data[5]);
	subRound(B, C, D, E, A, f32, KK2, 15, data[1]);
	subRound(A, B, C, D, E, f32, KK2, 11, data[3]);
	subRound(E, A, B, C, D, f32, KK2, 8, data[7]);
	subRound(D, E, A, B, C, f32, KK2, 6, data[14]);
	subRound(C, D, E, A, B, f32, KK2, 6, data[6]);
	subRound(B, C, D, E, A, f32, KK2, 14, data[9]);
	subRound(A, B, C, D, E, f32, KK2, 12, data[11]);
	subRound(E, A, B, C, D, f32, KK2, 13, data[8]);
	subRound(D, E, A, B, C, f32, KK2, 5, data[12]);
	subRound(C, D, E, A, B, f32, KK2, 14, data[2]);
	subRound(B, C, D, E, A, f32, KK2, 13, data[10]);
	subRound(A, B, C, D, E, f32, KK2, 13, data[0]);
	subRound(E, A, B, C, D, f32, KK2, 7, data[4]);
	subRound(D, E, A, B, C, f32, KK2, 5, data[13]);

/* j=48...63 */
	subRound(C, D, E, A, B, f16, KK3, 15, data[8]);
	subRound(B, C, D, E, A, f16, KK3, 5, data[6]);
	subRound(A, B, C, D, E, f16, KK3, 8, data[4]);
	subRound(E, A, B, C, D, f16, KK3, 11, data[1]);
	subRound(D, E, A, B, C, f16, KK3, 14, data[3]);
	subRound(C, D, E, A, B, f16, KK3, 14, data[11]);
	subRound(B, C, D, E, A, f16, KK3, 6, data[15]);
	subRound(A, B, C, D, E, f16, KK3, 14, data[0]);
	subRound(E, A, B, C, D, f16, KK3, 6, data[5]);
	subRound(D, E, A, B, C, f16, KK3, 9, data[12]);
	subRound(C, D, E, A, B, f16, KK3, 12, data[2]);
	subRound(B, C, D, E, A, f16, KK3, 9, data[13]);
	subRound(A, B, C, D, E, f16, KK3, 12, data[9]);
	subRound(E, A, B, C, D, f16, KK3, 5, data[7]);
	subRound(D, E, A, B, C, f16, KK3, 15, data[10]);
	subRound(C, D, E, A, B, f16, KK3, 8, data[14]);

/* j=64...79 */
	subRound(B, C, D, E, A, f0, KK4, 8, data[12]);
	subRound(A, B, C, D, E, f0, KK4, 5, data[15]);
	subRound(E, A, B, C, D, f0, KK4, 12, data[10]);
	subRound(D, E, A, B, C, f0, KK4, 9, data[4]);
	subRound(C, D, E, A, B, f0, KK4, 12, data[1]);
	subRound(B, C, D, E, A, f0, KK4, 5, data[5]);
	subRound(A, B, C, D, E, f0, KK4, 14, data[8]);
	subRound(E, A, B, C, D, f0, KK4, 6, data[7]);
	subRound(D, E, A, B, C, f0, KK4, 8, data[6]);
	subRound(C, D, E, A, B, f0, KK4, 13, data[2]);
	subRound(B, C, D, E, A, f0, KK4, 6, data[13]);
	subRound(A, B, C, D, E, f0, KK4, 5, data[14]);
	subRound(E, A, B, C, D, f0, KK4, 15, data[0]);
	subRound(D, E, A, B, C, f0, KK4, 13, data[3]);
	subRound(C, D, E, A, B, f0, KK4, 11, data[9]);
	subRound(B, C, D, E, A, f0, KK4, 11, data[11]);

	T = ctx->digest[1] + D + CC;
	ctx->digest[1] = ctx->digest[2] + E + DD;
	ctx->digest[2] = ctx->digest[3] + A + EE;
	ctx->digest[3] = ctx->digest[4] + B + AA;
	ctx->digest[4] = ctx->digest[0] + C + BB;
	ctx->digest[0] = T;
}

#if 1

#ifndef EXTRACT_UCHAR
#define EXTRACT_UCHAR(p)  (*(word8 *)(p))
#endif

#define STRING2INT(s) ((((((EXTRACT_UCHAR(s+3) << 8)    \
			 | EXTRACT_UCHAR(s+2)) << 8)  \
			 | EXTRACT_UCHAR(s+1)) << 8)  \
			 | EXTRACT_UCHAR(s))
#else
word32 STRING2INT(word8 * s)
{
	word32 r;
	int i;

	for (i = 0, r = 0; i < 4; i++)
		r = (r << 8) | s[3-i];
	return r;
}
#endif

static void ripemd_block(struct ripemd_ctx *ctx, word8 * block)
{
	word32 data[RIPEMD_DATALEN];
	int i;

	/* Update block count */
	if (!++ctx->count_l)
		++ctx->count_h;

	/* Endian independent conversion */
	for (i = 0; i < RIPEMD_DATALEN; i++, block += 4)
		data[i] = STRING2INT(block);

	ripemd_transform(ctx, data);
}

void ripemd_update(struct ripemd_ctx *ctx, word8 * buffer, word32 len)
{
	if (ctx->index) {	/* Try to fill partial block */
		unsigned left = RIPEMD_DATASIZE - ctx->index;
		if (len < left) {
			MemMove(ctx->block + ctx->index, buffer, len);
			ctx->index += len;
			return;	/* Finished */
		} else {
			MemMove(ctx->block + ctx->index, buffer, left);
			ripemd_block(ctx, ctx->block);
			buffer += left;
			len -= left;
		}
	}
	while (len >= RIPEMD_DATASIZE) {
		ripemd_block(ctx, buffer);
		buffer += RIPEMD_DATASIZE;
		len -= RIPEMD_DATASIZE;
	}
	if ((ctx->index = len))
		/* This assignment is intended */
		/* Buffer leftovers */
		MemMove(ctx->block, buffer, len);
}

/* Final wrapup - pad to RIPEMD_DATASIZE-byte boundary with the bit pattern
   1 0* (64-bit count of bits processed, MSB-first) */

void ripemd_final(struct ripemd_ctx *ctx)
{
	word32 data[RIPEMD_DATALEN];
	int i;
	int words;

	i = ctx->index;
	/* Set the first char of padding to 0x80.  This is safe since there is
	   always at least one byte free */
	ctx->block[i++] = 0x80;

	/* Fill rest of word */
	for (; i & 3; i++)
		ctx->block[i] = 0;

	/* i is now a multiple of the word size 4 */
	words = i >> 2;
	for (i = 0; i < words; i++)
		data[i] = STRING2INT(ctx->block + 4 * i);

	if (words > (RIPEMD_DATALEN - 2)) {	/* No room for length in this block. Process it and
						 * pad with another one */
		for (i = words; i < RIPEMD_DATALEN; i++)
			data[i] = 0;
		ripemd_transform(ctx, data);
		for (i = 0; i < (RIPEMD_DATALEN - 2); i++)
			data[i] = 0;
	} else
		for (i = words; i < RIPEMD_DATALEN - 2; i++)
			data[i] = 0;
	/* Theres 512 = 2^9 bits in one block */
	data[RIPEMD_DATALEN - 1] =
	    (ctx->count_h << 9) | (ctx->count_l >> 23);
	data[RIPEMD_DATALEN - 2] = (ctx->count_l << 9) | (ctx->index << 3);
	ripemd_transform(ctx, data);
}

void ripemd_digest(struct ripemd_ctx *ctx, word8 * s)
{
	int i;

	for (i = 0; i < RIPEMD_DIGESTLEN; i++) {
		*s++ = ctx->digest[i];
		*s++ = 0xff & (ctx->digest[i] >> 8);
		*s++ = 0xff & (ctx->digest[i] >> 16);
		*s++ = 0xff & ctx->digest[i] >> 24;
	}

}

/*
    SHA-256 - Secure Hashing Algorithm v2 Implementation
    Copyright (C) 2000-2001, Daniel Roethlisberger <admin@roe.ch>
    Distributed under the GNU Lesser General Public License.
	See http://www.gnu.org/copyleft for details.
    Version 1.0.0-pre4
*/

#include "sha256.h"
#include "sha256s.h"


/*** CONFIGURATION **************************************************************/

/* define to have all temporary variables and memory area zeroed after use
 * Doing so will slow down the engine by around 20%
 * Note that the caller is responsible for clearing buffers passed to the hash
 * engine after the engine has finished. The context is cleared by SHA256Final. */
#define PARANOID

/* define to correct endianness for little-endian systems (x86).
 * If you have a little-endian machine and need to conform to the standards,
 * you need to define this. While you need this for interoperability,
 * it is not required if this implementation is only used on little-endian
 * machines and is never required to work in conjunction with other
 * SHA-256 implementations. It will make the implementation ca. 5% faster
 * if you skip endianness conversion.
 * Obviously, for the test vectors to pass, you need to activate this on 
 * little-endian machines. Whatever you do, don't define this on a
 * big-endian system.
 * If the above doesn't make any sense to you, and you're on an
 * Intel (or compatible) system, just leave it defined.
 */
//#define CONVERT_ENDIANNESS

/* define this to use an alternative method for the SHA-256 core rounds
 * this might be faster on some systems, and slower on others.
 * On a Dual Celeron 400A running Win NT 4, using MSVC5 (optimized for speed)
 * the alternative core performs very slightly better (1%). Please report any
 * observations you make regarding speeds of the different cores to me.
 */
#define ALTERNATIVE_CORE

/* define to build test application -- do not define this if you want to
 * use this library in another program.
 */
//#define SHA256_TEST

/* include if you want to test against additional, inofficial test vectors
 * this has no effect if SHA256_TEST is not defined.
 */
/*#include "sha256v.h"*/

/* very verbose mode prints all intermediate round data to verify against
 * those presented in the specs. If calling application allows the use of
 * printf(), this may be used without the test application.
 */
/*#define VERY_VERBOSE*/

/* define if you want the test app to do some basic benchmarking
 * this is currently unportable, as it uses Win's GetTickCount.
 * It should be easy to exchange this function with a portable
 * function call which returns some kind of tick count.
 * this has no effect if SHA256_TEST is not defined.
 */
/*#define SHA256_TIME*/

/********************************************************************************/


/* this method should not be called from the outside.
 * see sha256.h for public methods. */
void SHA256Transform(SHA256_CTX* ctx, unsigned char block[64]);

#ifdef SHA256_TEST
# include <stdio.h> /* for printf */
# include <string.h> /* for strlen */
# ifdef SHA256_TIME
# include <windows.h> /* for GetTickCount */
# endif
#else
# ifdef VERY_VERBOSE
#  include <stdio.h> /* for printf */
# endif
#endif

/* use MS VC intrinsic rotate if available,
 * results in speed improvement of up to 15% */
#ifdef _MSC_VER
# include <stdlib.h>
# pragma intrinsic(_lrotr)
# pragma intrinsic(_lrotl)
# define ROTR(x,y)  _lrotr((x),(y))
# define ROTL(x,y)  _lrotl((x),(y))
#else /*_MSC_VER*/
  /* else use generic rotate */
# define ROTR(x,y)	(((x)>>(y)) | ((x)<<(32-(y))))
# define ROTL(x,y)	(((x)<<(y)) | ((x)>>(32-(y))))
#endif /*_MSC_VER*/

/* define very basic operations shift and rotate */
/* the names seem twisted but the specs use them
 * in exactly this way. */
#define S(x,y)  ROTR((x),(y))
#define R(x,y)  ((x)>>(y))

/* define byte swap operations */
#ifdef CONVERT_ENDIANNESS
# define bswap(x)       ((ROTR((x),8) & 0xFF00FF00) | (ROTL((x),8) & 0x00FF00FF))
# define bswapcopy(x,y) (x) = bswap(y)
#endif /* CONVERT_ENDIANNESS */

/* SHA-256 function macros */
/* the specs define XOR for Ch and Maj, but OR produces
 * semantically equal results for reasons of boolean algebra */
#define Ch(x,y,z)	(((x)&(y)) | ((~(x))&(z)))
#define Maj(x,y,z)	(((x)&(y)) | ((x)&(z)) | ((y)&(z)))
#define S0(x)		(S((x), 2) ^ S((x),13) ^ S((x),22))
#define S1(x)		(S((x), 6) ^ S((x),11) ^ S((x),25))
#define s0(x)		(S((x), 7) ^ S((x),18) ^ R((x), 3))
#define s1(x)		(S((x),17) ^ S((x),19) ^ R((x),10))

/* Initializes the engine */
void SHA256Init(SHA256_CTX* ctx)
{
	/* fractional parts of square roots of first eigth primes */
	ctx->H1 = 0x6a09e667;
	ctx->H2 = 0xbb67ae85;
	ctx->H3 = 0x3c6ef372;
	ctx->H4 = 0xa54ff53a;
	ctx->H5 = 0x510e527f;
	ctx->H6 = 0x9b05688c;
	ctx->H7 = 0x1f83d9ab;
	ctx->H8 = 0x5be0cd19;

	ctx->leftover.len = 0;

    ctx->hbits = 0;
    ctx->lbits = 0;

	return;
}

/* Update the intermediate hash with more plaintext */
void SHA256Update(SHA256_CTX* ctx, unsigned char* buffer, unsigned long len)
{	
	unsigned int blocks;
	unsigned int chars;
	unsigned int i;
	unsigned char* p;

    /* increase bitcount */
    ctx->lbits += len*8;
    if(ctx->lbits < len*8)
        ctx->hbits++;

	/* find out number of blocks to crunch */
	chars = len + ctx->leftover.len;
	blocks = chars >> 6;

	if(blocks)
	{
		if(ctx->leftover.len)
		{
			/* fill up leftover with buffer data */
			p = ctx->leftover.buf + ctx->leftover.len;
			for(i = 0; i < 64 - ctx->leftover.len; i++)
				p[i] = buffer[i];

			SHA256Transform(ctx, ctx->leftover.buf);
			blocks--;
		}
		else
			ctx->leftover.len = 64;	/* no leftover pretransformed - correct calculation below */

		for(i = 0; i < blocks; i++)
			SHA256Transform(ctx, buffer - ctx->leftover.len + (i+1)*64);

		ctx->leftover.len = chars % 64;
		if(ctx->leftover.len)
		{
			/* copy rest of buffer to leftover */
			p = buffer + len - ctx->leftover.len;
			for(i = 0; i < ctx->leftover.len; i++)
				ctx->leftover.buf[i] = p[i];
		}
	}
	else
	{
		/* add buffer to leftover */
		p = ctx->leftover.buf + ctx->leftover.len;
		for(i = 0; i < len; i++)
			p[i] = buffer[i];
		ctx->leftover.len += len;
	}

#ifdef PARANOID
	blocks = 0;
	chars = 0;
	i = 0;
	p = (unsigned char*)0;
#endif /* PARANOID */

	return;
}

/* Finalize hash value and clean up */
void SHA256Final(unsigned char digest[32], SHA256_CTX* ctx)
{
	unsigned int i;

    /* store byte 1000000b at end of buf */
	ctx->leftover.buf[ctx->leftover.len] = 0x80;
	/* pad rest */
	for(i = ctx->leftover.len + 1; i < 64; i++)
		ctx->leftover.buf[i] = 0x00;
	
	/* does 64bit large numofmessagebits fit into leftover? */
	if(ctx->leftover.len > 55)
	{
		/* need to pad with 0 and crunch another block */
		SHA256Transform(ctx, ctx->leftover.buf);
		/* pad new up to begin of actual 40bit size value (we are cheating!) */
		for(i = 0; i <= ctx->leftover.len; i++)
			ctx->leftover.buf[i] = 0x00;
	}

    /* store bitcount into end of last buffer */
#ifdef CONVERT_ENDIANNESS
    bswapcopy(*((unsigned long*)(ctx->leftover.buf+56)), ctx->hbits);
	bswapcopy(*((unsigned long*)(ctx->leftover.buf+60)), ctx->lbits);
#else /* CONVERT_ENDIANNESS */
	*((unsigned long*)(ctx->leftover.buf+56)) = ctx->hbits;
	*((unsigned long*)(ctx->leftover.buf+60)) = ctx->lbits;
#endif /* CONVERT_ENDIANNESS */

    SHA256Transform(ctx, ctx->leftover.buf);

	/* copy hash */
#ifdef CONVERT_ENDIANNESS
    bswapcopy(((unsigned long*)digest)[0], ctx->H1);
	bswapcopy(((unsigned long*)digest)[1], ctx->H2);
	bswapcopy(((unsigned long*)digest)[2], ctx->H3);
	bswapcopy(((unsigned long*)digest)[3], ctx->H4);
	bswapcopy(((unsigned long*)digest)[4], ctx->H5);
	bswapcopy(((unsigned long*)digest)[5], ctx->H6);
	bswapcopy(((unsigned long*)digest)[6], ctx->H7);
    bswapcopy(((unsigned long*)digest)[7], ctx->H8);
#else /* CONVERT_ENDIANNESS */
	((unsigned long*)digest)[0] = ctx->H1;
	((unsigned long*)digest)[1] = ctx->H2;
	((unsigned long*)digest)[2] = ctx->H3;
	((unsigned long*)digest)[3] = ctx->H4;
	((unsigned long*)digest)[4] = ctx->H5;
	((unsigned long*)digest)[5] = ctx->H6;
	((unsigned long*)digest)[6] = ctx->H7;
    ((unsigned long*)digest)[7] = ctx->H8;
#endif /* CONVERT_ENDIANNESS */

#ifdef PARANOID
    ctx->H1 = 0;
    ctx->H2 = 0;
    ctx->H3 = 0;
    ctx->H4 = 0;
    ctx->H5 = 0;
    ctx->H6 = 0;
    ctx->H7 = 0;
    ctx->H8 = 0;
    ctx->leftover.len = 0;
	for(i = 0; i < 16; i++);
        ((unsigned long*)ctx->leftover.buf)[i] = 0;
    ctx->hbits = ctx->lbits = 0;
#endif /* PARANOID */

    return;
}

/* Crunches a single block into the hash */
#include <stdio.h>
void SHA256Transform(SHA256_CTX* ctx, unsigned char block[64])
{
    unsigned long W[64]; /* Wj expanded message blocks */
	unsigned int i;
    unsigned long T1;
#ifdef ALTERNATIVE_CORE
	unsigned long reg[72]; /* a to h shifting registers */
#else /* ALTERNATIVE_CORE */
    unsigned long a, b, c, d, e, f, g, h;
#endif /* ALTERNATIVE_CORE */

    /* expand message blocks */
#ifdef CONVERT_ENDIANNESS
	bswapcopy(W[ 0], ((unsigned long*)block)[ 0]);
	bswapcopy(W[ 1], ((unsigned long*)block)[ 1]);
	bswapcopy(W[ 2], ((unsigned long*)block)[ 2]);
	bswapcopy(W[ 3], ((unsigned long*)block)[ 3]);
	bswapcopy(W[ 4], ((unsigned long*)block)[ 4]);
	bswapcopy(W[ 5], ((unsigned long*)block)[ 5]);
	bswapcopy(W[ 6], ((unsigned long*)block)[ 6]);
	bswapcopy(W[ 7], ((unsigned long*)block)[ 7]);
	bswapcopy(W[ 8], ((unsigned long*)block)[ 8]);
	bswapcopy(W[ 9], ((unsigned long*)block)[ 9]);
	bswapcopy(W[10], ((unsigned long*)block)[10]);
	bswapcopy(W[11], ((unsigned long*)block)[11]);
	bswapcopy(W[12], ((unsigned long*)block)[12]);
	bswapcopy(W[13], ((unsigned long*)block)[13]);
	bswapcopy(W[14], ((unsigned long*)block)[14]);
	bswapcopy(W[15], ((unsigned long*)block)[15]);
#else /* CONVERT_ENDIANNESS */
	W[ 0] = ((unsigned long*)block)[ 0];
	W[ 1] = ((unsigned long*)block)[ 1];
	W[ 2] = ((unsigned long*)block)[ 2];
	W[ 3] = ((unsigned long*)block)[ 3];
	W[ 4] = ((unsigned long*)block)[ 4];
	W[ 5] = ((unsigned long*)block)[ 5];
	W[ 6] = ((unsigned long*)block)[ 6];
	W[ 7] = ((unsigned long*)block)[ 7];
	W[ 8] = ((unsigned long*)block)[ 8];
	W[ 9] = ((unsigned long*)block)[ 9];
	W[10] = ((unsigned long*)block)[10];
	W[11] = ((unsigned long*)block)[11];
	W[12] = ((unsigned long*)block)[12];
	W[13] = ((unsigned long*)block)[13];
	W[14] = ((unsigned long*)block)[14];
	W[15] = ((unsigned long*)block)[15];
#endif /* CONVERT_ENDIANNESS */
	for(i = 16; i < 64; i++)
		W[i] = s1(W[i-2]) + W[i-7] + s0(W[i-15]) + W[i-16];

#ifdef VERY_VERBOSE
    printf("\n");
	printf("buffer: %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x\n", W[ 0], W[ 1], W[ 2], W[ 3], W[ 4], W[ 5], W[ 6], W[ 7]);
	printf("        %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x\n", W[ 8], W[ 9], W[10], W[11], W[12], W[13], W[14], W[15]);
    printf("\n");
    printf("            a        b        c        d        e        f        g        h   \n");
    printf("\n");
#endif /* VERY_VERBOSE */

#ifdef ALTERNATIVE_CORE
	
    /* init registers with (i-1)th intermediate hash value */
	reg[7] = ctx->H1;
	reg[6] = ctx->H2;
	reg[5] = ctx->H3;
	reg[4] = ctx->H4;
	reg[3] = ctx->H5;
	reg[2] = ctx->H6;
	reg[1] = ctx->H7;
	reg[0] = ctx->H8;

#ifdef VERY_VERBOSE
	printf("init:   %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x\n", reg[7], reg[6], reg[5], reg[4], reg[3], reg[2], reg[1], reg[0]);
#endif /* VERY_VERBOSE */
   
	/* apply the SHA-256 compression function to update registers */
    for(i = 0; i < 64; i++)
	{
        /* h:0 g:1 f:2 e:3 d:4 c:5 b:6 a:7 */
		/* T1 = h + S1(e) + Ch(e,f,g) + Ki + Wi */
		T1 = reg[i] + S1(reg[i+3]) + Ch(reg[i+3],reg[i+2],reg[i+1]) + K[i] + W[i];
		/* e(+1) = d + T1 */
		reg[i+4] += T1;
		/* a(+1) = T1 + S0(a) + Maj(a,b,c) */
		reg[i+8] = T1 + S0(reg[i+7]) + Maj(reg[i+7],reg[i+6],reg[i+5]);

#ifdef VERY_VERBOSE
        printf("t = %2i  %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x\n", i, reg[i+8], reg[i+7], reg[i+6], reg[i+5], reg[i+4], reg[i+3], reg[i+2], reg[i+1]);
#endif /* VERY_VERBOSE */
	}

   	/* add reg[0..7] to intermediate hash value */
	ctx->H1 += reg[71];
	ctx->H2 += reg[70];
	ctx->H3 += reg[69];
	ctx->H4 += reg[68];
	ctx->H5 += reg[67];
	ctx->H6 += reg[66];
	ctx->H7 += reg[65];
	ctx->H8 += reg[64];

#else /* ALTERNATIVE_CORE */

    /* init registers with (i-1)th intermediate hash value */
	a = ctx->H1;
	b = ctx->H2;
	c = ctx->H3;
	d = ctx->H4;
	e = ctx->H5;
	f = ctx->H6;
	g = ctx->H7;
	h = ctx->H8;

#ifdef VERY_VERBOSE
	printf("init:   %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x\n", a, b, c, d, e, f, g, h);
#endif /* VERY_VERBOSE */


    /* define the single round macro */
#ifdef VERY_VERBOSE
# define ROUND(a_,b_,c_,d_,e_,f_,g_,h_) T1 = (h_) + S1((e_)) + Ch((e_),(f_),(g_)) + K[i] + W[i]; \
	(d_) += T1; \
	(h_) = T1 + S0((a_)) + Maj((a_),(b_),(c_)); \
    printf("t = %2i  %.8x %.8x %.8x %.8x %.8x %.8x %.8x %.8x\n", i, h_, a_, b_, c_, d_, e_, f_, g_); \
    i++
#else /* VERY_VERBOSE */
# define ROUND(a_,b_,c_,d_,e_,f_,g_,h_) T1 = (h_) + S1((e_)) + Ch((e_),(f_),(g_)) + K[i] + W[i]; \
	(d_) += T1; \
	(h_) = T1 + S0((a_)) + Maj((a_),(b_),(c_)); \
    i++
#endif /* VERY_VERBOSE */

	/* apply the SHA-256 compression function to update registers */
    i = 0;
    while(i < 64)
    {
	    ROUND(a,b,c,d,e,f,g,h);
	    ROUND(h,a,b,c,d,e,f,g);
	    ROUND(g,h,a,b,c,d,e,f);
	    ROUND(f,g,h,a,b,c,d,e);
	    ROUND(e,f,g,h,a,b,c,d);
	    ROUND(d,e,f,g,h,a,b,c);
	    ROUND(c,d,e,f,g,h,a,b);
	    ROUND(b,c,d,e,f,g,h,a);
    }

	/* add reg[0..7] to intermediate hash value */
	ctx->H1 += a;
	ctx->H2 += b;
	ctx->H3 += c;
	ctx->H4 += d;
	ctx->H5 += e;
	ctx->H6 += f;
	ctx->H7 += g;
	ctx->H8 += h;

#endif /* ALTERNATIVE_CORE */


#ifdef VERY_VERBOSE
    printf("\n");
    printf("-------------------------------------------------------------------------------\n");
#endif /* VERY_VERBOSE */


#ifdef PARANOID
    T1 = 0;
    for(i = 0; i < 64; i++)
        W[i] = 0;
# ifdef ALTERNATIVE_CORE
    for(i = 0; i < 72; i++)
	    reg[i] = 0;
# else /* ALTERNATIVE_CORE */
    a = b = c = d = e = f = g = h = 0;
# endif /* ALTERNATIVE_CORE */
#endif /* PARANOID */

	return;
}

#ifdef SHA256_TEST
/* Test app */
void hashstring(SHA256_CTX ctx, unsigned char hash[32], unsigned char* string, unsigned long len);
int main(int argc, char*argv[])
{
	SHA256_CTX ctx;
	unsigned char hash[32];
    unsigned int errors = 0;

#ifdef INOFFICIAL_VECTORS
    unsigned int i;
#endif /* INOFFICIAL_VECTORS */

#ifdef SHA256_TIME
    unsigned int j;
    unsigned int starttime;
    unsigned int endtime;
    unsigned int timelen;
    unsigned char timestring[] = "abcabcabc";

#endif /* SHA256_TIME */



    /* official test vector 1 */
    unsigned char string1[] = "abc";
    unsigned char hash1[] = {0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
                             0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
                             0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
                             0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};

    /* official test vector 2 */
    unsigned char string2[] = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
    unsigned char hash2[] = {0x24, 0x8d, 0x6a, 0x61, 0xd2, 0x06, 0x38, 0xb8,
                             0xe5, 0xc0, 0x26, 0x93, 0x0c, 0x3e, 0x60, 0x39,
                             0xa3, 0x3c, 0xe4, 0x59, 0x64, 0xff, 0x21, 0x67,
                             0xf6, 0xec, 0xed, 0xd4, 0x19, 0xdb, 0x06, 0xc1};

    printf("SHA-256 - Secure Hashing Algorithm v2 Implementation\n");
    printf("Copyright (C) 2000-2001, Daniel Roethlisberger <admin@roe.ch>\n");
    printf("Distributed under the GNU Lesser General Public License.\n");
    printf("See http://www.gnu.org/copyleft for details.\n\n");

    printf("Testing:\n");
    
    printf("         against  official  test vector  1... ");
    hashstring(ctx, hash, string1, strlen(string1));
    if(!memcmp(hash, hash1, 32))
        printf("PASSED.\n");
    else
    {
        printf("FAILED.\n");
        errors++;
    }

    printf("         against  official  test vector  2... ");
    hashstring(ctx, hash, string2, strlen(string2));
    if(!memcmp(hash, hash2, 32))
        printf("PASSED.\n");
    else
    {
        printf("FAILED.\n");
        errors++;
    }

    /* inofficial test vectors are in sha256v.h */
#ifdef INOFFICIAL_VECTORS

    for(i = 0; i < INOFFICIAL_VECTORS; i++)
    {
        printf("         against inofficial test vector %2i... ", i+1);
        hashstring(ctx, hash, vector[i][0], vectorlen[i]);
        if(!memcmp(hash, vector[i][1], 32))
            printf("PASSED.\n");
        else
        {
            printf("FAILED.\n");
            errors++;
        }
    }
#endif /* INOFFICIAL_VECTORS */

    if(errors)
    {
        printf("\nWARNING! There were %i test vectors that have failed!\n"
            "Please let me know about the details of this failure (admin@roe.ch).\n\n", errors);
    }
    else
    {
        printf("\nAll available test vectors passed.\n"
            "It should be safe to use this implementation compiled with this compiler.\n\n");
    }

#ifdef SHA256_TIME
    printf("Running benchmark on short strings...");
    
    starttime = GetTickCount();
    timelen = strlen(timestring);
    for(j = 0; j < 1024*1024; j++)
    {
        hashstring(ctx, hash, timestring, timelen);
    }
    endtime = GetTickCount();
    printf(" [%i ticks]\n\n", endtime - starttime);
#endif /* SHA256_TIME */

    return errors;
}
/* performs a test hash */
void hashstring(SHA256_CTX ctx, unsigned char hash[32], unsigned char* string, unsigned long len)
{
    SHA256Init(&ctx);
	SHA256Update(&ctx, string, len);
	SHA256Final(hash, &ctx);

#ifdef VERY_VERBOSE
    printf("\n");
    printf("hash:   %.2x%.2x%.2x%.2x %.2x%.2x%.2x%.2x %.2x%.2x%.2x%.2x %.2x%.2x%.2x%.2x"
                  " %.2x%.2x%.2x%.2x %.2x%.2x%.2x%.2x %.2x%.2x%.2x%.2x %.2x%.2x%.2x%.2x\n",
            hash[ 00], hash[ 01], hash[ 02], hash[ 03], hash[ 04], hash[ 05], hash[ 06], hash[ 07],
            hash[010], hash[011], hash[012], hash[013], hash[014], hash[015], hash[016], hash[017],
            hash[020], hash[021], hash[022], hash[023], hash[024], hash[025], hash[026], hash[027],
            hash[030], hash[031], hash[032], hash[033], hash[034], hash[035], hash[036], hash[037]);
    printf("\n");
    printf("-------------------------------------------------------------------------------\n\n");
#endif /* VERY_VERBOSE */
}
#endif /* SHA256_TEST */

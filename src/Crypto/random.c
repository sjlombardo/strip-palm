
#include "random.h"
#include "types.h"
#include "sha256.h"

#ifdef NOPILOT 
#include "posix_compat.h"
#include <stdlib.h>
#include <stdio.h>
#else
#include <PalmOS.h>
#endif

#define READSIZE (MD_DIGESTSIZE/2)

static byte e_pool[POOL_SIZE];
static int e_read_location = 0, e_used = 0, e_write_location = 0, e_filled=0;
static byte e_md[MD_DIGESTSIZE];

void random_clean() {
	e_read_location=0;
	e_used=0;
	e_write_location=0;
	e_filled=0;
	MemSet(e_pool, sizeof(e_pool), 0);
	MemSet(e_md, sizeof(e_md), 0);
}

int random_bytes_created() {
	return e_filled; 
}

int random_bytes_used() {
	return e_read_location;
}

int random_bytes_available() {
	return e_write_location - e_read_location;
}

void random_seed(byte * in, int length) {
	int i, j, len, bytes_left;
    SHA256_CTX sha256_ctx;

	int w_location = e_write_location;

	/*	increment e_location, wrap around if we reached the end of the pool*/
	e_write_location += length;
	if (e_write_location >= POOL_SIZE) {
		e_write_location -= POOL_SIZE;
	}

	/*	Loop through, taking digests of locations 
		in the entropy pool until we fill up output */
	for( i = 0 ; i < length; i += MD_DIGESTSIZE) {
		bytes_left = length - i;
		bytes_left = ( bytes_left > MD_DIGESTSIZE) ? MD_DIGESTSIZE : bytes_left ;	
    	SHA256Init(&sha256_ctx);

		/*	Currently stored digest info */
   		SHA256Update(&sha256_ctx, e_md, MD_DIGESTSIZE);
		
		len = ( (POOL_SIZE - w_location) < MD_DIGESTSIZE ) ? 
			(POOL_SIZE - w_location) : MD_DIGESTSIZE;
   		SHA256Update(&sha256_ctx, &(e_pool[w_location]), len);
		if(len < MD_DIGESTSIZE) 
    		SHA256Update(&sha256_ctx, &(e_pool[0]), MD_DIGESTSIZE-len);

    	SHA256Update(&sha256_ctx, &(in[i]) , bytes_left);
    	SHA256Final(e_md, &sha256_ctx);

		/*	mix up the pool in the area that we just used with the
			bytes from the message digest */
		for (j=0; j < MD_DIGESTSIZE; j++) {
			if(w_location >= POOL_SIZE) 
				w_location = 0;
			e_pool[w_location++]^=e_md[j];
		}
		(e_filled < POOL_SIZE) ? (e_filled += MD_DIGESTSIZE) : (e_filled);
	}
	e_used=1;	
}

void random_bytes(byte * out, int length) {

	int i, j, len, bytes_left;
    SHA256_CTX sha256_ctx;
	int r_location = e_read_location;

	/*	if not e_used then they are calling
		random_bytes BEFORE seeding. We will
		scrape together what entropy we can
		and seed. */
	if( !e_used ) {
		random_seed((byte *) &length, 4);
	}

	/*	increment e_location, wrap around if we reached the end of the pool*/
	e_read_location += length;
	if (e_read_location >= POOL_SIZE) {
		e_read_location -= POOL_SIZE;
		//e_read_location = 0;
	}

	/* 	must check if read_location will surpass write location
		if so, set back read_location */
	if ((e_read_location > e_write_location) && (e_filled < POOL_SIZE)) {
		e_read_location = e_read_location%e_write_location;
		r_location = e_read_location;
		e_read_location += length;
	}
 
	/*	Loop through, taking digests of locations 
		in the entropy pool until we fill up output */
	for( i = 0 ; i < length; i += READSIZE) {

		bytes_left = length - i;
		bytes_left = ((bytes_left > READSIZE) ? READSIZE : bytes_left);	
		//bytes_left = ((length > READSIZE) ? READSIZE : bytes_left);	
    	SHA256Init(&sha256_ctx);
		
		/*	Currently stored digest info */
   		SHA256Update(&sha256_ctx, e_md, MD_DIGESTSIZE);

		/*	First update consists of bytes from the current "read"
			location in the pool. If e_location is to close to 
			end of the pool, shorten the number of bytes to use,
			and wrap around to the beginning */
		len = ( (POOL_SIZE - r_location) < READSIZE ) ? 
			(POOL_SIZE - r_location) : READSIZE ;
   		SHA256Update(&sha256_ctx, &(e_pool[r_location]), len);
		if(len < READSIZE) 
    		SHA256Update(&sha256_ctx, &(e_pool[0]), READSIZE-len);

    	SHA256Final(e_md, &sha256_ctx);

		/*	mix up the pool in the area that we just used with the
			first half of the bytes from the message digest */
		for (j=0; j < READSIZE; j++) {
			if(r_location >= POOL_SIZE) 
				r_location = 0;
			e_pool[r_location++]^=e_md[j];
		}	

		/* Move data onto the output buffer */
		MemMove(&(out[i]), &(e_md[READSIZE]), bytes_left);
	}		
	
}

#ifdef TEST

#include <time.h>

unsigned char * bin2hex (byte * in, int length) {
    static unsigned char cipher_tmp[200];
    int j;
    for (j = 0; j < length; j++) {
        sprintf(&((char *) cipher_tmp)[2 * j], "%.2x",
            in[j]);
    }
    return cipher_tmp;
}  

int main( char argc, char **argv ) {

	byte random[32];
	byte * buffer;
	int i;
	//long t = time(&t);	
	long t = 100000;	

	for(i= 0; i < 400; i++){
		fprintf(stderr, "%d, ", i);
		buffer = malloc(i);
		random_bytes(buffer, i);
		random_seed(buffer, i);
		free(buffer);
	}

	for(i = 0; i < 20; i++) {
		random_bytes(random, sizeof(random));
		printf("%d: %s\n", i, bin2hex(random, 32));
	}
	random_clean();
	exit(0);
}

#endif

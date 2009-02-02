#include <stdlib.h>
#include "types.h"
#include "crypt.h"
#include "rijndael.h"

unsigned char * bin2hex (byte * in, int length) {
	static unsigned char cipher_tmp[200];
	int j;
	for (j = 0; j < length; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2X",
			in[j]);
	}
	return cipher_tmp;
}

int main()
{
	char *keyword;
	unsigned char *plaintext;
	unsigned char *ciphertext;
	char *prevciphertext;
	unsigned char *ciphertemp;
	int  j, i, iteration;
	
	/*printf("Blocksize: %d\nKeysize: %d\n", RIJNDAEL_BLOCKSIZE, RIJNDAEL_KEYSIZE);*/

	keyword = calloc(1, RIJNDAEL_KEYSIZE);
	prevciphertext = calloc(1, RIJNDAEL_KEYSIZE);
	ciphertemp = calloc(1,RIJNDAEL_KEYSIZE);
	ciphertext = calloc(1,RIJNDAEL_BLOCKSIZE);
	plaintext = calloc(1,RIJNDAEL_BLOCKSIZE);

	for(iteration=0; iteration< 400; iteration++) {
		printf("I=%d\n", iteration);	
		printf("KEY=%s\n", bin2hex(keyword, RIJNDAEL_KEYSIZE));	
		printf("PT=%s\n", bin2hex(plaintext, RIJNDAEL_BLOCKSIZE));	

		for(i=0; i<10000; i++) {
			memmove(prevciphertext, ciphertext, RIJNDAEL_BLOCKSIZE);
			stripCrypt(keyword, plaintext, ciphertext, RIJNDAEL_BLOCKSIZE, 1);
			memmove(plaintext, ciphertext, RIJNDAEL_BLOCKSIZE);
		}
		printf("CT=%s\n\n", bin2hex(ciphertext, RIJNDAEL_BLOCKSIZE));	
		memmove(ciphertemp, prevciphertext, RIJNDAEL_BLOCKSIZE);
		memmove(ciphertemp+RIJNDAEL_BLOCKSIZE, ciphertext, RIJNDAEL_BLOCKSIZE);
		for(j=0; j<RIJNDAEL_KEYSIZE; j++) 
			keyword[j]=keyword[j]^ciphertemp[j];
	}
	
	return 0;
}


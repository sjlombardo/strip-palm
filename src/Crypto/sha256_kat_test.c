#include <stdlib.h>
#include "types.h"
#include "crypt.h"
#include "sha256_driver.h"

#define INPUT0 "abc"
#define MD0 "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad" 
#define INPUT1 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#define MD1 "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"

unsigned char * bin2hex (byte * in, int length) {
	static unsigned char cipher_tmp[200];
	int j;
	for (j = 0; j < length; j++) {
		sprintf(&((char *) cipher_tmp)[2 * j], "%.2x",
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

	ciphertext = calloc(1,MD_DIGESTSIZE);

	printf("PT=%s\n",INPUT0 );	
	md_string(INPUT0, ciphertext);
	printf("EXP=%s\n", MD0);	
	printf("GOT=%s\n", bin2hex(ciphertext,MD_DIGESTSIZE));	
	if (strcmp(MD0, bin2hex(ciphertext,MD_DIGESTSIZE))==0) printf("OK!\n\n");
	else printf("ERROR!\n\n");

	printf("PT=%s\n",INPUT1 );	
	md_string(INPUT1, ciphertext);
	printf("EXP=%s\n", MD1);	
	printf("GOT=%s\n", bin2hex(ciphertext,MD_DIGESTSIZE));	
	if (strcmp(MD1, bin2hex(ciphertext,MD_DIGESTSIZE))==0) printf("OK!\n\n");
	else printf("ERROR!\n\n");

	return 0;
}


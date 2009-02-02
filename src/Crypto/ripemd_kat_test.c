#include <stdlib.h>
#include "types.h"
#include "crypt.h"
#include "ripemd_driver.h"

#define INPUT0 "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
#define MD0 "b0e20b6e3116640286ed3a87a5713079b21f5189"
#define INPUT1 "abcdefghijklmnopqrstuvwxyz"
#define MD1 "f71c27109c692c1b56bbdceb5b9d2865b3708dbc"
#define INPUT2 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
#define MD2 "12a053384a9c0c88e405a06c27dcf49ada62eb2b"  


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

	ciphertext = calloc(1,RIPEMD_DIGESTSIZE);

	printf("PT=%s\n",INPUT0 );	
	ripemd_string(INPUT0, ciphertext);
	printf("EXP=%s\n", MD0);	
	printf("GOT=%s\n", bin2hex(ciphertext,RIPEMD_DIGESTSIZE));	
	if (strcmp(MD0, bin2hex(ciphertext,RIPEMD_DIGESTSIZE))==0) printf("OK!\n\n");
	else printf("ERROR!\n\n");

	printf("PT=%s\n",INPUT1 );	
	ripemd_string(INPUT1, ciphertext);
	printf("EXP=%s\n", MD1);	
	printf("GOT=%s\n", bin2hex(ciphertext,RIPEMD_DIGESTSIZE));	
	if (strcmp(MD1, bin2hex(ciphertext,RIPEMD_DIGESTSIZE))==0) printf("OK!\n\n");
	else printf("ERROR!\n\n");

	printf("PT=%s\n",INPUT2 );	
	ripemd_string(INPUT2, ciphertext);
	printf("EXP=%s\n", MD2);	
	printf("GOT=%s\n", bin2hex(ciphertext,RIPEMD_DIGESTSIZE));	
	if (strcmp(MD2, bin2hex(ciphertext,RIPEMD_DIGESTSIZE))==0) printf("OK!\n\n");
	else printf("ERROR!\n\n");

	return 0;
}


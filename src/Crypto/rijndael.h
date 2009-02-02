
#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#include "types.h"

typedef struct rijndael_instance {
	int Nk,Nb,Nr;
	word8 fi[24],ri[24];
	word32 fkey[120];
	word32 rkey[120];
} RI;

void rijndael_encrypt(RI * , word8 * );
void rijndael_decrypt(RI * , word8 * );
void rijndael_set_key(RI * , word8 * , int );

#define RIJNDAEL_KEYSIZE 32
#define RIJNDAEL_BLOCKSIZE 16

#endif

/*
 * Copyright (C) 1998,1999,2000 Nikos Mavroyanopoulos
 * 
 * This library is free software; you can redistribute it and/or modify it 
 * under the terms of the GNU Library General Public License as published 
 * by the Free Software Foundation; either version 2 of the License, or 
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 02111-1307, USA.
 */



#include "types.h"
#include "crypt.h"
#include "rijndael.h"
#include "rijndael_cbc.h"
#ifdef NOPILOT
#include "posix_compat.h"
#include <stdlib.h>
#else
#include <PalmOS.h>
#endif

/* CBC MODE */

int rijndael_cbc_init( CBC_BUFFER* buf, void *IV)
{
/* For cbc */
	MemMove(buf->previous_ciphertext, IV, RIJNDAEL_BLOCKSIZE);
	MemMove(buf->previous_plaintext, IV, RIJNDAEL_BLOCKSIZE);
	return 0;
}

int rijndael_cbc_encrypt( CBC_BUFFER* buf, void *plaintext, int len, void* akey)
{
	word32 *fplain = plaintext;
	word32 *plain;
	int i, j; 
	
	for (j = 0; j < len / RIJNDAEL_BLOCKSIZE; j++) {
		plain = &fplain[j * RIJNDAEL_BLOCKSIZE / sizeof(word32)];

		for (i = 0; i < RIJNDAEL_BLOCKSIZE / sizeof(word32); i++) {
			plain[i] ^= buf->previous_ciphertext[i];
		}

		rijndael_encrypt(akey, (word8 *)plain);

		/* Copy the ciphertext to prev_ciphertext */
		MemMove(buf->previous_ciphertext, plain, RIJNDAEL_BLOCKSIZE);
	}

	return 0;
}

int rijndael_cbc_decrypt( CBC_BUFFER* buf, void *ciphertext, int len, void* akey)
{
	word32 *cipher;
	word32 *fcipher = ciphertext;
	int i, j; 

	for (j = 0; j < len / RIJNDAEL_BLOCKSIZE; j++) {

		cipher = &fcipher[j * RIJNDAEL_BLOCKSIZE / sizeof(word32)];
		MemMove(buf->previous_cipher, cipher, RIJNDAEL_BLOCKSIZE);
		rijndael_decrypt(akey, (word8 *) cipher);

		for (i = 0; i < RIJNDAEL_BLOCKSIZE / sizeof(word32); i++) {
			cipher[i] ^= buf->previous_plaintext[i];
		}

		/* Copy the ciphertext to prev_cipher */
		MemMove(buf->previous_plaintext, buf->previous_cipher, RIJNDAEL_BLOCKSIZE);
	}

	return 0;
}

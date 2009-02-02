/*
Program : Strip (Secure Tool for Recalling Important Passwords) 
Description: A secure password and account manager for the Palm(t) Computing Platform 
Copyright (C) 1999  Stephen J Lombardo

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

Strip has been written and developed by Stephen J Lombardo (Zetetic Enterprises) 1999

Contact Info:
lombardos@zetetic.net
http://www.zetetic.net/
Zetetic Enterprises
348 Wasington Ave 
Clifton NJ, 07011

Bug reports and feature requests should be sent to bugs@zetetic.net.


------RSA Data Security, Inc. MD5 Message Digest Algorithm-------------
Strip uses the MD5 message digest algorithm, Copyright (C) 1990, 
RSA Data Security, Inc. All rights reserved. See md5.c or md5.h 
for specific terms and warranty disclaimer from RSA Data Security Inc.
-----------------------------------------------------------------------

------Three-way block encryption---------------------------------------
Strip uses the 3-Way block encryption algoritm, Copyright (C) Joan 
Daemen. All rights reserved.
-----------------------------------------------------------------------

        <**  DO NOT EXPORT **>
Strip uses strong cryptography. "3-way" is a block algoritm with a
96 bit key length, and "MD5" creates a 128 bit message digest. In the 
United states it is currently illegal to export products describing
or incorporating encryption techniques with key lengths greater
than 40 bits. It is therefore illegal to export this program in
any format. Please dont get the government on my back...
*/

#ifdef NOPILOT
#include "posix_compat.h"
#include <stdlib.h>
#else
#include <PalmOS.h>
#endif

#include "crypt.h"
#include "block_cipher_driver.h"
#include "rijndael.h"

#ifdef STRIP_CBC
#include "rijndael_cbc.h"
#include "random.h"

#endif

/******************************************************
 * Function: getTWSize
 * Description: pass in the length of the data and this
 * function will return the size of the neccesary memory
 * allocation for 3-way run. Includes padding.
 * ****************************************************/
int getSCSize(int len)
{
    int c=0;

    if(len<RIJNDAEL_BLOCKSIZE)
        len=RIJNDAEL_BLOCKSIZE;
    c= (len/RIJNDAEL_BLOCKSIZE);
    if(!(len%RIJNDAEL_BLOCKSIZE)) {
#ifdef STRIP_CBC
        return(c*RIJNDAEL_BLOCKSIZE)+RIJNDAEL_BLOCKSIZE;
#else 
        return(c*RIJNDAEL_BLOCKSIZE);
#endif
    }
    else

#ifdef STRIP_CBC
        return (((c+1)*RIJNDAEL_BLOCKSIZE))+RIJNDAEL_BLOCKSIZE;
#else 
        return (((c+1)*RIJNDAEL_BLOCKSIZE));
#endif
}


/*******************************************************
 * Function: stripCrypt
 * Description: encrypts/decrypts a memory block. puts 
 * the results into an out buffer. ikey is the password
 * ****************************************************/
void stripCrypt(byte *ikey, void *str, void *out, int sLen, int enc)
{
	RI key;
	int pt_len=0;
#ifdef STRIP_CBC
	byte IV[RIJNDAEL_BLOCKSIZE];
	CBC_BUFFER cbc_state;	

	rijndael_set_key(&key, (void *) ikey, RIJNDAEL_KEYSIZE);
	pt_len = sLen - RIJNDAEL_BLOCKSIZE;
		
	if(enc) {
	
			// generate randomness for IV 
#ifdef NOPILOT
		int i;
		for (i=0; i< (RIJNDAEL_BLOCKSIZE/sizeof(int)); i++) {
			int rand_num= rand();
			MemMove(IV+(i*sizeof(int)), &rand_num, sizeof(int));
		}
#else
		random_bytes( IV, RIJNDAEL_BLOCKSIZE);
#endif		

		MemMove(out, IV,  RIJNDAEL_BLOCKSIZE);
		MemMove(out+RIJNDAEL_BLOCKSIZE, str, pt_len);
	
		rijndael_cbc_init( &cbc_state, IV);
		rijndael_cbc_encrypt( &cbc_state, out+RIJNDAEL_BLOCKSIZE, pt_len, &key);	
	}
	else {
		MemMove(IV, str, RIJNDAEL_BLOCKSIZE);
		MemMove(out, str+RIJNDAEL_BLOCKSIZE, pt_len);

		rijndael_cbc_init( &cbc_state, IV);
		rijndael_cbc_decrypt( &cbc_state, out, pt_len, &key);	
	}	
#else
	int offset=0;
	byte ciphertext[RIJNDAEL_BLOCKSIZE];
	rijndael_set_key(&key, (void *) ikey, RIJNDAEL_KEYSIZE);
	pt_len = sLen - RIJNDAEL_BLOCKSIZE;

	
	//encrypt or decrypt block by block
	for(;offset<sLen;)
	{
		MemMove(ciphertext, str+offset, RIJNDAEL_BLOCKSIZE);
		if(enc) 
			rijndael_encrypt(&key, (void *) ciphertext);
		else 
			rijndael_decrypt(&key, (void *) ciphertext);
		
		MemMove(out+offset, ciphertext, RIJNDAEL_BLOCKSIZE);
		offset+=RIJNDAEL_BLOCKSIZE;
	}        
		
	MemSet(ciphertext, RIJNDAEL_BLOCKSIZE, 0);
	MemSet(&key, sizeof(RI), 0);
#endif
}

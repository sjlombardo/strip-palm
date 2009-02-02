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

#include <PalmOS.h>
#include <Encrypt.h>
#include "md5_driver.h"

#define BLOCK_des 8

/******************************************************
 * Function: getSCSize
 * Description: pass in the length of the data and this
 * function will return the size of the neccesary memory
 * allocation for 3-way run. Includes padding.
 * ****************************************************/
int getSCSize_des(int len)
{
    int c=0;
    if(len<BLOCK_des)
        len=BLOCK_des;
    c= (len/BLOCK_des);
    if(!(len%BLOCK_des))
    {
        return(c*BLOCK_des);
    }
    else
        return (((c+1)*BLOCK_des));
}

/*******************************************************
 * Function: xorFold
 * Description: fold a 128bit hash into 64 bits.
 * *****************************************************/
void xOrFold(char * key)
{
	int i;
	for(i=0; i<8; i++)
	{
		key[i]^=key[i+8];
	}
}

/*******************************************************
 * Function: stripCrypt
 * Description: encrypts/decrypts a memory block. puts 
 * the results into an out buffer. dkey is the string
 * ****************************************************/
void stripCrypt_des(char * ikey, MemPtr str, MemPtr out, int sLen, int enc)
{
       int offset=0;
	   char ivector[BLOCK_des], ovector[BLOCK_des], k[16]; 
		Boolean e;

		(enc==1)?(e=true):(e=false);
            //generate the key.
       md5_string(ikey, k);
		xOrFold(k);

            //encrypt or decrypt block by block
       for(;offset<sLen;)
       {
           MemMove(ivector, str+offset, BLOCK_des);
			EncDES(ivector, k, ovector, e);
           MemMove(out+offset, ovector, BLOCK_des);
           offset+=BLOCK_des;
       }  
       
            // wipeout keying info.
       MemSet(ivector, sizeof(ivector), 0);
       MemSet(ovector, sizeof(ovector), 0);
       MemSet(k,sizeof(k), 0);
}

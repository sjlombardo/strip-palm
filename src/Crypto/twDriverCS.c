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
#include "tw.h"

extern void MDString(char *in, char *out);
extern void MDBlock(char *in, int len,  char *out);
extern void encrypt(word32 *block, word32 *key);
extern void decrypt(word32 *block, word32 *key);

/******************************************************
 * Function: getTWSize
 * Description: pass in the length of the data and this
 * function will return the size of the neccesary memory
 * allocation for 3-way run. Includes padding.
 * ****************************************************/
int getSCSizeA(int len)
{
    int c=0;
    if(len<BLOCKA)
        len=BLOCKA;
    c= (len/BLOCKA);
    if(!(len%BLOCKA))
    {
        return(c*BLOCKA);
    }
    else
        return (((c+1)*BLOCKA));
}

/********************************************************
 * Function: twKey
 * Description: pass this function a null terminated
 * string or char array and it will generate a valid 
 * 96 bit key for the 3-way encryption algorithm. 
 * Method: generate the digest of the passed in string
 * followed by the digest for that digest. concatonate
 * the two arrays and get one big array of 256 bits.
 * Ignore the last 64 bits. take the resulting 192 bits 
 * and fold the last 96 bits over the first 96 bits using
 * and XOR. i.e bit[n]^=bit[n+96]. the resulting array is
 * 96 bits its bit pattern is totaly dependent on the 
 * original strings message digest. If anyone cant think
 * of a better way to do this, let me know.
 * ******************************************************/
void twKey(char * ikey, MemPtr out)
{
       int i;
       char dKey[24], mdKey1[16], mdKey2[16];
      
       // Hash the input string, hash the output, then concatonate 
       MDString(ikey, mdKey1);
       MDBlock(mdKey1, 16, mdKey2);

       //concatanate the arrays
       MemMove(dKey, mdKey1, 16);
       MemMove(dKey+16, mdKey2, 8);

       //now fold dKey over itself at 96 bits, XORing as we go.
       for(i=0; i<12; i++)
       {
           dKey[i]^=dKey[i+BLOCKA];
       }

       MemMove(out, dKey, BLOCKA);
       
            //wipe out keying info.
       MemSet(dKey,0, sizeof(dKey));
       MemSet(mdKey1, 0, sizeof(mdKey1));
       MemSet(mdKey2, 0, sizeof(mdKey2));
}

/*******************************************************
 * Function: stripCrypt
 * Description: encrypts/decrypts a memory block. puts 
 * the results into an out buffer. ikey is the string
 * ****************************************************/
void stripCryptA(char * ikey, MemPtr str, MemPtr out, int sLen, int enc)
{
       word32 vector[3], key[3];
       int offset=0;

            //generate the key.
       twKey(ikey, key);
       
            //encrypt or decrypt block by block
       for(;offset<sLen;)
       {
           MemMove(vector, str+offset, BLOCKA);
           if(enc)
               encrypt(vector, key);
           else
               decrypt(vector, key);
               
           MemMove(out+offset, vector, BLOCKA);
           offset+=BLOCKA;
       }  
       
            // wipe out keying info.
       MemSet(vector, 0, sizeof(vector));
       MemSet(key, 0, sizeof(key));   
}

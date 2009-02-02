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

Thanks to Paul Schuurmans (schuur@mesa.nl) for working
on this patched version of md5Driver.c.  
*/

#ifdef NOPILOT
#include "posix_compat.h"
#include <stdlib.h>
#else
#include <PalmOS.h>
#endif

#include "types.h"
#include "sha256.h"
#include "sha256_driver.h"

/******************************************************
 * Function: sha256_block
 * Description: computes a message digest for a memory
 * block. Assumes the out array is of the proper size
 * ****************************************************/
void md_block(byte * inblock, int len, byte *out)
{
	SHA256_CTX sha256_ctx;
 
	SHA256Init(&sha256_ctx);
	SHA256Update(&sha256_ctx, inblock, len);
	SHA256Final(out, &sha256_ctx);

	MemSet(&sha256_ctx, sizeof(SHA256_CTX), 0); 
}


/******************************************************
 * Function: sha256_string
 * Description: computes a message digest for a string.
 * Assumes out array is of the proper size.
 * ****************************************************/
void md_string (char *inString, byte *out)
{
	unsigned int len = StrLen(inString);
	if(out == NULL || inString == NULL) return;
	md_block(inString, len, out);
}



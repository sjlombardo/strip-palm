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
#include "hybrid_md_driver.h"
#include "md5_driver.h"
#include "ripemd_driver.h"

/******************************************************
 * Function: md_string
 * Description: computes a message digest for a string.
 * Assumes out array is of the proper size.
 * ****************************************************/
void hybrid_md_string(char *in, byte *out)
{
	unsigned int len;
	if(out == NULL || in == NULL) return;
	len = StrLen(in);
	hybrid_md_block(in, len, out);
}

void hybrid_md_block(byte *in, int len, byte *out)
{
	if(out == NULL || in == NULL) return;
	ripemd_block(in, len, out);	
	EncDigestMD5(in, len, out+RIPEMD_DIGESTSIZE);
}

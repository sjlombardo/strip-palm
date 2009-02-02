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

------Idea block encryption---------------------------------------
Strip uses the Idea block encryption algoritm, Copyright (C) Ascom. All rights reserved.
Idea is a patented algorithm. It is free for non commercial use, if you wish to use 
this product or the Idea algorithm in general for commercial purposes, you must purchase a license
from Ascom at http://www.ascom.ch/infosec/idea/pricing.html
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
#include "StripCS.h"
#include "types.h"
#include "skey.h"
#include "strip_types.h"
#include "sha256_driver.h"
#include "account_hash.h"

#ifdef HAVE_GDBHOOK
#include "set_a4.h"
#else
#define SET_A4_FROM_A5
#define RESTORE_A4
#endif

static char * emptyString = "\0";

void ChangeAccountFormat(UInt16 i, Account_old * CurrAcc, Account * acct_new) {
	acct_new->SystemID = CurrAcc->SystemID;
	acct_new->AccountID = i;
	acct_new->username =CurrAcc->username;
	acct_new->password =CurrAcc->password;
	acct_new->system =CurrAcc->type;
	acct_new->comment=CurrAcc->comment;
	acct_new->service=emptyString;
	acct_new->key=emptyString;
	acct_new->series=99;
	acct_new->hash_type=HASHTYPE_MD5;
	acct_new->system_type= 0;
	acct_new->service_type= 0;
	acct_new->username_type= 0;
	acct_new->password_type= 0;
	acct_new->account_mod_date=TimGetSeconds();
	acct_new->password_mod_date=acct_new->account_mod_date;
	acct_new->binary_data_length=0;
	MemMove(acct_new->hash, generateAccountHash(acct_new), sizeof(md_hash));
}


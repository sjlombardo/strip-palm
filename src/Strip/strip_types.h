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


------Idea block encryption---------------------------------------
Strip uses the Idea block encryption algoritm, Copyright (C) Ascom. All rights reserved.
Idea is a patented algorithm. It is free for non commercial use, if you wish to use 
this product or the Idea algorithm in general for commercial purposes, you must purchase a license
from Ascom at http://www.ascom.ch/infosec/idea/pricing.html
-----------------------------------------------------------------------

        <**  DO NOT EXPORT **>
Strip uses strong cryptography. "Idea" is a block algoritm with a
128 bit key length, and "MD5" creates a 128 bit message digest. In the 
United states it is currently illegal to export products describing
or incorporating encryption techniques with key lengths greater
than 40 bits. It is therefore illegal to export this program in
any format. Please dont get the government on my back...
*/  

#ifndef STRIP_TYPES_H
#define STRIP_TYPES_H

#include <PalmOS.h> 
#include "types.h"

#define StripCreator 'SJLO'
#define StripPrefID 6667
#define StripVersionNumber 7
#define passwordDBType 'STRP'
#define passwordDBName "StripPassword-SJLO"
#define systemDBType 'STRP'
#define systemDBName "StripSystems-SJLO"
#define accountDBType 'STRP'
#define accountDBName "StripAccounts-SJLO"
#define otpDBType 'SKey'
#define otpDBName "StripOTP-SJLO"

typedef struct 
{
	Boolean echoOff;
	Boolean accountFirst;
	Boolean accountSort;
	Boolean autoLock;
	Int16 pwType;
	Int16 pwLengthIndex;
	Boolean smart_beaming;
	UInt16 lastCategoryIndex;
}
StripPrefType;

typedef struct 
{
	UInt16 SystemID;
	char *name;
 }
System;

typedef struct 
{
	UInt16 SystemID;
	char name[1];
 }
PSystem;

typedef struct 
{
	UInt16 SystemID;
	UInt16 AccountID;
	md_hash hash;
	UInt16 series;
	UInt16 hash_type;
	UInt16 system_type;
	UInt16 service_type;
	UInt16 username_type;
	UInt16 password_type;
	UInt32 account_mod_date;
	UInt32 password_mod_date;
	UInt16 binary_data_length;
	char *system;
	char *username;
	char *password;
	char *comment;
	char *key;
	char *service;
	byte *binary_data;
 }
Account;

typedef struct 
{
	UInt16 SystemID;
	UInt16 AccountID;
	md_hash hash;
	UInt16 series;
	UInt16 hash_type;
	UInt16 system_type;
	UInt16 service_type;
	UInt16 username_type;
	UInt16 password_type;
	UInt32 account_mod_date;
	UInt32 password_mod_date;
	UInt16 binary_data_length;
	char username[1];
 }
PAccount;

typedef struct
{
	UInt32 first_use;
	char *email;
	char *code;
} Registration;

typedef struct
{
	UInt32 first_use;
	char email[1];
} PRegistration;

#define ACCT_HEADER (sizeof( UInt16 )+sizeof( UInt16)+sizeof(md_hash))
#define SYST_HEADER (sizeof( UInt16))

#define DECRYPT 0
#define ENCRYPT 1

#endif

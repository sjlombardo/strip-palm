/*	
Program : Strip (Secure Tool for Recalling Important Passwords) 
Description: A secure password and account manager for the Palm(t) Computing Platform 
Copyright (C) 1999  Stephen J Lombardo

This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

Strip has been written and developed by Stephen J Lombardo (Zetetic Enterprises) 1999

Bug reports and feature requests should be sent to bugs@zetetic.net.
*/  

#ifndef STORAGE_UTIL_H
#define STORAGE_UTIL_H

#ifdef NOMULTISEG
#define SEGATTR 
#else
#define SEGATTR __attribute__ ((section ("strip_db")))
#endif 

#include <PalmOS.h> 
#include "strip_types.h"
#include "types.h"

MemHandle freeHandle (MemHandle handle);
UInt16 getSystemSize (System * sys, Boolean enc) SEGATTR;
UInt16 getAccountSize (Account * acct, Boolean enc) SEGATTR;
void UnpackSystem (System * sys, MemPtr p, MemPtr scratch, md_hash * pass, 
	UInt16 recLen, Boolean decrypt) SEGATTR;
void PackSystem (MemPtr retbuff, System sys, md_hash *pass, Boolean encrypt) SEGATTR;
void UnpackPassword (MemPtr p, MemPtr scratch, md_hash *spass) SEGATTR;
void PackPassword (MemPtr retbuff,  md_hash *spass) SEGATTR;
void UnpackAccount (Account * acct, MemPtr p, MemPtr scratch,  
	md_hash * pass, UInt16 recLen, Boolean decrypt, Boolean isRec) SEGATTR;
void PackAccount (MemPtr retbuff, Account acct, md_hash * pass, Boolean encrypt) SEGATTR; 
UInt16 getSIDFromAccountIndex (DmOpenRef db, UInt16 index) SEGATTR;
UInt16 getAIDFromAccountIndex(DmOpenRef db, UInt16 index) SEGATTR;
md_hash * getHashFromAccountIndex (DmOpenRef db, UInt16 index) SEGATTR;
void getAccountFromIndex (DmOpenRef db, md_hash * SysPass, UInt16 index, MemHandle tmp, Account * acc) SEGATTR;
void getSystemFromIndex (DmOpenRef db, md_hash * SysPass, UInt16 index, MemHandle tmp, System * s) SEGATTR;
Err getDatabase (DmOpenRef * DBptr, UInt32 type, UInt32 creator, UInt32 mode,
	UInt16 card, char *name, Boolean * created) SEGATTR;
void writeRecord (MemPtr record, MemHandle recordDBrec) SEGATTR;
UInt16 getUniqueSystemID (DmOpenRef db) SEGATTR;
UInt16 getIndexForSystemID (DmOpenRef db, UInt16 sysid) SEGATTR;  
UInt16 getUniqueAccountID (DmOpenRef db) SEGATTR;
UInt16 getIndexOfNthAcct (DmOpenRef db, UInt16 currentSID, UInt16 n) SEGATTR;
UInt16 getIndexForAccountID (DmOpenRef db, UInt16 currentSID, UInt16 aid) SEGATTR; 
UInt16 getSIDForSystemIndex (DmOpenRef db, UInt16 i) SEGATTR;
UInt16 numAccountsInSystem (DmOpenRef db, UInt16 id) SEGATTR;

UInt16 getRegistrationSize (Registration *reg) SEGATTR;
void PackRegistration (MemPtr retbuff, Registration reg) SEGATTR;
void UnpackRegistration (Registration *reg, MemPtr p) SEGATTR;
				
#endif

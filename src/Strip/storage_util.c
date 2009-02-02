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

------Three-way block encryption---------------------------------------
Strip uses the 3-Way block encryption algoritm, Copyright (C) Joan 
Daemen. All rights reserved.
-----------------------------------------------------------------------

        <**  DO NOT EXPORT **>
Strip uses strong cryptography. "3-way" is a block algoritm with a
96 bit key length, "Idea" is a block algoritm with a
128 bit key length, and "MD5" creates a 128 bit message digest. In the 
United states it is currently illegal to export products describing
or incorporating encryption techniques with key lengths greater
than 40 bits. It is therefore illegal to export this program in
any format. Please dont get the government on my back...

*/  
	
#include <PalmOS.h> 
#include "storage_util.h"
#include "strip_types.h"
#include "types.h"
#include "block_cipher_driver.h"
#include "sha256_driver.h"
	
#ifdef HAVE_GDBHOOK
#include "set_a4.h"
#ifdef DEBUG
extern void _gdb_hook ();
#endif
#else
#define SET_A4_FROM_A5
#define RESTORE_A4
#endif

#define DECRYPT 0
#define ENCRYPT 1

/************************************************************************
 * Function: freeHandle
 * Description: free the given handle
 * **********************************************************************/
MemHandle freeHandle (MemHandle handle) {
	if (handle) {
		MemPtr p = MemHandleLock (handle);
		MemSet (p, MemPtrSize (p), 0);
		MemHandleUnlock (handle);
		MemHandleFree (handle);
	}
	return(handle=NULL);
}

/*********************************************************************
 * Function: getSystemSize
 * Description: pass the function a pointer to a system and it 
 * will return the buffer length needed to hold that system when
 * it is encrypted. 
 * Note: uses getSCSize function included from twDriver.c
 * *******************************************************************/ 
UInt16 getSystemSize (System * sys, Boolean enc) {
	UInt16 length = sizeof (sys->SystemID) + StrLen (sys->name) + 1;
	if (enc) return (getSCSize(length-SYST_HEADER)+SYST_HEADER);
	else return length;
}

/*********************************************************************
 * Function: getAccountSize
 * Description: pass the function a pointer to an account and a boolean
 * for whether or not the account will be encrypted and it
 * will return the buffer length needed to hold that account. 
 * Note: uses getSCSize function included from twDriver.c
 * *******************************************************************/ 
UInt16 getAccountSize (Account * acct, Boolean enc) {
	UInt16 length =
		sizeof (acct->SystemID) + sizeof (acct->AccountID)+
		sizeof (acct->hash)+ sizeof(acct->series) + sizeof(acct->hash_type)+
		sizeof(acct->system_type)+ sizeof(acct->service_type)+ 
		sizeof(acct->username_type)+ sizeof(acct->password_type)+   
		sizeof (acct->account_mod_date)+ sizeof(acct->password_mod_date) + 
		sizeof(acct->binary_data_length)+ 
		StrLen (acct->username) + StrLen (acct->password) +
		StrLen (acct->system) + StrLen (acct->comment) + StrLen(acct->service) +
		StrLen (acct->key) + 6 + acct->binary_data_length;
	
	/*	if the account will be encrypted call getSCSize, 
		otherwise just return the raw length */
	if (enc) return (getSCSize(length-ACCT_HEADER)+ACCT_HEADER);
	else return length;
}

/************************************************************************************
 * Function: UnpackSystem
 * Description: This is a utility function that will take a packed System ,
 * optionally decrypt it based on the passed in password, and set up 
 * an unpacked system. 
 * **********************************************************************************/ 
void UnpackSystem (System * sys, MemPtr p, MemPtr scratch, md_hash * pass, 
	UInt16 recLen, Boolean decrypt) {
	PSystem * psys;
	char *s;
	
	/*	if necessary, decrypt, otherwise just copy the memory to the scratch buffer */
	if (decrypt) {
		MemMove(scratch, p, SYST_HEADER); 	
		stripCrypt (*pass, (p+SYST_HEADER), (scratch+SYST_HEADER), (recLen-SYST_HEADER), DECRYPT);
	} else MemMove (p, scratch, recLen);
	
	/*	set up the system, pointing the name to the first char in the name string. */
	psys = (PSystem *) scratch;
	s = psys->name;
	sys->SystemID = psys->SystemID;
	sys->name = s;
	s += StrLen (s) + 1;
}


/************************************************************************************
 * Function: PackSystem
 * Description: Utility function that takes an unpacked system, optionally encrypts
 * it and packs it into a buffer, strings are seperated by null characters. puts the 
 * content in retbuffer
 * *********************************************************************************/ 
void PackSystem (MemPtr retbuff, System sys, md_hash * pass, Boolean encrypt) {
	UInt16 offset = 0;
	MemPtr psys;
	if ((psys = MemPtrNew (MemPtrSize (retbuff)))) {
		/*	move the data into the buffer. */
		MemMove (psys + offset, &sys.SystemID, sizeof (sys.SystemID));
		offset += sizeof (sys.SystemID);
		MemMove (psys + offset, sys.name, StrLen (sys.name) + 1);
		offset += StrLen (sys.name) + 1;
		
		if (encrypt) {
			MemMove(retbuff, psys, SYST_HEADER);
			stripCrypt (*pass, psys+SYST_HEADER, retbuff+SYST_HEADER, getSystemSize(&sys, true)-SYST_HEADER, ENCRYPT);
		} else MemMove (retbuff, psys, getSystemSize (&sys, true));

		MemSet (psys, MemPtrSize (psys), 0);
		MemPtrFree (psys);
	}
}

/***********************************************************************************
 * Function: UnpackPassword
 * Description: unpack a password and decrpt it using spass
 * *********************************************************************************/ 
void UnpackPassword (MemPtr p, MemPtr scratch, md_hash * spass) {
	stripCrypt (*spass, p, scratch, getSCSize(sizeof(md_hash)), DECRYPT);
}


/***********************************************************************************
 * Function: PackPassword
 * Description: pack a password and encrypt it using spass
 * *********************************************************************************/ 
void PackPassword (MemPtr retbuff,  md_hash * spass) {
	MemPtr ppass;
	if ((ppass = MemPtrNew (getSCSize(sizeof(md_hash))))) {
		MemMove (ppass, spass, sizeof (md_hash));
		stripCrypt (*spass, ppass, retbuff, getSCSize(sizeof(md_hash)), ENCRYPT);
		MemSet (ppass, MemPtrSize (ppass), 0);
		MemPtrFree (ppass);
	}
}


/************************************************************************************
 * Function: UnpackAccount
 * Description: This is a utility function that will take a packed account ,
 * optionally decrypt it based on the passed in password, and set up 
 * an unpacked account. isRec determines whether the packed account is a full record.
 * remember that fullrecords have the plaintext system id prepended, so if it
 * is a full record we will ignore this space.
 * **********************************************************************************/ 
void UnpackAccount (Account * acct, MemPtr p, MemPtr scratch,
			   md_hash * pass, UInt16 recLen, Boolean decrypt, Boolean isRec) {
	PAccount * pacct;
	char *s;

	/*	decrypt if neccessary */
	if (decrypt) {
		MemMove(scratch, p, ACCT_HEADER); 	
		stripCrypt (*pass, (p+ACCT_HEADER), (scratch+ACCT_HEADER), (recLen-ACCT_HEADER), DECRYPT);
	} else
		MemMove (scratch, p , recLen);
		
	/*	split record up into its different components. */
	pacct = (PAccount *) scratch;
	s = pacct->username;
	acct->SystemID = pacct->SystemID;
	acct->AccountID = pacct->AccountID;
	MemMove(acct->hash, pacct->hash, sizeof(md_hash));
	acct->series = pacct->series;
	acct->hash_type = pacct->hash_type;
	acct->system_type = pacct->system_type;
	acct->service_type = pacct->service_type;
	acct->username_type = pacct->username_type;
	acct->password_type = pacct->password_type;

	acct->account_mod_date = pacct->account_mod_date;
	acct->password_mod_date = pacct->password_mod_date;
	acct->binary_data_length = pacct->binary_data_length;
	acct->system = s;
	s += StrLen (s) + 1;
	acct->service = s;
	s += StrLen (s) + 1;
	acct->username = s;
	s += StrLen (s) + 1;
	acct->password = s;
	s += StrLen (s) + 1;
	acct->comment = s;
	s += StrLen (s) + 1;
	acct->key = s;
	s += StrLen (s) + 1;
	acct->binary_data = s;
}


/************************************************************************************
 * Function: PackAccount
 * Description: Utility function that takes an unpacked account, optionally encrypts
 * it and packs it into a buffer, strings are seperated by null characters. puts the 
 * content in retbuffer
 * *********************************************************************************/ 
void PackAccount (MemPtr retbuff, Account acct, md_hash * pass,
			 Boolean encrypt) {
	UInt16 offset = 0;
	MemPtr pacct;
	if ((pacct = MemPtrNew (MemPtrSize (retbuff)))) {	
		/*	pack the fields of the account buffer together */
		MemMove (pacct + offset, &acct.SystemID, sizeof (acct.SystemID));
		offset += sizeof (acct.SystemID);
		MemMove (pacct + offset, &acct.AccountID, sizeof (acct.AccountID));
		offset += sizeof (acct.AccountID);
		MemMove (pacct + offset, acct.hash, sizeof (md_hash));
		offset += sizeof (md_hash);
		MemMove (pacct + offset, &acct.series, sizeof (acct.series));
		offset += sizeof (acct.series);
		MemMove (pacct + offset, &acct.hash_type, sizeof (acct.hash_type));
		offset += sizeof (acct.hash_type);
		MemMove (pacct + offset, &acct.system_type, sizeof (acct.system_type));
		offset += sizeof (acct.system_type);
		MemMove (pacct + offset, &acct.service_type, sizeof (acct.service_type));
		offset += sizeof (acct.service_type);
		MemMove (pacct + offset, &acct.username_type, sizeof (acct.username_type));
		offset += sizeof (acct.username_type);
		MemMove (pacct + offset, &acct.password_type, sizeof (acct.password_type));
		offset += sizeof (acct.password_type);

		MemMove (pacct + offset, &acct.account_mod_date, sizeof (acct.account_mod_date));
		offset += sizeof (acct.account_mod_date);
		MemMove (pacct + offset, &acct.password_mod_date, sizeof (acct.password_mod_date));
		offset += sizeof (acct.password_mod_date);
		MemMove (pacct + offset, &acct.binary_data_length, sizeof (acct.binary_data_length));
		offset += sizeof (acct.binary_data_length);

		MemMove (pacct + offset, acct.system, StrLen (acct.system) + 1);
		offset += StrLen (acct.system) + 1;
		MemMove (pacct + offset, acct.service, StrLen (acct.service) + 1);
		offset += StrLen (acct.service) + 1;
		MemMove (pacct + offset, acct.username, StrLen (acct.username) + 1);
		offset += StrLen (acct.username) + 1;
		MemMove (pacct + offset, acct.password, StrLen (acct.password) + 1);
		offset += StrLen (acct.password) + 1;
		MemMove (pacct + offset, acct.comment, StrLen (acct.comment) + 1);
		offset += StrLen (acct.comment) + 1;
		MemMove (pacct + offset, acct.key, StrLen (acct.key) + 1);
		offset += StrLen (acct.key) + 1;

		MemMove (pacct + offset, &acct.binary_data, acct.binary_data_length);
		offset += acct.binary_data_length;

		/*	optionally encrypt */
		if (encrypt) {
			MemMove (retbuff, pacct, ACCT_HEADER);
			stripCrypt (*pass, (pacct+ACCT_HEADER), (retbuff+ACCT_HEADER), 
				(getAccountSize (&acct, true) - ACCT_HEADER), 1);  				 
		} else MemMove (retbuff, pacct, getAccountSize (&acct, false));

		MemSet (pacct, MemPtrSize (pacct), 0);
		MemPtrFree (pacct);
	}
}

/**************************************************************************
 * Function: getSIDFromAccountIndex
 * Description: returns the system id for the account located at a given
 * index. Remember that the first few bytes of an account record are the
 * system ID of the account.  Just pop these off.
 * ************************************************************************/ 
UInt16 getSIDFromAccountIndex (DmOpenRef AccountDB, UInt16 index) {
	UInt16 ret = 0;
	MemHandle rec = DmQueryRecord (AccountDB, index);
	if (rec) {
		MemPtr buff = MemHandleLock (rec);
		MemMove (&ret, buff, sizeof (ret));
		MemHandleUnlock (rec);
	}
	return ret;
}


/**************************************************************************
 * Function: getAIDFromAccountIndex
 * Description: returns the account id for the account located at a given
 * index. Remember that the first few bytes of an account record are the
 * system ID of the account.  Just skip these an pop off the AID.
 * ************************************************************************/ 
UInt16 getAIDFromAccountIndex(DmOpenRef AccountDB, UInt16 index) {
	UInt16 ret = 0;
	MemHandle rec = DmQueryRecord (AccountDB, index);
	if (rec) {
		MemPtr buff = MemHandleLock (rec);
		MemMove (&ret, buff+sizeof(ret), sizeof (ret));
		MemHandleUnlock (rec);
	}
	return ret;
}

/**************************************************************************
 * Function: getHashFromAccountIndex
 * Description: returns the unique has for the account located at a given
 * index. Remember that the first few bytes of an account record are the
 * system ID of the account.  Just skip these an pop off the AID.
 * ************************************************************************/ 
md_hash * getHashFromAccountIndex (DmOpenRef AccountDB, UInt16 index) {
	static md_hash ret;
	MemHandle rec = DmQueryRecord (AccountDB, index);
	if (rec) {
		MemPtr buff = MemHandleLock (rec);
		MemMove (ret, buff+sizeof(UInt16)+sizeof(UInt16), sizeof (ret));
		MemHandleUnlock (rec);
	}
	return &ret;
}

/**************************************************************************
 * Function: getAccountFromIndex
 * Description: based upon an account index, this will locate the
 * account for that index, unpack and decrypt it and initialize acc
 * ************************************************************************/ 
void getAccountFromIndex (DmOpenRef AccountDB, md_hash * SysPass, UInt16 index, MemHandle tmp, Account * acc) {
	/*	query the record from the database */
	MemHandle rec = DmQueryRecord (AccountDB, index);
	
	if (rec){
		MemPtr scratch, buff = MemHandleLock (rec);
		
		/*	resize buffer */
		if (MemHandleResize (tmp, MemPtrSize (buff)) == 0) {
			scratch = MemHandleLock (tmp);
			
			/*	unpack the account */
			UnpackAccount (acc, buff, scratch, SysPass, MemHandleSize (rec), true, true);
		}
		MemHandleUnlock (rec);
	}
}


/**************************************************************************
 * Function: getSystemFromIndex
 * Description: based upon a system database index, this will locate the
 * system for that index, unpack and decrypt it and initialize s
 * ************************************************************************/ 
void getSystemFromIndex (DmOpenRef SystemDB, md_hash * SysPass, UInt16 index, MemHandle tmp, System * s) {
	MemHandle rec = DmQueryRecord (SystemDB, index);
	if (rec) {
		MemPtr scratch, buff = MemHandleLock (rec);
		
			/*	resize the buffer */
		if (MemHandleResize (tmp, MemPtrSize (buff)) == 0) {
			scratch = MemHandleLock (tmp);
			
			/*	unpack and decrypt the account */
			UnpackSystem (s, buff, scratch, SysPass, MemHandleSize (rec), true); 
		}
		MemHandleUnlock (rec);
	}
}


/**********************************************************************
 * Function: getDatabase
 * Description: pass the function the necessare database information,
 * and it will either open an existing database or create a new one if 
 * neccessary. "created" will be true if a new database was created
 * *******************************************************************/ 
Err getDatabaseByTypeCreatorName (DmOpenRef * DBptr, UInt32 type, 
	UInt32 creator, UInt32 mode, char *name) {
	 
    Err errors;
    LocalID id;
    UInt16 cardNum, attr;
    DmSearchStateType srch;
    Char db_name[32];
 
	errors = DmGetNextDatabaseByTypeCreator(true, &srch, type, creator,  false, 
		&cardNum, &id);

    while(!errors && id) {
		*DBptr =  DmOpenDatabase (cardNum, id, mode);
        DmDatabaseInfo (cardNum, id, db_name, &attr, NULL, NULL, NULL, NULL, NULL,
             NULL, NULL, NULL, NULL);
		if(StrCompare(name, db_name) == 0) {
            attr |= dmHdrAttrBackup;
            DmSetDatabaseInfo (cardNum, id, NULL, &attr, NULL, NULL, NULL, NULL,
                    NULL, NULL, NULL, NULL, NULL);
            return 0;
		}
		if(*DBptr) DmCloseDatabase(*DBptr);
		errors = DmGetNextDatabaseByTypeCreator(false, &srch, type, creator,  false, 
			&cardNum, &id);
    } 
	return 1; 
} 
    
Err getDatabase (DmOpenRef * DBptr, UInt32 type, UInt32 creator, UInt32 mode,
    UInt16 card, char *name, Boolean * created) {
    Err errors;
    *created = false;

    errors = getDatabaseByTypeCreatorName (DBptr, type, creator, mode, name); 

    /* if the database does not exist, make a new one. */
    if (errors) {
        errors = DmCreateDatabase (card, name, creator, type, false);
        if (errors) return errors;
        *created = true;
    	errors = getDatabaseByTypeCreatorName (DBptr, type, creator, mode, name); 
        if (!*DBptr || errors) return DmGetLastErr ();
    }

    return 0; 
}

/********************************************************************
 * Function: addRecord
 * Description:  function responsible for writing a packed System record
 * to the database. 
 * ******************************************************************/ 
void writeRecord (MemPtr record, MemHandle recordDBrec) {
	UInt16 length = 0, offset = 0;
	Char *ch;
	
	/* get length of the system buffer */
	length = MemPtrSize (record);
	
	/* re-size and write. */
	if (MemHandleResize (recordDBrec, length) == 0) {
		ch = MemHandleLock (recordDBrec);
		DmWrite (ch, offset, record, length);
		MemHandleUnlock (recordDBrec);
	}
}

/*******************************************************************
 * Function: getUniqueSystemID
 * Description: return a unique system id that can be assigned to a
 * new system.
 * Note: SystemID 0 is reserved for the Unfiled system. Unfiled is 
 * where beamed accounts go when they are first received if they
 * dont have anywhere else to go.
 * ****************************************************************/ 
UInt16 getUniqueSystemID (DmOpenRef SystemDB) {
	UInt16 i, id;
	
	/*	get the number of system records. note that we cant just
		use totalItems++ because systems can be added and deleted
		at will... */
	UInt16 totalItems = DmNumRecordsInCategory (SystemDB, dmAllCategories);
	UInt16 max = 0;
	
	/*	iterate through the records, and we will return the highest 
		one it higher than the highest current value. */
	for (i = 0; i < totalItems; i++) {
		MemHandle scr;
		if ((scr = MemHandleNew (1))) {
			id = getSIDForSystemIndex (SystemDB, i);
			if (id > max) max = id;
			freeHandle (scr);
		}
	}
	return max + 1;
}


/*******************************************************************
 * Function: getIndexForSystemID
 * Description: return an index for a unique system id.
 * ****************************************************************/ 
UInt16 getIndexForSystemID (DmOpenRef SystemDB, UInt16 sysid) {
	UInt16 i, id, index = 0;
	
	/*	get the number of system records. note that we cant just
		use totalItems++ because systems can be added and deleted
		at will... */
	UInt16 totalItems = DmNumRecordsInCategory (SystemDB, dmAllCategories);
	Boolean stop = false;
	
	/*	iterate through the records, and we will return the highest 
		one it higher than the highest current value. */
	for (i = 0; i < totalItems && !stop; i++) {
		MemHandle scr;
		if ((scr = MemHandleNew (1))) {
			id = getSIDForSystemIndex (SystemDB, i);
			if (id == sysid) index = i;
			freeHandle (scr);
		}
	}
	return index;
}


/*******************************************************************
 * Function: getUniqueAccountID
 * Description: return a unique account id that can be assigned to a
 * new account.
 * ****************************************************************/ 
UInt16 getUniqueAccountID (DmOpenRef AccountDB) {
	UInt16 i, id;
	
	/*	get the number of account records. note that we cant just
		use totalItems++ because account can be added and deleted and
		they are in alphabetical sort order, not is AccountID order. */
	UInt16 totalItems = DmNumRecordsInCategory (AccountDB, dmAllCategories);
	UInt16 max = 0;
	
	/*	iterate through the records, and we will return the highest 
		one it higher than the highest current value. */
	for (i = 0; i < totalItems; i++) {
		id = getAIDFromAccountIndex (AccountDB, i);
		if (id > max) max = id;
	}
	return max + 1;
}


/*************************************************************************
 * Function: getIndexOfNthAcct
 * Description: the nth account in a system is not necessarily the nth 
 * account in the database, (remember sort order). this function will
 * take n as the nth account in a system and return the records index 
 * in the database.
 * **********************************************************************/ 
UInt16 getIndexOfNthAcct (DmOpenRef AccountDB, UInt16 currentSID, UInt16 n) {
	UInt16 i, id;
	UInt16 totalItems = DmNumRecordsInCategory (AccountDB, dmAllCategories);
	UInt16 index = 0;
	UInt16 counter = 0;
	Boolean cont = true;
	
	/*	iterate through the accounts, till we find the nth account for
		the current systemID. */
	for (i = 0; (i < totalItems) && cont; i++) {
		
		/*	note: getSIDFromAccountIndex is fast because it doesnt need 
			to decrypt anything. */
		id = getSIDFromAccountIndex (AccountDB, i);
		if (id == currentSID) {
			counter++;
			index = i;
			if (counter > n) cont = false;
		}
	}
	return index;
}


/*************************************************************************
 * Function: getIndexForAccountID
 * Description: get the selection index for the specified account ID.
 * **********************************************************************/ 
UInt16 getIndexForAccountID (DmOpenRef AccountDB, UInt16 currentSID, UInt16 aid) {
	UInt16 i, id, index = 0, counter = 0;
	UInt16 totalItems = DmNumRecordsInCategory (AccountDB, dmAllCategories);
	Boolean cont = true;
	
	/*	iterate through the accounts, till we find the nth account for
		the current systemID. */
	for (i = 0; (i < totalItems) && cont; i++) {
		/* note: getSIDFromAccountIndex is fast because it doesnt need 
		to decrypt anything. */
		id = getSIDFromAccountIndex (AccountDB, i);
		if (id == currentSID) {
			if(aid == getAIDFromAccountIndex(AccountDB, i) ) {
				index = counter;
				cont = false;
			}	
			counter++;
		}
	}
	return index;
}

/******************************************************************************
 * Function: getSIDForSystemIndex
 * Description: this will get the system id for a given index in the
 * system database.
 * ****************************************************************************/ 
UInt16 getSIDForSystemIndex (DmOpenRef SystemDB, UInt16 i) {
	UInt16 ret;
	MemHandle rec = DmQueryRecord (SystemDB, i);
	if (rec) {
		MemPtr buff = MemHandleLock (rec);
		MemMove (&ret, buff, sizeof (ret));
		MemHandleUnlock (rec);
	}
	return ret;
}


/*****************************************************************
 * Function: numAccountsInSystem
 * Description: count the number of accounts for a given system 
 * ID 
 * ***************************************************************/ 
UInt16 numAccountsInSystem (DmOpenRef AccountDB, UInt16 id) {
	UInt16 i, acid;
	UInt16 totalItems = DmNumRecordsInCategory (AccountDB, dmAllCategories);
	UInt16 numAccounts = 0;
	
	/* iterate through the records, increment when we find a match */
	for (i = 0; i < totalItems; i++) {
		acid = getSIDFromAccountIndex (AccountDB, i);
		if (acid == id) numAccounts++;
	}
	return numAccounts;
}

/************************************************************************************
 * Function: UnpackRegistration
 * Description: This is a utility function that will unpack a packed Registration struct
 * **********************************************************************************/ 
void UnpackRegistration (Registration *reg, MemPtr p) { 
	PRegistration * preg;
	char *s;
	
	/*	set up the system, pointing the name to the first char in the name string. */
	preg = (PRegistration *) p;

	s = preg->email;
	reg->first_use = preg->first_use;
	reg->email = s;
	s += StrLen (s) + 1;
	reg->code = s;
}

/************************************************************************************
 * Function: PackRegistration
 * Description: Utility function that takes an unpacked Registration, optionally encrypts
 * it and packs it into a buffer, strings are seperated by null characters. puts the 
 * content in retbuffer
 * *********************************************************************************/ 
void PackRegistration (MemPtr retbuff, Registration reg) {
	UInt16 offset = 0;
	MemPtr preg;
	if ((preg = MemPtrNew (MemPtrSize (retbuff)))) {
		/*	move the data into the buffer. */
		MemMove (preg + offset, &reg.first_use, sizeof (reg.first_use));
		offset += sizeof (reg.first_use);
		MemMove (preg + offset, reg.email, StrLen (reg.email) + 1);
		offset += StrLen (reg.email) + 1;
		MemMove (preg + offset, reg.code, StrLen (reg.code) + 1);
		offset += StrLen (reg.code) + 1;

		MemMove (retbuff, preg, MemPtrSize(preg));
		MemSet (preg, MemPtrSize (preg), 0);
		MemPtrFree (preg);
	}
}

/*********************************************************************
 * Function: getRegistrationSize
 * Description: pass the function a pointer to a Registration
 * and d it will return the buffer length needed to hold that packed structure.  
 * *******************************************************************/ 
UInt16 getRegistrationSize (Registration *reg) {
	UInt16 length =
		sizeof (reg->first_use) + 
		StrLen (reg->email) + 1 +
		StrLen (reg->code) + 1;
	return length;
}


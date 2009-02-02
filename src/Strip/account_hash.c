
#include "account_hash.h"
#include "sha256_driver.h"
#include "storage_util.h"
#include "random.h"

/**************************************************************************
 * Function: generateAccountHash
 * Description: returns the unique hash for the account.
 * ************************************************************************/ 
md_hash * generateAccountHash (Account * acct) {
	static md_hash ret;
	unsigned char * hashable;
	int data_length = 0, string_length = 0;
	
	MemSet(ret, sizeof(md_hash), 0);
	
	/* username, password, acct mod date, 
	 * pw mod date, and 256 bits of randomness */
	data_length = 
		StrLen(acct->username)+
		StrLen(acct->system)+
		StrLen(acct->password)+
		StrLen(acct->service)+
		StrLen(acct->comment)+
		sizeof(acct->account_mod_date)+
		sizeof(acct->password_mod_date)+
		(sizeof(Int16)*16)+1;
		
		
	if((hashable=MemPtrNew(data_length))) {
		MemSet(hashable, data_length, 0);
		StrCopy(hashable, acct->username);	
		string_length+=StrLen(acct->username);
		StrCat(hashable, acct->system);	
		string_length+=StrLen(acct->system);
		StrCat(hashable, acct->password);
		string_length+=StrLen(acct->password);	
		StrCat(hashable, acct->service);
		string_length+=StrLen(acct->service);	
		StrCat(hashable, acct->comment);
		string_length+=StrLen(acct->comment);	
		
		MemMove(hashable+string_length, 
			&acct->account_mod_date, 
			sizeof(acct->account_mod_date));
		string_length+=sizeof(acct->account_mod_date);
		
		MemMove(hashable+string_length, 
			&acct->password_mod_date, 				
			sizeof(acct->password_mod_date));
		string_length+=sizeof(acct->password_mod_date);
		
		/* move some randomness onto the end 
		 * to make dictionary attacks impossible.   */
		random_bytes(hashable+string_length, 32);
		string_length+=32;
		
		md_block(hashable, string_length, ret);	
		MemPtrFree(hashable);
	}	
	return &ret;
}

/*************************************************************************
 * Function: replaceAccountHash
 * Description: regernate the hash on a single account based on account
 * index
 * ***********************************************************************/ 
void replaceAccountHash(UInt16 index, DmOpenRef db, md_hash * SysPass) {
	Account ac;
	MemHandle rH;
	MemPtr pac = NULL, scratch = NULL, scratch2=NULL;
	if ((rH = DmGetRecord (db, index))) {
		pac = MemHandleLock (rH);
		if ((scratch = MemPtrNew (MemPtrSize (pac)))) {
			UnpackAccount (&ac, pac, scratch, SysPass, 
				MemHandleSize (rH), true, true);
			if ((scratch2 = MemPtrNew (MemPtrSize (pac)))) {
				MemMove(ac.hash, 
					generateAccountHash(&ac), 
					sizeof(md_hash)); 
				PackAccount (scratch2, ac, SysPass, true);
				writeRecord(scratch2, rH);
			}
		}
		MemPtrFree(scratch);
		MemPtrFree(scratch2);
		MemHandleUnlock (rH);
		DmReleaseRecord (db, index, true);
	}
}

/*************************************************************************
 * Function: replaceAllAccountHashes
 * Description: regernate the hash on a all the accounts.
 * ***********************************************************************/ 
void replaceAllAccountHashes(DmOpenRef db, md_hash * SysPass) {
	int i;
	UInt16 totalAItems = DmNumRecordsInCategory (
		db, dmAllCategories);
	/* loop through the accounts and replace hashe */
	for (i = 0; i < totalAItems; i++) {
		replaceAccountHash(i, db, SysPass);
	}
}

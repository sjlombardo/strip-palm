/* 
 * $Id: sync.cpp,v 1.1.1.1 2005/08/08 14:51:26 lombardo Exp $
 * Copyright (C) 2000 Ron Pedde
 * 
 * Windows sync action
 *
 */


#include <windows.h>
#include <stdlib.h>
#include <syncmgr.h>
#include <hslog.h>
#include "sync.h"
#include "gdbm.h"

#define MAX_RECORD_SIZE	0xFFF0

long CopyFromHH(CONDHANDLE, char *);
long PalmToGDB(char *, char *);


/*********************************************************
 * Function: PalmToGDB
 *
 * Description: Copy databased from the handheld 
 * to the PC, overwriting if necessary.
 *********************************************************/
long PalmToGDB(char *cPalmDB, char *cLocalDB) {
	long retval;
	BYTE hDB;
	int index=0;
	CRawRecordInfo riRaw;
	char buffer[MAX_RECORD_SIZE];
	GDBM_FILE gf;
	datum dt_record, dt_key;

	retval=SyncOpenDB(cPalmDB, 0, hDB);
	if(retval != SYNCERR_NONE) {
		LogAddEntry("Can't open remote DB",slWarning,FALSE);
		return retval;
	}

	gf=gdbm_open(cLocalDB, 512, GDBM_NEWDB, 0600, 0);
	if(!gf) {
		LogAddFormattedEntry(slWarning,FALSE,"Can't open local DB (%s)",cLocalDB);
		SyncCloseDB(hDB);
		return SYNCERR_FILE_NOT_OPEN;
	}
	
	riRaw.m_FileHandle=hDB;
	riRaw.m_pBytes=(unsigned char*)buffer;
	riRaw.m_TotalBytes=sizeof(buffer);

	for(index=0; ;index++) {
		riRaw.m_RecIndex=index;
		if(!SyncReadRecordByIndex(riRaw)) {
			dt_record.dptr=buffer;
			dt_record.dsize=riRaw.m_RecSize;
			dt_key.dptr=(char*)&index;
			dt_key.dsize=sizeof(int);

			if(gdbm_store(gf,dt_key,dt_record,GDBM_INSERT) < 0) {
				LogAddEntry("Can't insert local record",slWarning,FALSE);
				SyncCloseDB(hDB);
				return SYNCERR_UNKNOWN;
			}

		} else { /* Done? */
			break;
		}
		
	}

	LogAddFormattedEntry(slText,TRUE,"Synchronized %d records from %s",
		index,cPalmDB);
	SyncCloseDB(hDB);

	gdbm_close(gf);

	return SYNCERR_NONE;
}



/*********************************************************
 * Function: CopyFromHH
 *
 * Description: Run throught each palm database we
 * want to save, saving each in turn.
 *********************************************************/
long CopyFromHH(CONDHANDLE hConduit, char *cPath) {
	char *fullpath;
	long retval = 0;

	fullpath=(char*)malloc(_MAX_FNAME);
	if(!fullpath)
		return SYNCERR_LOCAL_MEM;

	wsprintf(fullpath,"%sStripAccounts.gdb",cPath);
	if((retval=PalmToGDB("StripAccounts-SJLO",fullpath)))
		return retval;
	
	wsprintf(fullpath,"%sStripPassword.gdb",cPath);
	if((retval=PalmToGDB("StripPassword-SJLO",fullpath)))
		return retval;

	wsprintf(fullpath,"%sStripSystems.gdb",cPath);
	if((retval=PalmToGDB("StripSystems-SJLO",fullpath)))
		return retval;
	
	free(fullpath);
	return 0;
}


/*********************************************************
 * Function: DoSync
 *
 * Description: Kick off the sync process
 *********************************************************/

long DoSync(eSyncTypes sync, char *cPath) {
	long retval=-1;
	CONDHANDLE hConduit;

	LogAddFormattedEntry(slText,TRUE,"Synchronizing to  %s",cPath);

	if((retval=SyncRegisterConduit(hConduit)) != SYNCERR_NONE) {
		return retval;
	}
	
	switch(sync) {
	case eFast:
	case eSlow:
		LogAddEntry("Unsupported sync type",slWarning,FALSE);
		break;

	case eHHtoPC:
		retval=CopyFromHH(hConduit,cPath);
		break;

	case ePCtoHH:
		LogAddEntry("Unsupported sync type",slWarning,FALSE);
		break;

	case eDoNothing:
		retval=0;
		break;

	default:
		LogAddEntry("Unsupported sync type",slWarning,FALSE);
		break;
	}
	
	SyncUnRegisterConduit(hConduit);
	return 0;
}

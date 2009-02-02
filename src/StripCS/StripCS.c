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
#include "StripCSRsc.h"
#include "StripCS.h"
#include "types.h"
#include "md5_driver.h"
#include "sha256_driver.h"
#include "skey.h"
#include "storage_util.h"
#include "strip_types.h"
#include "convert.h"
#include "random.h"

#ifdef HAVE_GDBHOOK
#include "set_a4.h"
#ifdef DEBUG
extern void _gdb_hook ();
#endif
#else
#define SET_A4_FROM_A5
#define RESTORE_A4
#endif

static Boolean PasswordHandleEvent (EventType*);
static Err StartApplication ();

static MemPtr GetObjectFromActiveForm (UInt16);
static void EventLoop ();
static void StopApplication ();
static void checkPassword ();
static void UnpackSystem_old (System_old * sys, MemPtr p, MemPtr scratch, char *pass,
                UInt16 recLen, Boolean decrypt, int v);
static void UnpackAccount_old (Account_old * acct, MemPtr p, MemPtr scratch,
                 char *pass, UInt16 recLen, Boolean decrypt, Boolean isRec,
                 int v);
static void UnpackPassword_old (MemPtr p, MemPtr scratch, char *spass, int v);

extern int getSCSize_tw (int len);
extern int getSCSize_idea (int len);
extern int getSCSize_des (int len);
extern int getSCSize (int len);

extern void stripCrypt_tw (char *ikey, MemPtr str, MemPtr out, int sLen,
						  int enc);
extern void stripCrypt_idea (char *ikey, MemPtr str, MemPtr out, int sLen,
							  int enc);
extern void stripCrypt_des (char *ikey, MemPtr str, MemPtr out, int sLen,
							  int enc); 
extern void stripCrypt (byte *ikey, void *str, void *out, int sLen,
							  int enc); 
							  
/* Global Variables */ 
UInt16 currentForm, oldForm;
static DmOpenRef SystemDB, AccountDB, PasswordDB;
Boolean firstRun = false, passwordEchoOff = false, hideSecretRecords;
char *SysPass;
md_hash NewSysPass;

/************************************************************************
 * Function: GetObjectFromActiveForm
 * Description: pass this function the object id of any UI object in the 
 * currently active form and it will return a valid pointer to the 
 * UI object.
 * *********************************************************************/ 
static MemPtr 
GetObjectFromActiveForm (UInt16 objectID) 
{
	FormType *curForm = FrmGetActiveForm ();
	return FrmGetObjectPtr (curForm, FrmGetObjectIndex (curForm, objectID));
}

/***************************************************************************
 * Function: cryptSwitch
 * Description: handles changing the system password based upon the 
 * password change screen. Basically checks that current password is correct,
 * checks that the new password was entered correctly, then re-encrypts the
 * databases based upon the new password.
 * ************************************************************************/ 
static void 
cryptSwitch (int v) 
{
	
		// total number of records to re-write
	UInt16 totalAItems = DmNumRecordsInCategory (AccountDB, dmAllCategories);
	UInt16 totalSItems = DmNumRecordsInCategory (SystemDB, dmAllCategories);
	MemPtr pac = NULL, scratch = NULL, scratch2 = NULL;
	UInt16 i = 0, senc = 0, aenc = 0;
	MemHandle rH;
	char s[5], a[5];
	StripPrefType prefs;	
	UInt16 prefsSize, prefsVersion;

	FormType *preF = FrmGetActiveForm ();
	FormType *f = FrmInitForm (pleaseWait);
	FrmDrawForm (f);
	
		// re-encrypt the password 
	if ((rH = DmGetRecord (PasswordDB, 0)))	
	{
		if ((scratch = MemPtrNew (getSCSize(sizeof(md_hash)))))			
		{
			PackPassword (scratch, &NewSysPass);			
			writeRecord (scratch, rH);
			MemPtrFree (scratch);
		}
		DmReleaseRecord (PasswordDB, 0, true);
	}
	
		// loop through the systems and re-encrypt
	for (i = 0; i < totalSItems; i++)
	{
		System_old sys;
		if ((rH = DmGetRecord (SystemDB, i)))	
		{
			pac = MemHandleLock (rH);
			if ((scratch = MemPtrNew (MemPtrSize (pac))))	
			{	
					// decrypt the system with old password
				switch (v)	
				{
					case 0:
						UnpackSystem_old (&sys, pac, scratch, SysPass,
										MemHandleSize (rH), true, 1);
										
						scratch2 = MemPtrNew (getSystemSize((System *)&sys, true));
						break;
					case 1:
						UnpackSystem_old (&sys, pac, scratch, SysPass,
										MemHandleSize (rH), true, 2);
						scratch2 = MemPtrNew (getSystemSize ((System *)&sys,true) );
						break;
					case 2:
						UnpackSystem_old (&sys, pac, scratch, SysPass,
										MemHandleSize (rH), true, 0);
						scratch2 = MemPtrNew (getSystemSize ((System *)&sys, true ));
						break;
				}
				if (scratch2)				
				{			
					PackSystem(scratch2, *((System *) &sys), &NewSysPass, true);
					MemHandleUnlock (rH);
					writeRecord (scratch2, rH);
					senc++;
					MemPtrFree (scratch2);
				}
				MemPtrFree (scratch);
			}
			DmReleaseRecord (SystemDB, i, true);
		}
	}
	
		// loop through the accounts and re-encrypt
	for (i = 0; i < totalAItems; i++)	
	{
		Account_old ac;
		Account ac_new;
		if ((rH = DmGetRecord (AccountDB, i)))
			
		{
			pac = MemHandleLock (rH);
			if ((scratch = MemPtrNew (MemPtrSize (pac))))
				
			{
				
					// decrypt the system with old password
				switch (v)	
				{
					case 0:
						UnpackAccount_old(&ac, pac, scratch, SysPass,
										 MemHandleSize (rH), true, true, 1);
						ChangeAccountFormat(i, &ac, &ac_new);
						scratch2 = MemPtrNew (getAccountSize(&ac_new, true));
						break; 
					case 1:
						UnpackAccount_old (&ac, pac, scratch, SysPass,
										 MemHandleSize (rH), true, true, 2);
						ChangeAccountFormat(i, &ac, &ac_new);
						scratch2 = MemPtrNew (getAccountSize(&ac_new, true));
						break; 
					case 2:
						UnpackAccount_old(&ac, pac, scratch, SysPass,
										 MemHandleSize (rH), true, true, 0);
						ChangeAccountFormat(i, &ac, &ac_new);
						scratch2 = MemPtrNew (getAccountSize(&ac_new,true));
						break; 
				}

				if (scratch2)
				{
					PackAccount(scratch2, ac_new, &NewSysPass, true);
					MemHandleUnlock (rH);
					writeRecord (scratch2, rH);
					aenc++;
					MemPtrFree (scratch2);
				}
				MemPtrFree (scratch);
			}
			DmReleaseRecord (AccountDB, i, true);
		}
	}
	FrmEraseForm (f);
	FrmDeleteForm (f);
	FrmSetActiveForm (preF);
		// close databases.
	DmCloseDatabase (SystemDB);
	DmCloseDatabase (AccountDB);
	DmCloseDatabase (PasswordDB);

	{
		UInt16 cardNo;
		UInt32 type;
		LocalID dbID;
		DmSearchStateType search;

		type = systemDBType;
		DmGetNextDatabaseByTypeCreator(true, &search, systemDBTypeOld, 
			StripCreator, true, &cardNo, &dbID);
		DmSetDatabaseInfo(cardNo, dbID, NULL, NULL, NULL, NULL, NULL,
			NULL, NULL, NULL, NULL, &type, NULL);
	
		type = accountDBType;
		DmGetNextDatabaseByTypeCreator(true, &search, accountDBTypeOld, 
			StripCreator, true, &cardNo, &dbID);
		DmSetDatabaseInfo(cardNo, dbID, NULL, NULL, NULL, NULL, NULL,
			NULL, NULL, NULL, NULL, &type, NULL);

		type = passwordDBType;
		DmGetNextDatabaseByTypeCreator(true, &search, passwordDBTypeOld, 
			StripCreator, true, &cardNo, &dbID);
		DmSetDatabaseInfo(cardNo, dbID, NULL, NULL, NULL, NULL, NULL,
			NULL, NULL, NULL, NULL,  &type, NULL);

	}

	prefsSize = sizeof (StripPrefType);
	prefsVersion = PrefGetAppPreferences (StripCreator, StripPrefID, &prefs, &prefsSize, true);
    if  (prefsVersion != StripVersionNumber) {
        prefs.smart_beaming = false;
        PrefSetAppPreferences (StripCreator, StripPrefID, StripVersionNumber,
            &prefs, sizeof (StripPrefType), true);
        prefsVersion = PrefGetAppPreferences (StripCreator, StripPrefID,
            &prefs, &prefsSize, true);
	} 

	StrIToA (s, senc);
	StrIToA (a, aenc);
	FrmCustomAlert (infoDialog, s, a, NULL);

	StopApplication ();
	SysReset ();
}


/********************************************************************************
 * Function: StartApplication
 * Description: This is the first function that gets called and it is 
 * responsible for initializing databases and other global variables, checking
 * to see whether private records will be shown and calculating the auto-off time
 * for the current system.
 * ******************************************************************************/ 
static Err 
StartApplication (void) 
{
	UInt16 mode = dmModeReadWrite;
	Err errors = 0;
	Boolean created;
	StripPrefType prefs;	
	UInt16 prefsSize, prefsVersion;

		// set current form to be the password opener
		currentForm = PasswordForm;
	
		// check about private records
		hideSecretRecords = PrefGetPreference (prefHidePrivateRecordsV33);
	if (!hideSecretRecords)
		mode |= dmModeShowSecret;

	/*  handle program prefrences */
	prefsSize = sizeof (StripPrefType);
	prefsVersion = PrefGetAppPreferences (StripCreator, StripPrefID, &prefs, &prefsSize, true);
	if (prefsVersion == noPreferenceFound) { 
        FrmCustomAlert (GenericError, "This version of StripCS is only able to convert 0.5 databases. If you're using an earlier version you must run the StripCS_0.5.prc file that came with this distro first. If you aren't upgrading, just run Strip.prc!", NULL, NULL);
		return -1;
	} else if (prefsVersion == StripVersionNumber) {
        FrmCustomAlert (GenericError, "It looks like you have already converted your databases with StripCS. You may now use the latest version of Strip.", NULL, NULL);
		return -1;
	}
	
		// open or create databases.
		errors =
		getDatabase (&SystemDB, systemDBTypeOld, StripCreator, mode, 0,
					  systemDBName, &created);

		errors =
		getDatabase (&AccountDB, accountDBTypeOld, StripCreator, mode, 0,
					  accountDBName, &created);

		errors =
		getDatabase (&PasswordDB, passwordDBTypeOld, StripCreator, mode, 0,
					  passwordDBName, &created);

	
		// if the password database does not exist, or there are no records in it note that 
		// this is the first run, so the user will be prompted to enter a new password.
		if (created 
			||(DmNumRecordsInCategory (PasswordDB, dmAllCategories) == 0))
		
	{
		firstRun = true;
	}
	
		// set up the timer stuff.  start by setting auto off time to 0. the function returns the old 
		// auto off time. If the oldAutoOffTime is 0 then the system will never shut down. this is not
		// the behavior that we want, so we reset the autoOffTime to 300. if the oldAutoOffTime is not 
		// 0 then we set it back immediatly.  Note that in the StopApplication function we 
		// set the autoOffTime back to what it was before this program started no matter what.
		return 0;
}


/************************************************************************
 * Function: StopApplication
 * Description:  this function is responsible for stopping all application
 * related activity, freeing used memory, resetting the auto-off time, and
 * closing the databases.
 * **********************************************************************/ 
static void 
StopApplication (void) 
{
	FrmCloseAllForms ();
	
}


/********************************************************************************
 * Description: this is the function responsible for checking the 
 * input password value of the authentication form. 
 * ******************************************************************************/ 
static void 
checkPassword (void) 
{
	MemPtr pass1, scratch = NULL;
	char *input;

	UInt16 index = 0;
	MemHandle rec;
	mdKey in;
	ListType *list;
	
		// compact text and get a pointer.
		FldCompactText (GetObjectFromActiveForm (PasswordField));
	input = FldGetTextPtr (GetObjectFromActiveForm (PasswordField));
	list = GetObjectFromActiveForm (selPopupList);
	
		// if SysPass is defined, free it. this happens when Strip locks
		// itself after the timeout.
		if (SysPass)
		MemPtrFree (SysPass);
	
		// if its the first time the user has used the program we need 
		// to set some things up. 
		if (input && StrLen (input))
		
	{
		
			// read the password from the database, decrypt with the input text.
			if ((rec = DmQueryRecord (PasswordDB, index)))
			
		{
			pass1 = MemHandleLock (rec);
			if ((scratch = MemPtrNew (24)))
				
			{
				UInt16 chk = LstGetSelection (list);
				
					//printf("%d\n", LstGetSelection(list)); 
					switch (chk)
					
				{
					case 0:
						UnpackPassword_old (pass1, scratch, input, 1);
						break;
					case 1:
						UnpackPassword_old (pass1, scratch, input, 2);
						break;
					case 2:
						UnpackPassword_old (pass1, scratch, input, 0);
						break;
				}
			}
			MemHandleUnlock (rec);
		}
		
			// the message digest of the password they provided should be exactly the
			// same as the message digest that was just decrypted out of the password
			// database. Do a MemCmp to make sure they are the same.
		md5_string (input, in);

		if ((!MemCmp (in, scratch, 16)) && input)
			
		{
			
				// if so, copy the password onto the system-password
		if ((SysPass = MemPtrNew (StrLen (input) + 1)))
				StrCopy (SysPass, input);
		if (scratch)
				MemPtrFree (scratch);
		md_string(SysPass, NewSysPass);
		cryptSwitch (LstGetSelection (list));
		}
		
		else
			
		{
			
				// FAILURE!!!!!!
				// free the memory and tell the user they entered the wrong password.
				FieldType *fld = GetObjectFromActiveForm (PasswordField);
			FrmCustomAlert (GenericError,
							  "The password you entered is incorrect", NULL,
							  NULL);
				FldSetSelection (fld, 0, FldGetTextLength (fld));
			LstDrawList (list);
			if (scratch)
				
			{
				MemPtrFree (scratch);
				SysPass = NULL;
			}
		}
	}
	
		// null string is always wrong!!!
		else
		
	{
		FrmCustomAlert (GenericError, "You forgot to enter a password!!",
						 NULL, NULL);
		LstDrawList (list);
	}
}


/************************************************************************************
 * Function: UnpackSystem_old
 * Description: This is a utility function that will take a packed System ,
 * optionally decrypt it based on the passed in password, and set up 
 * an unpacked system. 
 * **********************************************************************************/ 
static void 
UnpackSystem_old (System_old * sys, MemPtr p, MemPtr scratch, char *pass,
			   UInt16 recLen, Boolean decrypt, int v) 
{
	PSystem_old * psys;
	char *s;

	
		// if necessary, decrypt, otherwise just copy the memory to the scratch buffer
		if (decrypt)
		switch (v)
			
		{
			case 0:
				stripCrypt_tw (SysPass, p, scratch, recLen, 0);
				break;
			case 1:
				stripCrypt_idea (SysPass, p, scratch, recLen, 0);
				break;
			case 2:
				stripCrypt_des (SysPass, p, scratch, recLen, 0);
				break;
		}
	
	else
		MemMove (p, scratch, recLen);
	
		// set up the system, pointing the name to the first char in the name string.
		psys = (PSystem_old *) scratch;
	s = psys->name;
	sys->SystemID = psys->SystemID;
	sys->name = s;
	s += StrLen (s) + 1;
}


/***********************************************************************************
 * Function: UnpackPassword_old
 * Description: unpack a password and decrpt it using spass
 * *********************************************************************************/ 
static void 
UnpackPassword_old (MemPtr p, MemPtr scratch, char *spass, int v) 
{
	switch (v)
		
	{
		case 0:
			stripCrypt_tw (spass, p, scratch, 24, 0);
			break;
		case 1:
			stripCrypt_idea (spass, p, scratch, 24, 0);
			break;
		case 2:
			stripCrypt_des (spass, p, scratch, 24, 0);
			break;
	}
}


/************************************************************************************
 * Function: UnpackAccountA
 * Description: This is a utility function that will take a packed account ,
 * optionally decrypt it based on the passed in password, and set up 
 * an unpacked account. isRec determines whether the packed account is a full record.
 * remember that fullrecords have the plaintext system id prepended, so if it
 * is a full record we will ignore this space.
 * **********************************************************************************/ 
static void 
UnpackAccount_old (Account_old * acct, MemPtr p, MemPtr scratch,
				char *pass, UInt16 recLen, Boolean decrypt, Boolean isRec,
				int v) 
{
	PAccount_old * pacct;
	char *s;

	UInt16 offset = sizeof (offset);
	recLen = recLen - offset;
	
		// decrypt if neccessary
	if (decrypt)
		switch (v)
			
		{
			case 0:
				stripCrypt_tw (pass, p + offset, scratch, recLen, 0);
				break;
			case 1:
				stripCrypt_idea (pass, p + offset, scratch, recLen, 0);
				break;
			case 2:
				stripCrypt_des (pass, p + offset, scratch, recLen, 0);
				break;
		}	
	else
		
			// if buffer has the systemID header disregard it.
		if (isRec)
		MemMove (scratch, p + offset, recLen);
	
	else
		MemMove (scratch, p, recLen);
	
		// split record up into its different components.   
		pacct = (PAccount_old *) scratch;
	s = pacct->username;
	acct->SystemID = pacct->SystemID;
	acct->AccountID = pacct->AccountID;
	acct->username = s;
	s += StrLen (s) + 1;
	acct->password = s;
	s += StrLen (s) + 1;
	acct->type = s;
	s += StrLen (s) + 1;
	acct->comment = s;
	s += StrLen (s) + 1;
}

/****************************************************************************
 * Function: PasswordHandleEvent
 * Description: callback function that handles events for the form that
 * checks the password to login to the program. This one is a little tricky
 * . We accomplish an "echo-off" mode by covering the text the user writes
 * with a field contating '*' characters.  If you look at source file Strip.rcp
 * you will see that there are actually two fields that occupy the same exact
 * pixel locations on the field. which ever one is drawn last is the
 * one that will show up. If the user clicks the "echo-off" checkbox on 
 * the screen It will draw the CoverPasswordField over the actual password
 * field.  We therefore need to intecept any key down events that 
 * come into the event queue in order to handle the echo off stuff. This 
 * also poses a problem with selection. We need to make sure that the fields
 * both have the same selections and the same insertion points or it 
 * is confusing to the user. This function is called immediatly before
 * the default event handler, so it should never interfere with system
 * events.If anybody can think of a better way to allow
 * echo off, please let me know.
 * ************************************************************************/ 
static Boolean 
PasswordHandleEvent (EventType *event) 
{
	Boolean handled;
	
		SET_A4_FROM_A5 

		handled = false;
	switch (event->eType)
		
	{
		case ctlSelectEvent:
			switch (event->data.ctlSelect.controlID)
				
			{
					
						// they clicked ok, so check the password
				case PasswordOk:
					checkPassword ();
					handled = true;
					break;
			}
		case frmOpenEvent:
			
				//LstSetSelection((ListPtr)GetObjectFromActiveForm(selPopupList), 0);
				FrmDrawForm (FrmGetActiveForm ());
			FrmSetFocus (FrmGetActiveForm (),
						  FrmGetObjectIndex (FrmGetActiveForm (),
											  PasswordField));
				handled = true; break;
		default:
			break;
	}
	
		RESTORE_A4 

		return (handled);
}


/*********************************************************************
 * Function: ApplicationHandleEvent
 * Description: this is the event handler that we use to 
 * set up forms on frmLoadEvents. It sets the event handlers
 * for every other non modal form in the program
 * *******************************************************************/ 
static Boolean 
ApplicationHandleEvent (EventType *event) 
{
	FormType *frm;
	Int16 formId;
	Boolean handled = false;
	if (event->eType == frmLoadEvent)
		
	{
		
			// load and activate the requested form
			formId = event->data.frmLoad.formID;
		frm = FrmInitForm (formId);
		FrmSetActiveForm (frm);
		
			// set an event handler
			switch (formId)
			
		{
			case PasswordForm:
				FrmSetEventHandler (frm, PasswordHandleEvent);
				break;
		}
		handled = true;
	}
	return handled;
}


/**********************************************************************
 * Function: EventLoop
 * Description: this is the main event loop for the program. It 
 * listens for events for .5 seconds, if none come in, it checks 
 * wheter it should timeout and lock the program. If the unit
 * is scheduled to sleep within the next five seconds, it locks
 * the display. 
 * Note: timeout does not work properly if you overclock you 
 * palm's processor.
 * ********************************************************************/ 
static void 
EventLoop (void) 
{
	EventType event;
	UInt16 error;
	
	do
		
	{
		
			// wait a bit for an event
			EvtGetEvent (&event, 50);

				/* Dont seed with empty events!*/
			if(event.eType != nilEvent)
				random_seed((byte *) &event, sizeof(event)); 
	
			// first the system gets the event, then the Menu event handler, then the application
			// event handler, then finally the form event handler
			if (!SysHandleEvent (&event))
			if (!MenuHandleEvent (0, &event, &error))
				if (!ApplicationHandleEvent (&event))
					FrmDispatchEvent (&event);
	}
	while (event.eType != appStopEvent);
}


/**********************************************************************************
 * Function: PilotMain
 * Description: this is the function that is acctually called by the PalmOS when
 * application start and other events occur. we handle those system launch events
 * here
 * *******************************************************************************/ 
UInt32 PilotMain (UInt16 cmd, MemPtr cmdPBP, UInt16 launchFlags) 
{
	Err err = 0;
	
		// request to start application normally
		if (cmd == sysAppLaunchCmdNormalLaunch)
		
	{
#if ((defined DEBUG) && (defined HAVE_GDBHOOK))	
	_gdb_hook();
#endif 
			// call StartApplication to initialize things, 
			// go to the opening form and enter the event loop,
			// until end.
			if ((err = StartApplication ()) == 0)
			
		{
			FrmGotoForm (PasswordForm);
			EventLoop ();
			StopApplication ();
		}
	}
	return cmd;
}



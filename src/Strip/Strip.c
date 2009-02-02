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

 
 * modified by bret musser, palm@bret.musser.com, 2/19/2001, to fix note form handling 
 * bugs and to add some basic keyboard support, e.g. next/prev field in account forms
 * and keyboard shortcuts
*/  
	
#include <PalmOS.h> 

#include "Strip.h"
#include "StripRsc.h"
#include "strip_types.h"
#include "storage_util.h"
#include "skey.h"
#include "types.h"
#include "sha256_driver.h"
#include "block_cipher_driver.h"
#include "account_hash.h"
#include "random.h"
#include "hex2bin.h"
#include "register.h"

#ifdef HAVE_GDBHOOK
#include "set_a4.h"
#ifdef DEBUG
extern void _gdb_hook ();
#endif
#else
#define SET_A4_FROM_A5
#define RESTORE_A4
#endif


static void * GetObjectFromActiveForm (UInt16 objectID);
static Int16 SortPosAccountFunction (Account * rec1, MemPtr rec2, Int16 unused, SortRecordInfoType *unused1, SortRecordInfoType *unused2, MemHandle appInfo);
static Int16 CompareAccountFunction (MemPtr rec1, MemPtr rec2, Int16 unused, SortRecordInfoType *unused1, SortRecordInfoType *unused2, MemHandle appInfo);
static Int16 SortPosSystemFunction (System * rec1, MemPtr rec2, Int16 unused, SortRecordInfoType *unused1, SortRecordInfoType *unused2, MemHandle appInfo);
static FieldType * setFieldFromHandle (UInt16 field, MemHandle text);
static FieldType * setFieldFromString (UInt16 field, Char *str);
static void SetAttributes (UInt16 edit, UInt16 under, UInt16 scroll, Boolean visible, UInt16 fieldID);
static void objectVisible(UInt16 objectID, Boolean visible);
static void freeCache();
static void cacheSystem (UInt16 index);
static void cacheAccount (UInt16 index); 
static void UpdateScrollbar (UInt16 fieldID, UInt16 scrollbarID); 
static void ScrollLines (Int16 toScroll, Boolean redraw, UInt16 fieldID, UInt16 scrollbarID);
static void PageScroll (WinDirectionType direction, UInt16 fieldID, UInt16 scrollbarID);
static void changePassword (void);
static void initSystems (void);
static void initPassword (md_hash * pass);
static void DrawCharsToFitWidth (char *s, RectangleType *r);
static void AccountListDrawFunction (Int16 itemNum, RectanglePtr bounds, Char **data); 
static void SystemListDrawFunction (Int16 itemNum, RectangleType *bounds, Char **data);
static void AccountFormInit (void);
static void SystemFormInit (void);
static void DisplayAccountInfoBox (void);
static void DisplayInfoBox (void);
static void DisplayAboutBox (void);
static Err StartApplication (void);
static void StopApplication (void);
static void changeForm (UInt16 id);
static void checkPassword (void);
static void generatePasswordString (UInt16 fieldID, Int16 length, Int16  type);
static void generatePw (UInt16 fieldID);
static void showPreferenceScreen ();
static void editSystem (void);
static Boolean editAccount (void);
static void freeCurAcc (void);
static Boolean createNewAccount (void);
static void WriteEditableSystemInfoToScreen (void);
static void HandleClickInPopup (EventType *event);
static void showCreateAccountForm (void);
static void showEditAccountForm (void);
static void WriteEditableAccountInfoToScreen (void);
static void WriteAccountInfoToScreen (void);
static Boolean EditSystemHandleEvent (EventType *event);
static Boolean AddSystemHandleEvent (EventType *event);
static Boolean EditCommentHandleEvent (EventType *event); 
static Boolean generatePasswordHandleEvent (EventType *event); 
static Boolean preferencesHandleEvent (EventType *event);
static Boolean ChangePasswordHandleEvent (EventType *event);
static Boolean PasswordHandleEvent (EventType *event);
static Boolean editAccountHandleEvent (EventType *event);
static Boolean showAccountHandleEvent (EventType *event);
static Boolean newAccountHandleEvent (EventType *event);
static Boolean skeyHandleEvent(EventType *event);
static void createNewSystem (void);
static void deleteAccountFromDB (void);
static void deleteSystemFromDB (void);
static void showShowAccount (UInt16 index);
static Err BeamStream(ExgSocketPtr s, MemPtr buff, UInt32 bytes);
static void BeamAccount(UInt16 index);
static void BeamSystem(UInt16 index);
static Boolean HandleCommonMenus (UInt16 menuID);
static Boolean AccountFormHandleEvent (EventType *event);
static void showAccountForm (UInt16 index);
static Boolean SystemFormHandleEvent (EventType *event);
static Boolean ApplicationHandleEvent (EventType *event);
static void SearchAccounts (FindParamsType *findParams);
static void GoToAccount (GoToParamsType *goToParams);
static void HandlePowerOff (EventType *event);
static void EventLoop (void);
static Err ReadBytesIntoAccount(DmOpenRef db, ExgSocketType *socket, UInt32 bytes, UInt16 aid, Int16 *beamCategory);
static Err ReceiveBeamStream(DmOpenRef db, ExgSocketType *socket);
static void UpdatePasswordScrollers(void);
static Boolean ChooseBeamLocationHandleEvent (EventType *event);
static void beamSelectSystemInit (void);
static void promptBeamCategory (Int16 *beamCategory);
//Char * bin2hex (byte * in, Char * out,  Int16 length);
static void setSystemForAccountForm(UInt16 index);

#ifdef WITH_REGISTER
static void registerForm (void);
static void writeReg (UInt32 date, char *email, char *code);
static void readReg(UInt32 *date, char **email, char **code, MemPtr *scratch);
static Boolean isValidRegCode(char *email, char *code);
static Int16 isValidReg(void);
static Boolean RegisterHandleEvent (EventType *event);
static void writeRegCode(char *email, char *code);
static void warnRegistration(void);
#endif

static FieldPtr GetFocusObjectPtr(void);

#define EVAL_DAYS 15
#define VALID_SECONDS (EVAL_DAYS * 86400)
#define REG_INVALID 0
#define REG_VALID 1
#define REG_EVAL 2

/* Global Variables */ 
UInt16 currentForm, oldForm;


Boolean firstRun = false, hideSecretRecords, closing = false, authenticated = false, regScreen = false;
UInt16 currentSID = 0, currentAID = 0, selectedAccount = 0, selectedSystem = 0;

static md_hash SysPass;
static char *emptyString = STR_EOS;
static const char alphas[53] = "abcdefhijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";	//52
static const char numerics[11] = "0123456789";	// 10
static const char metas[27]= "!#$%&()*+,-./<=>?@[]^_{|}~";	//26
static DmOpenRef SystemDB, AccountDB, PasswordDB;

static UInt16 EditCommentYes; // set 1 if editing comment, added by bret musser 2/19/2001
System CurSys;
Account CurAcc;
MemHandle CurSysScratch, CurAccScratch, CurComment;

StripPrefType prefs;

static inline int min(UInt32 a, UInt32 b) {
	if(a<b) {
		return a;
	}	
	return b;
}

/************************************************************************
 * Function: GetFocusObjectPtr
 * Description: return a pointer to whatever UI object currently has
 * the input focus
 * *********************************************************************/
static FieldPtr GetFocusObjectPtr(void)
{
    FormPtr frm;
    UInt16 focus;
    FormObjectKind objType;

    frm=FrmGetActiveForm();
    focus=FrmGetFocus(frm);
        
        // if no focus return null
    if(focus==noFocus)
        return NULL;

    objType=FrmGetObjectType(frm, focus);

    if(objType == frmFieldObj)
        return (FrmGetObjectPtr(frm, focus));

        // handle tables, this version of strip currently doesnt have any tables
        // but who knows, it might someday
    else if(objType==frmTableObj)
        return (TblGetCurrentField (FrmGetObjectPtr(frm, focus)));

    return NULL;
}

/************************************************************************
 * Function: GetObjectFromActiveForm
 * Description: pass this function the object id of any UI object in the 
 * currently active form and it will return a valid pointer to the 
 * UI object.
 * *********************************************************************/ 
static MemPtr GetObjectFromActiveForm (UInt16 objectID)  {
	FormType *curForm = FrmGetActiveForm ();
	return FrmGetObjectPtr (curForm, FrmGetObjectIndex (curForm, objectID));
}

/***********************************************************************
 * Function: SortPosAccountFunction
 * Description: Callback function to find the proper insertion index 
 * for an account based on alphabetical order of the account username
 * *********************************************************************/ 
static Int16 SortPosAccountFunction (Account * rec1, MemPtr rec2, Int16 unused,
	SortRecordInfoType *unused1, SortRecordInfoType *unused2,  MemHandle appInfo) {
	Int16 result = 0, sysid;
	Account ac;
	MemPtr scratch;
	
	SET_A4_FROM_A5 
		
	/*	pop the system id off the record.  If the sysid is -1 then the record has been beamed
		and is not encrypted, therefore we always return 1 so the unencrypted record ends
		up at the beginning of the database. */
	MemMove (&sysid, rec2, sizeof (sysid));
	
	if (sysid == -1) result = 1;
	else {
		if ((scratch = MemPtrNew (MemPtrSize (rec2)))) {
			/* unpack the second account and compare the usernames */
			UnpackAccount (&ac, rec2, scratch, &SysPass, MemPtrSize (rec2), true, true);
			if (prefs.accountSort) {
				result = StrCompare (rec1->username, ac.username);
				if (result == 0) result = StrCompare (rec1->system, ac.system);
			} else {
				result = StrCompare (rec1->system, ac.system);
				if (result == 0) result = StrCompare (rec1->username, ac.username);
			}
			MemSet (scratch, MemPtrSize (scratch), 0);
			MemPtrFree (scratch);
		}
	}
	
		RESTORE_A4 

	
	return result;
}


/***********************************************************************
 * Function: CompareAccountFunction
 * Description: Callback function to find the proper sort index 
 * for an account based on alphabetical order of the account username or type 
* *********************************************************************/ 
static Int16 CompareAccountFunction (MemPtr rec1, MemPtr rec2, Int16 unused,
	SortRecordInfoType *unused1, SortRecordInfoType *unused2, MemHandle appInfo) {
	Int16 result = 0;
	Account one, two;
	MemPtr scratch1, scratch2;
	
	SET_A4_FROM_A5 

		if ((scratch1 = MemPtrNew (MemPtrSize (rec1))) 
			&& (scratch2 = MemPtrNew (MemPtrSize (rec2)))) {
			UnpackAccount (&one, rec1, scratch1, &SysPass, MemPtrSize (rec1), true, true);
			UnpackAccount (&two, rec2, scratch2, &SysPass, MemPtrSize (rec2), true, true);
			if (prefs.accountSort) {
				result = StrCompare (one.username, two.username);
				if (result == 0) result = StrCompare (one.system, two.system);
			} else {
				result = StrCompare (one.system, two.system);
				if (result == 0) result = StrCompare (one.username, two.username);
			}
			MemSet (scratch1, MemPtrSize (scratch1), 0);
			MemSet (scratch2, MemPtrSize (scratch2), 0);
			MemPtrFree (scratch1);
			MemPtrFree (scratch2);
		}
	
	RESTORE_A4 

		return result;
}


/***********************************************************************
 * Function: SortPosSystemFunction
 * Description: Callback function to find the proper insertion index 
 * for an system based on alphabetical order of the system name
 * *********************************************************************/ 
static Int16 SortPosSystemFunction (System * rec1, MemPtr rec2, Int16 unused,
	SortRecordInfoType *unused1, SortRecordInfoType *unused2, MemHandle appInfo) {
	Int16 result = 0;
	System sys;
	MemPtr scratch;
	
	SET_A4_FROM_A5 

	if ((scratch = MemPtrNew (MemPtrSize (rec2)))) {
		/* unpack the second system and compare the names */
		UnpackSystem (&sys, rec2, scratch, &SysPass, MemPtrSize (rec2), true); 
		result = StrCompare (rec1->name, sys.name);
		MemSet (scratch, MemPtrSize (scratch), 0);
		MemPtrFree (scratch);
	}
	
	RESTORE_A4 


	return result;
}
	
/************************************************************************
 * Function: setFieldFromHandle
 * Description:  Pass the function the object id of a field and a handle
 * containing the text and it sets the field value to the text handle.
 * It will return a pointer to the set field.
 * **********************************************************************/ 
static FieldType *setFieldFromHandle (UInt16 field, MemHandle text) {
	MemHandle oldText;
	FieldType *fld = GetObjectFromActiveForm (field);
	
	/* get a pointer to the old handle */
	oldText = (MemHandle) FldGetTextHandle (fld);
	FldSetTextHandle (fld, (MemHandle) text);
	FldDrawField (fld);
	
	/* deallocate the old handle */
	if(oldText) freeHandle (oldText);
	return fld;
}

/************************************************************************
 * Function: setFieldFromString
 * Description:  Pass the function the object id of a field and a string
 * containing the text and it creates a new handle, and calls setField from
 * handle to set the field value. 
 * It will return a pointer to the set field.
 * **********************************************************************/ 
static FieldType *setFieldFromString (UInt16 field, Char *str) {
	MemHandle text = MemHandleNew (StrLen (str) + 1);
	if (!text) return NULL;	
	/* copy the string to the new handle */
	StrCopy(MemHandleLock(text), str);
	MemHandleUnlock(text);
	return setFieldFromHandle(field, text);
}

/**************************************************************************
 * Function: SetAttributes
 * Description: pass it a set of variables representing attributes of a field
 * including editablility, underlined, scrollable, and visible. Also pass
 * it the object id of the field you wish to set for.
 * ************************************************************************/ 
static void SetAttributes (UInt16 edit, UInt16 under, UInt16 scroll, Boolean visible, UInt16 fieldID) {
	FieldType *fld;
	FieldAttrType attr;
	fld = GetObjectFromActiveForm (fieldID);
	
	/* get the current attributes, change some of them. */
	FldGetAttributes (fld, &attr);
	attr.editable = edit;
	attr.underlined = under;
	attr.hasScrollBar = scroll;
	
	/* set the new attributes. */
	FldSetAttributes (fld, &attr);
	
	/* if not visible erase the field. */
	if (!visible) FldEraseField (fld);
}

/************************************************************************
 * Function: objectVisible
 * Description: show or hide an object.
 * **********************************************************************/ 
static void objectVisible(UInt16 objectID, Boolean visible) {
	ControlType *p = GetObjectFromActiveForm (objectID);
	if(visible)
		CtlShowControl(p);
	else 
		CtlHideControl(p);
}

/************************************************************************
 * Function: freeCache
 * Description: free the global password, system, and account cache.
 * **********************************************************************/ 
static void freeCache (void) {
	if (SysPass) MemSet (SysPass, sizeof (SysPass), 0);
	freeHandle (CurSysScratch);
	freeHandle (CurAccScratch);
	CurComment = freeHandle (CurComment);
}


/************************************************************************
 * Function: cacheSystem
 * Description: this function will bring a system into the global cache
 * based upon its index withing the system database.
 * **********************************************************************/ 
static void cacheSystem (UInt16 index) {
	/* if there is already a cached system, free it. */
	freeHandle (CurSysScratch);
	
	/* get the new system. */
	if ((CurSysScratch = MemHandleNew (1))) {
		getSystemFromIndex (SystemDB, &SysPass, index, CurSysScratch, &CurSys);
	}
}


/***********************************************************************
 * Function: cacheAccount
 * Description: this function will bring an account into the global cache
 * based upon its index withing the account database.
 * *********************************************************************/ 
static void cacheAccount (UInt16 index) {
	/* if there is already a cached account, free it. */
	freeHandle (CurAccScratch);
	
	/* get the new account */
	if ((CurAccScratch = MemHandleNew (1)))
		getAccountFromIndex (AccountDB, &SysPass, index, CurAccScratch, &CurAcc);
}


/************************************************************************
 * Function: UpdateScrollbar
 * Description: updates the scrollbar for a scrollable field
 * **********************************************************************/ 
static void UpdateScrollbar (UInt16 fieldID, UInt16 scrollbarID) {
	ScrollBarType *scroll;
	UInt16 currentPos;
	UInt16 textHeight;
	UInt16 fieldHeight;
	UInt16 maxValue;
	FieldType *field = GetObjectFromActiveForm(fieldID);
	
	FldGetScrollValues (field, &currentPos, &textHeight, &fieldHeight);
	
	/* calculate max value based on field height and text height */
	if (textHeight > fieldHeight) maxValue = textHeight - fieldHeight;
	else if (currentPos) maxValue = currentPos;
	else maxValue = 0;
	
	/* get a pointer to the scrollbar and setup the scroll bar. */
	scroll = GetObjectFromActiveForm (scrollbarID);
	SclSetScrollBar (scroll, currentPos, 0, maxValue, fieldHeight - 1);
}


/***********************************************************************
 * Function: ScrollLines
 * Description: scrolls a field based a variable number of lines and optionally
 * redraws
 * *********************************************************************/ 
static void ScrollLines (Int16 toScroll, Boolean redraw, UInt16 fieldID, UInt16 scrollbarID) {
	FieldType *field = GetObjectFromActiveForm (fieldID);
	
	/* scroll the field according to the number of lines. */
	if (toScroll < 0) FldScrollField (field, -toScroll, winUp);
	
	else
		FldScrollField (field, toScroll, winDown);
	
	/* redraw if neccessary or if requested */
	if ((FldGetNumberOfBlankLines (field) && toScroll < 0) || redraw)
		UpdateScrollbar (fieldID, scrollbarID);
}

/*********************************************************************
 * Function: PageScroll
 * Description: Scroll a field up or down one entire page
 * *******************************************************************/ 
static void PageScroll (WinDirectionType direction, UInt16 fieldID, UInt16 scrollbarID) {
	FieldType *field;
	field = GetObjectFromActiveForm (fieldID);
	
	/* make sure the field is scrollable */
	if (FldScrollable (field, direction)) {	
		/* find out how many lines are visible */
		int toScroll = FldGetVisibleLines (field) - 1;
		if (direction == winUp) toScroll = -toScroll;
		
		/* scroll em */
		ScrollLines (toScroll, true, fieldID, scrollbarID);
	}
}

/***************************************************************************
 * Function: changePassword
 * Description: handles changing the system password based upon the 
 * password change screen. Basically checks that current password is correct,
 * checks that the new password was entered correctly, then re-encrypts the
 * databases based upon the new password.
 * ************************************************************************/ 
static void changePassword (void) {
	char *oP, *pWS, *cP;
	md_hash newPass, test;
	
	/*	compact text fields. this is not really neccessary, but it is
		a good habit as it frees wasted memory. */
	FldCompactText (GetObjectFromActiveForm (ChangePasswordCurrentField));
	FldCompactText (GetObjectFromActiveForm (ChangePasswordNewField));
	FldCompactText (GetObjectFromActiveForm (ChangePasswordField));
	
	/* get pointers to all the fields. */
	cP = FldGetTextPtr (GetObjectFromActiveForm (ChangePasswordNewField));
	oP = FldGetTextPtr (GetObjectFromActiveForm (ChangePasswordCurrentField));
	pWS = FldGetTextPtr (GetObjectFromActiveForm (ChangePasswordField));
	
	md_string(oP, test);	
		
	/*	if the user doesnt enter anything, just assume they dont really want to
		change the password and pop them back to the last form they were at. */
	if ((!cP) || (!oP) || (!pWS) || (!StrLen (cP)) || (!StrLen (oP)) || (!StrLen (pWS)))
		changeForm (oldForm);
		
	/*	if they specified the wrong system password they arent allowed to change 
		the system passwords. */
	else if (MemCmp (test, SysPass, sizeof(md_hash)))
		FrmCustomAlert (GenericError, STR_INCORRECT_PASSWORD, NULL, NULL); 
	/*	verification failed, warn the user. */
	else if (StrCompare (pWS, cP))
		FrmCustomAlert (GenericError, STR_PASSWORDS_DONT_MATCH, NULL, NULL); 
	/*	everything looks good, lets go to work. */
	else {
		/* total number of records to re-write */
		UInt16 i = 0;
		MemHandle rH;
		UInt16 totalAItems = DmNumRecordsInCategory (AccountDB, dmAllCategories);
		UInt16 totalSItems = DmNumRecordsInCategory (SystemDB, dmAllCategories);
		MemPtr pac = NULL, scratch = NULL, scratch2 = NULL;
		FormType *preF = FrmGetActiveForm ();
		FormType *f = FrmInitForm (pleaseWait);
		FrmDrawForm (f);

		md_string (pWS, newPass);
		/*	re-encrypt the password */
		if ((rH = DmGetRecord (PasswordDB, 0))) {
			if ((scratch = MemPtrNew(getSCSize(sizeof(md_hash))))) {
				PackPassword (scratch, &newPass);
				writeRecord(scratch, rH);
				MemSet (scratch, MemPtrSize (scratch), 0);
				MemPtrFree (scratch);
			}
			DmReleaseRecord (PasswordDB, 0, true);
		}
		
		/*	loop through the systems and re-encrypt */
		for (i = 0; i < totalSItems; i++) {
			System sys;
			if ((rH = DmGetRecord (SystemDB, i))) {
				pac = MemHandleLock (rH);
				if ((scratch = MemPtrNew (MemPtrSize (pac)))) {
					/*	decrypt the system with old password */
					UnpackSystem (&sys, pac, scratch, &SysPass, MemHandleSize (rH), true);
					if ((scratch2 = MemPtrNew (getSystemSize(&sys, true)))) {
						/*	re-encrypt with new password */
						PackSystem (scratch2, sys, &newPass, true);
						writeRecord(scratch2, rH);
						MemSet (scratch2, MemPtrSize (scratch2), 0);
						MemPtrFree (scratch2);
					}
					MemSet (scratch, MemPtrSize (scratch), 0);
					MemPtrFree (scratch);
				}
				MemHandleUnlock (rH);
				DmReleaseRecord (SystemDB, i, true);
			}
		}
		
		/* loop through the accounts and re-encrypt */
		for (i = 0; i < totalAItems; i++) {
			UInt16 id;
			Account ac;
			if ((rH = DmGetRecord (AccountDB, i))) {
				pac = MemHandleLock (rH);
				if ((scratch = MemPtrNew (MemPtrSize (pac)))) {
					
					/*	decrypt the system with old password */
					UnpackAccount (&ac, pac, scratch, &SysPass,
						MemHandleSize (rH), true, true);
					id = ac.SystemID;
					if ((scratch2 = MemPtrNew (getAccountSize (&ac, true)))) {	
						/* re-encrypt with new password */
						PackAccount (scratch2, ac, &newPass, true);
						writeRecord(scratch2, rH);
						MemSet (scratch2, MemPtrSize (scratch2), 0);
						MemPtrFree (scratch2);
					}
					MemSet (scratch, MemPtrSize (scratch), 0);
					MemPtrFree (scratch);
				}
				MemHandleUnlock (rH);
				DmReleaseRecord (AccountDB, i, true);
			}
		}
		
		MemSet (SysPass, sizeof(md_hash), 0);
		MemMove (SysPass, newPass, sizeof(md_hash));
		MemSet (newPass, sizeof(md_hash), 0);
		MemSet (test, sizeof(md_hash), 0);

		FrmEraseForm (f);
		FrmDeleteForm (f);
		FrmSetActiveForm (preF);
		changeForm (StripSystemForm);
	}
}


/*************************************************************************
 * Function: initSystems
 * Description: Simple function creates the "Unfiled category" with 
 * SystemID of 0
 * **********************************************************************/ 
static void initSystems (void) {
	System sys;
	UInt16 index = 0;
	MemHandle rec;
	if ((rec = DmNewRecord (SystemDB, &index, 1))) {
		/*	set up the system info */
		sys.SystemID = 0;
		sys.name = STR_UNFILED_CATEGORY;
		if (rec) {
			MemPtr scratch;
			if ((scratch = MemPtrNew (getSystemSize(&sys, true)))) {	
				/*	encrypt and write it. */
				PackSystem (scratch, sys, &SysPass, true);
				writeRecord(scratch, rec);
				MemSet (scratch, MemPtrSize (scratch), 0);
				MemPtrFree (scratch);
			}
		}
		DmReleaseRecord (SystemDB, index, true);
	}
}


/*********************************************************************
 * Function: initPassword
 * Description: pass it the string password that the user originally 
 * requests, and write it out to the database.
 * *******************************************************************/ 
static void initPassword (md_hash * pass) {
	UInt16 index = 0;
	MemHandle rec;
	if ((rec = DmNewRecord (PasswordDB, &index, 1))) {
		MemPtr scratch;
		if ((scratch = MemPtrNew (getSCSize(sizeof(md_hash))))) {
			PackPassword(scratch, pass);
			writeRecord(scratch, rec);
			MemSet (scratch, MemPtrSize (scratch), 0);
			MemPtrFree (scratch);
		}
		DmReleaseRecord (PasswordDB, index, true);
	}
}


#ifdef WITH_REGISTER
static void writeRegCode(char *email, char *code) {
	UInt32 date;
	MemPtr scratch = NULL;
	char *tmp_email;
	char *tmp_code;
	readReg(&date, &tmp_email, &tmp_code, &scratch);
	writeReg(date, email, code);
	MemPtrFree(scratch);
}


/*********************************************************************
 * Function: writeReg
 * Description: 
 * *******************************************************************/ 
static void writeReg (UInt32 date, char *email, char *code) {
	UInt16 index = 1;
	MemHandle rec;
	Registration reg;
	
	reg.first_use = date;
	reg.email = email;
	reg.code = code;

	if ((rec = DmNewRecord (PasswordDB, &index, 1))) {
		MemPtr scratch;
		if ((scratch = MemPtrNew (getRegistrationSize(&reg)))) {
			PackRegistration(scratch, reg);
			writeRecord(scratch, rec);
			MemSet (scratch, MemPtrSize (scratch), 0);
			MemPtrFree (scratch);
		}
		DmReleaseRecord (PasswordDB, index, true);
	}
}

/*********************************************************************
 * Function: readReg
 * Description: 
 * *******************************************************************/ 
static void readReg(UInt32 *date, char **email, char **code, MemPtr *scratch) {
	UInt16 index = 1;
	MemHandle rec;
	Registration reg;
	MemPtr regpack;

	if ((rec = DmQueryRecord (PasswordDB, index))) {
		regpack = MemHandleLock (rec);
		if ((*scratch = MemPtrNew (MemPtrSize(regpack)))) {
			MemMove (*scratch, regpack, MemPtrSize(regpack));
			UnpackRegistration(&reg, regpack);
		}
		MemHandleUnlock (rec);
	}

	*date = reg.first_use;	
	*email = reg.email;
	*code =  reg.code;
}

static Boolean isValidRegCode(char *email, char *code) {
	if(email && code && StrLen(email) && StrLen(code)) {
	//	FrmCustomAlert(GenericError, email, "\n", getCode(email));
		if(!StrCompare(code, getCode(email))) return true;
	}
	return false;
}

static void warnRegistration() {
	UInt32 first_date = 0, cur_date = 0;
	MemPtr scratch = NULL;
	char *email = NULL;
	char *code = NULL;
	static char dayss[6];
	int days_left;
	cur_date = TimGetSeconds();
	
	readReg(&first_date, &email, &code, &scratch);

	days_left = ((cur_date - first_date) / 86400) + 1;
	StrIToA(dayss, days_left);
	FrmCustomAlert(GenericError,
				STR_EVAL_START,
				dayss, STR_EVAL_END);

	if(scratch != NULL) MemPtrFree(scratch);
}

/*********************************************************************
 * Function: isValidReg
 * Description: 
 * *******************************************************************/ 
static Int16 isValidReg() {
	UInt32 first_date = 0, cur_date = 0;
	MemPtr scratch = NULL;
	char *email = NULL;
	char *code = NULL;
	Boolean retval = 0;
	cur_date = TimGetSeconds();
	
	readReg(&first_date, &email, &code, &scratch);

	if(isValidRegCode(email,code)) {
		retval = REG_VALID;
	} else if(cur_date < (first_date + VALID_SECONDS)) { 
		retval = REG_EVAL;
	} else {
		retval = REG_INVALID;
	}

	if(scratch != NULL) MemPtrFree(scratch);

	return retval;
}
#endif

/********************************************************************
 * Function: DrawCharsToFitWidth
 * Description: simple utility call that will draw the chars of string
 * s into the rectange bounds. This is the function we use to 
 * draw the lists to the screen.
 * ******************************************************************/ 
static void DrawCharsToFitWidth (char *s, RectangleType *r) {
	Int16 strLen = StrLen (s);
	Int16 pixelWidth = r->extent.x;
	Boolean truncate;
	FntCharsInWidth (s, &pixelWidth, &strLen, &truncate);
	WinDrawChars (s, strLen, r->topLeft.x, r->topLeft.y);
}


/********************************************************************
 * Function: AccountListDrawFunction
 * Description: Callback function that does the drawing of the 
 * account names to the accountList
 * ******************************************************************/ 
static void AccountListDrawFunction (Int16 itemNum, RectangleType *bounds, Char **data) { 
	UInt16 length;
	Account ac;
	MemHandle scr;
	MemPtr toDraw;
	
	SET_A4_FROM_A5 

	if ((scr = MemHandleNew (1))) {
		
	/*	get the account indicated by itemNum */
		getAccountFromIndex (AccountDB, &SysPass, getIndexOfNthAcct (AccountDB, currentSID, itemNum), scr, &ac);
		
	/*	if there is a account type, cat it onto the end */
		length = StrLen (ac.username) + StrLen (ac.system) + 5;
		if ((toDraw = MemPtrNew (length))) {
			if (prefs.accountFirst) {
				StrCopy (toDraw, ac.username);
				if (StrLen (ac.system)) {
					StrCat (toDraw, STR_ACCOUNT_DELIM);
					StrCat (toDraw, ac.system);
				}
			} else {
				StrCopy (toDraw, STR_EOS);
				if (StrLen (ac.system)) {
					StrCat (toDraw, ac.system);
					StrCat (toDraw, STR_ACCOUNT_DELIM);
				}
				StrCat (toDraw, ac.username);
			}
			/* draw it */
			DrawCharsToFitWidth ((Char*) toDraw, bounds);
			MemSet (toDraw, MemPtrSize (toDraw), 0);
			MemPtrFree (toDraw);
		}
		MemHandleFree (scr);
	}
	
	RESTORE_A4 

}

/********************************************************************
 * Function: SystemListDrawFunction
 * Description: Callback function that does the drawing of the 
 * system names to the SystemList
 * ******************************************************************/ 
static void SystemListDrawFunction (Int16 itemNum, RectangleType *bounds, Char **data) {
	System sys;
	MemHandle scr;
	
	SET_A4_FROM_A5 

//	DrawCharsToFitWidth ("All", bounds);

	if ((scr = MemHandleNew (1))) {	
		/*	get the system and draw it */
		getSystemFromIndex (SystemDB, &SysPass, itemNum, scr, &sys);
		DrawCharsToFitWidth (sys.name, bounds);
		freeHandle (scr);
	}
	
	RESTORE_A4 

}

/*********************************************************************
 * Function: AccountFormInit
 * Description: function will set up the list to be drawn
 * find out how many items will be in the list, and install the
 * AccountListDrawFunction
 * *******************************************************************/ 
static void AccountFormInit (void) {
	UInt16 numAcc = numAccountsInSystem (AccountDB, currentSID);
	ListType *list = GetObjectFromActiveForm (accountList);

	UInt16 numSys = DmNumRecordsInCategory(SystemDB, dmAllCategories);
	ListType *slist = GetObjectFromActiveForm(SystemList);

	LstSetDrawFunction (slist, SystemListDrawFunction);
	/*	if there are less than 8 systems, set the list height to be
		the number of systems. If there are more than 8 systems a maximum
		of 8 will be shown at a time (without scrolling). */
	LstSetListChoices (slist, NULL, numSys);

	if (numSys < 15) 
		LstSetHeight (slist, numSys); 
	else
		LstSetHeight (slist, 15);
	
		// get the popup, set the selection and label
	LstSetSelection (slist, selectedSystem);
	CtlSetLabel (GetObjectFromActiveForm (AccountSystemPopupTrigger),
				  CurSys.name);

	LstSetListChoices(list, NULL, numAcc);
	LstSetDrawFunction(list, AccountListDrawFunction);
	if (selectedAccount > 0) {
		LstSetSelection(list, selectedAccount);
		LstMakeItemVisible(list, selectedAccount);
	}
}


/*********************************************************************
 * Function: SystemFormInit
 * Description: function will set up the list to be drawn
 * find out how many items will be in the list, and install the
 * SystemListDrawFunction
 * *******************************************************************/ 
static void SystemFormInit (void) {
	UInt16 numSys = DmNumRecordsInCategory(SystemDB, dmAllCategories);
	ListType *list = GetObjectFromActiveForm(SystemList);
	LstSetListChoices(list, NULL, numSys);
	LstSetDrawFunction(list, SystemListDrawFunction);
	if (selectedSystem > 0) {
		LstSetSelection(list, selectedSystem);
		LstMakeItemVisible(list, selectedSystem);
	}
}



/**********************************************************************
 * Function: DisplayAccountInfoBox
 * Description: pops up a dialog box 
 * ********************************************************************/ 
static void DisplayAccountInfoBox (void) {
	static char aid[8], sid[8], sig0[25], sig1[25], sig2[17];
	char acc_mod[dateStringLength+timeStringLength+1], pw_mod[dateStringLength+timeStringLength+1];
	char date_temp[dateStringLength];
	char time_temp[timeStringLength];
	DateTimeType calculate;

    FormType *previousForm = FrmGetActiveForm ();
    FormType *frm = FrmInitForm (accountInfoDialog);
    UInt16 button;
   
	FrmSetActiveForm (frm);
	/* calling FrmDrawForm saves the pixels behind the modal dialog
	 * so that the old form will be redrawn correctly when 
	 * this modal dialog pops down. */
	FrmDrawForm (frm);

	MemSet(sig0, 25, 0);
	MemSet(sig1, 25, 0);
	MemSet(sig2, 17, 0);
	
	bin2hex(CurAcc.hash, sig0, 12);
	bin2hex(&(CurAcc.hash)[12], sig1, 12);
	bin2hex(&(CurAcc.hash)[24], sig2, 8);
	setFieldFromString(AccountSig0, sig0);
	setFieldFromString(AccountSig1, sig1);
	setFieldFromString(AccountSig2, sig2);
	/*
	setFieldFromString(AccountSig0, bin2hex(CurAcc.hash, sig0, 12));
	setFieldFromString(AccountSig1, bin2hex(&(CurAcc.hash)[12], sig1, 12));
	setFieldFromString(AccountSig2, bin2hex(&(CurAcc.hash)[24], sig2, 8));
	*/
	setFieldFromString(SystemIDField, StrIToA (sid, CurAcc.SystemID));
	setFieldFromString(SystemIDField, StrIToA (sid, CurAcc.SystemID));
	setFieldFromString(AccountIDField, StrIToA (aid, CurAcc.AccountID));

	/* calculate date infos and strings */	
	TimSecondsToDateTime(CurAcc.account_mod_date, &calculate);
	DateToAscii(calculate.month, calculate.day, calculate.year, dfMDYWithSlashes, date_temp);
	TimeToAscii(calculate.hour, calculate.minute, tfColonAMPM, time_temp);
	StrCopy(acc_mod, date_temp); StrCat(acc_mod, " "); StrCat(acc_mod, time_temp);
	setFieldFromString(AccountModifiedField, acc_mod );
	TimSecondsToDateTime(CurAcc.password_mod_date, &calculate);
	DateToAscii(calculate.month, calculate.day, calculate.year, dfMDYWithSlashes, date_temp);
	TimeToAscii(calculate.hour, calculate.minute, tfColonAMPM, time_temp);
	StrCopy(pw_mod, date_temp); StrCat(pw_mod, " "); StrCat(pw_mod, time_temp);
	setFieldFromString(PasswordModifiedField, pw_mod );

	button = FrmDoDialog (frm);

	/* erase and delete the form */
	FrmEraseForm (frm);
	FrmDeleteForm (frm);
	if (previousForm) FrmSetActiveForm (previousForm); 
}

/**********************************************************************
 * Function: DisplayInfoBox
 * Description: pops up a dialog box informing the user of how many
 * systems and accounts that strip is tracking.
 * ********************************************************************/
static void DisplayInfoBox(void) {
	static char s[6], a[6];
	StrIToA(s, DmNumRecordsInCategory(SystemDB, dmAllCategories));
	StrIToA(a, DmNumRecordsInCategory(AccountDB, dmAllCategories));

	FrmCustomAlert(infoDialog, s, a, NULL);
}

/***********************************************************************
 * Function: DisplayAboutBox
 * Description: pops up the modal dialog "about strip"
 * *********************************************************************/ 
static void DisplayAboutBox (void) {
	FormType *previousForm = FrmGetActiveForm ();
	FormType *frm = FrmInitForm (aboutAlert);
	UInt16 button;
	
	/*	pop up the dialog. */
	button = FrmDoDialog (frm);
	
	/*	set the previous form. */
	if (previousForm) FrmSetActiveForm (previousForm);
	
	/* Must call FrmDeleteForm or the memory never get released. */
	FrmDeleteForm (frm);
}

/* FIXME 
 * This function should handle in place upgrades (as an alternative to StripCS)
 * */
static Err doUpgrade(UInt16 oldPrefsVersion) {

	if 	(oldPrefsVersion < 6 ) {
		FrmCustomAlert (GenericError, STR_WRONGVERSION, NULL, NULL);
		return -1;
	} else if(oldPrefsVersion == 6) { 
		if (DmNumRecordsInCategory (PasswordDB, dmAllCategories) == 1)
#ifdef WITH_REGISTER
			writeReg(TimGetSeconds(), STR_EMPTY, STR_EMPTY);
#endif
		/*
			FrmCustomAlert(GenericError,
					"Setting lastCategoryIndex",
					NULL, NULL);
		*/
		prefs.lastCategoryIndex = 0;
	}

	return 0;
}

/********************************************************************************
 * Function: StartApplication
 * Description: This is the first function that gets called and it is 
 * responsible for initializing databases and other global variables, checking
 * to see whether private records will be shown and calculating the auto-off time
 * for the current system.
 * ******************************************************************************/ 
static Err StartApplication (void) {
	UInt16 mode = dmModeReadWrite;
	Int16 prefsSize, prefsVersion, oldPrefsVersion;
	Err errors = 0;
	Boolean created;
	
	/*	set current form to be the password opener */
	currentForm = PasswordForm;
	
	/*	check about private records */
	hideSecretRecords = PrefGetPreference (prefHidePrivateRecordsV33);
	if (!hideSecretRecords) mode |= dmModeShowSecret;
	
	/*	handle program prefrences */
	prefsSize = sizeof (StripPrefType);
	prefsVersion = PrefGetAppPreferences (StripCreator, StripPrefID, &prefs, &prefsSize, true);
	oldPrefsVersion = prefsVersion;

	if (prefsVersion == noPreferenceFound) {
	
		prefs.echoOff = false;
		prefs.accountFirst = true;
		prefs.accountSort = true;
		prefs.autoLock = true;
		prefs.smart_beaming = false;
		prefs.pwType = 2;
		prefs.pwLengthIndex = 4;
		prefs.lastCategoryIndex = 0;

		PrefSetAppPreferences (StripCreator, StripPrefID, StripVersionNumber,
			&prefs, sizeof (StripPrefType), true);
		prefsVersion = PrefGetAppPreferences (StripCreator, StripPrefID, 
			&prefs, &prefsSize, true);
	} 
	
	/*	open or create databases. */
	errors = getDatabase (&SystemDB, systemDBType, StripCreator, mode, 0, systemDBName, &created);
	errors = getDatabase (&AccountDB, accountDBType, StripCreator, mode, 0, accountDBName, &created);
	errors = getDatabase (&PasswordDB, passwordDBType, StripCreator, mode, 0, passwordDBName, &created); 
	
	/*	if the password database does not exist, or there are no records in it note that 
		this is the first run, so the user will be prompted to enter a new password. */
	if (created || (DmNumRecordsInCategory (PasswordDB, dmAllCategories) == 0)) {
		firstRun = true;
	} 

	return doUpgrade(oldPrefsVersion);
}


/************************************************************************
 * Function: StopApplication
 * Description:  this function is responsible for stopping all application
 * related activity, freeing used memory, resetting the auto-off time, and
 * closing the databases.
 * **********************************************************************/ 
static void StopApplication (void) {
	
	
	/* save the data, close the forms, free the System, password and account caches */
	FrmSaveAllForms();
	FrmCloseAllForms();
	freeCache();
	
	PrefSetAppPreferences (StripCreator, StripPrefID, StripVersionNumber,
							&prefs, sizeof (StripPrefType), true);
	/*	close databases. */
	DmCloseDatabase (SystemDB);
	DmCloseDatabase (AccountDB);
	DmCloseDatabase (PasswordDB);
}

/*****************************************************************************
 * Function: changeForm
 * Description: utility function that changes the current form and tracks
 * the current and last form shown.
 * ***************************************************************************/ 
static void changeForm (UInt16 id) {
	oldForm = currentForm;
	/*	this function changes the current form and sends a form load event. */
	FrmGotoForm (id);
	currentForm = id;
}

#ifdef WITH_REGISTER
/*******************************************************************
 * Function: registerForm
 * Description: this function is responsible 
 * *****************************************************************/ 
static void registerForm (void) {
	/*	get pointer to previous form and initalize the modal dialog */
	FormType *previousForm = FrmGetActiveForm ();
	FormType *frm = FrmInitForm (RegisterForm);
	char *email = NULL;
	char *code = NULL;
	UInt16 button;
	MemPtr scratch = NULL;
	UInt32 date;
	char *tmp_email;
	char *tmp_code;
	

	/*	draw the form */
	FrmSetActiveForm (frm);
	FrmDrawForm (frm);
	
	/*	set event handler */
	FrmSetEventHandler (frm, RegisterHandleEvent);
	
	readReg(&date, &tmp_email, &tmp_code, &scratch);
	setFieldFromString (RegisterEmail, tmp_email);
	setFieldFromString (RegisterCode, tmp_code);
	MemPtrFree(scratch);	
	
	/*	handle the button click */
	do {
		button = FrmDoDialog (frm);
		if(button == RegisterOk) {
			FldCompactText (GetObjectFromActiveForm (RegisterEmail));
			FldCompactText (GetObjectFromActiveForm (RegisterCode));
			email = FldGetTextPtr (GetObjectFromActiveForm (RegisterEmail));
			code = FldGetTextPtr (GetObjectFromActiveForm (RegisterCode));
	
			if (email && code && StrLen(email) && StrLen(code) && isValidRegCode(email, code)) {
							writeRegCode(email, code);
			} else {
				FrmCustomAlert(GenericError,
					STR_BADREGCODE,
					NULL, NULL);
			}	
		} 
	} while((isValidReg() != REG_VALID) && button == RegisterOk);

	FrmEraseForm (frm);
	FrmDeleteForm (frm);
	if (previousForm) {
			FrmSetActiveForm (previousForm);
	}

}
#endif

/********************************************************************************
 * Function: checkPassword
 * Description: this is the function responsible for checking the 
 * input password value of the authentication form. 
 * ******************************************************************************/ 
static void checkPassword (void) {
	MemPtr pass1, scratch = NULL;
	char *input;

	UInt16 index = 0;
	MemHandle rec;
	md_hash in, saved;
	

	/*	compact text and get a pointer. */
	FldCompactText (GetObjectFromActiveForm (PasswordField));
	input = FldGetTextPtr (GetObjectFromActiveForm (PasswordField));

	/*	if its the first time the user has used the program we need 
		to set some things up. */
	if (firstRun) {	
		/*	if they entered a password */
		if (input && StrLen (input)) {	
			md_string (input, in);
				/* store the new password to  db */
			initPassword (&in);
#ifdef WITH_REGISTER
			writeReg(TimGetSeconds(), STR_EMPTY, STR_EMPTY);
#endif
		} else {
			/* otherwise tell them that the password they enter will be the default password */
			FrmCustomAlert (GenericError, STR_FIRSTTIME,NULL, NULL); 
			input = NULL;
			firstRun = true;
			return;
		}
	}

	/*
	if (!firstRun && (isValidReg() == REG_INVALID)) {
		//FrmCustomAlert(GenericError, STR_EVAL, NULL, NULL); 
		//registerForm();
	}	else */
	if (input && StrLen (input)) {

		md_string (input, in);
	
		/*	read the password from the database, decrypt with the input text. */
		if ((rec = DmQueryRecord (PasswordDB, index))) {
			pass1 = MemHandleLock (rec);
			if ((scratch = MemPtrNew (getSCSize(sizeof(md_hash)))))
				UnpackPassword (pass1, scratch, &in);
			MemHandleUnlock (rec);
		}
		
		/*	the message digest of the password they provided should be exactly the
			same as the message digest that was just decrypted out of the password
			database. Do a MemCmp to make sure they are the same. */
		if (!MemCmp (in, scratch, sizeof(md_hash))) {	
			/*	if so, copy the password onto the system-password hash */
			MemMove (SysPass, in, sizeof(md_hash));
			
			/*	if its the first run initialize the Unfiled system */
			if (firstRun) {
				initSystems ();
				firstRun = false;
			}
			
			if (scratch) {
				MemSet (scratch, MemPtrSize (scratch), 0);
				MemPtrFree (scratch);
			}
			MemSet (in, sizeof (md_hash), 0);
			MemSet (saved, sizeof (md_hash), 0);
			
			/*	turn the underlining off on the password input fields. this is a bug-fix for
				a redraw problem. */
			SetAttributes (1, 0, 1, true, PasswordField);
			
			/*	SUCCESS!!!!! */
			authenticated = true;
// FIXME - change this to allow multiple views
			showAccountForm (prefs.lastCategoryIndex);
			//showAccountForm (0);
//			changeForm (StripSystemForm);
		} else {
			
			/*	FAILURE!!!!!!
				free the memory and tell the user they entered the wrong password. */
			FieldType *fld = GetObjectFromActiveForm (PasswordField);
			FrmCustomAlert (GenericError, STR_INCORRECT_PASSWORD, NULL, NULL);
			FldSetSelection (fld, 0, FldGetTextLength (fld));
			if (scratch) {
				MemSet (scratch, MemPtrSize (scratch), 0);
				MemPtrFree (scratch);
			}
		}
	} else {
		/*	null string is always wrong!!! */
		FrmCustomAlert (GenericError, STR_EMPTY_PASSWORD,NULL, NULL); 
		input = NULL;
	}
}


/*******************************************************************
 * Function: generatePasswordString
 * Description: this function will generate a new random password.
 * *****************************************************************/ 
static void generatePasswordString (UInt16 fieldID, Int16 length, Int16 type) {
	Char *p, *z;
	byte *r;
	//Char tmp;
	Char tmp[2];
	Int16 valids = 0;
	if ((p = MemPtrNew (length + 1)) && 
		(r = MemPtrNew (length * sizeof(UInt32))) &&
		(z = MemPtrNew (sizeof(alphas)+sizeof(numerics)+sizeof(metas)))) {
		Int16 i;

		StrCopy (z, STR_EMPTY);
		StrCopy (p, STR_EMPTY);

		/* build array of valid characters */
		switch (type) {
			case 0:
				StrCat (z, numerics);
				break;
			case 1:
				StrCat (z, alphas);
				StrCat (z, numerics);
				break;
			default:
				StrCat (z, metas);
				StrCat (z, numerics);
				StrCat (z, alphas);
				break;
		}
		valids = StrLen (z);

		/* Get randomness! */
		random_bytes(r, length*sizeof(UInt32));

		for (i = 0; i < length; i++) {
			MemSet (tmp, sizeof(tmp), 0);
			MemMove(tmp, z + (((UInt32) * &(r[i*sizeof(UInt32)])) % valids), sizeof(Char));
			//tmp = z[ ((UInt32) * &(r[i*sizeof(UInt32)])) % valids];
			StrCat (p, tmp);
		}

		setFieldFromString (fieldID, p);
		MemSet (p, length, 0);
		MemPtrFree (p);
		MemPtrFree (z);
		MemPtrFree (r);
	}
}


/*******************************************************************
 * Function: generatePw
 * Description: this function will pop up the password generation
 * dialog and optionally generate a new password.
 * 
 * question: convert generatepw to respond to frmsave/close events?  
 * what happens if switch app while in generate password form, should we 
 * save or just quit?  
 * 
 * *****************************************************************/
static void generatePw (UInt16 fieldID) {
	
	/*	get pointer to previous form and initalize the modal dialog */
	FormType *previousForm = FrmGetActiveForm ();
	FormType *frm = FrmInitForm (generatePassword);
	UInt16 button;
	ListType *list;
	Boolean generate = false;
	Int16 selected = 8, type = 2;
	Boolean n = false, a = false, m = false;
	
	/*	draw the form */
	FrmSetActiveForm (frm);
	list = GetObjectFromActiveForm (generatePasswordPopupList);
	LstSetSelection (list, prefs.pwLengthIndex);
	CtlSetLabel (GetObjectFromActiveForm (generatePasswordPopupTrigger),
		LstGetSelectionText (list, LstGetSelection (list)));
	switch (prefs.pwType) {
		case 0:
			CtlSetValue (GetObjectFromActiveForm (pwNum), true);
			break;
		case 1:
			CtlSetValue (GetObjectFromActiveForm (pwAlNum), true);
			break;
		case 2:
			CtlSetValue (GetObjectFromActiveForm (pwAlNumM), true);
			break;
		default:
			break;
	}
	FrmDrawForm (frm);
	
	/*	set event handler */
	FrmSetEventHandler (frm, generatePasswordHandleEvent);
	
	/*	handle the button click */
	button = FrmDoDialog (frm);
	list = GetObjectFromActiveForm (generatePasswordPopupList);
	selected = StrAToI (LstGetSelectionText (list, LstGetSelection (list)));
	if (selected < 4 || selected > 32)
		selected = 8;
	n = CtlGetValue (GetObjectFromActiveForm (pwNum));
	a = CtlGetValue (GetObjectFromActiveForm (pwAlNum));
	m = CtlGetValue (GetObjectFromActiveForm (pwAlNumM));
	if (n) type = 0;
	else if (a) type = 1;
	else if (m) type = 2;
	else type = 2;
	
	prefs.pwType = type;
	prefs.pwLengthIndex = LstGetSelection (list);
	if (button == generatePasswordOk)
		generate = true;
	else if (button == generatePasswordCancel) generate = false;
	
	FrmEraseForm (frm);
	FrmDeleteForm (frm);
	if (previousForm) {	
		/*	re-set the old form */
		FrmSetActiveForm (previousForm);
		if (generate) generatePasswordString (fieldID, selected, type);
	}
}


/*******************************************************************
 * Function: showPreferenceScreen
 * Description: this function will pop up the preference editing
 * dialog.
 * *****************************************************************/ 
static void showPreferenceScreen (void) {
	
	/*	get pointer to previous form and initalize the modal dialog */
	FormType *previousForm = FrmGetActiveForm ();
	FormType *frm = FrmInitForm (preferenceScreen);
	UInt16 button;
	
	/*	draw the form */
	FrmSetActiveForm (frm);
	FrmDrawForm (frm);
	
	/*	set event handler */
	
	FrmSetEventHandler (frm, preferencesHandleEvent);
	if (prefs.accountSort) CtlSetValue (GetObjectFromActiveForm (prSAN), true);
	else CtlSetValue (GetObjectFromActiveForm (prSAT), true);

	if (prefs.accountFirst) CtlSetValue (GetObjectFromActiveForm (prOAN), true);
	else CtlSetValue (GetObjectFromActiveForm (prOAT), true);

	if (prefs.autoLock) CtlSetValue (GetObjectFromActiveForm (poLock), true);

	if (prefs.smart_beaming) CtlSetValue (GetObjectFromActiveForm (prSB), true);
	
	/*	handle the button click */
	button = FrmDoDialog (frm);
	
	if (button == preferenceScreenOk) {
		Boolean tmp = CtlGetValue (GetObjectFromActiveForm (prSAN)), resort = false; 
		
		if (tmp != prefs.accountSort) resort = true;
		
		prefs.accountSort = tmp;
		prefs.accountFirst = CtlGetValue (GetObjectFromActiveForm (prOAN));
		prefs.autoLock = CtlGetValue (GetObjectFromActiveForm (poLock));
		prefs.smart_beaming = CtlGetValue (GetObjectFromActiveForm (prSB));
		
		if (resort) {
			FormType *preF = FrmGetActiveForm ();
			FormType *f = FrmInitForm (pleaseWait);
			FrmDrawForm (f);
			DmInsertionSort (AccountDB, (DmComparF *) CompareAccountFunction, 0); 
			FrmEraseForm (f);
			FrmDeleteForm (f);
			FrmSetActiveForm (preF);
		}
	}
	FrmEraseForm (frm);
	FrmDeleteForm (frm);
	if (previousForm) {
		/*	re-set the old form */
		FrmSetActiveForm (previousForm);
		changeForm (FrmGetActiveFormID ());
	}
}

/*******************************************************************
 * Function: editSystem
 * Description: this function is responsible for editing a system
 * record. It pops up a modal dialog which allows the user to 
 * modify the system name.
 * *****************************************************************/ 
static void editSystem (void) {
	
	/*	get pointer to previous form and initalize the modal dialog */
	FormType *previousForm = FrmGetActiveForm ();
	FormType *frm = FrmInitForm (EditSystemForm);
	UInt16 button;
	System sys;
	MemHandle rec;
	UInt16 recNum = selectedSystem, index2 = selectedSystem;
	
	/*	draw the form */
	FrmSetActiveForm (frm);
	FrmDrawForm (frm);
	
	/*	set event handler */
	FrmSetEventHandler (frm, EditSystemHandleEvent);
	
	/*	write the system name to the field */
	WriteEditableSystemInfoToScreen ();
	
	/*	handle the button click */
	button = FrmDoDialog (frm);
	
	if (button == editSystemOk) {
		/*	user accepted */
		sys.SystemID = currentSID;
		
		/*	compact text and get string pointer */
		FldCompactText (GetObjectFromActiveForm (EditSystemName));
		sys.name = FldGetTextPtr (GetObjectFromActiveForm (EditSystemName));
		
		if (sys.name && StrLen (sys.name) && StrCompare(sys.name, CurSys.name)) {
			
			/*	its a vaild name so we find the new sort position, and 
				re-write the record */
			index2 = DmFindSortPosition (SystemDB, &sys, 0,
				(DmComparF *) SortPosSystemFunction, 0);
			if ((rec = DmGetRecord (SystemDB, recNum))) {
				MemPtr scratch;
				if ((scratch = MemPtrNew (getSystemSize (&sys, true)))) {
					PackSystem (scratch, sys, &SysPass, true);
					writeRecord(scratch, rec);
					MemSet (scratch, MemPtrSize (scratch), 0);
					MemPtrFree (scratch);
				}
				DmReleaseRecord (SystemDB, recNum, true);
			}
			
			/*	move the record to its new position */
			DmMoveRecord (SystemDB, recNum, index2);
			if(index2 > recNum)
				setSystemForAccountForm(index2 - 1);
			else
				setSystemForAccountForm(index2);
		}
	}
	
	else if (button == DeleteSystem) {
		/*	the want to delete the system */
		deleteSystemFromDB();
		if(index2 != 0)
			setSystemForAccountForm(index2-1);
		else 
			setSystemForAccountForm(index2);
	}
	FrmEraseForm (frm);
	FrmDeleteForm (frm);
	if (previousForm) {
		/*	re-set the old form */
		FrmSetActiveForm (previousForm);
		AccountFormInit();
//	SystemFormInit ();
		LstDrawList (GetObjectFromActiveForm (accountList));
		FrmSetActiveForm (previousForm);
	}
}


/**********************************************************************
 * Function: editAccount
 * Description: this function is responsible for changing account 
 * information based upon the editited contents of the EditAccountForm
 * ********************************************************************/ 
static Boolean editAccount (void) {
	MemHandle rec;
	MemPtr scratch;
	char *pass_temp;
	
	/*	set up the popuptrigger list that allows the user
		to change the system an accont is linked to. */
	UInt16 index2 = 0;
	UInt16 index = getIndexOfNthAcct (AccountDB, currentSID, selectedAccount);
	UInt16 sysIdx = 0;
	ListType *list = GetObjectFromActiveForm (EditAccountPopupList);
	
	/*	compact the text fields */
	FldCompactText (GetObjectFromActiveForm (EditAccountUsername));
	FldCompactText (GetObjectFromActiveForm (EditAccountPassword));
	FldCompactText (GetObjectFromActiveForm (EditAccountType));
	FldCompactText (GetObjectFromActiveForm (EditAccountService));
	
	/*	get the new system ID and username */
	sysIdx = LstGetSelection (list);
	CurAcc.SystemID = getSIDForSystemIndex (SystemDB, sysIdx);
	CurAcc.username = FldGetTextPtr (GetObjectFromActiveForm (EditAccountUsername)); 
	CurAcc.account_mod_date = TimGetSeconds();
	
	if (!CurAcc.username || !StrLen (CurAcc.username)) {
		FrmCustomAlert (GenericError, STR_EMPTY_USERNAME, NULL, NULL); 
		return false;
	}
	
	/*	get the record to edit */
	rec = DmGetRecord (AccountDB, index);
	pass_temp = CurAcc.password;
	CurAcc.password = FldGetTextPtr (GetObjectFromActiveForm (EditAccountPassword)); 
	CurAcc.system = FldGetTextPtr (GetObjectFromActiveForm (EditAccountType)); 
	CurAcc.service = FldGetTextPtr (GetObjectFromActiveForm (EditAccountService)); 
	
	if (!CurAcc.password) CurAcc.password = emptyString;
	if (!CurAcc.system) CurAcc.system = emptyString; 
	if (!CurAcc.service) CurAcc.service = emptyString; 
	
	CurAcc.system_type=LstGetSelection(GetObjectFromActiveForm (eaSystemList));
	CurAcc.service_type=LstGetSelection(GetObjectFromActiveForm (eaServiceList));
	CurAcc.username_type=LstGetSelection(GetObjectFromActiveForm (eaLoginList));
	CurAcc.password_type=LstGetSelection(GetObjectFromActiveForm (eaPasswordList));

	/* if the password changed modify the password change date! */
	if (StrCompare(pass_temp, CurAcc.password)) CurAcc.password_mod_date = CurAcc.account_mod_date;	

	/*	lock the comment */
	CurAcc.comment = MemHandleLock (CurComment);

	index2 = DmFindSortPosition (AccountDB, &CurAcc, 0, (DmComparF *) SortPosAccountFunction, 0); 
	
	/* write out the new account to the database */
	if ((scratch = MemPtrNew (getAccountSize (&CurAcc, true)))) {
		PackAccount (scratch, CurAcc, &SysPass, true);
		if(rec) {
			writeRecord (scratch, rec);
			DmReleaseRecord (AccountDB, index, true);
			DmMoveRecord (AccountDB, index, index2);
		}
		MemSet (scratch, MemPtrSize (scratch), 0);
		MemPtrFree (scratch);
	}
	CurComment = freeHandle (CurComment);

	/* fix redraw if an account is moved from one category to another */
	setSystemForAccountForm(sysIdx);
	selectedAccount = getIndexForAccountID (AccountDB, currentSID, currentAID);
	return true;
}


/*************************************************************
 * Function: freeCurAcc
 * Description: function that resets the current account cache
 * this function will be called when the user cancels and
 * new or edit account reqest is cancelled.
 * Note: we must free the handle for the Current comment
 * ***********************************************************/ 
static void freeCurAcc (void) {
	CurAcc.SystemID = 0;
	CurAcc.AccountID = 0;
	CurAcc.username = NULL;
	CurAcc.password = NULL;
	CurComment = freeHandle (CurComment);
	CurAcc.comment = NULL;
}

/***********************************************************************
 * Function: createNewAccount
 * Description: this will get the information from the newAccountForm 
 * and creating and encrypting an account.
 * *********************************************************************/ 
static Boolean createNewAccount (void) {
	MemPtr scratch;
	MemHandle rec;
	UInt16 index = dmMaxRecordIndex;

	/*	get the systemID and a uniqe account id. */
	CurAcc.SystemID = currentSID;
	CurAcc.AccountID = getUniqueAccountID (AccountDB);
	
	/*	compact text */
	FldCompactText (GetObjectFromActiveForm (addAccountUsername));
	FldCompactText (GetObjectFromActiveForm (addAccountPassword));
	FldCompactText (GetObjectFromActiveForm (addAccountType));
	FldCompactText (GetObjectFromActiveForm (addAccountService));
	
	CurAcc.username = FldGetTextPtr (GetObjectFromActiveForm (addAccountUsername));

	/* FIXME if the user doenst enter a username then then they should be returned to the 
	 * screen */
	if (!CurAcc.username || !StrLen (CurAcc.username)) {
		FrmCustomAlert (GenericError, STR_EMPTY_USERNAME, NULL, NULL); 
		return false;
	}
	
	/*	get the account type password and comment */
	CurAcc.password = FldGetTextPtr (GetObjectFromActiveForm (addAccountPassword));
	CurAcc.system = FldGetTextPtr (GetObjectFromActiveForm (addAccountType));
	CurAcc.service = FldGetTextPtr (GetObjectFromActiveForm (addAccountService));
	if (!CurAcc.password) CurAcc.password = emptyString;
	if (!CurAcc.system) CurAcc.system = emptyString;
	if (!CurAcc.service) CurAcc.service = emptyString;

	CurAcc.comment = MemHandleLock (CurComment);

	CurAcc.system_type=LstGetSelection(GetObjectFromActiveForm (naSystemList));
	CurAcc.service_type=LstGetSelection(GetObjectFromActiveForm (naServiceList));
	CurAcc.username_type=LstGetSelection(GetObjectFromActiveForm (naLoginList));
	CurAcc.password_type=LstGetSelection(GetObjectFromActiveForm (naPasswordList));

	CurAcc.key=emptyString;
	CurAcc.series=99;
	CurAcc.hash_type=HASHTYPE_MD5;
	CurAcc.account_mod_date = TimGetSeconds();
	CurAcc.password_mod_date = CurAcc.account_mod_date;

	/* for now there is no binary data */
	CurAcc.binary_data_length=0;

	MemSet(CurAcc.hash, sizeof(md_hash), 0);
	MemMove(CurAcc.hash, generateAccountHash(&CurAcc), sizeof(md_hash));

	/*	get the sort position */
	index = DmFindSortPosition (AccountDB, &CurAcc, 0,
		(DmComparF *) SortPosAccountFunction, 0);

	if ((scratch = MemPtrNew (getAccountSize (&CurAcc, true)))) {
		PackAccount (scratch, CurAcc, &SysPass, true);
		if ((rec = DmNewRecord (AccountDB, &index, 1))) {			
			/*	add the account */
			writeRecord(scratch, rec);
			DmReleaseRecord (AccountDB, index, true);
		}
		MemSet (scratch, MemPtrSize (scratch), 0);
		MemPtrFree (scratch);
	}
	CurComment = freeHandle (CurComment);
	selectedAccount = getIndexForAccountID (AccountDB, currentSID, currentAID);		
//	AccountFormInit();
//	changeForm (StripAccountForm);
	return true;
}

/***************************************************************************
 * Function: WriteEditableSystemInfoToScreen
 * Description: writes the current system name to the EditSystem modal
 * dialog.
 * ************************************************************************/ 
	static void
WriteEditableSystemInfoToScreen (void) 
{
	UInt16 fldLen;
	FieldType *fld;
	
		// set the string value
		setFieldFromString (EditSystemName, CurSys.name);
	
		// set the insertion point to be the end of the string
		fld = GetObjectFromActiveForm (EditSystemName);
	fldLen = FldGetTextLength (fld);
	FldSetInsertionPoint (fld, fldLen);
	FrmSetFocus (FrmGetActiveForm (),
				  FrmGetObjectIndex (FrmGetActiveForm (), EditSystemName)); 
}


/**************************************************************************
 * Function: HandleClickInPopup
 * Description: Handles the selection process of clicking the system list
 * popup in the edit accout form
 * ***********************************************************************/ 
static void HandleClickInPopup (EventType *event) {
	System s;
	
		// get pointers to the relevent structures
	ListType *list = event->data.popSelect.listP;
	ControlType *c = event->data.popSelect.controlP;
	UInt16 selection = event->data.popSelect.selection;
	MemHandle scratch;
	if ((scratch = MemHandleNew (1))) {
		// re-set the label to the new selection
		getSystemFromIndex (SystemDB, &SysPass, selection, scratch, &s);
		LstSetSelection (list, selection);
		CtlSetLabel (c, (Char*) s.name);
		freeHandle (scratch);
	}
}

/****************************************************************************
 * Function: showCreateAccountForm
 * Description: sets up the newAccountForm, preps the CurComment handle 
 * and displays the newAccountForm
 * *************************************************************************/ 
	static void
showCreateAccountForm (void) 
{
	
		// get a new handle
		if ((CurComment = MemHandleNew (1)))
		
	{
		
			// set the string to null
			StrCopy (MemHandleLock (CurComment), STR_EOS);
		MemHandleUnlock (CurComment);
	}
	changeForm (makeNewAccount);
}


/***************************************************************************
 * Function: showEditAccountForm
 * Description: sets up the EditAccountForm , preps the handle and 
 * displays the EditAccountForm
 * *************************************************************************/ 
	static void
showEditAccountForm (void) 
{
	
		// if there is a comment, copy the comment into the new handle
		if (CurAcc.comment)
		
	{
		if ((CurComment = MemHandleNew (StrLen (CurAcc.comment) + 1)))
			StrCopy (MemHandleLock (CurComment), CurAcc.comment);
	}
	
		// otherwise set it to null string.
		else
		
	{
		if ((CurComment = MemHandleNew (1)))
			StrCopy (MemHandleLock (CurComment), STR_EOS);
	}
	MemHandleUnlock (CurComment);
	changeForm (EditAccountForm);
}


/****************************************************************************
 * Function: WriteEditableAccountInfoToScreen
 * Description: write the current account info into the editable boxes
 * *************************************************************************/ 
	static void
WriteEditableAccountInfoToScreen (void) 
{
	UInt16 fldLen;
	FieldType *fld;
	ListType *list;
	UInt16 numSys = DmNumRecordsInCategory (SystemDB, dmAllCategories);
	
	list = GetObjectFromActiveForm (EditAccountPopupList);
	LstSetDrawFunction (list, SystemListDrawFunction);
	/*	if there are less than 8 systems, set the list height to be
		the number of systems. If there are more than 8 systems a maximum
		of 8 will be shown at a time (without scrolling). */
	LstSetListChoices (list, NULL, numSys);

	if (numSys < 8) 
		LstSetHeight (list, DmNumRecordsInCategory (SystemDB, dmAllCategories)); 
	else
		LstSetHeight (list, 8);
	
		// get the popup, set the selection and label
	LstSetSelection (list, selectedSystem);
	CtlSetLabel (GetObjectFromActiveForm (EditAccountPopupTrigger),
				  CurSys.name); 

	/* set up the popuptrigger's for the fields */
	LstSetSelection(GetObjectFromActiveForm(eaSystemList),CurAcc.system_type);
	CtlSetLabel(GetObjectFromActiveForm(eaSystemTrigger),
			LstGetSelectionText(GetObjectFromActiveForm(eaSystemList),CurAcc.system_type));
	LstSetSelection(GetObjectFromActiveForm(eaServiceList),CurAcc.service_type);
	CtlSetLabel(GetObjectFromActiveForm(eaServiceTrigger),
			LstGetSelectionText(GetObjectFromActiveForm(eaServiceList),CurAcc.service_type));
	LstSetSelection(GetObjectFromActiveForm(eaLoginList),CurAcc.username_type);
	CtlSetLabel(GetObjectFromActiveForm(eaLoginTrigger),
			LstGetSelectionText(GetObjectFromActiveForm(eaLoginList),CurAcc.username_type));
	LstSetSelection(GetObjectFromActiveForm(eaPasswordList),CurAcc.password_type);
	CtlSetLabel(GetObjectFromActiveForm(eaPasswordTrigger),
			LstGetSelectionText(GetObjectFromActiveForm(eaPasswordList),CurAcc.password_type));

		// set up the fields 
	if (CurAcc.username)
		setFieldFromString (EditAccountUsername, CurAcc.username);
	if (CurAcc.password)
		setFieldFromString (EditAccountPassword, CurAcc.password);
	if (CurAcc.system)
		setFieldFromString (EditAccountType, CurAcc.system);
	if(CurAcc.service)
		setFieldFromString (EditAccountService, CurAcc.service);
	
		// grab focus after the last character of the username field
		fld = GetObjectFromActiveForm (EditAccountUsername);
	fldLen = FldGetTextLength (fld);
	FldSetInsertionPoint (fld, fldLen);
	FrmSetFocus (FrmGetActiveForm (),
				  FrmGetObjectIndex (FrmGetActiveForm (),

									 EditAccountUsername)); } 

/****************************************************************************
 * Function: WriteAccountInfoToScreen
 * Description: this function caches the selected account, 
 * and writes the accoutn info for the accout
 * *************************************************************************/ 
	static void
WriteAccountInfoToScreen (void) 
{

    FormType *editForm = FrmInitForm(EditAccountForm);

		// cache the account
	cacheAccount (getIndexOfNthAcct (AccountDB, currentSID, selectedAccount));
	if (StrLen (CurAcc.comment) != 0)
		objectVisible (AccountCommentButton, true);

	setFieldFromString (ShowAccountSystemName, CurSys.name);

	setFieldFromString (AccountTypeLabel,
  		LstGetSelectionText(FrmGetObjectPtr (editForm, 
			FrmGetObjectIndex (editForm, eaSystemList)),CurAcc.system_type));
	setFieldFromString (AccountServiceLabel,
  		LstGetSelectionText(FrmGetObjectPtr (editForm, 
			FrmGetObjectIndex (editForm, eaServiceList)),CurAcc.service_type));
	setFieldFromString (AccountUsernameLabel,
  		LstGetSelectionText(FrmGetObjectPtr (editForm, 
			FrmGetObjectIndex (editForm, eaLoginList)),CurAcc.username_type));
	setFieldFromString (AccountPasswordLabel,
  		LstGetSelectionText(FrmGetObjectPtr (editForm, 
			FrmGetObjectIndex (editForm, eaPasswordList)),CurAcc.password_type));

		// set up the fields
	if (CurAcc.username)
		setFieldFromString (AccountUsername, CurAcc.username);
	if (CurAcc.password)
		setFieldFromString (AccountPassword, CurAcc.password);
	if (CurAcc.system)
		setFieldFromString (AccountType, CurAcc.system);
	if (CurAcc.service)
		setFieldFromString (AccountService, CurAcc.service);

	FrmDeleteForm(editForm);
}


/********************************************************************
 * Function: EditSystemHandleEvent
 * Description: Event handler for the edit system and new system 
 * modal dialogs. basically a wrapper to HandleCommonMenues
 * ******************************************************************/ 
	static Boolean
EditSystemHandleEvent (EventType *event) 
{
	Boolean handled;
	//Char *p;
	
#ifdef __GNUC__
		SET_A4_FROM_A5 
#endif	/*  */
		handled = false;
	switch (event->eType)
		
	{
		case menuEvent:
			
				// handle menus
				handled = HandleCommonMenus (event->data.menu.itemID);
			break;
		
		case frmCloseEvent:
		/*	p = FldGetTextPtr (GetObjectFromActiveForm (EditSystemName));
			if (p)
				MemSet (p, StrLen (p), 0); */
			break;
		default:
			break;
	}
	
		RESTORE_A4 

		return (handled);
}

#ifdef WITH_REGISTER
/********************************************************************
 * Function: RegisterHandleEvent
 * Description: Event handler for the new register screen
 * ******************************************************************/ 
	static Boolean
RegisterHandleEvent (EventType *event) 
{
	Boolean handled;
	//Char *p;
	
#ifdef __GNUC__
		SET_A4_FROM_A5 
#endif	/*  */
		handled = false;
	switch (event->eType)
	{
		case menuEvent:
				// handle menus
				handled = HandleCommonMenus (event->data.menu.itemID);
			break;
		default:
			break;
	}
		RESTORE_A4 

		return (handled);
}
#endif

/********************************************************************
 * Function: AddSystemHandleEvent
 * Description: Event handler for the edit system and new system 
 * modal dialogs. basically a wrapper to HandleCommonMenues
 * ******************************************************************/ 
	static Boolean
AddSystemHandleEvent (EventType *event) 
{
	Boolean handled;
	//Char *p;
	
		SET_A4_FROM_A5 

		handled = false;
	switch (event->eType)
		
	{
		case menuEvent:
			
				// handle menus
				handled = HandleCommonMenus (event->data.menu.itemID);
			break;
		case frmCloseEvent:
		/*	p = FldGetTextPtr (GetObjectFromActiveForm (addSystemName));
			if (p)
				MemSet (p, StrLen (p), 0); */
			break;
		default:
			break;
	}
	
		RESTORE_A4 

		return (handled);
}


/**************************************************************************
 * Function: EditCommentHandleEvent
 * Description: event handler for the editComment screen. Specifically
 * handles the scrolling of the text
 * 
 * added to by bret musser, 2/19/2001, to work as a form, not a dialog
 * and thus able to respond to poweroff and stopapp
 * ***********************************************************************/ 
	static Boolean
EditCommentHandleEvent (EventType *event) 
{
	FieldType *fld;
	UInt16 fldLen;
	Boolean handled;
	UInt16 c;
	FormPtr frm;
	
	SET_A4_FROM_A5 
	  
	handled = false;
	switch (event->eType) {
		
	 case keyDownEvent:
		// handle up and down button keys, and scroll the list
		c = event->data.keyDown.chr;
		if (c == pageUpChr)
		  PageScroll (winUp, EditAccountComment, EditAccountScrollbar);
		else if (c == pageDownChr)
		  PageScroll (winDown, EditAccountComment, EditAccountScrollbar);
		break;
		
	 case ctlSelectEvent:
		// deal with buttons
		switch (event->data.ctlSelect.controlID) {
		 case EditCommentOk:
			frm = FrmGetActiveForm ();
			if(EditCommentYes == 1) {
				// prevent the text handle from being freed on closing the form
				// else curcomment will be freed
				fld = GetObjectFromActiveForm (EditAccountComment);
				FldSetTextHandle(fld, NULL); 
				FldCompactText(fld);
			}
			FrmReturnToForm(0); // goes to previous form
			handled = true;
			break;
		 default:
			break;
		}
		break;
  
		
	 case fldChangedEvent:
		// if the field height changes
		UpdateScrollbar (EditAccountComment, EditAccountScrollbar);
		handled = true;
		break;
	 case sclRepeatEvent:
		// if the user hold down the scroll button..
		ScrollLines (event->data.sclRepeat.newValue - event->data.sclRepeat.value, 
			     false, EditAccountComment, EditAccountScrollbar);
		break;
	 case menuEvent:
		// handle menus
		handled = HandleCommonMenus (event->data.menu.itemID);
		break;
		
	 case frmOpenEvent: 
		// get the comment and set the handle.
		frm = FrmGetActiveForm ();
		FrmDrawForm(frm);
		if(EditCommentYes == 1) { 
			// if we are editing a new comment, use handle CurComment (a global var)
			// and set editable 
			SetAttributes (1, 1, 1, true, EditAccountComment);
			setFieldFromHandle (EditAccountComment, CurComment);
		} else {
			// if we're viewing a comment, set text from account's comment text
			// and make sure not editable
			SetAttributes (0, 0, 1, true, EditAccountComment);
			if (CurAcc.comment) setFieldFromString (EditAccountComment, CurAcc.comment);
		}
		
		// set the insertion point after the last character of the comment
		fld = GetObjectFromActiveForm (EditAccountComment);
		fldLen = FldGetTextLength (fld);
		FldSetInsertionPoint (fld, fldLen);
		FrmSetFocus (frm, FrmGetObjectIndex (frm, EditAccountComment));
		UpdateScrollbar (EditAccountComment, EditAccountScrollbar);
		handled = true;
		break;
		
	 case frmSaveEvent:
		if(EditCommentYes == 1) {
			// prevent the text handle from being freed on closing the form
			// else curcomment will be freed
			fld = GetObjectFromActiveForm (EditAccountComment);
			FldSetTextHandle(fld, NULL); 
			FldCompactText (fld);
		}
		// fall through
	 case frmCloseEvent:
		// handled = true;
		break;
		
	 default:
		break;
	}
	
	RESTORE_A4 
	  
	return (handled);
}


/**********************************************************************
 * Function: generatePasswordHandleEvent
 * Description: this function handles the events for the generatePassord
 * screen.
 * *******************************************************************/ 
	static Boolean
generatePasswordHandleEvent (EventType *event) 
{
	Boolean handled, tmp;
	
		SET_A4_FROM_A5 

		handled = false;
	switch (event->eType)
		
	{
		case ctlSelectEvent:
			switch (event->data.ctlSelect.controlID)
				
			{
				case pwNum:
					tmp = CtlGetValue (GetObjectFromActiveForm (pwNum));
					if (tmp)
						
					{
						CtlSetValue (GetObjectFromActiveForm (pwAlNum),
									  false);
							CtlSetValue (GetObjectFromActiveForm (pwAlNumM),
										  false); }
					
					else
						
					{
						CtlSetValue (GetObjectFromActiveForm (pwAlNum),
									  true);
							CtlSetValue (GetObjectFromActiveForm (pwAlNumM),
										  false); }
					handled = true;
					break;
				case pwAlNum:
					tmp = CtlGetValue (GetObjectFromActiveForm (pwAlNum));
					if (tmp)
						
					{
						CtlSetValue (GetObjectFromActiveForm (pwNum), false);
						CtlSetValue (GetObjectFromActiveForm (pwAlNumM),
									  false); }
					
					else
						
					{
						CtlSetValue (GetObjectFromActiveForm (pwAlNumM),
									  true);
							CtlSetValue (GetObjectFromActiveForm (pwNum),
										  false); }
					handled = true;
					break;
				case pwAlNumM:
					tmp = CtlGetValue (GetObjectFromActiveForm (pwAlNumM));
					if (tmp)
						
					{
						CtlSetValue (GetObjectFromActiveForm (pwNum), false);
						CtlSetValue (GetObjectFromActiveForm (pwAlNum),
									  false); }
					
					else
						
					{
						CtlSetValue (GetObjectFromActiveForm (pwNum), true);
						CtlSetValue (GetObjectFromActiveForm (pwAlNum),
									  false); }
					handled = true;
					break;
				default:
					break;
			}
			break;
		default:
			break;
	}
	
		RESTORE_A4 

		return (handled);
}


/**********************************************************************
 * Function: preferencesHandleEvent
 * Description: this function handles the events for the preferences
 * screen.
 * *******************************************************************/ 
	static Boolean
preferencesHandleEvent (EventType *event) 
{
	Boolean handled, tmp;
	
		SET_A4_FROM_A5 

		handled = false;
	switch (event->eType)
		
	{
		case ctlSelectEvent:
			switch (event->data.ctlSelect.controlID)
				
			{
				case prSAN:
					tmp = CtlGetValue (GetObjectFromActiveForm (prSAN));
					if (tmp)
						CtlSetValue (GetObjectFromActiveForm (prSAT), false);
					
					else
						CtlSetValue (GetObjectFromActiveForm (prSAT), true);
					handled = true;
					break;
				case prSAT:
					tmp = CtlGetValue (GetObjectFromActiveForm (prSAT));
					if (tmp)
						CtlSetValue (GetObjectFromActiveForm (prSAN), false);
					
					else
						CtlSetValue (GetObjectFromActiveForm (prSAN), true);
					handled = true;
					break;
				case prOAN:
					tmp = CtlGetValue (GetObjectFromActiveForm (prOAN));
					if (tmp)
						CtlSetValue (GetObjectFromActiveForm (prOAT), false);
					
					else
						CtlSetValue (GetObjectFromActiveForm (prOAT), true);
					handled = true;
					break;
				case prOAT:
					tmp = CtlGetValue (GetObjectFromActiveForm (prOAT));
					if (tmp)
						CtlSetValue (GetObjectFromActiveForm (prOAN), false);
					
					else
						CtlSetValue (GetObjectFromActiveForm (prOAN), true);
					handled = true;
					break;
				default:
					break;
			}
			break;
		default:
			break;
	}
	
		RESTORE_A4 

		return (handled);
}


/**********************************************************************
 * Function: ChangePasswordHandleEvent
 * Description: this function handles the events for the changePassord
 * screen.
 * *******************************************************************/ 
	static Boolean
ChangePasswordHandleEvent (EventType *event) 
{
	Boolean handled;
	//Char *p;
	
		SET_A4_FROM_A5 

		handled = false;
	switch (event->eType)
		
	{
		case ctlSelectEvent:
			switch (event->data.ctlSelect.controlID)
				
			{
					
						// if they accept the changes, sanity check them and accept
				case ChangePasswordOk:
					changePassword ();
					break;
					
						// just change to the last form if they cancel
				case ChangePasswordCancel:
					changeForm (oldForm);
					break;
				default:
					break;
			}
			handled = true;
			break;
			
				// draw form and set focus in the first field
		case frmOpenEvent:
			FrmDrawForm (FrmGetActiveForm ());
			FrmSetFocus (FrmGetActiveForm (),
						  FrmGetObjectIndex (FrmGetActiveForm (),
											 ChangePasswordCurrentField));
				handled = true;
			break;
			
				// handle menu events
		case menuEvent:
			handled = HandleCommonMenus (event->data.menu.itemID);
			break;
		case frmCloseEvent:
		// don't save if get a random close
		
		/*	p =
				FldGetTextPtr (GetObjectFromActiveForm
							   (ChangePasswordCurrentField));
				if (p) MemSet (p, StrLen (p), 0);
			p =
				FldGetTextPtr (GetObjectFromActiveForm
							   (ChangePasswordNewField));
				if (p) MemSet (p, StrLen (p), 0);
			p =
				FldGetTextPtr (GetObjectFromActiveForm (ChangePasswordField));
				if (p) MemSet (p, StrLen (p), 0); */
			break;
		default:
			break;
	}
	
		RESTORE_A4 

		return (handled);
}

/**********************************************************************
 * Function: UpdatePasswordScrollers
 * Description: this function sets the scroll arrows for the 
 *              password field
 * *******************************************************************/ 
static void UpdatePasswordScrollers(void)
{
	FieldType *fld = (FieldType*) GetObjectFromActiveForm(PasswordField);

	if(FldScrollable(fld, winUp))
		CtlSetLabel(GetObjectFromActiveForm(PasswordUp), "\010"); // UP
	else
		CtlSetLabel(GetObjectFromActiveForm(PasswordUp), "\022"); // NONE

	if(FldScrollable(fld, winDown))
		CtlSetLabel(GetObjectFromActiveForm(PasswordDown), "\007"); // DOWN
	else
		CtlSetLabel(GetObjectFromActiveForm(PasswordDown), "\022"); // NONE
}

/****************************************************************************
 * Function: PasswordHandleEvent
 * Description: callback function that handles events for the form that
 * checks the password to login to the program. We accomplish an "echo-off" 
 * mode by changing the font to symbol11 writing 'box' characters instead 
 * of text. 
 * ************************************************************************/ 
static Boolean
PasswordHandleEvent (EventType *event) 
{
	FieldType *fld;
	FontID fontID;
	Boolean handled;
#ifdef WITH_REGISTER
	Int16 reg;	
#endif
	SET_A4_FROM_A5 

	fld = (FieldType*) GetObjectFromActiveForm(PasswordField);
	handled = false;


	switch (event->eType)
		
	{
		case menuCmdBarOpenEvent:
			handled = true;
			break;

		case ctlSelectEvent:
			switch (event->data.ctlSelect.controlID)
			{
					
				// they clicked ok, so check the password
				case PasswordOk:
					checkPassword ();
					handled = true;
					break;
					
				// they want to change the echo status
				case EchoOffCheckbox:
					
					// get the value of the checkbox
					prefs.echoOff =
					CtlGetValue (GetObjectFromActiveForm
								 (EchoOffCheckbox)); 
					// set the appropriate font
					if (prefs.echoOff)
						fontID = symbol11Font; 
					else
						fontID = stdFont;

					FldSetFont(fld, fontID); 
					UpdatePasswordScrollers();
					handled = true;
					break;

				case PasswordUp:
					if(FldScrollable(fld, winUp))
						FldScrollField(fld, 1, winUp);
					UpdatePasswordScrollers();
					break;

				case PasswordDown:
					if(FldScrollable(fld, winDown))
						FldScrollField(fld, 1, winDown);
					UpdatePasswordScrollers();
					break;

				default:
					break;
			}
			break;

		case keyDownEvent:
			switch(event->data.keyDown.chr) {
			case pageUpChr:
				if(FldScrollable(fld, winUp))
					FldScrollField(fld, 1, winUp);
				UpdatePasswordScrollers();
				break;

			case pageDownChr:
				if(FldScrollable(fld, winDown))
					FldScrollField(fld, 1, winDown);
				UpdatePasswordScrollers();
				break;
			}
			break;

		case fldChangedEvent:
				UpdatePasswordScrollers();
				break;

		case frmOpenEvent:
			authenticated = false;
		
			// set the attributes so that the fields are underlined
			SetAttributes (1, 1, 1, true, PasswordField);
			/* This is a hack fix it */
			if (prefs.echoOff) {
				fontID = symbol11Font; 
				FldSetFont(fld, fontID); 
			}	
			// set the default password echo to be the last value of prefs.echoOff
			CtlSetValue (GetObjectFromActiveForm (EchoOffCheckbox),
						 prefs.echoOff);
			FrmDrawForm (FrmGetActiveForm ());
			UpdatePasswordScrollers();
			FrmSetFocus (FrmGetActiveForm (), FrmGetObjectIndex (FrmGetActiveForm (),
					 PasswordField)); 
			// if its the first run, pop up a dialog letting them know that the password they choose will be
			// the one that they get
			if (firstRun)
				FrmCustomAlert (GenericError, STR_FIRSTTIME, NULL, NULL); 

#ifdef WITH_REGISTER
			reg = isValidReg();
			if (!firstRun && (reg == REG_INVALID)) {
				warnRegistration();
				registerForm();
			} else if (reg == REG_EVAL) {
				warnRegistration();
			}
#endif		
			handled = true;
			break;
			
				// handle menu events
		case menuEvent:
			handled = HandleCommonMenus (event->data.menu.itemID);
			break;
			
		default:
			break;
	}
	RESTORE_A4 

	return (handled);
}


/*********************************************************************
 * Function: editAccountHandleEvent
 * Description: callback event handler for the edit account form
 * 
 * code to switch next/prev field added by bret musser 2/19/2001
 * *******************************************************************/ 
	static Boolean
editAccountHandleEvent (EventType *event) 
{
	FormType *frm;
	UInt16 currobj, nextobj;
	Boolean handled;
	Boolean ok;
	
		SET_A4_FROM_A5 

		handled = false;
	switch (event->eType) {
	 case keyDownEvent:
		switch(event->data.keyDown.chr) {
		 case vchrNextField:
			frm = FrmGetActiveForm ();
			if(noFocus == FrmGetFocus(frm)) {
				// set focus to first field
				nextobj = EditAccountType; 
			} else {
				currobj = FrmGetObjectId(frm, FrmGetFocus(frm));
				switch(currobj) {
				 case EditAccountType:
					nextobj = EditAccountService;
					break;
				 case EditAccountService:
					nextobj = EditAccountUsername;
					break;
				 case EditAccountUsername:
					nextobj = EditAccountPassword;
					break;
				 case EditAccountPassword:
					nextobj = EditAccountType;
					break;
				 default:
					nextobj = EditAccountType;
					break;
				}
			}
			FrmSetFocus(frm, FrmGetObjectIndex(frm, nextobj));
			break;
		 case vchrPrevField:
			frm = FrmGetActiveForm ();
			if(noFocus == FrmGetFocus(frm)) {
				// set focus to first field
				nextobj = EditAccountType; 
			} else {
				currobj = FrmGetObjectId(frm, FrmGetFocus(frm));
				switch(currobj) {
				 case EditAccountType:
					nextobj = EditAccountPassword;
					break;
				 case EditAccountService:
					nextobj = EditAccountType;
					break;
				 case EditAccountUsername:
					nextobj = EditAccountService;
					break;
				 case EditAccountPassword:
					nextobj = EditAccountUsername;
					break;
				 default:
					nextobj = EditAccountType;
					break;
				}
			}
			FrmSetFocus(frm, FrmGetObjectIndex(frm, nextobj));					
			break;
		}
		break;
		
	 case ctlSelectEvent:
		switch (event->data.ctlSelect.controlID)
				
			{
					
						// if they cancel, free the cache and change forms
				case editAccountCancel:
					freeCurAcc ();
					changeForm (ShowAccount);
					handled = true;
					break;
					
						// they accept the work, so commit it
				case editAccountOk:
					ok = editAccount();
					if(ok)
						changeForm (StripAccountForm);
					handled = true;
					break;
					
						// they want to edit the comment, so goto that form
			        case EditAccountCommentButton: 
					// editComment (EditAccountForm), removed bjm 2/19/01
					EditCommentYes = 1;
					FrmPopupForm(EditAccountCommentForm);
					handled = true;
					break;
					
						// they want to delete it, so kiss it goodby
				case DeleteAccount:
					deleteAccountFromDB ();
					handled = true;
					break;
				case generatePWButton:
					generatePw (EditAccountPassword);
					handled = true;
					break;
					
				case eaSystemTrigger:
				case eaLoginTrigger:
				case eaServiceTrigger:
				case eaPasswordTrigger:
				default:
					handled = false;
					break;
			}
			break;

//			 they selected a new system, so handle the click in the popup
		case popSelectEvent:
			if(event->data.popSelect.controlID == EditAccountPopupTrigger) {
				HandleClickInPopup (event);
				handled = true;
			}
			break; 

		case fldChangedEvent:
			
				// if the field height changes
				UpdateScrollbar (EditAccountPassword,
								 EditAccountPasswordScrollbar);
				handled = true; break;
		case sclRepeatEvent:
			
				// if the user hold down the scroll button..
				ScrollLines (event->data.sclRepeat.newValue -
							 event->data.sclRepeat.value, false,
							 EditAccountPassword,
							 EditAccountPasswordScrollbar); break;
			
				// when it opens, draw the form and write out the info
		case frmOpenEvent:
			FrmDrawForm (FrmGetActiveForm ());
			SetAttributes (1, 1, 1, true, EditAccountPassword);
			WriteEditableAccountInfoToScreen ();
			UpdateScrollbar (EditAccountPassword,
							  EditAccountPasswordScrollbar); handled = true;
			break;
	 case menuEvent:
		switch(event->data.menu.itemID) {
		 case EditAddNote:
			EditCommentYes = 1;
			FrmPopupForm(EditAccountCommentForm);
			handled = true;
			break;
		 case EditGenPW:
			generatePw (EditAccountPassword);
			handled = true;
			break;
		 default:
			handled = HandleCommonMenus (event->data.menu.itemID);
			break;
		}
		break;
	 case frmUpdateEvent:
		// needed to redraw form when returning from notes
		// note: if make this more complicated, must also handle redraw update code
		frm = FrmGetActiveForm ();
		FrmDrawForm(frm);
		handled = true;
		break;
		
	 case frmSaveEvent:
		editAccount (); // xxx to save on random closes of forms, need to check this
		handled = true;
		break;
		
	 case frmCloseEvent:
		/*	p =
				FldGetTextPtr (GetObjectFromActiveForm (EditAccountUsername));
				if (p) MemSet (p, StrLen (p), 0);
			p =
				FldGetTextPtr (GetObjectFromActiveForm (EditAccountPassword));
				if (p) MemSet (p, StrLen (p), 0);
			p = FldGetTextPtr (GetObjectFromActiveForm (EditAccountType));
			if (p)
				MemSet (p, StrLen (p), 0); */
		// handled = true;
		break;
		
	 default:
		break;
	}
	
		RESTORE_A4 

		return (handled);
}


/********************************************************************
 * Function: showAccountHandleEvent
 * Description: callback event handler for the form that displays the
 * account information
 * *****************************************************************/ 
	static Boolean
showAccountHandleEvent (EventType *event) 
{
	Boolean handled;
	//Char *p;
	
		SET_A4_FROM_A5 

		handled = false;
	switch (event->eType)
		
	{
			
				// power stroke can cause this behavior if the 
				// user has their preferences set up to 
				// beam on power stroke. anyway- beam the account
		case keyDownEvent:
#ifndef DEBUG
			if (event->data.keyDown.chr == sendDataChr)
				BeamAccount (getIndexOfNthAcct (AccountDB, currentSID, selectedAccount));
#endif
			break;
		case ctlSelectEvent:
			switch (event->data.ctlSelect.controlID)
				
			{
					
						// switch forms
				case AccountClose:
					changeForm (StripAccountForm);
					break;
					
					// Calculate a S/Key phrase
			    case AccountSKey:
					changeForm (StripSKeyForm);
					break;
					
						// show this accouts comment
				case AccountCommentButton:
					EditCommentYes = 0;
				        FrmPopupForm(EditAccountCommentForm);
				        // showComment ();
					break;
					
						// edit this account
				case EditAccount:
					showEditAccountForm ();
					break;
				default:
					break;
			}
			handled = true;
			break;
			
				// write the account info to the screen and then draw it.
		case frmOpenEvent:
			FrmDrawForm (FrmGetActiveForm ());
			SetAttributes (0, 0, 1, true, AccountPassword);
			WriteAccountInfoToScreen ();
			UpdateScrollbar (AccountPassword, AccountPasswordScrollbar);
			handled = true;
			break;
		case fldChangedEvent:
			
				// if the field height changes
			UpdateScrollbar (AccountPassword, AccountPasswordScrollbar);
			handled = true;
		        break;
		case sclRepeatEvent:
			
				// if the user hold down the scroll button..
				ScrollLines (event->data.sclRepeat.newValue -
							 event->data.sclRepeat.value, false,
							 AccountPassword, AccountPasswordScrollbar);
			break;
		case menuEvent:
			handled = HandleCommonMenus (event->data.menu.itemID);
			break;
		case frmCloseEvent:
		/*	p =
				FldGetTextPtr (GetObjectFromActiveForm
							   (ShowAccountSystemName));
				if (p) MemSet (p, StrLen (p), 0);
			p = FldGetTextPtr (GetObjectFromActiveForm (AccountUsername));
			if (p)
				MemSet (p, StrLen (p), 0);
			p = FldGetTextPtr (GetObjectFromActiveForm (AccountPassword));
			if (p)
				MemSet (p, StrLen (p), 0);
			p = FldGetTextPtr (GetObjectFromActiveForm (AccountType));
			if (p)
				MemSet (p, StrLen (p), 0); */
			objectVisible (AccountCommentButton, false);
			break;
		default:
			break;
	}
	
		RESTORE_A4 

		return (handled);
}


/*********************************************************************
 * Function: newAccountHandleEvent
 * Description: event handler for the new account creation screen
 * *******************************************************************/ 
	static Boolean
newAccountHandleEvent (EventType *event) 
{
	FormType *frm;
	UInt16 currobj, nextobj;
	Boolean handled;
	Boolean ok;
	//Char *p;
	
	SET_A4_FROM_A5 
	handled = false;
	switch (event->eType) {
	 case keyDownEvent:
		switch(event->data.keyDown.chr) {
		 case vchrNextField:
			frm = FrmGetActiveForm ();
			if(noFocus == FrmGetFocus(frm)) {
				// set focus to first field
				nextobj = addAccountType; 
			} else {
				currobj = FrmGetObjectId(frm, FrmGetFocus(frm));
				switch(currobj) {
				 case addAccountType:
					nextobj = addAccountService;
					break;
				 case addAccountService:
					nextobj = addAccountUsername;
					break;
				 case addAccountUsername:
					nextobj = addAccountPassword;
					break;
				 case addAccountPassword:
					nextobj = addAccountType;
					break;
				 default:
					nextobj = addAccountType;
					break;
				}
			}
			FrmSetFocus(frm, FrmGetObjectIndex(frm, nextobj));
			break;
		 case vchrPrevField:
			frm = FrmGetActiveForm ();
			if(noFocus == FrmGetFocus(frm)) {
				// set focus to first field
				nextobj = addAccountType; 
			} else {
				currobj = FrmGetObjectId(frm, FrmGetFocus(frm));
				switch(currobj) {
				 case addAccountType:
					nextobj = addAccountPassword;
					break;
				 case addAccountService:
					nextobj = addAccountType;
					break;
				 case addAccountUsername:
					nextobj = addAccountService;
					break;
				 case addAccountPassword:
					nextobj = addAccountUsername;
					break;
				 default:
					nextobj = addAccountType;
					break;
				}
			}
			FrmSetFocus(frm, FrmGetObjectIndex(frm, nextobj));					
			break;
		}
		break;
		
		
		case ctlSelectEvent:
			switch (event->data.ctlSelect.controlID)
				
			{
					
						// they accept the info, so add the account
				case addAccountOk:
					ok = createNewAccount();
					if(ok)
				        changeForm (StripAccountForm);				

					handled = true;
					break;
					
						// add a comment
				case AddAccountCommentButton:
					// editComment (makeNewAccount);
					EditCommentYes = 1;
					FrmPopupForm(EditAccountCommentForm);
					handled = true;
					break;
					
						// cancel, so free the cache and change back to 
						// the previous form
				case addAccountCancel:
					freeCurAcc ();
					changeForm (StripAccountForm);
					handled = true;
					break;
				case generatePWButton:
					generatePw (addAccountPassword);
					handled = true;
					break;

				case naSystemTrigger:
				case naLoginTrigger:
				case naServiceTrigger:
				case naPasswordTrigger:
				default:
					break;
			}
			break;
			
				// form open, draw the form and set the focus to the
				// first field
		case frmOpenEvent:
			FrmDrawForm (FrmGetActiveForm ());
			SetAttributes (1, 1, 1, true, addAccountPassword);
			FrmSetFocus (FrmGetActiveForm (),
						  FrmGetObjectIndex (FrmGetActiveForm (),
											 addAccountType));
			handled = true; 
			break;
		case fldChangedEvent:
			
				// if the field height changes
				UpdateScrollbar (addAccountPassword,
								 addAccountPasswordScrollbar);
				handled = true; break;
		case sclRepeatEvent:
			
				// if the user hold down the scroll button..
				ScrollLines (event->data.sclRepeat.newValue -
							 event->data.sclRepeat.value, false,
							 addAccountPassword,
							 addAccountPasswordScrollbar); break;
	 case menuEvent:
		switch(event->data.menu.itemID) {
		 case EditAddNote:
			EditCommentYes = 1;
			FrmPopupForm(EditAccountCommentForm);
			handled = true;
			break;
		 case EditGenPW:
			generatePw (addAccountPassword);
			handled = true;
			break;
		 default:
			handled = HandleCommonMenus (event->data.menu.itemID);
			break;
		}
		break;
		
		
	 case frmSaveEvent:
		createNewAccount();
		handled = true;
		
	 case frmUpdateEvent:
		// needed to redraw form when returning from notes
		// note: if make this more complicated, must also handle redraw update code
		frm = FrmGetActiveForm ();
		FrmDrawForm(frm);
		handled = true;
		break;
		
	 case frmCloseEvent:
		/*	p = FldGetTextPtr (GetObjectFromActiveForm (addAccountUsername));
			if (p)
				MemSet (p, StrLen (p), 0);
			p = FldGetTextPtr (GetObjectFromActiveForm (addAccountPassword));
			if (p)
				MemSet (p, StrLen (p), 0);
			p = FldGetTextPtr (GetObjectFromActiveForm (addAccountType));
			if (p)
				MemSet (p, StrLen (p), 0); */
		// handled = true;
		break;
		
	 default:
		break;
	}
	
		RESTORE_A4 

		return (handled);
}

/********************************************************************
 * Function: skeyHandleEvent
 * Description: callback event handler for the form that displays the
 * skey challenge
 * *****************************************************************/
static Boolean skeyHandleEvent(EventType *event)
{
    Boolean     handled;
    Char *pkey;
    MemHandle rec;
    int series, hashtype;
    MemPtr scratch;
    static char key[8];
	
    SET_A4_FROM_A5;

    handled = false;
    switch (event->eType)
		{
			/* power stroke can cause this behavior if the 
			 * user has their preferences set up to 
			 * beam on power stroke. anyway- beam the account
			 */
        case keyDownEvent:
#ifndef DEBUG
            if(event->data.keyDown.chr==sendDataChr)
                BeamAccount(getIndexOfNthAcct(AccountDB, currentSID, selectedAccount));
#endif
            break;
			
        case ctlSelectEvent:
			handled=true;
            switch(event->data.ctlSelect.controlID)
				{
                case SKeyDone:
					/* pack and save... */
					FldCompactText(GetObjectFromActiveForm(SKeyKey));
					FldCompactText(GetObjectFromActiveForm(SKeySeries));
					
					CurAcc.key=FldGetTextPtr(GetObjectFromActiveForm(SKeyKey));
					CurAcc.series=StrAToI(FldGetTextPtr(GetObjectFromActiveForm(SKeySeries))) - 1;
					CurAcc.hash_type=LstGetSelection(GetObjectFromActiveForm(SKeyHashList));
					
					if(CurAcc.series == -1)
						CurAcc.series=99;
					
					if(!CurAcc.key)
						CurAcc.key = emptyString;
					
					rec=DmGetRecord(AccountDB, getIndexOfNthAcct(AccountDB, currentSID, selectedAccount));
					
					if((scratch=MemPtrNew(getAccountSize(&CurAcc,true))) != NULL) {
						PackAccount(scratch, CurAcc, &SysPass, true);
						if(rec) {
							writeRecord(scratch,rec);
							DmReleaseRecord(AccountDB,getIndexOfNthAcct(AccountDB, currentSID, selectedAccount),true);
						}
						MemSet(scratch,MemPtrSize(scratch),0);
						MemPtrFree(scratch);
					}

					/* Fall through */

				case SKeyCancel:
                    changeForm(ShowAccount);
                    break;
					
				case SKeyHashTrigger:
					// Use the default handler
					handled=false;
					break;
					
				case SKeyCalc:
					series=StrAToI(FldGetTextPtr(GetObjectFromActiveForm(SKeySeries)));
					pkey=FldGetTextPtr(GetObjectFromActiveForm(SKeyKey));
					hashtype=LstGetSelection(GetObjectFromActiveForm(SKeyHashList));
					
					if(get_key(series,pkey,CurAcc.password,(char*)&key,hashtype)) {
						setFieldFromString(SKeyResponse,btoe((char*)&key));
						setFieldFromString(SKeyHex,btoh((char*)&key));
					} else {
						setFieldFromString(SKeyResponse,"Error");
					}
                    break;
				}
            break;
			
        case frmOpenEvent:  
            FrmDrawForm(FrmGetActiveForm());
			if(!dict_open()) {
				FrmCustomAlert(GenericError,"OTP database not installed",NULL,NULL);
			}
			
			/* Set hash type, sequence, and key from account */
			if(CurAcc.series > 9999)
				CurAcc.series=9999;
			if(CurAcc.series < 0)
				CurAcc.series=0;
			
			StrPrintF(key,"%d",CurAcc.series);
			setFieldFromString(SKeySeries,key);
			setFieldFromString(SKeyKey,CurAcc.key);
			LstSetSelection(GetObjectFromActiveForm(SKeyHashList),CurAcc.hash_type);
			CtlSetLabel(GetObjectFromActiveForm(SKeyHashTrigger),
						LstGetSelectionText(GetObjectFromActiveForm(SKeyHashList),CurAcc.hash_type));
			
            handled = true;
            break;
            
        case menuEvent:     
            handled=HandleCommonMenus(event->data.menu.itemID);
            break;
			
		case frmCloseEvent:
			dict_close();
            break;

		default:
			break;
		}
    RESTORE_A4;

    return(handled);
}

/********************************************************************
 * Function: createNewSystem
 * Description: this function will pop up the modal dialog and collect
 * the information to create a new system/category
 * ******************************************************************/ 
	static void
createNewSystem (void) 
{
	
		// save the old form and initialize the new one
	FormType *previousForm = FrmGetActiveForm ();
	FormType *frm = FrmInitForm (makeNewSystem);
	UInt16 button;
	System sys;
	MemHandle rec;
	UInt16 index = selectedSystem;
	
		// set active form, draw it
		FrmSetActiveForm (frm);
	FrmDrawForm (frm);
	
		// set the event handler and set the focus
		FrmSetEventHandler (frm, AddSystemHandleEvent);
	FrmSetFocus (frm, FrmGetObjectIndex (frm, addSystemName));
	button = FrmDoDialog (frm);
	if (button == addSystemOk)
		
	{
		
			// if the user selected the ok button, add the system 
		sys.SystemID = getUniqueSystemID (SystemDB);
		FldCompactText (GetObjectFromActiveForm (addSystemName));
		sys.name = FldGetTextPtr (GetObjectFromActiveForm (addSystemName));
		
			// null strings are not valid
		if (sys.name && StrLen (sys.name))
		{
			
				// find the sort position of the new system
				index =
				DmFindSortPosition (SystemDB, &sys, 0,
									(DmComparF *) SortPosSystemFunction, 0);
				if ((rec = DmNewRecord (SystemDB, &index, 1)))
				
			{
				MemPtr scratch;
				if ((scratch = MemPtrNew (getSystemSize (&sys, true))))
					
				{
					
						// pack it up and write it out
						PackSystem (scratch, sys, &SysPass, true);
					writeRecord (scratch, rec);
					MemSet (scratch, MemPtrSize (scratch), 0);
					MemPtrFree (scratch);
				}
				DmReleaseRecord (SystemDB, index, true);
			}
		}
	}
		
		// go back to the old form
	FrmEraseForm (frm);
	FrmDeleteForm (frm);
	if (previousForm)
	{

			if (button == addSystemOk) {
				// set active form and redraw the list
				setSystemForAccountForm(index);
			}
			FrmSetActiveForm (previousForm);
			AccountFormInit();
//		SystemFormInit ();
			LstDrawList (GetObjectFromActiveForm (accountList));
	}
}


/*****************************************************************************
 * Function: deleteAccountFromDB
 * Description: this function will promt the user to delete and accout,
 * if they agree, it will delete the record from the database entirely
 * **************************************************************************/ 
static void deleteAccountFromDB (void) 
{
	
		// prompt the user
		if (FrmCustomAlert (DeleteAlert, "Delete this account?", NULL, NULL)
			== 0)
		
	{
		
			// delete it
			DmRemoveRecord (AccountDB, getIndexOfNthAcct (AccountDB, currentSID, selectedAccount));
		changeForm (StripAccountForm);
	}
}


/******************************************************************************
 * Function: deleteSystemFromDB
 * Description: this function will prompt the user to delete a system and
 * all the associated account. it will then remove the system, then it
 * will iterate through the account database and delete all accounts with
 * that system id.
 * ****************************************************************************/ 
	static void
deleteSystemFromDB (void) 
{
	
		// prompt the user
		if (FrmCustomAlert
			(DeleteAlert, "Delete this system and all associated accounts?",
			 NULL, NULL) == 0)
		
	{
		UInt16 totalItems =
			DmNumRecordsInCategory (AccountDB, dmAllCategories); UInt16 i;
		Boolean delete = false;
		Int32 SysID = getSIDForSystemIndex (SystemDB, selectedSystem);
		
			// remove the system
			DmRemoveRecord (SystemDB, selectedSystem);
		
			// loop through the accounts
			for (i = 0; (i < totalItems); i++)
			
		{
			
				// get the system id
				UInt16 id = getSIDFromAccountIndex(AccountDB, i);
			if (id == SysID)
				
			{
				
					// if the account needs to be deleted,
					// mark it
					delete = true;
			}
			if (delete)
				
			{
				
					// remove the record
					DmRemoveRecord (AccountDB, i);
				
					// decriment both the current index (this
					// will remain the same if we delete an account)
					// and also the total items, so we dont end up 
					// querying accounts that dont exist.
					i--;
				totalItems--;
			}
			delete = false;
		}
// 		this is unecessary
//		changeForm (StripAccountForm);
	}
}



/***********************************************************************
 * Function: showShowAccount
 * Description: get the current Account id and change the form
 * *********************************************************************/ 
	static void
showShowAccount (UInt16 index) 
{
	currentAID = getAIDFromAccountIndex (AccountDB, index);
	changeForm (ShowAccount);
}




/********************************************************************************
 * Function:BeamStream
 * Description: pass it a buffer, and the length in bytes of that buffer and 
 * it will beam it to another hand-held.  In this case the program will
 * always be running when we beam, so we are not terribly concerned with 
 * buffering
 * *****************************************************************************/
static Err BeamStream(ExgSocketType *s, MemPtr buff, UInt32 bytes)
{
    Err err=0;

        // while there is no errors and we have bytes left
    while(!err && bytes>0)
    {
            // ExgSend does the actual beaming.
        UInt32 sent=ExgSend(s, buff, bytes, &err);
        bytes-=sent;

            // move the pointer along in the buffer
        buff=((char *) buff)+sent;
    }
    return err;
}

/***********************************************************************
 * Function: BeamAccount
 * Description: pass it the index of the account you want to beam 
 * and it will send that account and all associated information 
 * to another handlheld.  Accounts are not beamed in encrypted format,
 * because another handheld would have to know the key of the beaming
 * hand held, which is a security liability. As far as I know of, not 
 * too many people have access to infrared packet sniffers. and event if
 * they did the range of these devices would be line of sight, so im not
 * to worried.
 * ********************************************************************/
static void BeamAccount(UInt16 index)
{
    Account ac;
    Err err;
    ExgSocketType s;
    MemHandle scratch;
    MemPtr scratch2;
    MemPtr p;

    if((scratch=MemHandleNew(1)))
    {
            //decrypt an account
        getAccountFromIndex(AccountDB, &SysPass, index, scratch, &ac);
    
        if((scratch2=MemPtrNew(getAccountSize(&ac, false))))
        {
                // pack the account into a null seperated buffer,
                // but WITHOUT encrypting it
            PackAccount(scratch2, ac, &SysPass, false); 
            
                // clean out the socket
            MemSet(&s, sizeof(s), 0);

#ifdef LOCAL_IR
	s.localMode=true;
#endif

                // make the description the username.
                // I am not using a mime-type so the 
                // extension is ".act" for the "file"
                // set the target to this creator-code "SJLO"
            s.description=ac.username;
            s.name="StripAccount.act";
            s.target=StripCreator;
        
                // initialize the socket and beam the buffer
            err=ExgPut(&s);
            if(!err)
                err= BeamStream(&s, scratch2, getAccountSize(&ac, false));
        
                // make sure to disconnect!!!
            err=ExgDisconnect(&s, err);
            
            MemSet(scratch2, MemPtrSize(scratch2), 0);
            MemPtrFree(scratch2);
        }
        p=MemHandleLock(scratch);
        MemSet(p, MemPtrSize(p), 0);
        MemHandleUnlock(scratch);
        MemHandleFree(scratch);
    }
}

/***********************************************************************
 * Function: BeamSystem
 * Description: pass it the index of the System you wish to beam.
 ***********************************************************************/
static void BeamSystem(UInt16 index)
{
    Err err;
    ExgSocketType s;
	UInt16 numAccounts;	
	if((numAccounts=numAccountsInSystem(AccountDB, index))>0)
	{
		int i;
    	MemSet(&s, sizeof(s), 0);

#ifdef LOCAL_IR
	s.localMode=true;
#endif

        	// make the description the name of the category.
            // set the target to this creator-code "SJLO"
        s.description=CurSys.name;
        s.target=StripCreator;
        s.name="StripCategory";
       
        err=ExgPut(&s);
        if(!err)
            err= BeamStream(&s, &numAccounts, sizeof(numAccounts));

		for(i=0; i<numAccounts ; i++)
		{
    		MemHandle scratch;
    		MemPtr scratch2;
    		MemPtr p;
    		Account ac;
			
    		if((scratch=MemHandleNew(1)))
    		{
				UInt16 actSize;
            		//decrypt an account
        		getAccountFromIndex(AccountDB, &SysPass, getIndexOfNthAcct(AccountDB, currentSID, i), scratch, &ac);
    
        		if((scratch2=MemPtrNew(getAccountSize(&ac, false))))
        		{
            	    	// pack the account into a null seperated buffer,
            	    	// but WITHOUT encrypting it
            		PackAccount(scratch2, ac, &SysPass, false); 
            
                		// clean out the socket
                		// initialize the socket and beam the buffer
					actSize=getAccountSize(&ac,false);
					err=BeamStream(&s,&actSize, sizeof(actSize)); 
                	err= BeamStream(&s, scratch2, getAccountSize(&ac, false));
            		MemSet(scratch2, MemPtrSize(scratch2), 0);
            		MemPtrFree(scratch2);
        		}
        		p=MemHandleLock(scratch);
        		MemSet(p, MemPtrSize(p), 0);
        		MemHandleUnlock(scratch);
        		MemHandleFree(scratch);
			}
    	}
           	// make sure to disconnect!!!
       err=ExgDisconnect(&s, err);
	}
}



/*************************************************************************
 * Function: HandleCommonMenus
 * Description: this is the event handler that handles all of the
 * menu events for the program
 * ***********************************************************************/ 
	static Boolean
HandleCommonMenus (UInt16 menuID) 
{
	Boolean handled = false;
	FieldPtr fld;
	switch (menuID)
	{
			
				// edit commands.
		case AboutMe:
			
				// pop up about box
				DisplayAboutBox ();
			handled = true;
			break;
		case ChPass:
			
				// pop up change password form
				changeForm (ChangePasswordForm);
			handled = true;
			break;
		case PrefMenu:
			showPreferenceScreen ();
			handled = true;
			break;

		case RegMenu:
#ifdef WITH_REGISTER
			registerForm();
#endif
			handled = true;
			break;

		case NewSysPull:
			
				// pop up new system form
				createNewSystem ();
			handled = true;
			break;
		case NewAccPull:
			
				// pop up new account form
				showCreateAccountForm ();
			handled = true;
			break;
		case EditSysPull:
			
				// if the system id is not zero ("Unfiled"), pop up 
				// the edit system screen
				if (currentSID == 0)
				FrmCustomAlert (GenericError,
								 "You cannot edit the", STR_UNFILED_CATEGORY, "category!");
			else
				editSystem ();
			handled = true;
			break;
		case EditAccPull:
			
				// pop up edit account screen
				showEditAccountForm ();
			handled = true;
			break;
		case BeamAccPull:
			
				// beam the current account
			BeamAccount (getIndexOfNthAcct (AccountDB, currentSID, selectedAccount));
			break;
		case BeamSysPull:
			
				// beam the current account
			BeamSystem (currentSID);
			break;
		case AppInfo:
			
				// pop up app info box
			DisplayInfoBox ();
			handled = true;
			break;
		case AccountInfo:
			DisplayAccountInfoBox();
			handled = true;
			break;
		case RegenAccountHash:
			if (FrmCustomAlert (RegenAlert, STR_REGEN_ALERT, NULL, NULL)
			== 0) {
				FormType *preF = FrmGetActiveForm ();
				FormType *f = FrmInitForm (pleaseWait);
				FrmDrawForm (f); 
				replaceAccountHash(getIndexOfNthAcct (AccountDB, currentSID, selectedAccount),
					AccountDB, &SysPass);
				FrmEraseForm (f);
				FrmDeleteForm (f);
				FrmSetActiveForm (preF); 
			}
			handled = true;
			break;	
		case RegenAllHashes:
			if (FrmCustomAlert (RegenAlert, STR_REGEN_ALL_ALERT, NULL, NULL)
			== 0) {
				FormType *preF = FrmGetActiveForm ();
				FormType *f = FrmInitForm (pleaseWait);
				FrmDrawForm (f); 
				replaceAllAccountHashes(AccountDB, &SysPass);
				FrmEraseForm (f);
				FrmDeleteForm (f);
				FrmSetActiveForm (preF); 
			}
			handled = true;
			break;

       // edit commands.
		case EditUndo:
		case EditCut:
		case EditCopy:
		case EditPaste:
		case EditSelectAll:
			fld=GetFocusObjectPtr();
				if(!fld) {
					handled = false;
					break;
				}	
				if(menuID==EditUndo)
					FldUndo(fld);
				else if(menuID==EditCut)
					FldCut(fld);
				else if(menuID==EditCopy)
					FldCopy(fld);
				else if(menuID==EditPaste)
					FldPaste(fld);
				else if(menuID==EditSelectAll)
					FldSetSelection(fld, 0, FldGetTextLength(fld));

				handled = true;
			break;

		case EditKeyboard:
 			// pop up keyboard
			SysKeyboardDialog(kbdDefault);
			handled = true;
			break;
            
		case EditGrafitti:
			// pop up graffiti reference
			SysGraffitiReferenceDialog(referenceDefault);
			break;
			
		default:
				// not handled
				break;
	}
	return handled;
}


/****************************************************************************
 * Function: AccountFormHandleEvent
 * Description: Event handler for the account form. the up and down buttons
 * will scroll the list one full page.  
 * *************************************************************************/ 
	static Boolean
AccountFormHandleEvent (EventType *event) 
{
	Boolean handled;
	//Char *p;
	UInt16 c;
	
		SET_A4_FROM_A5 

		handled = false;
	switch (event->eType)
		
	{
	 //			 they selected a new system, so handle the click in the popup
		case popSelectEvent:
			if(event->data.popSelect.controlID == AccountSystemPopupTrigger) {
				HandleClickInPopup (event);
				showAccountForm (event->data.popSelect.selection);
				handled = true;
			}
			break;

/*
		case popSelectEvent:
			if(event->data.popSelect.controlID == SystemListPopupTrigger) {
				HandleClickInPopup (event);
				LstDrawList (GetObjectFromActiveForm (SystemList));
				handled = true;
			}
			break; 
*/			
				// handle up and down button keys, and scroll the list
		case keyDownEvent:
			c = event->data.keyDown.chr;
			if (c == pageUpChr)
				LstScrollList (GetObjectFromActiveForm (accountList), winUp, 7);
			
			else if (c == pageDownChr)
				LstScrollList (GetObjectFromActiveForm (accountList), winDown,
								7); 
			break;
		
		case ctlSelectEvent:
			switch (event->data.ctlSelect.controlID)
				
			{
				/*	
						// edit button allows the user to edit the selected system, if 
						// its not SID 0 ("Unfiled" system)
				case EditSystem:
					if (currentSID == 0)
						FrmCustomAlert (GenericError,
										 "You cannot edit the default system!!",
										 NULL, NULL);
					else
						editSystem ();

					handled = true;
					break;
					
						// done with this screen so go back to the system list
				case DoneAccount:
					changeForm (StripSystemForm);
					handled = true;
					break;
					*/
					
						// create a new account
				case NewAccount:
					showCreateAccountForm ();
					handled = true;
					break;

				case NewCategory:
					createNewSystem ();
					handled = true;
					break;
					
				default:
					break;
			}
			break;
			
				// if the user selects and account to view, pop up the
				// screen that will allow them to view it.
		case lstSelectEvent:
			selectedAccount = event->data.lstSelect.selection;
			showShowAccount (selectedAccount);
			break;
			
				// write the system name to the screen, and draw the form
		case frmOpenEvent:
			FrmDrawForm (FrmGetActiveForm ());
			selectedAccount = 0;
//			setFieldFromString (AccountSystemName, CurSys.name);
			handled = true;
			break;
		case menuEvent:
			handled = HandleCommonMenus (event->data.menu.itemID);
			break;
		case frmCloseEvent:
		/*	p = FldGetTextPtr (GetObjectFromActiveForm (AccountSystemName));
			if (p)
				MemSet (p, StrLen (p), 0); */
			break;

		default:
			break;
	}
	
		RESTORE_A4 

		return (handled);
}

static void setSystemForAccountForm(UInt16 index) {
	prefs.lastCategoryIndex = index;
	selectedSystem = index;
	cacheSystem (index);	
	/*	note the system ID */
	currentSID = CurSys.SystemID;
}
/*********************************************************
 * Function: showAccountForm
 * Description: set up, cache and diplay the account form
 * ******************************************************/ 
static void showAccountForm (UInt16 index) {
	setSystemForAccountForm(index);
	changeForm (StripAccountForm);
}


/****************************************************************************
 * Function: SystemFormHandleEvent
 * Description: Event handler for the system form. the up and down buttons
 * will scroll the list one full page.  
 * *************************************************************************/ 
	static Boolean
SystemFormHandleEvent (EventType *event) 
{
	Boolean handled;
	UInt16 c;
	
		SET_A4_FROM_A5 

		handled = false;
	switch (event->eType)
		
	{
			
				// handle up and down button keys, and scroll the list
		case keyDownEvent:
			c = event->data.keyDown.chr;
			if (c == pageUpChr) LstScrollList (GetObjectFromActiveForm (SystemList), winUp, 9);
		        else if (c == pageDownChr) LstScrollList (GetObjectFromActiveForm (SystemList), winDown, 9);
		        break;
		case ctlSelectEvent:
			switch (event->data.ctlSelect.controlID)
				
			{
					
						// pop up new system modal dialog
				case NewSystem:
					createNewSystem ();
					break;
				default:
					break;
			}
			handled = true;
			break;
			
				// the user selected a system in the list, so show the accouts
				// for that system
		case lstSelectEvent:
			showAccountForm (event->data.lstSelect.selection);
			break;
			
				// draw the form
		case frmOpenEvent:
			// selectedSystem = 0;
			FrmDrawForm (FrmGetActiveForm ());
			handled = true;
			break;
		case menuEvent:
			handled = HandleCommonMenus (event->data.menu.itemID);
			break;
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
			case StripSystemForm:
				SystemFormInit ();
				FrmSetEventHandler (frm, SystemFormHandleEvent);
				break;
			case StripAccountForm:
				AccountFormInit ();
				FrmSetEventHandler (frm, AccountFormHandleEvent);
				break;
			case makeNewAccount:
				FrmSetEventHandler (frm, newAccountHandleEvent);
				break;
			case EditSystemForm:
				FrmSetEventHandler (frm, EditSystemHandleEvent);
				break;
			case EditAccountForm:
				FrmSetEventHandler (frm, editAccountHandleEvent);
				break;
			case EditAccountCommentForm:
				FrmSetEventHandler (frm, EditCommentHandleEvent);
				break;
			case ShowAccount:
				FrmSetEventHandler (frm, showAccountHandleEvent);
				break;
			case StripSKeyForm:
				FrmSetEventHandler (frm, skeyHandleEvent);
				break;
			case PasswordForm:
				FrmSetEventHandler (frm, PasswordHandleEvent);
				break;
			case ChangePasswordForm:
				FrmSetEventHandler (frm, ChangePasswordHandleEvent);
				break;
			default:
				break;
		}
		handled = true;
	}
	return handled;
}


/********************************************************************
 * Function: SearchAccounts
 * Description:  this is the function that will handle the find system
 * request. ONLY CALL THIS FUNCTION IF THE PROGRAM IS RUNNING.
 * *****************************************************************/ 
	static void
SearchAccounts (FindParamsType *findParams) 
{
	UInt16 pos;
	UInt16 fieldNum;
	UInt16 cardNo = 0;
	UInt16 recordNum;
	Char *header;
	Boolean done;
	MemHandle rH;
	MemHandle hH;
	RectangleType r;
	findParams->more = false;
	hH = DmGetResource (strRsc, FindHeaderString);
	header = MemHandleLock (hH);
	done = FindDrawHeader (findParams, header);
	MemHandleUnlock (hH);
	if (done)
		
	{
		findParams->more = true;
	}
	
	else
		
	{
		recordNum = findParams->recordNum;
		for (;;)
			
		{
			Boolean match = false;
			MemPtr pac, scratch;
			MemHandle scr;
			Char *toDraw;
			Account ac;
			System sys;
			UInt16 length;
			if ((recordNum & 0x0002) == 0 && EvtSysEventAvail (true))
				
			{
				findParams->more = true;
				break;
			}
			rH =
				DmQueryNextInCategory (AccountDB, &recordNum,
									   dmAllCategories); if (!rH) break;
			pac = MemHandleLock (rH);
			if ((scratch = MemPtrNew (MemPtrSize (pac))))
				
			{
				
					// decrypt the system with old password
					UnpackAccount (&ac, pac, scratch, &SysPass,
								   MemHandleSize (rH), true, true);
				if (
					  (match =
					   FindStrInStr ((Char*) ac.system,
									 findParams->strToFind, &pos)) != false)
					fieldNum = 0;
				
				else
					if (
						(match =
						 FindStrInStr ((Char*) ac.service,
									   findParams->strToFind,
									   &pos)) != false) fieldNum = 1;
				
				else
					if (
						(match =
						 FindStrInStr ((Char*) ac.username,
									   findParams->strToFind,
									   &pos)) != false) fieldNum = 2;

				else
					if (
						(match =
						 FindStrInStr ((Char*) ac.password,
									   findParams->strToFind,
									   &pos)) != false) fieldNum = 3;
				
				else
					if (
						(match =
						 FindStrInStr ((Char*) ac.comment,
									   findParams->strToFind,
									   &pos)) != false) fieldNum = 3;
				if (match)
					
				{
					fieldNum = getIndexForSystemID (SystemDB, ac.SystemID);
					done =
						FindSaveMatch (findParams, recordNum, pos, fieldNum,
									   0, cardNo, 0);
					if (done)
						break;
					scr = MemHandleNew (1);
					getSystemFromIndex (SystemDB, &SysPass, getIndexForSystemID (SystemDB, ac.SystemID),
										 scr, &sys);
					length =
						StrLen (ac.username) + StrLen (ac.system) +
						StrLen (sys.name) + 10;
					if ((toDraw = MemPtrNew (length)))
						
					{
						MemSet (toDraw, MemPtrSize (toDraw), 0);
						StrNCopy (toDraw, (Char*) sys.name, 10);
						if (StrLen (sys.name) > 10)
							
						{
							StrCat (toDraw, "...");
						}
						StrCat (toDraw, ",");
						StrNCat (toDraw,  ac.username, 25);
						if (StrLen (ac.username) > 15)
							
						{
							StrCat (toDraw, "...");
						}
						StrCat (toDraw, ",");
						StrCat (toDraw, (Char*) ac.system);
						FindGetLineBounds (findParams, &r);
						DrawCharsToFitWidth (toDraw, &r);
						findParams->lineNumber++;
						MemSet (toDraw, StrLen (toDraw), 0);
						MemPtrFree (toDraw);
					}
					freeHandle (scr);
				}
				MemSet (scratch, MemPtrSize (scratch), 0);
				MemPtrFree (scratch);
			}
			MemHandleUnlock (rH);
			if (done)
				break;
			recordNum++;
		}
	}
}


/********************************************************************
 * Function: GoToAccount
 * Description: Caches account and System and enques and event to 
 * show the proper account.
 * *****************************************************************/ 
	static void
GoToAccount (GoToParamsType *goToParams) 
{
	
		//EventType event;
		UInt16 recordNum = goToParams->recordNum;
	MemPtr p, r, s;
	if ((r = DmGetRecord (AccountDB, recordNum)))
		
	{
		Account ac;
		p = MemHandleLock (r);
		if ((s = MemPtrNew (MemPtrSize (p))))
			
		{
			UnpackAccount (&ac, p, s, &SysPass, MemHandleSize (r), true,
							true); currentAID = ac.AccountID;
			currentSID = ac.SystemID;
			MemSet (s, MemPtrSize (s), 0);
			MemPtrFree (s);
		}
		MemHandleUnlock (r);
		DmReleaseRecord (AccountDB, recordNum, true);
	}
	selectedSystem = getIndexForSystemID (SystemDB, currentSID);
	selectedAccount = getIndexForAccountID (AccountDB, currentSID, currentAID);
	cacheSystem (selectedSystem);
	cacheAccount (selectedAccount);
	changeForm (ShowAccount);
}


/********************************************************************
 * Function: HandlePowerOff
 * Description: if the user presses the power button it locks the 
 * display and requires the user to re-enter the password 
 * when the unit turns on again
 * *****************************************************************/ 
	static void
HandlePowerOff (EventType *event) 
{
	if (event->eType == keyDownEvent) {
		if ((event->data.keyDown.chr == hardPowerChr || event->data.keyDown.chr == autoOffChr) && prefs.autoLock) {
			if (SysPass && authenticated) {
				FrmSaveAllForms();
				MemSet (SysPass, sizeof(md_hash), 0);
			}
			FrmCloseAllForms ();
			changeForm (PasswordForm);
		}
	}
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
	
			// pre-process event
			HandlePowerOff (&event);
		
			// first the system gets the event, then the Menu event handler, then the application
			// event handler, then finally the form event handler
			if (!SysHandleEvent (&event))
			if (!MenuHandleEvent (0, &event, &error))
				if (!ApplicationHandleEvent (&event))
					FrmDispatchEvent (&event);
	}
	while (event.eType != appStopEvent);
}


/*************************************************************************
 * Function: ReadBytesIntoAccount
 * Description: this function is called when an account is
 * being beamed into the program. If Strip is running locally it
 * encrypts the account and writes it to the database. If Strip is 
 * not running the program does not know the password, so it writes
 * the account to the databse in plaintext format, and it will be
 * encrypted the next time Strip is run by the user
 * ***********************************************************************/
static Err ReadBytesIntoAccount(DmOpenRef db, ExgSocketType *socket, UInt32 bytes, UInt16 aid, Int16 *beamCategory)
{
    char buffer[100];
    Err err = 0;
	UInt16 index, exist_index=0;
    UInt32 received;
    MemHandle rec, pac=NULL;
    MemPtr scrPtr, scratch, scratch2;
    UInt32 recSize=0;
    Boolean aRec=false, exists=false, smart_beam=false;
	Int16 i;
    Account ac;
	UInt16 totalAItems = DmNumRecordsInCategory (AccountDB, dmAllCategories); 

				SET_A4_FROM_A5 

	smart_beam=prefs.smart_beaming;
				RESTORE_A4 


	do 
    {
            // find out how many bytes to read
        Int32 bytesToRead=min(bytes, sizeof(buffer));

            // read these bytes int memory
        received=ExgReceive(socket, buffer, bytesToRead, &err);

        bytes-=received;

            // if there is no error, create a new memory handle
            // or resize the existing one to accomodate the new data
        if(!err)
        {
            if(!pac) {
                pac=MemHandleNew(received);
            } else {
                MemHandleResize(pac, recSize+received);
			}
            if(!pac)
            {
                err=1;
                break;
            }
        }

        aRec=true;
        scrPtr=MemHandleLock(pac);

            // pack the recieved data onto the buffer
        MemMove(scrPtr+recSize,buffer,received);
        MemHandleUnlock(pac);
        recSize+=received;
    }
    while(!err && (received > 0) && (bytes > 0) );
    
    scratch=MemPtrNew(recSize);
    scrPtr=MemHandleLock(pac);

							 
        // unpack the beamed data into a local account
    UnpackAccount(&ac, scrPtr, scratch, NULL, recSize, false, false);

	if(smart_beam) {
		for(i=0; i<totalAItems; i++) {
			if(!MemCmp(ac.hash, getHashFromAccountIndex(AccountDB, i), sizeof(md_hash))) {
				exists=true;
				exist_index=i;
				break;
			}
		}
	}
	

	if(exists && smart_beam) {
		ac.AccountID=getAIDFromAccountIndex(AccountDB, exist_index);	
		ac.SystemID=getSIDFromAccountIndex(AccountDB, exist_index);	
	} else if (smart_beam) {
		// If Smart Beam is turned on, prompting is disabled
		// - too many issues with overwriting accounts
		ac.AccountID=aid;
		ac.SystemID=0;  // this would be beamCategory w/o SmartBeam
	} else {	

		// Not Smart Beaming... prompt them for a category destination
		promptBeamCategory(beamCategory);   // BCJ

		ac.AccountID=aid;
			// BCJ: assign it a system ID of beamCategory 
		ac.SystemID= * (beamCategory);      // BCJ
			// generate new sig since not smart_beaming.
		MemMove(ac.hash, generateAccountHash(&ac), sizeof(md_hash));
	}

	index=DmFindSortPosition(db, &ac, 0, (DmComparF *) SortPosAccountFunction, 0);

	/* Encrypt the account */
   	scratch2=MemPtrNew(getAccountSize(&ac, true));
	PackAccount(scratch2, ac, &SysPass, true);
   
	if(exists && smart_beam) {
		if((rec = DmGetRecord (db, exist_index))) {
			writeRecord (scratch2, rec);
			DmReleaseRecord (db, exist_index, true);
			DmMoveRecord (db, exist_index, index);
		}
	} 
	else {
        	// create a new record and add hte accout to the database
    	if((rec = DmNewRecord(db, &index, 1)))
    	{
       	 	writeRecord( scratch2, rec);
        	DmReleaseRecord(db, index, true);
    	}
   } 
        // free used memory
    MemSet(scratch, MemPtrSize(scratch), 0);
    MemSet(scratch2, MemPtrSize(scratch2), 0);
    MemSet(scrPtr, MemPtrSize(scrPtr), 0);
    
    MemPtrFree(scratch);
    MemPtrFree(scratch2);
    MemPtrFree(scrPtr);

    return err;
}
    
/*************************************************************************************
 * Function: ReceiveBeamStream
 * Description: a wrapper function for ReadBytesIntoAccount. this function simply
 * gets a uniqe account ID or assigns the account id of 0. it accepts the
 * incoming socket, and disconnects when all the bytes have been read from the
 * stream
 * **********************************************************************************/
static Err ReceiveBeamStream(DmOpenRef db, ExgSocketType *socket)
{
    Err err;
    UInt16 aid;
  	Boolean single=false; 
    Int16 beamCategory = -1;  // Brad added this

	if(socket->name)
	{
		Char *loc=StrChr(socket->name, '.');
		if(loc && StrCaselessCompare(loc, ".act")==0)
			single=true;
	} 

        // accept incoming socket
    err=ExgAccept(socket);

    if(!err)
	{
		if(single || socket->type)
		{
       		aid=getUniqueAccountID(AccountDB);

        		// read bytes into a new account
			err=ReadBytesIntoAccount(db, socket, 0xffffffff, aid, &beamCategory);
		}
		else
		{
			UInt16 numAccounts, actSize;
			
			ExgReceive(socket, &numAccounts, sizeof(numAccounts), &err);
			while(!err && numAccounts -- > 0)
			{
				ExgReceive(socket, &actSize, sizeof(actSize), &err);
				if(!err)
				{
        			aid=getUniqueAccountID(AccountDB);
					err=ReadBytesIntoAccount(db, socket, actSize, aid, &beamCategory);
				}
			}
		}
	}					
			
        // dont forget to disconnect.
    err=ExgDisconnect(socket, err);

        // this application does not support the goto or find commands because 
        // of the encryption it uses. so dont go anywhere
	
	socket->goToParams.recordNum=NULL;	
	return err;
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
	if (cmd == sysAppLaunchCmdNormalLaunch) {
		// call StartApplication to initialize things, 
		// go to the opening form and enter the event loop,
		// until end.
					
#if ((defined DEBUG) && (defined HAVE_GDBHOOK))	
		if (!(launchFlags & sysAppLaunchFlagSubCall)) {
			_gdb_hook();
#endif 
		if ((err = StartApplication ()) == 0) { 
			FrmGotoForm (PasswordForm);
			EventLoop ();
			StopApplication ();
		}
	} else if (cmd == sysAppLaunchCmdSaveData) { 
		// OS request to save data.
		// save all form data
		FrmSaveAllForms ();
	} else if (cmd == sysAppLaunchCmdFind) { 
		//handle find
		if (launchFlags & sysAppLaunchFlagSubCall) {
			SET_A4_FROM_A5 
			if (authenticated)
				SearchAccounts ((FindParamsType*) cmdPBP);
			RESTORE_A4 
		}
	} else if (cmd == sysAppLaunchCmdGoTo) { 
		if (launchFlags & sysAppLaunchFlagSubCall) {
			SET_A4_FROM_A5 
			if (authenticated)
				GoToAccount ((GoToParamsType*) cmdPBP);
			RESTORE_A4 

		}
	} else if (cmd == sysAppLaunchCmdSyncNotify) {
		UInt32 romVersion;
		
		// OS Notification that a hotsync has occured. 
		// get rom version, if it is greater than three, register
		// with the exchange manager.
		FtrGet (sysFtrCreator, sysFtrNumROMVersion, &romVersion);
		if (sysGetROMVerMajor (romVersion) >= 3)
			ExgRegisterData (StripCreator, exgRegExtensionID, "act");
	} else if (cmd == sysAppLaunchCmdExgAskUser)  {
		ExgAskParamType *param;
		param= (ExgAskParamType *)cmdPBP;

		if (launchFlags & sysAppLaunchFlagSubCall) {
			SET_A4_FROM_A5 
			if(authenticated)
				param->result=exgAskDialog;
			else
				param->result=exgAskCancel;
			RESTORE_A4 
		} else {
			param->result=exgAskCancel;
		}
	} else if (cmd == sysAppLaunchCmdExgReceiveData) {
		// OS notification that another palm pilot is attempting
		// to beam us data. 
		if (launchFlags & sysAppLaunchFlagSubCall) {
			SET_A4_FROM_A5 
			if(authenticated) {
				FrmSaveAllForms ();
					// recieve the beam
				err = ReceiveBeamStream (AccountDB, (ExgSocketType*) cmdPBP);
			}
			RESTORE_A4 
		}
	}
	return err;
}

#if 0
/**********************************************************************
 * Function: bin2hex
 * Description: converts a byte string to ASCII hex.
 * ********************************************************************/ 
Char * bin2hex (byte * in, Char * out,  Int16 length) {
    Int16 j;
	Char temp[32];
    for (j = 0; j < length; j++) {
		MemSet(temp, 32 , 0);
		StrPrintF(temp, "%x", in[j]);
		MemMove(&((char *) out)[2 * j], &((char *) temp)[2], 2); 
    }
    return out;
}
#endif

static void promptBeamCategory (Int16 *beamCategory) {
       //System sys;
       //MemHandle scratch;
             // Only display the prompt if a category hasn't been chosen
             if ( (*(beamCategory)) < 0)
             {
                 // display the dialog and have them choose a category
                 FormType *prevForm = FrmGetActiveForm ();
                 FormType *beamLocForm = FrmInitForm(ChooseBeamLocation);
                 UInt16 button;
                 ListType *list;
                 * (beamCategory) = 0;   // Unfiled category by default
  
                 FrmSetActiveForm(beamLocForm);
                 FrmSetEventHandler (beamLocForm, ChooseBeamLocationHandleEvent);
       // Try putting this here
                 FrmDrawForm(beamLocForm);
								 beamSelectSystemInit ();
                 list = GetObjectFromActiveForm (ChooseBeamLocationPopupList);
                 LstSetDrawFunction(list, SystemListDrawFunction);
//      scratch = MemHandleNew(1);
                 LstSetSelection (list, selectedSystem);
//       getSystemFromIndex (SystemDB, &SysPass, selectedSystem, scratch, &sys);
       CtlSetLabel (GetObjectFromActiveForm (ChooseBeamLocationPopupTrigger), CurSys.name);
//       freeHandle(scratch);
                 button = FrmDoDialog (beamLocForm);
                 * (beamCategory) = getSIDForSystemIndex (SystemDB, LstGetSelection(list));
                 FrmEraseForm(beamLocForm);
                 FrmDeleteForm(beamLocForm);
                 if (prevForm) {
                         FrmSetActiveForm (prevForm);
                 }
            }                                      
 }

 static Boolean ChooseBeamLocationHandleEvent (EventType *event)
 {
       Boolean handled;
       SET_A4_FROM_A5
       handled = false;
       switch (event->eType)
      {
               case ctlSelectEvent:
                       switch (event->data.ctlSelect.controlID)
                       {
                               case ChooseBeamLocationPopupTrigger:
                                       beamSelectSystemInit ();
                                       break;
                            default:
                                       handled = false;
                                       break;
                       }
                       break;
               case popSelectEvent:
                       if (event->data.popSelect.controlID == ChooseBeamLocationPopupTrigger) {
                               HandleClickInPopup (event);
                              handled = true;
                       }
                       break;
               case frmOpenEvent:
 //                       FrmDrawForm (FrmGetActiveForm ());
                       break;
              default:
                       break;
       }
 
       RESTORE_A4
       return (handled);
 }
 
 static void beamSelectSystemInit (void) {
         UInt16 numSys = DmNumRecordsInCategory (SystemDB, dmAllCategories);
         ListType *list = GetObjectFromActiveForm (ChooseBeamLocationPopupList);
  
         /*      if there are less than 8 systems, set the list height to be
                 the number of systems. If there are more than 8 systems a maximum
                of 8 will be shown at a time (without scrolling). */
         if (numSys < 8)
                 LstSetHeight (list, DmNumRecordsInCategory (SystemDB, dmAllCategories));
         else
                 LstSetHeight (list, 8);
  
         LstSetListChoices (list, NULL, numSys);
 }                                                

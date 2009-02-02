/*
 * $Id: skey.c,v 1.1.1.1 2005/08/08 14:51:27 lombardo Exp $
 * Description: routines for generating MD5 S/Key one-time-passwords
 * as described in RFC1760 implemented by Ron Pedde (ron@pedde.com) for 
 * Strip (Secure tool for recalling important passwords) by Stephen J Lombardo.
 *
 * RFC1760 is available electronically at ftp://ftp.isi.edu/in-notes/rfc1760.txt
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Strip has been written and developed by Stephen J Lombardo (Zetetic Enterprises) 1999
 * 
 * Contact Info:
 * lombardos@zetetic.net
 * http://www.zetetic.net/
 * Zetetic Enterprises
 * 348 Wasington Ave 
 * Clifton NJ, 07011
 * 
 * Bug reports and feature requests should be sent to bugs@zetetic.net.
 */

#include <ExgMgr.h>
#include <PalmOS.h>

#include "Strip.h"
#include "skey.h"
#include "StripRsc.h"

/************************************************************************
 * Forwards
 * *********************************************************************/

int get_key(int seq, char *seed, char *passwd, char *key, int hashtype);
void smash(unsigned char *in, unsigned char *out, int len, int hashtype);
void key2hex(unsigned char *out, unsigned char *in);
void key2english(unsigned char *out, unsigned char *in);
int getbits(unsigned char *ptr, int startbit, int len);

char *btoe(unsigned char *in);
char *btoh(unsigned char *in);

int dict_open(void);
int dict_close(void);
char *dict_lookup(int index);

/************************************************************************
 * Globals
 * *********************************************************************/

unsigned char buf[32]; /* this is the static buffer into which the otp goes */
unsigned char eword[5]; /* english word lookup */
DmOpenRef otpDB=NULL;

/************************************************************************
 * Function: get_key
 * Description: generate a MD5 hashed one-time-password given a
 * sequence number, a seed, and the shared secret
 *
 * It returns a pointer to a static buffer -- it will get overwritten
 * with multiple calls to get_key
 *
 * hashtype = 0 for MD5, 1 for MD4
 * *********************************************************************/
int get_key(int seq, char *seed, char *passwd, char *key, int hashtype) 
{
    int len;
    char *data;
    char *ptr;

    if((!seed)||(!passwd))
	return 0;

    len=StrLen(seed) + StrLen(passwd);

    data=MemPtrNew(len + 1);
    if(!data)
	return 0;

    StrCopy(data,seed);
    StrCat(data,passwd);

    /* RFC says that the seed may not contain blanks, and should be 
     * strictly alphanumeric.  Some implementations strip the high
     * bit, so we will too.  I'm not completely convinced that this
     * should be done, though. */

    ptr=data;
    while(*ptr) {
	*ptr=(*ptr & 0x7F);  /* *ptr++ &= 0x7F.  Yeah, I know... I just *like* long code */
	ptr++;               /* besides, it optimizes out the same anyway.               */
    }

    smash(data,key,StrLen(data),hashtype);

    /* Now that it is smashed, we can get rid of the allocated space */
    MemSet(data,len,0x00);
    MemPtrFree(data);

    while(seq--) {
	smash(key, key, 8, hashtype);
    }

    return 1;
}

/************************************************************************
 * Function: btoe
 * Description: thin wrapper for key2english that utilizes the
 * statuc buffer 'buf'
 ************************************************************************/
char *btoe(unsigned char *in) 
{
    MemSet(buf,sizeof(buf),0x00);
    key2english((unsigned char*)&buf,in);
    return (char*)&buf;
}

/************************************************************************
 * Function: btoh
 * Description: thin wrapper for key2hex that utilizes the
 * statuc buffer 'buf'
 ************************************************************************/
char *btoh(unsigned char *in) 
{
    MemSet(buf,sizeof(buf),0x00);
    key2hex((unsigned char*)&buf,in);
    return (char*)&buf;
}

/************************************************************************
 * Function: smash
 * Description: Given a chunk of data, generate a 16 byte MD5 hash,
 * then fold it back into itself by XORing between the two 8 byte
 * halves of the hash.  Why?  I'm not sure... except that the RFC says
 * that they deem 64 bits long enough to be secure, but short enough
 * to generate manageable passwords.  I guess I believe them.
 *
 * The ubiquitous them.  Kinda eerie, isn't it?
 ***********************************************************************/
void smash(unsigned char *in, unsigned char *out, int len, int hashtype) 
{
    char unfolded[16];  /* since the out is probably only 8 */
    int i;

    // MemSet((char*)&unfolded,sizeof(unfolded),0x00);
    if(hashtype == HASHTYPE_MD5) {
	EncDigestMD5(in,len,(unsigned char *)&unfolded);
    } else {
	// MD4
	EncDigestMD4(in,len,(unsigned char *)&unfolded);
    }

    /* XOR the two 64 bit halves back upon themselves */
    for(i=0; i<8; i++) {
	out[i] = unfolded[i] ^ unfolded[i+8];
    }
}
/************************************************************************
 * Function: key2hex
 * Description: Display 8 bytes as a series of 16-bit hex 
 * digits.  Due to some strangeness of the palm StrPrintF,
 * it couldn't be used here.  <sigh>
 *
 * This function will require a 20 byte output buffer. 
 ************************************************************************/

void key2hex(unsigned char *out, unsigned char *in) 
{
    /* This is completely baked, because the pilot StrPrintF doesn't
     * support any real formats.  <sigh>
     * Guess we'll roll our own.
     */
    int index;
    char *ptr=out;
    char *hexdigits="0123456789ABCDEF";
    
    for(index=0; index < 8; index++) {
	*ptr++=hexdigits[in[index]/16];
	*ptr++=hexdigits[in[index]%16];

	if(index%2) {
	    *ptr++ = ' ';
	}
    }

    *ptr++='\x0';
}


/***************************************************************
 * Function: add_item
 * Description: add an english word as defined above into
 * a string.  Due to some strangness of the palm StrNCopy,
 * it couldn't be used here.  
 *
 * All in all, many of the palm functions seems to behave 
 * strangely.
 ***************************************************************/
/*
void add_item(char **buf, int which) 
{
    StrNCopy(*buf,keylist[which],4);
    *buf += StrLen(*buf);
    StrCopy((*buf)++," ");
}
*/
/**************************************************************
 * Function: btoe
 * Description: Encode 8 bytes in 'c' as a string out
 * english words.  Returns a pointer to the passed static
 * buffer.
 **************************************************************/
void key2english(unsigned char *out, unsigned char *in) 
{
    /* We end up 2 bits short of an even 11 (64 vice 66), so when
     * we englishize it, we randomize the last two bits
     * with 2 bit parity info.  This means we actually
     * have to allocate extra room, since the input buffer is
     * probably only 8 bytes.  Thats what the deal with 
     * tempkey is.
     */
    char tempkey[9];
    int index, parity;

    /* copy the old key */
    MemSet(tempkey,sizeof(tempkey),0);
    MemMove(tempkey,in,8);

    /* pad the last two bits with parity info */
    parity=0;
    for(index=0;index < 64; index += 2) {
	parity += getbits(tempkey,index,2);
    }

    tempkey[8] = (parity << 6) & 0xFF; 

    /* This could be quite fixed up now, since the array isn't fixed width */
    StrCat(out,dict_lookup(getbits(tempkey,0,11)));
    StrCat(out," ");
    StrCat(out,dict_lookup(getbits(tempkey,11,11)));
    StrCat(out," ");
    StrCat(out,dict_lookup(getbits(tempkey,22,11)));
    StrCat(out," ");
    StrCat(out,dict_lookup(getbits(tempkey,33,11)));
    StrCat(out," ");
    StrCat(out,dict_lookup(getbits(tempkey,44,11)));
    StrCat(out," ");
    StrCat(out,dict_lookup(getbits(tempkey,55,11)));
    StrCat(out," ");
}



/**************************************************************
 * Function:  dict_open
 * Description: open the english dictionary.  Returns 0 if
 * the database could not be opened.  (Not installed)
 *
 * This is done whenever the SKey form is opened.  It could
 * be done at startup, with the rest of the databases, but I'm
 * of the opinion that SKey is probably rarely used, and a 
 * small performance hit at the start of the skey form is
 * probably not a big deal.  I'd rather it there then at the
 * start of the app itself.
 **************************************************************/
int dict_open(void) 
{
    if(otpDB) {
	/* This shouldn't happen */
#ifdef DEBUG
	FrmCustomAlert(GenericError, "Re-opening already open OTP db.",NULL,NULL);
#endif
	
	dict_close();
    }

    otpDB=DmOpenDatabaseByTypeCreator(otpDBType,StripCreator,dmModeReadOnly);
    if(!otpDB)
	return 0;

    return 1;
}

/**************************************************************
 * Function:  dict_close
 * Description: close the english dictionary
 **************************************************************/
int dict_close(void) 
{
    if(otpDB) {
	DmCloseDatabase(otpDB);
	otpDB=NULL;
    }
    return 1;
}
/**************************************************************
 * Function:  dict_lookup
 * Description: lookup an entry into the english otp database.
 * 
 * The database should already have been opened.
 **************************************************************/
char *dict_lookup(int index) 
{
    MemHandle rec;
    MemPtr recPtr;

    StrCopy(eword,"XXXX");

    if(otpDB) {
	rec=DmQueryRecord(otpDB,index);
	if(rec) {
	    recPtr=MemHandleLock(rec);
	    MemMove((void*)&eword,recPtr,4);
	    MemPtrUnlock(recPtr);
	}
    }
    return (char*)&eword;
}

/**************************************************************
 * Function:  getbits
 * Description: return len bits from the data at ptr,
 * starting from bit 'startbit'
 *
 * This looks just gross
 **************************************************************/
int getbits(unsigned char *ptr, int startbit, int len) 
{
    unsigned long result;
    unsigned char byte1, byte2, byte3=0;

    /* The data is going to run at most 3 bytes, so we'll load 
     * all three (or two if necessary, so as not to overflow,
     * and shift out what we don't need
     */

    byte1 = ptr[startbit/8];
    byte2 = ptr[(startbit/8) + 1];
    if(((startbit % 8) >= 6) && (len > 8))
	byte3 = ptr[(startbit/8) + 2];

    /* Make it a big unsigned int, then drop off the low bits by 
     * sliding it right, and mask off any unessary high bits
     */
    result = byte1;
    result = (result << 8) | byte2;
    result = (result << 8) | byte3;

    result = result >> (24 - (len + (startbit % 8)));
    result = (result & (0xFFFF >> (16 - len)));

    return result;
}

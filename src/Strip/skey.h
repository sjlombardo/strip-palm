/*
 * $Id: skey.h,v 1.1.1.1 2005/08/08 14:51:27 lombardo Exp $
 * Description: routines for generating MD5 S/Key one-time-passwords
 * as described in RFC1760 (ftp://ftp.isi.edu/in-notes/rfc1760.txt)
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

#ifndef SKEY_H
#define SKEY_H

#define HASHTYPE_MD5       0
#define HASHTYPE_MD4       1

/* Internal */
extern int dict_open(void);
extern int dict_close(void);

extern int get_key(int, char*, char*, char *, int);
extern char *btoe(unsigned char *);
extern char *btoh(unsigned char *);

#endif /* SKEY_H */

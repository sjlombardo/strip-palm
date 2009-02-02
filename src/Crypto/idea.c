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
/******************************************************************************/
/*                                                                            */
/* I N T E R N A T I O N A L  D A T A  E N C R Y P T I O N  A L G O R I T H M */
/*                                                                            */
/******************************************************************************/
/* Author:       Richard De Moliner (demoliner@isi.ee.ethz.ch)                */
/*               Signal and Information Processing Laboratory                 */
/*               Swiss Federal Institute of Technology                        */
/*               CH-8092 Zuerich, Switzerland                                 */
/* Created:      April 23, 1992                                               */
/* Changes:      November 16, 1993 (support of ANSI-C and C++)                */
/* System:       SUN SPARCstation, SUN acc ANSI-C-Compiler, SUN-OS 4.1.3      */
/******************************************************************************/
#include "idea.h"

#define mulMod        0x10001 /* 2**16 + 1                                    */
#define ones           0xFFFF /* 2**16 - 1                                    */

/******************************************************************************/
/* Multiplication in the multiplicative group, a = a * b                      */
/* pre:  0 <= a <= 0xFFFF.                                                    */
/*       0 <= b <= 0xFFFF.                                                    */
/* post: 'a' and 'b' have been modified.                                      */
/*       a = a * b; where '*' is multiplication in the multiplicative group.  */
/* note: This implementation of '*' is not complete. To bee complete the      */
/*       result has to bee masked (MUL(a, b); a &= ones;).                    */

#define Mul(a, b)                                                              \
  if (a == 0) a = mulMod - b;                                                  \
  else if (b == 0) a = mulMod - a;                                             \
  else {                                                                       \
    a *= b;                                                                    \
    if ((a & ones) >= (b = a >> 16)) a -= b;                                   \
    else a += mulMod - b;                                                      \
  } /* Mul */

/******************************************************************************/
/* Encryption and decryption algorithm IDEA. Depending on the value of 'key'  */
/* 'Idea_Crypt' either encrypts or decrypts 'dataIn'. The result is stored    */
/* in 'dataOut'.                                                              */
/* pre:  'dataIn'  contains the plain/cipher-text block.                      */
/*       'key'     contains the encryption/decryption key.                    */
/* post: 'dataOut' contains the cipher/plain-text block.                      */

#ifdef ANSI_C
  void Idea_Crypt (Idea_Data dataIn, Idea_Data dataOut, Idea_Key key)
#else
  Idea_Crypt (dataIn, dataOut, key)
  Idea_Data dataIn;
  Idea_Data dataOut;
  Idea_Key key;
#endif

{ register u_int32 x0, x1, x2, x3, t0, t1, t2;
  int round;

  x0 = (u_int32)*dataIn++; x1 = (u_int32)*dataIn++;
  x2 = (u_int32)*dataIn++; x3 = (u_int32)*dataIn;
  for (round = Idea_nofRound; round > 0; round--) {
    t1 = (u_int32)*key++;
    x1 += (u_int32)*key++;
    x2 += (u_int32)*key++; x2 &= ones;
    t2 = (u_int32)*key++;
    Mul(x0, t1); x0 &= ones;
    Mul(x3, t2);
    t0 = (u_int32)*key++;
    t1 = x0 ^ x2;
    Mul(t0, t1); t0 &= ones;
    t1 = (u_int32)*key++;
    t2 = ((x1 ^ x3) + t0) & ones;
    Mul(t1, t2); t1 &= ones;
    t0 += t1;
    x0 ^= t1; x3 ^= t0; x3 &= ones;
    t0 ^= x1; x1 = x2 ^ t1; x2 = t0;
  }
  t0 = (u_int32)*key++;
  Mul(x0, t0);
  *dataOut++ = (u_int16)(x0 & ones);
  *dataOut++ = (u_int16)(((u_int32)*key++ + x2) & ones);
  *dataOut++ = (u_int16)(((u_int32)*key++ + x1) & ones);
  t0 = (u_int32)*key;
  Mul(x3, t0);
  *dataOut = (u_int16)(x3 & ones);
} /* Idea_Crypt */

/******************************************************************************/
/* Multiplicative Inverse by Extended Stein Greatest Common Divisor Algorithm.*/
/* pre:  0 <= x <= 0xFFFF.                                                    */
/* post: x * MulInv(x) == 1, where '*' is multiplication in the               */
/*                           multiplicative group.                            */

#ifdef ANSI_C
  static u_int16 MulInv (u_int16 x)
#else
  static u_int16 MulInv (x)
  u_int16 x;
#endif

{ register int32 n1, n2, N, a1, a2, b1, b2;

  if (x <= 1) return x;
  n1 = N = (int32)x; n2 = mulMod;
  a1 = b2 = 1; a2 = b1 = 0;
  do {
    while ((n1 & 1) == 0) {
      if (a1 & 1) 
      {
        if (a1 < 0) { a1 += mulMod; b1 -= N; }
        else { a1 -= mulMod; b1 += N; }
      }
      n1 >>= 1; a1 >>= 1; b1 >>= 1;
    }
    if (n1 < n2)
      do {
        n2 -= n1; a2 -= a1; b2 -= b1;
        if (n2 == 0) return (u_int16)(a1 < 0 ? a1 + mulMod : a1);
        while ((n2 & 1) == 0) {
          if (a2 & 1)
	  {
            if (a2 < 0) { a2 += mulMod; b2 -= N; }
            else { a2 -= mulMod; b2 += N; }
	  }
          n2 >>= 1; a2 >>= 1; b2 >>= 1;
        }
      } while (n1 <= n2);
    n1 -= n2; a1 -= a2; b1 -= b2;
  } while (n1);
  return (u_int16)(a2 < 0 ? a2 + mulMod : a2);
} /* MulInv */

/******************************************************************************/
/* Additive Inverse.                                                          */
/* pre:  0 <= x <= 0xFFFF.                                                    */
/* post: x + AddInv(x) == 0, where '+' is addition in the additive group.     */

#define AddInv(x)  (-x & ones)

/******************************************************************************/
/* Inverts a decryption/encrytion key to a encrytion/decryption key.          */
/* pre:  'key'    contains the encryption/decryption key.                     */
/* post: 'invKey' contains the decryption/encryption key.                     */

#ifdef ANSI_C
  void Idea_InvertKey (Idea_Key key, Idea_Key invKey)
#else
  Idea_InvertKey (key, invKey)
  Idea_Key key;
  Idea_Key invKey;
#endif

{ register u_int16 t, *in, *out;
  register int lo, hi, i;

  in = key; out = invKey;
  lo = 0; hi = 6 * Idea_nofRound;
  t = MulInv(in[lo]); out[lo++] = MulInv(in[hi]); out[hi++] = t;
  t = AddInv(in[lo]); out[lo++] = AddInv(in[hi]); out[hi++] = t;
  t = AddInv(in[lo]); out[lo++] = AddInv(in[hi]); out[hi++] = t;
  t = MulInv(in[lo]); out[lo++] = MulInv(in[hi]); out[hi] = t;
  for (i = (Idea_nofRound - 1) / 2 ; i != 0 ; i --) {
    t = in[lo]; out[lo++] = in[hi -= 5]; out[hi ++] = t;
    t = in[lo]; out[lo++] = in[hi]; out[hi] = t;
    t = MulInv(in[lo]); out[lo++] = MulInv(in[hi -= 5]); out[hi++] = t;
    t = AddInv(in[lo]); out[lo++] = AddInv(in[++hi]); out[hi--] = t;
    t = AddInv(in[lo]); out[lo++] = AddInv(in[hi]); out[hi++] = t;
    t = MulInv(in[lo]); out[lo++] = MulInv(in[++hi]); out[hi] = t;
  }
#if (Idea_nofRound % 2 == 0)
  t = in[lo]; out[lo++] = in[hi -= 5]; out[hi++] = t;
  t = in[lo]; out[lo++] = in[hi]; out[hi] = t;
  out[lo] = MulInv(in[lo]); lo++;
  t = AddInv(in[lo]); out[lo] = AddInv(in[lo + 1]); lo++; out[lo++] = t;
  out[lo] = MulInv(in[lo]);
#else
  out[lo] = in[lo]; lo++;
  out[lo] = in[lo];
#endif
} /* Idea_InvertKey */

/******************************************************************************/
/* Expands a user key of 128 bits to a full encryption key                    */
/* pre:  'userKey' contains the 128 bit user key                              */
/* post: 'key'     contains the encryption key                                */

#ifdef ANSI_C
  void Idea_ExpandUserKey (Idea_UserKey userKey, Idea_Key key)
#else
  Idea_ExpandUserKey (userKey, key)
  Idea_UserKey userKey;
  Idea_Key key;
#endif

{ register int i;

#if (Idea_keyLen <= Idea_userKeyLen)
  for (i = 0; i < Idea_keyLen; i++) key[i] = userKey[i];
#else
  for (i = 0; i < Idea_userKeyLen; i++) key[i] = userKey[i];
  for (i = Idea_userKeyLen; i < Idea_keyLen; i++)
    if ((i & 7) < 6)
      key[i] = (key[i - 7] & 127) << 9 | key[i - 6] >> 7;
    else if ((i & 7) == 6)
      key[i] = (key[i - 7] & 127) << 9 | key[i - 14] >> 7; 
    else
      key[i] = (key[i - 15] & 127) << 9 | key[i - 14] >> 7; 
#endif
} /* Idea_ExpandUserKey */

/******************************************************************************/

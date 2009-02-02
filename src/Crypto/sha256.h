/*	
    SHA-256 - Secure Hashing Algorithm v2 Implementation
    Copyright (C) 2000-2001, Daniel Roethlisberger <admin@roe.ch>
    Distributed under the GNU Lesser General Public License.
    See http://www.gnu.org/copyleft for details.
    Version 1.0.0-pre4
*/

#ifndef __SHA256_H
#define __SHA256_H

/* Context struct */
typedef struct
{
	unsigned long H1;
	unsigned long H2;
	unsigned long H3;
	unsigned long H4;
	unsigned long H5;
	unsigned long H6;
	unsigned long H7;
	unsigned long H8;
	struct
	{
		unsigned int len;
		unsigned char buf[64];
	} leftover;
    unsigned long hbits;
    unsigned long lbits;
} SHA256_CTX;

/* Exported functions */
#ifdef __cplusplus
extern "C" {
#endif
void SHA256Init(SHA256_CTX* ctx);
void SHA256Update(SHA256_CTX* ctx, unsigned char* buffer, unsigned long len);
void SHA256Final(unsigned char digest[32], SHA256_CTX* ctx);
#ifdef __cplusplus
}
#endif

#endif /* __SHA256_H */


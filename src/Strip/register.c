#ifdef NOPILOT
#include "posix_compat.h"
#else
#include <PalmOS.h>
#endif

#include "sha256_driver.h"
#include "hex2bin.h"
#include "register.h"

const char *getCode(char *email) {
	md_hash hash_out;
	static byte out[SMALLBLOCK + 1];
	byte *data;
	int datalen = sizeof(md_hash) + StrLen(email) + StrLen(REG_SALT_Q);
	int i, j, outsize, block;

	outsize = sizeof(md_hash) / REG_REDUCTIONS;

	MemSet(out, sizeof(out), 0);
	
	data = MemPtrNew(datalen);
	MemSet(data, datalen, 0);
	MemMove(data + sizeof(md_hash), email, StrLen(email));
	MemMove(data + sizeof(md_hash) + StrLen(email), REG_SALT_Q, StrLen(REG_SALT_Q));

	for(i=0; i < REG_ITERATIONS; i++) {	
		MemSet(hash_out, sizeof(md_hash), 0);
		md_block(data, datalen, hash_out);
		MemMove(data, hash_out, sizeof(md_hash));
	}

	for(i=1; i <= REG_REDUCTIONS; i++) {
		block = sizeof(md_hash) / i / 2;
		for(j=0; j < block; j++) {
			data[j] ^= data[j+block];
		}	
	}

	bin2hex(data, out, SMALLBLOCK);
	MemPtrFree(data);
	return out;
}



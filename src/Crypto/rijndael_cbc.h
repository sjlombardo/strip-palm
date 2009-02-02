#ifndef RIJNDAEL_CBC_H
#define RIJNDAEL_CBC_H

#include "types.h"

int rijndael_cbc_init( CBC_BUFFER* buf, void *IV);
int rijndael_cbc_encrypt( CBC_BUFFER* buf, void *plaintext, int len, void* akey);
int rijndael_cbc_decrypt( CBC_BUFFER* buf, void *ciphertext, int len, void* akey);

#endif

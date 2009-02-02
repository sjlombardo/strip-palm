
#ifndef TYPES_H
#define TYPES_H

#define MD_DIGESTSIZE 32

typedef unsigned char byte;
typedef byte md_hash[MD_DIGESTSIZE];

typedef unsigned long word32;
typedef unsigned char word8;

typedef struct cbc_buf {
    word32 previous_ciphertext[4];
    word32 previous_plaintext[4];
    word32 previous_cipher[4];
} CBC_BUFFER;

#endif

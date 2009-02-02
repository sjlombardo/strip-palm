
#ifndef CRYPT_H
#define CRYPT_H

#define rotl32(x,n)   (((x) << ((word32)(n))) | ((x) >> (32 - (word32)(n))))
#define rotr32(x,n)   (((x) >> ((word32)(n))) | ((x) << (32 - (word32)(n))))

#define STRIP_CBC

#endif

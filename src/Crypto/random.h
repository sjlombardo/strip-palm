
#ifndef RAND_H
#define RAND_H

#include "types.h"
#define POOL_SIZE 2047

int  random_bytes_created();
int  random_bytes_used();
int  random_bytes_available();
void random_seed(byte * , int length);
void random_bytes(byte * , int length);
void random_clean();

#endif

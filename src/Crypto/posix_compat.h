
#ifndef POSIX_COMPAT_H
#define POSIX_COMPAT_H

#define MemPtrNew(len)					malloc(len)
//#define MemMove(ptr1,ptr2,len)  memmove(ptr1,ptr2,len)
#define MemMove(ptr1,ptr2,len)  memcpy(ptr1,ptr2,len)
#define MemSet(ptr,len,val)     memset(ptr,val,len)
#define StrLen(str)             strlen(str)
#define MemPtrFree(ptr)					free(ptr)
#define StrNCompare(str1, str2, len)	strncmp(str1, str2, len)	
#endif


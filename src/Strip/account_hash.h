#ifndef ACCOUNT_HASH_H
#define ACCOUNT_HASH_H
#include "strip_types.h"
#include "types.h"

md_hash * generateAccountHash (Account *acct);
void replaceAccountHash(UInt16 index, DmOpenRef db, md_hash * SysPass);
void replaceAllAccountHashes(DmOpenRef db, md_hash * SysPass);

#endif

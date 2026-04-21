#ifndef _DOLPHIN_OSRTCPRIV
#define _DOLPHIN_OSRTCPRIV

#include <dolphin/os/OSRtc.h>

void __OSInitSram();
OSSram *__OSLockSram();
BOOL __OSSyncSram();
BOOL __OSUnlockSram(BOOL commit);
OSSramEx *__OSLockSramEx();

#endif // _DOLPHIN_OSRTCPRIV

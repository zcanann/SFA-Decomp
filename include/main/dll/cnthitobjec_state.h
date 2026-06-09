#ifndef MAIN_DLL_CNTHITOBJEC_STATE_H_
#define MAIN_DLL_CNTHITOBJEC_STATE_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct CntHitObjectFlags {
    u8 disabled : 1;
    u8 pad : 7;
} CntHitObjectFlags;

typedef struct CntHitObjectState {
    int remainingHealth;
    int allowedHitSources;
    u8 allowedHitSourceCount;
    CntHitObjectFlags flags;
    u8 padA[0xC - 0xA];
} CntHitObjectState;

STATIC_ASSERT(offsetof(CntHitObjectState, allowedHitSources) == 0x04);
STATIC_ASSERT(offsetof(CntHitObjectState, allowedHitSourceCount) == 0x08);
STATIC_ASSERT(offsetof(CntHitObjectState, flags) == 0x09);
STATIC_ASSERT(sizeof(CntHitObjectState) == 0x0C);

#endif /* MAIN_DLL_CNTHITOBJEC_STATE_H_ */

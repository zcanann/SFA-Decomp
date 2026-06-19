#ifndef MAIN_DLL_DFPTORCHSTATE_STRUCT_H_
#define MAIN_DLL_DFPTORCHSTATE_STRUCT_H_

#include "types.h"

typedef struct DfpTorchState
{
    int gameBit; /* lit-state gamebit, -1 = none (def+0x1E) */
    s16 flickerTimer; /* 0x04 */
    s16 litTimer; /* 0x06: 0x7D0 countdown while lit */
    u8 visibleLatch; /* 0x08 */
    u8 mode; /* 0x09: def+0x19 */
    u8 lit; /* 0x0A */
    u8 sfxPending; /* 0x0B */
    u8 prevLit; /* 0x0C */
    u8 colorIdx; /* 0x0D: def+0x1C */
    u8 unk0E[2];
} DfpTorchState;


/* extern-cleanup: consolidated prototypes */
void fn_80202EF0(int obj, int p2);

#endif

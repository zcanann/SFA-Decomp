#ifndef MAIN_DLL_DBSH_TYPES_H_
#define MAIN_DLL_DBSH_TYPES_H_

#include "types.h"

typedef struct DbshSymbolFlags
{
    u8 finished : 1;
    u8 active : 1;
} DbshSymbolFlags;

typedef struct DbshSymbolState
{
    void* partnerObj; /* nearest objType-0x20F symbol, spun in mirror */
    f32 spinSpeed;
    f32 sfxTimerB; /* object creak sfx 0x4A3 */
    f32 sfxTimerA; /* player grunt sfx 0x13A */
    int spinProgress; /* 0..0x7EF4 = fully turned */
    int prevSpinProgress;
    int triggerHandle;
    u8 pad1C[2];
    s16 phase; /* update: 0 hide, 1 scuff, 2 arm trigger, 3 resolve */
    DbshSymbolFlags flags;
    u8 pad21[3];
} DbshSymbolState;

#endif

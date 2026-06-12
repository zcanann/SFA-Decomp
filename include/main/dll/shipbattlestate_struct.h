#ifndef MAIN_DLL_SHIPBATTLESTATE_STRUCT_H_
#define MAIN_DLL_SHIPBATTLESTATE_STRUCT_H_

#include "types.h"

typedef struct ShipBattleState
{
    u8 unk00[0x24];
    f32 unk24; /* lbl/(lbl + def[0x24]) damping factor */
    int unk28; /* -1 at init */
    u8 unk2C[0x6A - 0x2C];
    s16 unk6A; /* def+0x1A */
    u8 pad6C[2];
    s16 unk6E; /* -1 at init */
    u8 unk70[0x140 - 0x70];
} ShipBattleState;

#endif

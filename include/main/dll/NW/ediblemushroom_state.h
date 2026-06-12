#ifndef MAIN_DLL_NW_EDIBLEMUSHROOM_STATE_H_
#define MAIN_DLL_NW_EDIBLEMUSHROOM_STATE_H_

#include "global.h"

typedef struct EdiblemushroomState
{
    u8 pad0[0x68 - 0x0];
    f32 unk68;
    u8 pad6C[0x70 - 0x6C];
    f32 unk70;
    u8 pad74[0x108 - 0x74];
    f32 unk108;
    f32 unk10C;
    f32 unk110;
    f32 unk114;
    f32 unk118;
    f32 unk11C;
    f32 unk120;
    u8 pad124[0x134 - 0x124];
    s16 eventId;
    u8 unk136;
    u8 unk137;
} EdiblemushroomState;

#endif

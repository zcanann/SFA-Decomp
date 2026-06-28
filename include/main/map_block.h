#ifndef MAIN_MAP_BLOCK_H_
#define MAIN_MAP_BLOCK_H_

#include "global.h"

/*
 * MapBlockData - the record returned by mapGetBlock(). Field widths
 * mirror the deref widths observed in mmp_barrel.c / mmp_moonrock.c /
 * track_dolphin.c; unobserved ranges are padded (positional unkNN
 * names, true size unverified - do not take sizeof).
 */
typedef struct MapBlockData {
    u8 pad0[0x4 - 0x0];
    u16 unk4;
    u8 pad6[0xC - 0x6];
    s32 unkC;
    s32 allocHandle;
    u16 unk14;
    u8 pad16[0x30 - 0x16];
    s32 flags;
    u8 pad34[0x58 - 0x34];
    s32 unk58;
    u8 pad5C[0x90 - 0x5C];
    u16 unk90;
    u8 pad92[0x9A - 0x92];
    u16 unk9A;
    u8 pad9C[0xA1 - 0x9C];
    u8 unkA1;
    u8 unkA2;
    u8 padA3;
} MapBlockData;

#endif

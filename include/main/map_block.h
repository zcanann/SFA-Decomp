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
    u16 flags4; /* 0x04: block-state bits; bit 8 = block loaded, bit 1 toggled per tick */
    u8 pad6[0xC - 0x6];
    s32 unkC;
    s32 allocHandle;
    u16 unk14;
    u8 pad16[0x30 - 0x16];
    s32 flags;
    u8 pad34[0x58 - 0x34];
    s32 vertices; /* 0x58: base of the VertexS16 array (stride 6), walked by index*6 */
    u8 pad5C[0x90 - 0x5C];
    u16 vertexCount; /* 0x90: entries in the vertices array (DCStoreRange size = count*6) */
    u8 pad92[0x9A - 0x92];
    u16 polyGroupCount; /* 0x9A: render/poly groups (mapBlockFn_800606ec index bound) */
    u8 pad9C[0xA1 - 0x9C];
    u8 edgeCount; /* 0xA1: edges (fn_800606FC -> EdgeVerts index bound) */
    u8 layerCount; /* 0xA2: shader layers (fn_8006070C index bound) */
    u8 padA3;
} MapBlockData;

#endif

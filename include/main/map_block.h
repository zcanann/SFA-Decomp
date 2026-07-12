#ifndef MAIN_MAP_BLOCK_H_
#define MAIN_MAP_BLOCK_H_

#include "global.h"

/*
 * MapBlockData - the record returned by mapGetBlock(). Field widths
 * mirror the deref widths observed in mmp_barrel.c / mmp_moonrock.c /
 * track_dolphin.c; unobserved ranges are padded (positional unkNN
 * names, true size unverified - do not take sizeof).
 */
typedef struct MapShader
{
    u8 pad0[0x3C];
    u32 flags;
    u8 pad40;
    u8 layerCount;
    u8 pad42[2];
} MapShader;

STATIC_ASSERT(sizeof(MapShader) == 0x44);
STATIC_ASSERT(offsetof(MapShader, flags) == 0x3C);
STATIC_ASSERT(offsetof(MapShader, layerCount) == 0x41);

typedef struct MapBlockData {
    u8 pad0[0x4 - 0x0];
    u16 flags4; /* 0x04: block-state bits; bit 8 = block loaded, bit 1 toggled per tick */
    u8 pad6[0xC - 0x6];
    s32 shadowTexHeader; /* 0x0C: pointer to the block's projected-shadow texture header; passed to objectShadow_setup(Swapped)ProjectedTexture, deref +0x60 (GX tex handle vs textureFn_8006c5c4), +0x64 (u8 fill alpha), +0x65 (u8==0xff special-draw select) in track_dolphin.c */
    s32 allocHandle;
    u16 unk14;
    u8 pad16[0x30 - 0x16];
    s32 flags;
    u8 pad34[0x4C - 0x34];
    void* gcPolygons; /* 0x4C: MapTriIndex[] collision mesh (stride 8), count = nPolygons @0x98 */
    void* polygonGroups; /* 0x50: MapTriGroup[] (stride 0x14), count = polyGroupCount @0x9A */
    void* textures; /* 0x54: texture IDs */
    s32 vertices; /* 0x58: base of the VertexS16 array (stride 6), walked by index*6 */
    void* vertexColors; /* 0x5C: RGBA4444 (stride 2) */
    void* vertexTexCoords; /* 0x60: vec2s (stride 4) */
    MapShader* shaders; /* 0x64: count = layerCount @0xA2 */
    void* displayLists; /* 0x68: MapBlockBoundsRec[] (stride 0x1C), count = edgeCount @0xA1 */
    u8 pad6C[0x70 - 0x6C];
    void* hits; /* 0x70: from HITS.bin; 0 in file, populated by MapBlock_initHits */
    u8 pad74[0x78 - 0x74];
    void* renderInstrsMain; /* 0x78: normal geometry bitstream */
    void* renderInstrsTransp; /* 0x7C: transparent+glow bitstream */
    void* renderInstrsWater; /* 0x80: water+reflective bitstream */
    u16 nRenderInstrsMain; /* 0x84: stream size in bytes */
    u16 nRenderInstrsTransp; /* 0x86 */
    u16 nRenderInstrsWater; /* 0x88 */
    u8 pad8A[0x90 - 0x8A];
    u16 vertexCount; /* 0x90: entries in the vertices array (DCStoreRange size = count*6) */
    u8 pad92[0x98 - 0x92];
    u16 nPolygons; /* 0x98: entries in gcPolygons (cacheAllocAndCopy size = count<<3) */
    u16 polyGroupCount; /* 0x9A: render/poly groups (mapBlockFn_800606ec index bound) */
    u8 pad9C[0xA1 - 0x9C];
    u8 edgeCount; /* 0xA1: edges (fn_800606FC -> EdgeVerts index bound) */
    u8 layerCount; /* 0xA2: shader layers (fn_8006070C index bound) */
    u8 padA3;
} MapBlockData;

MapShader* fn_8006070C(MapBlockData* block, int index);

#endif

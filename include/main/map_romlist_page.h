#ifndef MAIN_MAP_ROMLIST_PAGE_H_
#define MAIN_MAP_ROMLIST_PAGE_H_

#include "game/objects/object_setup.h"

typedef struct MapRomListPage
{
    s16 sizeX;
    s16 sizeZ;
    s16 originX;
    s16 originZ;
    u16 objectDataSize;
    u8 unk0A[0x02];
    u32* cells;
    s8* loadedObjectBits;
    u32* cellRects;
    u8 unk18;
    u8 mapLayer;
    u8 unk1A[0x06];
    ObjPlacement* objects;
    f32 worldX;
    f32 worldZ;
    u32* layerRects;
    u32* visCellRects;
    u32* visLayerRects;
} MapRomListPage;

STATIC_ASSERT(offsetof(MapRomListPage, objectDataSize) == 0x08);
STATIC_ASSERT(offsetof(MapRomListPage, cells) == 0x0C);
STATIC_ASSERT(offsetof(MapRomListPage, loadedObjectBits) == 0x10);
STATIC_ASSERT(offsetof(MapRomListPage, cellRects) == 0x14);
STATIC_ASSERT(offsetof(MapRomListPage, layerRects) == 0x2C);
STATIC_ASSERT(offsetof(MapRomListPage, visCellRects) == 0x30);
STATIC_ASSERT(offsetof(MapRomListPage, visLayerRects) == 0x34);
STATIC_ASSERT(offsetof(MapRomListPage, objects) == 0x20);
STATIC_ASSERT(offsetof(MapRomListPage, worldX) == 0x24);
STATIC_ASSERT(offsetof(MapRomListPage, worldZ) == 0x28);
STATIC_ASSERT(sizeof(MapRomListPage) == 0x38);

typedef struct MapRomListIndex
{
    int groupOffset[32];
    int objectsSize;
    int curvesOffset;
    int groupsStart;
} MapRomListIndex;

STATIC_ASSERT(offsetof(MapRomListIndex, objectsSize) == 0x80);
STATIC_ASSERT(offsetof(MapRomListIndex, curvesOffset) == 0x84);
STATIC_ASSERT(offsetof(MapRomListIndex, groupsStart) == 0x88);
STATIC_ASSERT(sizeof(MapRomListIndex) == 0x8C);

#endif /* MAIN_MAP_ROMLIST_PAGE_H_ */

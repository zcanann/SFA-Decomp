#ifndef MAIN_COLLISION_POLYGON_H_
#define MAIN_COLLISION_POLYGON_H_

#include "global.h"

/* Shared model/map polygon group. The next group's firstTri closes this range. */
typedef struct CollisionPolygonGroup {
    u16 firstTri;
    s16 minX;
    s16 maxX;
    s16 minY;
    s16 maxY;
    s16 minZ;
    s16 maxZ;
    u8 unk0E[2];
    u32 flags;
} CollisionPolygonGroup;

STATIC_ASSERT(sizeof(CollisionPolygonGroup) == 0x14);
STATIC_ASSERT(offsetof(CollisionPolygonGroup, firstTri) == 0x00);
STATIC_ASSERT(offsetof(CollisionPolygonGroup, minX) == 0x02);
STATIC_ASSERT(offsetof(CollisionPolygonGroup, maxX) == 0x04);
STATIC_ASSERT(offsetof(CollisionPolygonGroup, minY) == 0x06);
STATIC_ASSERT(offsetof(CollisionPolygonGroup, maxY) == 0x08);
STATIC_ASSERT(offsetof(CollisionPolygonGroup, minZ) == 0x0A);
STATIC_ASSERT(offsetof(CollisionPolygonGroup, maxZ) == 0x0C);
STATIC_ASSERT(offsetof(CollisionPolygonGroup, flags) == 0x10);

#endif

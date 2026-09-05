#ifndef MAIN_DLL_OBJFSA_INTERNAL_H_
#define MAIN_DLL_OBJFSA_INTERNAL_H_

#include "global.h"
#include "main/dll/objfsa.h"
#include "types.h"

#define OBJFSA_PATCHGROUP_STRIDE        0x28
#define OBJFSA_ACTIVE_WALKGROUPS_OFFSET 0x4C48
#define OBJFSA_WALKGROUP_COUNT          0xB5

extern int gObjfsaPatchCount;
extern u8 gObjfsaWalkGroupActive[];

typedef struct ObjfsaPatchPlane {
    s16 normalX;
    s16 normalZ;
} ObjfsaPatchPlane;

STATIC_ASSERT(sizeof(ObjfsaPatchPlane) == 4);
STATIC_ASSERT(offsetof(ObjfsaPatchPlane, normalX) == 0);
STATIC_ASSERT(offsetof(ObjfsaPatchPlane, normalZ) == 2);

typedef struct ObjfsaPatch {
    union {
        ObjfsaPatchPlane planes[OBJFSA_PATCHGROUP_PATCH_COUNT];
        s16 normalComponents[OBJFSA_PATCHGROUP_PATCH_COUNT * 2];
    };
    f32 planeOffsets[OBJFSA_PATCHGROUP_PATCH_COUNT];
    s16 maxY;
    s16 minY;
    u16 groupId;
    s16 exit0X;
    s16 exit0Z;
    s16 exit1X;
    s16 exit1Z;
    u8 pad2E[2];
} ObjfsaPatch;

STATIC_ASSERT(sizeof(ObjfsaPatch) == 0x30);
STATIC_ASSERT(offsetof(ObjfsaPatch, planes) == 0);
STATIC_ASSERT(offsetof(ObjfsaPatch, normalComponents) == 0);
STATIC_ASSERT(offsetof(ObjfsaPatch, planeOffsets) == 0x10);
STATIC_ASSERT(offsetof(ObjfsaPatch, maxY) == 0x20);
STATIC_ASSERT(offsetof(ObjfsaPatch, minY) == 0x22);
STATIC_ASSERT(offsetof(ObjfsaPatch, groupId) == 0x24);

typedef struct ObjfsaWalkGroup
{
    ObjfsaPatchPlane planes[OBJFSA_PATCHGROUP_PATCH_COUNT];
    f32 planeOffsets[OBJFSA_PATCHGROUP_PATCH_COUNT];
    s16 maxY;
    s16 minY;
    u8 patchIndices[OBJFSA_PATCHGROUP_PATCH_COUNT];
} ObjfsaWalkGroup;

extern ObjfsaPatch gObjfsaPatches[256];
extern ObjfsaWalkGroup gObjfsaWalkGroups[OBJFSA_WALKGROUP_COUNT];

typedef struct ObjfsaStorage
{
    ObjfsaPatch patches[256];
    ObjfsaWalkGroup walkGroups[OBJFSA_WALKGROUP_COUNT];
    u8 activeWalkGroups[OBJFSA_WALKGROUP_COUNT];
} ObjfsaStorage;

STATIC_ASSERT(offsetof(ObjfsaStorage, walkGroups) == 0x3000);
STATIC_ASSERT(offsetof(ObjfsaStorage, activeWalkGroups) == OBJFSA_ACTIVE_WALKGROUPS_OFFSET);
STATIC_ASSERT(sizeof(ObjfsaStorage) == 0x4D00);

/* Type 0x26 curve records carry the walk-group outline after the common
 * RomCurveDef prefix.  Each linked edge has a pair of X/Z corner offsets. */
typedef struct ObjfsaWalkCurveDef
{
    u8 pad00[3];
    u8 walkGroup;
    s8 firstEdge[4];
    f32 x;
    f32 y;
    f32 z;
    u32 id;
    s8 maxYExtent;
    s8 type;
    s8 minYExtent;
    u8 pad1B;
    s32 linkIds[4];
    u8 pad2C[4];
    s8 secondEdge[4];
    s8 linkEdges[4][4];
} ObjfsaWalkCurveDef;

STATIC_ASSERT(offsetof(ObjfsaWalkCurveDef, walkGroup) == 0x3);
STATIC_ASSERT(offsetof(ObjfsaWalkCurveDef, linkIds) == 0x1C);
STATIC_ASSERT(offsetof(ObjfsaWalkCurveDef, linkEdges) == 0x34);

#endif /* MAIN_DLL_OBJFSA_INTERNAL_H_ */

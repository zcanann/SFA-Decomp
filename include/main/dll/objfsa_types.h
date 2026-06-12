#ifndef MAIN_DLL_OBJFSA_TYPES_H_
#define MAIN_DLL_OBJFSA_TYPES_H_

#include "types.h"

typedef struct ObjfsaPatchPlane
{
    s16 normalX;
    s16 normalZ;
} ObjfsaPatchPlane;

typedef struct ObjfsaPatch
{
    ObjfsaPatchPlane planes[OBJFSA_PATCHGROUP_PATCH_COUNT];
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

typedef struct ObjfsaWalkGroup
{
    ObjfsaPatchPlane planes[OBJFSA_PATCHGROUP_PATCH_COUNT];
    f32 planeOffsets[OBJFSA_PATCHGROUP_PATCH_COUNT];
    s16 maxY;
    s16 minY;
    u8 patchIndices[OBJFSA_PATCHGROUP_PATCH_COUNT];
} ObjfsaWalkGroup;

#endif

#ifndef MAIN_DLL_OBJFSA_QUERY_API_H_
#define MAIN_DLL_OBJFSA_QUERY_API_H_

#include "types.h"
#include "global.h"

#define OBJFSA_PATCHGROUP_PATCH_COUNT 4

typedef struct ObjfsaWalkGroupPatchInfo {
    u8 walkGroupIndex;
    u8 patchMask;
    u16 patchGroupIds[OBJFSA_PATCHGROUP_PATCH_COUNT];
} ObjfsaWalkGroupPatchInfo;

STATIC_ASSERT(sizeof(ObjfsaWalkGroupPatchInfo) == 0x0A);
STATIC_ASSERT(offsetof(ObjfsaWalkGroupPatchInfo, walkGroupIndex) == 0x00);
STATIC_ASSERT(offsetof(ObjfsaWalkGroupPatchInfo, patchMask) == 0x01);
STATIC_ASSERT(offsetof(ObjfsaWalkGroupPatchInfo, patchGroupIds) == 0x02);
STATIC_ASSERT(sizeof(((ObjfsaWalkGroupPatchInfo*)0)->patchGroupIds) == 0x08);

/* A zero return leaves patchInfo untouched. */
int Objfsa_GetWalkGroupIndexAtPoint(f32* point, ObjfsaWalkGroupPatchInfo* patchInfo);

#endif /* MAIN_DLL_OBJFSA_QUERY_API_H_ */

#ifndef MAIN_DLL_DLL_0269_EXPLODEPLAN_H_
#define MAIN_DLL_DLL_0269_EXPLODEPLAN_H_

#include "global.h"
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/obj_placement.h"

/* opaque per-instance extra state; no field is read or written by this DLL */
typedef struct ExplodePlanState
{
    u8 reserved[0x4];
} ExplodePlanState;

/* explodeplan placement record (tail past the common ObjPlacement head) */
typedef struct ExplodePlanPlacement
{
    ObjPlacement base;
    s8 rotX; /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1E - 0x19];
    s16 removeGameBit; /* 0x1E: game bit that removes this prop */
} ExplodePlanPlacement;

STATIC_ASSERT(offsetof(ExplodePlanPlacement, rotX) == 0x18);
STATIC_ASSERT(offsetof(ExplodePlanPlacement, removeGameBit) == 0x1E);
STATIC_ASSERT(sizeof(ExplodePlanPlacement) == 0x20);


int explodeplan_getExtraSize(void);
int explodeplan_getObjectTypeId(void);
void explodeplan_free(void);
void explodeplan_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void explodeplan_hitDetect(void);
void explodeplan_update(GameObject* obj);
void explodeplan_init(GameObject* obj, ExplodePlanPlacement* placement);
void explodeplan_release(void);
void explodeplan_initialise(void);

extern ObjectDescriptor gExplodePlanObjDescriptor;

#endif /* MAIN_DLL_DLL_0269_EXPLODEPLAN_H_ */

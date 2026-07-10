#ifndef MAIN_DLL_DLL_0269_EXPLODEPLAN_H_
#define MAIN_DLL_DLL_0269_EXPLODEPLAN_H_

#include "global.h"
#include "main/game_object.h"

/* opaque per-instance extra state; no field is read or written by this DLL */
typedef struct ExplodePlanState
{
    u8 pad0[0x4];
} ExplodePlanState;

/* explodeplan placement record (tail past the common ObjPlacement head) */
typedef struct ExplodePlanPlacement
{
    u8 pad0[0x18];
    s8 rotXByte; /* 0x18: rotX in 1/256 turns */
    u8 pad19[0x1E - 0x19];
    s16 removeGameBit; /* 0x1E: game bit that removes this prop */
} ExplodePlanPlacement;

STATIC_ASSERT(offsetof(ExplodePlanPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(ExplodePlanPlacement, removeGameBit) == 0x1E);
STATIC_ASSERT(sizeof(ExplodePlanPlacement) == 0x20);

int explodeplan_getExtraSize(void);
int explodeplan_getObjectTypeId(void);
void explodeplan_free(void);
void explodeplan_render(void* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible);
void explodeplan_hitDetect(void);
void explodeplan_update(GameObject* obj);
void explodeplan_init(GameObject* obj, char* arg);
void explodeplan_release(void);
void explodeplan_initialise(void);

#endif /* MAIN_DLL_DLL_0269_EXPLODEPLAN_H_ */

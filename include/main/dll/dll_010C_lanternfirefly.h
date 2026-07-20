#ifndef MAIN_DLL_DLL_010C_LANTERNFIREFLY_H_
#define MAIN_DLL_DLL_010C_LANTERNFIREFLY_H_

#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/dll/CF/lanternfirefly_state.h"

/* FireFlyLantern allocates this exact 0x24-byte setup for its children. */
typedef struct LanternFireFlyPlacement {
    ObjPlacement base; /* 0x00 */
    s8 wanderRange;    /* 0x18 */
    u8 stateId;        /* 0x19 */
    s16 timer;         /* 0x1A active lifetime */
    s16 driftRangeZ;   /* 0x1C Z drift distance */
    u8 unk1E[0x24 - 0x1E];
} LanternFireFlyPlacement;

STATIC_ASSERT(offsetof(LanternFireFlyPlacement, wanderRange) == 0x18);
STATIC_ASSERT(offsetof(LanternFireFlyPlacement, timer) == 0x1A);
STATIC_ASSERT(offsetof(LanternFireFlyPlacement, driftRangeZ) == 0x1C);
STATIC_ASSERT(sizeof(LanternFireFlyPlacement) == 0x24);

int LanternFireFly_getExtraSize(void);
int LanternFireFly_getObjectTypeId(void);
void LanternFireFly_free(GameObject* obj, int flag);
void LanternFireFly_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void LanternFireFly_hitDetect(void);
void LanternFireFly_update(GameObject* obj);
void LanternFireFly_init(GameObject* obj, LanternFireFlyPlacement* placement);
void LanternFireFly_release(void);
void LanternFireFly_initialise(void);
void LanternFireFly_setScale(GameObject* obj, f32* vec);
void LanternFireFly_func0B(GameObject* obj);
void LanternFireFly_modelMtxFn(GameObject* obj, f32 anchorX, f32 anchorY, f32 anchorZ);
void LanternFireFly_pickDriftOffset(GameObject* obj);
void LanternFireFly_advanceControlRing(GameObject* obj);

#endif /* MAIN_DLL_DLL_010C_LANTERNFIREFLY_H_ */

#ifndef MAIN_DLL_WM_DLL_0207_WMWORM_H_
#define MAIN_DLL_WM_DLL_0207_WMWORM_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct WmWormSetup
{
    ObjPlacement base;
    s8 effectScale;
    u8 pad19;
    s16 particleEffectId;
    s16 burstCount;
} WmWormSetup;

typedef struct WmWormState
{
    f32 effectScale;
    s16 particleEffectId;
    u8 pad06[2];
    s16 burstCount;
    u8 pad0A[2];
    s16 unk0C;
    u8 pad0E[2];
    f32 homeX;
    f32 homeY;
    f32 homeZ;
} WmWormState;

STATIC_ASSERT(offsetof(WmWormSetup, effectScale) == 0x18);
STATIC_ASSERT(offsetof(WmWormSetup, particleEffectId) == 0x1a);
STATIC_ASSERT(offsetof(WmWormSetup, burstCount) == 0x1c);
STATIC_ASSERT(sizeof(WmWormState) == 0x1c);
STATIC_ASSERT(offsetof(WmWormState, particleEffectId) == 0x04);
STATIC_ASSERT(offsetof(WmWormState, burstCount) == 0x08);
STATIC_ASSERT(offsetof(WmWormState, unk0C) == 0x0c);
STATIC_ASSERT(offsetof(WmWormState, homeX) == 0x10);

void WM_Worm_update(GameObject* obj);
void WM_Worm_init(GameObject* obj, WmWormSetup* setup);
void WM_Worm_release(void);
void WM_Worm_initialise(void);

void fn_801F3F18(GameObject* obj);
int WM_LevelControl_getExtraSize(void);
int WM_LevelControl_getObjectTypeId(void);
void WM_LevelControl_free(int obj);
void WM_LevelControl_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void WM_LevelControl_hitDetect(void);

#endif /* MAIN_DLL_WM_DLL_0207_WMWORM_H_ */

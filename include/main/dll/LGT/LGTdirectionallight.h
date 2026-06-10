#ifndef MAIN_DLL_LGT_LGTDIRECTIONALLIGHT_H_
#define MAIN_DLL_LGT_LGTDIRECTIONALLIGHT_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct WmWormSetup {
    ObjPlacement base;
    s8 effectScale;
    u8 pad19;
    s16 particleEffectId;
    s16 burstCount;
} WmWormSetup;

typedef struct WmWormState {
    f32 effectScale;
    s16 particleEffectId;
    u8 pad06[2];
    s16 burstCount;
    u8 pad0A[2];
    s16 bool0C;
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
STATIC_ASSERT(offsetof(WmWormState, bool0C) == 0x0c);
STATIC_ASSERT(offsetof(WmWormState, homeX) == 0x10);

void wmworm_update(GameObject *obj);
void wmworm_init(GameObject *obj, WmWormSetup *setup);
void wmworm_release(void);
void wmworm_initialise(void);

void fn_801F3F18(int obj);
int wmlevelcontrol_getExtraSize(void);
int wmlevelcontrol_getObjectTypeId(void);
void wmlevelcontrol_free(int obj);
void wmlevelcontrol_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void wmlevelcontrol_hitDetect(void);

#endif /* MAIN_DLL_LGT_LGTDIRECTIONALLIGHT_H_ */

#ifndef MAIN_DLL_WC_DLL_0290_WCPUSHBLOCK_H_
#define MAIN_DLL_WC_DLL_0290_WCPUSHBLOCK_H_

#include "global.h"
#include "main/game_object.h"
#include "main/obj_placement.h"

typedef struct PushBlockFlags
{
    u8 phase : 3;
    u8 sfxActive : 1;
    u8 pad : 4;
} PushBlockFlags;

typedef struct WCPushBlockSetup
{
    ObjPlacement base;
    u8 unk18;
    u8 modelIndex;
    s16 initialTile;
    u8 pad1C[0x24 - 0x1C];
} WCPushBlockSetup;

typedef struct WCPushBlockRuntimeState
{
    u8 pad00[0x268];
    GameObject* controller;
    f32 targetX;
    f32 targetZ;
    f32 baseY;
    f32 bobY;
    u16 bobAngle;
    s16 tileX;
    s16 tileY;
    u8 pushDir;
    u8 initialTile;
    u8 moveResult;
    PushBlockFlags flags;
    u8 pad286[2];
} WCPushBlockRuntimeState;

STATIC_ASSERT(sizeof(PushBlockFlags) == 1);
STATIC_ASSERT(sizeof(WCPushBlockRuntimeState) == 0x288);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, controller) == 0x268);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, targetX) == 0x26C);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, targetZ) == 0x270);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, baseY) == 0x274);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, bobY) == 0x278);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, bobAngle) == 0x27C);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, tileX) == 0x27E);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, tileY) == 0x280);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, pushDir) == 0x282);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, initialTile) == 0x283);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, moveResult) == 0x284);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, flags) == 0x285);
STATIC_ASSERT(sizeof(WCPushBlockSetup) == 0x24);
STATIC_ASSERT(offsetof(WCPushBlockSetup, base.posY) == 0x0C);
STATIC_ASSERT(offsetof(WCPushBlockSetup, modelIndex) == 0x19);
STATIC_ASSERT(offsetof(WCPushBlockSetup, initialTile) == 0x1A);

extern f32 gWcPushBlockControllerSearchRange;
extern f32 lbl_803E6D5C;
extern f32 lbl_803E6D60;
extern f32 lbl_803E6D64;
extern f32 lbl_803E6D68;
extern f32 lbl_803E6D6C;
extern f32 lbl_803E6D70;
extern f32 gWcPushBlockSlideSfxMaxVolume;
extern f32 lbl_803E6D78;
extern f32 gWcPushBlockMaxSlideSpeed;
extern f32 gWcPushBlockSlideAccel;
extern f32 gWcPushBlockMinSlideSpeed;
extern f32 gWcPushBlockBobAngleSpeed;
extern f32 gWcPushBlockBobAmplitude;
extern f32 gWcPushBlockPi;
extern f32 gWcPushBlockAngleScale;

int wcpushblock_getExtraSize(void);
int wcpushblock_getObjectTypeId(GameObject* obj);
void wcpushblock_free(void);
void wcpushblock_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void wcpushblock_hitDetect(void);
void wcpushblock_init(GameObject* obj, WCPushBlockSetup* setup);
void wcpushblock_release(void);
void wcpushblock_initialise(void);
void wcpushblock_update(GameObject* obj);

#endif /* MAIN_DLL_WC_DLL_0290_WCPUSHBLOCK_H_ */

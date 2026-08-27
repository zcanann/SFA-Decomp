#ifndef MAIN_DLL_WC_DLL_0290_WCPUSHBLOCK_H_
#define MAIN_DLL_WC_DLL_0290_WCPUSHBLOCK_H_

#include "global.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/dll/WC/wc_block_state.h"

#define WCPUSHBLOCK_GAMEBIT_A_SOLVED 0x812
#define WCPUSHBLOCK_GAMEBIT_A_FADE   0x808
#define WCPUSHBLOCK_GAMEBIT_A_COUNT  0x810
#define WCPUSHBLOCK_GAMEBIT_B_SOLVED 0x813
#define WCPUSHBLOCK_GAMEBIT_B_FADE   0x809
#define WCPUSHBLOCK_GAMEBIT_B_COUNT  0x811

typedef struct PushBlockFlags {
    u8 phase : 3;
    u8 sfxActive : 1;
    u8 pad : 4;
} PushBlockFlags;

typedef struct WCPushBlockSetup {
    ObjPlacement base;
    u8 unk18;
    s8 modelIndex;
    s16 initialTile;
    u8 pad1C[0x24 - 0x1C];
} WCPushBlockSetup;

typedef struct WCPushBlockRuntimeState {
    WCBlockState block;
    u8 moveResult;
    PushBlockFlags flags;
    u8 pad286[2];
} WCPushBlockRuntimeState;

STATIC_ASSERT(sizeof(PushBlockFlags) == 1);
STATIC_ASSERT(sizeof(WCPushBlockRuntimeState) == 0x288);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, block.controller) == 0x268);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, block.targetX) == 0x26C);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, block.targetZ) == 0x270);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, block.baseY) == 0x274);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, block.bobY) == 0x278);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, block.bobAngle) == 0x27C);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, block.cellX) == 0x27E);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, block.cellZ) == 0x280);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, block.pushDir) == 0x282);
STATIC_ASSERT(offsetof(WCPushBlockRuntimeState, block.tileIndex) == 0x283);
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
extern f32 gWcPushBlockSlideSfxVolumeRange;
extern f32 gWcPushBlockSlideSfxMaxSpeed;
extern f32 gWcPushBlockSlideSfxMaxVolume;
extern f32 lbl_803E6D78;
extern f32 gWcPushBlockMaxSlideSpeed;
extern f32 gWcPushBlockSlideAccel;
extern f32 gWcPushBlockMinSlideSpeed;
extern f32 gWcPushBlockBobAngleSpeed;
extern f32 gWcPushBlockBobAmplitude;
extern f32 gWcPushBlockPi;
extern f32 gWcPushBlockAngleScale;
extern f32 lbl_803E6D54;

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

#ifndef DLLS_OBJECTS_213_KALDACHOM_H_
#define DLLS_OBJECTS_213_KALDACHOM_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/dll/baddie_state.h"

typedef struct KaldachomPlacement {
    ObjPlacement base;     /* 0x00 */
    u8 pad18[0x28 - 0x18]; /* 0x18 */
    s8 scale;              /* 0x28 */
    u8 pad29[0x2F - 0x29]; /* 0x29 */
    u8 aggroChance;        /* 0x2F */
} KaldachomPlacement;

typedef struct KaldachomControl {
    GameObject* spawnedDustObj; /* 0x00 */
    u8 pad04[0x10 - 0x04];      /* 0x04 */
    f32 upperMouthPosX;         /* 0x10 */
    f32 upperMouthPosY;         /* 0x14 */
    f32 upperMouthPosZ;         /* 0x18 */
    u8 pad1C[0x28 - 0x1C];      /* 0x1C */
    f32 lowerMouthPosX;         /* 0x28 */
    f32 lowerMouthPosY;         /* 0x2C */
    f32 lowerMouthPosZ;         /* 0x30 */
    f32 pullupSfxTimer;         /* 0x34 */
    f32 idleAnimTimer;          /* 0x38 */
    f32 unk3C;                  /* 0x3C */
    f32 hitFlashTimer;          /* 0x40 */
    f32 returnStateTimer;       /* 0x44 */
    s16 textureScrollAngle;     /* 0x48 */
    u8 climbFxIndex;            /* 0x4A */
    u8 soundFlags;              /* 0x4B */
} KaldachomControl;

typedef int (*KaldachomStateHandler)(GameObject* obj, GroundBaddieState* state);

typedef struct KaldachomState {
    GroundBaddieState ground;
    KaldachomControl controlData; /* 0x410 */
} KaldachomState;

STATIC_ASSERT(offsetof(KaldachomPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(KaldachomPlacement, scale) == 0x28);
STATIC_ASSERT(offsetof(KaldachomPlacement, aggroChance) == 0x2F);
STATIC_ASSERT(sizeof(KaldachomPlacement) == 0x30);

STATIC_ASSERT(offsetof(KaldachomControl, spawnedDustObj) == 0x0);
STATIC_ASSERT(offsetof(KaldachomControl, upperMouthPosX) == 0x10);
STATIC_ASSERT(offsetof(KaldachomControl, upperMouthPosY) == 0x14);
STATIC_ASSERT(offsetof(KaldachomControl, upperMouthPosZ) == 0x18);
STATIC_ASSERT(offsetof(KaldachomControl, lowerMouthPosX) == 0x28);
STATIC_ASSERT(offsetof(KaldachomControl, lowerMouthPosY) == 0x2C);
STATIC_ASSERT(offsetof(KaldachomControl, lowerMouthPosZ) == 0x30);
STATIC_ASSERT(offsetof(KaldachomControl, pullupSfxTimer) == 0x34);
STATIC_ASSERT(offsetof(KaldachomControl, idleAnimTimer) == 0x38);
STATIC_ASSERT(offsetof(KaldachomControl, unk3C) == 0x3C);
STATIC_ASSERT(offsetof(KaldachomControl, hitFlashTimer) == 0x40);
STATIC_ASSERT(offsetof(KaldachomControl, returnStateTimer) == 0x44);
STATIC_ASSERT(offsetof(KaldachomControl, textureScrollAngle) == 0x48);
STATIC_ASSERT(offsetof(KaldachomControl, climbFxIndex) == 0x4A);
STATIC_ASSERT(offsetof(KaldachomControl, soundFlags) == 0x4B);
STATIC_ASSERT(sizeof(KaldachomControl) == 0x4C);

STATIC_ASSERT(offsetof(KaldachomState, ground) == 0x0);
STATIC_ASSERT(offsetof(KaldachomState, controlData) == 0x410);
STATIC_ASSERT(sizeof(KaldachomState) == 0x45C);

int kaldachom_stateHandlerB05(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerB04(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerB03(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerB02(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerB01(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerB00(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerA07(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerA06(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerA05(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerA04(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerA03(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerA02(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerA01(GameObject* obj, GroundBaddieState* state);
int kaldachom_stateHandlerA00(GameObject* obj, GroundBaddieState* state);

void kaldachom_spawnDustEffects(GameObject* obj, KaldachomControl* control);
void kaldachom_spawnMouthProjectile(GameObject* obj, KaldachomState* state, u8 useUpperMouthPoint);
void kaldachom_handleAnimEvents(GameObject* obj, KaldachomState* objectState, GroundBaddieState* state);
void kaldachom_updateCombat(GameObject* obj, GroundBaddieState* objectStateAddress, GroundBaddieState* stateAddress);
void kaldachom_func0B(void);
s16 kaldachom_getControlMode(GameObject* obj);
int kaldachom_getExtraSize(void);
int kaldachom_getObjectTypeId(void);
void kaldachom_free(GameObject* obj);
void kaldachom_render(GameObject* obj, int fwdArg2, int fwdArg3, int fwdArg4, int fwdArg5, s8 visible);
void kaldachom_hitDetect(GameObject* obj);
void kaldachom_update(GameObject* obj);
void kaldachom_init(GameObject* obj, KaldachomPlacement* placement, int flags);
void kaldachom_release(void);
void kaldachom_initialise(void);

extern s16 gKaldachomMoves[6];
extern f32 gKaldachomMoveSpeeds[5];
extern KaldachomStateHandler gKaldachomStateHandlersA[8];
extern KaldachomStateHandler gKaldachomStateHandlersB[6];
extern ObjectDescriptor12 gKaldachomObjDescriptor;

#endif /* DLLS_OBJECTS_213_KALDACHOM_H_ */

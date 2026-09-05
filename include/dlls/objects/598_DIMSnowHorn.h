#ifndef DLLS_OBJECTS_598_DIMSNOWHORN_H_
#define DLLS_OBJECTS_598_DIMSNOWHORN_H_

#include "game/objects/object.h"
#include "global.h"
#include "types.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_002E_moveLib.h"
#include "main/objseq.h"
#include "dlls/object_descriptor.h"

typedef struct SnowHornEntry {
    f32 posX;
    f32 posY;
    f32 posZ;
    s16 rotX;
    u8 padE[2];
    f32 altPosX;
    f32 altPosY;
    f32 altPosZ;
    s16 altRotX;
    u16 altPoseGameBit;
    u16 flipRotGameBit;
    u8 pad22[2];
} SnowHornEntry;

STATIC_ASSERT(sizeof(SnowHornEntry) == 0x24);

typedef struct DIMSnowHorn1Placement {
    ObjPlacement base;
    s8 spawnRot;
    u8 spawnVariant;
} DIMSnowHorn1Placement;

STATIC_ASSERT(offsetof(DIMSnowHorn1Placement, spawnRot) == 0x18);

/* Per-object extra state (getExtraSize == 0xD0C); BaddieState is the prefix. */
typedef struct DIMSnowHorn1State {
    BaddieState baddie;
    MoveLibState lookController; /* 0x35C: dll_2E look-controller block */
    CharacterEyeAnimState
        eyeAnimState; /* 0x980: head-aim / eye-blink record (characterDoEyeAnims / characterHeadLookCalm / characterHeadLookRelax) */
    u8 pad9A8[0x9B0 - 0x9A8];
    f32 pathPointArray[12]; /* 0x9B0: ObjPath_GetPointWorldPositionArray(2,4) -> 4 XYZ points */
    u8 pad9E0[0x9E8 - 0x9E0];
    f32 pathPosX; /* model-matrix offset vec */
    f32 pathPosY;
    f32 pathPosZ;
    u8 pad9F4[0xA84 - 0x9F4];
    s16 countdownTimer;
    s16 advanceCountThreshold; /* 0xA86: push-count at state+0x334 must reach this (=5) to advance state */
    s16 airMeterValue;
    u8 mountMode; /* 0=unmounted, 2=riding */
    u8 padA8B;
    u8 mode;
    u8 triggerMode;
    u8 flags; /* 0xA8E: bit0x2 riding (GAMEBIT_NW_SnowHorn03E3), bit0x8 hitvol-priority, bit0x20 sequence-triggered */
    u8 dismountSide;   /* 0xA8F: nonzero = side 2; set cross-DLL */
    u8 mountSide;      /* 0xA90: nonzero = side 1; set cross-DLL */
    u8 proximityPhase; /* 0xA91: 0/1/2 phase toggling linked objects by player distance (stateHandler05) */
    u8 padA92[2];
    f32 hitReactStepScale;
    u8 padA98[0xD00 - 0xA98];
    u8 hitReactState; /* 0xD00: ObjHitReact_Update persistent state (in/out), gates characterHeadLookRelax */
    u8 padD01[3];
    f32 randomTimerD04;
    f32 randomTimerD08;
} DIMSnowHorn1State;

STATIC_ASSERT(sizeof(DIMSnowHorn1State) == 0xD0C);
STATIC_ASSERT(offsetof(DIMSnowHorn1State, countdownTimer) == 0xA84);

typedef struct DIMSnowHorn1PieceCounts {
    u8 counts[4];
} DIMSnowHorn1PieceCounts;

STATIC_ASSERT(sizeof(DIMSnowHorn1PieceCounts) == 4);

extern f32 gDIMSnowHorn1LocomotionSpeedRanges[];
extern s16 gDIMSnowHorn1MoveIds[2];
extern f32 gDIMSnowHorn1MoveSpeeds[2];
extern s16 gDIMSnowHorn1LocomotionMoveIds[4];

extern f32 gDIMSnowHorn1ModelMtx[16];
extern void* gDIMSnowHorn1DefaultStateHandler;
extern void* gDIMSnowHorn1StateHandlers[];
extern u8 gDIMSnowHorn1ConfigTable[];
extern void* gDIMSnowHorn1Texture;
extern s16 gDIMSnowHorn1TextureId;
extern f32 gDIMSnowHorn1PathCollisionData[2];

void DIMSnowHorn1_func23(void);
int DIMSnowHorn1_defaultStateHandler(void);
int DIMSnowHorn1_stateHandler04(GameObject* obj, DIMSnowHorn1State* state);
int DIMSnowHorn1_stateHandler00(GameObject* obj);
int DIMSnowHorn1_stateHandler02(GameObject* obj, DIMSnowHorn1State* state, f32 fv);
int DIMSnowHorn1_stateHandler03(GameObject* obj, DIMSnowHorn1State* state);
int DIMSnowHorn1_stateHandler01(GameObject* obj, DIMSnowHorn1State* state, f32 fv);
int DIMSnowHorn1_stateHandler0B(GameObject* obj, DIMSnowHorn1State* state);
int DIMSnowHorn1_stateHandler09(GameObject* obj, DIMSnowHorn1State* state, f32 fv);
int DIMSnowHorn1_stateHandler08(GameObject* obj, DIMSnowHorn1State* state);
int DIMSnowHorn1_stateHandler07(GameObject* obj, DIMSnowHorn1State* state);
int DIMSnowHorn1_stateHandler06(GameObject* obj, DIMSnowHorn1State* state);
int DIMSnowHorn1_stateHandler05(GameObject* obj, DIMSnowHorn1State* state);
int DIMSnowHorn1_stateHandler0A(GameObject* obj, DIMSnowHorn1State* state, f32 t);
void DIMSnowHorn1_func21(void);
int DIMSnowHorn1_getRacePosition(void);
f32 DIMSnowHorn1_func19(GameObject* obj, f32* out);
void DIMSnowHorn1_getPlayerAnim(void* unused, f32* out_f, int* out_i);
void DIMSnowHorn1_setMountState(GameObject* obj, int value);
int DIMSnowHorn1_getMountState(void);
void DIMSnowHorn1_getCameraPosition(GameObject* obj, f32* outX, f32* outY, f32* outZ);
int DIMSnowHorn1_getDismountSide(GameObject* obj);
int DIMSnowHorn1_canDismount(GameObject* obj);
void DIMSnowHorn1_getRiderPosition(GameObject* obj, f32* out_x, f32* out_y, f32* out_z);
int DIMSnowHorn1_getMountSide(GameObject* obj);
int DIMSnowHorn1_animEventCallback(GameObject* obj, int unused, ObjSeqState* animUpdate);
void DIMSnowHorn1_handleRiderScale(GameObject* obj, f32 scale);
int DIMSnowHorn1_canMount(GameObject* obj);
int DIMSnowHorn1_getExtraSize(void);
int DIMSnowHorn1_getObjectTypeId(void);
void DIMSnowHorn1_free(GameObject* obj);
void DIMSnowHorn1_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void DIMSnowHorn1_hitDetect(void);
void DIMSnowHorn1_spawnFootstepEffects(void* obj, DIMSnowHorn1State* pointState, DIMSnowHorn1State* inputState);
void DIMSnowHorn1_ridingUpdate(GameObject* obj, int frameStep, int slot);
void DIMSnowHorn1_update(GameObject* obj);
void DIMSnowHorn1_release(void);
void DIMSnowHorn1_initialise(void);
void DIMSnowHorn1_init(GameObject* obj, DIMSnowHorn1Placement* p2, int p3);

extern ObjectDescriptor24 gDIMSnowHorn1ObjDescriptor;

#endif /* DLLS_OBJECTS_598_DIMSNOWHORN_H_ */

#ifndef MAIN_DLL_DR_DLL_0258_DRCLOUDRUNNER_H_
#define MAIN_DLL_DR_DLL_0258_DRCLOUDRUNNER_H_

#include "game/objects/object.h"
#include "global.h"
#include "main/vec_types.h"
#include "main/objseq.h"
#include "main/dll/DR/cloudrunner_state.h"
#include "game/objects/object_setup.h"

typedef enum DRCloudRunnerObjectId {
    DR_CLOUDRUNNER_OBJECT_ID = 1049,
} DRCloudRunnerObjectId;

/* placement record passed to init / read by the state handlers */
typedef struct DRCloudRunnerPlacement {
    ObjPlacement base;
    s8 spawnRot;          /* 0x18: initial facing, shifted left 8 into anim.rotX */
    u8 spawnVariant;      /* 0x19: -> CloudRunnerState.spawnVariant */
    s16 airMeterCapacity; /* 0x1A: initial air meter capacity -> CloudRunnerState.airTimeRemaining */
    s16 pathSpeedTenths;  /* 0x1C: rom-curve follow speed in tenths -> CloudRunnerState.pathFollowSpeed */
    s16 enableGameBit;    /* 0x1E: game bit that enables the mount */
} DRCloudRunnerPlacement;

STATIC_ASSERT(offsetof(DRCloudRunnerPlacement, spawnRot) == 0x18);
STATIC_ASSERT(offsetof(DRCloudRunnerPlacement, airMeterCapacity) == 0x1A);
STATIC_ASSERT(offsetof(DRCloudRunnerPlacement, enableGameBit) == 0x1E);

typedef struct DRCloudRunnerMoveParams {
    u8 unk00[12];
    Vec3f pathPointsA;
    Vec3f pathCollisionA;
    Vec3f pathPointsB;
    Vec3f pathCollisionB;
    Vec3f pathPointsC;
    Vec3f pathCollisionC;
    Vec3f unk54;
    s16 moveIds[6];
    s16 pitchAngles[6];
    f32 unk78[6];
    f32 inputScaleX[3];
    f32 inputScaleZ[3];
    f32 speedMax[3];
    f32 speedMin[3];
    f32 moveSpeeds[4];
} DRCloudRunnerMoveParams;

STATIC_ASSERT(sizeof(DRCloudRunnerMoveParams) == 0xD0);
STATIC_ASSERT(offsetof(DRCloudRunnerMoveParams, moveIds) == 0x60);
STATIC_ASSERT(offsetof(DRCloudRunnerMoveParams, inputScaleX) == 0x90);
STATIC_ASSERT(offsetof(DRCloudRunnerMoveParams, moveSpeeds) == 0xC0);

extern void* gDRCloudRunnerStateHandlers[];
extern void* gDRCloudRunnerDefaultStateHandler;
extern s16 gDRCloudRunnerDefaultRotX;
extern s16 gDRCloudRunnerHeadingAngleOffset;
extern s16 gDRCloudRunnerSmoothedRotX;
extern const s16 gDRCloudRunnerGameBitIds[4];
extern const int gDRCloudRunnerCurveIds[4];
extern DRCloudRunnerMoveParams gDRCloudRunnerMoveParamTable;
extern int gDRCloudRunnerAirMeterBaseline;
extern const Vec3f gDRCloudRunnerVecTable[];
extern s16 gDRCloudRunnerRollAngleLimits;

extern char sOnCloudFormat[];

extern int lbl_803DC770;
extern int lbl_803DC774;
extern int lbl_803DC778;
extern int lbl_803DC77C;
extern int lbl_803DC780;
extern int lbl_803DC784;
extern f32 lbl_803DC78C;
extern f32 lbl_803DC790;

int DR_CloudRunner_defaultStateHandler(void);
void DR_CloudRunner_func21(void);
int DR_CloudRunner_getRacePosition(void);
int DR_CloudRunner_getMountState(void);
int DR_CloudRunner_canDismount(void);
int DR_CloudRunner_canMount(void);
int DR_CloudRunner_getExtraSize(void);
int DR_CloudRunner_getObjectTypeId(void);
void DR_CloudRunner_release(void);
f32 DR_CloudRunner_func19(int obj, f32* out);
void DR_CloudRunner_getPlayerAnim(int obj, f32* a, int* b);
int DR_CloudRunner_getMountSide(GameObject* obj);
void DR_CloudRunner_handleRiderScale(GameObject* obj);
int DR_CloudRunner_getDismountSide(GameObject* obj);
void DR_CloudRunner_getRiderPosition(GameObject* obj, f32* x, f32* y, f32* z);
int DR_CloudRunner_stateHandler07(GameObject* obj);
int DR_CloudRunner_stateHandler00(GameObject* obj);
int DR_CloudRunner_stateHandler01(GameObject* obj, CloudRunnerState* state);
int DR_CloudRunner_stateHandler02(GameObject* obj, CloudRunnerState* state);
int DR_CloudRunner_stateHandler03(GameObject* obj, CloudRunnerState* state);
int DR_CloudRunner_stateHandler04(GameObject* obj, CloudRunnerState* state);
int DR_CloudRunner_stateHandler05(GameObject* obj, CloudRunnerState* state, f32 value);
int DR_CloudRunner_stateHandler06(GameObject* obj, CloudRunnerState* state);
void DR_CloudRunner_free(GameObject* obj);
void DR_CloudRunner_initialise(void);
void DR_CloudRunner_render(GameObject* p1, int p2, int p3, int p4, int p5, s8 vis);
void DR_CloudRunner_setMountState(GameObject* obj, int param);
int DR_CloudRunner_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
void DR_CloudRunner_getCameraPosition(GameObject* obj, f32* a, f32* b, f32* c);
void DR_CloudRunner_init(GameObject* obj, DRCloudRunnerPlacement* p2);
void DR_CloudRunner_func23(GameObject* obj, int mode, int* out);
void DR_CloudRunner_hitDetect(GameObject* obj);
void DR_CloudRunner_update(GameObject* obj);
void DR_CloudRunner_setupPath(GameObject* obj, CloudRunnerState* state, int mode);
void DR_CloudRunner_fireProjectile(GameObject* obj);

#endif /* MAIN_DLL_DR_DLL_0258_DRCLOUDRUNNER_H_ */

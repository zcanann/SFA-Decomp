#ifndef DLLS_OBJECTS_601_SB_CLOUDRUN_H_
#define DLLS_OBJECTS_601_SB_CLOUDRUN_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object.h"
#include "main/objseq.h"
#include "types.h"

typedef struct SBCloudRunnerState SBCloudRunnerState;
typedef struct SBCloudRunnerRideState SBCloudRunnerRideState;

/* Obj_AllocObjectSetup allocates 0x18 bytes for the spawned object 0x119. */
typedef struct SBCloudRunnerBurstSetup {
    u8 pad0[4];
    u8 placementMode;
    u8 group;
    u8 linkA;
    u8 linkB;
    f32 x;
    f32 y;
    f32 z;
    u8 pad14[4];
} SBCloudRunnerBurstSetup;

struct SBCloudRunnerRideState {
    u8 pad0[0x10];
    void* targetObj;
    u8 pad14[0x18];
    s16 cloudYawDrift;
    s16 rotZAccum;
    u8 pad30[0x30];
    f32 liftAmount;
    u8 pad64;
    s8 rideState;
    u8 pad66[4];
    s16 rotorAngle;
    u8 pad6C[4];
    int stickX;
    int stickY;
    f32 bankAmount;
    f32 liftBase;
};

struct SBCloudRunnerState {
    f32 riderPosition[3];
    u8 pad0C[4];
    GameObject* targetObj; /* 0x10: laser-locked target (object type 0x8E) */
    void* resource;        /* 0x14: acquired resource handle */
    void* texture0;        /* 0x18 */
    void* texture1;        /* 0x1C */
    u8 pad20[0x2C - 0x20];
    s16 rotXAccum; /* 0x2C: roll accumulator, biased into anim.rotX */
    s16 rotZ;      /* 0x2E: integrated body roll */
    u8 pad30[0x4C - 0x30];
    f32 spawnPosX;     /* 0x4C */
    f32 spawnPosY;     /* 0x50 */
    f32 spawnPosZ;     /* 0x54 */
    f32 tiltY;         /* 0x58: banking integrator (Y) */
    f32 tiltZ;         /* 0x5C: banking integrator (Z) */
    f32 steerSmoothed; /* 0x60: smoothed FX heading */
    s8 burstCooldown;  /* 0x64: frames until next A-burst allowed */
    s8 rideSubState;   /* 0x65: 0=ride, 1=tilt, 2/3=dismount */
    u8 pad66[0x6C - 0x66];
    s16 rideFrames; /* 0x6C: frames in current rideSubState */
    s8 done;        /* 0x6E: ride finished, hide object */
    u8 pad6F[0x70 - 0x6F];
    s32 stickX;         /* 0x70 */
    s32 stickY;         /* 0x74 */
    f32 steerX;         /* 0x78 */
    f32 steerZ;         /* 0x7C */
    u8 aButtonHeld : 1; /* 0x80: A held last frame */
    u8 pad80 : 7;
};

STATIC_ASSERT(offsetof(SBCloudRunnerState, riderPosition) == 0x00);
STATIC_ASSERT(offsetof(SBCloudRunnerState, pad0C) == 0x0C);
STATIC_ASSERT(offsetof(SBCloudRunnerState, targetObj) == 0x10);
STATIC_ASSERT(offsetof(SBCloudRunnerState, resource) == 0x14);
STATIC_ASSERT(offsetof(SBCloudRunnerState, texture0) == 0x18);
STATIC_ASSERT(offsetof(SBCloudRunnerState, texture1) == 0x1C);
STATIC_ASSERT(offsetof(SBCloudRunnerState, rotXAccum) == 0x2C);
STATIC_ASSERT(offsetof(SBCloudRunnerState, rotZ) == 0x2E);
STATIC_ASSERT(offsetof(SBCloudRunnerState, spawnPosX) == 0x4C);
STATIC_ASSERT(offsetof(SBCloudRunnerState, tiltY) == 0x58);
STATIC_ASSERT(offsetof(SBCloudRunnerState, steerSmoothed) == 0x60);
STATIC_ASSERT(offsetof(SBCloudRunnerState, burstCooldown) == 0x64);
STATIC_ASSERT(offsetof(SBCloudRunnerState, rideSubState) == 0x65);
STATIC_ASSERT(offsetof(SBCloudRunnerState, rideFrames) == 0x6C);
STATIC_ASSERT(offsetof(SBCloudRunnerState, done) == 0x6E);
STATIC_ASSERT(offsetof(SBCloudRunnerState, stickX) == 0x70);
STATIC_ASSERT(offsetof(SBCloudRunnerState, steerX) == 0x78);
STATIC_ASSERT(sizeof(SBCloudRunnerState) == 0x84);

STATIC_ASSERT(sizeof(SBCloudRunnerBurstSetup) == 0x18);
STATIC_ASSERT(offsetof(SBCloudRunnerBurstSetup, placementMode) == 0x04);
STATIC_ASSERT(offsetof(SBCloudRunnerBurstSetup, group) == 0x05);
STATIC_ASSERT(offsetof(SBCloudRunnerBurstSetup, linkA) == 0x06);
STATIC_ASSERT(offsetof(SBCloudRunnerBurstSetup, linkB) == 0x07);
STATIC_ASSERT(offsetof(SBCloudRunnerBurstSetup, x) == 0x08);
STATIC_ASSERT(offsetof(SBCloudRunnerBurstSetup, y) == 0x0C);
STATIC_ASSERT(offsetof(SBCloudRunnerBurstSetup, z) == 0x10);
STATIC_ASSERT(offsetof(SBCloudRunnerBurstSetup, pad14) == 0x14);

typedef struct {
    u8 pad[0x1b];
    s8 sfxFlag;
} WCAnimEvents;

struct WCPartfxArgs {
    s16 v[3];
    s16 _pad;
    f32 scale;
};

void SB_CloudRunner_onSeqFree(GameObject* obj);
void SB_CloudRunner_SpawnFromPath(GameObject* path, u8* unusedState);
void SB_CloudRunner_UpdateCloudAction(GameObject* obj, SBCloudRunnerRideState* state);
void SB_CloudRunner_UpdateRideTilt(GameObject* obj, SBCloudRunnerRideState* state);
void SB_CloudRunner_UpdateSteer(GameObject* obj, SBCloudRunnerState* state);
int SB_CloudRunner_SeqFn(GameObject* obj, int unused, ObjSeqState* animUpdate);
void SB_CloudRunner_HandlePriorityHit(GameObject* obj, SBCloudRunnerState* state);
int SB_CloudRunner_getTargetMode(GameObject* obj);
void SB_CloudRunner_getSpawnPos(GameObject* obj, f32* x, f32* y, f32* z);
void SB_CloudRunner_func23(void);
void SB_CloudRunner_handleRiderScale(void* obj);
void SB_CloudRunner_func21(void);
int SB_CloudRunner_getRacePosition(void);
f32 SB_CloudRunner_func19(int unused, f32* p);
void SB_CloudRunner_getPlayerAnim(int obj, f32* out, int* outInt);
void SB_CloudRunner_setMountState(void);
int SB_CloudRunner_getMountState(void);
void SB_CloudRunner_getCameraPosition(GameObject* src, f32* out_x, f32* out_y, f32* out_z);
int SB_CloudRunner_getDismountSide(void);
int SB_CloudRunner_canDismount(void);
void SB_CloudRunner_getRiderPosition(GameObject* obj, f32* x, f32* y, f32* z);
int SB_CloudRunner_getMountSide(void);
int SB_CloudRunner_canMount(void);
int SB_CloudRunner_getExtraSize(void);
int SB_CloudRunner_getObjectTypeId(void);
void SB_CloudRunner_free(GameObject* obj);
void SB_CloudRunner_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void SB_CloudRunner_hitDetect(void);
void SB_CloudRunner_update(GameObject* obj);
void SB_CloudRunner_init(GameObject* obj);
void SB_CloudRunner_release(void);
void SB_CloudRunner_initialise(void);

extern ObjectDescriptor24 gSB_CloudRunnerObjDescriptor;

#endif

#ifndef DLLS_OBJECTS_318_H_
#define DLLS_OBJECTS_318_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/dll/curves_collision_state.h"

typedef enum DimBossIceSmashPlacementFlag {
    DIM_BOSS_ICE_SMASH_PLACEMENT_HOMING = 0x01,
    DIM_BOSS_ICE_SMASH_PLACEMENT_PATH_CONTROL = 0x02,
    DIM_BOSS_ICE_SMASH_PLACEMENT_TRAIL_PARTICLES = 0x04,
} DimBossIceSmashPlacementFlag;

typedef enum DimBossIceSmashStateFlag {
    DIM_BOSS_ICE_SMASH_STATE_ACTIVE = 0x01,
    DIM_BOSS_ICE_SMASH_STATE_FINISHED = 0x02,
} DimBossIceSmashStateFlag;

typedef enum DimBossIceSmashDirectionFlag {
    DIM_BOSS_ICE_SMASH_POSITIVE_VELOCITY_X = 0x01,
    DIM_BOSS_ICE_SMASH_POSITIVE_VELOCITY_Z = 0x02,
    DIM_BOSS_ICE_SMASH_POSITIVE_ANGULAR_VELOCITY_X = 0x04,
    DIM_BOSS_ICE_SMASH_POSITIVE_ANGULAR_VELOCITY_Y = 0x08,
    DIM_BOSS_ICE_SMASH_POSITIVE_ANGULAR_VELOCITY_Z = 0x10,
} DimBossIceSmashDirectionFlag;

/*
 * The setup fields through homingTargetZ are evidenced by this TU. The
 * complete record extent after 0x47 is not yet proven.
 */
typedef struct DimBossIceSmashPlacement {
    ObjPlacement base;   /* 0x00 */
    u8 bankIndex;        /* 0x18 */
    u8 pad19;            /* 0x19 */
    s16 spawnRotX;       /* 0x1A */
    s16 spawnRotY;       /* 0x1C */
    s16 spawnRotZ;       /* 0x1E */
    s16 velocityX;       /* 0x20 */
    s16 velocityY;       /* 0x22 */
    s16 velocityZ;       /* 0x24 */
    s16 gravityX;        /* 0x26 */
    s16 gravityY;        /* 0x28 */
    s16 gravityZ;        /* 0x2A */
    s16 rotVelX;         /* 0x2C */
    s16 rotVelY;         /* 0x2E */
    s16 rotVelZ;         /* 0x30 */
    s16 rotGravityX;     /* 0x32 */
    s16 rotGravityY;     /* 0x34 */
    s16 rotGravityZ;     /* 0x36 */
    u16 lifetime;        /* 0x38 */
    u16 fadeStartFrame;  /* 0x3A */
    u8 flags;            /* 0x3C: DimBossIceSmashPlacementFlag */
    u8 pad3D;            /* 0x3D */
    s16 activateGameBit; /* 0x3E */
    s16 triggerGameBit;  /* 0x40 */
    s16 homingTargetX;   /* 0x42 */
    s16 homingTargetY;   /* 0x44 */
    s16 homingTargetZ;   /* 0x46 */
} DimBossIceSmashPlacement;

/* DIMBossIceSmash_getExtraSize proves the complete 0x2A0-byte allocation. */
typedef struct DimBossIceSmashState {
    CurvesCollisionState path; /* 0x000 */
    u8 pad268[4];              /* 0x268 */
    f32 spawnScaleX;           /* 0x26C */
    f32 spawnScaleY;           /* 0x270 */
    f32 spawnScaleZ;           /* 0x274 */
    f32 angVelX;               /* 0x278 */
    f32 angVelY;               /* 0x27C */
    f32 angVelZ;               /* 0x280 */
    f32 angAccelX;             /* 0x284 */
    f32 angAccelY;             /* 0x288 */
    f32 angAccelZ;             /* 0x28C */
    f32 accelX;                /* 0x290 */
    f32 accelY;                /* 0x294 */
    f32 accelZ;                /* 0x298 */
    s16 timer;                 /* 0x29C */
    u8 stateFlags;             /* 0x29E: DimBossIceSmashStateFlag */
    u8 directionFlags;         /* 0x29F: DimBossIceSmashDirectionFlag */
} DimBossIceSmashState;

STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, base) == 0x00);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, bankIndex) == 0x18);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, pad19) == 0x19);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, spawnRotX) == 0x1A);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, spawnRotY) == 0x1C);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, spawnRotZ) == 0x1E);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, velocityX) == 0x20);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, velocityY) == 0x22);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, velocityZ) == 0x24);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, gravityX) == 0x26);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, gravityY) == 0x28);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, gravityZ) == 0x2A);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, rotVelX) == 0x2C);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, rotVelY) == 0x2E);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, rotVelZ) == 0x30);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, rotGravityX) == 0x32);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, rotGravityY) == 0x34);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, rotGravityZ) == 0x36);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, lifetime) == 0x38);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, fadeStartFrame) == 0x3A);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, flags) == 0x3C);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, pad3D) == 0x3D);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, activateGameBit) == 0x3E);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, triggerGameBit) == 0x40);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, homingTargetX) == 0x42);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, homingTargetY) == 0x44);
STATIC_ASSERT(offsetof(DimBossIceSmashPlacement, homingTargetZ) == 0x46);

STATIC_ASSERT(offsetof(DimBossIceSmashState, path) == 0x000);
STATIC_ASSERT(offsetof(DimBossIceSmashState, pad268) == 0x268);
STATIC_ASSERT(offsetof(DimBossIceSmashState, spawnScaleX) == 0x26C);
STATIC_ASSERT(offsetof(DimBossIceSmashState, spawnScaleY) == 0x270);
STATIC_ASSERT(offsetof(DimBossIceSmashState, spawnScaleZ) == 0x274);
STATIC_ASSERT(offsetof(DimBossIceSmashState, angVelX) == 0x278);
STATIC_ASSERT(offsetof(DimBossIceSmashState, angVelY) == 0x27C);
STATIC_ASSERT(offsetof(DimBossIceSmashState, angVelZ) == 0x280);
STATIC_ASSERT(offsetof(DimBossIceSmashState, angAccelX) == 0x284);
STATIC_ASSERT(offsetof(DimBossIceSmashState, angAccelY) == 0x288);
STATIC_ASSERT(offsetof(DimBossIceSmashState, angAccelZ) == 0x28C);
STATIC_ASSERT(offsetof(DimBossIceSmashState, accelX) == 0x290);
STATIC_ASSERT(offsetof(DimBossIceSmashState, accelY) == 0x294);
STATIC_ASSERT(offsetof(DimBossIceSmashState, accelZ) == 0x298);
STATIC_ASSERT(offsetof(DimBossIceSmashState, timer) == 0x29C);
STATIC_ASSERT(offsetof(DimBossIceSmashState, stateFlags) == 0x29E);
STATIC_ASSERT(offsetof(DimBossIceSmashState, directionFlags) == 0x29F);
STATIC_ASSERT(sizeof(DimBossIceSmashState) == 0x2A0);

void DIMBossIceSmash_initLaunchState(GameObject* obj, DimBossIceSmashState* state, DimBossIceSmashPlacement* placement);
int DIMBossIceSmash_getExtraSize(void);
u32 DIMBossIceSmash_getObjectTypeId(GameObject* obj);
void DIMBossIceSmash_free(GameObject* obj);
void DIMBossIceSmash_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5,
                            s8 visible);
void DIMBossIceSmash_hitDetect(void);
void DIMBossIceSmash_update(GameObject* obj);
void DIMBossIceSmash_init(GameObject* obj, DimBossIceSmashPlacement* placement);
void DIMBossIceSmash_release(void);
void DIMBossIceSmash_initialise(void);

extern ObjectDescriptor10WithPadding gDIMBossIceSmashObjDescriptor;

#endif /* DLLS_OBJECTS_318_H_ */

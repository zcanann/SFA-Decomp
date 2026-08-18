#ifndef DLLS_OBJECTS_426_BOMB_PLANT_SP_H_
#define DLLS_OBJECTS_426_BOMB_PLANT_SP_H_

#include "dlls/object_descriptor.h"
#include "main/dll/curves_collision_state.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/modellight_api.h"

#define BOMB_PLANT_SPORE_OBJECT_ID 0x198

typedef struct BombPlantSporeFlags {
    u8 hitSurface : 1;
    u8 waitingForDetonateAck : 1;
    u8 unknown : 6;
} BombPlantSporeFlags;

typedef struct BombPlantSporePlacement {
    ObjPlacement base;
    u8 unknown18[2];
    union {
        struct {
            s16 angleSpread;
            s16 baseAngle;
        } behavior;
        struct {
            s16 spawnYaw;
            s16 rotXSeed;
        } spawn;
    };
    u8 unknown1E[6];
} BombPlantSporePlacement;

typedef struct BombPlantSporeState {
    s16 pickupMsgBitId;
    s16 pickupMsgValue;
    f32 pickupMsgDelay;
    CurvesCollisionState path;
    ModelLightStruct* light;
    f32 fuseTimer;
    f32 driftAmplitude;
    f32 driftSpeed;
    f32 driftAmplitudeTarget;
    f32 driftTimer;
    f32 driftBaseX;
    f32 driftBaseZ;
    f32 driftSin;
    f32 driftCos;
    f32 spinTimer;
    f32 driftSpeedTarget;
    f32 spinChangeTimer;
    f32 detonateTimer;
    s16 currentSpinAngle;
    s16 burstDriftAngle;
    s16 spinAngle;
    s16 yawStep;
    BombPlantSporeFlags flags;
    u8 unknown2B1[3];
} BombPlantSporeState;

STATIC_ASSERT(sizeof(BombPlantSporePlacement) == 0x24);
STATIC_ASSERT(offsetof(BombPlantSporePlacement, base) == 0x00);
STATIC_ASSERT(offsetof(BombPlantSporePlacement, unknown18) == 0x18);
STATIC_ASSERT(offsetof(BombPlantSporePlacement, behavior.angleSpread) == 0x1A);
STATIC_ASSERT(offsetof(BombPlantSporePlacement, behavior.baseAngle) == 0x1C);
STATIC_ASSERT(offsetof(BombPlantSporePlacement, spawn.spawnYaw) == 0x1A);
STATIC_ASSERT(offsetof(BombPlantSporePlacement, spawn.rotXSeed) == 0x1C);
STATIC_ASSERT(offsetof(BombPlantSporePlacement, unknown1E) == 0x1E);

STATIC_ASSERT(sizeof(BombPlantSporeState) == 0x2B4);
STATIC_ASSERT(offsetof(BombPlantSporeState, pickupMsgBitId) == 0x000);
STATIC_ASSERT(offsetof(BombPlantSporeState, pickupMsgValue) == 0x002);
STATIC_ASSERT(offsetof(BombPlantSporeState, pickupMsgDelay) == 0x004);
STATIC_ASSERT(offsetof(BombPlantSporeState, path) == 0x008);
STATIC_ASSERT(offsetof(BombPlantSporeState, light) == 0x270);
STATIC_ASSERT(offsetof(BombPlantSporeState, fuseTimer) == 0x274);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftAmplitude) == 0x278);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftSpeed) == 0x27C);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftAmplitudeTarget) == 0x280);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftTimer) == 0x284);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftBaseX) == 0x288);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftBaseZ) == 0x28C);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftSin) == 0x290);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftCos) == 0x294);
STATIC_ASSERT(offsetof(BombPlantSporeState, spinTimer) == 0x298);
STATIC_ASSERT(offsetof(BombPlantSporeState, driftSpeedTarget) == 0x29C);
STATIC_ASSERT(offsetof(BombPlantSporeState, spinChangeTimer) == 0x2A0);
STATIC_ASSERT(offsetof(BombPlantSporeState, detonateTimer) == 0x2A4);
STATIC_ASSERT(offsetof(BombPlantSporeState, currentSpinAngle) == 0x2A8);
STATIC_ASSERT(offsetof(BombPlantSporeState, burstDriftAngle) == 0x2AA);
STATIC_ASSERT(offsetof(BombPlantSporeState, spinAngle) == 0x2AC);
STATIC_ASSERT(offsetof(BombPlantSporeState, yawStep) == 0x2AE);
STATIC_ASSERT(offsetof(BombPlantSporeState, flags) == 0x2B0);
STATIC_ASSERT(offsetof(BombPlantSporeState, unknown2B1) == 0x2B1);

int BombPlantSpore_getExtraSize(void);
void BombPlantSpore_free(GameObject* obj);
void BombPlantSpore_update(GameObject* obj);
void BombPlantSpore_init(GameObject* obj, BombPlantSporePlacement* placement);

extern ObjectDescriptor10WithPadding gBombPlantSporeObjDescriptor;

#endif /* DLLS_OBJECTS_426_BOMB_PLANT_SP_H_ */

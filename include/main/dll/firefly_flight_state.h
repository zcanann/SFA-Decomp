#ifndef MAIN_DLL_FIREFLY_FLIGHT_STATE_H_
#define MAIN_DLL_FIREFLY_FLIGHT_STATE_H_

#include "game/objects/object.h"
#include "global.h"

typedef union FireFlyFlightOwnerData {
    void* pointLight;
    u32 opaqueWord;
} FireFlyFlightOwnerData;

typedef struct FireFlyActiveBits {
    u8 active : 1;
} FireFlyActiveBits;

typedef struct FireFlyFlightState {
    FireFlyFlightOwnerData ownerData;
    f32 splineX[4];
    f32 splineY[4];
    f32 splineZ[4];
    f32 targetX;
    f32 targetY;
    f32 targetZ;
    f32 splineT;
    f32 splineSpeed;
    f32 proximityAlpha;
    f32 playerRadius;
    f32 radius;
    f32 posX;
    f32 posY;
    f32 posZ;
    s16 angle;
    s16 angleStep;
    s16 ampMax;
    u8 kind;
    u8 unk67;
    u8 pathAge;
    u8 pad69[2];
    u8 firstFrame;
    FireFlyActiveBits activeFlags;
    u8 pad6D[3];
    f32 despawnTimer;
    f32 lifeTimer;
    f32 unk78;
} FireFlyFlightState;

STATIC_ASSERT(sizeof(FireFlyFlightOwnerData) == 0x4);
STATIC_ASSERT(sizeof(FireFlyFlightState) == 0x7C);
STATIC_ASSERT(offsetof(FireFlyFlightState, ownerData) == 0x00);
STATIC_ASSERT(offsetof(FireFlyFlightState, splineX) == 0x04);
STATIC_ASSERT(offsetof(FireFlyFlightState, splineY) == 0x14);
STATIC_ASSERT(offsetof(FireFlyFlightState, splineZ) == 0x24);
STATIC_ASSERT(offsetof(FireFlyFlightState, targetX) == 0x34);
STATIC_ASSERT(offsetof(FireFlyFlightState, splineT) == 0x40);
STATIC_ASSERT(offsetof(FireFlyFlightState, radius) == 0x50);
STATIC_ASSERT(offsetof(FireFlyFlightState, angle) == 0x60);
STATIC_ASSERT(offsetof(FireFlyFlightState, kind) == 0x66);
STATIC_ASSERT(offsetof(FireFlyFlightState, pathAge) == 0x68);
STATIC_ASSERT(offsetof(FireFlyFlightState, firstFrame) == 0x6B);
STATIC_ASSERT(offsetof(FireFlyFlightState, activeFlags) == 0x6C);
STATIC_ASSERT(offsetof(FireFlyFlightState, despawnTimer) == 0x70);
STATIC_ASSERT(offsetof(FireFlyFlightState, lifeTimer) == 0x74);
STATIC_ASSERT(offsetof(FireFlyFlightState, unk78) == 0x78);

void firefly_initFlightRec(GameObject* obj, FireFlyFlightState* state);
void firefly_pickWanderTarget(GameObject* obj, FireFlyFlightState* state);
void firefly_shiftPathHistory(GameObject* obj, FireFlyFlightState* state);

#endif /* MAIN_DLL_FIREFLY_FLIGHT_STATE_H_ */

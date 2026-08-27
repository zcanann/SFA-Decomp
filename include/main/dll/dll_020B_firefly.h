#ifndef MAIN_DLL_DLL_020B_FIREFLY_H_
#define MAIN_DLL_DLL_020B_FIREFLY_H_

#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "global.h"
#include "main/dll/firefly_flight_state.h"

#define FIREFLY_EXTRA_SIZE 0x88

typedef struct FireFlyMapData {
    ObjPlacement base;
    u8 pad18[2];
    s16 variantParam; /* 0x1A: only 0x7F is read (arms the 3600-frame life timer) */
    u8 pad1C[0x20 - 0x1C];
    s16 requiredGameBit; /* 0x20: game bit gating activation (-1 = none) */
} FireFlyMapData;

typedef struct FireFlyState {
    FireFlyFlightState flight;
    u8 flags; /* 0x7C: player-touch latch */
    u8 pad7D[0x80 - 0x7D];
    s16 messageParam; /* 0x80: outparam for the talk message */
    u8 pad82[FIREFLY_EXTRA_SIZE - 0x82];
} FireFlyState;

STATIC_ASSERT(offsetof(FireFlyMapData, variantParam) == 0x1A);
STATIC_ASSERT(offsetof(FireFlyMapData, requiredGameBit) == 0x20);
STATIC_ASSERT(offsetof(FireFlyState, flight) == 0x00);
STATIC_ASSERT(offsetof(FireFlyState, flight.ownerData) == 0x00);
STATIC_ASSERT(offsetof(FireFlyState, flight.splineX) == 0x04);
STATIC_ASSERT(offsetof(FireFlyState, flight.targetX) == 0x34);
STATIC_ASSERT(offsetof(FireFlyState, flight.splineT) == 0x40);
STATIC_ASSERT(offsetof(FireFlyState, flight.radius) == 0x50);
STATIC_ASSERT(offsetof(FireFlyState, flight.angle) == 0x60);
STATIC_ASSERT(offsetof(FireFlyState, flight.kind) == 0x66);
STATIC_ASSERT(offsetof(FireFlyState, flight.firstFrame) == 0x6B);
STATIC_ASSERT(offsetof(FireFlyState, flight.activeFlags) == 0x6C);
STATIC_ASSERT(offsetof(FireFlyState, flight.despawnTimer) == 0x70);
STATIC_ASSERT(offsetof(FireFlyState, flight.lifeTimer) == 0x74);
STATIC_ASSERT(offsetof(FireFlyState, flight.unk78) == 0x78);
STATIC_ASSERT(offsetof(FireFlyState, flags) == 0x7C);
STATIC_ASSERT(offsetof(FireFlyState, messageParam) == 0x80);
STATIC_ASSERT(sizeof(FireFlyState) == FIREFLY_EXTRA_SIZE);

extern s16 gFireFlyDespawnThreshold;

void firefly_activeTick(GameObject* obj);
void firefly_free(GameObject* obj);
void firefly_update(GameObject* obj);
void firefly_init(GameObject* obj, FireFlyMapData* mapData);
int firefly_getExtraSize(void);
int firefly_getObjectTypeId(void);
void firefly_render(void);
void firefly_hitDetect(void);
void firefly_release(void);
void firefly_initialise(void);
int firefly_animEventCallback(GameObject* obj);

#endif /* MAIN_DLL_DLL_020B_FIREFLY_H_ */

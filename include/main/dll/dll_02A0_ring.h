#ifndef MAIN_DLL_DLL_02A0_RING_H
#define MAIN_DLL_DLL_02A0_RING_H

#include "global.h"
#include "game/objects/object.h"
#include "main/model_light.h"
#include "game/objects/object_setup.h"

typedef struct RingFlags
{
    u8 bIntangible : 1; //set when collected
    u8 bSpawnParticles : 1;
    u8 bMissed : 1; //triggers "missed a gold ring" text
    u8 bit10 : 1; //set for silver rings during Andross + WC rings
    u8 pad : 4;
} RingFlags;

typedef struct RingState
{
    u8 mode;
    u8 route;
    u16 linkId;
    f32 pullHeight;
    f32 origX;
    f32 origY;
    f32 arwingYOffset;
    RingFlags flags;
    u8 phase;
    u8 pad16[2];
    f32 pullTimer;
    u8 pad1C[4];
    ModelLightStruct* light;
} RingState;

typedef struct RingPlacement
{
    ObjPlacement base;
    s8 modeFlag;
    u8 route;
    s16 linkId;
    s16 pullHeight;
    s16 counterGameBit; /* 0x1E: score bit incremented when the ring is collected */
    s16 activateBit;
} RingPlacement;

typedef struct RingTable
{
    int spiralEffectId;
    int burstEffectId;
    int spiralAngleStep;
    int burstCount;
    int spinStep;
    f32 spiralPhaseSpeed;
} RingTable;

STATIC_ASSERT(sizeof(RingFlags) == 0x1);
STATIC_ASSERT(sizeof(RingState) == 0x24);
STATIC_ASSERT(offsetof(RingState, route) == 0x01);
STATIC_ASSERT(offsetof(RingState, linkId) == 0x02);
STATIC_ASSERT(offsetof(RingState, pullHeight) == 0x04);
STATIC_ASSERT(offsetof(RingState, origX) == 0x08);
STATIC_ASSERT(offsetof(RingState, origY) == 0x0C);
STATIC_ASSERT(offsetof(RingState, arwingYOffset) == 0x10);
STATIC_ASSERT(offsetof(RingState, flags) == 0x14);
STATIC_ASSERT(offsetof(RingState, phase) == 0x15);
STATIC_ASSERT(offsetof(RingState, pullTimer) == 0x18);
STATIC_ASSERT(offsetof(RingState, light) == 0x20);
STATIC_ASSERT(offsetof(RingPlacement, modeFlag) == 0x18);
STATIC_ASSERT(offsetof(RingPlacement, route) == 0x19);
STATIC_ASSERT(offsetof(RingPlacement, linkId) == 0x1A);
STATIC_ASSERT(offsetof(RingPlacement, pullHeight) == 0x1C);
STATIC_ASSERT(offsetof(RingPlacement, counterGameBit) == 0x1E);
STATIC_ASSERT(offsetof(RingPlacement, activateBit) == 0x20);

extern RingTable gRingModeParams[];

int ring_getExtraSize(void);
int ring_getObjectTypeId(void);
void ring_free(GameObject* obj);
void ring_hitDetect(void);
void ring_render(GameObject* obj, int p2, int p3, int p4, int p5, f32 scale);
void ring_release(void);
void ring_initialise(void);
void ring_init(GameObject* obj, RingPlacement* setup);
void ring_update(GameObject* obj);
void ring_updateMovingAxis(GameObject* obj, RingState* state);
void ring_onCollect(GameObject* obj, RingState* state, GameObject* arwing);
int ring_checkArwingCollision(GameObject* obj, RingState* state, GameObject* arwing);

#endif

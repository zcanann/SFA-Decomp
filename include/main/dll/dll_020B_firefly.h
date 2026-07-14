#ifndef MAIN_DLL_DLL_020B_FIREFLY_H_
#define MAIN_DLL_DLL_020B_FIREFLY_H_

#include "main/game_object.h"
#include "global.h"
#include "main/obj_placement.h"

#define FIREFLY_EXTRA_SIZE 0x88

typedef struct FireFlyActiveBits
{
    u8 active : 1; /* 0x6C & 0x80: lit and wandering */
} FireFlyActiveBits;

typedef struct FireFlyMapData
{
    ObjPlacement base;
    u8 pad18[2];
    s16 variantParam; /* 0x1A: only 0x7F is read (arms the 3600-frame life timer) */
    u8 pad1C[0x20 - 0x1C];
    s16 requiredGameBit; /* 0x20: game bit gating activation (-1 = none) */
} FireFlyMapData;

typedef struct FireFlyState
{
    void* light;           /* 0x00: point-light handle (modelLightStruct) */
    f32 splineX[4];        /* 0x04: B-spline control points (X) */
    f32 splineY[4];        /* 0x14 */
    f32 splineZ[4];        /* 0x24 */
    f32 targetX;           /* 0x34: next wander target */
    f32 targetY;           /* 0x38 */
    f32 targetZ;           /* 0x3C */
    f32 splineT;           /* 0x40: spline parameter; >1 shifts a new segment in */
    f32 splineSpeed;       /* 0x44: dT per frame, re-rolled each segment */
    f32 proximityAlpha;    /* 0x48: glow brightness, eased toward the near/far bound */
    f32 playerRadius;      /* 0x4C: player XZ distance that brightens the glow */
    u8 pad50[0x66 - 0x50]; /* 0x50: wander parameters managed by LgtFireFlyRec helpers */
    u8 kind;               /* 0x66: trail/near particle-fx colour */
    u8 pad67;
    u8 pathAge; /* 0x68: spline segments consumed; 4+ stops re-targeting */
    u8 pad69[0x6C - 0x69];
    u8 activeFlags; /* 0x6C: FireFlyActiveBits */
    u8 pad6D[0x70 - 0x6D];
    f32 despawnTimer; /* 0x70: post-collect frames; sparkles above 170, frees at 0 */
    f32 lifeTimer;    /* 0x74: expiry despawns the timed placement variant */
    u8 pad78[0x7C - 0x78];
    u8 flags; /* 0x7C: player-touch latch */
    u8 pad7D[0x80 - 0x7D];
    s16 messageParam; /* 0x80: outparam for the talk message */
    u8 pad82[FIREFLY_EXTRA_SIZE - 0x82];
} FireFlyState;

STATIC_ASSERT(offsetof(FireFlyMapData, variantParam) == 0x1A);
STATIC_ASSERT(offsetof(FireFlyMapData, requiredGameBit) == 0x20);
STATIC_ASSERT(offsetof(FireFlyState, light) == 0x00);
STATIC_ASSERT(offsetof(FireFlyState, splineX) == 0x04);
STATIC_ASSERT(offsetof(FireFlyState, splineY) == 0x14);
STATIC_ASSERT(offsetof(FireFlyState, splineZ) == 0x24);
STATIC_ASSERT(offsetof(FireFlyState, targetX) == 0x34);
STATIC_ASSERT(offsetof(FireFlyState, splineT) == 0x40);
STATIC_ASSERT(offsetof(FireFlyState, kind) == 0x66);
STATIC_ASSERT(offsetof(FireFlyState, activeFlags) == 0x6C);
STATIC_ASSERT(offsetof(FireFlyState, despawnTimer) == 0x70);
STATIC_ASSERT(offsetof(FireFlyState, lifeTimer) == 0x74);
STATIC_ASSERT(offsetof(FireFlyState, flags) == 0x7C);
STATIC_ASSERT(offsetof(FireFlyState, messageParam) == 0x80);
STATIC_ASSERT(sizeof(FireFlyState) == FIREFLY_EXTRA_SIZE);

extern s16 lbl_803DC128;
extern f32 lbl_803E5EA8;
extern f32 lbl_803E5ED8;
extern f32 lbl_803E5EDC;
extern f32 lbl_803E5EE0;
extern f32 lbl_803E5EE4;
extern f32 lbl_803E5EE8;
extern f32 lbl_803E5EEC;
extern f32 lbl_803E5EF0;

void FireFlyFn_801f4f88(GameObject* obj);
void firefly_free(GameObject* obj);
void firefly_update(GameObject* obj);
void firefly_init(GameObject* obj, FireFlyMapData* mapData);
int firefly_getExtraSize(void);
int firefly_getObjectTypeId(void);
void firefly_render(void);
void firefly_hitDetect(void);
void firefly_release(void);
void firefly_initialise(void);

#endif /* MAIN_DLL_DLL_020B_FIREFLY_H_ */

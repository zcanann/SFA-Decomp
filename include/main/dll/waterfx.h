#ifndef MAIN_DLL_WATERFX_H_
#define MAIN_DLL_WATERFX_H_

#include "global.h"
#include "main/dll/waterfx_interface.h"
#include "main/texture.h"
#include "main/lightmap_api.h"
#include "dolphin/mtx/vec_types.h"

typedef struct WaterMovementRipple {
    f32 x;
    f32 y;
    f32 z;
    f32 unknown0C;
    f32 scale;
    s16 alpha;
    s16 yaw;
    u8 hidden;
    u8 pad19[3];
} WaterMovementRipple;

typedef struct WaterSplashBurst {
    f32 x;
    f32 y;
    f32 z;
    f32 size;
    f32 life;
    f32 lifeSpeed;
    u32 bandColors[8];
    u8 dropCount;
    u8 pad39[3];
} WaterSplashBurst;

typedef struct WaterCircularRipple {
    f32 x;
    f32 y;
    f32 z;
    f32 unknown0C;
    f32 scale;
    s16 yaw;
    s16 alpha;
    s16 fadeRate;
    u8 pad1a[2];
} WaterCircularRipple;

typedef struct WaterSplashDrop {
    f32 x;
    f32 y;
    f32 z;
    f32 vx;
    f32 vy;
    f32 vz;
    s8 parentIdx;
    u8 pad19[3];
} WaterSplashDrop;

#define WATERFX_POOL_SIZE    30
#define WATERFX_MAX_SPLASHES 10

typedef struct WaterfxStorage {
    LightmapTriangle rippleTriangles[WATERFX_POOL_SIZE * 2];
    LightmapTriangle wakeTriangles[WATERFX_POOL_SIZE * 2];
    LightmapVertex rippleVertices[WATERFX_POOL_SIZE * 4];
    LightmapVertex wakeVertices[WATERFX_POOL_SIZE * 4];
    WaterCircularRipple ripples[WATERFX_POOL_SIZE];
    WaterSplashBurst splashes[WATERFX_MAX_SPLASHES];
    WaterSplashDrop drops[WATERFX_POOL_SIZE];
    WaterMovementRipple wakes[WATERFX_POOL_SIZE];
} WaterfxStorage;

STATIC_ASSERT(sizeof(WaterCircularRipple) == 0x1C);
STATIC_ASSERT(offsetof(WaterCircularRipple, yaw) == 0x14);
STATIC_ASSERT(offsetof(WaterCircularRipple, alpha) == 0x16);
STATIC_ASSERT(offsetof(WaterCircularRipple, fadeRate) == 0x18);
STATIC_ASSERT(sizeof(WaterMovementRipple) == 0x1C);
STATIC_ASSERT(offsetof(WaterMovementRipple, alpha) == 0x14);
STATIC_ASSERT(offsetof(WaterMovementRipple, yaw) == 0x16);
STATIC_ASSERT(offsetof(WaterMovementRipple, hidden) == 0x18);
STATIC_ASSERT(sizeof(WaterSplashBurst) == 0x3C);
STATIC_ASSERT(offsetof(WaterSplashBurst, bandColors) == 0x18);
STATIC_ASSERT(offsetof(WaterSplashBurst, dropCount) == 0x38);
STATIC_ASSERT(sizeof(WaterSplashDrop) == 0x1C);
STATIC_ASSERT(offsetof(WaterSplashDrop, vx) == 0x0C);
STATIC_ASSERT(offsetof(WaterSplashDrop, parentIdx) == 0x18);
STATIC_ASSERT(offsetof(WaterfxStorage, rippleTriangles) == 0);
STATIC_ASSERT(offsetof(WaterfxStorage, wakeTriangles) == 0x3C0);
STATIC_ASSERT(offsetof(WaterfxStorage, rippleVertices) == 0x780);
STATIC_ASSERT(offsetof(WaterfxStorage, wakeVertices) == 0xF00);
STATIC_ASSERT(offsetof(WaterfxStorage, ripples) == 0x1680);
STATIC_ASSERT(offsetof(WaterfxStorage, splashes) == 0x19C8);
STATIC_ASSERT(offsetof(WaterfxStorage, drops) == 0x1C20);
STATIC_ASSERT(offsetof(WaterfxStorage, wakes) == 0x1F68);
STATIC_ASSERT(sizeof(WaterfxStorage) == 0x22B0);

extern f32 gWaterfxRippleScale;
extern u8 gWaterfxPendingImpactPositionValid;
extern f32 gWaterfxPendingImpactPosition[];
extern char sWaterfxDllAllocFailed[];
extern f32 (*gWaterfxSplashTexCoordArray)[2];
extern Vec* gWaterfxSplashPosArray;
extern void* gWaterfxSplashDisplayList;
extern Texture* gWaterfxWakeTexture;
extern Texture* gWaterfxSplashTexture1;
extern Texture* gWaterfxSplashTexture0;
extern Texture* gWaterfxRippleTexture;
extern WaterSplashDrop* gWaterfxDropPool;
extern int gWaterfxDropCount;
extern WaterMovementRipple* gWaterfxWakePool;
extern int gWaterfxWakeCount;
extern WaterSplashBurst* gWaterfxSplashPool;
extern int gWaterfxSplashCount;
extern WaterCircularRipple* gWaterfxRipplePool;
extern int gWaterfxRippleCount;
extern LightmapTriangle* gWaterfxWakeTriangles;
extern LightmapVertex* gWaterfxWakeVertices;
extern LightmapTriangle* gWaterfxRippleTriangles;
extern LightmapVertex* gWaterfxRippleVertices;

int waterfx_consumePendingImpactNearPoint(f32* vec, f32 dist);
void waterfx_spawnCircularRipple(f32 x, f32 y, f32 z, s16 yaw, f32 unknown0C, int intensity);
void waterfx_setRippleScale(int flag, f32 val);
void waterfx_spawnMovementRipple(f32 x, f32 y, f32 z, s16 yaw, f32 unknown0C);
void waterfx_spawnSplashBurst(GameObject* obj, f32 x, f32 y, f32 z, f32 size);
int waterfx_spawnSplashDrops(WaterSplashBurst* src, int idx, int count, f32 v);
void waterfx_render(int unusedDisplayList, int unusedMatrixList);
void waterfx_run(int frames);
void waterfx_spawnImpactSurface(GameObject* obj, u16 limbMask, Vec* impactPositions, ObjCollisionState* collision,
                                f32 speed);
void waterfx_onMapSetup(void);
void waterfx_release(void);
void waterfx_initialise(void);
void waterfx_drawSplashBurst(WaterSplashBurst* particle);

#endif /* MAIN_DLL_WATERFX_H_ */

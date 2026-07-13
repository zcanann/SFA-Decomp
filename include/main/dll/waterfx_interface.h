#ifndef MAIN_DLL_WATERFX_INTERFACE_H_
#define MAIN_DLL_WATERFX_INTERFACE_H_

#include "global.h"

typedef void (*WaterfxRunFrameFn)(void);
typedef void (*WaterfxImpactSurfaceFn)(u8* objHeader, u16 limbMask, f32* impactPositions,
                                       u8* surface, f32 speed);
typedef void (*WaterfxRenderFn)(int renderPass, int flags);
typedef void (*WaterfxSpawnSplashBurstFn)(void* sourceObject, f32 x, f32 y, f32 z,
                                          f32 radius);
typedef void (*WaterfxSpawnRippleFn)(f32 x, f32 y, f32 z, s16 sourceId, f32 radius,
                                     int intensity);
typedef void (*WaterfxSpawnSimpleRippleFn)(s16 sourceId, f32 x, f32 y, f32 z,
                                           f32 radius);
typedef void (*WaterfxOnMapSetupFn)(void);
typedef void (*WaterfxSetRippleScaleFn)(int flag, f32 value);

typedef struct WaterfxInterface {
    u8 pad00[0x04];
    WaterfxRunFrameFn runFrame;
    WaterfxImpactSurfaceFn spawnImpactSurface;
    WaterfxRenderFn render;
    WaterfxSpawnSplashBurstFn spawnSplashBurst;
    WaterfxSpawnRippleFn spawnRipple;
    WaterfxSpawnSimpleRippleFn spawnSimpleRipple;
    WaterfxOnMapSetupFn onMapSetup;
    WaterfxSetRippleScaleFn setRippleScale;
} WaterfxInterface;

STATIC_ASSERT(offsetof(WaterfxInterface, runFrame) == 0x04);
STATIC_ASSERT(offsetof(WaterfxInterface, spawnImpactSurface) == 0x08);
STATIC_ASSERT(offsetof(WaterfxInterface, render) == 0x0C);
STATIC_ASSERT(offsetof(WaterfxInterface, spawnSplashBurst) == 0x10);
STATIC_ASSERT(offsetof(WaterfxInterface, spawnRipple) == 0x14);
STATIC_ASSERT(offsetof(WaterfxInterface, spawnSimpleRipple) == 0x18);
STATIC_ASSERT(offsetof(WaterfxInterface, onMapSetup) == 0x1C);
STATIC_ASSERT(offsetof(WaterfxInterface, setRippleScale) == 0x20);

extern WaterfxInterface** gWaterfxInterface;

#endif /* MAIN_DLL_WATERFX_INTERFACE_H_ */

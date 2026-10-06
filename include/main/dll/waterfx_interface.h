#ifndef MAIN_DLL_WATERFX_INTERFACE_H_
#define MAIN_DLL_WATERFX_INTERFACE_H_

#include "global.h"
#include "main/dll/obj_collision_state.h"

typedef void (*WaterfxRunFrameFn)(int frames);
typedef void (*WaterfxImpactSurfaceFn)(GameObject* obj, u16 limbMask, Vec* impactPositions,
                                       ObjCollisionState* collision, f32 speed);
typedef void (*WaterfxRenderFn)(int unusedDisplayList, int unusedMatrixList);
typedef void (*WaterfxSpawnSplashBurstFn)(GameObject* sourceObject, f32 x, f32 y, f32 z, f32 size);
typedef void (*WaterfxSpawnCircularRippleFn)(f32 x, f32 y, f32 z, s16 yaw, f32 unknown0C, int intensity);
typedef void (*WaterfxSpawnMovementRippleFn)(f32 x, f32 y, f32 z, s16 yaw, f32 unknown0C);
typedef void (*WaterfxOnMapSetupFn)(void);
typedef void (*WaterfxSetRippleScaleFn)(int flag, f32 value);

typedef struct WaterfxInterface {
    u32 reserved;
    WaterfxRunFrameFn runFrame;
    WaterfxImpactSurfaceFn spawnImpactSurface;
    WaterfxRenderFn render;
    WaterfxSpawnSplashBurstFn spawnSplashBurst;
    WaterfxSpawnCircularRippleFn spawnCircularRipple;
    WaterfxSpawnMovementRippleFn spawnMovementRipple;
    WaterfxOnMapSetupFn onMapSetup;
    WaterfxSetRippleScaleFn setRippleScale;
} WaterfxInterface;

STATIC_ASSERT(offsetof(WaterfxInterface, runFrame) == 0x04);
STATIC_ASSERT(offsetof(WaterfxInterface, spawnImpactSurface) == 0x08);
STATIC_ASSERT(offsetof(WaterfxInterface, render) == 0x0C);
STATIC_ASSERT(offsetof(WaterfxInterface, spawnSplashBurst) == 0x10);
STATIC_ASSERT(offsetof(WaterfxInterface, spawnCircularRipple) == 0x14);
STATIC_ASSERT(offsetof(WaterfxInterface, spawnMovementRipple) == 0x18);
STATIC_ASSERT(offsetof(WaterfxInterface, onMapSetup) == 0x1C);
STATIC_ASSERT(offsetof(WaterfxInterface, setRippleScale) == 0x20);

STATIC_ASSERT(sizeof(WaterfxInterface) == 0x24);

typedef struct WaterfxDescriptor {
    u32 reserved[3];
    u32 slotCountAndFlags;
    void (*initialise)(void);
    void (*release)(void);
    WaterfxInterface interface;
} WaterfxDescriptor;

STATIC_ASSERT(offsetof(WaterfxDescriptor, interface) == 0x18);
STATIC_ASSERT(sizeof(WaterfxDescriptor) == 0x3C);

extern WaterfxDescriptor gWaterfxDescriptor;
extern WaterfxInterface** gWaterfxInterface;

#endif /* MAIN_DLL_WATERFX_INTERFACE_H_ */

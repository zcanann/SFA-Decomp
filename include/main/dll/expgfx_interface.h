#ifndef MAIN_DLL_EXPGFX_INTERFACE_H_
#define MAIN_DLL_EXPGFX_INTERFACE_H_

#include "global.h"
#include "game/objects/object_fwd.h"
#include "main/dll/effectspawnconfig_struct.h"

typedef void (*ExpgfxOnMapSetupFn)(void);
typedef int (*ExpgfxSpawnEffectFn)(EffectSpawnConfig* config, int preferredPoolIndex, int slotType,
                                   int planeOffsetSetId);
typedef void (*ExpgfxUpdateFrameStateFn)(int sourceMode, int frameCount, int unused0, int unused1);
typedef void (*ExpgfxResetAllPoolsFn)(void);
typedef void (*ExpgfxFreeSourceFn)(GameObject* sourceObject);
typedef int (*ExpgfxFunc09Fn)(void);
typedef void (*ExpgfxNopFn)(void);
typedef int (*ExpgfxUpdateSourceFrameFlagsFn)(GameObject* sourceObject);

typedef struct ExpgfxInterface {
    u32 reserved;
    ExpgfxOnMapSetupFn onMapSetup;
    ExpgfxSpawnEffectFn spawnEffect;
    ExpgfxUpdateFrameStateFn updateFrameState;
    ExpgfxResetAllPoolsFn resetAllPools;
    ExpgfxFreeSourceFn freeSource;
    ExpgfxFreeSourceFn freeSource2;
    ExpgfxFunc09Fn func09;
    ExpgfxNopFn func0ANop;
    ExpgfxNopFn func0BNop;
    ExpgfxFreeSourceFn freeOwner3;
    ExpgfxUpdateSourceFrameFlagsFn updateSourceFrameFlags;
} ExpgfxInterface;

STATIC_ASSERT(sizeof(ExpgfxInterface) == 0x30);
STATIC_ASSERT(offsetof(ExpgfxInterface, onMapSetup) == 0x04);
STATIC_ASSERT(offsetof(ExpgfxInterface, spawnEffect) == 0x08);
STATIC_ASSERT(offsetof(ExpgfxInterface, updateFrameState) == 0x0C);
STATIC_ASSERT(offsetof(ExpgfxInterface, resetAllPools) == 0x10);
STATIC_ASSERT(offsetof(ExpgfxInterface, freeSource) == 0x14);
STATIC_ASSERT(offsetof(ExpgfxInterface, freeSource2) == 0x18);
STATIC_ASSERT(offsetof(ExpgfxInterface, func09) == 0x1C);
STATIC_ASSERT(offsetof(ExpgfxInterface, func0ANop) == 0x20);
STATIC_ASSERT(offsetof(ExpgfxInterface, func0BNop) == 0x24);
STATIC_ASSERT(offsetof(ExpgfxInterface, freeOwner3) == 0x28);
STATIC_ASSERT(offsetof(ExpgfxInterface, updateSourceFrameFlags) == 0x2C);

extern ExpgfxInterface** gExpgfxInterface;

#endif /* MAIN_DLL_EXPGFX_INTERFACE_H_ */

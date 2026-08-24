#ifndef MAIN_DLL_PROJGFX_INTERFACE_H_
#define MAIN_DLL_PROJGFX_INTERFACE_H_

#include "game/objects/object_fwd.h"
#include "global.h"

typedef void (*ProjgfxResourceSpawnFn)(GameObject* obj, int unused1, int unused2, int spawnFlags, int modelId,
                                       int effectId, int unused3);
typedef void (*ProjgfxOnMapSetupFn)(void);
typedef int (*ProjgfxRetMinusOneFn)(void);
typedef void (*ProjgfxNopFn)(void);
typedef int (*ProjgfxGetObjectTypeIdFn)(void);
typedef void (*ProjgfxSetZScaleUnsupportedFn)(void);
typedef void (*ProjgfxRayHitUnsupportedFn)(void);

typedef struct ProjgfxResourceVTable {
    u8 pad00[4];
    ProjgfxResourceSpawnFn spawnEffect;
} ProjgfxResourceVTable;

typedef struct ProjgfxResource {
    ProjgfxResourceVTable* vtable;
} ProjgfxResource;

STATIC_ASSERT(offsetof(ProjgfxResourceVTable, spawnEffect) == 0x04);

typedef struct ProjgfxInterface
{
    u8 pad00[0x04];
    ProjgfxOnMapSetupFn onMapSetup;
    ProjgfxRetMinusOneFn func04RetMinusOne;
    ProjgfxNopFn func05Nop;
    ProjgfxNopFn func06Nop;
    ProjgfxNopFn func07Nop;
    ProjgfxGetObjectTypeIdFn getObjectTypeId;
    ProjgfxSetZScaleUnsupportedFn setZScaleUnsupported;
    ProjgfxRayHitUnsupportedFn rayHitUnsupported;
} ProjgfxInterface;

STATIC_ASSERT(offsetof(ProjgfxInterface, onMapSetup) == 0x04);
STATIC_ASSERT(offsetof(ProjgfxInterface, func04RetMinusOne) == 0x08);
STATIC_ASSERT(offsetof(ProjgfxInterface, func05Nop) == 0x0C);
STATIC_ASSERT(offsetof(ProjgfxInterface, func06Nop) == 0x10);
STATIC_ASSERT(offsetof(ProjgfxInterface, func07Nop) == 0x14);
STATIC_ASSERT(offsetof(ProjgfxInterface, getObjectTypeId) == 0x18);
STATIC_ASSERT(offsetof(ProjgfxInterface, setZScaleUnsupported) == 0x1C);
STATIC_ASSERT(offsetof(ProjgfxInterface, rayHitUnsupported) == 0x20);

extern ProjgfxInterface** gProjgfxInterface;

#endif /* MAIN_DLL_PROJGFX_INTERFACE_H_ */

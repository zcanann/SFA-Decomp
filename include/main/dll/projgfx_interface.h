#ifndef MAIN_DLL_PROJGFX_INTERFACE_H_
#define MAIN_DLL_PROJGFX_INTERFACE_H_

#include "global.h"

typedef void (*ProjgfxOnMapSetupFn)(void);
typedef int (*ProjgfxRetMinusOneFn)(void);
typedef void (*ProjgfxNopFn)(void);
typedef int (*ProjgfxGetObjectTypeIdFn)(void);
typedef void (*ProjgfxSetZScaleUnsupportedFn)(void);
typedef void (*ProjgfxRayHitUnsupportedFn)(void);

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

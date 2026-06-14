#ifndef MAIN_SHTHORNTAIL_INTERFACE_H_
#define MAIN_SHTHORNTAIL_INTERFACE_H_

#include "global.h"

typedef void (*SHthorntailUpdateEnvfxActFn)(int sourceObj, int targetObj, void *entry, int flags);
typedef void (*SHthorntailOnMapSetupFn)(void);
typedef void (*SHthorntailRunFn)(void);
typedef void (*SHthorntailRenderFn)(int unused0, int unused1, int unused2, int unused3, int flags);
typedef void (*SHthorntailGetTailHeightFn)(f32 *outHeight);
typedef void (*SHthorntailGetSkyStateFn)(int *outState);
typedef int (*SHthorntailIsTailSwingQueuedFn)(void *out);
typedef void (*SHthorntailSetEnvironmentBlendFn)(f32 blend);

typedef struct SHthorntailAnimationInterface {
  u8 pad00[0x04];
  SHthorntailUpdateEnvfxActFn updateEnvfxAct;
  SHthorntailOnMapSetupFn onMapSetup;
  SHthorntailRunFn run;
  SHthorntailRenderFn render;
  SHthorntailGetTailHeightFn getTailHeight;
  u8 pad18[0x20 - 0x18];
  SHthorntailGetSkyStateFn getSkyState;
  SHthorntailIsTailSwingQueuedFn isTailSwingQueued;
  SHthorntailSetEnvironmentBlendFn setEnvironmentBlend;
} SHthorntailAnimationInterface;

STATIC_ASSERT(offsetof(SHthorntailAnimationInterface, updateEnvfxAct) == 0x04);
STATIC_ASSERT(offsetof(SHthorntailAnimationInterface, onMapSetup) == 0x08);
STATIC_ASSERT(offsetof(SHthorntailAnimationInterface, run) == 0x0C);
STATIC_ASSERT(offsetof(SHthorntailAnimationInterface, render) == 0x10);
STATIC_ASSERT(offsetof(SHthorntailAnimationInterface, getTailHeight) == 0x14);
STATIC_ASSERT(offsetof(SHthorntailAnimationInterface, getSkyState) == 0x20);
STATIC_ASSERT(offsetof(SHthorntailAnimationInterface, isTailSwingQueued) == 0x24);
STATIC_ASSERT(offsetof(SHthorntailAnimationInterface, setEnvironmentBlend) == 0x28);

extern SHthorntailAnimationInterface **gSHthorntailAnimationInterface;

#endif /* MAIN_SHTHORNTAIL_INTERFACE_H_ */

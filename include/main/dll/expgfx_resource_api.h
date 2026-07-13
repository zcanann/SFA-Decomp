#ifndef MAIN_DLL_EXPGFX_RESOURCE_API_H_
#define MAIN_DLL_EXPGFX_RESOURCE_API_H_

#include "types.h"

extern f32 gExpgfxFrameTimerA;
extern f32 gExpgfxFrameTimerB;
extern f32 gExpgfxFrameTimerC;

void expgfx_updateResourceEntries(int unused);
int expgfx_acquireResourceEntry(int resourceId);

#endif // MAIN_DLL_EXPGFX_RESOURCE_API_H_

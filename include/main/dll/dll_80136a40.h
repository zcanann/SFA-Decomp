#ifndef MAIN_DLL_DLL_80136A40_H_
#define MAIN_DLL_DLL_80136A40_H_

#include "types.h"

/*
 * Public exports of dll_80136a40 (the Tricky behaviour DLL). Declared here so
 * consumers include this instead of hand-writing a local extern.
 */
void* trickyGetQueuedPathParticlePos(void* obj);

#endif

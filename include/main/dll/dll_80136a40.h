#ifndef MAIN_DLL_DLL_80136A40_H_
#define MAIN_DLL_DLL_80136A40_H_

#include "main/game_object.h"
#include "types.h"
#include "main/debug.h"

/*
 * Public exports of dll_80136a40 (the Tricky behaviour DLL). Declared here so
 * consumers include this instead of hand-writing a local extern.
 */
void* trickyGetQueuedPathParticlePos(GameObject* obj);

#endif

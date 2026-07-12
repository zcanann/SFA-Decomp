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
GameObject* fn_80138F84(GameObject* tricky);
int trickyFn_80138f14(GameObject* tricky);
void trickyImpress(GameObject* obj);
void fn_80138908(GameObject* obj, int value);
int fn_80138920(GameObject* obj, int sfxId, int volume);

#endif

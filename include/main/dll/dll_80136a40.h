#ifndef MAIN_DLL_DLL_80136A40_H_
#define MAIN_DLL_DLL_80136A40_H_

#include "game/objects/object.h"
#include "main/dll/tricky_state.h"
#include "types.h"
#include "main/debug.h"

/*
 * Public exports of dll_80136a40 (the Tricky behaviour DLL). Declared here so
 * consumers include this instead of hand-writing a local extern.
 */
void* trickyGetQueuedPathParticlePos(GameObject* obj);
f32 trickyGetAnimSpeed(GameObject* tricky);
GameObject* trickyGetStayPoint(GameObject* tricky);
int trickyGetAimPitchOffset(GameObject* tricky);
int Tricky_requestRecallAndCheckBusy(GameObject* tricky);
void trickyImpress(GameObject* obj);
void trickySetSoundSuppressed(GameObject* obj, int value);
int trickyTryPlaySound(GameObject* obj, u16 sfxId, int volume);
void debugPrintInit(void);
void debugPrintReset(void);
void debugPrintfxy(int x, int y, char* fmt, ...);
void errDisplayInstallHandlers(void);
void* errorThreadFunc(void* unused);
void reportAllocFail(int region0SizeKb, int region0FreeKb, int region1SizeKb, int region1FreeKb, int region2SizeKb,
                     int region2FreeKb, int memoryState, int tickCount, int requestedSize, int largestFree0,
                     int largestFree1);
void debugPrintDraw(void* context);
void objAnimFreeChildren(GameObject* obj, TrickyState* state, GameObject** child);
GameObject* trickyFindNearestUsableBaddie(GameObject* origin, f32 maxRadius, int allowSpecialTypes);
void Tricky_updateBlendChannelWeight(GameObject* obj, TrickyState* state);
void Tricky_emitQueuedPathParticles(GameObject* obj, TrickyState* state);
int trickySelectQueuedCommandTarget(TrickyState* state, int commandType);
void tricky_updateModelVariantFade(GameObject* obj, TrickyState* state);

#endif

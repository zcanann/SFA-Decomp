#ifndef MAIN_DLL_DLL_80136A40_H_
#define MAIN_DLL_DLL_80136A40_H_

#include "game/objects/object.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/tricky_state.h"
#include "types.h"
#include "main/debug.h"

/*
 * Public exports of dll_80136a40 (the Tricky behaviour DLL). Declared here so
 * consumers include this instead of hand-writing a local extern.
 */
f32* trickyGetMouthPosition(GameObject* obj);
f32 trickyGetAnimSpeed(GameObject* tricky);
GameObject* trickyGetStayPoint(GameObject* tricky);
int trickyGetMouthYawOffset(GameObject* tricky);
int Tricky_requestRecallAndCheckBusy(GameObject* tricky);
void trickyImpress(GameObject* obj);
void trickySetSoundSuppressed(GameObject* obj, int value);
int trickyTryPlaySound(GameObject* obj, u16 sfxId, int mouthOpenAngle);
void debugPrintInit(void);
void debugPrintReset(void);
void debugPrintfxy(int x, int y, char* fmt, ...);
void errDisplayInstallHandlers(void);
void* errorThreadFunc(void* unused);
void reportAllocFail(int region0SizeKb, int region0FreeKb, int region1SizeKb, int region1FreeKb, int region2SizeKb,
                     int region2FreeKb, int memoryState, int tickCount, int requestedSize, int largestFree0,
                     int largestFree1);
void debugPrintDraw(void* context);
void trickyFreePromptChild(GameObject* obj, TrickyState* state, GameObject** childRef);
GameObject* trickyFindNearestUsableBaddie(GameObject* origin, f32 maxRadius, int allowSpecialTypes);
void Tricky_updateBlendChannelWeight(GameObject* obj, TrickyState* state);
void Tricky_emitQueuedPathParticles(GameObject* obj, TrickyState* state);
int trickySelectQueuedCommandTarget(TrickyState* state, enum TrickyCommandType commandType);
void trickyUpdateColorVariant(GameObject* obj, TrickyState* state);

#endif

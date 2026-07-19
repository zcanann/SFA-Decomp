#ifndef MAIN_DLL_DLL_00C4_TRICKY_API_H_
#define MAIN_DLL_DLL_00C4_TRICKY_API_H_

#include "main/game_object.h"

void baddie_updateWhileFrozen(GameObject* obj, u8* state, u8 fromHit);
void trickyReportError(const char* fmt, ...);
void trickyDebugPrint(const char* fmt, ...);

void tricky_handleDefeat(GameObject* obj, int state);
void baddieInstantiateWeapon(GameObject* obj, int state);

extern const u16 gSkeetlaFootstepSfxId2;

#endif /* MAIN_DLL_DLL_00C4_TRICKY_API_H_ */

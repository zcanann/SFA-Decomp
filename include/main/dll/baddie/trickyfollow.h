#ifndef MAIN_DLL_BADDIE_TRICKYFOLLOW_H_
#define MAIN_DLL_BADDIE_TRICKYFOLLOW_H_

#include "ghidra_import.h"

int trickyFn_8013b368(u8 *obj, f32 vel, u8 *state);
void trickyUpdateApproachSpeed(u8* obj, f32 baseRadius, u8* state, f32* targetPos, u8 flag);

#endif /* MAIN_DLL_BADDIE_TRICKYFOLLOW_H_ */

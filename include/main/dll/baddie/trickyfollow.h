#ifndef MAIN_DLL_BADDIE_TRICKYFOLLOW_H_
#define MAIN_DLL_BADDIE_TRICKYFOLLOW_H_

#include "main/dll/tricky_state.h"

int trickyFn_8013b368(GameObject* obj, f32 vel, TrickyState* state);
void trickyUpdateApproachSpeed(GameObject* obj, f32 baseRadius, TrickyState* state, f32* targetPos, u8 flag);

#endif /* MAIN_DLL_BADDIE_TRICKYFOLLOW_H_ */

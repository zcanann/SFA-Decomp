#ifndef MAIN_DLL_XYZANIMATOR_API_H_
#define MAIN_DLL_XYZANIMATOR_API_H_

#include "main/game_object.h"

struct XyzAnimatorPlacement;
struct XyzAnimatorState;

f32 objFn_801948c0(GameObject* obj, u8 coord);
void XyzAnimator_captureGeometry(struct XyzAnimatorPlacement* setup, struct XyzAnimatorState* state, int block);
void fn_80194C40(struct XyzAnimatorPlacement* setup, struct XyzAnimatorState* state, int block);

#endif /* MAIN_DLL_XYZANIMATOR_API_H_ */

#ifndef MAIN_OBJPRINT_ANIM_API_H_
#define MAIN_OBJPRINT_ANIM_API_H_

#include "global.h"
#include "main/game_object.h"

void objAnimFn_80038f38(GameObject* obj, char* state);
void fn_8003B500(GameObject* obj, s16* state, f32 value);
void fn_80039B54(int obj, s16* curve, s16* state, f32 val);

#define objAnimFn_80038f38IntStateLegacy(obj, state)                                                            \
    ((void (*)(GameObject*, int))objAnimFn_80038f38)((obj), (state))

#endif /* MAIN_OBJPRINT_ANIM_API_H_ */

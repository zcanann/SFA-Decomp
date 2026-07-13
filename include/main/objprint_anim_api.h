#ifndef MAIN_OBJPRINT_ANIM_API_H_
#define MAIN_OBJPRINT_ANIM_API_H_

#include "global.h"
#include "main/game_object.h"

void objAnimFn_80038f38(GameObject* obj, char* state);
void fn_8003B500(GameObject* obj, s16* state);
void fn_80039B54(int obj, s16* curve, s16* state, f32 val);

#define fn_8003B500FloatLegacy(obj, state, value)                                                               \
    ((void (*)(GameObject*, s16*, f32))fn_8003B500)((obj), (state), (value))
#define objAnimFn_80038f38IntStateLegacy(obj, state)                                                            \
    ((void (*)(GameObject*, int))objAnimFn_80038f38)((obj), (state))
#define fn_8003B500IntStateLegacy(obj, state, value)                                                            \
    ((void (*)(GameObject*, int, f32))fn_8003B500)((obj), (state), (value))

#endif /* MAIN_OBJPRINT_ANIM_API_H_ */

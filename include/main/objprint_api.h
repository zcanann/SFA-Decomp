#ifndef MAIN_OBJPRINT_API_H_
#define MAIN_OBJPRINT_API_H_

#include "global.h"
#include "main/game_object.h"

int* seqFn_800394a0(void);
void objPosFn_80039510(GameObject* obj, int key, f32* outPosition);
void fn_8003AAE0(GameObject* obj, int* keys, int count, int lo, int hi);
s16* objModelGetVecFn_800395d8(GameObject* obj, int target);
void fn_8003A168(GameObject* obj, int state);
void fn_8003B608(s16 red, s16 green, s16 blue);
void fn_8003B5E0(int red, int green, int blue, u8 alpha);
void fn_8003B950(f32* matrix);

#define fn_8003B5E0IntAlphaLegacy(red, green, blue, alpha) \
    ((void (*)(int, int, int, int))fn_8003B5E0)((red), (green), (blue), (alpha))
#define fn_8003A168PointerStateLegacy(obj, state) \
    ((void (*)(GameObject*, void*))fn_8003A168)((obj), (state))

#endif /* MAIN_OBJPRINT_API_H_ */

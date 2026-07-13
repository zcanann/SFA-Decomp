#ifndef MAIN_TRACK_BBOX_API_H_
#define MAIN_TRACK_BBOX_API_H_

#include "types.h"

void objBboxFn_800640cc(f32* from, f32* to, f32 radius, int mode, int* hit, int* self, int flags, int mask, u8 slot,
                        u8 arg10);

#define objBboxFnIntLegacy(from, to, radius, mode, hit, self, flags, mask, slot, arg10)                           \
    (((int (*)(void*, void*, f32, int, void*, int, int, int, int, int))objBboxFn_800640cc)(                      \
        (from), (to), (radius), (mode), (hit), (self), (flags), (mask), (slot), (arg10)))

#endif /* MAIN_TRACK_BBOX_API_H_ */

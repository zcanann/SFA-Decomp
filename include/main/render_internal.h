#ifndef MAIN_RENDER_INTERNAL_H_
#define MAIN_RENDER_INTERNAL_H_

#include "types.h"

extern int gRenderMode;
extern f32 lbl_803DE544;
extern int lbl_802C18C0[];
extern int lbl_802C1A24[];

void render_copyPackedU64Tail(u64* dst, u32 packed);
void render_copyPackedU64Head(u64* dst, u32 packed);

#endif /* MAIN_RENDER_INTERNAL_H_ */

#ifndef MAIN_RENDER_INTERNAL_H_
#define MAIN_RENDER_INTERNAL_H_

#include "types.h"

struct ObjAnimState;

extern int gRenderMode;
extern f32 lbl_803DE544;
extern const int lbl_802C18C0[];
extern const int lbl_802C1A24[];

void render_copyPackedU64Tail(u64* dst, u32 packed);
void render_copyPackedU64Head(u64* dst, u32 packed);
void lbl_80006C6C(int* out, u8* dst, void* animState, u8* jointData, int jointCount, u8* jointScratch,
                  int flags, int mode);
void fn_80007F78(struct ObjAnimState* anim, s16* dst, s16* out);

#endif /* MAIN_RENDER_INTERNAL_H_ */

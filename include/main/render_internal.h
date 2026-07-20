#ifndef MAIN_RENDER_INTERNAL_H_
#define MAIN_RENDER_INTERNAL_H_

#include "types.h"

struct ObjAnimState;

extern int gRenderMode;
extern f32 gModelRenderSubframeScale;
extern const int gModelRenderAdpcmStepTable[];
extern const int gModelRenderAdpcmIndexDeltaTable[];

void render_copyPackedU64Tail(u64* dst, u32 packed);
void render_copyPackedU64Head(u64* dst, u32 packed);
void lbl_80006C6C(int* out, u8* dst, void* animState, u8* jointData, int jointCount, u8* jointScratch,
                  int flags, int mode);
void modelRenderInterpolateRootTransform(struct ObjAnimState* anim, s16* outPosition, s16* outRotation);

#endif /* MAIN_RENDER_INTERNAL_H_ */

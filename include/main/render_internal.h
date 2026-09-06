#ifndef MAIN_RENDER_INTERNAL_H_
#define MAIN_RENDER_INTERNAL_H_

#include "types.h"

struct ObjAnimState;

extern int gRenderMode;
extern const f32 gModelRenderSubframeScale[1];
extern const int gModelRenderAdpcmStepTable[];
extern const int gModelRenderAdpcmIndexDeltaTable[];

void modelAnimBuildJointMatrices(int* out, u8* dst, void* animState, u8* jointData, int jointCount, u8* jointScratch,
                                 int flags, int mode);
void modelRenderInterpolateRootTransform(struct ObjAnimState* anim, s16* outPosition, s16* outRotation);

#endif /* MAIN_RENDER_INTERNAL_H_ */

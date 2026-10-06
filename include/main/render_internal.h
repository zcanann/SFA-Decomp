#ifndef MAIN_RENDER_INTERNAL_H_
#define MAIN_RENDER_INTERNAL_H_

#include "types.h"

struct ObjAnimState;
struct ModelBone;
struct ModelJointAdjustment;

extern const f32 gModelRenderSubframeScale[1];
extern const int gModelRenderAdpcmStepTable[];
extern const int gModelRenderAdpcmIndexDeltaTable[];

/* The selected joint buffer is also the intermediate pose workspace. */
void modelAnimBuildJointMatrices(u8** jointWorkspace, f32* rootTransform, struct ObjAnimState* animState,
                                 const struct ModelBone* bones, int jointCount,
                                 const struct ModelJointAdjustment* jointAdjustments, int flags, int mode);
void modelRenderInterpolateRootTransform(struct ObjAnimState* anim, s16* outPosition, s16* outRotation);

#endif /* MAIN_RENDER_INTERNAL_H_ */

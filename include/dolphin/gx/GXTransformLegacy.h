#ifndef DOLPHIN_GX_GXTRANSFORMLEGACY_H_
#define DOLPHIN_GX_GXTRANSFORMLEGACY_H_

#include "types.h"

void GXSetProjection(f32* matrix, s32 projectionMode);
void GXSetViewport(f32 left, f32 top, f32 width, f32 height, f32 nearPlane, f32 farPlane);

#endif /* DOLPHIN_GX_GXTRANSFORMLEGACY_H_ */

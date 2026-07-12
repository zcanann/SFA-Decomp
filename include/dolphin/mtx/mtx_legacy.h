#ifndef DOLPHIN_MTX_MTX_LEGACY_H_
#define DOLPHIN_MTX_MTX_LEGACY_H_

#include "types.h"

f32 PSVECMag(f32* v);
void PSVECAdd(f32* a, f32* b, f32* out);
void PSVECCrossProduct(f32* a, f32* b, f32* out);
void PSVECNormalize(void* src, void* dst);
void PSVECScale(f32* in, f32* out, f32 scale);
void PSVECSubtract(f32* a, f32* b, f32* out);
void PSMTXCopy(f32* src, f32* dst);
void PSMTXConcat(f32* a, f32* b, f32* out);
void PSMTXIdentity(f32* mtx);
void PSMTXMultVec(f32* mtx, f32* src, f32* dst);
void PSMTXMultVecSR(f32* mtx, f32* src, f32* dst);
void PSMTXRotAxisRad(f32* mtx, f32* axis, f32 rad);
void PSMTXRotRad(f32* mtx, int axis, f32 rad);
void C_MTXOrtho(f32* matrix, f32 top, f32 bottom, f32 left, f32 right, f32 nearPlane, f32 farPlane);
void C_MTXPerspective(f32* matrix, f32 fovY, f32 aspect, f32 nearPlane, f32 farPlane);
void C_MTXLightPerspective(f32* matrix, f32 fovY, f32 aspect, f32 scaleS, f32 scaleT, f32 transS, f32 transT);

#endif /* DOLPHIN_MTX_MTX_LEGACY_H_ */

#ifndef DOLPHIN_MTX_MTX_LEGACY_H_
#define DOLPHIN_MTX_MTX_LEGACY_H_

#include "types.h"

f32 PSVECMag(f32* v);
void PSVECAdd(f32* a, f32* b, f32* out);
void PSVECCrossProduct(f32* a, f32* b, f32* out);
void PSVECNormalize(void* src, void* dst);
void PSVECScale(f32* in, f32* out, f32 scale);
void PSVECSubtract(f32* a, f32* b, f32* out);
void PSMTXConcat(f32 a[3][4], f32 b[3][4], f32 out[3][4]);
void PSMTXIdentity(f32* mtx);
void PSMTXMultVec(f32* mtx, f32* src, f32* dst);
void PSMTXMultVecSR(f32* mtx, f32* src, f32* dst);
void PSMTXRotAxisRad(f32* mtx, f32* axis, f32 rad);
void PSMTXRotRad(f32* mtx, int axis, f32 rad);

#endif /* DOLPHIN_MTX_MTX_LEGACY_H_ */

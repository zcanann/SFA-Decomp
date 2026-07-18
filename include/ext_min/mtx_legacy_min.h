#ifndef EXT_MIN_MTX_LEGACY_MIN_H_
#define EXT_MIN_MTX_LEGACY_MIN_H_

#include "types.h"


f32 PSVECMag(f32* v);
void PSMTXMultVecSR(f32* mtx, f32* src, f32* dst);
void PSVECNormalize(f32* src, f32* dst);
f32 PSVECDotProduct(f32* a, f32* b);
void PSVECCrossProduct(f32* a, f32* b, f32* out);
void PSMTXCopy(f32* src, f32* dst);
void PSVECSubtract(f32* a, f32* b, f32* out);
#endif /* EXT_MIN_MTX_LEGACY_MIN_H_ */

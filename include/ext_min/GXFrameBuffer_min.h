#ifndef EXT_MIN_GXFRAMEBUFFER_MIN_H_
#define EXT_MIN_GXFRAMEBUFFER_MIN_H_

#include "types.h"


void GXSetDispCopySrc(u16 left, u16 top, u16 wd, u16 ht);
u32 GXSetDispCopyYScale(f32 vscale);
void GXSetDispCopyDst(u16 wd, u16 ht);
void GXSetDispCopyGamma(GXGamma gamma);
void GXCopyDisp(void* dest, GXBool clear);
#endif /* EXT_MIN_GXFRAMEBUFFER_MIN_H_ */

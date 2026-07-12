#ifndef TRACK_INTERSECT_API_H_
#define TRACK_INTERSECT_API_H_

#include "types.h"

u32 getScreenResolution(void);
u32 objAudioFn_8006ef38(void);
void _gxSetFogParams(void);
void geomDrawFn_800796f0(void);
void gxBlendFn_800789ac(void);
void gxBlendFn_80078b4c(void);
void gxTexColorFn_80079254(void);
void gxTextureFn_800794e0(void);
void mapInitFn_8006fccc(void);
void normalize(f32* x, f32* y, f32* z);
void textBlendSetupFn_80078a7c(void);
void textRenderChar(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);
void textRenderSetupFn_800795e8(void);
void textRenderSetupFn_80079804(void);
void textureSetupFn_800799c0(void);

#endif /* TRACK_INTERSECT_API_H_ */

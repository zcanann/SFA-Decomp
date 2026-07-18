#ifndef TRACK_INTERSECT_RENDER_SETUP_API_H_
#define TRACK_INTERSECT_RENDER_SETUP_API_H_

#include "types.h"

typedef struct ProjectedShadowTexture ProjectedShadowTexture;

void fn_80073AAC(void* texture, u32* colorA, u32* colorB);
void gxDebugTextureFn_80078c1c(void);
void fn_80078DFC(void);
void fn_80078ED0(void);
void fn_80079180(void);
void _gxSetTevColor1(int r, int g, int b, int a);
void _gxSetTevColor2(int r, int g, int b, int a);
void gxTevAddTextureFrameBlendStages(void);
void setupReflectionIndirectTev(u8 flag);
void objectShadow_setupSwappedProjectedTexture(ProjectedShadowTexture* shadow, u32* color, f32 mtx[3][4]);
void objectShadow_setupProjectedTexture(ProjectedShadowTexture* shadow, u32* color, f32 mtx[3][4]);
void fn_80077AD8(ProjectedShadowTexture* shadow, u32* color, f32 mtx[3][4], f32 depth);
void fn_80077EF8(ProjectedShadowTexture* shadow, u32* color, f32 mtx[3][4], f32 scale);
void textRenderSetupFn_80079804(void);
void textureSetupFn_800799c0(void);

#endif /* TRACK_INTERSECT_RENDER_SETUP_API_H_ */

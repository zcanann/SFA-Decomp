#ifndef TRACK_INTERSECT_RENDER_SETUP_API_H_
#define TRACK_INTERSECT_RENDER_SETUP_API_H_

#include "types.h"
#include "main/projected_shadow.h"

void setupAdditiveTintedTexture(void* texture, u32* colorA, u32* colorB);
void gxSetDebugTextMode(void);
void gxTevModulateRasStage(void);
void gxTevRasTimesColor1Stage(void);
void gxTevPassRasStage(void);
void _gxSetTevColor1(int r, int g, int b, int a);
void _gxSetTevColor2(int r, int g, int b, int a);
void gxTevAddTextureFrameBlendStages(void);
void setupReflectionIndirectTev(u8 flag);
void objectShadow_setupSwappedProjectedTexture(ProjectedShadowTexture* shadow, GXColor* color, f32 mtx[3][4]);
void objectShadow_setupProjectedTexture(ProjectedShadowTexture* shadow, GXColor* color, f32 mtx[3][4]);
void objectShadow_setupProjectedTextureDepthFade(ProjectedShadowTexture* shadow, GXColor* color, f32 mtx[3][4],
                                                 f32 depth);
void objectShadow_setupProjectedTextureChannel(ProjectedShadowTexture* shadow, GXColor* color, f32 mtx[3][4],
                                               f32 scale);
/*
 * Closes out the TEV pipeline configuration that drawViewFinderAperture etc. open:
 * pushes the current ind-stage / chan-ctrl / tex-gen counts in
 * gTevIndStageCount..00B back into GX, and if the global tint alpha
 * gHudTintAlpha isn't fully transparent (0xFF) appends one final TEV
 * stage that K-multiplies the tint over the existing color, advancing
 * gTevStageCursor (TEV stage cursor) and gTevStageCount (stage count).
 */
void gxTevCommitStages(void);
void gxTevResetStages(void);

#endif /* TRACK_INTERSECT_RENDER_SETUP_API_H_ */

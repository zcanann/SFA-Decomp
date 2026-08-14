#ifndef TRACK_INTERSECT_H_
#define TRACK_INTERSECT_H_

#include "dolphin/gx.h"
#include "dolphin/mtx.h"
#include "game/objects/object.h"
#include "track/intersect_depth_read_api.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_hud_api.h"
#include "track/intersect_geom_api.h"
#include "track/intersect_screen_api.h"
#include "track/intersect_whirlpool_api.h"
#include "main/projected_shadow.h"
#include "types.h"

void* surfaceSfxGetRecord(u32 i);
void waterFxUpdate(f32 step);
void waterFxDraw(void);
void waterFxSpawnContactEffect(u8* obj, f32* pos, u8 flip, u8 type);
void waterFxSetDisabled(int disabled);
void waterFxInit(void);
void mtx44Perspective(f32* matrix, u16* perspectiveNorm, f32 fovY, f32 aspect, f32 nearPlane, f32 farPlane, f32 scale);
void normalize(f32* x, f32* y, f32* z);
void mtx44Identity(f32* matrix);
void resetSomeGxFlags(void);
void fogSetRange(f32 start, f32 end);
void setFogColorRgb(u8 red, u8 green, u8 blue);
void screenImageDraw(u8 alpha);
void doSpiritVisionFilter(void);
void doColorFilter(u8* mod);
void doDistortionFilter(f32* position, f32 radius, u8* modulation, f32 angle);
int moonFxRenderCallback(u8* obj, void** objB, int slot);
void drawOrthoTexturedQuad(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2, int z);
void textRenderChar(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2);
void drawRect(f32 sx, f32 sy, int x, int y);
void objectShadow_setupSwappedProjectedTexture(ProjectedShadowTexture* shadow, GXColor* colorPtr, Mtx mtx);
void objectShadow_setupProjectedTexture(ProjectedShadowTexture* shadow, GXColor* colorPtr, Mtx mtx);
void objectShadow_setupProjectedTextureDepthFade(ProjectedShadowTexture* shadow, GXColor* colorPtr, Mtx mtx, f32 depth);
void objectShadow_setupProjectedTextureChannel(ProjectedShadowTexture* shadow, GXColor* colorPtr, Mtx mtx, f32 scale);
void gxSetOpaqueNoZWriteMode(void);
void gxSetAdditiveBlendZTest(void);
void gxSetAdditiveBlendNoZTest(void);
void gxSetAlphaBlendNoZTest(void);
void gxSetAlphaBlendZTest(void);
void textRenderSetup(void);
void gxTevAddColor1Stage(void);
void gxTevModulateColor1Stage(void);
void gxTevColor1TexAlphaStage(void);
void gxTevTextureTimesColor1Stage(void);
void drawViewFinderAperture(f32 sx, f32 sy, u8 a, u8 flag);
void drawSnowFlashOverlay(f32 s1, u8 flashAlpha, void* vec, f32 s2, u8 alpha0, u8 alpha1, f32 s3);
void doHeatEffect(u8 alpha);
void renderMotionBlur(f32 alpha);
void doBlurFilter(f32 wx, f32 wy, f32 wz, u8 param4, u8 param5);
void setupWaterReflectionTev(Texture* handle1, Texture* handle2);
void setupReflectionDistortTev(Texture* texHandle);
void setupReflectionBumpDistortTev(void* texture);
void setupWaterCausticTev(void);
void loadReflectionTexMtxs(void);

#endif /* TRACK_INTERSECT_H_ */

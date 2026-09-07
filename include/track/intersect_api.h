#ifndef TRACK_INTERSECT_API_H_
#define TRACK_INTERSECT_API_H_

#include "types.h"
#include "track/intersect_depth_read_api.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_geom_api.h"
#include "track/intersect_render_setup_api.h"
#include "track/intersect_screen_api.h"

struct ObjDef;

void intersectModLineBuild(struct ObjDef* definition);
void gxSetOpaqueZWriteMode(void);
void gxSetAdditiveBlendNoZTest(void);
void gxSetAlphaBlendZTest(void);
void gxTevModulateColor1Stage(void);
void gxTevColor1TexAlphaStage(void);
void waterFxInit(void);
void waterFxSetDisabled(int disabled);
void mtx44Perspective(f32* matrix, u16* perspectiveNorm, f32 fovY, f32 aspect, f32 nearPlane, f32 farPlane, f32 scale);
void normalize(f32* x, f32* y, f32* z);
void gxSetAlphaBlendNoZTest(void);
void textRenderChar(int x0, int y0, int x1, int y1, f32 u0, f32 v0, f32 u1, f32 v1);
void gxTevTextureTimesColor1Stage(void);
void setupWaterReflectionTev(Texture* handle1, Texture* handle2);
void setupReflectionDistortTev(Texture* textureHandle);
void setupReflectionBumpDistortTev(void* texture);
void loadReflectionTexMtxs(void);
void gxSetAdditiveBlendZTest(void);
void gxTevAddColor1Stage(void);
/* Per-frame alpha decrement of the two water-effect pools. */
void waterFxUpdate(f32 step);
void waterFxDraw(void);
int moonFxRenderCallback(u8* obj, void** model, int slot);
void resetSomeGxFlags(void);
void fogSetRange(f32 start, f32 end);
void setFogColorRgb(u8 red, u8 green, u8 blue);
void screenImageDraw(u8 alpha);
void doColorFilter(u8* modulation);
void doDistortionFilter(f32* position, f32 radius, u8* modulation, f32 angle);
void doSpiritVisionFilter(void);
/*
 * Fullscreen 640x480 texture-tinted quad with shape-controlled alpha:
 * `flag != 0` lights the screen with three pre-set GXColors stamped into
 * K0/T1/T2; `flag == 0` instead does a single K0 modulate where K0's
 * alpha is the caller's byte divided by 4. Builds a per-call 3x4 tex
 * coord matrix that scales the source texture by 1/scaleX and 1/scaleY
 * with a sub-pixel offset baked from -320.0f/50.
 */
void drawViewFinderAperture(f32 scaleX, f32 scaleY, u8 alpha, u8 flag);
void doHeatEffect(u8 alpha);
void drawOrthoTexturedQuad(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2, int z);
/*
 * Generic ortho-projected single-color quad blit. Sets the GX state up
 * fresh (no tex coords, color from constant K0, additive blend, fixed
 * 0x3C texmtx) then emits four GX_VTXFMT1 vertices at z=-0x18C with
 * width 4*size_x and height 4*size_y in screen pixels. Used as the
 * "draw fullscreen tint" primitive by the dialog code in cardShowLoadingMsg.
 */
void drawRect(f32 sx, f32 sy, int x, int y);
void drawSnowFlashOverlay(f32 s1, u8 flashAlpha, void* vec, f32 s2, u8 alpha0, u8 alpha1, f32 s3);
void gxSetOpaqueNoZWriteMode(void);
void textRenderSetup(void);
/*
 * Fullscreen 640x480 textured quad with caller-supplied alpha. The alpha
 * is multiplied by lbl_803DEF20 (a 0..255 scale), converted to int and
 * stamped into byte 3 of the K0 GXColor cache (gMotionBlurKColor). Sets up
 * one TEV stage that K-multiplies the texture by alpha; uses fixed UVs
 * 0..0x80 so the texture maps once across the screen. Used when fading
 * the screen to texture (e.g. boot logo / "now loading").
 */
void renderMotionBlur(f32 alpha);
void doBlurFilter(f32 wx, f32 wy, f32 wz, u8 param4, u8 param5);
void setupWaterCausticTev(void);

#endif /* TRACK_INTERSECT_API_H_ */

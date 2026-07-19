#ifndef TRACK_INTERSECT_H_
#define TRACK_INTERSECT_H_

#include "dolphin/gx.h"
#include "main/game_object.h"
#include "track/intersect_depth_read_api.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_hud_api.h"
#include "track/intersect_geom_api.h"
#include "track/intersect_screen_api.h"
#include "track/intersect_whirlpool_api.h"
#include "ghidra_import.h"

typedef struct ProjectedShadowTexture ProjectedShadowTexture;

void* fn_8006F388(u32 i);
void timeFn_8006f400(f32 step);
void drawFn_8006f500(void);
void playerEarthWalkerAudioFn_8006f950(u8* obj, f32* pos, u8 flip, u8 type);
void fn_8006FC00(int param_1);
void mapInitFn_8006fccc(void);
void matrixFn_8006ff0c(float* param_6, short* param_7, f32 param_1, f32 param_2, f32 param_3, f32 param_4, f32 param_5);
void normalize(f32* x, f32* y, f32* z);
void fn_80070234(f32* param_1);
void resetSomeGxFlags(void);
void fogFn_80070404(f32 a, f32 b);
void fn_800704FC(u8 param_1, u8 param_2, u8 param_3);
void screenImageDraw(u8 alpha);
void doSpiritVisionFilter(void);
void doColorFilter(u8* mod);
void doDistortionFilter(f32* position, f32 radius, u8* modulation, f32 angle);
int moonFxCb_80074110(u8* obj, int* objB, int slot);
void skyDrawFn_80075d5c(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2, int z);
void textRenderChar(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2);
void drawRect(f32 sx, f32 sy, int x, int y);
void objectShadow_setupSwappedProjectedTexture(ProjectedShadowTexture* shadow, u32* colorPtr, Mtx mtx);
void objectShadow_setupProjectedTexture(ProjectedShadowTexture* shadow, u32* colorPtr, Mtx mtx);
void trackIntersect_drawColorBand(void);
void fn_80077AD8(ProjectedShadowTexture* shadow, u32* colorPtr, Mtx mtx, f32 depth);
void fn_80077EF8(ProjectedShadowTexture* shadow, u32* colorPtr, Mtx mtx, f32 scale);
void FUN_80070ec8(void);
void fn_8007880C(void);
void gxBlendFn_800788dc(void);
void gxBlendFn_800789ac(void);
void textBlendSetupFn_80078a7c(void);
void gxBlendFn_80078b4c(void);
void textRenderSetup(void);
void gxTevAddColor1Stage(void);
void gxTexColorFn_80079254(void);
void gxTextureFn_800794e0(void);
void textRenderSetupFn_800795e8(void);
void drawViewFinderAperture(f32 sx, f32 sy, u8 a, u8 flag);
void drawFn_80079e64(f32 s1, u8 mtxIdx, void* vec, f32 s2, u8 alpha0, u8 alpha1, f32 s3);
void doHeatEffect(u8 alpha);
void renderMotionBlur(f32 alpha);
void doBlurFilter(f32 wx, f32 wy, f32 wz, u8 param4, u8 param5);
void fn_8007BD8C(int handle1, int handle2);
void fn_8007C664(int param_1);
void fn_8007CAF4(void* texture);
void gxTextureSetupFn_8007cf7c(void);
void fn_8007D670(void);
void FUN_800723a0(void);

#endif /* TRACK_INTERSECT_H_ */

#ifndef TRACK_INTERSECT_INTERNAL_H_
#define TRACK_INTERSECT_INTERNAL_H_

#include "global.h"
#include "dolphin/gx.h"
#include "main/texture.h"

extern f32 gFogNearZ;
extern f32 gFogFarZ;
extern u32 gTevStageCursor;
extern u32 gTevTexCoordCursor;
extern u32 gTevTexMapCursor;
extern f32 gFogStartZ;
extern f32 gFogEndZ;
extern GXColor gFogColor;
extern u8 gGxZModeValid;
extern u8 gGxZCompLocValid;
extern u8 gGxZModeCompareEnable;
extern int gGxZModeCompareFunc;
extern u8 gGxZModeUpdateEnable;
extern u8 gGxZCompLocCached;
extern u8 gTevStageCount;
extern u8 gTevTexGenCount;
extern u8 gTevChanCount;
extern u8 gTevIndStageCount;
extern u32 screenWidth;
extern f32 hudMatrix[4][4];

typedef struct RippleEntry
{
    f32 x, y, z;
    u16 id;
    u8 alpha;
    u8 flip;
} RippleEntry;
typedef struct SplashQuad
{
    f32 v[12];
    u16 angle;
    u8 type;
    u8 alpha;
    u8 flip;
    u8 pad[3];
} SplashQuad;

STATIC_ASSERT(sizeof(RippleEntry) == 0x10);
STATIC_ASSERT(sizeof(SplashQuad) == 0x38);

typedef struct WaterFxState
{
    f32 scales[4];
    Texture* textures[4];
    RippleEntry ripples[0x100];
    SplashQuad quads[0x100];
} WaterFxState;
STATIC_ASSERT(offsetof(WaterFxState, textures) == 0x10);
STATIC_ASSERT(offsetof(WaterFxState, ripples) == 0x20);
STATIC_ASSERT(offsetof(WaterFxState, quads) == 0x1020);
STATIC_ASSERT(sizeof(WaterFxState) == 0x4820);

extern f32 gWaterFxState[4];
extern Texture* gWaterFxTextures[4];
extern RippleEntry gWaterRipples[0x100];
extern SplashQuad gWaterSplashQuads[0x100];
extern u8 gWaterFxDisabled;
extern u8 gWaterQuadWriteIdx;
extern u8 gWaterRippleWriteIdx;
extern u8 gWaterFxBank;

extern int lbl_803DD03C;
extern int gPerspectiveMtx[];
extern u8 gMoonFxDayNo;
extern f32 gSnowFlashOverlayAngle;
extern u8 gReflectionTintAlpha;
extern u8 gHudTintAlpha;
extern GXColor gReflectionBumpTintColor;
extern GXColor gReflectionBumpKColor;
extern GXColor gReflectionTintColor;
extern GXColor gReflectionKColor;
extern GXColor gWaterReflectionKColorR;
extern GXColor gWaterReflectionKColorG;
extern GXColor gWaterReflectionKColorB;
extern GXColor gBlurFilterKColor;
extern GXColor gMotionBlurKColor;
extern GXColor gHeatEffectKColor;
extern GXColor gObjectShadowTevColor;
extern f32 gCausticReflectionDiskScale;
extern f32 gTrackProjectedTexScale;
extern f32 gTrackNormalTexScale;
extern f32 gFrozenReflectionNormalScale;
extern GXColor gFrozenTintColor;
extern f32 gFrozenWhirlpoolTexScale;
extern f32 gDistortionTexCoordScale;
extern f32 gDistortionAlphaRadius;
extern f32 gDistortionIndMtxRadius;
extern GXColor gSpiritVisionKColor0;
extern GXColor gSpiritVisionKColor1;
extern GXColor gSpiritVisionKColor2;
extern GXColor gSpiritVisionRegColor;
extern GXColor gScreenImageRegColor;
extern GXColor gScreenImageKColor0;
extern GXColor gScreenImageKColor1;
extern GXColor gScreenImageKColor2;
extern GXColor gScreenImageKColor3;
extern GXColor gWhirlpoolReflectionTintColor;
extern GXColor gWhirlpoolReflectionKColor;

extern GXColor gWaterCausticKColor;

#endif /* TRACK_INTERSECT_INTERNAL_H_ */

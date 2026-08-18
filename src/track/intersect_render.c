#include "global.h"
#include "dolphin/card.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/gamebits_api.h"
#include "main/rcp_dolphin_api.h"
#include "dolphin/mtx.h"
#include "track/intersect.h"
#include "track/intersect_depth_read_api.h"
#include "track/intersect_fog_api.h"
#include "track/intersect_texture_api.h"
#include "main/model.h"
#include "main/model_engine.h"
#include "main/texture.h"
#include "main/dll/player_state.h"
#include "main/sky_interface.h"
#include "main/textrender_api.h"
#include "main/gametext_color_api.h"
#include "main/gameloop_api.h"
#include "main/frame_timing.h"
#include "main/trig.h"
#include "main/camera.h"
#include "main/track_dolphin_api.h"
#include "main/vecmath.h"
#include "main/object_render.h"
#include "game/objects/object.h"
#include "main/screen_transition.h"
#include "dolphin/gx/GXPixel.h"
#include "main/mm.h"
#include "main/newshadows.h"
#include "main/objprint_api.h"
#include "main/maketex_api.h"
#include "main/pad.h"
#include "main/pi_dolphin.h"
#include "main/shader_api.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXTransform.h"
#include "main/hud_visibility_api.h"
#include "main/pi_dolphin_api.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_geom_api.h"
#include "track/intersect_hud_api.h"
#include "track/intersect_internal.h"

typedef void (*GXSetAlphaCompareIntFn)(int comp0, int ref0, int op, int comp1, int ref1);


typedef struct
{
    f32 m[6];
} IndMtxInit;

typedef struct
{
    IndMtxInit ind;
    u32 blk[6][7];
} IndStageInitData;

static const IndStageInitData sIndStageInitData = {
    {{0.5f, 0.0f, 0.0f, 0.0f, 0.5f, 0.0f}},
    {{0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF},
     {2, 2, 2, 2, 2, 1, 0},
     {0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF},
     {2, 2, 2, 1, 0, 0, 0},
     {0xF, 0xF, 0xF, 0xF, 0xF, 0xF, 0xF},
     {2, 1, 0, 0, 0, 0, 0}}};
static const IndMtxInit sIndMtxZeroInit = {{0.0f, 0.0f, 0.0f, 0.0f, 0.0f, 0.0f}};


extern GXColor gProjectedShadowFogColor;

f32 gWaterReflectionIndTexMtx[3][2][3] = {
    {{0.0f, 0.5f, 0.0f}, {0.0f, 0.0f, -0.5f}},
    {{0.0f, 0.8f, 0.0f}, {0.0f, 0.0f, 0.8f}},
    {{0.0f, -0.2f, 0.0f}, {0.0f, 0.0f, 0.2f}}};
f32 gFrozenObjectIndTexMtx[2][3] = {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}};
f32 gScreenImageIndTexMtx1[2][3] = {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}};
f32 gScreenImageIndTexMtx2[2][3] = {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}};
f32 gWhirlpoolIndTexMtx[2][3] = {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}};

extern inline float sqrtf(float x)
{
    volatile float y;
    if (x > 0.0f)
    {
        double guess = __frsqrte((double)x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        y = (float)(x * guess);
        return y;
    }
    return x;
}

typedef struct StageCountTable
{
    u8 count[7];
} StageCountTable;

static const GXColor sApertureColorBlack = {0, 0, 0, 255};
static const GXColor sApertureColorEdge = {0, 0, 0, 4};
static const GXColor sApertureColorCentre = {0, 0, 0, 255};
static const StageCountTable sProjectedShadowStageCounts = {{3, 3, 2, 2, 1, 1, 1}};
static const GXColor sMoonFxTint = {0, 0, 255, 255};
static const GXColor sDistortKColor0 = {0x42, 0x42, 0x42, 0};
static const GXColor sDistortKColor1 = {0x81, 0x81, 0x81, 0};
static const GXColor sDistortKColor2 = {0x19, 0x19, 0x19, 0};
static const GXColor sDistortTevColor = {0x10, 0x10, 0x10, 0};
static const GXColor sColorFilterKColor0 = {0x42, 0x42, 0x42, 0};
static const GXColor sColorFilterKColor1 = {0x6E, 0x6E, 0x6E, 0};
static const GXColor sColorFilterKColor2 = {0x14, 0x14, 0x14, 0};
static const GXColor sColorFilterTevColor = {0x0A, 0x0A, 0x0A, 255};

extern u32 gProjectedShadowFogColorBits;



void gxSetPeControl_ZCompLoc_(u8 zCompLoc)
{
    if (gGxZCompLocCached != zCompLoc || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(zCompLoc);
        gGxZCompLocCached = zCompLoc;
        gGxZCompLocValid = 1;
    }
}


void gxSetZMode_(u8 compareEnable, int compareFunc, u8 updateEnable)
{
    if (gGxZModeCompareEnable != compareEnable || gGxZModeCompareFunc != compareFunc ||
        gGxZModeUpdateEnable != updateEnable || gGxZModeValid == 0)
    {
        GXSetZMode(compareEnable, compareFunc, updateEnable);
        gGxZModeCompareEnable = compareEnable;
        gGxZModeCompareFunc = compareFunc;
        gGxZModeUpdateEnable = updateEnable;
        gGxZModeValid = 1;
    }
}

void resetSomeGxFlags(void)
{
    gGxZModeValid = 0;
    gGxZCompLocValid = 0;
}

void setHudOpacity(u8 opacity)
{
    gHudTintAlpha = opacity;
}

void _gxSetFogParams(void)
{
    GXColor c = gFogColor;
    GXSetFog(GX_FOG_PERSP_EXP, gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ, c);
}

void fogSetRange(f32 start, f32 end)
{
    f32 xc, yc, x, y;
    GXColor c;

    gFogNearZ = Camera_GetNearPlane();
    gFogFarZ = Camera_GetFarPlane();

    x = 0.001f * start;
    y = 0.001f * end;

    xc = (x < 0.0f) ? 0.0f : ((x > 2.0f) ? 2.0f : x);
    yc = (y < 0.0f) ? 0.0f : ((y > 2.0f) ? 2.0f : y);

    gFogStartZ = xc * (gFogFarZ - gFogNearZ) + gFogNearZ;
    gFogEndZ = yc * (gFogFarZ - gFogNearZ) + gFogNearZ;
    c = gFogColor;
    GXSetFog(GX_FOG_PERSP_EXP, gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ, c);
}

void getFogColorRgb(u8* rgbOut)
{
    rgbOut[0] = gFogColor.r;
    rgbOut[1] = gFogColor.g;
    rgbOut[2] = gFogColor.b;
}

void setFogColorRgb(u8 red, u8 green, u8 blue)
{
    gFogColor.r = red;
    gFogColor.g = green;
    gFogColor.b = blue;
}

int renderWhirlpool(void* obj_a, void** obj_b, int slot)
{

    Shader* renderOp;
    Texture* tex2;
    ModelFileHeader* model;
    int handle1;
    u8 ignoredLightColor;
    Mtx scaleMtx;
    f32 fA, fB;
    GXBool wrapBit;
    void (*pcb)(void*, void**, int);

    model = obj_b[0];
    renderOp = ObjModel_GetRenderOp((ModelFileHeader*)model, slot);
    handle1 = *(int*)Shader_getLayer(renderOp, 0);
    selectTexture((Texture*)textureIdxToPtr(handle1), 0);
    selectReflectionTexture(1);
    tex2 = textureIdxToPtr(renderOp->auxTextureIndex);
    wrapBit = (tex2->maxLod - tex2->minLod > 0) ? GX_TRUE : GX_FALSE;
    GXInitTexObj((void*)tex2->gxTexObj, (u8*)tex2 + sizeof(Texture), tex2->width, tex2->height,
                 tex2->format, GX_REPEAT, GX_REPEAT, wrapBit);
    selectTexture((Texture*)tex2, 2);
    GXLoadTexMtxImm(gCameraLightPerspectiveScaledMatrix, GX_PTTEXMTX6, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_POS, 0, GX_FALSE, GX_PTTEXMTX6);
    GXLoadTexMtxImm(gCameraLightPerspectiveFlipYMatrix, GX_PTTEXMTX7, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_POS, 0, GX_FALSE, GX_PTTEXMTX7);
    newshadows_getReflectionScrollOffsets(&fA, &fB);
    PSMTXScale(scaleMtx, 1.0f, 1.0f, 1.0f);
    scaleMtx[1][3] = -fA;
    GXLoadTexMtxImm(scaleMtx, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);

    if (isHeavyFogEnabled() != 0)
    {
        gWhirlpoolReflectionTintColor.r = gFogColor.r;
        gWhirlpoolReflectionTintColor.g = gFogColor.g;
        gWhirlpoolReflectionTintColor.b = gFogColor.b;
        gWhirlpoolReflectionTintColor.a = 0x80;
    }
    else
    {
        (*gSkyInterface)
            ->getCurrentAmbientAndLightColors(&gWhirlpoolReflectionTintColor.r,
                                              &gWhirlpoolReflectionTintColor.g,
                                              &gWhirlpoolReflectionTintColor.b,
                                              &ignoredLightColor, &ignoredLightColor, &ignoredLightColor);
        gWhirlpoolReflectionTintColor.r = (u8)((int)gWhirlpoolReflectionTintColor.r >> 3);
        gWhirlpoolReflectionTintColor.g = (u8)((int)gWhirlpoolReflectionTintColor.g >> 3);
        gWhirlpoolReflectionTintColor.b = (u8)((int)gWhirlpoolReflectionTintColor.b >> 3);
        gWhirlpoolReflectionTintColor.a = gReflectionTintAlpha;
    }
    GXSetTevColor(GX_TEVREG2, gWhirlpoolReflectionTintColor);
    GXSetTevKColor(GX_KCOLOR0, gWhirlpoolReflectionKColor);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K0);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD2, GX_TEXMAP2);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, gWhirlpoolIndTexMtx, -1);
    GXSetIndTexMtx(GX_ITM_1, gWhirlpoolIndTexMtx, -2);
    GXSetTevIndirect(GX_TEVSTAGE0, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_C2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (isHeavyFogEnabled() != 0)
    {
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVPREV);
    }
    else
    {
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    }
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_CPREV, GX_CC_TEXC, GX_CC_KONST, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD3, GX_TEXMAP0, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_CPREV, GX_CC_TEXC, GX_CC_TEXA, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_RASA);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumIndStages(1);
    GXSetNumChans(1);
    GXSetNumTexGens(4);
    GXSetNumTevStages(3);

    pcb = (void (*)(void*, void**, int))ObjModel_GetPostRenderCallback((ObjModel*)obj_b);
    if (pcb != 0)
    {
        pcb(obj_a, obj_b, slot);
    }
    else
    {
        u8 zCompLoc = 1;
        if (((GameObject*)obj_a)->anim.renderAlpha < 0xFF || (renderOp->flags & 0x40000000) != 0 ||
            renderOp->alpha < 0xFF)
        {
            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
            if ((model->flags & 0x400) != 0)
            {
                if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                    gGxZModeValid == 0)
                {
                    GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 0;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
            else if ((model->flags & 0x2000) != 0)
            {
                zCompLoc = 0;
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 1 ||
                    gGxZModeValid == 0)
                {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 1;
                    gGxZModeValid = 1;
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_GREATER, objGetAlphaCompareThreshold(), GX_AOP_AND, GX_GREATER, objGetAlphaCompareThreshold());
            }
            else
            {
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                    gGxZModeValid == 0)
                {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
        }
        else
        {
            if ((renderOp->flags & 0x400) != 0)
            {
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                if ((model->flags & 0x400) != 0)
                {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                }
                else
                {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 1 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_GREATER, 0xC0, GX_AOP_AND, GX_GREATER, 0xC0);
            }
            else
            {
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                if ((model->flags & 0x400) != 0)
                {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                }
                else
                {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 1 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
        }
        if ((renderOp->flags & 0x400) != 0)
        {
            zCompLoc = 0;
        }
        if (gGxZCompLocCached != zCompLoc || gGxZCompLocValid == 0)
        {
            GXSetZCompLoc(zCompLoc);
            gGxZCompLocCached = zCompLoc;
            gGxZCompLocValid = 1;
        }
    }
    if ((renderOp->flags & 0x8) != 0)
    {
        GXSetCullMode(GX_CULL_BACK);
    }
    else
    {
        GXSetCullMode(GX_CULL_NONE);
    }
    return 1;
}

void screenImageDraw(u8 alpha)
{

    Mtx mtx_60;
    Mtx mtx_30;
    Texture* handle;
    f32 fA;
    f32 fB;

    newshadows_getReflectionScrollOffsets(&fA, &fB);
    getNewShadowCausticTexture((u32*)&handle);
    updateReflectionTextures();
    selectReflectionTexture(0);
    selectTexture(handle, 1);
    gScreenImageKColor0.a = alpha;
    GXSetTevKColor(GX_KCOLOR0, gScreenImageKColor0);
    GXSetTevKColor(GX_KCOLOR1, gScreenImageKColor1);
    GXSetTevKColor(GX_KCOLOR2, gScreenImageKColor2);
    GXSetTevKColor(GX_KCOLOR3, gScreenImageKColor3);

    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);

    PSMTXScale(mtx_60, 0.2f, 0.2f, 1.0f);
    mtx_60[1][3] = -fA;
    GXLoadTexMtxImm(mtx_60, GX_TEXMTX0, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);

    PSMTXScale(mtx_60, 0.25f, 0.25f, 1.0f);
    PSMTXRotRad(mtx_30, 'z', 0.7853982f);
    PSMTXConcat(mtx_30, mtx_60, mtx_60);
    mtx_60[0][3] = fB;
    mtx_60[1][3] = fB;
    GXLoadTexMtxImm(mtx_60, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);

    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, gScreenImageIndTexMtx1, -3);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_0, GX_ITW_0, 0, 0, GX_ITBA_S);

    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD2, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_1, gScreenImageIndTexMtx2, -3);
    GXSetTevIndirect(GX_TEVSTAGE2, GX_INDTEXSTAGE1, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_S);

    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_ALPHA_BUMPN);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_RASA);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD0, GX_TEXMAP0, GX_ALPHA_BUMPN);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_APREV, GX_CA_ZERO, GX_CA_ZERO, GX_CA_RASA);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVPREV);

    GXSetTevKColorSel(GX_TEVSTAGE3, GX_TEV_KCSEL_K0);
    GXSetTevKAlphaSel(GX_TEVSTAGE3, GX_TEV_KASEL_1_2);
    GXSetTevDirect(GX_TEVSTAGE3);
    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_ZERO, GX_CC_KONST, GX_CC_CPREV, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_KONST, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_2, GX_TRUE, GX_TEVREG0);

    GXSetTevKColorSel(GX_TEVSTAGE4, GX_TEV_KCSEL_K1);
    GXSetTevKAlphaSel(GX_TEVSTAGE4, GX_TEV_KASEL_1_2);
    GXSetTevDirect(GX_TEVSTAGE4);
    GXSetTevOrder(GX_TEVSTAGE4, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE4, GX_CC_KONST, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C0);
    GXSetTevAlphaIn(GX_TEVSTAGE4, GX_CA_APREV, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE4, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(GX_TEVSTAGE4, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_2, GX_TRUE, GX_TEVREG1);

    GXSetTevKColorSel(GX_TEVSTAGE5, GX_TEV_KCSEL_K2);
    GXSetTevOrder(GX_TEVSTAGE5, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE5);
    GXSetTevColorIn(GX_TEVSTAGE5, GX_CC_ZERO, GX_CC_KONST, GX_CC_CPREV, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE5, GX_CA_A0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A1);
    GXSetTevSwapMode(GX_TEVSTAGE5, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevKColorSel(GX_TEVSTAGE6, GX_TEV_KCSEL_K3);
    GXSetTevKAlphaSel(GX_TEVSTAGE6, GX_TEV_KASEL_1_2);
    GXSetTevColor(GX_TEVREG2, gScreenImageRegColor);
    GXSetTevOrder(GX_TEVSTAGE6, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE6);
    GXSetTevColorIn(GX_TEVSTAGE6, GX_CC_KONST, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1);
    GXSetTevAlphaIn(GX_TEVSTAGE6, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE6, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE6, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(GX_TEVSTAGE6, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevKAlphaSel(GX_TEVSTAGE7, GX_TEV_KASEL_K0_A);
    GXSetTevDirect(GX_TEVSTAGE7);
    GXSetTevOrder(GX_TEVSTAGE7, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE7, GX_CC_C1, GX_CC_C0, GX_CC_APREV, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE7, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE7, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE7, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE7, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetNumTexGens(3);
    GXSetNumIndStages(2);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTevStages(8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(GX_IDENTITY);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(GX_PNMTX0);
}

void doSpiritVisionFilter(void)
{


    updateReflectionTextures();
    selectReflectionTexture(0);
    GXSetTevSwapModeTable(GX_TEV_SWAP0, GX_CH_GREEN, GX_CH_BLUE, GX_CH_RED, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP2, GX_CH_GREEN, GX_CH_GREEN, GX_CH_GREEN, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_BLUE, GX_CH_BLUE, GX_CH_BLUE, GX_CH_ALPHA);

    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);

    GXSetTevKColor(GX_KCOLOR0, gSpiritVisionKColor0);
    GXSetTevKColor(GX_KCOLOR1, gSpiritVisionKColor1);
    GXSetTevKColor(GX_KCOLOR2, gSpiritVisionKColor2);
    GXSetTevColor(GX_TEVREG0, gSpiritVisionRegColor);

    GXSetNumTexGens(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTevStages(4);

    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C0);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A0);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP1);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K1);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K1_A);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP2);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);

    GXSetTevKColorSel(GX_TEVSTAGE2, GX_TEV_KCSEL_K2);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP3);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevDirect(GX_TEVSTAGE3);
    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_CPREV, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(GX_IDENTITY);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
    GXSetTevSwapModeTable(GX_TEV_SWAP0, GX_CH_RED, GX_CH_GREEN, GX_CH_BLUE, GX_CH_ALPHA);
}

void doColorFilter(u8* mod)
{
    GXColor c0, c1, c2, c3;

    c0 = sColorFilterKColor0;
    c1 = sColorFilterKColor1;
    c2 = sColorFilterKColor2;
    c3 = sColorFilterTevColor;
    {
        int s0, s1, s2;
        c0.r = (u8)(c0.r + (s0 = mod[0] >> 3));
        c0.g = (u8)(c0.g + (s1 = mod[1] >> 3));
        c0.b = (u8)(c0.b + (s2 = mod[2] >> 3));
        c1.r = (u8)(c1.r + s0);
        c1.g = (u8)(c1.g + s1);
        c1.b = (u8)(c1.b + s2);
        c2.r = (u8)(c2.r + s0);
        c2.g = (u8)(c2.g + s1);
        c2.b = (u8)(c2.b + s2);
    }

    updateReflectionTextures();
    selectReflectionTexture(0);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP2, GX_CH_GREEN, GX_CH_GREEN, GX_CH_GREEN, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_BLUE, GX_CH_BLUE, GX_CH_BLUE, GX_CH_ALPHA);

    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);

    GXSetTevKColor(GX_KCOLOR0, c0);
    GXSetTevKColor(GX_KCOLOR1, c1);
    GXSetTevKColor(GX_KCOLOR2, c2);
    GXSetTevColor(GX_TEVREG0, c3);

    GXSetNumTexGens(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTevStages(3);

    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C0);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A0);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP1);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K1);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K1_A);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP2);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);

    GXSetTevKColorSel(GX_TEVSTAGE2, GX_TEV_KCSEL_K2);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP3);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(GX_IDENTITY);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}

static inline f32 distortSqrtf(f32 x)
{
    volatile float y;
    double guess = __frsqrte((double)x);
    guess = 0.5 * guess * (3.0 - guess * guess * x);
    guess = 0.5 * guess * (3.0 - guess * guess * x);
    guess = 0.5 * guess * (3.0 - guess * guess * x);
    y = (float)(x * guess);
    return y;
}

void doDistortionFilter(f32* pos, f32 radius, u8* mod, f32 angle)
{
    Mtx mtx_d0;
    Mtx mtx_a0;
    Mtx mtx_70;
    f32 indMtx[6];
    Texture* handle1;
    Texture* handle2;
    f32 proj5, proj4, proj3, proj2, proj1, proj0;
    GXColor c0;
    GXColor c1;
    GXColor c2;
    GXColor c3;
    Texture* handle3;
    f32 x, z;

    c0 = sDistortKColor0;
    c1 = sDistortKColor1;
    c2 = sDistortKColor2;
    c3 = sDistortTevColor;
    {
        int b0, b1, b2;
        int s0, s1, s2;
        c0.r = (u8)(c0.r + (s0 = (b0 = mod[0]) >> 2));
        c0.g = (u8)(c0.g + (s1 = (b1 = mod[1]) >> 2));
        c0.b = (u8)(c0.b + (s2 = (b2 = mod[2]) >> 2));
        c1.r = (u8)(c1.r + s0);
        c1.g = (u8)(c1.g + s1);
        c1.b = (u8)(c1.b + s2);
        c2.r = (u8)(c2.r + s0);
        c2.g = (u8)(c2.g + s1);
        c2.b = (u8)(c2.b + s2);
        c3.r = (u8)(c3.r + (b0 >> 3));
        c3.g = (u8)(c3.g + (b1 >> 3));
        c3.b = (u8)(c3.b + (b2 >> 3));
    }

    x = pos[0];
    z = pos[2];
    x = x - playerMapOffsetX;
    z = z - playerMapOffsetZ;
    Camera_ProjectWorldSphere(x, pos[1], z, radius, &proj5, &proj4, &proj3, &proj2, &proj1, &proj0);
    proj3 += 1.0f;
    c0.a = (u8)(((u32)(16777216.0f * proj3) & 0x00FF0000) >> 16);

    selectReflectionTexture(0);
    getReflectionTexture2((u32*)&handle1);
    selectTexture(handle1, 1);
    getNewShadowRadialTexture(&handle2);
    selectTexture(handle2, 2);

    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP2, GX_CH_GREEN, GX_CH_GREEN, GX_CH_GREEN, GX_CH_ALPHA);
    GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_BLUE, GX_CH_BLUE, GX_CH_BLUE, GX_CH_ALPHA);

    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);

    PSMTXTrans(mtx_a0, 0.5f * (-proj5) - 0.5f, 0.5f * proj4 - 0.5f, 0.0f);
    {
        f32 s = gDistortionTexCoordScale;
        PSMTXScale(mtx_70, s / proj2, s / proj1, 0.0f);
    }
    PSMTXConcat(mtx_70, mtx_a0, mtx_d0);
    PSMTXTrans(mtx_a0, 0.5f, 0.5f, 0.0f);
    PSMTXConcat(mtx_a0, mtx_d0, mtx_d0);
    GXLoadTexMtxImm(mtx_d0, GX_TEXMTX0, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);

    {
        f32 r2 = gDistortionAlphaRadius / radius;
        f32 sr;
        sr = (r2 > 0.0f) ? distortSqrtf(r2) : r2;
        if (sr > 1.0f)
        {
            c1.a = 0xFF;
        }
        else
        {
            c1.a = 255.0f * sr;
        }
        sr *= 2.0f;
        if (sr > 1.0f)
            sr = 1.0f;
        c3.a = 255.0f * sr;
    }

    GXSetTevKColor(GX_KCOLOR0, c0);
    GXSetTevKColor(GX_KCOLOR1, c1);
    GXSetTevKColor(GX_KCOLOR2, c2);
    GXSetTevColor(GX_TEVREG0, c3);

    getNewShadowDistortionTexture(&handle3);
    selectTexture(handle3, 3);

    {
        f32 ind_s = gDistortionIndMtxRadius / radius;
        if (ind_s > 0.5f)
            ind_s = 0.5f;
        indMtx[0] = ind_s;
        indMtx[1] = 0.0f;
        indMtx[2] = 0.0f;
        indMtx[3] = 0.0f;
        indMtx[4] = ind_s;
        indMtx[5] = 0.0f;
    }

    PSMTXTrans(mtx_a0, 0.5f * (-proj5) - 0.5f, 0.5f * proj4 - 0.5f, 0.0f);
    PSMTXScale(mtx_70, 0.8f, 0.8f, 0.0f);
    PSMTXRotRad(mtx_d0, 'z', angle);
    PSMTXConcat(mtx_70, mtx_a0, mtx_70);
    PSMTXConcat(mtx_d0, mtx_70, mtx_d0);
    PSMTXTrans(mtx_a0, 0.5f, 0.5f, 0.0f);
    PSMTXConcat(mtx_a0, mtx_d0, mtx_d0);
    GXLoadTexMtxImm(mtx_d0, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);

    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD3, GX_TEXMAP3);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, (f32(*)[3])indMtx, 1);

    GXSetTevIndirect(GX_TEVSTAGE2, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetTevIndirect(GX_TEVSTAGE3, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetTevIndirect(GX_TEVSTAGE4, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);

    GXSetNumTexGens(4);
    GXSetNumIndStages(1);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTevStages(6);

    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_TEXA, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP1);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVREG2);

    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_KONST, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP1);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

    GXSetTevKColorSel(GX_TEVSTAGE2, GX_TEV_KCSEL_K0);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C0);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_APREV, GX_CA_A0, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP1);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

    GXSetTevKColorSel(GX_TEVSTAGE3, GX_TEV_KCSEL_K1);
    GXSetTevKAlphaSel(GX_TEVSTAGE3, GX_TEV_KASEL_K1_A);
    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_ZERO, GX_CA_A2, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP2);
    GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVREG2);

    GXSetTevKColorSel(GX_TEVSTAGE4, GX_TEV_KCSEL_K2);
    GXSetTevOrder(GX_TEVSTAGE4, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE4, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE4, GX_CA_A2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE4, GX_TEV_SWAP0, GX_TEV_SWAP3);
    GXSetTevColorOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

    GXSetTevDirect(GX_TEVSTAGE5);
    GXSetTevOrder(GX_TEVSTAGE5, GX_TEXCOORD2, GX_TEXMAP2, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE5, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE5, GX_CA_TEXA, GX_CA_ZERO, GX_CA_APREV, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE5, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_INVSRCALPHA, GX_BL_SRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetCurrentMtx(GX_IDENTITY);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}

int objFrozenRenderCb(void* obj_a, void** obj_b, int slot)
{
    Mtx mtx_54;
    Mtx mtx_24;
    Shader* renderOp;
    void* tex;
    ModelFileHeader* model;
    GXColor temp;
    void (*pcb)(void*, void**, int);
    int alpha_byte;
    GXColor fogColor;

    model = obj_b[0];
    renderOp = ObjModel_GetRenderOp((ModelFileHeader*)model, slot);
    tex = (void*)getNewShadowReflectionGradientTexture();
    selectReflectionTexture(0);
    selectTexture((Texture*)tex, 1);
    selectWhirlpoolTexture(2);

    GXLoadTexMtxImm(gCameraLightPerspectiveFlipYMatrix, GX_PTTEXMTX7, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_POS, 0, GX_FALSE, GX_PTTEXMTX7);

    if (model == 0 || model->normalCount != 0)
    {
        PSMTXScale(mtx_54, gFrozenReflectionNormalScale, gFrozenReflectionNormalScale, 0.0f);
        mtx_54[2][3] = 1.0f;
        PSMTXTrans(mtx_24, 0.5f, 0.5f, 0.0f);
        PSMTXConcat(mtx_24, mtx_54, mtx_54);
    }
    else
    {
        PSMTXScale(mtx_54, 0.0f, 0.0f, 0.0f);
        mtx_54[0][3] = 0.5f;
        mtx_54[1][3] = 0.5f;
        mtx_54[2][3] = 1.0f;
    }
    GXLoadTexMtxImm(mtx_54, GX_PTTEXMTX6, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_NRM, GX_TEXMTX0, GX_TRUE, GX_PTTEXMTX6);

    PSMTXScale(mtx_54, gFrozenWhirlpoolTexScale, gFrozenWhirlpoolTexScale, 0.0f);
    mtx_54[2][3] = 1.0f;
    GXLoadTexMtxImm(mtx_54, GX_PTTEXMTX5, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX3x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX5);

    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, gFrozenObjectIndTexMtx, -1);
    GXSetTevIndirect(GX_TEVSTAGE0, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD2, GX_TEXMAP2, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_CPREV, GX_CC_TEXC, GX_CC_KONST, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetNumIndStages(1);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(3);
    GXSetNumTevStages(2);

    alpha_byte = (renderOp->alpha * ((u8*)obj_a)[0x37]) >> 8;
    temp.a = alpha_byte;
    GXSetTevKColor(GX_KCOLOR0, temp);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevKColor(GX_KCOLOR1, gFrozenTintColor);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K1);

    pcb = (void (*)(void*, void**, int))ObjModel_GetPostRenderCallback((ObjModel*)obj_b);
    if (pcb != 0)
    {
        pcb(obj_a, obj_b, slot);
    }
    else
    {
        u8 zCompLoc = 1;
        int ref1;
        if (((u8*)obj_a)[0x37] < 0xff || (renderOp->flags & 0x40000000) != 0 ||
            renderOp->alpha < 0xff)
        {
            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
            if ((model->flags & 0x400) != 0)
            {
                if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                    gGxZModeValid == 0)
                {
                    GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 0;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
            else if ((model->flags & 0x2000) != 0)
            {
                zCompLoc = 0;
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 1 ||
                    gGxZModeValid == 0)
                {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 1;
                    gGxZModeValid = 1;
                }
                obj_a = (void*)objGetAlphaCompareThreshold();
                ref1 = objGetAlphaCompareThreshold();
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_GREATER, ref1, GX_AOP_AND, GX_GREATER, (int)obj_a);
            }
            else
            {
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                    gGxZModeValid == 0)
                {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
        }
        else
        {
            if ((renderOp->flags & 0x400) != 0)
            {
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                if ((model->flags & 0x400) != 0)
                {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                }
                else
                {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 1 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_GREATER, 192, GX_AOP_AND, GX_GREATER, 192);
            }
            else
            {
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                if ((model->flags & 0x400) != 0)
                {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                }
                else
                {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 1 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
        }
        if ((renderOp->flags & 0x400) != 0)
        {
            zCompLoc = 0;
        }
        if (gGxZCompLocCached != zCompLoc || gGxZCompLocValid == 0)
        {
            GXSetZCompLoc(zCompLoc);
            gGxZCompLocCached = zCompLoc;
            gGxZCompLocValid = 1;
        }
    }
    GXSetCullMode(GX_CULL_NONE);
    if ((model->flags & 0x100) != 0)
    {
        fogColor = temp;
        GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, fogColor);
    }
    else
    {
        fogColor = gFogColor;
        GXSetFog(GX_FOG_PERSP_EXP, gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ, fogColor);
    }
    return 1;
}

/*
 * Three-tex-coord-gen ind+direct TEV setup. Loads the active env-mtx
 * (gCameraLightPerspectiveFlipYMatrix) for tex0, scales tex1 by 4.0f through a 3x4
 * matrix from PSMTXScale, and stamps an indirect tex matrix from local
 * stack data. Two TEV stages: stage 0 K-modulates the texture by alpha,
 * stage 1 modulates by the second texture. Uses ind tex stage 0 to warp
 * tex coord 0 by tex1.
 */
void setupQuakeSpellRingGxState(u8 alpha)
{

    Texture* handle1;
    Texture* handle2;
    f32 a;
    f32 b;
    GXColor c;
    f32 ind_mtx[2][3];
    Mtx tex_mtx;
    Mtx mtx;

    Camera_GetViewMatrix();
    selectReflectionTexture(0);
    GXLoadTexMtxImm(gCameraLightPerspectiveFlipYMatrix, GX_PTTEXMTX6, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_POS, 0, GX_FALSE, GX_PTTEXMTX6);
    newshadows_getReflectionScrollOffsets(&a, &b);
    a *= 8.0f;
    getNewShadowCausticTexture((u32*)&handle1);
    selectTexture(handle1, 1);
    PSMTXScale((f32(*)[4])tex_mtx, 4.0f, 4.0f, 4.0f);
    tex_mtx[0][3] = a;
    GXLoadTexMtxImm(tex_mtx, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);
    ind_mtx[0][0] = 0.5f;
    ind_mtx[0][1] = 0.0f;
    ind_mtx[0][2] = 0.0f;
    ind_mtx[1][0] = 0.0f;
    ind_mtx[1][1] = 0.25f;
    ind_mtx[1][2] = 0.0f;
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, ind_mtx, -3);
    GXSetTevIndirect(GX_TEVSTAGE0, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    mtx[0][0] = 0.6f;
    mtx[0][1] = 0.0f;
    mtx[0][2] = 0.0f;
    mtx[0][3] = 0.5f;
    mtx[1][0] = 0.0f;
    mtx[1][1] = 0.6f;
    mtx[1][2] = 0.0f;
    mtx[1][3] = 0.5f;
    mtx[2][0] = 0.0f;
    mtx[2][1] = 0.0f;
    mtx[2][2] = 0.0f;
    mtx[2][3] = 1.0f;
    GXLoadTexMtxImm(mtx, GX_PTTEXMTX7, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_TRUE, GX_PTTEXMTX7);
    getNewShadowDiskTexture((u32*)&handle2);
    selectTexture(handle2, 2);
    c.a = alpha;
    GXSetTevKColor(GX_KCOLOR0, c);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
    GXSetNumIndStages(1);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(3);
    GXSetNumTevStages(2);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD2, GX_TEXMAP2, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_BACK);
}

void setupAdditiveTintedTexture(void* texture, u32* colorA, u32* colorB)
{
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    selectTexture((Texture*)texture, 0);
    GXSetTevKColor(GX_KCOLOR0, *(GXColor*)colorA);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevColor(GX_TEVREG0, *(GXColor*)colorB);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C0);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_BACK);
}

int objModelNormalDiskRenderCb(GameObject* object, ObjModel* model, int slot)
{
    Texture* diskTextureHandle;
    GXColor konstColor;
    GXColor tintColor;
    Mtx normalTexMtx;
    Texture* baseTexture;
    ModelFileHeader* modelFile;

    tintColor = sMoonFxTint;
    modelFile = model->file;
    baseTexture = (Texture*)textureIdxToPtr(*(int*)Shader_getLayer(ObjModel_GetRenderOp(modelFile, 0), 0));
    normalTexMtx[0][0] = 0.7f;
    normalTexMtx[0][1] = 0.0f;
    normalTexMtx[0][2] = 0.0f;
    normalTexMtx[0][3] = 0.5f;
    normalTexMtx[1][0] = 0.0f;
    normalTexMtx[1][1] = 0.7f;
    normalTexMtx[1][2] = 0.0f;
    normalTexMtx[1][3] = 0.5f;
    normalTexMtx[2][0] = 0.0f;
    normalTexMtx[2][1] = 0.0f;
    normalTexMtx[2][2] = 0.0f;
    normalTexMtx[2][3] = 1.0f;
    GXLoadTexMtxImm(normalTexMtx, GX_PTTEXMTX7, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_TRUE, GX_PTTEXMTX7);
    getNewShadowDiskTexture((u32*)&diskTextureHandle);
    selectTexture(diskTextureHandle, 0);
    konstColor.a = object->anim.renderAlpha;
    GXSetTevKColor(GX_KCOLOR0, konstColor);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
    GXSetTevColor(GX_TEVREG0, tintColor);
    GXSetNumIndStages(0);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);
    GXSetTevDirect(GX_TEVSTAGE0);
    if (modelFile->flags24 & MODEL_FLAGS24_VERY_BRIGHT)
    {
        GXSetNumChans(1);
        GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR0A0);
        GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_RASA);
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    }
    else
    {
        GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetNumChans(0);
        GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_TEXA, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A0);
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    }
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    selectTexture(baseTexture, 1);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_C0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_APREV, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_BACK);
    return 1;
}

int moonFxRenderCallback(u8* obj, void** objB, int slot)
{
    GXColor colorK;
    GXColor colorFog;
    Mtx mtx;
    Shader* op;
    Texture* tex;
    f32 tx;

    op = ObjModel_GetRenderOp((ModelFileHeader*)objB[0], slot);
    tex = (Texture*)textureIdxToPtr(*(int*)Shader_getLayer((void*)op, 0));
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    gMoonFxDayNo = mainGetBit(0x2ba);
    tx = gMoonFxDayNo / 30.0f;
    PSMTXTrans(mtx, tx, 0.0f, 0.0f);
    GXLoadTexMtxImm(mtx, GX_TEXMTX0, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    GXSetNumTexGens(2);
    GXSetNumTevStages(3);
    GXSetNumIndStages(0);
    selectTexture(tex, 0);
    colorK.a = (op->alpha * ((GameObject*)obj)->anim.renderAlpha) >> 8;
    GXSetTevKColor(GX_KCOLOR0, colorK);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    colorFog.a = 0x3e;
    GXSetTevKColor(GX_KCOLOR1, colorFog);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K1_A);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_KONST, GX_CA_TEXA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVREG0);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_APREV, GX_CA_ZERO, GX_CA_A0, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetCullMode(GX_CULL_NONE);
    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, colorFog);
    return 1;
}

int objModelProjectedIndirectRenderCb(GameObject* object, ObjModel* model, int slot)
{
    Mtx projectedTexMtx;
    Mtx normalTexMtx;
    Mtx transformMtx;
    f32 indirectMtx[6];
    void* renderOp;
    void* baseTexture;
    ModelFileHeader* modelFile;
    GXColor konstColor;
    int alphaValue;
    void (*postRenderCallback)(GameObject*, ObjModel*, int);

    *(IndMtxInit*)indirectMtx = sIndMtxZeroInit;

    modelFile = model->file;
    renderOp = ObjModel_GetRenderOp(modelFile, slot);
    baseTexture = textureIdxToPtr(*(int*)Shader_getLayer(renderOp, 0));

    PSMTXScale(normalTexMtx, gTrackNormalTexScale, gTrackNormalTexScale, 0.0f);
    normalTexMtx[2][3] = 1.0f;
    GXLoadTexMtxImm(normalTexMtx, GX_PTTEXMTX7, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_NRM, GX_TEXMTX0, GX_TRUE, GX_PTTEXMTX7);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);
    GXSetNumIndStages(2);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD0, GX_TEXMAP2);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, (f32(*)[3])indirectMtx, 0);
    GXSetTevIndirect(GX_TEVSTAGE0, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    selectTexture((Texture*)baseTexture, 0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ONE);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD0, GX_TEXMAP2);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE1, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_OFF);
    PSMTXScale(transformMtx, gTrackProjectedTexScale, gTrackProjectedTexScale, 1.0f);
    PSMTXConcat(transformMtx, gCameraLightPerspectiveFlipYMatrix, projectedTexMtx);
    PSMTXTrans(transformMtx, 0.5f * (1.0f - gTrackProjectedTexScale),
               0.5f * (1.0f - gTrackProjectedTexScale), 0.0f);
    PSMTXConcat(transformMtx, projectedTexMtx, projectedTexMtx);
    GXLoadTexMtxImm(projectedTexMtx, GX_PTTEXMTX6, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_POS, 0, GX_TRUE, GX_PTTEXMTX6);

    alphaValue = (((Shader*)renderOp)->alpha * object->anim.renderAlpha) >> 8;
    konstColor.a = alphaValue;
    GXSetTevKColor(GX_KCOLOR0, konstColor);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP0, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_RASC, GX_CC_TEXC, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    postRenderCallback = (void (*)(GameObject*, ObjModel*, int))ObjModel_GetPostRenderCallback(model);
    if (postRenderCallback != 0)
    {
        postRenderCallback(object, model, slot);
    }
    else
    {
        u8 zCompLoc = 1;
        if (object->anim.renderAlpha < 0xff || (((Shader*)renderOp)->flags & SHADER_FLAG_FORCE_BLEND) != 0 ||
            ((Shader*)renderOp)->alpha < 0xff)
        {
            GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
            if ((modelFile->flags & MODEL_FLAG_NO_DEPTH_TEST) != 0)
            {
                if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                    gGxZModeValid == 0)
                {
                    GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 0;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
            else if ((modelFile->flags & MODEL_FLAG_ALPHA_Z_UPDATE) != 0)
            {
                zCompLoc = 0;
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 1 ||
                    gGxZModeValid == 0)
                {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 1;
                    gGxZModeValid = 1;
                }
                {
                    int firstAlphaThreshold;
                    alphaValue = objGetAlphaCompareThreshold();
                    firstAlphaThreshold = objGetAlphaCompareThreshold();
                    ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_GREATER, firstAlphaThreshold, GX_AOP_AND,
                                                               GX_GREATER, alphaValue);
                }
            }
            else
            {
                if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                    gGxZModeValid == 0)
                {
                    GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
                    gGxZModeCompareEnable = 1;
                    gGxZModeCompareFunc = 3;
                    gGxZModeUpdateEnable = 0;
                    gGxZModeValid = 1;
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
        }
        else
        {
            if ((((Shader*)renderOp)->flags & SHADER_FLAG_ALPHA_TEST_OPAQUE) != 0)
            {
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                if ((modelFile->flags & MODEL_FLAG_NO_DEPTH_TEST) != 0)
                {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                }
                else
                {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 1 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_GREATER, 0xC0, GX_AOP_AND, GX_GREATER, 0xC0);
            }
            else
            {
                GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
                if ((modelFile->flags & MODEL_FLAG_NO_DEPTH_TEST) != 0)
                {
                    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_FALSE, GX_LEQUAL, GX_FALSE);
                        gGxZModeCompareEnable = 0;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 0;
                        gGxZModeValid = 1;
                    }
                }
                else
                {
                    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 1 ||
                        gGxZModeValid == 0)
                    {
                        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
                        gGxZModeCompareEnable = 1;
                        gGxZModeCompareFunc = 3;
                        gGxZModeUpdateEnable = 1;
                        gGxZModeValid = 1;
                    }
                }
                ((GXSetAlphaCompareIntFn)GXSetAlphaCompare)(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
            }
        }
        if ((((Shader*)renderOp)->flags & SHADER_FLAG_ALPHA_TEST_OPAQUE) != 0)
        {
            zCompLoc = 0;
        }
        if (gGxZCompLocCached != zCompLoc || gGxZCompLocValid == 0)
        {
            GXSetZCompLoc(zCompLoc);
            gGxZCompLocCached = zCompLoc;
            gGxZCompLocValid = 1;
        }
    }
    if ((((Shader*)renderOp)->flags & SHADER_FLAG_BACKFACE_CULL) != 0)
    {
        GXSetCullMode(GX_CULL_BACK);
    }
    else
    {
        GXSetCullMode(GX_CULL_NONE);
    }
    return 1;
}

u32 objCausticReflectionRenderCb(void* handle, void* model)
{

    Mtx mtx_ec;
    Mtx mtx_bc;
    Mtx mtx_8c;
    Mtx mtx_5c;
    f32 indMtx_44[6];
    f32 indMtx_2c[6];
    Texture* handle1;
    Texture* handle2;
    f32 scrollX, scrollY;
    f32 f31_val;
    GXColor temp;
    f32* viewMtx;

    viewMtx = Camera_GetViewMatrix();
    if (model != 0)
    {
        ObjModelJointMatrix* jm = ObjModel_GetJointMatrix((u8*)model, 0);
        f32 px, py, pz, dist;
        PSMTXConcat((f32(*)[4])viewMtx, (f32(*)[4])jm, mtx_8c);
        px = mtx_8c[0][3];
        py = mtx_8c[1][3];
        pz = mtx_8c[2][3];
        dist = sqrtf(px * px + py * py + pz * pz);
        f31_val = 200.0f / dist;
        if (f31_val > 1.0f)
            f31_val = 1.0f;
    }
    else
    {
        f31_val = 1.0f;
    }

    selectReflectionTexture(0);
    GXLoadTexMtxImm(gCameraLightPerspectiveFlipYMatrix, GX_PTTEXMTX6, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_POS, 0, GX_FALSE, GX_PTTEXMTX6);
    newshadows_getReflectionScrollOffsets(&scrollX, &scrollY);
    scrollX *= 4.0f;
    scrollY *= 4.0f;
    getNewShadowCausticTexture((u32*)&handle1);
    selectTexture(handle1, 1);

    PSMTXScale(mtx_ec, 4.0f, 4.0f, 4.0f);
    mtx_ec[0][3] = scrollX;
    GXLoadTexMtxImm(mtx_ec, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);

    {
        f32 v = 0.5f * f31_val;
        indMtx_44[0] = v;
        indMtx_44[1] = 0.0f;
        indMtx_44[2] = 0.0f;
        indMtx_44[3] = 0.0f;
        indMtx_44[4] = v;
        indMtx_44[5] = 0.0f;
    }
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, (f32(*)[3])indMtx_44, -4);
    GXSetTevIndirect(GX_TEVSTAGE0, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_0, GX_ITW_0, 0, 0, GX_ITBA_OFF);

    PSMTXScale(mtx_bc, 0.83f, 0.83f, 0.83f);
    PSMTXRotRad(mtx_5c, 'z', 0.7853982f);
    PSMTXConcat(mtx_5c, mtx_bc, mtx_bc);
    mtx_bc[0][3] = scrollY;
    mtx_bc[1][3] = scrollY;
    GXLoadTexMtxImm(mtx_bc, GX_TEXMTX2, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX2, GX_FALSE, GX_PTIDENTITY);

    {
        f32 v44 = 0.3536f * f31_val;
        f32 v48 = -0.3536f * f31_val;
        indMtx_2c[0] = v44;
        indMtx_2c[1] = v44;
        indMtx_2c[2] = 0.0f;
        indMtx_2c[3] = v48;
        indMtx_2c[4] = v44;
        indMtx_2c[5] = 0.0f;
    }
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD2, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_1, (f32(*)[3])indMtx_2c, -4);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE1, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_OFF);

    mtx_8c[0][0] = gCausticReflectionDiskScale;
    mtx_8c[0][1] = 0.0f;
    mtx_8c[0][2] = 0.0f;
    mtx_8c[0][3] = 0.5f;
    mtx_8c[1][0] = 0.0f;
    mtx_8c[1][1] = gCausticReflectionDiskScale;
    mtx_8c[1][2] = 0.0f;
    mtx_8c[1][3] = 0.5f;
    mtx_8c[2][0] = 0.0f;
    mtx_8c[2][1] = 0.0f;
    mtx_8c[2][2] = 0.0f;
    mtx_8c[2][3] = 1.0f;
    GXLoadTexMtxImm((f32(*)[4])mtx_8c, GX_PTTEXMTX7, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX3x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, GX_PTTEXMTX7);

    getNewShadowDiskTexture((u32*)&handle2);
    selectTexture(handle2, 2);

    GXSetNumIndStages(2);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(4);
    GXSetNumTevStages(3);

    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    temp.a = ((GameObject*)handle)->anim.renderAlpha;
    GXSetTevKColor(GX_KCOLOR0, temp);
    GXSetTevKAlphaSel(GX_TEVSTAGE2, GX_TEV_KASEL_K0_A);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD3, GX_TEXMAP2, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetCullMode(GX_CULL_BACK);
    return 1;
}

void hudDrawRect(int x1, int y1, int x2, int y2, GXColor color)
{
    f32 zero = 0.0f;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    color.a = (u8)(((s32)color.a * gHudTintAlpha) >> 8);
    GXSetTevKColor(GX_KCOLOR0, color);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1 << 2;
    GXWGFifo.s16 = y1 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2 << 2;
    GXWGFifo.s16 = y1 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2 << 2;
    GXWGFifo.s16 = y2 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1 << 2;
    GXWGFifo.s16 = y2 << 2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    Camera_RebuildProjectionMatrix();
}

void drawViewFinderLine(f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, f32 x4, f32 y4, GXColor* color)
{
    f32 zero = 0.0f;
    f32 scale = 4.0f;
    f32 fy4, fx4, fy3, fx3, fy2, fx2, fy1, fx1;
    fx1 = scale * x1;
    fy1 = scale * y1;
    fx2 = scale * x2;
    fy2 = scale * y2;
    fx3 = scale * x3;
    fy3 = scale * y3;
    fx4 = scale * x4;
    fy4 = scale * y4;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    color->a = (u8)(((s32)color->a * gHudTintAlpha) >> 8);
    GXSetTevKColor(GX_KCOLOR0, *color);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx1;
    GXWGFifo.s16 = fy1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx2;
    GXWGFifo.s16 = fy2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx3;
    GXWGFifo.s16 = fy3;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx4;
    GXWGFifo.s16 = fy4;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    Camera_RebuildProjectionMatrix();
}

void hudDrawTriangle(f32 x1, f32 y1, f32 x2, f32 y2, f32 x3, f32 y3, GXColor color)
{
    f32 zero = 0.0f;
    f32 scale = 4.0f;
    f32 fy3, fx3, fy2, fx2, fy1, fx1;
    fx1 = scale * x1;
    fy1 = scale * y1;
    fx2 = scale * x2;
    fy2 = scale * y2;
    fx3 = scale * x3;
    fy3 = scale * y3;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    color.a = (u8)(((s32)color.a * gHudTintAlpha) >> 8);
    GXSetTevKColor(GX_KCOLOR0, color);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXBegin(GX_TRIANGLES, GX_VTXFMT1, 3);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx1;
    GXWGFifo.s16 = fy1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx2;
    GXWGFifo.s16 = fy2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = fx3;
    GXWGFifo.s16 = fy3;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    Camera_RebuildProjectionMatrix();
}

void drawOrthoTexturedQuad(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2, int z)
{

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v2;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = z;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v2;

    Camera_RebuildProjectionMatrix();
}

void textRenderChar(int x1, int y1, int x2, int y2, f32 u1, f32 v1, f32 u2, f32 v2)
{

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y1;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x2;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u2;
    GXWGFifo.f32 = v2;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = x1;
    GXWGFifo.s16 = y2;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v2;

    Camera_RebuildProjectionMatrix();
}

void drawPartialTexture(void* obj, f32 sx, f32 sy, int alpha_mod, int scale, int width, int height, int u_offset,
                        int v_offset)
{
    GXColor c;
    s32 alpha;
    s32 w;
    u16 drawScale;
    f32 u1, u0, v0, v1;

    c.r = 0xFF;
    c.g = 0xFF;
    c.b = 0xFF;
    alpha = (u8)alpha_mod;
    alpha *= gHudTintAlpha;
    c.a = (u8)(alpha >> 8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetTevKColor(GX_KCOLOR0, c);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if ((u32)((Texture*)obj)->imageOffset != 0)
    {
        GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
        GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR_NULL);
        GXSetTevDirect(GX_TEVSTAGE1);
        GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetNumTevStages(2);
    }
    else
    {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    selectTextureWithSecondary((Texture*)obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    drawScale = scale;
    w = (s32)(((u32)(width << 2) * drawScale) >> 8);
    sx = 4.0f * sx;
    sy = 4.0f * sy;
    u0 = (f32)(u32)u_offset / (f32)((Texture*)obj)->width;
    v0 = (f32)(u32)v_offset / (f32)((Texture*)obj)->height;
    u1 = (f32)(u32)(width + u_offset) / (f32)((Texture*)obj)->width;
    v1 = (f32)(u32)(height + v_offset) / (f32)((Texture*)obj)->height;

    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)(((u32)(height << 2) * drawScale) >> 8));
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)(((u32)(height << 2) * drawScale) >> 8));
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;

    Camera_RebuildProjectionMatrix();
}

/*
 * Generic ortho-projected single-color quad blit. Sets the GX state up
 * fresh (no tex coords, color from constant K0, additive blend, fixed
 * 0x3C texmtx) then emits four GX_VTXFMT1 vertices at z=-0x18C with
 * width 4*size_x and height 4*size_y in screen pixels. Used as the
 * "draw fullscreen tint" primitive by the dialog code in cardShowLoadingMsg.
 */
void drawRect(f32 sx, f32 sy, int x, int y)
{

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetColorUpdate(GX_FALSE);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ONE);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(1);
    GXSetNumIndStages(0);
    GXSetNumTexGens(0);
    GXSetNumTevStages(1);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 1 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_ALWAYS, GX_TRUE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 1;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 0 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_FALSE);
        gGxZCompLocCached = 0;
        gGxZCompLocValid = 1;
    }
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    GXSetCurrentMtx(GX_IDENTITY);
    sx = 4.0f * sx;
    sy = 4.0f * sy;
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -0x18C;

    GXWGFifo.s16 = (s16)(sx + (f32)((u32)x * 4));
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -0x18C;

    GXWGFifo.s16 = (s16)(sx + (f32)((u32)x * 4));
    GXWGFifo.s16 = (s16)(sy + (f32)((u32)y * 4));
    GXWGFifo.s16 = -0x18C;

    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = (s16)(sy + (f32)((u32)y * 4));
    GXWGFifo.s16 = -0x18C;

    Camera_RebuildProjectionMatrix();
    GXSetColorUpdate(GX_TRUE);
}

void drawScaledTexture(void* obj, f32 sx, f32 sy, int alpha_mod, int scale, int width, int height, int flags)
{
    GXColor c;
    s32 w, h;
    s32 alpha;
    f32 u0, u1, v0, v1;
    u8 fbits;

    c.r = 0xFF;
    c.g = 0xFF;
    c.b = 0xFF;
    alpha = (u8)alpha_mod;
    alpha *= gHudTintAlpha;
    c.a = (u8)(alpha >> 8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetTevKColor(GX_KCOLOR0, c);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if ((u32)((Texture*)obj)->imageOffset != 0)
    {
        GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
        GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR_NULL);
        GXSetTevDirect(GX_TEVSTAGE1);
        GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetNumTevStages(2);
    }
    else
    {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    selectTextureWithSecondary((Texture*)obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    fbits = (u8)flags;
    if ((fbits & 4) != 0)
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    }
    else
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    }
    w = (s32)(((u32)(width << 2) * (u16)scale) >> 8);
    h = (s32)(((u32)(height << 2) * (u16)scale) >> 8);
    sx = 4.0f * sx;
    sy = 4.0f * sy;
    {
        f32 ur = (f32)(u32)width / (f32)(u16)((Texture*)obj)->width;
        f32 vr = (f32)(u32)height / (f32)(u16)((Texture*)obj)->height;
        if ((fbits & 1) != 0)
        {
            u0 = ur;
            u1 = 0.0f;
        }
        else
        {
            u0 = 0.0f;
            u1 = ur;
        }
        if ((fbits & 2) != 0)
        {
            v0 = vr;
            v1 = 0.0f;
        }
        else
        {
            v0 = 0.0f;
            v1 = vr;
        }
    }
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u1;
    GXWGFifo.f32 = v1;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = u0;
    GXWGFifo.f32 = v1;

    Camera_RebuildProjectionMatrix();
}

/*
 * Caller-coloured asset blit. Same mechanic as drawTexture but the K0
 * color comes from a writable GXColor the caller passes in (we apply the
 * gHudTintAlpha alpha tint to it in place). The flag arg picks between
 * "raster passthrough" (TevColorIn 0xF/0xF/0xF/0xE) and "K-tint replace"
 * (TevColorIn 0xF/0xE/0x8/0xF).
 */
void hudDrawColored(Texture* obj, int x, int y, u32* color, int scale, int flag)
{
    f32 zero = 0.0f;
    f32 one = 1.0f;

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    ((GXColor*)color)->a = (u8)(((s32)((GXColor*)color)->a * gHudTintAlpha) >> 8);
    GXSetTevKColor(GX_KCOLOR0, *(GXColor*)color);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    if ((u8)flag != 0)
    {
        GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
    }
    else
    {
        GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_KONST, GX_CC_TEXC, GX_CC_ZERO);
    }
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);
    if ((u32)((Texture*)obj)->imageOffset != 0)
    {
        GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
        GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);
        GXSetNumTevStages(2);
    }
    else
    {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    selectTextureWithSecondary((Texture*)obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u8)flag != 0)
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    }
    else
    {
        GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    }
    {
        s32 w, h;
        w = ((((Texture*)obj)->width << 2) * (u16)scale) / 256;
        h = ((((Texture*)obj)->height << 2) * (u16)scale) / 256;
        GXBegin(GX_QUADS, GX_VTXFMT1, 4);

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)(x << 2);
        GXWGFifo.s16 = (s16)(y << 2);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = zero;
        GXWGFifo.f32 = zero;

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)((x << 2) + w);
        GXWGFifo.s16 = (s16)(y << 2);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = one;
        GXWGFifo.f32 = zero;

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)((x << 2) + w);
        GXWGFifo.s16 = (s16)((y << 2) + h);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = one;
        GXWGFifo.f32 = one;

        GXWGFifo.u8 = 0x3C;
        GXWGFifo.s16 = (s16)(x << 2);
        GXWGFifo.s16 = (s16)((y << 2) + h);
        GXWGFifo.s16 = -8;
        GXWGFifo.f32 = zero;
        GXWGFifo.f32 = one;
    }
    Camera_RebuildProjectionMatrix();
}

/*
 * Quad-from-asset blit: takes an "asset record" (with width at +0xA,
 * height at +0xC, and an optional second-stage flag at +0x50), a per-
 * call alpha multiplier, screen-pos (sx, sy), and a u16 size scale.
 * Composes K0 from RGB(255,255,255) plus the global alpha tint
 * (alpha * gHudTintAlpha >> 8); if the asset opts in, layers a second
 * tex stage that further K-multiplies by the texture. Final width and
 * height are 4 * asset_dim * scale >> 8 in screen pixels at z=-8.
 */
void drawTexture(void* obj, f32 sx, f32 sy, int alpha_mod, int scale)
{
    f32 zero = 0.0f;
    f32 one = 1.0f;
    GXColor c;
    s32 w, h;
    s32 alpha;

    c.r = 0xFF;
    c.g = 0xFF;
    c.b = 0xFF;
    alpha = (u8)alpha_mod;
    alpha *= gHudTintAlpha;
    c.a = (u8)(alpha >> 8);

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetTevKColor(GX_KCOLOR0, c);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if ((u32)((Texture*)obj)->imageOffset != 0)
    {
        GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
        GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR_NULL);
        GXSetTevDirect(GX_TEVSTAGE1);
        GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
        GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetNumTevStages(2);
    }
    else
    {
        GXSetNumTevStages(1);
    }
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    selectTextureWithSecondary((Texture*)obj, 0);
    GXSetCullMode(GX_CULL_NONE);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    w = ((((Texture*)obj)->width << 2) * (u16)scale) / 256;
    h = ((((Texture*)obj)->height << 2) * (u16)scale) / 256;
    sx = 4.0f * sx;
    sy = 4.0f * sy;
    GXBegin(GX_QUADS, GX_VTXFMT1, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = zero;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = sy;
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = one;
    GXWGFifo.f32 = zero;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = (s16)(sx + (f32)(u32)w);
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = one;
    GXWGFifo.f32 = one;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = sx;
    GXWGFifo.s16 = (s16)(sy + (f32)(u32)h);
    GXWGFifo.s16 = -8;
    GXWGFifo.f32 = zero;
    GXWGFifo.f32 = one;

    Camera_RebuildProjectionMatrix();
}

void objectShadow_setupSwappedProjectedTexture(ProjectedShadowTexture* shadow, GXColor* colorPtr, Mtx mtx)
{
    Mtx tmp;

    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_ALPHA, GX_CH_RED, GX_CH_ALPHA, GX_CH_RED);
    PSMTXConcat(shadow->textureMtx, mtx, tmp);
    GXLoadTexMtxImm(tmp, GX_TEXMTX0, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    selectTexture(shadow->texture, 0);
    GXSetTevKColor(GX_KCOLOR0, *colorPtr);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevColor(GX_TEVREG1, gObjectShadowTevColor);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_A1, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP1);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVREG0);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_COMP_RGB8_GT, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void objectShadow_setupProjectedTexture(ProjectedShadowTexture* shadow, GXColor* colorPtr, Mtx mtx)
{
    Mtx tmp;

    PSMTXConcat(shadow->textureMtx, mtx, tmp);
    GXLoadTexMtxImm(tmp, GX_TEXMTX0, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    selectTexture(shadow->texture, 0);
    GXSetTevKColor(GX_KCOLOR0, *colorPtr);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void objectShadow_setupProjectedTextureDepthFade(ProjectedShadowTexture* shadow, GXColor* colorPtr, Mtx mtx, f32 depth)
{
    Mtx m58;
    Mtx m28;
    Vec v;
    GXColor c;
    Texture* handle;
    GXColor kc;
    f32 z;
    f32 d;
    f32 q;
    u8 t;

    kc = gProjectedShadowFogColor;
    PSMTXConcat(shadow->textureMtx, mtx, m58);
    GXLoadTexMtxImm(m58, GX_TEXMTX0, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    selectTexture(shadow->texture, 0);
    t = colorPtr->a;
    colorPtr->a = (t >> 1) + (t >> 2);
    c.r = colorPtr->a;
    c.g = colorPtr->a;
    c.b = colorPtr->a;
    GXSetTevKColor(GX_KCOLOR0, c);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    v.x = mtx[0][3];
    v.y = mtx[1][3];
    v.z = mtx[2][3];
    PSMTXMultVec(shadow->depthMtx, &v, &v);
    z = -v.z;
    getNewShadowRampTexture((u32*)&handle);
    selectTexture(handle, 1);
    m58[0][0] = 0.0f;
    m58[0][1] = 0.0f;
    d = z - depth;
    m58[0][2] = 1.0f / (q = z - d);
    m58[0][3] = z / q;
    m58[1][0] = 0.0f;
    m58[1][1] = 0.0f;
    m58[1][2] = 0.0f;
    m58[1][3] = 0.0f;
    PSMTXConcat(shadow->depthMtx, mtx, m28);
    PSMTXConcat(m58, m28, m28);
    GXLoadTexMtxImm(m28, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);
    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_CPREV, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);
    GXSetFog(GX_FOG_PERSP_EXP, gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ, kc);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_ZERO, GX_BL_INVSRCCLR, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void objectShadow_setupProjectedTextureChannel(ProjectedShadowTexture* shadow, GXColor* colorPtr, Mtx mtx, f32 scale)
{
    typedef struct
    {
        u32 w[7];
    } Blk28;
    Mtx mtx_110;
    Mtx mtx_e0;
    Blk28 buf_c4;
    Blk28 buf_a8;
    Blk28 buf_8c;
    Blk28 buf_70;
    Blk28 buf_54;
    Blk28 buf_38;
    StageCountTable stab;
    GXColor temp;
    GXColor color2;
    f32 vec3[3];
    Texture* handle;
    GXColor fog_var;
    int stage_idx;
    u32 stage_count;
    int stage_base;
    f32 f31_val;

    buf_c4 = *(Blk28*)&sIndStageInitData.blk[0];
    buf_a8 = *(Blk28*)&sIndStageInitData.blk[1];
    buf_8c = *(Blk28*)&sIndStageInitData.blk[2];
    buf_70 = *(Blk28*)&sIndStageInitData.blk[3];
    buf_54 = *(Blk28*)&sIndStageInitData.blk[4];
    buf_38 = *(Blk28*)&sIndStageInitData.blk[5];
    stab = sProjectedShadowStageCounts;
    *(u32*)&fog_var = gProjectedShadowFogColorBits;

    PSMTXConcat(shadow->textureMtx, mtx, mtx_110);
    GXLoadTexMtxImm(mtx_110, GX_TEXMTX0, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);

    selectTexture(shadow->texture, 0);

    if (shadow->mode < 8)
    {
        GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_RED);
        stage_idx = shadow->mode - 1;
    }
    else if (shadow->mode < 0x10)
    {
        GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_ALPHA, GX_CH_ALPHA, GX_CH_ALPHA, GX_CH_ALPHA);
        stage_idx = shadow->mode - 9;
    }
    if (stage_idx < 0)
        stage_idx = 0;

    color2.r = 0x7F;
    color2.g = 0x7F;
    color2.b = 0x7F;
    GXSetTevColor(GX_TEVREG0, color2);

    colorPtr->a = (u8)((colorPtr->a >> 1) + (colorPtr->a >> 2));
    temp.r = colorPtr->a;
    temp.g = colorPtr->a;
    temp.b = colorPtr->a;
    GXSetTevKColor(GX_KCOLOR0, temp);

    stage_base = 0;
    stage_count = stab.count[stage_idx];
    if (stage_count != 0)
    {
        GXSetTevDirect(GX_TEVSTAGE0);
        GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP1);
        GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ONE, buf_c4.w[stage_idx]);
        GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, buf_a8.w[stage_idx], GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        stage_base = 1;
    }

    if (stage_count > 1)
    {
        GXSetTevDirect(stage_base);
        GXSetTevSwapMode(stage_base, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevOrder(stage_base, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevColorIn(stage_base, GX_CC_ZERO, GX_CC_CPREV, GX_CC_ONE, buf_8c.w[stage_idx]);
        GXSetTevAlphaIn(stage_base, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        GXSetTevColorOp(stage_base, GX_TEV_ADD, GX_TB_ZERO, buf_70.w[stage_idx], GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(stage_base, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        stage_base++;
    }

    if (stage_count > 2)
    {
        GXSetTevDirect(stage_base);
        GXSetTevSwapMode(stage_base, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevOrder(stage_base, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevColorIn(stage_base, GX_CC_ZERO, GX_CC_CPREV, GX_CC_ONE, buf_54.w[stage_idx]);
        GXSetTevAlphaIn(stage_base, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        GXSetTevColorOp(stage_base, GX_TEV_ADD, GX_TB_ZERO, buf_38.w[stage_idx], GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(stage_base, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        stage_base++;
    }

    GXSetTevDirect(stage_base);
    GXSetTevSwapMode(stage_base, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevKColorSel(stage_base, GX_TEV_KCSEL_K0);
    GXSetTevOrder(stage_base, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    if (stage_count == 0)
    {
        GXSetTevColorIn(stage_base, GX_CC_TEXC, GX_CC_C0, GX_CC_KONST, GX_CC_ZERO);
    }
    else
    {
        GXSetTevColorIn(stage_base, GX_CC_CPREV, GX_CC_C0, GX_CC_KONST, GX_CC_ZERO);
    }
    GXSetTevAlphaIn(stage_base, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(stage_base, GX_TEV_COMP_R8_GT, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(stage_base, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    vec3[0] = mtx[0][3];
    vec3[1] = mtx[1][3];
    vec3[2] = mtx[2][3];
    PSMTXMultVec(shadow->depthMtx, (Vec*)vec3, (Vec*)vec3);
    f31_val = -vec3[2];

    getNewShadowRampTexture((u32*)&handle);
    selectTexture(handle, 1);

    {
        f32 d2;
        mtx_110[0][0] = 0.0f;
        mtx_110[0][1] = 0.0f;
        mtx_110[0][2] = 1.0f / (d2 = f31_val - (f31_val - scale));
        mtx_110[0][3] = f31_val / d2;
        mtx_110[1][0] = 0.0f;
        mtx_110[1][1] = 0.0f;
        mtx_110[1][2] = 0.0f;
        mtx_110[1][3] = 0.0f;
    }
    PSMTXConcat(shadow->depthMtx, mtx, mtx_e0);
    PSMTXConcat(mtx_110, mtx_e0, mtx_e0);
    GXLoadTexMtxImm(mtx_e0, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);

    GXSetTevDirect(stage_base + 1);
    GXSetTevSwapMode(stage_base + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevOrder(stage_base + 1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(stage_base + 1, GX_CC_CPREV, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ZERO);
    GXSetTevAlphaIn(stage_base + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(stage_base + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(stage_base + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(2);
    GXSetNumTevStages((stage_count + 2));

    GXSetFog(GX_FOG_PERSP_EXP, gFogStartZ, gFogEndZ, gFogNearZ, gFogFarZ, fog_var);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_ZERO, GX_BL_INVSRCCLR, GX_LO_NOOP);

    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void gxSetOpaqueZWriteMode(void)
{
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 1 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_TRUE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 1;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void gxSetOpaqueNoZWriteMode(void)
{
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_NONE, GX_BL_ONE, GX_BL_ZERO, GX_LO_NOOP);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void gxSetAdditiveBlendZTest(void)
{
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void gxSetAdditiveBlendNoZTest(void)
{
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_ONE, GX_LO_NOOP);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void gxSetAlphaBlendNoZTest(void)
{
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void gxSetAlphaBlendZTest(void)
{
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void gxSetDebugTextMode(void)
{
    GXSetCullMode(GX_CULL_NONE);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C0, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void gxTevModulateRasStage(void)
{
    GXSetTevOrder(gTevStageCursor, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_ZERO, GX_CC_CPREV, GX_CC_RASC, GX_CC_ZERO);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_APREV, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevChanCount += 1;
}

void gxTevRasTimesColor1Stage(void)
{
    GXSetTevOrder(gTevStageCursor, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_ZERO, GX_CC_RASC, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_RASA, GX_CA_A1, GX_CA_ZERO);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevChanCount += 1;
}

void textRenderSetup(void)
{
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, GX_COLOR_NULL);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_C1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_A1, GX_CA_TEXA, GX_CA_ZERO);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTexCoordGen2(gTevTexCoordCursor, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexCoordCursor += 1;
    gTevTexGenCount += 1;
    gTevTexMapCursor += 1;
}

void gxTevAddColor1Stage(void)
{
    GXSetTevOrder(gTevStageCursor, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_C1);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A1);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevChanCount += 1;
}

void gxTevPassRasStage(void)
{
    GXSetTevOrder(gTevStageCursor, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_RASC);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_RASA);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevChanCount += 1;
}

void gxTevModulateColor1Stage(void)
{
    GXSetTevOrder(gTevStageCursor, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_APREV, GX_CA_A1, GX_CA_ZERO);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevChanCount += 1;
}

void gxTevAddTextureFrameBlendStages(void)
{
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, GX_COLOR_NULL);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexMapCursor += 1;
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, GX_COLOR_NULL);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_CPREV, GX_CC_TEXC, GX_CC_A0, GX_CC_ZERO);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_APREV, GX_CA_TEXA, GX_CA_A0, GX_CA_ZERO);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTexCoordGen2(gTevTexCoordCursor, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexCoordCursor += 1;
    gTevTexGenCount += 1;
    gTevTexMapCursor += 1;
}

void gxTevColor1TexAlphaStage(void)
{
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, GX_COLOR_NULL);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_C1);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_TEXA, GX_CA_A1, GX_CA_ZERO);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTexCoordGen2(gTevTexCoordCursor, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexMapCursor += 1;
    gTevTexCoordCursor += 1;
    gTevTexGenCount += 1;
}

void gxTevTextureTimesColor1Stage(void)
{
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, GX_COLOR_NULL);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_TEXA, GX_CA_A1, GX_CA_ZERO);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTexCoordGen2(gTevTexCoordCursor, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexMapCursor += 1;
    gTevTexCoordCursor += 1;
    gTevTexGenCount += 1;
}

void gxTevTextureTimesRasStage(void)
{
    GXSetTevOrder(gTevStageCursor, gTevTexCoordCursor, gTevTexMapCursor, GX_COLOR0A0);
    GXSetTevDirect(gTevStageCursor);
    GXSetTevColorIn(gTevStageCursor, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTexCoordGen2(gTevTexCoordCursor, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    gTevStageCursor += 1;
    gTevStageCount += 1;
    gTevTexMapCursor += 1;
    gTevTexCoordCursor += 1;
    gTevTexGenCount += 1;
    gTevChanCount += 1;
}

/*
 * Closes out the TEV pipeline configuration that drawViewFinderAperture etc. open:
 * pushes the current ind-stage / chan-ctrl / tex-gen counts in
 * gTevIndStageCount..00B back into GX, and if the global tint alpha
 * gHudTintAlpha isn't fully transparent (0xFF) appends one final TEV
 * stage that K-multiplies the tint over the existing color, advancing
 * gTevStageCursor (TEV stage cursor) and gTevStageCount (stage count).
 */
void gxTevCommitStages(void)
{
    GXColor c;

    GXSetNumIndStages(gTevIndStageCount);
    if (gTevChanCount != 0)
    {
        GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetNumChans(1);
    }
    else
    {
        GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
        GXSetNumChans(0);
    }
    GXSetNumTexGens(gTevTexGenCount);
    if (gHudTintAlpha < 0xFF)
    {
        c.a = gHudTintAlpha;
        GXSetTevKColor(GX_KCOLOR0, c);
        GXSetTevKAlphaSel(gTevStageCursor, GX_TEV_KASEL_K0_A);
        GXSetTevOrder(gTevStageCursor, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevDirect(gTevStageCursor);
        GXSetTevColorIn(gTevStageCursor, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(gTevStageCursor, GX_CA_ZERO, GX_CA_APREV, GX_CA_KONST, GX_CA_ZERO);
        GXSetTevSwapMode(gTevStageCursor, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(gTevStageCursor, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        gTevStageCursor = gTevStageCursor + 1;
        gTevStageCount++;
    }
    GXSetNumTevStages(gTevStageCount);
    if (gTevChanCount != 0)
    {
        GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    }
}

void gxTevResetStages(void)
{
    gTevIndStageCount = 0;
    gTevChanCount = 0;
    gTevTexGenCount = 0;
    gTevStageCount = 0;
    gTevStageCursor = 0;
    gTevTexCoordCursor = 0;
    gTevTexMapCursor = 0;
}

void _gxSetTevColor2(u8 r, u8 g, u8 b, u8 a)
{
    GXColor c;
    c.r = r;
    c.g = g;
    c.b = b;
    c.a = a;
    GXSetTevColor(GX_TEVREG1, c);
}

void _gxSetTevColor1(u8 r, u8 g, u8 b, u8 a)
{
    GXColor c;
    c.r = r;
    c.g = g;
    c.b = b;
    c.a = a;
    GXSetTevColor(GX_TEVREG0, c);
}

/*
 * Fullscreen 640x480 texture-tinted quad with shape-controlled alpha:
 * `flag != 0` lights the screen with three pre-set GXColors stamped into
 * K0/T1/T2; `flag == 0` instead does a single K0 modulate where K0's
 * alpha is the caller's byte divided by 4. Builds a per-call 3x4 tex
 * coord matrix that scales the source texture by 1/sx and 1/sy with a
 * sub-pixel offset baked from -320.0f/50.
 */
void drawViewFinderAperture(f32 sx, f32 sy, u8 a, u8 flag)
{
    Texture* handle;
    GXColor c0, c1, c2;
    Mtx mtx;

    c0 = sApertureColorBlack;
    c1 = sApertureColorEdge;
    c2 = sApertureColorCentre;
    getNewShadowRadialTexture(&handle);
    selectTexture(handle, 0);
    {
        f32 dec = 0.5f;
        f32 zero = 0.0f;
        f32 inv_sx = dec / sx;
        f32 inv_sy = dec / sy;
        mtx[0][0] = inv_sx;
        mtx[0][1] = zero;
        mtx[0][2] = zero;
        mtx[0][3] = -320.0f * inv_sx + dec;
        mtx[1][0] = zero;
        mtx[1][1] = inv_sy;
        mtx[1][2] = zero;
        mtx[1][3] = -240.0f * inv_sy + dec;
        mtx[2][0] = zero;
        mtx[2][1] = zero;
        mtx[2][2] = zero;
        mtx[2][3] = 1.0f;
    }
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    GXLoadTexMtxImm(mtx, GX_TEXMTX0, GX_MTX2x4);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if (flag != 0)
    {
        c0.a = a;
        GXSetTevKColor(GX_KCOLOR0, c0);
        GXSetTevColor(GX_TEVREG0, c1);
        GXSetTevColor(GX_TEVREG1, c2);
        GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_TEXA, GX_CA_A0, GX_CA_A1, GX_CA_KONST);
        GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_COMP_RGB8_GT, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    }
    else
    {
        c0.a = (u8)((s32)a >> 2);
        GXSetTevKColor(GX_KCOLOR0, c0);
        GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_TEXA, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
        GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);
    }
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXClearVtxDesc();
    GXSetCurrentMtx(GX_IDENTITY);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_INVSRCALPHA, GX_BL_SRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;

    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(GX_PNMTX0);
}

void drawSnowFlashOverlay(f32 s1, u8 flashAlpha, void* vec, f32 s2, u8 alpha0, u8 alpha1, f32 s3)
{
    Mtx mtx_58;
    Mtx mtx_28;
    Texture* handle1;
    Texture* handle2;
    f32 ratio1;
    f32 angle;
    f32 ratio2;
    f32 fade1;
    f32 fade2;
    GXColor c_K2;
    GXColor c_K0;
    GXColor c_K1;

    c_K0.a = alpha0;
    c_K1.a = alpha1;
    ratio1 = ((f32)(u32)Camera_GetCurrentViewYaw() - 32768.0f) / 8192.0f;
    ratio2 = ((f32)(u32)Camera_GetCurrentViewPitch() - 32768.0f) / 8192.0f;
    if (getHudHiddenFrameCount() != 0)
    {
        angle = gSnowFlashOverlayAngle;
    }
    else
    {
        f32 t = atanf_fast(((Vec*)vec)->x / ((Vec*)vec)->y);
        angle = gSnowFlashOverlayAngle + interpolate(t - gSnowFlashOverlayAngle, 0.05f, timeDelta);
        gSnowFlashOverlayAngle = angle;
    }
    c_K2.a = flashAlpha;

    getReflectionTexture2((u32*)&handle1);
    selectTexture(handle1, 0);
    getNewShadowSnowFlashTexture((u32*)&handle2);
    selectTexture(handle2, 1);

    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);

    PSMTXScale(mtx_58, 6.0f * s2, 6.0f * s2, 0.0f);
    PSMTXTrans(mtx_28, ratio1 * s3, ratio2 * s3 + s1, 0.0f);
    PSMTXConcat(mtx_28, mtx_58, mtx_58);
    PSMTXRotRad(mtx_28, 'z', angle);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    PSMTXTrans(mtx_28, -0.5f, -0.5f, 0.0f);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    GXLoadTexMtxImm(mtx_58, GX_TEXMTX0, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);

    PSMTXScale(mtx_58, 12.0f * s2, 12.0f * s2, 0.0f);
    fade1 = 2.0f * ratio1;
    fade2 = 2.0f * ratio2;
    PSMTXTrans(mtx_28, fade1 * s3, 0.75f * s1 + fade2 * s3, 0.0f);
    PSMTXConcat(mtx_28, mtx_58, mtx_58);
    PSMTXRotRad(mtx_28, 'z', 0.5f * angle);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    PSMTXTrans(mtx_28, -0.5f, -0.5f, 0.0f);
    PSMTXConcat(mtx_58, mtx_28, mtx_58);
    GXLoadTexMtxImm(mtx_58, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);

    GXSetTevKColor(GX_KCOLOR0, c_K0);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_KONST, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

    GXSetTevDirect(GX_TEVSTAGE1);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_TEXC, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_APREV, GX_CA_TEXA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_2, GX_TRUE, GX_TEVPREV);

    GXSetTevKColor(GX_KCOLOR1, c_K1);
    GXSetTevKAlphaSel(GX_TEVSTAGE2, GX_TEV_KASEL_K1_A);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_KONST, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVREG0);

    GXSetTevDirect(GX_TEVSTAGE3);
    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD2, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_TEXC, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_ZERO, GX_CA_A0, GX_CA_TEXA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVREG0);

    GXSetTevKAlphaSel(GX_TEVSTAGE4, GX_TEV_KASEL_1);
    GXSetTevDirect(GX_TEVSTAGE4);
    GXSetTevOrder(GX_TEVSTAGE4, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE4, GX_CC_CPREV, GX_CC_C0, GX_CC_A0, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE4, GX_CA_APREV, GX_CA_KONST, GX_CA_A0, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE4, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevKColor(GX_KCOLOR2, c_K2);
    GXSetTevKAlphaSel(GX_TEVSTAGE5, GX_TEV_KASEL_K2_A);
    GXSetTevDirect(GX_TEVSTAGE5);
    GXSetTevOrder(GX_TEVSTAGE5, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE5, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE5, GX_CA_ZERO, GX_CA_APREV, GX_CA_KONST, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE5, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetNumTexGens(3);
    GXSetNumTevStages(6);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);

    GXClearVtxDesc();
    GXSetCurrentMtx(GX_IDENTITY);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 1 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LESS, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 1;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(GX_PNMTX0);
}

void doHeatEffect(u8 alpha)
{
    Mtx mtx_44;
    f32 indMtx[6];
    Texture* handle2;
    Texture* handle1;
    f32 fA;
    f32 fB;
    f32 mulY;
    f32 mulX;
    s16 v;
    u8 k;
    u8 a2;
    u8 a1;

    *(IndMtxInit*)indMtx = sIndStageInitData.ind;
    v = (s16)Camera_GetCurrentViewPitch();
    if (v < 0)
    {
        k = (((u16)(int)v >> 8) - 0xc0) << 2;
    }
    else
    {
        k = 0xff;
    }
    a1 = (alpha * 0xff) >> 8;
    a2 = (k * alpha) >> 8;

    selectReflectionTexture(0);
    getReflectionTexture2((u32*)&handle1);
    selectTexture(handle1, 1);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);

    newshadows_getReflectionScrollOffsets(&fA, &fB);
    fA *= 10.0f;
    fB *= 10.0f;
    getNewShadowCausticTexture((u32*)&handle2);
    selectTexture(handle2, 2);

    mathSinCosf(3.142f * fA, &mulX, &mulY);
    mulY *= 0.5f;
    mulX *= 0.5f;

    indMtx[0] = mulY;
    indMtx[1] = mulX;
    indMtx[3] = -mulX;
    indMtx[4] = mulY;

    PSMTXScale(mtx_44, 7.0f, 7.0f, 1.0f);
    mtx_44[0][3] = fA;
    mtx_44[1][3] = -fB;
    GXLoadTexMtxImm(mtx_44, GX_PTTEXMTX0, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX0);

    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP2);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, (f32(*)[3])indMtx, -6);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);

    GXSetTevKColor(GX_KCOLOR0, gHeatEffectKColor);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_KONST, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_TEXC, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_APREV, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

    GXSetNumTexGens(2);
    GXSetNumTevStages(3);
    GXSetNumIndStages(1);
    GXSetNumChans(1);
    GXClearVtxDesc();
    GXSetCurrentMtx(GX_IDENTITY);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 1 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LESS, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 1;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = a2;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = a2;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1e0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = a1;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1e0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = 0;
    GXWGFifo.u8 = a1;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;
    Camera_RebuildProjectionMatrix();
    GXSetCurrentMtx(GX_PNMTX0);
}

/*
 * Fullscreen 640x480 textured quad with caller-supplied alpha. The alpha
 * is multiplied by 255.0f (a 0..255 scale), converted to int and
 * stamped into byte 3 of the K0 GXColor cache (gMotionBlurKColor). Sets up
 * one TEV stage that K-multiplies the texture by alpha; uses fixed UVs
 * 0..0x80 so the texture maps once across the screen. Used when fading
 * the screen to texture (e.g. boot logo / "now loading").
 */
void renderMotionBlur(f32 alpha)
{
    Mtx mtx;

    gMotionBlurKColor.a = 255.0f * alpha;
    selectReflectionTexture(0);
    GXSetTevKColor(GX_KCOLOR0, gMotionBlurKColor);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    PSMTXIdentity(mtx);
    GXLoadTexMtxImm(mtx, GX_TEXMTX2, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXSetNumTexGens(1);
    GXSetNumTevStages(1);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_ZERO);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}

void doBlurFilter(f32 wx, f32 wy, f32 wz, u8 param4, u8 param5)
{
    Mtx mtx_27;
    Mtx mtx_24;
    Mtx mtx_2A;
    Mtx mtx_2D;
    Mtx mtx_30;
    GXColor c1;
    GXColor c0;
    Texture* handle;
    f32 pz, px, py, pw;
    int stage_base;

    wx = wx - playerMapOffsetX;
    wz = wz - playerMapOffsetZ;
    Camera_ProjectWorldPoint(wx, wy, wz, &px, &py, &pz, &pw);
    pz += 1.0f;
    c0.a = (u8)(((u32)(16777216.0f * pz) & 0x00FF0000) >> 16);
    selectReflectionTexture(0);
    getReflectionTexture2((u32*)&handle);
    selectTexture(handle, 1);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);

    PSMTXIdentity(mtx_24);
    mtx_24[1][3] = -0.0041666667f;
    GXLoadTexMtxImm(mtx_24, GX_TEXMTX2, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX2, GX_FALSE, GX_PTIDENTITY);

    PSMTXIdentity(mtx_2A);
    mtx_2A[1][3] = -0.0041666667f;
    GXLoadTexMtxImm(mtx_2A, GX_TEXMTX4, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX4, GX_FALSE, GX_PTIDENTITY);

    PSMTXIdentity(mtx_2D);
    mtx_2D[0][3] = 0.003125f;
    GXLoadTexMtxImm(mtx_2D, GX_TEXMTX5, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX5, GX_FALSE, GX_PTIDENTITY);

    PSMTXIdentity(mtx_30);
    mtx_30[0][3] = -0.003125f;
    GXLoadTexMtxImm(mtx_30, GX_TEXMTX6, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD4, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX6, GX_FALSE, GX_PTIDENTITY);

    GXSetTexCoordGen2(GX_TEXCOORD5, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);

    PSMTXIdentity(mtx_27);
    GXLoadTexMtxImm(mtx_27, GX_TEXMTX3, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX3, GX_FALSE, GX_PTIDENTITY);

    GXSetTevKColor(GX_KCOLOR0, c0);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, GX_TEV_KASEL_K0_A);
    c1 = gBlurFilterKColor;
    GXSetTevKColor(GX_KCOLOR1, c1);

    GXSetNumTexGens(6);
    GXSetNumIndStages(0);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(0);

    stage_base = 0;
    if (param5 == 0)
    {
        if (param4 == 0)
        {
            GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
            GXSetNumTevStages(7);

            GXSetTevDirect(GX_TEVSTAGE0);
            GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
            GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
            GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_TEXA, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
            GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
            GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
            GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_SUB, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVREG2);
            stage_base = 1;
        }
        else
        {
            GXSetNumTevStages(6);
        }

        GXSetTevDirect(stage_base);
        GXSetTevOrder(stage_base, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
        GXSetTevColorIn(stage_base, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
        GXSetTevAlphaIn(stage_base, GX_CA_KONST, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
        GXSetTevSwapMode(stage_base, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(stage_base, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(stage_base, GX_TEV_SUB, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVPREV);

        GXSetTevKColorSel(stage_base + 1, GX_TEV_KCSEL_K1);
        GXSetTevDirect(stage_base + 1);
        GXSetTevOrder(stage_base + 1, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(stage_base + 1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_ZERO);
        if (param4 == 0)
        {
            GXSetTevAlphaIn(stage_base + 1, GX_CA_APREV, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A2);
        }
        else
        {
            GXSetTevAlphaIn(stage_base + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        }
        GXSetTevSwapMode(stage_base + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(stage_base + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(stage_base + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVPREV);

        GXSetTevKColorSel(stage_base + 2, GX_TEV_KCSEL_K1);
        GXSetTevDirect(stage_base + 2);
        GXSetTevOrder(stage_base + 2, GX_TEXCOORD2, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(stage_base + 2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
        GXSetTevAlphaIn(stage_base + 2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(stage_base + 2, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(stage_base + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(stage_base + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

        GXSetTevKColorSel(stage_base + 3, GX_TEV_KCSEL_K1);
        GXSetTevDirect(stage_base + 3);
        GXSetTevOrder(stage_base + 3, GX_TEXCOORD3, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(stage_base + 3, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
        GXSetTevAlphaIn(stage_base + 3, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(stage_base + 3, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(stage_base + 3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(stage_base + 3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

        GXSetTevKColorSel(stage_base + 4, GX_TEV_KCSEL_K1);
        GXSetTevDirect(stage_base + 4);
        GXSetTevOrder(stage_base + 4, GX_TEXCOORD4, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(stage_base + 4, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
        GXSetTevAlphaIn(stage_base + 4, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(stage_base + 4, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(stage_base + 4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(stage_base + 4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

        GXSetTevKColorSel(stage_base + 5, GX_TEV_KCSEL_K1);
        GXSetTevDirect(stage_base + 5);
        GXSetTevOrder(stage_base + 5, GX_TEXCOORD5, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(stage_base + 5, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
        GXSetTevAlphaIn(stage_base + 5, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(stage_base + 5, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(stage_base + 5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(stage_base + 5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);
    }
    else
    {
        GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
        GXSetNumTevStages(7);

        GXSetTevDirect(GX_TEVSTAGE0);
        GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
        GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_TEXA, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
        GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
        GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);

        GXSetTevDirect(GX_TEVSTAGE1);
        GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
        GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_KONST, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
        GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

        GXSetTevKColorSel(GX_TEVSTAGE2, GX_TEV_KCSEL_K1);
        GXSetTevDirect(GX_TEVSTAGE2);
        GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_ZERO);
        GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_APREV, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A2);
        GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

        GXSetTevKColorSel(GX_TEVSTAGE3, GX_TEV_KCSEL_K1);
        GXSetTevDirect(GX_TEVSTAGE3);
        GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD2, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

        GXSetTevKColorSel(GX_TEVSTAGE4, GX_TEV_KCSEL_K1);
        GXSetTevDirect(GX_TEVSTAGE4);
        GXSetTevOrder(GX_TEVSTAGE4, GX_TEXCOORD3, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE4, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE4, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(GX_TEVSTAGE4, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

        GXSetTevKColorSel(GX_TEVSTAGE5, GX_TEV_KCSEL_K1);
        GXSetTevDirect(GX_TEVSTAGE5);
        GXSetTevOrder(GX_TEVSTAGE5, GX_TEXCOORD4, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE5, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE5, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(GX_TEVSTAGE5, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE5, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);

        GXSetTevKColorSel(GX_TEVSTAGE6, GX_TEV_KCSEL_K1);
        GXSetTevDirect(GX_TEVSTAGE6);
        GXSetTevOrder(GX_TEVSTAGE6, GX_TEXCOORD5, GX_TEXMAP0, GX_COLOR_NULL);
        GXSetTevColorIn(GX_TEVSTAGE6, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
        GXSetTevAlphaIn(GX_TEVSTAGE6, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(GX_TEVSTAGE6, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(GX_TEVSTAGE6, GX_TEV_ADD, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(GX_TEVSTAGE6, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    }

    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCullMode(GX_CULL_NONE);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 0 || gGxZModeCompareFunc != 7 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_FALSE, GX_ALWAYS, GX_FALSE);
        gGxZModeCompareEnable = 0;
        gGxZModeCompareFunc = 7;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
    GXSetProjection(hudMatrix, GX_ORTHOGRAPHIC);
    GXBegin(GX_QUADS, GX_VTXFMT0, 4);

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0x280;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0x80;
    GXWGFifo.s16 = 0x80;

    GXWGFifo.u8 = 0x3C;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x1E0;
    GXWGFifo.s16 = -8;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.u8 = 0xFF;
    GXWGFifo.s16 = 0;
    GXWGFifo.s16 = 0x80;

    Camera_RebuildProjectionMatrix();
}

void setupWaterReflectionTev(Texture* handle1, Texture* handle2)
{
    Mtx mtx_30;
    GXColor temp;
    GXColor temp2;
    GXColor k0;
    GXColor k1;
    GXColor k2;
    GXColor tev1;
    GXColor tev2;
    f32 (*indBase[1])[2][3];

    indBase[0] = gWaterReflectionIndTexMtx;
    selectReflectionTexture(0);
    selectTexture(handle1, 1);
    selectTexture(handle2, 2);

    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXLoadTexMtxImm(gCameraLightPerspectiveFlipYMatrix, GX_PTTEXMTX7, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_POS, 0, GX_FALSE, GX_PTTEXMTX7);
    PSMTXScale(mtx_30, 12.0f, 1.0f, 0.0f);
    GXLoadTexMtxImm(mtx_30, GX_TEXMTX0, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);

    if (isHeavyFogEnabled() != 0)
    {
        temp.r = gFogColor.r;
        temp.g = gFogColor.g;
        temp.b = gFogColor.b;
    }
    else
    {
        u8 ignoredLightColor;
        (*gSkyInterface)
            ->getCurrentAmbientAndLightColors(&temp.r, &temp.g, &temp.b, &ignoredLightColor, &ignoredLightColor,
                                              &ignoredLightColor);
    }

    k0 = gWaterReflectionKColorR;
    ((void (*)(int, GXColor*))GXSetTevKColor)(0, &k0);
    GXSetTevKColorSel(GX_TEVSTAGE0, GX_TEV_KCSEL_K0);
    k1 = gWaterReflectionKColorG;
    ((void (*)(int, GXColor*))GXSetTevKColor)(1, &k1);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K1);
    k2 = gWaterReflectionKColorB;
    ((void (*)(int, GXColor*))GXSetTevKColor)(2, &k2);
    GXSetTevKColorSel(GX_TEVSTAGE2, GX_TEV_KCSEL_K2);

    temp.r = (u8)((int)temp.r >> 2);
    temp.g = (u8)((int)temp.g >> 2);
    temp.b = (u8)((int)temp.b >> 2);
    tev1 = temp;
    ((void (*)(int, GXColor*))GXSetTevColor)(1, &tev1);

    temp2.r = (u8)(temp.r + 0xC0);
    temp2.g = (u8)(temp.g + 0xC0);
    temp2.b = (u8)(temp.b + 0xC0);
    tev2 = temp2;
    ((void (*)(int, GXColor*))GXSetTevColor)(2, &tev2);

    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, indBase[0][0], -1);
    GXSetIndTexMtx(GX_ITM_1, indBase[0][1], -1);
    GXSetIndTexMtx(GX_ITM_2, indBase[0][2], -1);
    GXSetTevIndirect(GX_TEVSTAGE0, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_S);
    GXSetTevIndirect(GX_TEVSTAGE2, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_2, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetNumIndStages(1);
    GXSetNumTexGens(3);
    GXSetNumTevStages(4);
    GXSetNumChans(1);

    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C0);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_RASA);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP0, GX_ALPHA_BUMPN);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_RASA, GX_CA_APREV, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevDirect(GX_TEVSTAGE3);
    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD2, GX_TEXMAP2, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_CPREV, GX_CC_C1, GX_CC_TEXA, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void setupReflectionIndirectTev(u8 flag)
{
    f32 mtx[6];

    selectReflectionTexture(1);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_POS, GX_TEXMTX2, GX_FALSE, GX_PTIDENTITY);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    mtx[0] = 0.0f;
    mtx[1] = 0.5f;
    mtx[2] = 0.0f;
    mtx[3] = 0.0f;
    mtx[4] = 0.0f;
    mtx[5] = 0.5f;
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD0, GX_TEXMAP0);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, (void*)mtx, -2);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_S);
    GXSetNumIndStages(1);
    GXSetNumTexGens(2);
    GXSetNumTevStages(2);
    GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_VTX, GX_LIGHT_NULL, GX_DF_NONE, GX_AF_NONE);
    GXSetNumChans(1);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_RASC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_RASA);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    if (flag != 0)
    {
        GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_TEXC, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    }
    else
    {
        GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_CPREV, GX_CC_ZERO);
    }
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_ALPHA_BUMPN);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_RASA, GX_CA_APREV, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
}

void setupReflectionDistortTev(Texture* texHandle)
{

    u8 ignoredLightColor;
    f32 sOff;
    f32 tOff;
    f32 indMtx[6];
    Mtx scaleMtx;

    selectReflectionTexture(0);
    selectTexture(texHandle, 1);
    newshadows_getReflectionScrollOffsets(&sOff, &tOff);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_POS, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX3x4, GX_TG_POS, GX_TEXMTX2, GX_FALSE, GX_PTIDENTITY);
    PSMTXScale(scaleMtx, 1.0f, 1.0f, 1.0f);
    GXLoadTexMtxImm(scaleMtx, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);
    indMtx[0] = 0.0f;
    indMtx[1] = 0.5f;
    indMtx[2] = 0.0f;
    indMtx[3] = 0.0f;
    indMtx[4] = 0.0f;
    indMtx[5] = 0.5f;
    if (isHeavyFogEnabled())
    {
        gReflectionTintColor.r = gFogColor.r;
        gReflectionTintColor.g = gFogColor.g;
        gReflectionTintColor.b = gFogColor.b;
        gReflectionTintColor.a = 0x80;
    }
    else
    {
        (*gSkyInterface)
            ->getCurrentAmbientAndLightColors(&gReflectionTintColor.r, &gReflectionTintColor.g, &gReflectionTintColor.b, &ignoredLightColor,
                                              &ignoredLightColor, &ignoredLightColor);
        gReflectionTintColor.r = gReflectionTintColor.r >> 3;
        gReflectionTintColor.g = gReflectionTintColor.g >> 3;
        gReflectionTintColor.b = gReflectionTintColor.b >> 3;
        gReflectionTintColor.a = gReflectionTintAlpha;
    }
    GXSetTevColor(GX_TEVREG2, gReflectionTintColor);
    GXSetTevKColor(GX_KCOLOR0, gReflectionKColor);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K0);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, (f32(*)[3])indMtx, -1);
    GXSetIndTexMtx(GX_ITM_1, (f32(*)[3])indMtx, -2);
    GXSetTevIndirect(GX_TEVSTAGE0, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_S);
    GXSetNumIndStages(1);
    GXSetNumChans(1);
    GXSetNumTexGens(3);
    GXSetNumTevStages(2);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_C2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (isHeavyFogEnabled())
    {
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVPREV);
    }
    else
    {
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    }
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD2, GX_TEXMAP0, GX_ALPHA_BUMPN);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_CPREV, GX_CC_TEXC, GX_CC_KONST, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_A1, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

void setupReflectionBumpDistortTev(void* texture)
{

    u8 ignoredLightColor;
    f32 sOff;
    f32 tOff;
    f32 indMtx[6];
    Mtx scaleMtx;

    selectReflectionTexture(0);
    loadNewShadowBumpTexture(1);
    newshadows_getReflectionScrollOffsets(&sOff, &tOff);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_POS, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX3x4, GX_TG_POS, GX_TEXMTX2, GX_FALSE, GX_PTIDENTITY);
    PSMTXScale(scaleMtx, 1.0f, 1.0f, 1.0f);
    GXLoadTexMtxImm(scaleMtx, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);
    indMtx[0] = 0.25f;
    indMtx[1] = 0.0f;
    indMtx[2] = 0.0f;
    indMtx[3] = 0.0f;
    indMtx[4] = 0.25f;
    indMtx[5] = 0.0f;
    if (isHeavyFogEnabled())
    {
        gReflectionBumpTintColor.r = gFogColor.r;
        gReflectionBumpTintColor.g = gFogColor.g;
        gReflectionBumpTintColor.b = gFogColor.b;
        gReflectionBumpTintColor.a = 0x80;
    }
    else
    {
        (*gSkyInterface)
            ->getCurrentAmbientAndLightColors(&gReflectionBumpTintColor.r, &gReflectionBumpTintColor.g, &gReflectionBumpTintColor.b, &ignoredLightColor,
                                              &ignoredLightColor, &ignoredLightColor);
        gReflectionBumpTintColor.r = gReflectionBumpTintColor.r >> 3;
        gReflectionBumpTintColor.g = gReflectionBumpTintColor.g >> 3;
        gReflectionBumpTintColor.b = gReflectionBumpTintColor.b >> 3;
        gReflectionBumpTintColor.a = gReflectionTintAlpha;
    }
    GXSetTevColor(GX_TEVREG2, gReflectionBumpTintColor);
    GXSetTevKColor(GX_KCOLOR0, gReflectionBumpKColor);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K0);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, (f32(*)[3])indMtx, -1);
    GXSetIndTexMtx(GX_ITM_1, (f32(*)[3])indMtx, -2);
    GXSetTevIndirect(GX_TEVSTAGE0, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_U);
    GXSetNumIndStages(1);
    GXSetNumChans(1);
    GXSetNumTexGens(3);
    GXSetNumTevStages(2);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_C2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (isHeavyFogEnabled())
    {
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVPREV);
    }
    else
    {
        GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    }
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD2, GX_TEXMAP0, GX_ALPHA_BUMPN);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_CPREV, GX_CC_TEXC, GX_CC_KONST, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_A1, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}



/* .bss block 0x80391DC0-0x803967C0 */

void setupWaterCausticTev(void)
{

    Mtx mtx_cc;
    Mtx mtx_9c;
    Mtx mtx_6c;
    f32 indMtx_54[6];
    f32 indMtx_3c[6];
    f32 indMtx_24[6];
    Texture* handle1;
    f32 fA, fB;
    GXColor temp;

    newshadows_getReflectionScrollOffsets(&fA, &fB);
    selectReflectionTexture(0);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_POS, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    getNewShadowCausticTexture((u32*)&handle1);
    selectTexture(handle1, 1);

    PSMTXScale(mtx_cc, 1.0f, 1.0f, 1.0f);
    mtx_cc[1][3] = fA;
    GXLoadTexMtxImm(mtx_cc, GX_TEXMTX3, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX3, GX_FALSE, GX_PTIDENTITY);

    indMtx_54[0] = 0.5f;
    indMtx_54[1] = 0.0f;
    indMtx_54[2] = 0.0f;
    indMtx_54[3] = 0.0f;
    indMtx_54[4] = 0.5f;
    indMtx_54[5] = 0.0f;
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, (f32(*)[3])indMtx_54, -2);
    GXSetTevIndirect(GX_TEVSTAGE0, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_0, GX_ITW_0, 0, 0, GX_ITBA_OFF);

    PSMTXScale(mtx_9c, 0.83f, 0.83f, 0.83f);
    PSMTXRotRad(mtx_6c, 'z', 0.7853982f);
    PSMTXConcat(mtx_6c, mtx_9c, mtx_9c);
    mtx_9c[0][3] = fB;
    mtx_9c[1][3] = fB;
    GXLoadTexMtxImm(mtx_9c, GX_TEXMTX4, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_TEX0, GX_TEXMTX4, GX_FALSE, GX_PTIDENTITY);

    indMtx_3c[0] = 0.3f;
    indMtx_3c[1] = 0.3f;
    indMtx_3c[2] = 0.0f;
    indMtx_3c[3] = -0.3f;
    indMtx_3c[4] = 0.3f;
    indMtx_3c[5] = 0.0f;
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD2, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_1, (f32(*)[3])indMtx_3c, -4);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE1, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_OFF);

    if (isHeavyFogEnabled() != 0)
    {
        gWaterCausticKColor.r = gFogColor.r;
        gWaterCausticKColor.g = gFogColor.g;
        gWaterCausticKColor.b = gFogColor.b;
        gWaterCausticKColor.a = 0x80;
    }
    else
    {
        u8 ignoredLightColor;
        u8* p1;
        u8* p2;
        (*gSkyInterface)
            ->getCurrentAmbientAndLightColors(&gWaterCausticKColor.r, p1 = &gWaterCausticKColor.g,
                                              p2 = &gWaterCausticKColor.b, &ignoredLightColor, &ignoredLightColor,
                                              &ignoredLightColor);
        gWaterCausticKColor.r = (u8)(gWaterCausticKColor.r >> 3);
        *p1 = (u8)(*p1 >> 3);
        *p2 = (u8)(*p2 >> 3);
        gWaterCausticKColor.a = gReflectionTintAlpha;
    }
    temp = gWaterCausticKColor;
    GXSetTevKColor(GX_KCOLOR0, temp);
    GXSetTevKAlphaSel(GX_TEVSTAGE1, GX_TEV_KASEL_K0_A);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_K0);

    GXSetNumIndStages(2);
    GXSetNumChans(1);
    GXSetNumTexGens(4);
    GXSetNumTevStages(4);

    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_KONST, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (isHeavyFogEnabled() != 0)
    {
        GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_DIVIDE_2, GX_TRUE, GX_TEVREG0);
    }
    else
    {
        GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    }
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);

    indMtx_24[0] = 0.0f;
    indMtx_24[1] = 0.5f;
    indMtx_24[2] = 0.0f;
    indMtx_24[3] = -0.5f;
    indMtx_24[4] = 0.0f;
    indMtx_24[5] = 0.0f;
    GXSetIndTexMtx(GX_ITM_2, (f32(*)[3])indMtx_24, -5);
    GXSetTevIndirect(GX_TEVSTAGE2, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_0, GX_ITW_0, 0, 0, GX_ITBA_OFF);
    GXSetTevIndirect(GX_TEVSTAGE3, GX_INDTEXSTAGE1, GX_ITF_8, GX_ITB_STU, GX_ITM_2, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_OFF);
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX3x4, GX_TG_POS, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);

    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetTevOrder(GX_TEVSTAGE3, GX_TEXCOORD3, GX_TEXMAP0, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE3, GX_CC_TEXC, GX_CC_C0, GX_CC_A0, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE3, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_RASA);
    GXSetTevSwapMode(GX_TEVSTAGE3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);

    GXSetBlendMode(GX_BM_BLEND, GX_BL_SRCALPHA, GX_BL_INVSRCALPHA, GX_LO_NOOP);
    GXSetCullMode(GX_CULL_NONE);
    if ((u32)gGxZModeCompareEnable != 1 || gGxZModeCompareFunc != 3 || gGxZModeUpdateEnable != 0 || gGxZModeValid == 0)
    {
        GXSetZMode(GX_TRUE, GX_LEQUAL, GX_FALSE);
        gGxZModeCompareEnable = 1;
        gGxZModeCompareFunc = 3;
        gGxZModeUpdateEnable = 0;
        gGxZModeValid = 1;
    }
    if ((u32)gGxZCompLocCached != 1 || gGxZCompLocValid == 0)
    {
        GXSetZCompLoc(GX_TRUE);
        gGxZCompLocCached = 1;
        gGxZCompLocValid = 1;
    }
    GXSetAlphaCompare(GX_ALWAYS, 0, GX_AOP_AND, GX_ALWAYS, 0);
}

#include "dolphin/PPCArch.h"
#include "dolphin/mtx.h"
#include "main/shader_api.h"
#include "sys/objects.h"
#include "main/newshadows.h"
#include "main/texture.h"
#include "main/model.h"
#include "dolphin/os/OSCache.h"
#include "main/pad.h"
#include "main/pi_data_file_api.h"
#include "main/shader_dolphin.h"
#include "main/dll/FRONT/n_options.h"
#include "dolphin/gx/GXCull.h"
#include "main/track_dolphin_api.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "dolphin/gx/GXCpu2Efb.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/os/OSTime.h"
#include "main/camera.h"
#include "main/debug.h"
#include "main/fileio.h"
#include "main/gameloop_api.h"
#include "main/map_load.h"
#include "main/map_texscroll.h"
#include "main/rcp_dolphin.h"
#include "main/sky_api.h"
#include "main/textrender_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "track/intersect_api.h"
#include "track/intersect_depth_read_api.h"
#include "dolphin/gx/GXBump.h"
#include "main/newshadows_texture_api.h"
#include "main/rcp_dolphin_render_api.h"
#include "main/pi_dolphin_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/vecmath.h"


static int sRcpUnused0;
int gRcpNextTevStage;
int gRcpNextTexMap;
int gRcpNextTexCoord;
int gRcpNextTexMtx;
int gRcpNextPostTexMtx;
int gRcpNextIndTexStage;
int gRcpNextTexCoordSource;
int gRcpNextKColor;
int gRcpNextKColorSel;
int gRcpNextKAlphaSel;
u8 gRcpTevPrevAlphaValid;
u8 gRcpNumTevStages;
u8 gRcpNumTexGens;
u8 gRcpNumIndStages;
int lbl_803DCD64;
int lbl_803DCD60;
int lbl_803DCD5C;
int lbl_803DCD58;
int lbl_803DCD54;
int lbl_803DCD50;
int lbl_803DCD4C;
u8 lbl_803DCD4B;
u8 lbl_803DCD4A;
u8 lbl_803DCD49;
u8 lbl_803DCD48;
f32 gHeavyFogTop;
f32 gHeavyFogBottom;
f32 gHeavyFogDepthScale;
f32 gHeavyFogDepthOffset;
f32 gHeavyFogWorldScale;
u8 gHeavyFogMode;
u8 gRcpTevPrevColorValid;
u8* sWarpNoiseTexture;
u8 gHeavyFogEnabled;

u8 lbl_803DB5E8 = 0xFF;
GXColor gHeatEffectColor = {0xFF, 0xFF, 0xFF, 0xC0};
f32 gHeatEffectScale = 1.0f;
int sWarpNoiseIndMtxScaleExp = -4;
u8 sWarpNoiseBaseColor[8] = {0x28, 0x20, 0, 0xFF, 0, 0, 0, 0};

typedef struct IndTexMtx23
{
    f32 m[2][3];
} IndTexMtx23;

struct piIndMtx
{
    f32 m[2][3];
};

const struct piIndMtx sEnvMapBumpIndMtx = {
    {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 sHeavyFogIndMtx = {
    {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const Vec sWarpedRingRotAxes[4] = {
    {3.0f, -1.0f, 1.0f}, {1.0f, -1.0f, 3.0f}, {1.0f, -2.0f, 1.0f}, {-2.0f, -1.0f, 1.0f}};
const IndTexMtx23 sWarpedRingIndMtx = {
    {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 sHeatShimmerIndMtx1 = {
    {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 sHeatShimmerIndMtx2[2] = {
    {{{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}},
    {{{0.0f, 0.0f, 0.0f}, {0.0f, 0.0f, 0.0f}}}};
const struct piIndMtx sWavyCausticIndMtx = {
    {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 sWarpedNoiseIndMtx = {
    {{0.0f, 0.5f, 0.0f}, {0.0f, 0.0f, 0.5f}}};
const IndTexMtx23 gTexIndMtxTable = {
    {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};

static const GXColorS10 kYuvTevColor0 = { -90, 0, -114, 135 };
static const GXColor kYuvKColor0 = { 0x00, 0x00, 0xE2, 0x58 };
static const GXColor kYuvKColor1 = { 0xB3, 0x00, 0x00, 0xB6 };
static const GXColor kYuvKColor2 = { 0xFF, 0x00, 0xFF, 0x80 };
extern GXTexObj sSecondaryTexObj;

static void chooseTevKonstSelectors(void* params, u8 colorEnabled, u8 alphaEnabled, int* colorSelection,
                                    int* alphaSelection) {
    u8* buf = params;
    u8 haveColorSel = 0;
    u8 haveAlphaSel = 0;
    if (colorEnabled != 0) {
        if (buf[0] == buf[1] && buf[0] == buf[2]) {
            if (buf[0] == 0xff) {
                *colorSelection = 0;
                haveColorSel = 1;
            } else if (buf[0] == 0xe0) {
                *colorSelection = 1;
                haveColorSel = 1;
            } else if (buf[0] == 0xc0) {
                *colorSelection = 2;
                haveColorSel = 1;
            } else if (buf[0] == 0xa0) {
                *colorSelection = 3;
                haveColorSel = 1;
            } else if (buf[0] == 0x80) {
                *colorSelection = 4;
                haveColorSel = 1;
            } else if (buf[0] == 0x60) {
                *colorSelection = 5;
                haveColorSel = 1;
            } else if (buf[0] == 0x40) {
                *colorSelection = 6;
                haveColorSel = 1;
            } else if (buf[0] == 0x20) {
                *colorSelection = 7;
                haveColorSel = 1;
            }
        }
        if (haveColorSel == 0) {
            *colorSelection = gRcpNextKColorSel;
        }
    } else {
        haveColorSel = 1;
    }
    if (alphaEnabled != 0) {
        if (buf[3] == 0xff) {
            *alphaSelection = 0;
            haveAlphaSel = 1;
        } else if (buf[3] == 0xe0) {
            *alphaSelection = 1;
            haveAlphaSel = 1;
        } else if (buf[3] == 0xc0) {
            *alphaSelection = 2;
            haveAlphaSel = 1;
        } else if (buf[3] == 0xa0) {
            *alphaSelection = 3;
            haveAlphaSel = 1;
        } else if (buf[3] == 0x80) {
            *alphaSelection = 4;
            haveAlphaSel = 1;
        } else if (buf[3] == 0x60) {
            *alphaSelection = 5;
            haveAlphaSel = 1;
        } else if (buf[3] == 0x40) {
            *alphaSelection = 6;
            haveAlphaSel = 1;
        } else if (buf[3] == 0x20) {
            *alphaSelection = 7;
            haveAlphaSel = 1;
        }
        if (haveAlphaSel == 0) {
            *alphaSelection = gRcpNextKAlphaSel;
        }
    } else {
        haveAlphaSel = 1;
    }
    if (haveColorSel == 0 || haveAlphaSel == 0) {
        GXSetTevKColor(gRcpNextKColor, *(GXColor*)params);
        gRcpNextKColor += 1;
        gRcpNextKColorSel += 1;
        gRcpNextKAlphaSel += 1;
    }
}

static void setHeatEffectInverted(void)
{
    gHeatEffectScale = -1.0f;
}

void setHeatEffectParams(u8 alpha, f32 scale)
{
    gHeatEffectColor.a = alpha;
    gHeatEffectScale = scale;
    if (scale > 1.0f)
    {
        gHeatEffectScale = 1.0f;
    }
}


static void setDefaultHeavyFogParams(void)
{
    gHeavyFogDepthScale = 0.0f;
    gHeavyFogDepthOffset = 0.8f;
    gHeavyFogWorldScale = 0.9f;
}

void disableHeavyFog(void)
{
    gHeavyFogEnabled = 0x0;
}

void enableHeavyFog(f32 top, f32 bottom, f32 depthScale, f32 depthOffset, f32 worldScale, u8 mode)
{
    gHeavyFogEnabled = 1;
    gHeavyFogTop = top;
    gHeavyFogBottom = bottom;
    gHeavyFogDepthScale = depthScale;
    gHeavyFogDepthOffset = depthOffset;
    gHeavyFogWorldScale = worldScale;
    gHeavyFogMode = mode;
}


void getHeavyFogRange(f32* high, f32* low)
{
    *high = gHeavyFogTop;
    *low = gHeavyFogBottom;
}

u8 isHeavyFogEnabled(void)
{
    return gHeavyFogEnabled;
}

void* Shader_getLayer(void* base, int idx)
{
    return &((Shader*)base)->layers[idx];
}
void selectTextureWithSecondary(Texture* texture, int mapId)
{
    void* base;
    if (texture == NULL)
        return;
    base = texture->gxTexObj;
    if (texture->preloaded != 0)
    {
        GXLoadTexObjPreLoaded(base, (GXTexRegion*)texture->tmemAddr, mapId);
    }
    else
    {
        GXLoadTexObj(base, mapId);
    }
    if ((void*)texture->imageOffset != NULL)
    {
        textureInitSecondaryGXTexObj(texture, &sSecondaryTexObj);
        GXLoadTexObj(&sSecondaryTexObj, GX_TEXMAP1);
    }
}

void selectTexture(Texture* texture, int mapId)
{
    void* base;
    if (texture == NULL)
        return;
    base = texture->gxTexObj;
    if (texture->preloaded != 0)
    {
        GXLoadTexObjPreLoaded(base, (GXTexRegion*)texture->tmemAddr, mapId);
    }
    else
    {
        GXLoadTexObj(base, mapId);
    }
}
void addWarpedNoiseTevStages(void* p1, void* mtx)
{
    IndTexMtx23 m;
    f32 sx;
    f32 sy;
    f32 wave;
    int out_c;
    int out_8;
    int yhi;
    int ylo;
    int y;
    int x;
    int v1;
    u8* dst;
    int v2;
    int v3;
    m = sWarpedNoiseIndMtx;
    if (sWarpNoiseTexture == 0)
    {
        sWarpNoiseTexture = textureAlloc(0x20, 0x20, 4, 0, 0, 1, 1, 1, 1);
        for (y = 0; y < 0x20; y++)
        {
            x = 0;
            yhi = (y >> 2) * 0x20;
            ylo = (y & 3) * 2;
            for (; x < 0x20; x++)
            {
                v1 = (int)(sWarpNoiseTexture + ylo);
                v1 = (int)((u8*)v1 + yhi);
                v1 = v1 + (x & 3) * 8;
                dst = (u8*)v1 + (x >> 2) * 0x100;
                v1 = randomGetRange(0x80, 0xff);
                v2 = v1 - randomGetRange(0, 0x40);
                v3 = v1 - randomGetRange(0x40, 0x80);
                *(u16*)(dst + 0x60) = ((v1 & 0xf8) >> 3) | ((v2 & 0xf8) << 8 | (v3 & 0xfc) << 3);
            }
        }
        DCFlushRange(sWarpNoiseTexture + sizeof(Texture), ((Texture*)sWarpNoiseTexture)->dataSize);
    }
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    wave = mathSinf(3.142f * sx);
    m.m[0][1] = 0.25f * wave + 0.5f;
    wave = mathSinf(3.142f * sy);
    m.m[1][2] = 0.25f * wave + 0.5f;
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD0, gRcpNextTexMap + 1, GX_ALPHA_BUMPN);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (mtx != 0)
    {
        GXLoadTexMtxImm(mtx, gRcpNextPostTexMtx, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, gRcpNextPostTexMtx);
        gRcpNextPostTexMtx += 3;
    }
    else
    {
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    }
    GXSetIndTexMtx(GX_ITM_0, m.m, sWarpNoiseIndMtxScaleExp);
    GXSetIndTexOrder(gRcpNextIndTexStage, gRcpNextTexCoord, gRcpNextTexMap);
    GXSetTevIndirect(gRcpNextTevStage, gRcpNextIndTexStage, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_U);
    chooseTevKonstSelectors(sWarpNoiseBaseColor, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(gRcpNextTevStage, out_c);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_KONST, GX_CC_TEXC, GX_CC_RASA, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevOrder(gRcpNextTevStage + 1, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevDirect(gRcpNextTevStage + 1);
    GXSetTevColorIn(gRcpNextTevStage + 1, GX_CC_C0, GX_CC_CPREV, GX_CC_APREV, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    {
        int id = gRcpNextTexMap;
        if (p1 != 0)
        {
            void* obj = (char*)p1 + 0x20;
            if (((Texture*)p1)->preloaded != 0)
            {
                GXLoadTexObjPreLoaded((GXTexObj*)obj, (GXTexRegion*)((Texture*)p1)->tmemAddr, id);
            }
            else
            {
                GXLoadTexObj((GXTexObj*)obj, id);
            }
        }
    }
    {
        int id2 = gRcpNextTexMap + 1;
        Texture* tex = (Texture*)sWarpNoiseTexture;
        if (tex != 0)
        {
            void* obj = textureGetGXTexObj(tex);
            if (tex->preloaded != 0)
            {
                GXLoadTexObjPreLoaded((GXTexObj*)obj, textureGetGXTexRegion(tex), id2);
            }
            else
            {
                GXLoadTexObj((GXTexObj*)obj, id2);
            }
        }
    }
    gRcpNextTexCoordSource += 1;
    gRcpNextTexCoord += 1;
    gRcpNextTevStage += 2;
    gRcpNextTexMap += 2;
    gRcpNumTevStages += 2;
    gRcpNumTexGens += 1;
    gRcpNumIndStages += 1;
}
void addYUVVideoTevStages(void* tex0, void* tex1, void* tex2, s16 w, s16 h)
{
    u8 buf5c[0x20];
    u8 buf3c[0x20];
    u8 buf1c[0x20];
    GXColorS10 cs10;
    int h2;
    int w2;
    if (gRcpNumTevStages > 0xb || gRcpNumTexGens > 6 || gRcpNextTexMap > 5 || gRcpNextKColor > 1)
    {
        return;
    }
    {
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
        GXSetTexCoordGen2(gRcpNextTexCoord + 1, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord + 1, gRcpNextTexMap + 1, GX_COLOR_NULL);
        GXSetTevDirect(gRcpNextTevStage);
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C0);
        GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVREG1);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_A0);
        GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVREG1);
        GXSetTevKColorSel(gRcpNextTevStage, gRcpNextKColorSel);
        GXSetTevKAlphaSel(gRcpNextTevStage, gRcpNextKAlphaSel);
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevOrder(gRcpNextTevStage + 1, gRcpNextTexCoord + 1, gRcpNextTexMap + 2, GX_COLOR_NULL);
        GXSetTevDirect(gRcpNextTevStage + 1);
        GXSetTevColorIn(gRcpNextTevStage + 1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C1);
        GXSetTevColorOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_2, GX_FALSE, GX_TEVREG1);
        GXSetTevAlphaIn(gRcpNextTevStage + 1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_A1);
        GXSetTevAlphaOp(gRcpNextTevStage + 1, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVREG1);
        GXSetTevKColorSel(gRcpNextTevStage + 1, gRcpNextKColorSel + 1);
        GXSetTevKAlphaSel(gRcpNextTevStage + 1, gRcpNextKAlphaSel + 1);
        GXSetTevSwapMode(gRcpNextTevStage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevOrder(gRcpNextTevStage + 2, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
        GXSetTevDirect(gRcpNextTevStage + 2);
        GXSetTevColorIn(gRcpNextTevStage + 2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ONE, GX_CC_C1);
        GXSetTevColorOp(gRcpNextTevStage + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevAlphaIn(gRcpNextTevStage + 2, GX_CA_TEXA, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A1);
        GXSetTevAlphaOp(gRcpNextTevStage + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevSwapMode(gRcpNextTevStage + 2, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevOrder(gRcpNextTevStage + 3, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevDirect(gRcpNextTevStage + 3);
        GXSetTevColorIn(gRcpNextTevStage + 3, GX_CC_A1, GX_CC_C1, GX_CC_KONST, GX_CC_ZERO);
        GXSetTevColorOp(gRcpNextTevStage + 3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevAlphaIn(gRcpNextTevStage + 3, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        GXSetTevAlphaOp(gRcpNextTevStage + 3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevSwapMode(gRcpNextTevStage + 3, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevKColorSel(gRcpNextTevStage + 3, gRcpNextKColorSel + 2);
        GXSetTevOrder(gRcpNextTevStage + 4, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevDirect(gRcpNextTevStage + 4);
        GXSetTevColorIn(gRcpNextTevStage + 4, GX_CC_CPREV, GX_CC_C1, GX_CC_KONST, GX_CC_ZERO);
        GXSetTevColorOp(gRcpNextTevStage + 4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaIn(gRcpNextTevStage + 4, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevAlphaOp(gRcpNextTevStage + 4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevSwapMode(gRcpNextTevStage + 4, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevKColorSel(gRcpNextTevStage + 4, GX_TEV_KCSEL_1_4);
        gRcpTevPrevColorValid = 1;
        cs10 = kYuvTevColor0;
        GXSetTevColorS10(GX_TEVREG0, cs10);
        GXSetTevKColor(gRcpNextKColor, kYuvKColor0);
        GXSetTevKColor(gRcpNextKColor + 1, kYuvKColor1);
        GXSetTevKColor(gRcpNextKColor + 2, kYuvKColor2);
        GXInitTexObj((GXTexObj*)buf5c, tex0, w, h, GX_TF_I8, GX_CLAMP, GX_CLAMP, 0);
        GXInitTexObjLOD((GXTexObj*)buf5c, GX_NEAR, GX_NEAR, 0.0f, 0.0f, 0.0f, 0, 0, GX_ANISO_1);
        GXLoadTexObj((GXTexObj*)buf5c, gRcpNextTexMap);
        GXInitTexObj((GXTexObj*)buf3c, tex1, w2 = w >> 1, h2 = h >> 1, GX_TF_I8, GX_CLAMP, GX_CLAMP, 0);
        GXInitTexObjLOD((GXTexObj*)buf3c, GX_NEAR, GX_NEAR, 0.0f, 0.0f, 0.0f, 0, 0, GX_ANISO_1);
        GXLoadTexObj((GXTexObj*)buf3c, gRcpNextTexMap + 1);
        GXInitTexObj((GXTexObj*)buf1c, tex2, w2, h2, GX_TF_I8, GX_CLAMP, GX_CLAMP, 0);
        GXInitTexObjLOD((GXTexObj*)buf1c, GX_NEAR, GX_NEAR, 0.0f, 0.0f, 0.0f, 0, 0, GX_ANISO_1);
        GXLoadTexObj((GXTexObj*)buf1c, gRcpNextTexMap + 2);
        gRcpNextTevStage += 5;
        gRcpNextTexCoord += 2;
        gRcpNextTexMap += 3;
        gRcpNextKColor += 3;
        gRcpNextKColorSel += 3;
        gRcpNextKAlphaSel += 3;
        gRcpNumTevStages += 5;
        gRcpNumTexGens += 2;
    }
}
void setupCausticBaseTevStages(void* viewMtx)
{
    f32 mtx40[3][4];
    f32 mtx70[3][4];
    f32 sx;
    f32 sy;
    Texture* obj7c;
    Texture* obj80;

    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_TEXA, GX_CA_ZERO, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    mtx40[0][0] = 0.1f;
    mtx40[0][1] = 0.0f;
    mtx40[0][2] = 0.0f;
    mtx40[0][3] = 0.0f;
    mtx40[1][0] = 0.0f;
    mtx40[1][1] = 0.0f;
    mtx40[1][2] = 0.1f;
    mtx40[1][3] = 0.0f;
    GXLoadTexMtxImm(mtx40, GX_TEXMTX0, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
    newshadows_getCausticTexture((u32*)&obj7c);
    if (obj7c != NULL)
    {
        void* obj = obj7c->gxTexObj;
        if (obj7c->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, (GXTexRegion*)obj7c->tmemAddr, GX_TEXMAP2);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, GX_TEXMAP2);
        }
    }
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    PSMTXTrans(mtx70, 0.25f * sx, 0.25f * sy, 0.0f);
    mtx70[0][0] = 0.0125f;
    mtx70[1][1] = 0.0125f;
    GXLoadTexMtxImm(mtx70, GX_TEXMTX1, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX1, GX_FALSE, GX_PTIDENTITY);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD2, GX_TEXMAP2);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_1_2);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_APREV, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_SUB, GX_TB_ADDHALF, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    newshadows_getRampTexture((u32*)&obj80);
    if (obj80 != NULL)
    {
        void* obj = obj80->gxTexObj;
        if (obj80->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, (GXTexRegion*)obj80->tmemAddr, GX_TEXMAP3);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, GX_TEXMAP3);
        }
    }
    mtx40[0][0] = 0.0f;
    mtx40[0][1] = 0.0f;
    mtx40[0][2] = 0.033333335f;
    mtx40[0][3] = 8.333333f;
    mtx40[1][0] = 0.0f;
    mtx40[1][1] = 0.0f;
    mtx40[1][2] = 0.0f;
    mtx40[1][3] = 0.0f;
    PSMTXConcat(mtx40, viewMtx, mtx40);
    GXLoadTexMtxImm(mtx40, GX_TEXMTX2, GX_MTX2x4);
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_POS, GX_TEXMTX2, GX_FALSE, GX_PTIDENTITY);
    GXSetTevDirect(GX_TEVSTAGE2);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD3, GX_TEXMAP3, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_TEXA, GX_CA_APREV, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpNextTevStage = 3;
    gRcpNextTexCoord = 4;
    gRcpNextTexMap = 4;
    gRcpNextIndTexStage = 1;
    gRcpNextTexMtx = 0x27;
    gRcpNumTevStages = 3;
    gRcpNumTexGens = 4;
    gRcpNumIndStages = 1;
}
void addShadowFalloffTevStages(void)
{
    f32 mtx1[4][4];
    f32 mtx2[3][4];
    Texture* obj1;
    GameObject* player;
    Texture* obj2;
    int id;
    f32 dist;
    f32 tmp;
    f32 t;

    obj1 = (Texture*)newshadows_getFalloffTexture();
    C_MTXLightOrtho(mtx1, 25.0f, -25.0f, -25.0f, 25.0f, 0.5f, 0.5f, 0.5f, 0.5f);
    GXLoadTexMtxImm(mtx1, gRcpNextPostTexMtx, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx);
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP1, GX_TEV_SWAP1);
    if (gRcpNextTevStage == 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    }
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    gRcpTevPrevColorValid = 1;
    id = gRcpNextTexMap;
    if (obj1 != NULL)
    {
        void* obj = obj1->gxTexObj;
        if (obj1->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, (GXTexRegion*)obj1->tmemAddr, id);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, id);
        }
    }
    gRcpNextPostTexMtx += 3;
    gRcpNextTexCoord += 1;
    gRcpNextTevStage += 1;
    gRcpNextTexMap += 1;
    player = Obj_GetPlayerObject();
    if (player != NULL)
    {
        dist = Camera_DistanceToCurrentViewPosition(player->anim.worldPosX,
                                                    player->anim.worldPosY,
                                                    player->anim.worldPosZ);
    }
    else
    {
        dist = 100.0f;
    }
    tmp = dist - 10.0f;
    t = -(1.0f / (dist - tmp));
    mtx2[0][0] = 0.0f;
    mtx2[0][1] = 0.0f;
    mtx2[0][2] = t;
    mtx2[0][3] = t * tmp;
    mtx2[1][0] = 0.0f;
    mtx2[1][1] = 0.0f;
    mtx2[1][2] = 0.0f;
    mtx2[1][3] = 0.0f;
    mtx2[2][0] = 0.0f;
    mtx2[2][1] = 0.0f;
    mtx2[2][2] = 0.0f;
    mtx2[2][3] = 0.0f;
    GXLoadTexMtxImm(mtx2, gRcpNextPostTexMtx, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx);
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP1, GX_TEV_SWAP1);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevKAlphaSel(gRcpNextTevStage, GX_TEV_KASEL_1);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_A1, GX_CA_TEXA, GX_CA_KONST);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    obj2 = (Texture*)newshadows_getInverseRampTexture();
    id = gRcpNextTexMap;
    if (obj2 != NULL)
    {
        void* obj = obj2->gxTexObj;
        if (obj2->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, (GXTexRegion*)obj2->tmemAddr, id);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, id);
        }
    }
    gRcpNextPostTexMtx += 3;
    gRcpNextTexCoord += 1;
    gRcpNextTevStage += 1;
    gRcpNextTexMap += 1;
    gRcpTevPrevAlphaValid = 1;
    gRcpNumTevStages += 2;
    gRcpNumTexGens += 2;
}

void addRenderOpFadeStage(void* p1)
{
    u8 buf[3];
    u8 b = ((Shader*)p1)->alphaOverride;
    buf[2] = b;
    buf[1] = b;
    buf[0] = b;
    GXSetTevKColor(gRcpNextKColor, *(GXColor*)buf);
    GXSetTevKColorSel(gRcpNextTevStage, gRcpNextKColorSel);
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_CPREV, GX_CC_C0, GX_CC_KONST, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextKColor += 1;
    gRcpNextKColorSel += 1;
    gRcpNextKAlphaSel += 1;
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}



void addWavyCausticTevStage(void)
{
    struct piIndMtx indmtx;
    Texture* tex;
    int id;
    f32 v;
    indmtx = sWavyCausticIndMtx;
    v = 0.5f * newshadows_getDistortionWaveOffset();
    indmtx.m[0][0] = v;
    indmtx.m[1][2] = v;
    if (gRcpNextTexCoord > 0)
    {
        GXSetIndTexOrder(gRcpNextIndTexStage, gRcpNextTexCoord - 1, gRcpNextTexMap + 1);
    }
    else
    {
        GXSetIndTexOrder(gRcpNextIndTexStage, gRcpNextTexCoord, gRcpNextTexMap + 1);
    }
    GXSetIndTexCoordScale(gRcpNextIndTexStage, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_1, indmtx.m, -3);
    GXSetTevIndirect(gRcpNextTevStage, gRcpNextIndTexStage, GX_ITF_8, GX_ITB_ST, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    newshadows_getCausticTexture((u32*)&tex);
    id = gRcpNextTexMap + 1;
    if (tex != NULL)
    {
        GXTexObj* obj = (GXTexObj*)tex->gxTexObj;
        if (tex->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(obj, (GXTexRegion*)tex->tmemAddr, id);
        }
        else
        {
            GXLoadTexObj(obj, id);
        }
    }
    GXLoadTexMtxImm(gCameraLightPerspectiveFlipYMatrix, gRcpNextPostTexMtx, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    newshadows_loadReflectionColorTexture(gRcpNextTexMap);
    gRcpNextIndTexStage += 1;
    gRcpNextPostTexMtx += 3;
    gRcpNextTexCoord += 1;
    gRcpNextTevStage += 1;
    gRcpNextTexMap += 2;
    gRcpNumTevStages++;
    gRcpNumTexGens++;
    gRcpNumIndStages++;
}





void addSmallReflectionTevStage(void)
{
    newshadows_loadSmallReflectionTexture(gRcpNextTexMap);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_TEXMTX2, GX_FALSE, GX_PTIDENTITY);
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevKColorSel(gRcpNextTevStage, GX_TEV_KCSEL_1_4);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextTexCoord++;
    gRcpNextTevStage++;
    gRcpNextTexMap++;
    gRcpNextTexMtx = 0x27;
    gRcpNumTevStages++;
    gRcpNumTexGens++;
}

void setupHeatShimmerTevStages(char* p1)
{
    f32 mtxf4[3][4];
    f32 mtxc4[3][4];
    f32 mtx94[3][4];
    f32 mtx64[3][4];
    IndTexMtx23 m1;
    IndTexMtx23 m2;
    Texture* tex30;
    Texture* tex2c;
    f32 rx;
    f32 ry;
    f32 cv;
    f32 sv;
    f32 tsx;
    f32 tsy;
    f32 f31v;
    f32 c;
    f32 k;
    f32 t;
    Texture* tex24;
    m1 = sHeatShimmerIndMtx1;
    m2 = sHeatShimmerIndMtx2[0];
    tex24 = ((Shader*)p1)->layers[0].texture;
    if (tex24 != 0)
    {
        void* obj = textureGetGXTexObj(tex24);
        if (tex24->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, textureGetGXTexRegion(tex24), GX_TEXMAP2);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, GX_TEXMAP2);
        }
    }
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    newshadows_getReflectionScrollOffsets(&rx, &ry);
    mathSinCosf(3.142f * rx, &sv, &cv);
    c = mathCosf(3.142f * ry);
    k = 0.125f * c + 0.75f;
    k *= gHeatEffectScale;
    cv *= k;
    sv *= k;
    m1.m[0][0] = cv;
    m1.m[0][1] = sv;
    m1.m[1][0] = -sv;
    m1.m[1][1] = cv;
    mathSinCosf(3.142f * -ry, &sv, &cv);
    c = mathCosf(3.142f * rx);
    f31v = 0.5f * c + 0.5f;
    k = 0.125f * c + 0.75f;
    k *= gHeatEffectScale;
    cv *= k;
    sv *= k;
    m2.m[0][0] = cv;
    m2.m[0][1] = sv;
    m2.m[1][0] = -sv;
    m2.m[1][1] = cv;
    newshadows_getHeatHazeTexture(&tex2c);
    if (tex2c != 0)
    {
        GXTexObj* obj = textureGetGXTexObj(tex2c);
        if (tex2c->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(tex2c), GX_TEXMAP0);
        }
        else
        {
            GXLoadTexObj(obj, GX_TEXMAP0);
        }
    }
    {
        u8 b = ((Shader*)p1)->layers[0].scrollMtx;
        if (b != 0xff)
        {
            mapTextureScrollGetOffset(b, &tsx, &tsy);
            PSMTXTrans(mtx64, tsx, tsy, 0.0f);
        }
        else
        {
            PSMTXIdentity(mtx64);
        }
    }
    GXLoadTexMtxImm(mtx64, GX_PTTEXMTX2, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX2);
    newshadows_getCausticTexture((u32*)&tex30);
    if (tex30 != 0)
    {
        void* obj = textureGetGXTexObj(tex30);
        if (tex30->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, textureGetGXTexRegion(tex30), GX_TEXMAP1);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, GX_TEXMAP1);
        }
    }
    PSMTXScale(mtxf4, 0.9f, 0.9f, 1.0f);
    mtxf4[1][3] = 0.125f * ry;
    GXLoadTexMtxImm(mtxf4, GX_PTTEXMTX0, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX0);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, m1.m, -2);
    GXSetIndTexMtx(GX_ITM_1, m2.m, -2);
    GXSetTevIndirect(GX_TEVSTAGE1, GX_INDTEXSTAGE0, GX_ITF_8, GX_ITB_STU, GX_ITM_0, GX_ITW_0, GX_ITW_0, 0, 0, GX_ITBA_OFF);
    PSMTXScale(mtxc4, 1.2f, 1.2f, 1.0f);
    PSMTXRotRad(mtx94, 0x7a, 0.7853982f);
    PSMTXConcat(mtx94, mtxc4, mtxc4);
    t = 0.0625f * rx;
    mtxc4[0][3] = t;
    mtxc4[1][3] = t;
    GXLoadTexMtxImm(mtxc4, GX_PTTEXMTX1, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX3x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX1);
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD2, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
    GXSetTevIndirect(GX_TEVSTAGE2, GX_INDTEXSTAGE1, GX_ITF_8, GX_ITB_STU, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_OFF);
    gHeatEffectColor.r = 64.0f * f31v;
    gHeatEffectColor.g = 0;
    gHeatEffectColor.b = 0;
    GXSetTevKColor(gRcpNextKColor, gHeatEffectColor);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, gRcpNextKAlphaSel);
    GXSetTevKColorSel(GX_TEVSTAGE1, gRcpNextKColorSel);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_RED, GX_CH_GREEN, GX_CH_BLUE, GX_CH_RED);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP2, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_KONST, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP3);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_KONST, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevOrder(GX_TEVSTAGE2, GX_TEXCOORD3, GX_TEXMAP0, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE2, GX_CC_CPREV, GX_CC_TEXC, GX_CC_APREV, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpNextTexCoord = 4;
    gRcpNextTevStage = 3;
    gRcpNextTexMap = 3;
    gRcpNextPostTexMtx = 0x49;
    gRcpNextIndTexStage = 2;
    gRcpNumTevStages = 3;
    gRcpNumTexGens = 4;
    gRcpNumIndStages = 2;
    gRcpNextKColor = 1;
    gRcpNextKColorSel = 0xd;
    gRcpNextKAlphaSel = 0x1d;
}



void addWarpedRingTevStages(void)
{
    f32 m1e8[3][4];
    f32 m1b8[3][4];
    f32 m188[3][4];
    f32 m158[3][4];
    f32 m128[3][4];
    f32 mf8[3][4];
    f32 mc8[3][4];
    f32 m98[3][4];
    f32 m68[3][4];
    IndTexMtx23 im;
    Vec va;
    Vec vb;
    Vec vc;
    Vec vd;
    Texture* tex1c;
    Texture* tex18;
    f32 rx;
    f32 ry;
    void* invView;
    va = ((Vec*)&sEnvMapBumpIndMtx)[4];
    vb = ((Vec*)&sEnvMapBumpIndMtx)[5];
    vc = ((Vec*)&sEnvMapBumpIndMtx)[6];
    vd = ((Vec*)&sEnvMapBumpIndMtx)[7];
    im = *(IndTexMtx23*)((Vec*)&sEnvMapBumpIndMtx + 8);
    invView = Camera_GetInverseViewMatrix();
    PSMTXRotAxisRad(mf8, &va, 1.0f);
    PSMTXRotAxisRad(mc8, &vb, 1.0f);
    PSMTXRotAxisRad(m98, &vc, 1.0f);
    PSMTXRotAxisRad(m68, &vd, 1.0f);
    m1e8[0][0] = 0.008f;
    m1e8[0][1] = 0.0f;
    m1e8[0][2] = 0.0f;
    m1e8[0][3] = 0.8f * (0.01f * playerMapOffsetX);
    m1e8[1][0] = 0.0f;
    m1e8[1][1] = 0.008f;
    m1e8[1][2] = 0.0f;
    m1e8[1][3] = 0.0f;
    m1e8[2][0] = 0.0f;
    m1e8[2][1] = 0.0f;
    m1e8[2][2] = 0.008f;
    m1e8[2][3] = 0.8f * (0.01f * playerMapOffsetZ);
    m1b8[0][0] = 0.005f;
    m1b8[0][1] = 0.0f;
    m1b8[0][2] = 0.0f;
    m1b8[0][3] = 0.5f * (0.01f * playerMapOffsetX);
    m1b8[1][0] = 0.0f;
    m1b8[1][1] = 0.005f;
    m1b8[1][2] = 0.0f;
    m1b8[1][3] = 0.0f;
    m1b8[2][0] = 0.0f;
    m1b8[2][1] = 0.0f;
    m1b8[2][2] = 0.005f;
    m1b8[2][3] = 0.5f * (0.01f * playerMapOffsetZ);
    PSMTXConcat(m1e8, invView, m1e8);
    PSMTXConcat(mf8, m1e8, m1e8);
    m1e8[2][0] = 0.0f;
    m1e8[2][1] = 0.0f;
    m1e8[2][2] = 0.0f;
    m1e8[2][3] = 1.0f;
    PSMTXConcat(m1b8, invView, m1b8);
    PSMTXConcat(mc8, m1b8, m1b8);
    m1b8[2][0] = 0.0f;
    m1b8[2][1] = 0.0f;
    m1b8[2][2] = 0.0f;
    m1b8[2][3] = 1.0f;
    GXLoadTexMtxImm(m1e8, gRcpNextPostTexMtx, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx);
    GXLoadTexMtxImm(m1b8, gRcpNextPostTexMtx + 3, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord + 1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx + 3);
    newshadows_getRingTexture(&tex1c);
    {
        int id = gRcpNextTexMap;
        if (tex1c != 0)
        {
            GXTexObj* obj = textureGetGXTexObj(tex1c);
            if (tex1c->preloaded != 0)
            {
                GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(tex1c), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
    }
    newshadows_getReflectionScrollOffsets(&rx, &ry);
    GXSetIndTexMtx(GX_ITM_1, im.m, -1);
    GXSetIndTexOrder(gRcpNextIndTexStage, gRcpNextTexCoord + 2, gRcpNextTexMap + 1);
    m188[0][0] = 0.01f;
    m188[0][1] = 0.0f;
    m188[0][2] = 0.0f;
    m188[0][3] = 0.01f * playerMapOffsetX + rx;
    m188[1][0] = 0.0f;
    m188[1][1] = 0.01f;
    m188[1][2] = 0.0f;
    m188[1][3] = 0.0f;
    m188[2][0] = 0.0f;
    m188[2][1] = 0.0f;
    m188[2][2] = 0.01f;
    m188[2][3] = 0.01f * playerMapOffsetZ;
    PSMTXRotRad(m128, 0x79, 1.1693705f);
    PSMTXConcat(m128, m188, m188);
    PSMTXConcat(m188, invView, m188);
    PSMTXConcat(m98, m188, m188);
    m188[2][0] = 0.0f;
    m188[2][1] = 0.0f;
    m188[2][2] = 0.0f;
    m188[2][3] = 1.0f;
    GXLoadTexMtxImm(m188, gRcpNextPostTexMtx + 6, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord + 2, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx + 6);
    GXSetTevIndirect(gRcpNextTevStage, gRcpNextIndTexStage, GX_ITF_8, GX_ITB_T, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 0, 0, GX_ITBA_OFF);
    GXSetIndTexCoordScale(gRcpNextIndTexStage, GX_ITS_1, GX_ITS_1);
    GXSetIndTexOrder(gRcpNextIndTexStage + 1, gRcpNextTexCoord + 3, gRcpNextTexMap + 1);
    m158[0][0] = 0.01f;
    m158[0][1] = 0.0f;
    m158[0][2] = 0.0f;
    m158[0][3] = 0.01f * playerMapOffsetX;
    m158[1][0] = 0.0f;
    m158[1][1] = 0.01f;
    m158[1][2] = 0.0f;
    m158[1][3] = 0.0f;
    m158[2][0] = 0.0f;
    m158[2][1] = 0.0f;
    m158[2][2] = 0.01f;
    m158[2][3] = 0.01f * playerMapOffsetZ + ry;
    PSMTXConcat(m158, invView, m158);
    PSMTXConcat(m68, m158, m158);
    m158[2][0] = 0.0f;
    m158[2][1] = 0.0f;
    m158[2][2] = 0.0f;
    m158[2][3] = 1.0f;
    GXLoadTexMtxImm(m158, gRcpNextPostTexMtx + 9, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord + 3, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx + 9);
    GXSetTevIndirect(gRcpNextTevStage + 1, gRcpNextIndTexStage + 1, GX_ITF_8, GX_ITB_T, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_OFF);
    GXSetIndTexCoordScale(gRcpNextIndTexStage + 1, GX_ITS_1, GX_ITS_1);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR0A0);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXA, GX_CC_CPREV);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    GXSetTevOrder(gRcpNextTevStage + 1, gRcpNextTexCoord + 1, gRcpNextTexMap, GX_COLOR0A0);
    GXSetTevColorIn(gRcpNextTevStage + 1, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXA, GX_CC_CPREV);
    GXSetTevAlphaIn(gRcpNextTevStage + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    newshadows_getCausticTexture((u32*)&tex18);
    {
        int id2 = gRcpNextTexMap + 1;
        if (tex18 != 0)
        {
            void* obj = textureGetGXTexObj(tex18);
            if (tex18->preloaded != 0)
            {
                GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(tex18), id2);
            }
            else
            {
                GXLoadTexObj(obj, id2);
            }
        }
    }
    gRcpNextTexCoord += 4;
    gRcpNextTevStage += 2;
    gRcpNextTexMap += 2;
    gRcpNextPostTexMtx += 0xc;
    gRcpNextIndTexStage += 2;
    gRcpNumTevStages += 2;
    gRcpNumTexGens += 4;
    gRcpNumIndStages += 2;
}


void renderHeavyFog(void* fogColor)
{
    f32 mcc[3][4];
    f32 m9c[3][4];
    f32 m6c[3][4];
    f32 mrot[3][4];
    IndTexMtx23 im;
    Texture* tex20;
    Texture* tex1c;
    f32 a;
    f32 b;
    f32(*iv)[4];
    f32 k;
    im = sHeavyFogIndMtx;
    iv = (f32(*)[4])Camera_GetInverseViewMatrix();
    mcc[0][0] = 0.0f;
    mcc[0][1] = 0.0f;
    mcc[0][2] = -1.0f / gHeavyFogDepthScale;
    mcc[0][3] = gHeavyFogDepthOffset;
    k = -1.0f / (gHeavyFogTop - gHeavyFogBottom);
    mcc[1][0] = k * iv[1][0];
    mcc[1][1] = k * iv[1][1];
    mcc[1][2] = k * iv[1][2];
    mcc[1][3] = k * iv[1][3] + -gHeavyFogTop * k;
    mcc[2][0] = 0.0f;
    mcc[2][1] = 0.0f;
    mcc[2][2] = 0.0f;
    mcc[2][3] = 1.0f;
    GXLoadTexMtxImm(mcc, gRcpNextPostTexMtx, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx);
    GXSetTevKColor(gRcpNextKColor, *(GXColor*)fogColor);
    newshadows_getHeavyFogTexture(&tex20);
    {
        int id = gRcpNextTexMap;
        if (tex20 != 0)
        {
            GXTexObj* obj = textureGetGXTexObj(tex20);
            if (tex20->preloaded != 0)
            {
                GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(tex20), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
    }
    if (gHeavyFogMode != 0)
    {
        newshadows_getReflectionScrollOffsets(&a, &b);
        b *= 0.25f;
        a *= 0.125f;
        GXSetIndTexMtx(GX_ITM_1, im.m, -2);
        GXSetIndTexOrder(gRcpNextIndTexStage, gRcpNextTexCoord + 1, gRcpNextTexMap + 1);
        m9c[0][0] = gHeavyFogWorldScale;
        m9c[0][1] = 0.0f;
        m9c[0][2] = 0.0f;
        m9c[0][3] = playerMapOffsetX * gHeavyFogWorldScale + a;
        m9c[1][0] = 0.0f;
        m9c[1][1] = gHeavyFogWorldScale;
        m9c[1][2] = 0.0f;
        m9c[1][3] = 0.0f;
        m9c[2][0] = 0.0f;
        m9c[2][1] = 0.0f;
        m9c[2][2] = 0.0f;
        m9c[2][3] = 1.0f;
        PSMTXRotRad(mrot, 0x7a, 1.1693705f);
        PSMTXConcat(mrot, m9c, m9c);
        PSMTXConcat(m9c, iv, m9c);
        GXLoadTexMtxImm(m9c, gRcpNextPostTexMtx + 3, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord + 1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx + 3);
        GXSetTevIndirect(gRcpNextTevStage, gRcpNextIndTexStage, GX_ITF_8, GX_ITB_T, GX_ITM_1, GX_ITW_0, GX_ITW_0, 0, 0, GX_ITBA_OFF);
        GXSetIndTexCoordScale(gRcpNextIndTexStage, GX_ITS_1, GX_ITS_1);
        GXSetIndTexOrder(gRcpNextIndTexStage + 1, gRcpNextTexCoord + 2, gRcpNextTexMap + 1);
        m6c[0][0] = 0.0f;
        m6c[0][1] = 0.0f;
        m6c[0][2] = gHeavyFogWorldScale;
        m6c[0][3] = playerMapOffsetZ * gHeavyFogWorldScale + b;
        m6c[1][0] = 0.0f;
        m6c[1][1] = gHeavyFogWorldScale;
        m6c[1][2] = 0.0f;
        m6c[1][3] = 0.0f;
        m6c[2][0] = 0.0f;
        m6c[2][1] = 0.0f;
        m6c[2][2] = 0.0f;
        m6c[2][3] = 1.0f;
        PSMTXRotRad(mrot, 0x78, 0.38397244f);
        PSMTXConcat(mrot, m6c, m6c);
        PSMTXConcat(m6c, iv, m6c);
        GXLoadTexMtxImm(m6c, gRcpNextPostTexMtx + 6, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord + 2, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx + 6);
        GXSetTevIndirect(gRcpNextTevStage + 1, gRcpNextIndTexStage + 1, GX_ITF_8, GX_ITB_T, GX_ITM_1, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_OFF);
        GXSetIndTexCoordScale(gRcpNextIndTexStage + 1, GX_ITS_1, GX_ITS_1);
        GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        gRcpTevPrevColorValid = 1;
        GXSetTevOrder(gRcpNextTevStage + 1, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
        GXSetTevColorIn(gRcpNextTevStage + 1, GX_CC_CPREV, GX_CC_KONST, GX_CC_TEXA, GX_CC_ZERO);
        GXSetTevAlphaIn(gRcpNextTevStage + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(gRcpNextTevStage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        newshadows_getCausticTexture((u32*)&tex1c);
        {
            int id2 = gRcpNextTexMap + 1;
            if (tex1c != 0)
            {
                void* obj = textureGetGXTexObj(tex1c);
                if (tex1c->preloaded != 0)
                {
                    GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(tex1c), id2);
                }
                else
                {
                    GXLoadTexObj(obj, id2);
                }
            }
        }
        GXSetTevKColorSel(gRcpNextTevStage + 1, gRcpNextKColorSel);
        gRcpNextTexCoord += 3;
        gRcpNextTevStage += 2;
        gRcpNextTexMap += 2;
        gRcpNextPostTexMtx += 9;
        gRcpNextIndTexStage += 2;
        gRcpNumTevStages += 2;
        gRcpNumTexGens += 3;
        gRcpNumIndStages += 2;
    }
    else
    {
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_CPREV, GX_CC_KONST, GX_CC_TEXA, GX_CC_ZERO);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevDirect(gRcpNextTevStage);
        GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        gRcpTevPrevColorValid = 1;
        GXSetTevKColorSel(gRcpNextTevStage, gRcpNextKColorSel);
        gRcpNextTexCoord += 1;
        gRcpNextTevStage += 1;
        gRcpNextTexMap += 1;
        gRcpNextPostTexMtx += 3;
        gRcpNumTevStages += 1;
        gRcpNumTexGens += 1;
    }
    gRcpNextKColor += 1;
    gRcpNextKColorSel += 1;
    gRcpNextKAlphaSel += 1;
}
void addVertexAlphaDimStage(u8* color)
{
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_CPREV, GX_CC_ZERO, GX_CC_RASA, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}


void addLightColorModulateStage(int* param)
{
    GXSetTevColor(GX_TEVREG1, *(GXColor*)param);
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}

void addAccumulatedLightBlendStages(void)
{
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevDirect(gRcpNextTevStage + 1);
    GXSetTevOrder(gRcpNextTevStage + 1, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(gRcpNextTevStage + 1, GX_CC_C1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(gRcpNextTevStage + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevDirect(gRcpNextTevStage + 2);
    GXSetTevOrder(gRcpNextTevStage + 2, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevColorIn(gRcpNextTevStage + 2, GX_CC_CPREV, GX_CC_C2, GX_CC_RASA, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage + 2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage + 2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextTevStage += 3;
    gRcpNumTevStages += 3;
}

void addAccumulatedLightModulateStage(void)
{
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}
int lbl_8030CEE0[9] = {
    0, 1, 2, 3, 4, 5, 6, 7, 8,
};



void addPointLightAccumStages(f32 scale, int* colorIn, f32* pos)
{
    f32 matA[3][4];
    f32 matB[3][4];
    Texture* src;
    int id;
    f32 f;
    if (!(gRcpNextKColor <= 3) || gRcpNumTevStages >= 0xc || gRcpNumTexGens >= 7)
    {
        return;
    }
    {
        f = 0.5f / scale;
        matA[0][0] = f;
        matA[0][1] = 0.0f;
        matA[0][2] = 0.0f;
        matA[0][3] = -pos[0] * f + 0.5f;
        matA[1][0] = 0.0f;
        matA[1][1] = 0.0f;
        matA[1][2] = f;
        matA[1][3] = -pos[2] * f + 0.5f;
        matA[2][0] = 0.0f;
        matA[2][1] = 0.0f;
        matA[2][2] = 0.0f;
        matA[2][3] = 1.0f;
        matB[0][0] = 0.0f;
        matB[0][1] = f;
        matB[0][2] = 0.0f;
        matB[0][3] = -pos[1] * f + 0.5f;
        matB[1][0] = 0.0f;
        matB[1][1] = 0.0f;
        matB[1][2] = 0.0f;
        matB[1][3] = 0.5f;
        matB[2][0] = 0.0f;
        matB[2][1] = 0.0f;
        matB[2][2] = 0.0f;
        matB[2][3] = 1.0f;
        newshadows_getRadialTexture(&src);
        GXLoadTexMtxImm(matA, gRcpNextPostTexMtx, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx);
        GXLoadTexMtxImm(matB, gRcpNextPostTexMtx + 3, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord + 1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx + 3);
        GXSetTevDirect(gRcpNextTevStage);
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
        GXSetTevKColor(gRcpNextKColor, *(GXColor*)colorIn);
        GXSetTevKColorSel(gRcpNextTevStage, gRcpNextKColorSel);
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_KONST, GX_CC_TEXC, GX_CC_ZERO);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
        GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevDirect(gRcpNextTevStage + 1);
        GXSetTevOrder(gRcpNextTevStage + 1, gRcpNextTexCoord + 1, gRcpNextTexMap, GX_COLOR_NULL);
        GXSetTevColorIn(gRcpNextTevStage + 1, GX_CC_ZERO, GX_CC_C0, GX_CC_TEXC, GX_CC_C1);
        GXSetTevAlphaIn(gRcpNextTevStage + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(gRcpNextTevStage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevAlphaOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        id = gRcpNextTexMap;
        if (src != NULL)
        {
            GXTexObj* obj = textureGetGXTexObj(src);
            if (src->preloaded != 0)
            {
                GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(src), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
        gRcpNextTevStage += 2;
        gRcpNextTexCoord += 2;
        gRcpNextTexMap += 1;
        gRcpNextKColor += 1;
        gRcpNextKColorSel += 1;
        gRcpNextKAlphaSel += 1;
        gRcpNextPostTexMtx += 6;
        gRcpNumTexGens += 2;
        gRcpNumTevStages += 2;
    }
}

void addFirstPointLightStages(f32 scale, int* colorIn, f32* pos, u8* chanColor)
{
    f32 matA[3][4];
    f32 matB[3][4];
    Texture* src;
    int id;
    f32 f;
    if (!(gRcpNextKColor <= 3) || gRcpNumTevStages >= 0xc || gRcpNumTexGens >= 7)
    {
        return;
    }
    {
        f = 0.5f / scale;
        matA[0][0] = f;
        matA[0][1] = 0.0f;
        matA[0][2] = 0.0f;
        matA[0][3] = -pos[0] * f + 0.5f;
        matA[1][0] = 0.0f;
        matA[1][1] = 0.0f;
        matA[1][2] = f;
        matA[1][3] = -pos[2] * f + 0.5f;
        matA[2][0] = 0.0f;
        matA[2][1] = 0.0f;
        matA[2][2] = 0.0f;
        matA[2][3] = 1.0f;
        matB[0][0] = 0.0f;
        matB[0][1] = f;
        matB[0][2] = 0.0f;
        matB[0][3] = -pos[1] * f + 0.5f;
        matB[1][0] = 0.0f;
        matB[1][1] = 0.0f;
        matB[1][2] = 0.0f;
        matB[1][3] = 0.5f;
        matB[2][0] = 0.0f;
        matB[2][1] = 0.0f;
        matB[2][2] = 0.0f;
        matB[2][3] = 1.0f;
        newshadows_getRadialTexture(&src);
        GXLoadTexMtxImm(matA, gRcpNextPostTexMtx, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx);
        GXLoadTexMtxImm(matB, gRcpNextPostTexMtx + 3, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord + 1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx + 3);
        GXSetTevDirect(gRcpNextTevStage);
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
        GXSetTevKColor(gRcpNextKColor, *(GXColor*)colorIn);
        GXSetTevKColorSel(gRcpNextTevStage, gRcpNextKColorSel);
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_KONST, GX_CC_TEXC, GX_CC_ZERO);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
        GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevDirect(gRcpNextTevStage + 1);
        GXSetTevOrder(gRcpNextTevStage + 1, gRcpNextTexCoord + 1, gRcpNextTexMap, GX_COLOR_NULL);
        GXSetTevColorIn(gRcpNextTevStage + 1, GX_CC_ZERO, GX_CC_C0, GX_CC_TEXC, GX_CC_ZERO);
        GXSetTevAlphaIn(gRcpNextTevStage + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(gRcpNextTevStage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevAlphaOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        id = gRcpNextTexMap;
        if (src != NULL)
        {
            GXTexObj* obj = textureGetGXTexObj(src);
            if (src->preloaded != 0)
            {
                GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(src), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
        gRcpNextTevStage += 2;
        gRcpNextTexCoord += 2;
        gRcpNextTexMap += 1;
        gRcpNextKColor += 1;
        gRcpNextKColorSel += 1;
        gRcpNextKAlphaSel += 1;
        gRcpNextPostTexMtx += 6;
        gRcpNumTexGens += 2;
        gRcpNumTevStages += 2;
    }
}


void addPointLightDirectStages(f32 scale, int* colorIn, f32* pos)
{
    f32 matA[3][4];
    f32 matB[3][4];
    Texture* src;
    int id;
    f32 f;
    if (!(gRcpNextKColor <= 3) || gRcpNumTevStages >= 0x10 || gRcpNumTexGens >= 7)
    {
        return;
    }
    {
        if (scale < 0.1f)
        {
            scale = 0.1f;
        }
        f = 0.5f / scale;
        matA[0][0] = f;
        matA[0][1] = 0.0f;
        matA[0][2] = 0.0f;
        matA[0][3] = -pos[0] * f + 0.5f;
        matA[1][0] = 0.0f;
        matA[1][1] = 0.0f;
        matA[1][2] = f;
        matA[1][3] = -pos[2] * f + 0.5f;
        matA[2][0] = 0.0f;
        matA[2][1] = 0.0f;
        matA[2][2] = 0.0f;
        matA[2][3] = 1.0f;
        matB[0][0] = 0.0f;
        matB[0][1] = f;
        matB[0][2] = 0.0f;
        matB[0][3] = -pos[1] * f + 0.5f;
        matB[1][0] = 0.0f;
        matB[1][1] = 0.0f;
        matB[1][2] = 0.0f;
        matB[1][3] = 0.5f;
        matB[2][0] = 0.0f;
        matB[2][1] = 0.0f;
        matB[2][2] = 0.0f;
        matB[2][3] = 1.0f;
        newshadows_getRadialTexture(&src);
        GXLoadTexMtxImm(matA, gRcpNextPostTexMtx, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx);
        GXLoadTexMtxImm(matB, gRcpNextPostTexMtx + 3, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord + 1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx + 3);
        GXSetTevDirect(gRcpNextTevStage);
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
        GXSetTevKColor(gRcpNextKColor, *(GXColor*)colorIn);
        GXSetTevKColorSel(gRcpNextTevStage, gRcpNextKColorSel);
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_KONST, GX_CC_TEXC, GX_CC_ZERO);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
        GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevDirect(gRcpNextTevStage + 1);
        GXSetTevOrder(gRcpNextTevStage + 1, gRcpNextTexCoord + 1, gRcpNextTexMap, GX_COLOR_NULL);
        GXSetTevColorIn(gRcpNextTevStage + 1, GX_CC_ZERO, GX_CC_C0, GX_CC_TEXC, GX_CC_CPREV);
        GXSetTevAlphaIn(gRcpNextTevStage + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(gRcpNextTevStage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        gRcpTevPrevColorValid = 1;
        id = gRcpNextTexMap;
        if (src != NULL)
        {
            GXTexObj* obj = textureGetGXTexObj(src);
            if (src->preloaded != 0)
            {
                GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(src), id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
        gRcpNextTevStage += 2;
        gRcpNextTexCoord += 2;
        gRcpNextTexMap += 1;
        gRcpNextKColor += 1;
        gRcpNextKColorSel += 1;
        gRcpNextKAlphaSel += 1;
        gRcpNextPostTexMtx += 6;
        gRcpNumTexGens += 2;
        gRcpNumTevStages += 2;
    }
}

void addSignedOverlayTexStage(u8* texSrc, void* texMtx, u8* color)
{
    GXSetTevDirect(gRcpNextTevStage);
    GXLoadTexMtxImm(texMtx, gRcpNextPostTexMtx, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
    GXSetTevKColorSel(gRcpNextTevStage, GX_TEV_KCSEL_1_2);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_KONST, GX_CC_TEXA, GX_CC_CPREV, GX_CC_CPREV);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_SUB, GX_TB_ADDHALF, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    {
        int id = gRcpNextTexMap;
        if (texSrc != NULL)
        {
            GXTexObj* obj = (GXTexObj*)((Texture*)texSrc)->gxTexObj;
            if (((Texture*)texSrc)->preloaded != 0)
            {
                GXLoadTexObjPreLoaded(obj, (GXTexRegion*)((Texture*)texSrc)->tmemAddr, id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
    }
    gRcpNextTexCoord++;
    gRcpNextTevStage++;
    gRcpNextTexMap++;
    gRcpNextPostTexMtx += 3;
    gRcpNumTevStages++;
    gRcpNumTexGens++;
}

void addSphereMapLitStages(void* p1, f32* wpad0, void* wpad1, int wpad2)
{
    if (p1 != 0)
    {
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
        GXSetTevDirect(gRcpNextTevStage);
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR0A0);
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_RASC, GX_CC_RASA, GX_CC_TEXC);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        gRcpTevPrevColorValid = 1;
        {
            int id = gRcpNextTexMap;
            if (p1 != 0)
            {
                char* tex = (char*)p1 + 0x20;
                if (((Texture*)p1)->preloaded != 0)
                {
                    GXLoadTexObjPreLoaded((GXTexObj*)tex, (GXTexRegion*)((Texture*)p1)->tmemAddr, id);
                }
                else
                {
                    GXLoadTexObj((GXTexObj*)tex, id);
                }
            }
        }
        gRcpNextTexCoord += 1;
        gRcpNextTevStage += 1;
        gRcpNextTexMap += 1;
        gRcpNumTexGens += 1;
        gRcpNumTevStages += 1;
        GXSetTevDirect(gRcpNextTevStage);
        GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR1A1);
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_RASC, GX_CC_RASA, GX_CC_CPREV);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        gRcpNextTevStage += 1;
        gRcpNumTevStages += 1;
    }
}

void addCastShadowTevStages(u8* objInst)
{
    Texture* src;
    f32 mtx[3][4];
    Texture* obj2;
    int id;
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevDirect(gRcpNextTevStage + 1);
    GXSetTevDirect(gRcpNextTevStage + 2);
    GXSetTevDirect(gRcpNextTevStage + 3);
    PSMTXConcat((f32(*)[4])(objInst + 0x30), (f32(*)[4])Camera_GetInverseViewMatrix(), mtx);
    GXLoadTexMtxImm(mtx, gRcpNextPostTexMtx, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_IDENTITY, GX_FALSE, gRcpNextPostTexMtx);
    PSMTXConcat((f32(*)[4])objInst, (f32(*)[4])Camera_GetInverseViewMatrix(), mtx);
    GXLoadTexMtxImm(mtx, gRcpNextPostTexMtx + 3, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord + 1, GX_TG_MTX3x4, GX_TG_POS, GX_IDENTITY, GX_FALSE, gRcpNextPostTexMtx + 3);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
    GXSetTevOrder(gRcpNextTevStage + 1, gRcpNextTexCoord + 1, gRcpNextTexMap + 1, GX_COLOR_NULL);
    GXSetTevOrder(gRcpNextTevStage + 2, gRcpNextTexCoord + 1, gRcpNextTexMap + 1, GX_COLOR_NULL);
    GXSetTevOrder(gRcpNextTevStage + 3, gRcpNextTexCoord + 1, gRcpNextTexMap + 1, GX_COLOR_NULL);
    GXSetTevKColorSel(gRcpNextTevStage + 2, GX_TEV_KCSEL_1_4);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevColorIn(gRcpNextTevStage + 1, GX_CC_C0, GX_CC_TEXC, GX_CC_ONE, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage + 1, GX_TEV_COMP_R8_GT, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevColorIn(gRcpNextTevStage + 2, GX_CC_C1, GX_CC_KONST, GX_CC_C0, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage + 2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage + 2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(gRcpNextTevStage + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevColorIn(gRcpNextTevStage + 3, GX_CC_C2, GX_CC_ZERO, GX_CC_C0, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage + 3, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(gRcpNextTevStage + 3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(gRcpNextTevStage + 3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
    GXSetTevAlphaOp(gRcpNextTevStage + 3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    newshadows_getRampTexture((u32*)&src);
    id = gRcpNextTexMap;
    if (src != NULL)
    {
        void* obj = src->gxTexObj;
        if (src->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, (GXTexRegion*)src->tmemAddr, id);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, id);
        }
    }
    id = gRcpNextTexMap + 1;
    obj2 = *(Texture**)(objInst + 0x60);
    if (obj2 != NULL)
    {
        void* obj = obj2->gxTexObj;
        if (obj2->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, (GXTexRegion*)obj2->tmemAddr, id);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, id);
        }
    }
    gRcpNextPostTexMtx += 6;
    gRcpNextTexCoord += 2;
    gRcpNextTexMap += 2;
    gRcpNumTexGens += 2;
    gRcpNumTevStages += 4;
    gRcpNextTevStage += 4;
}


void addProjectedLightTevStage(u8* texSrc, void* texMtx, int stageMode, int compMode, int variant)
{
    int inputSel;
    int texmap;
    GXSetTevDirect(gRcpNextTevStage);
    GXLoadTexMtxImm(texMtx, gRcpNextPostTexMtx, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, gRcpNextPostTexMtx);
    if (variant == 0 || variant == 2)
    {
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR0A0);
    }
    else
    {
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR1A1);
    }
    if (*(int*)&gRcpNextTevStage == 0)
    {
        inputSel = GX_CC_ONE;
    }
    else
    {
        inputSel = GX_CC_C1;
    }
    if (stageMode == 0)
    {
        if (compMode == 2)
        {
            GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, inputSel, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (compMode == 3)
        {
            GXSetTevColorIn(gRcpNextTevStage, inputSel, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (compMode == 1)
        {
            GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC, inputSel);
        }
        else if (variant == 0 || variant == 1)
        {
            GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_RASC, GX_CC_TEXC, inputSel);
        }
        else
        {
            GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXC, inputSel);
        }
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        if (compMode == 1)
        {
            GXSetTevColorOp(gRcpNextTevStage, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
            GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        }
        else
        {
            GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
            GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        }
    }
    else if (stageMode == 1)
    {
        if (compMode == 2)
        {
            GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_C2, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (compMode == 3)
        {
            GXSetTevColorIn(gRcpNextTevStage, GX_CC_C2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (compMode == 1)
        {
            GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C2);
        }
        else if (variant == 0 || variant == 1)
        {
            GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_RASC, GX_CC_TEXC, GX_CC_C2);
        }
        else
        {
            GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXC, GX_CC_C2);
        }
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        if (compMode == 1)
        {
            GXSetTevColorOp(gRcpNextTevStage, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
            GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
        }
        else
        {
            GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
            GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
        }
    }
    else
    {
        gRcpTevPrevAlphaValid = 1;
        gRcpTevPrevColorValid = 1;
        GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP1, GX_TEV_SWAP1);
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ONE);
        if (compMode == 3)
        {
            GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_RASA, GX_CA_TEXA, GX_CA_KONST);
            GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        }
        else
        {
            GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_RASA, GX_CA_TEXA, GX_CA_ZERO);
            GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        }
        GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    }
    texmap = gRcpNextTexMap;
    if (texSrc != NULL)
    {
        GXTexObj* tex = (GXTexObj*)((Texture*)texSrc)->gxTexObj;
        if (((Texture*)texSrc)->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(tex, (GXTexRegion*)((Texture*)texSrc)->tmemAddr, texmap);
        }
        else
        {
            GXLoadTexObj(tex, texmap);
        }
    }
    gRcpNextPostTexMtx += 3;
    gRcpNextTexCoord += 1;
    gRcpNextTevStage += 1;
    gRcpNextTexMap += 1;
    gRcpNumTevStages++;
    gRcpNumTexGens++;
}





void addEnvMapTexCoord(int scale)
{
    f32 m[3][4];
    PSMTXScale(m, scale, scale, 0.0f);
    m[2][3] = 1.0f;
    GXLoadTexMtxImm(m, gRcpNextPostTexMtx, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, gRcpNextPostTexMtx);
    gRcpNextPostTexMtx += 3;
    gRcpNextTexCoord++;
    gRcpNumTexGens++;
}

int addEnvMapBumpStages(void* p1, int p2, u8 p3, u32 p4)
{
    struct piIndMtx indmtx;
    f32 mtx[3][4];
    f32 v;
    int result;
    int texmap;
    int t;
    indmtx = sEnvMapBumpIndMtx;
    t = lbl_803DB5E8 & 1;
    result = 0;
    if (t == 0)
    {
        return 0;
    }
    GXSetIndTexMtx(GX_ITM_0, indmtx.m, 0);
    GXSetIndTexOrder(gRcpNextIndTexStage, gRcpNextTexCoord + p2, gRcpNextTexMap);
    if (p4 != 0)
    {
        Texture* texptr;
        u32 div;
        int p2v = (p3 & 0xf) * 4 + 1;
        texptr = (Texture*)(textureIdxToPtr(p4));
        div = (u32) texptr->width / (u32)(((Texture*)p1)->width * p2v);
        if (div != 0)
        {
            GXSetIndTexCoordScale(gRcpNextIndTexStage, lbl_8030CEE0[div - 1], lbl_8030CEE0[div - 1]);
        }
        else
        {
            result = p2v & 0xff;
        }
    }
    else
    {
        result = 1;
    }
    v = 0.5f * (3.0f * ((f32)(s32)((p3 & 0xf0) >> 4) / 7.0f - 1.0f));
    PSMTXScale(mtx, v, v, 0.0f);
    mtx[2][3] = 1.0f;
    GXLoadTexMtxImm(mtx, gRcpNextPostTexMtx, GX_MTX3x4);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, GX_TG_BINRM, GX_TEXMTX0, GX_FALSE, gRcpNextPostTexMtx);
    GXSetTexCoordGen2(gRcpNextTexCoord + 1, GX_TG_MTX2x4, GX_TG_TANGENT, GX_TEXMTX0, GX_FALSE, gRcpNextPostTexMtx);
    GXSetTevIndirect(gRcpNextTevStage, gRcpNextIndTexStage, GX_ITF_8, GX_ITB_ST, GX_ITM_S0, GX_ITW_0, GX_ITW_0, 0, 0, GX_ITBA_OFF);
    GXSetTevIndirect(gRcpNextTevStage + 1, gRcpNextIndTexStage, GX_ITF_8, GX_ITB_ST, GX_ITM_T0, GX_ITW_0, GX_ITW_0, 1, 0, GX_ITBA_OFF);
    GXSetTevIndirect(gRcpNextTevStage + 2, gRcpNextIndTexStage, GX_ITF_8, GX_ITB_NONE, GX_ITM_OFF, GX_ITW_OFF, GX_ITW_OFF, 1, 0, GX_ITBA_OFF);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, (gRcpNextTexMap + 1) | 0x100, GX_COLOR_NULL);
    GXSetTevOp(gRcpNextTevStage, GX_PASSCLR);
    GXSetTevOrder(gRcpNextTevStage + 1, gRcpNextTexCoord + 1, (gRcpNextTexMap + 1) | 0x100, GX_COLOR_NULL);
    GXSetTevOp(gRcpNextTevStage + 1, GX_PASSCLR);
    texmap = gRcpNextTexMap;
    if (p1 != 0)
    {
        char* tex = (char*)p1 + 0x20;
        if (((Texture*)p1)->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)tex, (GXTexRegion*)((Texture*)p1)->tmemAddr, texmap);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)tex, texmap);
        }
    }
    gRcpNextPostTexMtx += 3;
    gRcpNextIndTexStage += 1;
    gRcpNextTexCoord += 2;
    gRcpNextTevStage += 2;
    gRcpNextTexMap += 1;
    gRcpNumTevStages += 2;
    gRcpNumIndStages += 1;
    gRcpNumTexGens += 2;
    return result;
}





void addLitColorStage(u8 mode)
{
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (mode != 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_C2);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_CPREV, GX_CC_RASC, GX_CC_C2);
    }
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}

void addTexModulateReg2Stage(void)
{
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_C2, GX_CC_TEXC, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}


void addAlphaLitColorReg2Stage(u8 mode)
{
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (mode != 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_APREV, GX_CC_C1, GX_CC_C2);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_APREV, GX_CC_RASC, GX_CC_C2);
    }
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}

void addLightTexReg2Stage(void* p1, u8 flag2, u8 flag3)
{
    f32 mtxB[3][4];
    f32 mtxA[3][4];
    int texmap;
    if (gRcpNumIndStages == 0)
    {
        GXSetTevDirect(gRcpNextTevStage);
    }
    if (flag2 != 0)
    {
        GXSetTevIndRepeat(gRcpNextTevStage);
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord - 1, gRcpNextTexMap, GX_COLOR_NULL);
    }
    else
    {
        PSMTXScale(mtxA, -0.5f, -0.5f, 0.0f);
        PSMTXTrans(mtxB, 0.5f, 0.5f, 1.0f);
        PSMTXConcat(mtxB, mtxA, mtxA);
        GXLoadTexMtxImm(mtxA, gRcpNextPostTexMtx, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, gRcpNextPostTexMtx);
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR0A0);
        gRcpNextPostTexMtx += 3;
        gRcpNextTexCoord += 1;
        gRcpNumTexGens += 1;
    }
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_A2, GX_CA_ZERO);
    if (flag2 != 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C1, GX_CC_ZERO);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    }
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
    if ((flag3 & 1) != 0)
    {
        GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_BLUE, GX_CH_BLUE, GX_CH_BLUE, GX_CH_GREEN);
    }
    else
    {
        GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);
    }
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP3);
    texmap = gRcpNextTexMap;
    if (p1 != 0)
    {
        char* tex = (char*)p1 + 0x20;
        if (((Texture*)p1)->preloaded != 0)
        {
        GXLoadTexObjPreLoaded((GXTexObj*)tex, (GXTexRegion*)((Texture*)p1)->tmemAddr, texmap);
        }
        else
        {
        GXLoadTexObj((GXTexObj*)tex, texmap);
        }
    }
    gRcpNextTevStage += 1;
    gRcpNextTexMap += 1;
    gRcpNumTevStages += 1;
}






void addSphereMapTexStage(void* p1, u8 intensity)
{
    f32 mtxB[3][4];
    f32 mtxA[3][4];
    u8 buf[3];
    int out_c;
    int out_8;
    int texmap;
    PSMTXScale(mtxA, -0.5f, -0.5f, 0.0f);
    PSMTXTrans(mtxB, 0.5f, 0.5f, 1.0f);
    PSMTXConcat(mtxB, mtxA, mtxA);
    GXLoadTexMtxImm(mtxA, gRcpNextPostTexMtx, GX_MTX3x4);
    buf[0] = intensity;
    buf[1] = intensity;
    buf[2] = intensity;
    chooseTevKonstSelectors(buf, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(gRcpNextTevStage, out_c);
    GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, gRcpNextPostTexMtx);
    if (gRcpNumIndStages == 0)
    {
        GXSetTevDirect(gRcpNextTevStage);
    }
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_RASC);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    texmap = gRcpNextTexMap;
    if (p1 != 0)
    {
        GXTexObj* tex = textureGetGXTexObj((Texture*)p1);
        if (((Texture*)p1)->preloaded != 0)
        {
        GXLoadTexObjPreLoaded(tex, (GXTexRegion*)((Texture*)p1)->tmemAddr, texmap);
        }
        else
        {
        GXLoadTexObj(tex, texmap);
        }
    }
    gRcpNextPostTexMtx += 3;
    gRcpNextTevStage += 1;
    gRcpNextTexCoord += 1;
    gRcpNextTexMap += 1;
    gRcpNumTevStages += 1;
    gRcpNumTexGens += 1;
}



void addTexLayerStagesLit(void* p1, void* mtx)
{
    u8 buf[3];
    int out_c;
    int out_8;
    objGetSunColor(0, &buf[0], &buf[1], &buf[2]);
    if (mtx != 0)
    {
        GXLoadTexMtxImm(mtx, gRcpNextPostTexMtx, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, gRcpNextPostTexMtx);
        gRcpNextPostTexMtx += 3;
    }
    else
    {
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    }
    chooseTevKonstSelectors(buf, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(gRcpNextTevStage, out_c);
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_KONST, GX_CC_RASC, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    GXSetTevDirect(gRcpNextTevStage + 1);
    GXSetTevOrder(gRcpNextTevStage + 1, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(gRcpNextTevStage + 1, GX_CC_CPREV, GX_CC_RASC, GX_CC_RASA, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevDirect(gRcpNextTevStage + 2);
    GXSetTevOrder(gRcpNextTevStage + 2, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
    GXSetTevSwapMode(gRcpNextTevStage + 2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(gRcpNextTevStage + 2, GX_CC_ZERO, GX_CC_CPREV, GX_CC_TEXC, GX_CC_ZERO);
    GXSetTevAlphaIn(gRcpNextTevStage + 2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevColorOp(gRcpNextTevStage + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    {
        int id = gRcpNextTexMap;
        if (p1 != 0)
        {
            GXTexObj* obj = (GXTexObj*)((Texture*)p1)->gxTexObj;
            if (((Texture*)p1)->preloaded != 0)
            {
                GXLoadTexObjPreLoaded(obj, (GXTexRegion*)((Texture*)p1)->tmemAddr, id);
            }
            else
            {
                GXLoadTexObj(obj, id);
            }
        }
    }
    gRcpNextTexCoordSource += 1;
    gRcpNextTexCoord += 1;
    gRcpNextTevStage += 3;
    gRcpNextTexMap += 1;
    gRcpNumTevStages += 3;
    gRcpNumTexGens += 1;
}


GXTexObj sSecondaryTexObj;

void addTexLayerStage(Texture* tex, MtxPtr mtx, int mode)
{
    int map;
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (mtx != NULL)
    {
        GXLoadTexMtxImm(mtx, gRcpNextPostTexMtx, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, gRcpNextPostTexMtx);
        gRcpNextPostTexMtx += 3;
    }
    else
    {
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    }
    if (mode == 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    }
    else if (mode == 8)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_C2);
    }
    else if (mode == 4)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_TEXC, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    }
    else if (mode == 6)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_CPREV, GX_CC_ZERO);
    }
    else if (mode == 9)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_TEXC, GX_CC_CPREV, GX_CC_APREV, GX_CC_ZERO);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_TEXC, GX_CC_CPREV, GX_CC_APREV, GX_CC_ZERO);
    }
    if (gRcpTevPrevAlphaValid != 0)
    {
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_APREV, GX_CA_ZERO);
    }
    else
    {
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
        gRcpTevPrevAlphaValid = 1;
    }
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    map = gRcpNextTexMap;
    if (tex != NULL)
    {
        GXTexObj* to = textureGetGXTexObj(tex);
        if (tex->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(to, textureGetGXTexRegion(tex), map);
        }
        else
        {
            GXLoadTexObj(to, map);
        }
    }
    gRcpNextTexCoordSource += 1;
    gRcpNextTexCoord += 1;
    gRcpNextTevStage += 1;
    gRcpNextTexMap += 1;
    gRcpNumTevStages++;
    gRcpNumTexGens++;
}

void addTexLayerStageKColor(Texture* tex, MtxPtr mtx, int mode, GXColor* kparam)
{
    int sel;
    int v1;
    int map;
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (mtx != NULL)
    {
        GXLoadTexMtxImm(mtx, gRcpNextPostTexMtx, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, gRcpNextPostTexMtx);
        gRcpNextPostTexMtx += 3;
    }
    else
    {
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    }
    chooseTevKonstSelectors(kparam, 1, 0, &sel, &v1);
    GXSetTevKColorSel(gRcpNextTevStage, sel);
    if (mode == 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_ZERO);
    }
    else if (mode == 8)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C2);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_TEXC, GX_CC_CPREV, GX_CC_APREV, GX_CC_ZERO);
    }
    if (gRcpTevPrevAlphaValid != 0)
    {
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_APREV, GX_CA_ZERO);
    }
    else
    {
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_RASA, GX_CA_ZERO);
        gRcpTevPrevAlphaValid = 1;
    }
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    map = gRcpNextTexMap;
    if (tex != NULL)
    {
        GXTexObj* to = textureGetGXTexObj(tex);
        if (tex->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(to, textureGetGXTexRegion(tex), map);
        }
        else
        {
            GXLoadTexObj(to, map);
        }
    }
    gRcpNextTexCoordSource += 1;
    gRcpNextTexCoord += 1;
    gRcpNextTevStage += 1;
    gRcpNextTexMap += 1;
    gRcpNumTevStages++;
    gRcpNumTexGens++;
}

void addTexLayerStageKAlpha(Texture* tex, MtxPtr mtx, int mode, GXColor* kparam)
{
    int sel;
    int v1;
    int map;
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (mtx != NULL)
    {
        GXLoadTexMtxImm(mtx, gRcpNextPostTexMtx, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, gRcpNextPostTexMtx);
        gRcpNextPostTexMtx += 3;
    }
    else
    {
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    }
    chooseTevKonstSelectors(kparam, 0, 1, &sel, &v1);
    GXSetTevKAlphaSel(gRcpNextTevStage, v1);
    if (mode == 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    }
    else if (mode == 8)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_C2);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_TEXC, GX_CC_CPREV, GX_CC_APREV, GX_CC_ZERO);
    }
    if (gRcpTevPrevAlphaValid != 0)
    {
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_APREV, GX_CA_ZERO);
    }
    else
    {
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
        gRcpTevPrevAlphaValid = 1;
    }
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    map = gRcpNextTexMap;
    if (tex != NULL)
    {
        GXTexObj* to = textureGetGXTexObj(tex);
        if (tex->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(to, textureGetGXTexRegion(tex), map);
        }
        else
        {
            GXLoadTexObj(to, map);
        }
    }
    gRcpNextTexCoordSource += 1;
    gRcpNextTexCoord += 1;
    gRcpNextTevStage += 1;
    gRcpNextTexMap += 1;
    gRcpNumTevStages++;
    gRcpNumTexGens++;
}

typedef struct TevSwapEntry
{
    int r;
    int g;
    int b;
} TevSwapEntry;
TevSwapEntry gRcpTevSwapTable[24] = {
    {0, 1, 2}, {0, 2, 1}, {1, 0, 2}, {2, 0, 1}, {1, 2, 0}, {2, 1, 0}, {0, 0, 2}, {0, 2, 0},
    {2, 0, 0}, {0, 0, 1}, {0, 1, 0}, {1, 0, 0}, {1, 1, 2}, {1, 2, 1}, {2, 1, 1}, {1, 1, 0},
    {1, 0, 1}, {0, 1, 1}, {2, 2, 0}, {2, 0, 2}, {0, 2, 2}, {2, 2, 1}, {2, 1, 2}, {1, 2, 2},
};

void addTexLayerStageSwizzled(Texture* tex, MtxPtr mtx, int mode, GXColor* kparam, u8 swapSelector,
                              u8 useKColor)
{
    int sel;
    int v1;
    int map;
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP1);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, gRcpTevSwapTable[swapSelector].r, gRcpTevSwapTable[swapSelector].g,
                          gRcpTevSwapTable[swapSelector].b, GX_CH_ALPHA);
    if (mtx != NULL)
    {
        GXLoadTexMtxImm(mtx, gRcpNextPostTexMtx, GX_MTX3x4);
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, gRcpNextPostTexMtx);
        gRcpNextPostTexMtx += 3;
    }
    else
    {
        GXSetTexCoordGen2(gRcpNextTexCoord, GX_TG_MTX2x4, gRcpNextTexCoordSource, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    }
    if (useKColor != 0)
    {
        chooseTevKonstSelectors(kparam, 1, 1, &sel, &v1);
        GXSetTevKColorSel(gRcpNextTevStage, sel);
        if ((void*)tex->imageOffset != NULL)
        {
            GXSetTevKAlphaSel(gRcpNextTevStage + 1, v1);
        }
        else
        {
            GXSetTevKAlphaSel(gRcpNextTevStage, v1);
        }
    }
    else
    {
        GXSetTevKColor(gRcpNextKColor, *kparam);
        GXSetTevKColorSel(gRcpNextTevStage, gRcpNextKColorSel);
        if ((void*)tex->imageOffset != NULL)
        {
            GXSetTevKAlphaSel(gRcpNextTevStage + 1, gRcpNextKAlphaSel);
        }
        else
        {
            GXSetTevKAlphaSel(gRcpNextTevStage, gRcpNextKAlphaSel);
        }
        gRcpNextKColor += 1;
        gRcpNextKColorSel += 1;
        gRcpNextKAlphaSel += 1;
    }
    if (mode == 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_ZERO);
    }
    else if (mode == 8)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C1, GX_CC_C2);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_TEXC, GX_CC_CPREV, GX_CC_APREV, GX_CC_ZERO);
    }
    if (gRcpTevPrevAlphaValid != 0)
    {
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_APREV, GX_CA_ZERO);
    }
    else
    {
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
    }
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    map = gRcpNextTexMap;
    if (tex != NULL)
    {
        GXTexObj* to = textureGetGXTexObj(tex);
        if (tex->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(to, textureGetGXTexRegion(tex), map);
        }
        else
        {
            GXLoadTexObj(to, map);
        }
        if ((void*)tex->imageOffset != NULL)
        {
            textureInitSecondaryGXTexObj(tex, &sSecondaryTexObj);
            GXLoadTexObj(&sSecondaryTexObj, GX_TEXMAP1);
        }
    }
    if ((void*)tex->imageOffset != NULL)
    {
        gRcpNumTevStages++;
        gRcpNextTevStage += 1;
        gRcpNextTexMap += 1;
        GXSetTevDirect(gRcpNextTevStage);
        GXSetTevOrder(gRcpNextTevStage, gRcpNextTexCoord, gRcpNextTexMap, GX_COLOR_NULL);
        GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_ZERO);
        GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    }
    gRcpTevPrevAlphaValid = 1;
    gRcpNextTexCoordSource += 1;
    gRcpNextTexCoord += 1;
    gRcpNextTevStage += 1;
    gRcpNextTexMap += 1;
    gRcpNumTevStages++;
    gRcpNumTexGens++;
}


void addVertexColorStage(void)
{
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (gRcpNumTevStages == 0 || gRcpTevPrevColorValid == 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_RASC);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_RASA);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_CPREV, GX_CC_RASC, GX_CC_ZERO);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_APREV, GX_CA_RASA, GX_CA_ZERO);
    }
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}

void addVertexColorKAlphaStage(GXColor* param)
{
    int sel_color;
    int sel_alpha;
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    chooseTevKonstSelectors(param, 0, 1, &sel_color, &sel_alpha);
    GXSetTevKAlphaSel(gRcpNextTevStage, sel_alpha);
    if (gRcpNumTevStages == 0 || gRcpTevPrevColorValid == 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_RASC);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_CPREV, GX_CC_RASC, GX_CC_ZERO);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_APREV, GX_CA_KONST, GX_CA_ZERO);
    }
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}
void addColorFadeStage(GXColor* param)
{
    int sel;
    int v1;
    GXSetTevDirect(gRcpNextTevStage);
    GXSetTevColor(GX_TEVREG0, *param);
    chooseTevKonstSelectors(param, 1, 0, &sel, &v1);
    GXSetTevKColorSel(gRcpNextTevStage, sel);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (gRcpNumTevStages != 0 && gRcpTevPrevColorValid != 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_CPREV, GX_CC_KONST, GX_CC_A0, GX_CC_ZERO);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    }
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}

void addKColorModulateStage(GXColor* param)
{
    int sel_color;
    int sel_alpha;
    GXSetTevDirect(gRcpNextTevStage);
    chooseTevKonstSelectors(param, 1, 1, &sel_color, &sel_alpha);
    GXSetTevKAlphaSel(gRcpNextTevStage, sel_alpha);
    GXSetTevKColorSel(gRcpNextTevStage, sel_color);
    GXSetTevOrder(gRcpNextTevStage, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(gRcpNextTevStage, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (gRcpNumTevStages == 0 || gRcpTevPrevColorValid == 0)
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_KONST);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_KONST);
    }
    else
    {
        GXSetTevColorIn(gRcpNextTevStage, GX_CC_ZERO, GX_CC_CPREV, GX_CC_KONST, GX_CC_ZERO);
        GXSetTevAlphaIn(gRcpNextTevStage, GX_CA_ZERO, GX_CA_APREV, GX_CA_KONST, GX_CA_ZERO);
    }
    GXSetTevColorOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(gRcpNextTevStage, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    gRcpTevPrevColorValid = 1;
    gRcpNextTevStage += 1;
    gRcpNumTevStages++;
}

void Rcp_ApplyTextureStageCounts(void)
{
    GXSetNumTexGens(gRcpNumTexGens);
    GXSetNumTevStages(gRcpNumTevStages);
    GXSetNumIndStages(gRcpNumIndStages);
}
void Rcp_ResetTextureStageState(void)
{
    lbl_803DCD58 = 30;
    gRcpNextTexMtx = 30;
    lbl_803DCD54 = 64;
    gRcpNextPostTexMtx = 64;
    lbl_803DCD64 = 0;
    gRcpNextTevStage = 0;
    lbl_803DCD5C = 0;
    gRcpNextTexCoord = 0;
    lbl_803DCD60 = 0;
    gRcpNextTexMap = 0;
    lbl_803DCD50 = 0;
    gRcpNextIndTexStage = 0;
    lbl_803DCD4C = 4;
    gRcpNextTexCoordSource = 4;
    gRcpNextKColor = 0;
    gRcpNextKColorSel = 12;
    gRcpNextKAlphaSel = 28;
    gRcpTevPrevAlphaValid = 0;
    lbl_803DCD4B = 0;
    gRcpNumTevStages = 0;
    lbl_803DCD4A = 0;
    gRcpNumTexGens = 0;
    lbl_803DCD49 = 0;
    gRcpNumIndStages = 0;
    lbl_803DCD48 = 0;
    gRcpTevPrevColorValid = 0;
}

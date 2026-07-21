#include "dolphin/os/OSReport.h"
#include "dolphin/PPCArch.h"
#include "dolphin/mtx.h"
#include "main/frame_timing.h"
#include "main/shader_api.h"
#include "dolphin/gx/GXStruct.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_80136a40.h"
#include "main/gamebits.h"
#include "main/game_object.h"
#include "main/object_api.h"
#include "dolphin/gx/GXMisc.h"
#include "main/pi_dolphin.h"
#include "main/newshadows.h"
#include "main/mm.h"
#include "main/model.h"
#include "main/model_engine.h"
#include "main/texture.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/os/OSInterrupt.h"
#include "dolphin/os/OSStopwatch.h"
#include "string.h"
#include "main/pad.h"
#include "main/pi_data_file_api.h"
#include "main/pi_flush_api.h"
#include "main/pi_dolphin_texture_api.h"
#include "main/shader_dolphin.h"
#include "main/dll/FRONT/n_options.h"
#include "dolphin/os/OSResetSW.h"
#include "dolphin/gx/GXCull.h"
#include "main/track_dolphin_api.h"
#include "PowerPC_EABI_Support/Msl/MSL_C/MSL_Common/printf.h"
#include "dolphin/os/OSArena.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "dolphin/gx/GXCpu2Efb.h"
#include "dolphin/gx/GXManage.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXPerf.h"
#include "dolphin/gx/GXTev.h"
#include "dolphin/gx/GXTexture.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/os/OSTime.h"
#include "dolphin/vi.h"
#include "main/camera.h"
#include "main/debug.h"
#include "main/fileio.h"
#include "main/gameloop_api.h"
#include "main/map_load.h"
#include "main/map_texscroll.h"
#include "main/table_file.h"
#include "main/rcp_dolphin.h"
#include "main/sky_api.h"
#include "main/textrender_api.h"
#include "main/vecmath_distance_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "track/intersect_api.h"
#include "track/intersect_depth_read_api.h"


f32 lbl_803DCD44;
f32 lbl_803DCD40;
f32 lbl_803DCD3C;
f32 lbl_803DCD38;
f32 lbl_803DCD34;
u8 lbl_803DCD31;
u8 lbl_803DCD30;
u8* lbl_803DCD2C;
u8 lbl_803DCD28;

u8 lbl_803DB5E8 = 0xFF;
GXColor gHeatEffectColor = {0xFF, 0xFF, 0xFF, 0xC0};
f32 gHeatEffectScale = 1.0f;
int lbl_803DB5F4 = -4;
u8 lbl_803DB5F8[8] = {0x28, 0x20, 0, 0xFF, 0, 0, 0, 0};

typedef struct
{
    f32 v[2][3];
} IndTexMtx23;

struct piIndMtx
{
    f32 m[2][3];
};

const struct piIndMtx lbl_802C1D50 = {
    {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 lbl_802C1D68[4] = {
    {{{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}},
    {{{3.0f, -1.0f, 1.0f}, {1.0f, -1.0f, 3.0f}}},
    {{{1.0f, -2.0f, 1.0f}, {-2.0f, -1.0f, 1.0f}}},
    {{{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}}};
const IndTexMtx23 lbl_802C1DC8 = {
    {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 lbl_802C1DE0[2] = {
    {{{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}},
    {{{0.0f, 0.0f, 0.0f}, {0.0f, 0.0f, 0.0f}}}};
const struct piIndMtx lbl_802C1E10 = {
    {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};
const IndTexMtx23 lbl_802C1E28 = {
    {{0.0f, 0.5f, 0.0f}, {0.0f, 0.0f, 0.5f}}};
const IndTexMtx23 gTexIndMtxTable = {
    {{0.5f, 0.0f, 0.0f}, {0.0f, 0.5f, 0.0f}}};

extern f32 Prepared_803DEAD8;
extern f32 lbl_803DEAE0;
extern int lbl_803DCD7C;
extern int lbl_803DEAB0; /* first word of a GXColorS10 (through 803DEAC0) */
extern int lbl_803DEAB8;
extern int lbl_803DEABC;
extern int lbl_803DEAC0;
extern int lbl_803DCD74;
extern int lbl_803DCD70;
extern int lbl_803DCD6C;
extern GXTexObj lbl_803779A0;
extern u8 lbl_803DCD68;
extern int lbl_803DCD80;
extern u8 lbl_803DCD69;
extern f32 lbl_803DEADC;
extern int lbl_803DCD78;
extern u8 lbl_803DCD6B;
extern f32 lbl_803DEAFC;
extern f32 lbl_803DEB00;
extern int lbl_803DCD84;
extern f32 lbl_803DEAC8;
extern f32 lbl_803DEACC;
extern int lbl_803DCD88;
extern int lbl_803DCD8C;
extern int lbl_803DCD90;
extern u8 lbl_803DCD6A;


void gxTextureFn_8004bf88(void* bufp, u8 flag1, u8 flag2, int* out1, int* out2)
{
    u8* buf = bufp;
    u8 found1 = 0;
    u8 found2 = 0;
    if (flag1 != 0)
    {
        if (buf[0] == buf[1] && buf[0] == buf[2])
        {
            if (buf[0] == 0xff)
            {
                *out1 = 0;
                found1 = 1;
            }
            else if (buf[0] == 0xe0)
            {
                *out1 = 1;
                found1 = 1;
            }
            else if (buf[0] == 0xc0)
            {
                *out1 = 2;
                found1 = 1;
            }
            else if (buf[0] == 0xa0)
            {
                *out1 = 3;
                found1 = 1;
            }
            else if (buf[0] == 0x80)
            {
                *out1 = 4;
                found1 = 1;
            }
            else if (buf[0] == 0x60)
            {
                *out1 = 5;
                found1 = 1;
            }
            else if (buf[0] == 0x40)
            {
                *out1 = 6;
                found1 = 1;
            }
            else if (buf[0] == 0x20)
            {
                *out1 = 7;
                found1 = 1;
            }
        }
        if (found1 == 0)
        {
            *out1 = lbl_803DCD70;
        }
    }
    else
    {
        found1 = 1;
    }
    if (flag2 != 0)
    {
        if (buf[3] == 0xff)
        {
            *out2 = 0;
            found2 = 1;
        }
        else if (buf[3] == 0xe0)
        {
            *out2 = 1;
            found2 = 1;
        }
        else if (buf[3] == 0xc0)
        {
            *out2 = 2;
            found2 = 1;
        }
        else if (buf[3] == 0xa0)
        {
            *out2 = 3;
            found2 = 1;
        }
        else if (buf[3] == 0x80)
        {
            *out2 = 4;
            found2 = 1;
        }
        else if (buf[3] == 0x60)
        {
            *out2 = 5;
            found2 = 1;
        }
        else if (buf[3] == 0x40)
        {
            *out2 = 6;
            found2 = 1;
        }
        else if (buf[3] == 0x20)
        {
            *out2 = 7;
            found2 = 1;
        }
        if (found2 == 0)
        {
            *out2 = lbl_803DCD6C;
        }
    }
    else
    {
        found2 = 1;
    }
    if (found1 == 0 || found2 == 0)
    {
        GXSetTevKColor(lbl_803DCD74, *(GXColor*)bufp);
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
    }
}

extern f32 lbl_803DEB04;
extern f32 lbl_803DEB08;
extern f32 lbl_803DEB0C;
extern f32 lbl_803DEB10;
extern f32 lbl_803DEB14;
extern f32 lbl_803DEB18;

void setHeatEffectParams(u8 alpha, f32 scale)
{
    gHeatEffectColor.a = alpha;
    gHeatEffectScale = scale;
    if (scale > lbl_803DEAC8)
    {
        gHeatEffectScale = lbl_803DEAC8;
    }
}


void disableHeavyFog(void)
{
    lbl_803DCD28 = 0x0;
}

void enableHeavyFog(f32 a, f32 b, f32 c, f32 d, f32 e, u8 mode)
{
    lbl_803DCD28 = 1;
    lbl_803DCD44 = a;
    lbl_803DCD40 = b;
    lbl_803DCD3C = c;
    lbl_803DCD38 = d;
    lbl_803DCD34 = e;
    lbl_803DCD31 = mode;
}


void getHeavyFogRange(f32* high, f32* low)
{
    *high = lbl_803DCD44;
    *low = lbl_803DCD40;
}

u8 isHeavyFogEnabled(void)
{
    return lbl_803DCD28;
}

void* Shader_getLayer(void* base, int idx)
{
    return (u8*)base + idx * 8 + 0x24;
}
void textureFn_8004c264(Texture* texture, int mapId)
{
    void* base;
    if (texture == NULL)
        return;
    base = &((u8*)texture)[32];
    if (((u8*)texture)[72] != 0)
    {
        GXLoadTexObjPreLoaded(base, *(void**)((u8*)texture + 64), mapId);
    }
    else
    {
        GXLoadTexObj(base, mapId);
    }
    if (*(void**)((u8*)texture + 80) != NULL)
    {
        textureInitSecondaryGXTexObj(texture, &lbl_803779A0);
        GXLoadTexObj(&lbl_803779A0, GX_TEXMAP1);
    }
}

void selectTexture(Texture* texture, int mapId)
{
    void* base;
    if (texture == NULL)
        return;
    base = &((u8*)texture)[0x20];
    if (((u8*)texture)[0x48] != 0)
    {
        GXLoadTexObjPreLoaded(base, *(void**)((u8*)texture + 0x40), mapId);
    }
    else
    {
        GXLoadTexObj(base, mapId);
    }
}
void textureFn_8004c330(void* p1, void* mtx)
{
    IndTexMtx23 m;
    f32 sx;
    f32 sy;
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
    m = lbl_802C1E28;
    if (lbl_803DCD2C == 0)
    {
        lbl_803DCD2C = textureAlloc(0x20, 0x20, 4, 0, 0, 1, 1, 1, 1);
        for (y = 0; y < 0x20; y++)
        {
            x = 0;
            yhi = (y >> 2) * 0x20;
            ylo = (y & 3) * 2;
            for (; x < 0x20; x++)
            {
                v1 = (int)lbl_803DCD2C + ylo;
                v1 = v1 + yhi;
                v1 = v1 + (x & 3) * 8;
                dst = (u8*)v1 + (x >> 2) * 0x100;
                v1 = randomGetRange(0x80, 0xff);
                v2 = v1 - randomGetRange(0, 0x40);
                v3 = v1 - randomGetRange(0x40, 0x80);
                *(u16*)(dst + 0x60) = ((v1 & 0xf8) >> 3) | ((v2 & 0xf8) << 8 | (v3 & 0xfc) << 3);
            }
        }
        DCFlushRange(lbl_803DCD2C + 0x60, ((Texture*)lbl_803DCD2C)->dataSize);
    }
    newshadows_getReflectionScrollOffsets(&sx, &sy);
    m.v[0][1] = lbl_803DEAE0 * mathSinf(Prepared_803DEAD8 * sx) + lbl_803DEADC;
    m.v[1][2] = lbl_803DEAE0 * mathSinf(Prepared_803DEAD8 * sy) + lbl_803DEADC;
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD0, lbl_803DCD8C + 1, GX_ALPHA_BUMPN);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (mtx != 0)
    {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX2x4, lbl_803DCD78, GX_IDENTITY, GX_FALSE, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    }
    else
    {
        GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX2x4, lbl_803DCD78, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    }
    GXSetIndTexMtx(GX_ITM_0, m.v, (s8)lbl_803DB5F4);
    GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88, lbl_803DCD8C);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 7, 1, 0, 0, 0, 0, 3);
    gxTextureFn_8004bf88(lbl_803DB5F8, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(lbl_803DCD90, out_c);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_KONST, GX_CC_TEXC, GX_CC_RASA, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevOrder(lbl_803DCD90 + 1, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevColorIn(lbl_803DCD90 + 1, GX_CC_C0, GX_CC_CPREV, GX_CC_APREV, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    {
        int id = lbl_803DCD8C;
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
        int id2 = lbl_803DCD8C + 1;
        Texture* tex = (Texture*)lbl_803DCD2C;
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
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD6A += 2;
    lbl_803DCD69 += 1;
    lbl_803DCD68 += 1;
}
void fn_8004C7AC(void* tex0, void* tex1, void* tex2, s16 w, s16 h)
{
    u8 buf5c[0x20];
    u8 buf3c[0x20];
    u8 buf1c[0x20];
    GXColorS10 cs10;
    int h2;
    int w2;
    if (lbl_803DCD6A > 0xb || lbl_803DCD69 > 6 || lbl_803DCD8C > 5 || lbl_803DCD74 > 1)
    {
        return;
    }
    {
        GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88 + 1, lbl_803DCD8C + 1, GX_COLOR_NULL);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C0);
        GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVREG1);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_A0);
        GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVREG1);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevKAlphaSel(lbl_803DCD90, lbl_803DCD6C);
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C + 2, GX_COLOR_NULL);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevColorIn(lbl_803DCD90 + 1, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_C1);
        GXSetTevColorOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_2, GX_FALSE, GX_TEVREG1);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_KONST, GX_CA_A1);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_FALSE, GX_TEVREG1);
        GXSetTevKColorSel(lbl_803DCD90 + 1, lbl_803DCD70 + 1);
        GXSetTevKAlphaSel(lbl_803DCD90 + 1, lbl_803DCD6C + 1);
        GXSetTevSwapMode(lbl_803DCD90 + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevOrder(lbl_803DCD90 + 2, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
        GXSetTevDirect(lbl_803DCD90 + 2);
        GXSetTevColorIn(lbl_803DCD90 + 2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ONE, GX_CC_C1);
        GXSetTevColorOp(lbl_803DCD90 + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevAlphaIn(lbl_803DCD90 + 2, GX_CA_TEXA, GX_CA_ZERO, GX_CA_ZERO, GX_CA_A1);
        GXSetTevAlphaOp(lbl_803DCD90 + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevSwapMode(lbl_803DCD90 + 2, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevOrder(lbl_803DCD90 + 3, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevDirect(lbl_803DCD90 + 3);
        GXSetTevColorIn(lbl_803DCD90 + 3, GX_CC_A1, GX_CC_C1, GX_CC_KONST, GX_CC_ZERO);
        GXSetTevColorOp(lbl_803DCD90 + 3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevAlphaIn(lbl_803DCD90 + 3, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        GXSetTevAlphaOp(lbl_803DCD90 + 3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevSwapMode(lbl_803DCD90 + 3, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevKColorSel(lbl_803DCD90 + 3, lbl_803DCD70 + 2);
        GXSetTevOrder(lbl_803DCD90 + 4, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevDirect(lbl_803DCD90 + 4);
        GXSetTevColorIn(lbl_803DCD90 + 4, GX_CC_CPREV, GX_CC_C1, GX_CC_KONST, GX_CC_ZERO);
        GXSetTevColorOp(lbl_803DCD90 + 4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaIn(lbl_803DCD90 + 4, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevAlphaOp(lbl_803DCD90 + 4, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevSwapMode(lbl_803DCD90 + 4, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevKColorSel(lbl_803DCD90 + 4, GX_TEV_KCSEL_1_4);
        lbl_803DCD30 = 1;
        cs10 = *(GXColorS10*)&lbl_803DEAB0;
        GXSetTevColorS10(GX_TEVREG0, cs10);
        GXSetTevKColor(lbl_803DCD74, *(GXColor*)&lbl_803DEAB8);
        GXSetTevKColor(lbl_803DCD74 + 1, *(GXColor*)&lbl_803DEABC);
        GXSetTevKColor(lbl_803DCD74 + 2, *(GXColor*)&lbl_803DEAC0);
        GXInitTexObj((GXTexObj*)buf5c, tex0, w, h, GX_TF_I8, GX_CLAMP, GX_CLAMP, 0);
        GXInitTexObjLOD((GXTexObj*)buf5c, 0, 0, 0.0f, 0.0f, 0.0f, 0, 0, 0);
        GXLoadTexObj((GXTexObj*)buf5c, lbl_803DCD8C);
        GXInitTexObj((GXTexObj*)buf3c, tex1, w2 = w >> 1, h2 = h >> 1, GX_TF_I8, GX_CLAMP, GX_CLAMP, 0);
        GXInitTexObjLOD((GXTexObj*)buf3c, 0, 0, 0.0f, 0.0f, 0.0f, 0, 0, 0);
        GXLoadTexObj((GXTexObj*)buf3c, lbl_803DCD8C + 1);
        GXInitTexObj((GXTexObj*)buf1c, tex2, w2, h2, GX_TF_I8, GX_CLAMP, GX_CLAMP, 0);
        GXInitTexObjLOD((GXTexObj*)buf1c, 0, 0, 0.0f, 0.0f, 0.0f, 0, 0, 0);
        GXLoadTexObj((GXTexObj*)buf1c, lbl_803DCD8C + 2);
        lbl_803DCD90 = lbl_803DCD90 + 5;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 3;
        lbl_803DCD74 = lbl_803DCD74 + 3;
        lbl_803DCD70 = lbl_803DCD70 + 3;
        lbl_803DCD6C = lbl_803DCD6C + 3;
        lbl_803DCD6A += 5;
        lbl_803DCD69 += 2;
    }
}
void fn_8004CE0C(void* viewMtx)
{
    f32 mtx40[3][4];
    f32 mtx70[3][4];
    f32 sx;
    f32 sy;
    u8* obj7c;
    u8* obj80;

    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP0, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_TEXA, GX_CA_ZERO, GX_CA_RASA, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
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
    getNewShadowCausticTexture((u32*)&obj7c);
    if (obj7c != NULL)
    {
        void* obj = obj7c + 0x20;
        if (obj7c[0x48] != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, *(GXTexRegion**)(obj7c + 0x40), 2);
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
    GXSetTevIndirect(1, 0, 0, 7, 1, 0, 0, 0, 0, 0);
    GXSetTevKColorSel(GX_TEVSTAGE1, GX_TEV_KCSEL_1_2);
    GXSetTevOrder(GX_TEVSTAGE1, GX_TEXCOORD1, GX_TEXMAP1, GX_COLOR_NULL);
    GXSetTevColorIn(GX_TEVSTAGE1, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV, GX_CC_CPREV);
    GXSetTevAlphaIn(GX_TEVSTAGE1, GX_CA_ZERO, GX_CA_TEXA, GX_CA_APREV, GX_CA_ZERO);
    GXSetTevSwapMode(GX_TEVSTAGE1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(GX_TEVSTAGE1, GX_TEV_SUB, GX_TB_ADDHALF, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    getNewShadowRampTexture((u32*)&obj80);
    if (obj80 != NULL)
    {
        void* obj = obj80 + 0x20;
        if (obj80[0x48] != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, *(GXTexRegion**)(obj80 + 0x40), 3);
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
    lbl_803DCD90 = 3;
    lbl_803DCD88 = 4;
    lbl_803DCD8C = 4;
    lbl_803DCD7C = 1;
    lbl_803DCD84 = 0x27;
    lbl_803DCD6A = 3;
    lbl_803DCD69 = 4;
    lbl_803DCD68 = 1;
}
void fn_8004D230(void)
{
    f32 mtx1[4][4];
    f32 mtx2[3][4];
    u8* obj1;
    GameObject* player;
    u8* obj2;
    int id;
    f32 dist;
    f32 tmp;
    f32 t;

    obj1 = (u8*)getNewShadowFalloffTexture();
    C_MTXLightOrtho(mtx1, 25.0f, -25.0f, -25.0f, 25.0f, 0.5f, 0.5f, 0.5f, 0.5f);
    GXLoadTexMtxImm(mtx1, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
    GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP1, GX_TEV_SWAP1);
    if (lbl_803DCD90 == 0)
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    }
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    lbl_803DCD30 = 1;
    id = lbl_803DCD8C;
    if (obj1 != NULL)
    {
        void* obj = obj1 + 0x20;
        if (obj1[0x48] != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, *(GXTexRegion**)(obj1 + 0x40), id);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, id);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    player = Obj_GetPlayerObject();
    if (player != NULL)
    {
        dist = Camera_DistanceToCurrentViewPosition(((GameObject*)player)->anim.worldPosX,
                                                    ((GameObject*)player)->anim.worldPosY,
                                                    ((GameObject*)player)->anim.worldPosZ);
    }
    else
    {
        dist = lbl_803DEAFC;
    }
    tmp = dist - lbl_803DEB00;
    t = -(lbl_803DEAC8 / (dist - tmp));
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
    GXLoadTexMtxImm(mtx2, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP1, GX_TEV_SWAP1);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevKAlphaSel(lbl_803DCD90, GX_TEV_KASEL_1);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_A1, GX_CA_TEXA, GX_CA_KONST);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    obj2 = (u8*)getNewShadowInverseRampTexture();
    id = lbl_803DCD8C;
    if (obj2 != NULL)
    {
        void* obj = obj2 + 0x20;
        if (obj2[0x48] != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, *(GXTexRegion**)(obj2 + 0x40), id);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, id);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6B = 1;
    lbl_803DCD6A += 2;
    lbl_803DCD69 += 2;
}

void gxTextureFn_8004d5b4(void* p1)
{
    u8 buf[3];
    u8 b = *(u8*)((char*)p1 + 0x43);
    buf[2] = b;
    buf[1] = b;
    buf[0] = b;
    GXSetTevKColor(lbl_803DCD74, *(GXColor*)buf);
    GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_CPREV, GX_CC_C0, GX_CC_KONST, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD74 = lbl_803DCD74 + 1;
    lbl_803DCD70 = lbl_803DCD70 + 1;
    lbl_803DCD6C = lbl_803DCD6C + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}



void fn_8004D6D8(void)
{
    struct piIndMtx indmtx;
    void* tex;
    int id;
    f32 v;
    indmtx = lbl_802C1E10;
    v = lbl_803DEADC * getNewShadowDistortionWaveOffset();
    indmtx.m[0][0] = v;
    indmtx.m[1][2] = v;
    if (lbl_803DCD88 > 0)
    {
        GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88 - 1, lbl_803DCD8C + 1);
    }
    else
    {
        GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88, lbl_803DCD8C + 1);
    }
    GXSetIndTexCoordScale(lbl_803DCD7C, 0, 0);
    GXSetIndTexMtx(GX_ITM_1, indmtx.m, -3);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 3, 2, 0, 0, 0, 0, 0);
    getNewShadowCausticTexture((u32*)&tex);
    id = lbl_803DCD8C + 1;
    if (tex != NULL)
    {
        void* obj = (char*)tex + 0x20;
        if (((Texture*)tex)->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, (GXTexRegion*)((Texture*)tex)->tmemAddr, id);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, id);
        }
    }
    GXLoadTexMtxImm(lbl_80396820, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    selectReflectionTexture(lbl_803DCD8C);
    lbl_803DCD7C = lbl_803DCD7C + 1;
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD6A++;
    lbl_803DCD69++;
    lbl_803DCD68++;
}





void fn_8004D928(void)
{
    loadNewShadowSmallReflectionTexture(lbl_803DCD8C);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_TEXMTX2, GX_FALSE, GX_PTIDENTITY);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevKColorSel(lbl_803DCD90, GX_TEV_KCSEL_1_4);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_CPREV);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD88++;
    lbl_803DCD90++;
    lbl_803DCD8C++;
    lbl_803DCD84 = 0x27;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

void fn_8004DA54(char* p1)
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
    f32 s;
    f32 k;
    f32 t;
    Texture* tex24;
    m1 = lbl_802C1DC8;
    m2 = lbl_802C1DE0[0];
    tex24 = *(Texture**)(p1 + 0x24);
    if (tex24 != 0)
    {
        void* obj = textureGetGXTexObj(tex24);
        if (tex24->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, textureGetGXTexRegion(tex24), 2);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, GX_TEXMAP2);
        }
    }
    GXSetTexCoordGen2(GX_TEXCOORD3, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    newshadows_getReflectionScrollOffsets(&rx, &ry);
    mathSinCosf(Prepared_803DEAD8 * rx, &sv, &cv);
    s = mathCosf(Prepared_803DEAD8 * ry);
    k = lbl_803DEB08 * s + lbl_803DEB04;
    k = k * gHeatEffectScale;
    cv = cv * k;
    sv = sv * k;
    m1.v[0][0] = cv;
    m1.v[0][1] = sv;
    m1.v[1][0] = -sv;
    m1.v[1][1] = cv;
    mathSinCosf(Prepared_803DEAD8 * -ry, &sv, &cv);
    s = mathCosf(Prepared_803DEAD8 * rx);
    f31v = lbl_803DEADC * s + lbl_803DEADC;
    k = lbl_803DEB08 * s + lbl_803DEB04;
    k = k * gHeatEffectScale;
    cv = cv * k;
    sv = sv * k;
    m2.v[0][0] = cv;
    m2.v[0][1] = sv;
    m2.v[1][0] = -sv;
    m2.v[1][1] = cv;
    fn_8006C504(&tex2c);
    if (tex2c != 0)
    {
        GXTexObj* obj = textureGetGXTexObj(tex2c);
        if (tex2c->preloaded != 0)
        {
            GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(tex2c), 0);
        }
        else
        {
            GXLoadTexObj(obj, GX_TEXMAP0);
        }
    }
    {
        u8 b = *(u8*)(p1 + 0x2a);
        if (b != 0xff)
        {
            mapTextureScrollGetOffset(b, &tsx, &tsy);
            PSMTXTrans(mtx64, tsx, tsy, lbl_803DEACC);
        }
        else
        {
            PSMTXIdentity(mtx64);
        }
    }
    GXLoadTexMtxImm(mtx64, GX_PTTEXMTX2, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD0, GX_TG_MTX3x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX2);
    getNewShadowCausticTexture((u32*)&tex30);
    if (tex30 != 0)
    {
        void* obj = textureGetGXTexObj(tex30);
        if (tex30->preloaded != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, textureGetGXTexRegion(tex30), 1);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, GX_TEXMAP1);
        }
    }
    PSMTXScale(mtxf4, 0.9f, 0.9f, lbl_803DEAC8);
    mtxf4[1][3] = lbl_803DEB08 * ry;
    GXLoadTexMtxImm(mtxf4, GX_PTTEXMTX0, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD1, GX_TG_MTX3x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX0);
    GXSetIndTexOrder(GX_INDTEXSTAGE0, GX_TEXCOORD1, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE0, GX_ITS_1, GX_ITS_1);
    GXSetIndTexMtx(GX_ITM_0, m1.v, -2);
    GXSetIndTexMtx(GX_ITM_1, m2.v, -2);
    GXSetTevIndirect(1, 0, 0, 7, 1, 6, 6, 0, 0, 0);
    PSMTXScale(mtxc4, lbl_803DEB0C, *(f32*)&lbl_803DEB0C, lbl_803DEAC8);
    PSMTXRotRad(mtx94, 0x7a, lbl_803DEB10);
    PSMTXConcat(mtx94, mtxc4, mtxc4);
    t = lbl_803DEB14 * rx;
    mtxc4[0][3] = t;
    mtxc4[1][3] = t;
    GXLoadTexMtxImm(mtxc4, GX_PTTEXMTX1, GX_MTX3x4);
    GXSetTexCoordGen2(GX_TEXCOORD2, GX_TG_MTX3x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, GX_PTTEXMTX1);
    GXSetIndTexOrder(GX_INDTEXSTAGE1, GX_TEXCOORD2, GX_TEXMAP1);
    GXSetIndTexCoordScale(GX_INDTEXSTAGE1, GX_ITS_1, GX_ITS_1);
    GXSetTevIndirect(2, 1, 0, 7, 2, 0, 0, 1, 0, 0);
    gHeatEffectColor.r = lbl_803DEB18 * f31v;
    gHeatEffectColor.g = 0;
    gHeatEffectColor.b = 0;
    GXSetTevKColor(lbl_803DCD74, gHeatEffectColor);
    GXSetTevKAlphaSel(GX_TEVSTAGE0, lbl_803DCD6C);
    GXSetTevKColorSel(GX_TEVSTAGE1, lbl_803DCD70);
    GXSetTevDirect(GX_TEVSTAGE0);
    GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_RED, GX_CH_GREEN, GX_CH_BLUE, GX_CH_RED);
    GXSetTevOrder(GX_TEVSTAGE0, GX_TEXCOORD0, GX_TEXMAP2, GX_COLOR0A0);
    GXSetTevColorIn(GX_TEVSTAGE0, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    GXSetTevAlphaIn(GX_TEVSTAGE0, GX_CA_KONST, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevSwapMode(GX_TEVSTAGE0, GX_TEV_SWAP0, GX_TEV_SWAP3);
    GXSetTevColorOp(GX_TEVSTAGE0, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(GX_TEVSTAGE0, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_4, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
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
    lbl_803DCD88 = 4;
    lbl_803DCD90 = 3;
    lbl_803DCD8C = 3;
    lbl_803DCD80 = 0x49;
    lbl_803DCD7C = 2;
    lbl_803DCD6A = 3;
    lbl_803DCD69 = 4;
    lbl_803DCD68 = 2;
    lbl_803DCD74 = 1;
    lbl_803DCD70 = 0xd;
    lbl_803DCD6C = 0x1d;
}


extern f32 lbl_803DEB1C;
extern f32 lbl_803DEB20;
extern f32 lbl_803DEB24;
extern f32 lbl_803DEB28;
extern f32 SaveStart_803DEAD0;

void fn_8004E0FC(void)
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
    va = ((Vec*)&lbl_802C1D50)[4];
    vb = ((Vec*)&lbl_802C1D50)[5];
    vc = ((Vec*)&lbl_802C1D50)[6];
    vd = ((Vec*)&lbl_802C1D50)[7];
    im = *(IndTexMtx23*)((Vec*)&lbl_802C1D50 + 8);
    invView = Camera_GetInverseViewMatrix();
    PSMTXRotAxisRad(mf8, &va, lbl_803DEAC8);
    PSMTXRotAxisRad(mc8, &vb, lbl_803DEAC8);
    PSMTXRotAxisRad(m98, &vc, lbl_803DEAC8);
    PSMTXRotAxisRad(m68, &vd, lbl_803DEAC8);
    m1e8[0][0] = lbl_803DEB1C;
    m1e8[0][1] = 0.0f;
    m1e8[0][2] = 0.0f;
    m1e8[0][3] = SaveStart_803DEAD0 * (*(f32*)&lbl_803DEB20 * playerMapOffsetX);
    m1e8[1][0] = 0.0f;
    m1e8[1][1] = lbl_803DEB1C;
    m1e8[1][2] = 0.0f;
    m1e8[1][3] = 0.0f;
    m1e8[2][0] = 0.0f;
    m1e8[2][1] = 0.0f;
    m1e8[2][2] = lbl_803DEB1C;
    m1e8[2][3] = SaveStart_803DEAD0 * (lbl_803DEB20 * playerMapOffsetZ);
    m1b8[0][0] = lbl_803DEB24;
    m1b8[0][1] = 0.0f;
    m1b8[0][2] = 0.0f;
    m1b8[0][3] = lbl_803DEADC * (lbl_803DEB20 * playerMapOffsetX);
    m1b8[1][0] = 0.0f;
    m1b8[1][1] = lbl_803DEB24;
    m1b8[1][2] = 0.0f;
    m1b8[1][3] = 0.0f;
    m1b8[2][0] = 0.0f;
    m1b8[2][1] = 0.0f;
    m1b8[2][2] = lbl_803DEB24;
    m1b8[2][3] = lbl_803DEADC * (lbl_803DEB20 * playerMapOffsetZ);
    PSMTXConcat(m1e8, invView, m1e8);
    PSMTXConcat(mf8, m1e8, m1e8);
    m1e8[2][0] = 0.0f;
    m1e8[2][1] = 0.0f;
    m1e8[2][2] = 0.0f;
    m1e8[2][3] = lbl_803DEAC8;
    PSMTXConcat(m1b8, invView, m1b8);
    PSMTXConcat(mc8, m1b8, m1b8);
    m1b8[2][0] = 0.0f;
    m1b8[2][1] = 0.0f;
    m1b8[2][2] = 0.0f;
    m1b8[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(m1e8, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80);
    GXLoadTexMtxImm(m1b8, lbl_803DCD80 + 3, 0);
    GXSetTexCoordGen2(lbl_803DCD88 + 1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80 + 3);
    getNewShadowRingTexture(&tex1c);
    {
        int id = lbl_803DCD8C;
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
    GXSetIndTexMtx(GX_ITM_1, im.v, -1);
    GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88 + 2, lbl_803DCD8C + 1);
    m188[0][0] = lbl_803DEB20;
    m188[0][1] = 0.0f;
    m188[0][2] = 0.0f;
    m188[0][3] = lbl_803DEB20 * playerMapOffsetX + rx;
    m188[1][0] = 0.0f;
    m188[1][1] = lbl_803DEB20;
    m188[1][2] = 0.0f;
    m188[1][3] = 0.0f;
    m188[2][0] = 0.0f;
    m188[2][1] = 0.0f;
    m188[2][2] = lbl_803DEB20;
    m188[2][3] = lbl_803DEB20 * playerMapOffsetZ;
    PSMTXRotRad(m128, 0x79, lbl_803DEB28);
    PSMTXConcat(m128, m188, m188);
    PSMTXConcat(m188, invView, m188);
    PSMTXConcat(m98, m188, m188);
    m188[2][0] = 0.0f;
    m188[2][1] = 0.0f;
    m188[2][2] = 0.0f;
    m188[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(m188, lbl_803DCD80 + 6, 0);
    GXSetTexCoordGen2(lbl_803DCD88 + 2, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80 + 6);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 2, 2, 0, 0, 0, 0, 0);
    GXSetIndTexCoordScale(lbl_803DCD7C, 0, 0);
    GXSetIndTexOrder(lbl_803DCD7C + 1, lbl_803DCD88 + 3, lbl_803DCD8C + 1);
    m158[0][0] = lbl_803DEB20;
    m158[0][1] = 0.0f;
    m158[0][2] = 0.0f;
    m158[0][3] = lbl_803DEB20 * playerMapOffsetX;
    m158[1][0] = 0.0f;
    m158[1][1] = lbl_803DEB20;
    m158[1][2] = 0.0f;
    m158[1][3] = 0.0f;
    m158[2][0] = 0.0f;
    m158[2][1] = 0.0f;
    m158[2][2] = lbl_803DEB20;
    m158[2][3] = lbl_803DEB20 * playerMapOffsetZ + ry;
    PSMTXConcat(m158, invView, m158);
    PSMTXConcat(m68, m158, m158);
    m158[2][0] = 0.0f;
    m158[2][1] = 0.0f;
    m158[2][2] = 0.0f;
    m158[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(m158, lbl_803DCD80 + 9, 0);
    GXSetTexCoordGen2(lbl_803DCD88 + 3, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80 + 9);
    GXSetTevIndirect(lbl_803DCD90 + 1, lbl_803DCD7C + 1, 0, 2, 2, 0, 0, 1, 0, 0);
    GXSetIndTexCoordScale(lbl_803DCD7C + 1, 0, 0);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR0A0);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXA, GX_CC_CPREV);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, GX_COLOR0A0);
    GXSetTevColorIn(lbl_803DCD90 + 1, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXA, GX_CC_CPREV);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90 + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    getNewShadowCausticTexture((u32*)&tex18);
    {
        int id2 = lbl_803DCD8C + 1;
        if (tex18 != 0)
        {
            void* obj = textureGetGXTexObj(tex18);
            if (tex18->preloaded != 0)
            {
                GXLoadTexObjPreLoaded((GXTexObj*)obj, textureGetGXTexRegion(tex18), id2);
            }
            else
            {
                GXLoadTexObj((GXTexObj*)obj, id2);
            }
        }
    }
    lbl_803DCD88 = lbl_803DCD88 + 4;
    lbl_803DCD90 = lbl_803DCD90 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD80 = lbl_803DCD80 + 0xc;
    lbl_803DCD7C = lbl_803DCD7C + 2;
    lbl_803DCD6A += 2;
    lbl_803DCD69 += 4;
    lbl_803DCD68 += 2;
}

extern f32 lbl_803DEAC4;
extern f32 lbl_803DEB2C;

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
    im = lbl_802C1D68[0];
    iv = (f32(*)[4])Camera_GetInverseViewMatrix();
    mcc[0][0] = 0.0f;
    mcc[0][1] = 0.0f;
    mcc[0][2] = lbl_803DEAC4 / lbl_803DCD3C;
    mcc[0][3] = lbl_803DCD38;
    k = lbl_803DEAC4 / (lbl_803DCD44 - lbl_803DCD40);
    mcc[1][0] = k * iv[1][0];
    mcc[1][1] = k * iv[1][1];
    mcc[1][2] = k * iv[1][2];
    mcc[1][3] = k * iv[1][3] + -lbl_803DCD44 * k;
    mcc[2][0] = 0.0f;
    mcc[2][1] = 0.0f;
    mcc[2][2] = 0.0f;
    mcc[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(mcc, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80);
    GXSetTevKColor(lbl_803DCD74, *(GXColor*)fogColor);
    getNewShadowHeavyFogTexture(&tex20);
    {
        int id = lbl_803DCD8C;
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
    if (lbl_803DCD31 != 0)
    {
        newshadows_getReflectionScrollOffsets(&a, &b);
        b = b * lbl_803DEAE0;
        a = a * lbl_803DEB08;
        GXSetIndTexMtx(GX_ITM_1, im.v, -2);
        GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88 + 1, lbl_803DCD8C + 1);
        m9c[0][0] = lbl_803DCD34;
        m9c[0][1] = 0.0f;
        m9c[0][2] = 0.0f;
        m9c[0][3] = playerMapOffsetX * lbl_803DCD34 + a;
        m9c[1][0] = 0.0f;
        m9c[1][1] = lbl_803DCD34;
        m9c[1][2] = 0.0f;
        m9c[1][3] = 0.0f;
        m9c[2][0] = 0.0f;
        m9c[2][1] = 0.0f;
        m9c[2][2] = 0.0f;
        m9c[2][3] = lbl_803DEAC8;
        PSMTXRotRad(mrot, 0x7a, lbl_803DEB28);
        PSMTXConcat(mrot, m9c, m9c);
        PSMTXConcat(m9c, iv, m9c);
        GXLoadTexMtxImm(m9c, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80 + 3);
        GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 2, 2, 6, 6, 0, 0, 0);
        GXSetIndTexCoordScale(lbl_803DCD7C, 0, 0);
        GXSetIndTexOrder(lbl_803DCD7C + 1, lbl_803DCD88 + 2, lbl_803DCD8C + 1);
        m6c[0][0] = 0.0f;
        m6c[0][1] = 0.0f;
        m6c[0][2] = lbl_803DCD34;
        m6c[0][3] = playerMapOffsetZ * lbl_803DCD34 + b;
        m6c[1][0] = 0.0f;
        m6c[1][1] = lbl_803DCD34;
        m6c[1][2] = 0.0f;
        m6c[1][3] = 0.0f;
        m6c[2][0] = 0.0f;
        m6c[2][1] = 0.0f;
        m6c[2][2] = 0.0f;
        m6c[2][3] = lbl_803DEAC8;
        PSMTXRotRad(mrot, 0x78, lbl_803DEB2C);
        PSMTXConcat(mrot, m6c, m6c);
        PSMTXConcat(m6c, iv, m6c);
        GXLoadTexMtxImm(m6c, lbl_803DCD80 + 6, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 2, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80 + 6);
        GXSetTevIndirect(lbl_803DCD90 + 1, lbl_803DCD7C + 1, 0, 2, 2, 0, 0, 1, 0, 0);
        GXSetIndTexCoordScale(lbl_803DCD7C + 1, 0, 0);
        GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        lbl_803DCD30 = 1;
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
        GXSetTevColorIn(lbl_803DCD90 + 1, GX_CC_CPREV, GX_CC_KONST, GX_CC_TEXA, GX_CC_ZERO);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(lbl_803DCD90 + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        getNewShadowCausticTexture((u32*)&tex1c);
        {
            int id2 = lbl_803DCD8C + 1;
            if (tex1c != 0)
            {
                void* obj = textureGetGXTexObj(tex1c);
                if (tex1c->preloaded != 0)
                {
                    GXLoadTexObjPreLoaded((GXTexObj*)obj, textureGetGXTexRegion(tex1c), id2);
                }
                else
                {
                    GXLoadTexObj((GXTexObj*)obj, id2);
                }
            }
        }
        GXSetTevKColorSel(lbl_803DCD90 + 1, lbl_803DCD70);
        lbl_803DCD88 = lbl_803DCD88 + 3;
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 2;
        lbl_803DCD80 = lbl_803DCD80 + 9;
        lbl_803DCD7C = lbl_803DCD7C + 2;
        lbl_803DCD6A += 2;
        lbl_803DCD69 += 3;
        lbl_803DCD68 += 2;
    }
    else
    {
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
        GXSetTevColorIn(lbl_803DCD90, GX_CC_CPREV, GX_CC_KONST, GX_CC_TEXA, GX_CC_ZERO);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        lbl_803DCD30 = 1;
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        lbl_803DCD88 = lbl_803DCD88 + 1;
        lbl_803DCD90 = lbl_803DCD90 + 1;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 3;
        lbl_803DCD6A += 1;
        lbl_803DCD69 += 1;
    }
    lbl_803DCD74 = lbl_803DCD74 + 1;
    lbl_803DCD70 = lbl_803DCD70 + 1;
    lbl_803DCD6C = lbl_803DCD6C + 1;
}
void fn_8004EECC(u8* color)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_CPREV, GX_CC_ZERO, GX_CC_RASA, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}


void fn_8004EF9C(int* param)
{
    GXSetTevColor(GX_TEVREG1, *(GXColor*)param);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

void fn_8004F080(void)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevOrder(lbl_803DCD90 + 1, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(lbl_803DCD90 + 1, GX_CC_C1, GX_CC_ZERO, GX_CC_ZERO, GX_CC_CPREV);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90 + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevDirect(lbl_803DCD90 + 2);
    GXSetTevOrder(lbl_803DCD90 + 2, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevColorIn(lbl_803DCD90 + 2, GX_CC_CPREV, GX_CC_C2, GX_CC_RASA, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90 + 2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90 + 2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90 + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90 + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 3;
    lbl_803DCD6A += 3;
}

void fn_8004F2B0(void)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR_NULL);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}
extern int lbl_8030CEE0[];

extern f32 lbl_803DEB38;

extern f32 lbl_803DEB3C;

void fn_8004F380(f32 scale, int* colorIn, f32* pos)
{
    f32 matA[3][4];
    f32 matB[3][4];
    Texture* src;
    int id;
    f32 f;
    if (!(lbl_803DCD74 <= 3) || lbl_803DCD6A >= 0xc || lbl_803DCD69 >= 7)
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
        getNewShadowRadialTexture(&src);
        GXLoadTexMtxImm(matA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80);
        GXLoadTexMtxImm(matB, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80 + 3);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
        GXSetTevKColor(lbl_803DCD74, *(GXColor*)colorIn);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_KONST, GX_CC_TEXC, GX_CC_ZERO);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
        GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, GX_COLOR_NULL);
        GXSetTevColorIn(lbl_803DCD90 + 1, GX_CC_ZERO, GX_CC_C0, GX_CC_TEXC, GX_CC_C1);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(lbl_803DCD90 + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        id = lbl_803DCD8C;
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
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 6;
        lbl_803DCD69 += 2;
        lbl_803DCD6A += 2;
    }
}

void fn_8004F6D8(f32 scale, int* colorIn, f32* pos, u8* chanColor)
{
    f32 matA[3][4];
    f32 matB[3][4];
    Texture* src;
    int id;
    f32 f;
    if (!(lbl_803DCD74 <= 3) || lbl_803DCD6A >= 0xc || lbl_803DCD69 >= 7)
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
        getNewShadowRadialTexture(&src);
        GXLoadTexMtxImm(matA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80);
        GXLoadTexMtxImm(matB, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80 + 3);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
        GXSetTevKColor(lbl_803DCD74, *(GXColor*)colorIn);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_KONST, GX_CC_TEXC, GX_CC_ZERO);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
        GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, GX_COLOR_NULL);
        GXSetTevColorIn(lbl_803DCD90 + 1, GX_CC_ZERO, GX_CC_C0, GX_CC_TEXC, GX_CC_ZERO);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(lbl_803DCD90 + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        id = lbl_803DCD8C;
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
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 6;
        lbl_803DCD69 += 2;
        lbl_803DCD6A += 2;
    }
}


void fn_8004FA30(f32 scale, int* colorIn, f32* pos)
{
    f32 matA[3][4];
    f32 matB[3][4];
    Texture* src;
    int id;
    f32 f;
    if (!(lbl_803DCD74 <= 3) || lbl_803DCD6A >= 0x10 || lbl_803DCD69 >= 7)
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
        getNewShadowRadialTexture(&src);
        GXLoadTexMtxImm(matA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80);
        GXLoadTexMtxImm(matB, lbl_803DCD80 + 3, 0);
        GXSetTexCoordGen2(lbl_803DCD88 + 1, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80 + 3);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
        GXSetTevKColor(lbl_803DCD74, *(GXColor*)colorIn);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_KONST, GX_CC_TEXC, GX_CC_ZERO);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
        GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevDirect(lbl_803DCD90 + 1);
        GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C, GX_COLOR_NULL);
        GXSetTevColorIn(lbl_803DCD90 + 1, GX_CC_ZERO, GX_CC_C0, GX_CC_TEXC, GX_CC_CPREV);
        GXSetTevAlphaIn(lbl_803DCD90 + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
        GXSetTevSwapMode(lbl_803DCD90 + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        lbl_803DCD30 = 1;
        id = lbl_803DCD8C;
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
        lbl_803DCD90 = lbl_803DCD90 + 2;
        lbl_803DCD88 = lbl_803DCD88 + 2;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
        lbl_803DCD80 = lbl_803DCD80 + 6;
        lbl_803DCD69 += 2;
        lbl_803DCD6A += 2;
    }
}

void fn_8004FDA0(u8* texSrc, void* texMtx, u8* color)
{
    GXSetTevDirect(lbl_803DCD90);
    GXLoadTexMtxImm(texMtx, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
    GXSetTevKColorSel(lbl_803DCD90, GX_TEV_KCSEL_1_2);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_KONST, GX_CC_TEXA, GX_CC_CPREV, GX_CC_CPREV);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_SUB, GX_TB_ADDHALF, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    {
        int id = lbl_803DCD8C;
        if (texSrc != NULL)
        {
            void* obj = texSrc + 0x20;
            if (texSrc[0x48] != 0)
            {
                GXLoadTexObjPreLoaded((GXTexObj*)obj, *(GXTexRegion**)(texSrc + 0x40), id);
            }
            else
            {
                GXLoadTexObj((GXTexObj*)obj, id);
            }
        }
    }
    lbl_803DCD88++;
    lbl_803DCD90++;
    lbl_803DCD8C++;
    lbl_803DCD80 += 3;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

void textureFn_8004ff20(void* p1, f32* wpad0, void* wpad1, int wpad2)
{
    if (p1 != 0)
    {
        GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, GX_PTIDENTITY);
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR0A0);
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_RASC, GX_CC_RASA, GX_CC_TEXC);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        lbl_803DCD30 = 1;
        {
            int id = lbl_803DCD8C;
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
        lbl_803DCD88 = lbl_803DCD88 + 1;
        lbl_803DCD90 = lbl_803DCD90 + 1;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        lbl_803DCD69 += 1;
        lbl_803DCD6A += 1;
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR1A1);
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_RASC, GX_CC_RASA, GX_CC_CPREV);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        lbl_803DCD90 = lbl_803DCD90 + 1;
        lbl_803DCD6A += 1;
    }
}

void fn_8005011C(u8* objInst)
{
    u8* src;
    f32 mtx[3][4];
    u8* obj2;
    int id;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevDirect(lbl_803DCD90 + 2);
    GXSetTevDirect(lbl_803DCD90 + 3);
    PSMTXConcat((f32(*)[4])(objInst + 0x30), (f32(*)[4])Camera_GetInverseViewMatrix(), mtx);
    GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_IDENTITY, GX_FALSE, lbl_803DCD80);
    PSMTXConcat((f32(*)[4])objInst, (f32(*)[4])Camera_GetInverseViewMatrix(), mtx);
    GXLoadTexMtxImm(mtx, lbl_803DCD80 + 3, 0);
    GXSetTexCoordGen2(lbl_803DCD88 + 1, GX_TG_MTX3x4, GX_TG_POS, GX_IDENTITY, GX_FALSE, lbl_803DCD80 + 3);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
    GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, lbl_803DCD8C + 1, GX_COLOR_NULL);
    GXSetTevOrder(lbl_803DCD90 + 2, lbl_803DCD88 + 1, lbl_803DCD8C + 1, GX_COLOR_NULL);
    GXSetTevOrder(lbl_803DCD90 + 3, lbl_803DCD88 + 1, lbl_803DCD8C + 1, GX_COLOR_NULL);
    GXSetTevKColorSel(lbl_803DCD90 + 2, GX_TEV_KCSEL_1_4);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevColorIn(lbl_803DCD90 + 1, GX_CC_C0, GX_CC_TEXC, GX_CC_ONE, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90 + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90 + 1, GX_TEV_COMP_R8_GT, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG0);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevColorIn(lbl_803DCD90 + 2, GX_CC_C1, GX_CC_KONST, GX_CC_C0, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90 + 2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90 + 2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90 + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(lbl_803DCD90 + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevColorIn(lbl_803DCD90 + 3, GX_CC_C2, GX_CC_ZERO, GX_CC_C0, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90 + 3, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevSwapMode(lbl_803DCD90 + 3, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorOp(lbl_803DCD90 + 3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
    GXSetTevAlphaOp(lbl_803DCD90 + 3, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    getNewShadowRampTexture((u32*)&src);
    id = lbl_803DCD8C;
    if (src != NULL)
    {
        void* obj = src + 0x20;
        if (src[0x48] != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, *(GXTexRegion**)(src + 0x40), id);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, id);
        }
    }
    id = lbl_803DCD8C + 1;
    obj2 = *(u8**)(objInst + 0x60);
    if (obj2 != NULL)
    {
        void* obj = obj2 + 0x20;
        if (obj2[0x48] != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)obj, *(GXTexRegion**)(obj2 + 0x40), id);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)obj, id);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 6;
    lbl_803DCD88 = lbl_803DCD88 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 2;
    lbl_803DCD69 += 2;
    lbl_803DCD6A += 4;
    lbl_803DCD90 = lbl_803DCD90 + 4;
}


void fn_80050558(u8* texSrc, void* texMtx, int stageMode, int compMode, int variant)
{
    int inputSel;
    int texmap;
    GXSetTevDirect(lbl_803DCD90);
    GXLoadTexMtxImm(texMtx, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX3x4, GX_TG_POS, GX_PNMTX0, GX_FALSE, lbl_803DCD80);
    if (variant == 0 || variant == 2)
    {
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR0A0);
    }
    else
    {
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR1A1);
    }
    if (*(int*)&lbl_803DCD90 == 0)
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
            GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, inputSel, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (compMode == 3)
        {
            GXSetTevColorIn(lbl_803DCD90, inputSel, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (compMode == 1)
        {
            GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC, inputSel);
        }
        else if (variant == 0 || variant == 1)
        {
            GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_RASC, GX_CC_TEXC, inputSel);
        }
        else
        {
            GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXC, inputSel);
        }
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        if (compMode == 1)
        {
            GXSetTevColorOp(lbl_803DCD90, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
            GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        }
        else
        {
            GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
            GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
        }
    }
    else if (stageMode == 1)
    {
        if (compMode == 2)
        {
            GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_C2, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (compMode == 3)
        {
            GXSetTevColorIn(lbl_803DCD90, GX_CC_C2, GX_CC_ZERO, GX_CC_TEXC, GX_CC_ZERO);
        }
        else if (compMode == 1)
        {
            GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C2);
        }
        else if (variant == 0 || variant == 1)
        {
            GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_RASC, GX_CC_TEXC, GX_CC_C2);
        }
        else
        {
            GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_RASA, GX_CC_TEXC, GX_CC_C2);
        }
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
        GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
        if (compMode == 1)
        {
            GXSetTevColorOp(lbl_803DCD90, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
            GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
        }
        else
        {
            GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
            GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
        }
    }
    else
    {
        lbl_803DCD6B = 1;
        lbl_803DCD30 = 1;
        GXSetTevSwapModeTable(GX_TEV_SWAP1, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);
        GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP1, GX_TEV_SWAP1);
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ZERO, GX_CC_ONE);
        if (compMode == 3)
        {
            GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_RASA, GX_CA_TEXA, GX_CA_KONST);
            GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_SUB, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        }
        else
        {
            GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_RASA, GX_CA_TEXA, GX_CA_ZERO);
            GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
        }
        GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    }
    texmap = lbl_803DCD8C;
    if (texSrc != NULL)
    {
        u8* tex = texSrc + 0x20;
        if (texSrc[0x48] != 0)
        {
            GXLoadTexObjPreLoaded((GXTexObj*)tex, *(GXTexRegion**)(texSrc + 0x40), texmap);
        }
        else
        {
            GXLoadTexObj((GXTexObj*)tex, texmap);
        }
    }
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}





void fn_80050A28(int scale)
{
    f32 m[3][4];
    PSMTXScale(m, scale, scale, 0.0f);
    m[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(m, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX2x4, GX_TG_TEX0, GX_IDENTITY, GX_FALSE, lbl_803DCD80);
    lbl_803DCD80 += 3;
    lbl_803DCD88++;
    lbl_803DCD69++;
}

int textureFn_80050ad8(void* p1, int p2, u8 p3, u32 p4)
{
    struct piIndMtx indmtx;
    f32 mtx[3][4];
    f32 v;
    int result;
    int texmap;
    int t;
    indmtx = lbl_802C1D50;
    t = lbl_803DB5E8 & 1;
    result = 0;
    if (t == 0)
    {
        return 0;
    }
    GXSetIndTexMtx(GX_ITM_0, indmtx.m, 0);
    GXSetIndTexOrder(lbl_803DCD7C, lbl_803DCD88 + p2, lbl_803DCD8C);
    if (p4 != 0)
    {
        void* texptr;
        u32 div;
        int p2v = (p3 & 0xf) * 4 + 1;
        texptr = textureIdxToPtr(p4);
        div = (u32) ((Texture*)texptr)->width / (u32)(*(u16*)((char*)p1 + 0xa) * p2v);
        if (div != 0)
        {
            GXSetIndTexCoordScale(lbl_803DCD7C, lbl_8030CEE0[div - 1], lbl_8030CEE0[div - 1]);
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
    v = lbl_803DEADC * (lbl_803DEB38 * ((f32)(s32)((p3 & 0xf0) >> 4) / lbl_803DEB3C - lbl_803DEAC8));
    PSMTXScale(mtx, v, v, 0.0f);
    mtx[2][3] = lbl_803DEAC8;
    GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX2x4, GX_TG_BINRM, GX_TEXMTX0, GX_FALSE, lbl_803DCD80);
    GXSetTexCoordGen2(lbl_803DCD88 + 1, GX_TG_MTX2x4, GX_TG_TANGENT, GX_TEXMTX0, GX_FALSE, lbl_803DCD80);
    GXSetTevIndirect(lbl_803DCD90, lbl_803DCD7C, 0, 3, 5, 6, 6, 0, 0, 0);
    GXSetTevIndirect(lbl_803DCD90 + 1, lbl_803DCD7C, 0, 3, 9, 6, 6, 1, 0, 0);
    GXSetTevIndirect(lbl_803DCD90 + 2, lbl_803DCD7C, 0, 0, 0, 0, 0, 1, 0, 0);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, (lbl_803DCD8C + 1) | 0x100, GX_COLOR_NULL);
    GXSetTevOp(lbl_803DCD90, GX_PASSCLR);
    GXSetTevOrder(lbl_803DCD90 + 1, lbl_803DCD88 + 1, (lbl_803DCD8C + 1) | 0x100, GX_COLOR_NULL);
    GXSetTevOp(lbl_803DCD90 + 1, GX_PASSCLR);
    texmap = lbl_803DCD8C;
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
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD7C = lbl_803DCD7C + 1;
    lbl_803DCD88 = lbl_803DCD88 + 2;
    lbl_803DCD90 = lbl_803DCD90 + 2;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A += 2;
    lbl_803DCD68 += 1;
    lbl_803DCD69 += 2;
    return result;
}

extern int lbl_8030CEE0[];
extern f32 lbl_803DEB38;
extern f32 lbl_803DEB3C;




void gxTextureFn_80050e28(u8 mode)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (mode != 0)
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_CPREV, GX_CC_C1, GX_CC_C2);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_CPREV, GX_CC_RASC, GX_CC_C2);
    }
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_APREV);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

void fn_80050F2C(void)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_C2, GX_CC_TEXC, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}


void fn_80050FF4(u8 mode)
{
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    if (mode != 0)
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_APREV, GX_CC_C1, GX_CC_C2);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_APREV, GX_CC_RASC, GX_CC_C2);
    }
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}
extern f32 lbl_803DEB40;

void fn_800510F0(void* p1, u8 flag2, u8 flag3)
{
    f32 mtxB[3][4];
    f32 mtxA[3][4];
    int texmap;
    if (lbl_803DCD68 == 0)
    {
        GXSetTevDirect(lbl_803DCD90);
    }
    if (flag2 != 0)
    {
        GXSetTevIndRepeat(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88 - 1, lbl_803DCD8C, GX_COLOR_NULL);
    }
    else
    {
        PSMTXScale(mtxA, lbl_803DEB40, *(f32*)&lbl_803DEB40, 0.0f);
        PSMTXTrans(mtxB, lbl_803DEADC, *(f32*)&lbl_803DEADC, lbl_803DEAC8);
        PSMTXConcat(mtxB, mtxA, mtxA);
        GXLoadTexMtxImm(mtxA, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, lbl_803DCD80);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR0A0);
        lbl_803DCD80 = lbl_803DCD80 + 3;
        lbl_803DCD88 = lbl_803DCD88 + 1;
        lbl_803DCD69 += 1;
    }
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_TEXA, GX_CA_A2, GX_CA_ZERO);
    if (flag2 != 0)
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_TEXC, GX_CC_C1, GX_CC_ZERO);
    }
    else
    {
        GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_TEXC, GX_CC_RASC, GX_CC_ZERO);
    }
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG2);
    if ((flag3 & 1) != 0)
    {
        GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_BLUE, GX_CH_BLUE, GX_CH_BLUE, GX_CH_GREEN);
    }
    else
    {
        GXSetTevSwapModeTable(GX_TEV_SWAP3, GX_CH_RED, GX_CH_RED, GX_CH_RED, GX_CH_GREEN);
    }
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP3);
    texmap = lbl_803DCD8C;
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
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A += 1;
}






void textureFn_80051348(void* p1, u8 p2)
{
    f32 mtxB[3][4];
    f32 mtxA[3][4];
    u8 buf[3];
    int out_c;
    int out_8;
    int texmap;
    PSMTXScale(mtxA, lbl_803DEB40, *(f32*)&lbl_803DEB40, 0.0f);
    PSMTXTrans(mtxB, lbl_803DEADC, *(f32*)&lbl_803DEADC, lbl_803DEAC8);
    PSMTXConcat(mtxB, mtxA, mtxA);
    GXLoadTexMtxImm(mtxA, lbl_803DCD80, 0);
    buf[0] = p2;
    buf[1] = p2;
    buf[2] = p2;
    gxTextureFn_8004bf88(buf, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(lbl_803DCD90, out_c);
    GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX2x4, GX_TG_NRM, GX_TEXMTX0, GX_FALSE, lbl_803DCD80);
    if (lbl_803DCD68 == 0)
    {
        GXSetTevDirect(lbl_803DCD90);
    }
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, GX_COLOR0A0);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_TEXC, GX_CC_KONST, GX_CC_RASC);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVREG1);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    texmap = lbl_803DCD8C;
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
    lbl_803DCD80 = lbl_803DCD80 + 3;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A += 1;
    lbl_803DCD69 += 1;
}



void fn_80051528(void* p1, void* mtx)
{
    u8 buf[3];
    int out_c;
    int out_8;
    objGetColor(0, &buf[0], &buf[1], &buf[2]);
    if (mtx != 0)
    {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX2x4, lbl_803DCD78, GX_IDENTITY, GX_FALSE, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    }
    else
    {
        GXSetTexCoordGen2(lbl_803DCD88, GX_TG_MTX2x4, lbl_803DCD78, GX_IDENTITY, GX_FALSE, GX_PTIDENTITY);
    }
    gxTextureFn_8004bf88(buf, 1, 0, &out_c, &out_8);
    GXSetTevKColorSel(lbl_803DCD90, out_c);
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(lbl_803DCD90, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(lbl_803DCD90, GX_CC_ZERO, GX_CC_KONST, GX_CC_RASC, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    lbl_803DCD30 = 1;
    GXSetTevDirect(lbl_803DCD90 + 1);
    GXSetTevOrder(lbl_803DCD90 + 1, GX_TEXCOORD_NULL, GX_TEXMAP_NULL, GX_COLOR0A0);
    GXSetTevSwapMode(lbl_803DCD90 + 1, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(lbl_803DCD90 + 1, GX_CC_CPREV, GX_CC_RASC, GX_CC_RASA, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90 + 1, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO);
    GXSetTevColorOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90 + 1, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevDirect(lbl_803DCD90 + 2);
    GXSetTevOrder(lbl_803DCD90 + 2, lbl_803DCD88, lbl_803DCD8C, GX_COLOR_NULL);
    GXSetTevSwapMode(lbl_803DCD90 + 2, GX_TEV_SWAP0, GX_TEV_SWAP0);
    GXSetTevColorIn(lbl_803DCD90 + 2, GX_CC_ZERO, GX_CC_CPREV, GX_CC_TEXC, GX_CC_ZERO);
    GXSetTevAlphaIn(lbl_803DCD90 + 2, GX_CA_ZERO, GX_CA_ZERO, GX_CA_ZERO, GX_CA_TEXA);
    GXSetTevColorOp(lbl_803DCD90 + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    GXSetTevAlphaOp(lbl_803DCD90 + 2, GX_TEV_ADD, GX_TB_ZERO, GX_CS_SCALE_1, GX_TRUE, GX_TEVPREV);
    {
        int id = lbl_803DCD8C;
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
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 3;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A += 3;
    lbl_803DCD69 += 1;
}


GXTexObj lbl_803779A0;

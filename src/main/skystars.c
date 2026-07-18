#include "main/newclouds_state.h"
#include "main/object_api.h"
#include "main/newclouds.h"
#include "track/intersect_api.h"
#include "main/shader_api.h"
#include "main/pi_dolphin_api.h"
#include "main/objtexture.h"
#include "main/sky_interface.h"
#include "main/mm.h"
#include "main/camera.h"
#include "main/texture.h"
#include "main/rcp_dolphin_api.h"
#include "dolphin/gx/GXDispList.h"
#include "dolphin/gx/GXEnum.h"
#include "dolphin/os/OSCache.h"
#include "main/sky_state.h"
#include "dolphin/gx/GXLegacy.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/lightmap_api.h"
#include "main/render_mode_api.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "stdlib.h"

u8 gNewCloudStarsInitialized;
char* gNewCloudStarTextureB;
char* gNewCloudStarTextureA;

u8 gNewCloudStarAlphaRanges[8] = {0xA0, 0xAA, 0x82, 0x8C, 0x64, 0x6E, 0x50, 0x5A};
int gNewCloudStarFogColor = 0;

static inline void starFifoPosition3s16(s16 x, s16 y, s16 z)
{
    (*(PPCWGPipe2*)&GXWGFifo).s16 = x;
    (*(PPCWGPipe2*)&GXWGFifo).s16 = y;
    (*(PPCWGPipe2*)&GXWGFifo).s16 = z;
}

u8 gNewCloudStarColorRanges[24] = {
    0xD0, 0xFF, 0x80, 0xA0, 0x80, 0xA0, 0x80, 0xA0, 0x80, 0xA0, 0xD0, 0xFF,
    0xD0, 0xFF, 0xA0, 0xD0, 0x80, 0xA0, 0xD0, 0xFF, 0x80, 0xA0, 0xD0, 0xFF,
};
u16 gNewCloudStarDisplayListSizes[0x5C];
void* gNewCloudStarDisplayLists[0x5C];

#define NEWCLOUD_TEXTURE_STAR_A 0xc21 /* gNewCloudStarTextureA */
#define NEWCLOUD_TEXTURE_STAR_B 0xc22 /* gNewCloudStarTextureB */

void drawSkyStars(void)
{
    int timeOk;
    int start;
    int i;
    int alpha;
    int div;
    int red;
    int green;
    int blue;
    int a;
    u8* colRange;
    FogColor color;
    f32 t;

    timeOk = (*gSkyInterface)->getSunPosition(&t);
    if (isOvercastByteLegacy() != 0)
    {
        if (timeOk != 0)
        {
            if (t > 4000.0f)
            {
                alpha = 0xff;
            }
            else
            {
                alpha = (255.0f * (t / 4000.0f));
            }
        }
        else
        {
            if (t > 12000.0f || 0.0f == t)
            {
                return;
            }
            alpha = (255.0f - 255.0f * (t / 12000.0f));
        }
        start = 0x4c;
        div = 2;
    }
    else
    {
        start = 0;
        alpha = 0xff;
        div = 1;
    }
    GXSetCullMode(GX_CULL_NONE);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    textureSetupFn_800799c0();
    fn_800790AC();
    textRenderSetupFn_80079804();
    gxBlendFn_800789ac();
    color = *(FogColor*)&gNewCloudStarFogColor;
    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, color);
    Camera_UpdateViewMatrices();
    GXLoadPosMtxImm(Camera_GetViewRotationMatrix(), GX_PNMTX0);
    GXSetCurrentMtx(GX_PNMTX0);
    for (i = start; i < 0x5c; i++)
    {
        colRange = &gNewCloudStarColorRanges[(i & 3) * 6];
        red = randomGetRange(colRange[0], colRange[1]);
        green = randomGetRange(colRange[2], colRange[3]);
        blue = randomGetRange(colRange[4], colRange[5]);
        if (i < 0x4c)
        {
            colRange = &gNewCloudStarAlphaRanges[((i & 0xc) >> 2) * 2];
            a = (alpha * randomGetRange(colRange[0], colRange[1])) >> 8;
        }
        else
        {
            a = alpha;
        }
        _gxSetTevColor2((u8)red, (u8)green, (u8)blue, (u8)a);
        if (i == 0x4c)
        {
            selectTexture((Texture*)gNewCloudStarTextureA, 0);
            textureSetupFn_800799c0();
            textRenderSetupFn_800795e8();
            textRenderSetupFn_80079804();
        }
        else if (i == 0x54)
        {
            selectTexture((Texture*)gNewCloudStarTextureB, 0);
        }
        if (i < 0x4c)
        {
            GXSetPointSize((u8)randomGetRange(0xc, 0xc), GX_TO_ONE);
        }
        else if (i & 4)
        {
            GXSetPointSize((u8)(randomGetRange(0x30, 0x3c) / div), GX_TO_ONE);
        }
        else
        {
            GXSetPointSize((u8)(randomGetRange(0x48, 0x60) / div), GX_TO_ONE);
        }
        GXCallDisplayList(gNewCloudStarDisplayLists[i], gNewCloudStarDisplayListSizes[i]);
    }
}

static const f32 gNewCloudStarRadius[1] = {5000.0f};
static const f32 gNewCloudStarAxisThreshold[1] = {3750.0f};

void titleScreenDrawFn_80093db4(void)
{
    int k;
    int j;
    f32* constellation;
    f32* cp;
    int i;
    int idx;
    f32 v[3];
    f32 mtx1[12];
    f32 mtx2[12];

    GXSetMisc(1, 0);
    testAndSet_onlyUseHeap3(0);
    constellation = mmAlloc(0x4b0, 0x7f7f7fff, 0);
    testAndSet_onlyUseHeap3(1);
    for (i = 0, cp = constellation; i < 0x64; i++)
    {
        do
        {
            v[0] = (int)
            randomGetRange(-5000, 5000);
            v[1] = (int)
            randomGetRange(-5000, 5000);
            v[2] = (int)
            randomGetRange(-5000, 5000);
        }
        while (0.0f == v[0] && 0.0f == v[1] && 0.0f == v[2]);
        PSVECNormalize(v, v);
        PSVECScale(v, v, gNewCloudStarRadius[0]);
        cp[0] = v[0];
        cp[1] = v[1];
        cp[2] = v[2];
        cp += 3;
    }
    gNewCloudStarsInitialized = 1;
    gNewCloudStarTextureA = textureLoadAsset(NEWCLOUD_TEXTURE_STAR_A);
    gNewCloudStarTextureB = textureLoadAsset(NEWCLOUD_TEXTURE_STAR_B);
    for (k = 0; k < 0x5c; k++)
    {
        gNewCloudStarDisplayLists[k] = mmAlloc(0x220, 0x7f7f7fff, 0);
        DCInvalidateRange(gNewCloudStarDisplayLists[k], 0x220);
        GXBeginDisplayList(gNewCloudStarDisplayLists[k], 0x220);
        GXResetWriteGatherPipe();
        GXBegin(GX_POINTS, GX_VTXFMT0, 0x32);
        for (j = 0; j < 0x32; j++)
        {
            if (randomGetRange(0, 9) < 5)
            {
                do
                {
                    v[0] = (int)
                    randomGetRange(-5000, 5000);
                    v[1] = (int)
                    randomGetRange(-5000, 5000);
                    v[2] = (int)
                    randomGetRange(-5000, 5000);
                }
                while (0.0f == v[0] && 0.0f == v[1] && 0.0f == v[2]);
                PSVECNormalize(v, v);
                PSVECScale(v, v, gNewCloudStarRadius[0]);
            }
            else
            {
                f64 ax;
                idx = randomGetRange(0, 0x63);
                v[0] = constellation[idx * 3];
                v[1] = constellation[idx * 3 + 1];
                v[2] = constellation[idx * 3 + 2];
                ax = __fabs(v[0]);
                if (ax > gNewCloudStarAxisThreshold[0])
                {
                    PSMTXRotRad(mtx1, 0x79,
                                (0.015f *
                                    (2.0f *
                                        (3.142f *
                                            randomGetRange(-0x8000, 0x8000))
                    )
                    )
                    /
                    32768.0f
                    )
                    ;
                    PSMTXRotRad(mtx2, 0x7a,
                                (0.015f *
                                    (2.0f *
                                        (3.142f *
                                            randomGetRange(-0x8000, 0x8000))
                    )
                    )
                    /
                    32768.0f
                    )
                    ;
                }
                else
                {
                    f64 ay = __fabs(v[1]);
                    if (ay > gNewCloudStarAxisThreshold[0])
                    {
                        PSMTXRotRad(mtx1, 0x78,
                                    (0.015f *
                                        (2.0f *
                                            (3.142f *
                                                randomGetRange(-0x8000, 0x8000))
                        )
                        )
                        /
                        32768.0f
                        )
                        ;
                        PSMTXRotRad(mtx2, 0x7a,
                                    (0.015f *
                                        (2.0f *
                                            (3.142f *
                                                randomGetRange(-0x8000, 0x8000))
                        )
                        )
                        /
                        32768.0f
                        )
                        ;
                    }
                    else
                    {
                        PSMTXRotRad(mtx1, 0x78,
                                    (0.015f *
                                        (2.0f *
                                            (3.142f *
                                                randomGetRange(-0x8000, 0x8000))
                        )
                        )
                        /
                        32768.0f
                        )
                        ;
                        PSMTXRotRad(mtx2, 0x79,
                                    (0.015f *
                                        (2.0f *
                                            (3.142f *
                                                randomGetRange(-0x8000, 0x8000))
                        )
                        )
                        /
                        32768.0f
                        )
                        ;
                    }
                }
                PSMTXConcat((void*)mtx2, (void*)mtx1, (void*)mtx1);
                PSMTXMultVecSR(mtx1, v, v);
            }
            starFifoPosition3s16(v[0], v[1], v[2]);
            GXWGFifo.s16 = 0;
            GXWGFifo.s16 = 0;
        }
        gNewCloudStarDisplayListSizes[k] = GXEndDisplayList();
    }
    mm_free(constellation);
    GXSetMisc(1, 8);
}

/* descriptor/ptr table auto 0x8030f788-0x8030f7b0 */
u32 lbl_8030F788[10] = { 0x00000000, 0x00000000, 0x00000000, 0x00050000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };

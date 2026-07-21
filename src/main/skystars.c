#include "main/newclouds_state.h"
#include "main/object_api.h"
#include "main/newclouds.h"
#include "track/intersect_api.h"
#include "track/intersect_render_setup_api.h"
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
#include "dolphin/mtx.h"
#include "main/lightmap_api.h"
#include "main/render_mode_api.h"
#include "main/vecmath.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "stdlib.h"

u8 gNewCloudStarsInitialized;
Texture* gNewCloudStarTextureB;
Texture* gNewCloudStarTextureA;

typedef struct SkyStarAlphaRange
{
    u8 min;
    u8 max;
} SkyStarAlphaRange;

typedef struct SkyStarColorRange
{
    u8 minRed;
    u8 maxRed;
    u8 minGreen;
    u8 maxGreen;
    u8 minBlue;
    u8 maxBlue;
} SkyStarColorRange;

STATIC_ASSERT(sizeof(SkyStarAlphaRange) == 2);
STATIC_ASSERT(sizeof(SkyStarColorRange) == 6);

enum
{
    SKY_STAR_COLOR_RANGE_COUNT = 4,
    SKY_STAR_DISPLAY_LIST_COUNT = 0x5C,
    SKY_STAR_SMALL_DISPLAY_LIST_COUNT = 0x4C,
    SKY_STAR_TEXTURE_B_LIST_INDEX = 0x54,
    SKY_STAR_CONSTELLATION_POINT_COUNT = 0x64,
    SKY_STAR_POINTS_PER_DISPLAY_LIST = 0x32,
    SKY_STAR_DISPLAY_LIST_BUFFER_SIZE = 0x220
};

SkyStarAlphaRange gNewCloudStarAlphaRanges[SKY_STAR_COLOR_RANGE_COUNT] = {
    {0xA0, 0xAA}, {0x82, 0x8C}, {0x64, 0x6E}, {0x50, 0x5A}
};
FogColor gNewCloudStarFogColor = {0};

static inline void starFifoPosition3s16(s16 x, s16 y, s16 z)
{
    (*(PPCWGPipe2*)&GXWGFifo).s16 = x;
    (*(PPCWGPipe2*)&GXWGFifo).s16 = y;
    (*(PPCWGPipe2*)&GXWGFifo).s16 = z;
}

SkyStarColorRange gNewCloudStarColorRanges[SKY_STAR_COLOR_RANGE_COUNT] = {
    {0xD0, 0xFF, 0x80, 0xA0, 0x80, 0xA0},
    {0x80, 0xA0, 0x80, 0xA0, 0xD0, 0xFF},
    {0xD0, 0xFF, 0xA0, 0xD0, 0x80, 0xA0},
    {0xD0, 0xFF, 0x80, 0xA0, 0xD0, 0xFF},
};
u16 gNewCloudStarDisplayListSizes[SKY_STAR_DISPLAY_LIST_COUNT];
u8* gNewCloudStarDisplayLists[SKY_STAR_DISPLAY_LIST_COUNT];

#define NEWCLOUD_TEXTURE_STAR_A 0xc21 /* gNewCloudStarTextureA */
#define NEWCLOUD_TEXTURE_STAR_B 0xc22 /* gNewCloudStarTextureB */

void drawSkyStars(void)
{
    int timeOk;
    int firstDisplayList;
    int i;
    int alpha;
    int pointSizeDivisor;
    int red;
    int green;
    int blue;
    int starAlpha;
    SkyStarColorRange* colorRange;
    SkyStarAlphaRange* alphaRange;
    FogColor color;
    f32 sunTransitionTime;

    timeOk = (*gSkyInterface)->getSunPosition(&sunTransitionTime);
    if (isOvercast() != 0)
    {
        if (timeOk != 0)
        {
            if (sunTransitionTime > 4000.0f)
            {
                alpha = 0xff;
            }
            else
            {
                alpha = (255.0f * (sunTransitionTime / 4000.0f));
            }
        }
        else
        {
            if (sunTransitionTime > 12000.0f || 0.0f == sunTransitionTime)
            {
                return;
            }
            alpha = (255.0f - 255.0f * (sunTransitionTime / 12000.0f));
        }
        firstDisplayList = SKY_STAR_SMALL_DISPLAY_LIST_COUNT;
        pointSizeDivisor = 2;
    }
    else
    {
        firstDisplayList = 0;
        alpha = 0xff;
        pointSizeDivisor = 1;
    }
    GXSetCullMode(GX_CULL_NONE);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    textureSetupFn_800799c0();
    gxTevAddColor1Stage();
    textRenderSetupFn_80079804();
    gxBlendFn_800789ac();
    color = gNewCloudStarFogColor;
    GXSetFog(GX_FOG_NONE, 0.0f, 0.0f, 0.0f, 0.0f, color);
    Camera_UpdateViewMatrices();
    GXLoadPosMtxImm(Camera_GetViewRotationMatrix(), GX_PNMTX0);
    GXSetCurrentMtx(GX_PNMTX0);
    for (i = firstDisplayList; i < SKY_STAR_DISPLAY_LIST_COUNT; i++)
    {
        colorRange = &gNewCloudStarColorRanges[i & 3];
        red = randomGetRange(colorRange->minRed, colorRange->maxRed);
        green = randomGetRange(colorRange->minGreen, colorRange->maxGreen);
        blue = randomGetRange(colorRange->minBlue, colorRange->maxBlue);
        if (i < SKY_STAR_SMALL_DISPLAY_LIST_COUNT)
        {
            alphaRange = &gNewCloudStarAlphaRanges[(i & 0xc) >> 2];
            starAlpha = (alpha * randomGetRange(alphaRange->min, alphaRange->max)) >> 8;
        }
        else
        {
            starAlpha = alpha;
        }
        _gxSetTevColor2((u8)red, (u8)green, (u8)blue, (u8)starAlpha);
        if (i == SKY_STAR_SMALL_DISPLAY_LIST_COUNT)
        {
            selectTexture(gNewCloudStarTextureA, 0);
            textureSetupFn_800799c0();
            textRenderSetupFn_800795e8();
            textRenderSetupFn_80079804();
        }
        else if (i == SKY_STAR_TEXTURE_B_LIST_INDEX)
        {
            selectTexture(gNewCloudStarTextureB, 0);
        }
        if (i < SKY_STAR_SMALL_DISPLAY_LIST_COUNT)
        {
            GXSetPointSize((u8)randomGetRange(0xc, 0xc), GX_TO_ONE);
        }
        else if (i & 4)
        {
            GXSetPointSize((u8)(randomGetRange(0x30, 0x3c) / pointSizeDivisor), GX_TO_ONE);
        }
        else
        {
            GXSetPointSize((u8)(randomGetRange(0x48, 0x60) / pointSizeDivisor), GX_TO_ONE);
        }
        GXCallDisplayList(gNewCloudStarDisplayLists[i], gNewCloudStarDisplayListSizes[i]);
    }
}

void initSkyStars(void)
{
    int displayListIndex;
    int pointIndex;
    Vec3f* constellation;
    Vec3f* constellationPoint;
    int constellationPointIndex;
    int constellationIndex;
    Vec3f starPosition;
    Mtx rotationA;
    Mtx rotationB;

    GXSetMisc(1, 0);
    testAndSet_onlyUseHeap3(0);
    constellation = mmAlloc(SKY_STAR_CONSTELLATION_POINT_COUNT * sizeof(Vec3f), 0x7f7f7fff, 0);
    testAndSet_onlyUseHeap3(1);
    for (constellationPointIndex = 0, constellationPoint = constellation;
         constellationPointIndex < SKY_STAR_CONSTELLATION_POINT_COUNT;
         constellationPointIndex++)
    {
        do
        {
            starPosition.x = (int)
            randomGetRange(-5000, 5000);
            starPosition.y = (int)
            randomGetRange(-5000, 5000);
            starPosition.z = (int)
            randomGetRange(-5000, 5000);
        }
        while (0.0f == starPosition.x && 0.0f == starPosition.y && 0.0f == starPosition.z);
        PSVECNormalize(&starPosition, &starPosition);
        PSVECScale(&starPosition, &starPosition, 5000.0f);
        constellationPoint->x = starPosition.x;
        constellationPoint->y = starPosition.y;
        constellationPoint->z = starPosition.z;
        constellationPoint++;
    }
    gNewCloudStarsInitialized = 1;
    gNewCloudStarTextureA = textureLoadAsset(NEWCLOUD_TEXTURE_STAR_A);
    gNewCloudStarTextureB = textureLoadAsset(NEWCLOUD_TEXTURE_STAR_B);
    for (displayListIndex = 0; displayListIndex < SKY_STAR_DISPLAY_LIST_COUNT; displayListIndex++)
    {
        gNewCloudStarDisplayLists[displayListIndex] =
            mmAlloc(SKY_STAR_DISPLAY_LIST_BUFFER_SIZE, 0x7f7f7fff, 0);
        DCInvalidateRange(gNewCloudStarDisplayLists[displayListIndex], SKY_STAR_DISPLAY_LIST_BUFFER_SIZE);
        GXBeginDisplayList(gNewCloudStarDisplayLists[displayListIndex], SKY_STAR_DISPLAY_LIST_BUFFER_SIZE);
        GXResetWriteGatherPipe();
        GXBegin(GX_POINTS, GX_VTXFMT0, SKY_STAR_POINTS_PER_DISPLAY_LIST);
        for (pointIndex = 0; pointIndex < SKY_STAR_POINTS_PER_DISPLAY_LIST; pointIndex++)
        {
            if (randomGetRange(0, 9) < 5)
            {
                do
                {
                    starPosition.x = (int)
                    randomGetRange(-5000, 5000);
                    starPosition.y = (int)
                    randomGetRange(-5000, 5000);
                    starPosition.z = (int)
                    randomGetRange(-5000, 5000);
                }
                while (0.0f == starPosition.x && 0.0f == starPosition.y && 0.0f == starPosition.z);
                PSVECNormalize(&starPosition, &starPosition);
                PSVECScale(&starPosition, &starPosition, 5000.0f);
            }
            else
            {
                f64 ax;
                constellationIndex = randomGetRange(0, SKY_STAR_CONSTELLATION_POINT_COUNT - 1);
                starPosition.x = constellation[constellationIndex].x;
                starPosition.y = constellation[constellationIndex].y;
                starPosition.z = constellation[constellationIndex].z;
                ax = __fabs(starPosition.x);
                if (ax > 3750.0f)
                {
                    PSMTXRotRad(rotationA, 0x79,
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
                    PSMTXRotRad(rotationB, 0x7a,
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
                    f64 ay = __fabs(starPosition.y);
                    if (ay > 3750.0f)
                    {
                        PSMTXRotRad(rotationA, 0x78,
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
                        PSMTXRotRad(rotationB, 0x7a,
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
                        PSMTXRotRad(rotationA, 0x78,
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
                        PSMTXRotRad(rotationB, 0x79,
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
                PSMTXConcat(rotationB, rotationA, rotationA);
                PSMTXMultVecSR(rotationA, &starPosition, &starPosition);
            }
            starFifoPosition3s16(starPosition.x, starPosition.y, starPosition.z);
            GXWGFifo.s16 = 0;
            GXWGFifo.s16 = 0;
        }
        gNewCloudStarDisplayListSizes[displayListIndex] = GXEndDisplayList();
    }
    mm_free(constellation);
    GXSetMisc(1, 8);
}

/* descriptor/ptr table auto 0x8030f788-0x8030f7b0 */
u32 lbl_8030F788[10] = { 0x00000000, 0x00000000, 0x00000000, 0x00050000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };

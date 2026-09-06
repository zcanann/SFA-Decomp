#define OBJHITS_STATE_INDEX_S8
#define TEX_SETSHADER_U8
#include "main/newshadows.h"
#include "main/map_block.h"
#include "main/texture.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_depth_read_api.h"
#include "track/intersect_render_setup_api.h"
#include "main/hud_visibility_api.h"
#include "main/lightmap_api.h"
#include "main/shader_api.h"
#include "main/debug.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_float_helpers.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/frustum.h"
#include "main/asset_load.h"
#include "game/objects/object.h"
#include "main/gameloop_api.h"
#include "sys/objects.h"
#include "main/mm.h"
#include "main/model_light.h"
#include "main/model.h"
#include "main/model_render_instrs_api.h"
#include "main/objHitReact.h"
#include "main/objhits.h"
#undef OBJHITS_STATE_INDEX_S8
#include "main/objtype.h"
#include "main/object_transform.h"
#include "main/vecmath.h"
#include "dolphin/mtx.h"
#include "dolphin/os/OSFastCast.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXGeometry.h"
#include "dolphin/gx/GXLighting.h"
#include "dolphin/gx/GXBump.h"
#include "dolphin/gx/GXPixel.h"
#include "dolphin/gx/GXTev.h"
#include "main/camera.h"
#include "main/sky_state.h"
#include "main/track_dolphin.h"
#include "main/track_dolphin_api.h"
#include "main/track_dolphin_shadow_api.h"
#include "main/newshadows_shadow_api.h"
#include "dolphin/mtx/vec.h"
#define TRACK_BBOX_FLAGS_S8
#define TRACK_BBOX_MASK_TYPE  s8
#define TRACK_BBOX_ARG10_TYPE s8
#include "main/track_bbox_api.h"
#undef TRACK_BBOX_ARG10_TYPE
#undef TRACK_BBOX_MASK_TYPE
#undef TRACK_BBOX_FLAGS_S8
#include "main/dll/player_api.h"
#include "main/pause_menu_api.h"
#include "main/pi_dolphin.h"
#include "dolphin/os/OSCache.h"
#include "main/voxmaps.h"
#include "track/intersect_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/objmodel.h"
#include "main/sky.h"
#include "main/newshadows_texture_api.h"
#include "main/acosf_api.h"
#include "main/tex_dolphin.h"
#include "string.h"
#include "track/intersect_hud_api.h"
#include "track/intersect_screen_api.h"
#include "main/objprint_render_api.h"
#include "main/newshadows_audio_api.h"
#include "dolphin/gx/GXManage.h"
#include "dolphin/gx/GXTransform.h"
#include "dolphin/gx/GXStruct.h"
#include "dolphin/gx/GXTexture.h"
#include "main/frame_timing.h"
#include "main/sky_api.h"
#include "main/shader_dolphin.h"
#include "main/dll/modgfx.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "main/newshadows_internal.h"
extern Texture* gNewShadowHeavyFogTexture;
extern u8 gNewShadowHeavyFogIntensity;

void blendTextures(Texture* src1, Texture* src2, f32 blend, Texture* dst) {
    u32 format;
    u32 width;
    u32 height;
    u8 weightA;
    u8 weightB;
    int pixelB;
    int pixelA;
    int redB;
    int redA;
    int blue;
    int red;
    int green;
    u16 outputPixel;

    if (src1 == NULL) {
        return;
    }
    if (src2 == NULL) {
        return;
    }
    if (dst == NULL) {
        return;
    }
    format = src1->format;
    if (format != GX_TF_RGB565 && format != GX_TF_RGBA8) {
        return;
    }
    if (src2->format != format) {
        return;
    }
    if (dst->format != format) {
        return;
    }
    width = src1->width;
    if (width != src2->width) {
        return;
    }
    height = src1->height;
    if (height != src2->height) {
        return;
    }
    if (width != dst->width || height != dst->height) {
        return;
    }
    {
        weightA = (int)(255.0f * blend) & 0xff;
        weightB = (0xff - weightA) & 0xff;
        if (format == GX_TF_RGB565) {
            int y, x;
            u32 tileRow;
            u32 rowInTile;
            for (y = 0; y < src1->height; y++) {
                u8* sourcePixelA;
                u8* sourcePixelB;
                u8* destinationPixel;
                u32 rowWidth;
                int rowDataOffset;
                int tileColumnOffset;
                int pixelColumnOffset;
                x = 0;
                tileRow = y & 0xfffffffc;
                rowInTile = (y & 3) * 8;
                for (; x < (int)(rowWidth = src1->width); x++) {
                    pixelColumnOffset = (x & 3) * 2;
                    sourcePixelA = (u8*)src1 + pixelColumnOffset;
                    tileColumnOffset = (x >> 2) * 0x20;
                    sourcePixelA += tileColumnOffset;
                    sourcePixelA += rowInTile;
                    rowDataOffset = (int)rowWidth * tileRow * 2;
                    sourcePixelA += rowDataOffset;
                    pixelA = *(u16*)(sourcePixelA + sizeof(Texture));
                    redA = (pixelA & 0xf800) >> 8;
                    redA = (u8)(redA | ((pixelA & 0xe000) >> 13));
                    sourcePixelB = (u8*)src2 + pixelColumnOffset;
                    sourcePixelB += tileColumnOffset;
                    sourcePixelB += rowInTile;
                    sourcePixelB += rowDataOffset;
                    pixelB = *(u16*)(sourcePixelB + sizeof(Texture));
                    redB = (pixelB & 0xf800) >> 8;
                    redB = (u8)(redB | ((pixelB & 0xe000) >> 13));
                    blue = ((u8)(((int)(weightA * (u8)(((pixelA & 0x1f) << 3) | ((pixelA & 0x1c) >> 2))) >> 8) +
                                 ((int)(weightB * (u8)(((pixelB & 0x1f) << 3) | ((pixelB & 0x1c) >> 2))) >> 8)) &
                            0xf8) >>
                           3;
                    red = ((u8)(((int)(redA * weightA) >> 8) + ((int)(redB * weightB) >> 8)) & 0xf8) << 8;
                    green = ((u8)(((int)(weightA * (u8)(((pixelA & 0x7e0) >> 3) | ((pixelA & 0x600) >> 9))) >> 8) +
                                  ((int)(weightB * (u8)(((pixelB & 0x7e0) >> 3) | ((pixelB & 0x600) >> 9))) >> 8)) &
                             0xfc)
                            << 3;
                    outputPixel = blue | (red | green);
                    destinationPixel = (u8*)dst + pixelColumnOffset;
                    destinationPixel += tileColumnOffset;
                    destinationPixel += rowInTile;
                    destinationPixel += rowDataOffset;
                    *(u16*)(destinationPixel + sizeof(Texture)) = outputPixel;
                }
            }
        } else {
            int y, x;
            u32 tileRow;
            u32 rowInTile;
            for (y = 0; y < src1->height; y++) {
                u32 rowWidth;
                x = 0;
                tileRow = (y >> 2) * 8;
                rowInTile = (y & 3) * 8;
                for (; x < (int)(rowWidth = src1->width); x++) {
                    int rowDataOffset;
                    int pixelColumnOffset = (x & 3) * 2;
                    int tileColumnOffset;
                    int pixelA, pixelB;
                    u8 *sourcePixelA, *sourcePixelB, *destinationTile, *destinationRow;
                    int redA, redB, greenA, greenB;
                    sourcePixelA = (u8*)src1 + pixelColumnOffset;
                    tileColumnOffset = (x >> 2) * 0x40;
                    sourcePixelA += tileColumnOffset;
                    sourcePixelA += rowInTile;
                    rowDataOffset = (int)rowWidth * tileRow * 2;
                    sourcePixelA += rowDataOffset;
                    sourcePixelB = (u8*)src2 + pixelColumnOffset;
                    sourcePixelB += tileColumnOffset;
                    sourcePixelB += rowInTile;
                    sourcePixelB += rowDataOffset;
                    redA = *(u16*)(sourcePixelA + sizeof(Texture));
                    redA = (u8)redA;
                    redB = *(u16*)(sourcePixelB + sizeof(Texture));
                    redB = (u8)redB;
                    pixelA = *(u16*)(sourcePixelA + sizeof(Texture) + 0x20);
                    greenA = (pixelA & 0xff00) >> 8;
                    greenA = (u8)greenA;
                    pixelB = *(u16*)(sourcePixelB + sizeof(Texture) + 0x20);
                    greenB = (pixelB & 0xff00) >> 8;
                    greenB = (u8)greenB;
                    destinationTile = (u8*)dst + pixelColumnOffset;
                    destinationTile += tileColumnOffset;
                    destinationTile += rowInTile;
                    destinationRow = destinationTile + sizeof(Texture);
                    /* Retail writes the red byte with zero alpha. */
                    *(u16*)(destinationRow + rowDataOffset) =
                        (u8)(((int)(redA * weightA) >> 8) + ((int)(redB * weightB) >> 8));
                    *(u16*)(destinationRow + src1->width * tileRow * 2 + 0x20) =
                        ((u8)(((int)(greenA * weightA) >> 8) + ((int)(greenB * weightB) >> 8)) << 8) |
                        (u8)(((int)(weightA * (u8)pixelA) >> 8) + ((int)(weightB * (u8)pixelB) >> 8));
                }
            }
        }
        DCStoreRange((u8*)dst + sizeof(Texture), dst->dataSize);
    }
}

void updateHeavyFogTexture(int intensity) {
    u8* cache;
    u32 hi, mid;
    u32 scaled;
    u32 j;
    int row;

    cache = getCache();
    for (row = 0; (u32)row < 0x40; row++) {
        j = 0;
        hi = ((u32)row >> 2) << 8;
        mid = (row & 3) << 3;
        scaled = (row + intensity) * 0xff;
        for (; j < 0x40; j++) {
            int idx;
            u32 s;
            s = (j & 7) + ((j >> 3) << 5);
            s += mid;
            idx = s + hi;
            s = scaled;
            if (s > 0x3fc0) {
                s = 0x3fc0;
            }
            cache[idx] = (s * j) >> 12;
        }
    }
    memcpyToCache((u8*)gNewShadowHeavyFogTexture + sizeof(Texture), cache, 0);
    gNewShadowHeavyFogIntensity = intensity;
}

Camera* gNewShadowCurrentViewSlot;
u32 gNewShadowReflectionSmallTexture;
Texture* gNewShadowCausticTexture;
u32 gNewShadowReflectionTexture2;
u32 gNewShadowDiskTexture;
u32 gNewShadowSmallDiskTexture;
u32 gNewShadowBumpTexture;
u32 gNewShadowWhirlpoolTexture;
Texture* gNewShadowHeatHazeTexture;
u32 gNewShadowSnowFlashTexture;
Texture* gNewShadowRadialTexture;
Texture* gNewShadowDistortionTexture;
Texture* gNewShadowHeavyFogTexture;
Texture* gNewShadowLightningTexture;
Texture* gNewShadowRingTexture;
f32 gNewShadowReflectionScrollX;
f32 gNewShadowReflectionScrollY;
f32 gNewShadowDistortionWaveOffset;
u16 gNewShadowDistortionWavePhase;
u32 gNewShadowRampTexture;
u32 gNewShadowInverseRampTexture;
u32 gNewShadowReflectionGradientTexture;
u32 gNewShadowFalloffTexture;
u8 gNewShadowFrameIndex;
int gNewShadowLightAngleY;
int gNewShadowLightAngleX;
u8 gNewShadowHeavyFogIntensity;
Texture* gNewShadowReflectionTexture;
u8 gNewShadowCasterCount;

u8 gShadowCastModeTable[8] = {0xFF, 7, 6, 5, 4, 3, 2, 1};
f32 gStandardAspectRatio = 1.3333334f;

/* Linear search by pointer identity through the shadow entry table.
 * Clears the active flag when the entry matches the needle. */

extern Texture* gNewShadowFrameTextures[NEW_SHADOW_FRAME_COUNT];
extern Texture* gNewShadowCastTextures[NEW_SHADOW_MAX_CAST_TEXTURES];
extern NewShadowCastSlot gNewShadowCastSlots[NEW_SHADOW_MAX_CASTERS];
extern NewShadowCaster gNewShadowCasterTable[NEW_SHADOW_MAX_QUEUED_CASTERS];
extern Texture* gNewShadowNoiseTexFrames[NEW_SHADOW_NOISE_FRAME_COUNT];
extern NewShadowNoiseData gNewShadowNoiseData;
SurfaceSfxTable gSurfaceSfxTable = {
    {
        {0x0346, 0x0346, 0x0346, 0x0347, 0x0348, 0x0349, 0x034A, 0x034B, 0x0346, 0x034C},
        {0x0001, 0x0001, 0x0001, 0x0002, 0x0003, 0x0004, 0x0005, 0x0006, 0x0001, 0x033A},
        {0x012E, 0x012E, 0x012E, 0x012E, 0x012E, 0x012E, 0x012E, 0x012E, 0x012E, 0x012E},
        {0x0007, 0x0007, 0x0007, 0x0008, 0x0009, 0x000A, 0x000B, 0x000C, 0x0007, 0x033B},
        {0x0321, 0x0321, 0x0321, 0x0322, 0x0323, 0x0325, 0x0324, 0x0326, 0x0321, 0x033C},
        {0x021D, 0x021D, 0x021D, 0x021E, 0x021F, 0x0220, 0x0221, 0x0222, 0x021D, 0x033D},
        {0x0385, 0x0385, 0x0385, 0x0384, 0x0385, 0x000A, 0x0385, 0x0384, 0x0385, 0x0385},
        {0x0385, 0x0385, 0x0385, 0x0384, 0x0385, 0x000A, 0x0385, 0x0384, 0x0385, 0x0385},
        {0x0384, 0x044A, 0x044A, 0x0384, 0x03A4, 0x044A, 0x044A, 0x0384, 0x0384, 0x044A},
    },
    {0, 1, 2, 3, 0, 0, 0, 0, 0, 3, 0, 0, 0, 7, 5, 0, 0, 0, 0, 0, 0, 3, 5, 0, 4, 6, 0, 7, 0, 0, 0, 0, 8, 0, 9},
};

extern inline float sqrtf(float x) {
    volatile float y;
    if (x > 0.0f) {
        double guess = __frsqrte((double)x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        guess = 0.5 * guess * (3.0 - guess * guess * x);
        y = (float)(x * guess);
        return y;
    }
    return x;
}


static inline void boxBlurRow(u8* row, u8* blurred, int size, int window) {
    u32 sum;
    int k;

    sum = 0;
    for (k = 0; k < window; k++) {
        sum += row[k];
    }
    for (k = 0; k < size; k++) {
        blurred[k] = sum / window;
        sum -= row[k];
        sum += row[window + k];
    }
}

typedef union ShadowBlurOutput {
    u8 bytes[128];
    u16 halfwords[64];
    u32 words[32];
} ShadowBlurOutput;

typedef union ShadowBlurRow {
    u8 bytes[152];
    u16 halfwords[76];
    u32 words[38];
} ShadowBlurRow;

static void boxBlurTexture(u8* texData, int size, int window, u32 fill) {
    ShadowBlurOutput blurred;
    ShadowBlurRow row;
    u8* data;
    u32 i;

    data = texData + sizeof(Texture);
    if (window % 8 == 0) {
        u32 y = 0;

        for (; y < size; y++) {
            u32* tile = (u32*)(data + (y & 3) * 8 + (y >> 2) * 4 * size);
            u32* dst = row.words;
            u32* src;
            u32* tileDst;
            u32 x;

            for (i = 0; i < (window >> 3); i++) {
                dst[0] = fill;
                dst++;
            }
            src = tile;
            for (x = 0; x < size; x += 8) {
                dst[0] = src[0];
                dst[1] = src[1];
                dst += 2;
                src += 8;
            }
            for (i = 0; i < (window >> 3); i++) {
                dst[0] = fill;
                dst++;
            }
            boxBlurRow(row.bytes, blurred.bytes, size, window);
            src = blurred.words;
            tileDst = tile;
            for (x = 0; x < size; x += 8) {
                tileDst[0] = src[0];
                tileDst[1] = src[1];
                src += 2;
                tileDst += 8;
            }
        }
        {
            u32 x;

            for (x = 0; x < size; x++) {
                u8* col = data + (x & 7) + (x >> 3) * 32;
                u32* dst = row.words;
                u8* texturePtr;
                u8* bufferPtr;
                u32 yOffset;
                u32 paddingWord;

                for (paddingWord = 0; paddingWord < (window >> 3); paddingWord++) {
                    dst[0] = fill;
                    dst++;
                }
                bufferPtr = row.bytes + (window >> 1);
                texturePtr = col;
                for (yOffset = 0; yOffset < size; yOffset += 4) {
                    bufferPtr[0] = texturePtr[0];
                    bufferPtr[1] = texturePtr[8];
                    bufferPtr[2] = texturePtr[16];
                    bufferPtr[3] = texturePtr[24];
                    bufferPtr += 4;
                    texturePtr += (size >> 3) * 32;
                }
                dst = (u32*)(row.bytes + (size + (window >> 1)));
                for (paddingWord = 0; paddingWord < (window >> 3); paddingWord++) {
                    dst[0] = fill;
                    dst++;
                }
                boxBlurRow(row.bytes, blurred.bytes, size, window);
                bufferPtr = blurred.bytes;
                for (yOffset = 0; yOffset < size; yOffset += 4) {
                    col[0] = bufferPtr[0];
                    col[8] = bufferPtr[1];
                    col[16] = bufferPtr[2];
                    col[24] = bufferPtr[3];
                    bufferPtr += 4;
                    col += (size >> 3) * 32;
                }
            }
        }
    } else {
        u32 y = 0;
        u16 fillHalfword = fill;

        for (; y < size; y++) {
            u16* tile = (u16*)(data + (y & 3) * 8 + (y >> 2) * 4 * size);
            u16* src;
            u16* dst = row.halfwords;
            u32 x;

            for (i = 0; i < (window >> 2); i++) {
                dst[0] = fillHalfword;
                dst++;
            }
            src = tile;
            for (x = 0; x < size; x += 8) {
                dst[0] = src[0];
                dst[1] = src[1];
                dst[2] = src[2];
                dst[3] = src[3];
                dst += 4;
                src += 16;
            }
            for (i = 0; i < (window >> 2); i++) {
                dst[0] = fillHalfword;
                dst++;
            }
            boxBlurRow(row.bytes, blurred.bytes, size, window);
            src = blurred.halfwords;
            for (x = 0; x < size; x += 8) {
                tile[0] = src[0];
                tile[1] = src[1];
                tile[2] = src[2];
                tile[3] = src[3];
                src += 4;
                tile += 16;
            }
        }
        {
            u32 x;

            for (x = 0; x < size; x++) {
                u8* col = data + (x & 7) + (x >> 3) * 32;
                u16* dst = row.halfwords;
                u8* texturePtr;
                u8* bufferPtr;
                u32 yOffset;

                for (i = 0; i < (window >> 2); i++) {
                    dst[0] = fillHalfword;
                    dst++;
                }
                bufferPtr = row.bytes + (window >> 1);
                texturePtr = col;
                for (yOffset = 0; yOffset < size; yOffset += 4) {
                    bufferPtr[0] = texturePtr[0];
                    bufferPtr[1] = texturePtr[8];
                    bufferPtr[2] = texturePtr[16];
                    bufferPtr[3] = texturePtr[24];
                    bufferPtr += 4;
                    texturePtr += (size >> 3) * 32;
                }
                dst = (u16*)(row.bytes + (size + (window >> 1)));
                for (i = 0; i < (window >> 2); i++) {
                    dst[0] = fillHalfword;
                    dst++;
                }
                boxBlurRow(row.bytes, blurred.bytes, size, window);
                bufferPtr = blurred.bytes;
                for (yOffset = 0; yOffset < size; yOffset += 4) {
                    col[0] = bufferPtr[0];
                    col[8] = bufferPtr[1];
                    col[16] = bufferPtr[2];
                    col[24] = bufferPtr[3];
                    bufferPtr += 4;
                    col += (size >> 3) * 32;
                }
            }
        }
    }
    DCFlushRange(data, size * size);
}

void renderObjectShadowTexture(GameObject* obj) {
    f32 mtx[12];
    f32 vA, vB, vC, vD, vE, vF;
    f32 sc, objScale, saved, nx, ny, m;
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    Camera_ProjectWorldSphere(obj->anim.localPosX - playerMapOffsetX, obj->anim.localPosY,
                              obj->anim.localPosZ - playerMapOffsetZ,
                              1.3f * (obj->anim.hitboxScale * obj->anim.rootMotionScale), &vA, &vB, &vC, &vD, &vE, &vF);
    vD = 320.0f * vD + 8.0f;
    vE = 240.0f * vE + 8.0f;
    if (vD > vE) {
        m = vD;
    } else {
        m = vE;
    }
    sc = 64.0f / m;
    objScale = obj->anim.rootMotionScale * sc;
    nx = -vA;
    ny = vB;
    GXSetViewport(320.0f * nx, 240.0f * ny, 640.0f, 480.0f, 0.0f, 1.0f);
    if (vC < 0.0f) {
        ObjModel* model;
        saved = obj->anim.rootMotionScale;
        obj->anim.rootMotionScale = objScale;
        objSetRenderingShadowPass(1);
        objRender(0, 0, 0, 0, obj, 1);
        objSetRenderingShadowPass(0);
        obj->anim.rootMotionScale = saved;
        model = (ObjModel*)Obj_GetActiveModel(obj);
        model->bufferFlags &= ~0x8;
        gxSetZMode_(1, GX_LEQUAL, 1);
        GXSetTexCopySrc(0x100, 0xb0, 0x80, 0x80);
        GXSetTexCopyDst(0x80, 0x80, GX_CTF_B8, GX_FALSE);
        GXCopyTex(gNewShadowFrameTextures[gNewShadowFrameIndex] + 1, GX_TRUE);
        boxBlurTexture((u8*)gNewShadowFrameTextures[(gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT], 0x80, 0x10,
                       0);
        obj->anim.modelState->shadowScale = 1.0f / sc;
    } else {
        obj->anim.modelState->shadowScale = 0.0f;
    }
    Camera_ApplyFullViewport();
    obj->anim.modelState->shadowOffsetX = 320.0f * (-nx);
    obj->anim.modelState->shadowOffsetY = 240.0f * (-ny);
    obj->anim.modelState->shadowOffsetX += 320.0f;
    obj->anim.modelState->shadowOffsetY += 240.0f;
    obj->anim.modelState->shadowOffsetX -= 64.0f * obj->anim.modelState->shadowScale;
    obj->anim.modelState->shadowOffsetY -= 64.0f * obj->anim.modelState->shadowScale;
}

static void sortShadowEntriesDescending(NewShadowCaster* arr, int count) {
    int gap = 1;
    int i, j;
    NewShadowCaster tmp;
    int limit = (count - 1) / 9;
    while (gap <= limit) {
        gap = gap * 3 + 1;
    }
    while (gap > 0) {
        for (i = gap + 1; i <= count; i++) {
            tmp = arr[i - 1];
            j = i;
            while (j > gap && arr[j - gap - 1].scale < tmp.scale) {
                arr[j - 1] = arr[j - gap - 1];
                j -= gap;
            }
            arr[j - 1] = tmp;
        }
        gap /= 3;
    }
}
extern NewShadowEntry gNewShadowEntries[0x294 / sizeof(NewShadowEntry)];

void renderShadows(int unused0, int unused1, int unused2) {
    NewShadowCaster* casterPtr;
    f32* mc54p;
    f32* vAzp;
    f32* vAyp;
    Texture** texture;
    f32 dirY, dirZ, vAy, dirX, sCamX, sCamY;
    int savedRotY;
    s16 savedRotX;
    f32 om100[24];
    Mtx mTrans, mScale;
    Mtx44 mOrtho;
    f32 mc54[3], mc48[3];
    Vec vA, direction;
    Vec dot24, proj;
    Camera* slot;
    NewShadowData* shadowData = (NewShadowData*)gNewShadowEntries;
    void* layerTables;
    u32 blocks;
    f32 sCamZ, savedFovY, vAx, vAz, orthoHalf;
    int slotIdx, texIdx;
    s8 casterIdx;
    int w;
    GameObject* obj;
    s16 savedRotZ;
    ObjModelState* modelState;
    NewShadowCastSlot* castSlot;
    MtxPtr viewMtx;

    if (gNewShadowCasterCount == 0) {
        return;
    }
    CameraShake_Disable();
    sortShadowEntriesDescending(shadowData->casters, gNewShadowCasterCount);
    Camera_SetCurrentViewIndex(1);
    slot = Camera_GetCurrent();
    savedFovY = Camera_GetFovY();
    Camera_SetFovY(70.0f);
    Camera_SetAspectRatio(1.0f);
    sCamX = slot->x;
    sCamY = slot->y;
    sCamZ = slot->z;
    savedRotY = slot->pitch;
    savedRotX = slot->yaw;
    savedRotZ = slot->roll;
    slot->pitch = 0;
    direction.x = 0.0f;
    direction.y = 1.0f;
    direction.z = 0.0f;
    buildShadowVolumeBox(&direction.x, om100, 2.0f);
    mapGetBlocks(&layerTables, &blocks);
    texIdx = 0;
    slotIdx = 0;
    casterIdx = 0;
    casterPtr = shadowData->casters;
    mc54p = &mc54[0];
    vAzp = &vA.x + 2;
    vAyp = &vA.x + 1;
    for (; casterIdx < gNewShadowCasterCount && casterIdx < NEW_SHADOW_MAX_CASTERS; casterPtr++, casterIdx++) {
        u8 alpha;
        u8 kind;
        obj = casterPtr->obj;
        modelState = obj->anim.modelState;
        Camera_SetCurrentViewIndex(0);
        alpha = objShadowUpdateAlpha(obj, framesThisStep);
        Camera_SetCurrentViewIndex(1);
        if (alpha <= 4) {
            continue;
        }
        if ((modelState->flags & OBJ_MODEL_STATE_SHADOW_POS_OVERRIDE) != 0) {
            memcpy(mc48, &obj->anim.localPos, sizeof(Vec3f));
            memcpy(mc54p, &obj->anim.worldPos, sizeof(Vec3f));
            memcpy(&obj->anim.localPos, &modelState->overrideWorldPosX, sizeof(Vec3f));
            memcpy(&obj->anim.worldPos, &modelState->overrideWorldPosX, sizeof(Vec3f));
        }
        castSlot = (NewShadowCastSlot*)(((u8)slotIdx * sizeof(NewShadowCastSlot) + offsetof(NewShadowData, castSlots)) +
                                        (int)shadowData);
        castSlot->alpha = alpha;
        if ((u8)texIdx < NEW_SHADOW_MAX_CAST_TEXTURES && (kind = casterPtr->flags) != 0) {
            int screenW;
            if ((u8)texIdx < 3) {
                w = 0x100;
                orthoHalf = 0.5f;
            } else if ((u8)texIdx < 5) {
                w = 0x80;
                orthoHalf = 0.25f;
            } else {
                w = 0x40;
                orthoHalf = 0.125f;
            }
            if ((u8)texIdx == 0) {
                screenW = w << 1;
            } else {
                screenW = w;
            }
            if (kind == 2) {
                w = obj->anim.modelState->shadowTexture->width;
                screenW = w;
            }
            skyGetObjectLightDirection(obj, &vA.x, vAyp, vAzp);
            dot24.x = -modelState->shadowOffsetX;
            dot24.y = -modelState->shadowOffsetY;
            dot24.z = -modelState->shadowOffsetZ;
            {
                f32 dot = PSVECDotProduct(&dot24, &vA);
                if (dot < 1.0f && dot > -1.0f) {
                    f32 mag;
                    proj.x = 0.9f * dot24.x + 0.1f * vA.x;
                    proj.y = 0.9f * dot24.y + 0.1f * vA.y;
                    proj.z = 0.9f * dot24.z + 0.1f * vA.z;
                    mag = PSVECMag(&proj);
                    if (mag > 0.0f) {
                        mag = 1.0f / mag;
                        PSVECScale(&proj, &vA, mag);
                    }
                }
            }
            if (vA.y > (-0.707f)) {
                vA.y = -0.707f;
                PSVECNormalize(&vA, &vA);
            }
            vAx = vA.x;
            dirX = -vAx;
            vAy = vA.y;
            dirY = -vAy;
            vAz = vA.z;
            dirZ = -vAz;
            gNewShadowLightAngleX = (u16)getAngle(dirX, vAz);
            {
                f32 sqA = vAx * vAx;
                f32 sqB = vAz * vAz;
                gNewShadowLightAngleY = (u16)getAngle(sqrtf(sqB + sqA), vAy) - 0x3fc8;
            }
            slot->pitch = gNewShadowLightAngleY;
            slot->yaw = gNewShadowLightAngleX;
            {
                f32 mag = sqrtf(dirX * dirX + dirY * dirY + dirZ * dirZ);
                if (mag > 0.0f) {
                    f32 inv = 400.0f / mag;
                    dirX *= inv;
                    dirY *= inv;
                    dirZ *= inv;
                }
            }
            slot->parentObject = NULL;
            modelState->shadowOffsetX = -vA.x;
            modelState->shadowOffsetY = -vA.y;
            modelState->shadowOffsetZ = -vA.z;
            setScreenWidth(screenW);
            {
                f32* m = (f32*)ObjModel_GetJointMatrix((u8*)Obj_GetActiveModel(obj), 0);
                slot->x = dirX + m[3];
                slot->y = dirY + m[7];
                slot->z = dirZ + m[11];
            }
            if (obj->anim.parent == NULL) {
                slot->x += gMapSavedPlayerOffsetX;
                slot->z += gMapSavedPlayerOffsetZ;
            }
            vAz = modelState->shadowScale;
            vAx = -vAz;
            if (obj->anim.parent != NULL) {
                slot->x += playerMapOffsetX;
                slot->z += playerMapOffsetZ;
            }
            GXSetScissor(2, 2, screenW - 4, screenW - 4);
            GXSetViewport(0.0f, 0.0f, (f32)(u32)screenW, (f32)(u32)screenW, 0.0f, 1.0f);
            C_MTXOrtho(mOrtho, vAx, vAz, vAx, vAz, 1.0f, 1025.0f);
            GXSetProjection(mOrtho, GX_ORTHOGRAPHIC);
            Camera_UpdateViewMatrices();
            C_MTXLightOrtho((MtxPtr)castSlot->textureMtx, vAz, vAx, vAx, vAz, orthoHalf, orthoHalf, orthoHalf,
                            orthoHalf);
            {
                viewMtx = (MtxPtr)Camera_GetViewMatrix();
                PSMTXCopy(viewMtx, (MtxPtr)castSlot->depthMtx);
                PSMTXConcat((MtxPtr)castSlot->textureMtx, viewMtx, (MtxPtr)castSlot->textureMtx);
                obj->anim.modelState->shadowCastSlot = castSlot;
                {
                    Texture** texturePool = shadowData->castTextures;
                    texture = texturePool + (u8)texIdx;
                    castSlot->texture = *texture;
                    castSlot->mode = gShadowCastModeTable[(u8)texIdx];
                    objRenderShadowIfVisible(obj, 0, 0, 0, 0, 0);
                    if (casterPtr->flags == 2) {
                        gxSetZMode_(1, GX_LEQUAL, 1);
                        PSMTXScale((MtxPtr)castSlot->depthMtx, 0.0f, 0.0f, 0.0f);
                        castSlot->depthMtx[0][2] = -0.0009765625f;
                        castSlot->depthMtx[0][3] = -0.004875183f;
                        castSlot->depthMtx[2][3] = 1.0f;
                        PSMTXConcat((MtxPtr)castSlot->depthMtx, viewMtx, (MtxPtr)castSlot->depthMtx);
                        GXSetTexCopySrc(0, 0, screenW, screenW);
                        GXSetTexCopyDst(screenW, screenW, GX_TF_Z8, GX_FALSE);
                        {
                            GXRenderModeObj* renderMode = gRenderModeObj;
                            GXSetCopyFilter(0, renderMode->sample_pattern, 0, renderMode->vfilter);
                        }
                        GXCopyTex(obj->anim.modelState->shadowTexture + 1, GX_TRUE);
                        setDisplayCopyFilter();
                        castSlot->texture = obj->anim.modelState->shadowTexture;
                    } else {
                        if ((u8)texIdx == 0) {
                            gxSetZMode_(1, GX_LEQUAL, 1);
                            GXSetTexCopySrc(0, 0, screenW, screenW);
                            GXSetTexCopyDst(w, w, GX_CTF_R4, GX_TRUE);
                            GXCopyTex(*texture + 1, GX_TRUE);
                            castSlot->texture = *texture;
                        }
                        texIdx++;
                    }
                }
            }
        } else {
            f32 fx, fz;
            castSlot->texture = obj->anim.modelState->shadowTexture;
            fx = obj->anim.localPosX;
            fz = obj->anim.localPosZ;
            if (obj->anim.parent == NULL) {
                fx -= playerMapOffsetX;
                fz -= playerMapOffsetZ;
            }
            PSMTXTrans(mTrans, -fx, -obj->anim.localPosY, -fz);
            {
                f32 s = 0.5f / modelState->shadowScale;
                mScale[0][0] = s;
                mScale[0][1] = 0.0f;
                mScale[0][2] = 0.0f;
                mScale[0][3] = 0.5f;
                mScale[1][0] = 0.0f;
                mScale[1][1] = 0.0f;
                mScale[1][2] = s;
                mScale[1][3] = 0.5f;
                mScale[2][0] = 0.0f;
                mScale[2][1] = 0.0f;
                mScale[2][2] = 0.0f;
                mScale[2][3] = 1.0f;
            }
            PSMTXConcat(mScale, mTrans, (MtxPtr)castSlot->textureMtx);
            modelState->shadowOffsetX = direction.x;
            modelState->shadowOffsetY = direction.y;
            modelState->shadowOffsetZ = direction.z;
            obj->anim.modelState->shadowCastSlot = castSlot;
        }
        slotIdx++;
        if ((modelState->flags & OBJ_MODEL_STATE_SHADOW_POS_OVERRIDE) != 0) {
            memcpy(&obj->anim.localPos, mc48, sizeof(Vec3f));
            memcpy(&obj->anim.worldPos, mc54p, sizeof(Vec3f));
        }
    }
    if ((u8)texIdx > 1) {
        GXRenderModeObj* renderMode;
        gxSetZMode_(1, GX_LEQUAL, 1);
        renderMode = gRenderModeObj;
        GXSetCopyFilter(0, renderMode->sample_pattern, 0, renderMode->vfilter);
        GXSetTexCopySrc(0, 0, 0x100, 0x100);
        GXSetTexCopyDst(0x100, 0x100, GX_CTF_R8, GX_FALSE);
        GXCopyTex(shadowData->castTextures[1] + 1, GX_TRUE);
        GXPixModeSync();
        setDisplayCopyFilter();
    }
    clearScreenWidth();
    slot->x = sCamX;
    slot->y = sCamY;
    slot->z = sCamZ;
    slot->pitch = savedRotY;
    slot->yaw = savedRotX;
    slot->roll = savedRotZ;
    if (isDrawDistanceEnabled() != 0) {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        if (isWidescreen() != 0) {
            Camera_SetAspectRatio(2.25f);
        } else {
            Camera_SetAspectRatio(1.66f);
        }
        Camera_UpdateProjection(NULL, 0);
    } else if (isWidescreen() != 0) {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        Camera_SetAspectRatio(1.7777778f);
        Camera_UpdateProjection(NULL, 0);
    } else {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        Camera_SetAspectRatio(gStandardAspectRatio);
        Camera_UpdateProjection(NULL, 0);
    }
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
    CameraShake_Enable();
}

extern NewShadowCaster gNewShadowCasterTable[NEW_SHADOW_MAX_QUEUED_CASTERS];

void queueObjectShadow(GameObject* obj) {
    f32 dx, dy, dz, dist2;
    if (gNewShadowCasterCount < NEW_SHADOW_MAX_QUEUED_CASTERS) {
        gNewShadowCasterTable[gNewShadowCasterCount].obj = obj;
        dx = obj->anim.worldPosX - gNewShadowCurrentViewSlot->x;
        dy = obj->anim.worldPosY - gNewShadowCurrentViewSlot->y;
        dz = obj->anim.worldPosZ - gNewShadowCurrentViewSlot->z;
        dist2 = dx * dx + dy * dy + dz * dz;
        if (dist2 > 0.0f) {
            double guess = __frsqrte((double)dist2);
            volatile f32 root;
            guess = 0.5 * guess * (3.0 - guess * guess * dist2);
            guess = 0.5 * guess * (3.0 - guess * guess * dist2);
            guess = 0.5 * guess * (3.0 - guess * guess * dist2);
            root = (f32)(dist2 * guess);
            dist2 = root;
        }
        gNewShadowCasterTable[gNewShadowCasterCount].scale = obj->anim.modelState->shadowScale / dist2;
        if (obj->anim.modelInstance->shadowType == OBJ_SHADOW_TYPE_MODEL_GEOMETRIC) {
            gNewShadowCasterTable[gNewShadowCasterCount].flags = 1;
            if (obj->anim.modelInstance->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW) {
                gNewShadowCasterTable[gNewShadowCasterCount].flags = 2;
                gNewShadowCasterTable[gNewShadowCasterCount].scale = 3.4028235e+38f;
            }
        } else {
            gNewShadowCasterTable[gNewShadowCasterCount].flags = 0;
        }
        gNewShadowCasterCount++;
    }
}
extern Texture* gNewShadowTextureTable[8][4];

void newshadows_getShadowTextureTable4x8(Texture*** tableOut, int* columnsOut, int* rowsOut) {
    *tableOut = &gNewShadowTextureTable[0][0];
    *columnsOut = 4;
    *rowsOut = 8;
}

void newshadows_getNoiseTextureFrames(Texture*** tableOut, int* frameCountOut) {
    *tableOut = gNewShadowNoiseTexFrames;
    *frameCountOut = NEW_SHADOW_NOISE_FRAME_COUNT;
}

void newshadows_getSnowFlashTexture(u32* p) {
    *p = gNewShadowSnowFlashTexture;
}
void newshadows_getHeatHazeTexture(Texture** p) {
    *p = gNewShadowHeatHazeTexture;
}
void newshadows_getRingTexture(Texture** out) {
    *out = gNewShadowRingTexture;
}
void newshadows_getLightningTexture(Texture** p) {
    *p = gNewShadowLightningTexture;
}
void newshadows_getHeavyFogTexture(Texture** p) {
    *p = gNewShadowHeavyFogTexture;
}
void newshadows_getDistortionTexture(Texture** out) {
    *out = gNewShadowDistortionTexture;
}
void newshadows_getRadialTexture(Texture** out) {
    *out = gNewShadowRadialTexture;
}

void* newshadows_allocTexture512(void) {
    Texture* tex = (Texture*)textureAlloc(0x200, 0x200, 1, 0, 0, 0, 0, 0, 0);
    tex->refCount = 1;
    DCFlushRange((char*)tex + sizeof(Texture), tex->dataSize);
    return tex;
}
void newshadows_getRampTexture(u32* out) {
    *out = gNewShadowRampTexture;
}

u32 newshadows_getSmallDiskTexture(void) {
    return gNewShadowSmallDiskTexture;
}
void newshadows_getDiskTexture(u32* out) {
    *out = gNewShadowDiskTexture;
}
void newshadows_getReflectionDepthTexture(u32* p) {
    *p = gNewShadowReflectionTexture2;
}
void newshadows_getCausticTexture(u32* p) {
    *p = (u32)gNewShadowCausticTexture;
}

void getObjectShadowDrawParams(GameObject* obj, Texture** outTexture, f32* outScale, int* outX, int* outY) {
    int idx = (gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT;
    *outTexture = gNewShadowFrameTextures[idx];
    *outScale = obj->anim.modelState->shadowScale;
    *outX = (int)obj->anim.modelState->shadowOffsetX;
    *outY = (int)obj->anim.modelState->shadowOffsetY;
}

f32 newshadows_getDistortionWaveOffset(void) {
    return gNewShadowDistortionWaveOffset;
}

void newshadows_loadBumpTexture(int texMapId) {
    GXLoadTexObj(textureGetGXTexObj((Texture*)gNewShadowBumpTexture), texMapId);
}

void newshadows_loadWhirlpoolTexture(int id) {
    register int idCopy = id;
    Texture* p = (Texture*)gNewShadowWhirlpoolTexture;
    if (p->preloaded != 0) {
        struct _GXTexObj* obj = textureGetGXTexObj(p);
        GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(p), idCopy);
    } else {
        GXLoadTexObj(textureGetGXTexObj(p), idCopy);
    }
}

void newshadows_loadReflectionColorTexture(int id) {
    register int idCopy = id;
    Texture* p = gNewShadowReflectionTexture;
    if (p->preloaded != 0) {
        struct _GXTexObj* obj = textureGetGXTexObj(p);
        GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(p), idCopy);
    } else {
        GXLoadTexObj(textureGetGXTexObj(p), idCopy);
    }
}
u32 newshadows_getReflectionColorTexture(void) {
    return (u32)gNewShadowReflectionTexture;
}

NewShadowEntry gNewShadowEntries[0x294 / sizeof(NewShadowEntry)];
u32 newshadows_getReflectionGradientTexture(void) {
    return gNewShadowReflectionGradientTexture;
}

u32 newshadows_getInverseRampTexture(void) {
    return gNewShadowInverseRampTexture;
}
u32 newshadows_getFalloffTexture(void) {
    return gNewShadowFalloffTexture;
}

void newshadows_loadSmallReflectionTexture(int id) {
    register int idCopy = id;
    Texture* p = (Texture*)gNewShadowReflectionSmallTexture;
    if (p->preloaded != 0) {
        struct _GXTexObj* obj = textureGetGXTexObj(p);
        GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(p), idCopy);
    } else {
        GXLoadTexObj(textureGetGXTexObj(p), idCopy);
    }
}
void newshadows_drawReflectionTexture(void) {
    char* texture = (char*)gNewShadowReflectionTexture;
    drawTexture(texture, 0.0f, 0.0f, 0xff, 0x40);
    GXSetTexCopySrc(0, 0, 0x50, 0x3c);
    GXSetTexCopyDst(0x50, 0x3c, GX_TF_RGB565, GX_FALSE);
    GXCopyTex((char*)gNewShadowReflectionSmallTexture + sizeof(Texture), GX_TRUE);
    if (((Texture*)gNewShadowReflectionSmallTexture)->preloaded != 0) {
        GXTexObj* obj = textureGetGXTexObj((Texture*)gNewShadowReflectionSmallTexture);
        GXPreLoadEntireTexture(obj, textureGetGXTexRegion((Texture*)gNewShadowReflectionSmallTexture));
    }
}

void newshadows_captureReflectionTextures(void) {
    GXSetTexCopySrc(0, 0, 0x280, 0x1e0);
    GXSetTexCopyDst(0x140, 0xf0, GX_TF_RGB565, GX_TRUE);
    GXCopyTex((char*)gNewShadowReflectionTexture + sizeof(Texture), GX_FALSE);
    GXSetTexCopySrc(0, 0, 0x280, 0x1e0);
    GXSetTexCopyDst(0x140, 0xf0, GX_TF_Z8, GX_TRUE);
    GXCopyTex((char*)gNewShadowReflectionTexture2 + sizeof(Texture), GX_FALSE);
    if (gNewShadowReflectionTexture->preloaded != 0) {
        GXTexObj* obj = textureGetGXTexObj(gNewShadowReflectionTexture);
        GXPreLoadEntireTexture(obj, textureGetGXTexRegion(gNewShadowReflectionTexture));
    }
    if (((Texture*)gNewShadowReflectionTexture2)->preloaded != 0) {
        GXTexObj* obj = textureGetGXTexObj((Texture*)gNewShadowReflectionTexture2);
        GXPreLoadEntireTexture(obj, textureGetGXTexRegion((Texture*)gNewShadowReflectionTexture2));
    }
    if (gNewShadowReflectionTexture->preloaded == 0 || ((Texture*)gNewShadowReflectionTexture2)->preloaded == 0) {
        GXInvalidateTexAll();
    }
    GXPixModeSync();
}

void newshadows_beginFrame(void) {
    f32 hi, lo;
    if (getHudHiddenFrameCount() == 0) {
        gNewShadowReflectionScrollX = 0.0084f * timeDelta + gNewShadowReflectionScrollX;
        gNewShadowReflectionScrollY = 0.003f * timeDelta + gNewShadowReflectionScrollY;
        if (gNewShadowReflectionScrollX > 256.0f) {
            gNewShadowReflectionScrollX = gNewShadowReflectionScrollX - 256.0f;
        }
        if (gNewShadowReflectionScrollY > 256.0f) {
            gNewShadowReflectionScrollY = gNewShadowReflectionScrollY - 256.0f;
        }
    }
    gNewShadowCasterCount = 0;
    gNewShadowCurrentViewSlot = Camera_GetCurrent();
    gNewShadowDistortionWavePhase = gNewShadowDistortionWavePhase + framesThisStep * 0x28a;
    gNewShadowDistortionWaveOffset =
        0.2f * mathSinfHighPrecision(6.284f * (f32)(u32)gNewShadowDistortionWavePhase / 65536.0f);
    mapClearBlockEdgeFlags();
    gNewShadowFrameIndex = (gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT;
    if (isHeavyFogEnabled()) {
        f32 z = Camera_GetInverseViewMatrix()[7];
        int v;
        getHeavyFogRange(&hi, &lo);
        if (z >= hi) {
            v = 0;
        } else if (z <= lo) {
            v = 0x40;
        } else {
            v = (int)(64.0f * (hi - z) / (hi - lo));
        }
        if ((u8)v != gNewShadowHeavyFogIntensity) {
            updateHeavyFogTexture((u8)v);
        }
    }
}

void newshadows_getReflectionScrollOffsets(f32* outScrollX, f32* outScrollY) {
    *outScrollX = gNewShadowReflectionScrollX;
    *outScrollY = gNewShadowReflectionScrollY;
}

void newshadows_releaseTextureEntry(void* textureEntry) {
    int i;
    for (i = 0; i < NEW_SHADOW_ENTRY_CAPACITY; ++i) {
        if (gNewShadowEntries[i].isActive != 0 && &gNewShadowEntries[i] == textureEntry) {
            gNewShadowEntries[i].isActive = 0;
            return;
        }
    }
}

void newshadows_freeDistortionTexture(void) {
    mm_free(gNewShadowDistortionTexture);
    gNewShadowDistortionTexture = 0;
}

void newshadows_createDistortionTexture(void) {
    int tileColumnOffset;
    int columnPixelOffset;
    int x, y;
    f32 directionY, directionX;
    f32 radius;
    f32 strength;
    f32 normalizedX;
    gNewShadowDistortionTexture = textureAlloc(0x100, 0x100, 3, 0, 0, 0, 0, 1, 1);
    for (x = 0; x < 0x100; x++) {
        y = 0;
        tileColumnOffset = (x >> 2) * 0x20;
        columnPixelOffset = (x & 3) * 2;
        for (; y < 0x100; y++) {
            u8* columnBase;
            u8* tileBase;
            u8* texel;
            columnBase = (u8*)gNewShadowDistortionTexture;
            columnBase += columnPixelOffset;
            tileBase = columnBase + tileColumnOffset;
            tileBase += (y & 3) * 8;
            texel = tileBase + (y >> 2) * 0x800;
            directionX = x - 127.5f;
            directionY = y - 127.5f;
            radius = sqrtf(directionX * directionX + directionY * directionY);
            normalizedX = directionX / radius;
            directionY /= radius;
            strength = radius <= 112.0f ? (2.0f * (0.9f * 112.0f - 0.9f * radius)) / 256.0f : 0.0f;
            normalizedX *= strength;
            directionY *= strength;
            normalizedX = 127.0f * normalizedX + 128.0f;
            directionY = 127.0f * directionY + 128.0f;
            ((NewShadowVectorTexel*)(texel + sizeof(Texture)))->packedXY = (u16)((int)directionY | (((int)normalizedX & 0xffff) << 8));
        }
    }
    DCFlushRange(gNewShadowDistortionTexture + 1, gNewShadowDistortionTexture->dataSize);
}
/* Sample the animated noise field built from gNewShadowNoiseData: sums the
   contribution of every active placement at texel (sampleX,sampleZ) for animation frame
   `frame`. outIntensity = sparkle intensity (0..1), outShift = accumulated shift term. */
static void evalNoisePlacements(f32 sampleX, f32 sampleZ, f32 frame, const NewShadowNoisePlacement* placements,
                                int count, f32* outShift, f32* outIntensity) {
    const NewShadowNoisePlacement* place;
    int i;
    f32 intensity;
    f32 shift;

    intensity = shift = 0.0f;
    place = placements;
    for (i = 0; i < count; i++, place++) {
        f32 verticalOffset = 0.0f;
        if (frame < place->frameCount) {
            f32 distanceX, distanceZ, remainingLife, fade, wrappedDistance, wrappedZ, distance, phase, radiusProgress,
                radius;
            remainingLife = 0.25f + (place->frameCount - frame) / place->frameCount;
            if (remainingLife > 1.0f) {
                remainingLife = 1.0f;
            }
            fade = sqrtf(remainingLife);

            distanceX = __fabsf(place->x - sampleX);
            wrappedDistance = __fabsf((1.0f + place->x) - sampleX);
            if (wrappedDistance < distanceX) {
                distanceX = wrappedDistance;
            }
            wrappedDistance = __fabsf((place->x - 1.0f) - sampleX);
            if (wrappedDistance < distanceX) {
                distanceX = wrappedDistance;
            }

            distanceZ = __fabsf(place->z - sampleZ);
            if (sampleZ > place->z) {
                verticalOffset = sampleZ - place->z;
            }
            wrappedDistance = __fabsf((1.0f + place->z) - sampleZ);
            if (wrappedDistance < distanceZ) {
                distanceZ = wrappedDistance;
                verticalOffset = 0.0f;
            }
            wrappedZ = place->z - 1.0f;
            wrappedDistance = __fabsf(wrappedZ - sampleZ);
            if (wrappedDistance < distanceZ) {
                distanceZ = wrappedDistance;
                if (sampleZ > wrappedZ) {
                    verticalOffset = sampleZ - wrappedZ;
                }
            }

            distance = sqrtf(distanceX * distanceX + distanceZ * distanceZ);

            phase = frame / place->frameCount;
            radiusProgress = sqrtf(phase);
            radius = place->startRadius - radiusProgress * (place->startRadius - place->endRadius);
            if (distance <= radius) {
                f32 radialWeight = distance / radius;
                f32 falloff;
                radialWeight = 1.0f - radialWeight;
                falloff = sqrtf(radialWeight);
                intensity = fade * falloff + intensity;
                verticalOffset = verticalOffset / radius;
                shift = shift + verticalOffset;
                shift = 0.5f * (1.0f - frame / 16.0f) + shift;
            }
        }
    }
    if (intensity > 1.0f) {
        intensity = 1.0f;
    }
    if (shift > 1.0f) {
        shift = 1.0f;
    }
    *outShift = 0.125f * shift + 0.4375f;
    *outIntensity = intensity;
}
/* Scatter periodic noise placements, render their animation, then the caustic texture. */
void newshadows_initProceduralTextures(void) {
    u8 savedHeap;
    int placementAttempts;
    int row;
    f32* placementZ;
    NewShadowNoisePlacement* otherPlacement;
    f32* placementRadius;
    NewShadowNoisePlacement* placement;
    f32* placementX;
    u8 overlaps;
    int otherIndex;
    int placedCount;
    int frame;

    savedHeap = mmSetForceHeap3Only(1);
    placedCount = 0;
    placementAttempts = 0;
    placement = gNewShadowNoiseData.placements;
    while (placedCount < NEW_SHADOW_MAX_NOISE_PLACEMENTS && placementAttempts < 10000u) {
        placement->frameCount = randomGetRange(8, 0x10);
        placement->startRadius = 0.01f * randomGetRange(5, 10);
        placement->endRadius = placement->startRadius * (0.01f * randomGetRange(0x14, 0x32));
        placementAttempts = 0;
        placementX = &placement->x;
        placementZ = &placement->z;
        placementRadius = &placement->endRadius;
        do {
            *placementX = 0.001f * randomGetRange(0, 999);
            *placementZ = 0.001f * randomGetRange(0, 999);
            overlaps = 0;
            otherIndex = 0;
            otherPlacement = gNewShadowNoiseData.placements;
            while (otherIndex < placedCount && !overlaps) {
                f32 xDistance, zDistance, wrappedDistance;
                xDistance = __fabsf(*placementX - otherPlacement->x);
                wrappedDistance = __fabsf((1.0f + *placementX) - otherPlacement->x);
                if (wrappedDistance < xDistance) {
                    xDistance = wrappedDistance;
                }
                wrappedDistance = __fabsf((*placementX - 1.0f) - otherPlacement->x);
                if (wrappedDistance < xDistance) {
                    xDistance = wrappedDistance;
                }
                zDistance = __fabsf(*placementZ - otherPlacement->z);
                wrappedDistance = __fabsf((1.0f + *placementZ) - otherPlacement->z);
                if (wrappedDistance < zDistance) {
                    zDistance = wrappedDistance;
                }
                wrappedDistance = __fabsf((*placementZ - 1.0f) - otherPlacement->z);
                if (wrappedDistance < zDistance) {
                    zDistance = wrappedDistance;
                }
                wrappedDistance = zDistance * zDistance;
                zDistance = xDistance * xDistance + wrappedDistance;
                zDistance = sqrtf(zDistance);
                if (zDistance < *placementRadius + otherPlacement->startRadius) {
                    overlaps = 1;
                }
                otherPlacement++;
                otherIndex++;
            }
            placementAttempts++;
        } while (overlaps && placementAttempts < 10000u);
        placement++;
        placedCount++;
    }

    {
        u32 noisePlacementCount = placedCount;

        frame = 0;
        for (; frame < NEW_SHADOW_NOISE_FRAME_COUNT; frame++) {
            gNewShadowNoiseTexFrames[frame] = textureAlloc(0x40, 0x40, 3, 0, 0, 1, 1, 1, 1);
            for (row = 0; row < 0x40; row++) {
                int rowPixelOffset;
                int column, h;
                column = 0;
                h = (row >> 2) * 0x20;
                rowPixelOffset = (row & 3) * 2;
                for (; column < 0x40; column++) {
                    int highByte, lowByte;
                    int texelAddress = (int)gNewShadowNoiseTexFrames[frame] + h + rowPixelOffset;
                    f32 shift, intensity;
                    f32 rowCoord, columnCoord;
                    texelAddress += (column & 3) * 8;
                    texelAddress += (column >> 2) * 0x200;
                    rowCoord = row / 64.0f;
                    columnCoord = column / 64.0f;
                    evalNoisePlacements(rowCoord, columnCoord, frame, gNewShadowNoiseData.placements,
                                        noisePlacementCount, &shift, &intensity);
                    highByte = 255.0f * intensity;
                    highByte = (highByte & 0xffff) << 8;
                    lowByte = 255.0f * shift;
                    ((NewShadowVectorTexel*)(texelAddress + 0x60))->packedXY = highByte | lowByte;
                }
            }
            DCFlushRange(gNewShadowNoiseTexFrames[frame] + 1, gNewShadowNoiseTexFrames[frame]->dataSize);
        }
    }

    gNewShadowCausticTexture = textureAlloc(0x40, 0x40, 3, 0, 0, 1, 1, 1, 1);
    for (row = 0; row < 0x40; row++) {
        int column;
        int h, rowPixelOffset;
        f32 rowPhase;
        column = 0;
        h = (row >> 2) * 0x20;
        rowPixelOffset = (row & 3) * 2;
        rowPhase = 0.0981875f * row;
        for (; column < 0x40; column++) {
            f32 columnPhase, wave, carrier, productValue, waveValue;
            int highByte, lowByte;
            u8* texel = (u8*)gNewShadowCausticTexture + rowPixelOffset;
            texel += h;
            texel += (column & 3) * 8;
            texel += (column >> 2) * 0x200;
            columnPhase = 0.39275f * column;
            wave = mathCosfHighPrecision(0.5f * mathSinfHighPrecision(columnPhase) + rowPhase);
            carrier = mathCosfHighPrecision(columnPhase);
            productValue = wave * carrier;
            productValue = 127.0f * productValue + 127.0f;
            waveValue = 127.0f * wave + 127.0f;
            lowByte = waveValue;
            highByte = productValue;
            ((NewShadowVectorTexel*)(texel + 0x60))->packedXY = lowByte | ((highByte & 0xffff) << 8);
        }
    }
    DCFlushRange(gNewShadowCausticTexture + 1, gNewShadowCausticTexture->dataSize);

    gNewShadowReflectionScrollX = 0.0f;
    gNewShadowReflectionScrollY = 0.0f;
    mmSetForceHeap3Only(savedHeap);
}

NewShadowNoiseData gNewShadowNoiseData;
Texture* gNewShadowCastTextures[NEW_SHADOW_MAX_CAST_TEXTURES];
NewShadowCastSlot gNewShadowCastSlots[NEW_SHADOW_MAX_CASTERS];
NewShadowCaster gNewShadowCasterTable[NEW_SHADOW_MAX_QUEUED_CASTERS];
Texture* gNewShadowNoiseTexFrames[NEW_SHADOW_NOISE_FRAME_COUNT];
Texture* gNewShadowTextureTable[8][4];
Texture* gNewShadowFrameTextures[NEW_SHADOW_FRAME_COUNT];

static inline void fillDiskTexture(void) {
    int j;
    int i;
    f32 cy;
    u8* base;
    for (i = 0; i < 0x20; i++) {
        int rowoff;
        int lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - 16.0f;
        lowoff += rowoff;
        for (; j < 0x20; j++) {
            int off;
            int off2;
            f32 dx, dz, d2;
            base = (u8*)gNewShadowDiskTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x80;
            off2 = off + sizeof(Texture);
            dx = cy / 16.0f;
            dz = (f32)j - 16.0f;
            dz = dz / 16.0f;
            dx = dx * 1.1f;
            dz = dz * 1.1f;
            d2 = dx * dx + dz * dz;
            base[off2] = 255.0f * ((d2 > 1.0f) ? 0.0f : (1.0f - d2));
        }
    }
}

static inline void fillSmallDiskTexture(void) {
    int j;
    int i;
    f32 cy;
    u8* base;
    for (i = 0; i < 0x10; i++) {
        int rowoff;
        int lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - 8.0f;
        lowoff += rowoff;
        for (; j < 0x10; j++) {
            int off;
            int off2;
            f32 dx, dz, d2;
            base = (u8*)gNewShadowSmallDiskTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x40;
            off2 = off + sizeof(Texture);
            dx = cy / 8.0f;
            dz = (f32)j - 8.0f;
            dz = dz / 8.0f;
            dx = dx * 1.2f;
            dz = dz * 1.2f;
            d2 = dx * dx + dz * dz;
            if (d2 > 1.0f) {
                d2 = 0.0f;
            } else {
                d2 = sqrtf(1.0f - d2);
            }
            base[off2] = 255.0f * d2;
        }
    }
}

static inline void fillRampTexture(void) {
    int x, y;
    for (x = 0; x < 256; x++) {
        for (y = 0; y < 4; y++) {
            u8* texel = (u8*)gNewShadowRampTexture + (x & 7);
            texel += (x >> 3) * 32;
            texel += (y & 3) * 8;
            texel += (y >> 2) * 1024;
            texel[sizeof(Texture)] = x;
        }
    }
}

static inline void fillFalloffTexture(void) {
    int j;
    int i;
    f32 cy;
    u8* base;
    for (i = 0; i < 0x80; i++) {
        int rowoff;
        int lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - 64.0f;
        lowoff += rowoff;
        for (; j < 0x80; j++) {
            int off;
            int off2;
            u8 val;
            f32 cx, dy, d2;
            base = (u8*)gNewShadowFalloffTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x200;
            off2 = off + sizeof(Texture);
            dy = cy / 64.0f;
            cx = ((f32)j - 64.0f) / 64.0f;
            d2 = sqrtf(dy * dy + cx * cx);
            if (d2 < 0.5f) {
                val = 0xa0;
            } else if (d2 > 1.0f) {
                val = 0;
            } else {
                val = 160.0f * (1.0f - (d2 - 0.5f) / 0.5f);
            }
            base[off2] = val;
        }
    }
}

static inline void fillLightningTexture(void) {
    int j;
    int i;
    u8* base;
    for (i = 0; i < 0x20; i++) {
        int rowoff;
        int lowoff;
        f32 c0;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        c0 = i - 16.0f;
        lowoff += rowoff;
        for (; j < 4; j++) {
            int off;
            int off2;
            f32 v;
            base = (u8*)gNewShadowLightningTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x80;
            off2 = off + sizeof(Texture);
            v = sqrtf(__fabsf(c0 / 16.0f));
            v = sqrtf(v);
            base[off2] = 255.0f * (1.0f - v);
        }
    }
}

static inline void fillRingTexture(void) {
    int j;
    int i;
    f32 cy;
    u8* base;
    for (i = 0; i < 0x80; i++) {
        int rowoff;
        int lowoff;
        f32 cy2;
        cy = ((f32)i - 64.0f) / 64.0f;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy2 = cy * cy;
        lowoff += rowoff;
        for (; j < 0x80; j++) {
            int off;
            int off2;
            f32 cx, d2;
            base = (u8*)gNewShadowRingTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x200;
            off2 = off + sizeof(Texture);
            cx = ((f32)j - 64.0f) / 64.0f;
            d2 = sqrtf(cx * cx + cy2);
            if (d2 < 0.25f || d2 > 0.75f) {
                d2 = 0.0f;
            } else {
                f32 t = 2.0f * (d2 - 0.25f);
                if (t > 0.5f) {
                    d2 = -(2.0f * (t - 0.5f) - 1.0f);
                } else {
                    d2 = -(2.0f * (0.5f - t) - 1.0f);
                }
                d2 = sqrtf(d2);
            }
            base[off2] = 16.0f * d2;
        }
    }
}

static inline void fillInverseRampTexture(void) {
    int x, y;
    for (x = 0; x < 256; x++) {
        for (y = 0; y < 4; y++) {
            u8* texel = (u8*)gNewShadowInverseRampTexture + (x & 7);
            texel += (x >> 3) * 32;
            texel += (y & 3) * 8;
            texel += (y >> 2) * 1024;
            texel[sizeof(Texture)] = 255 - x;
        }
    }
}

static inline void fillReflectionGradientTexture(void) {
    int x, y;
    for (x = 0; x < 4; x++) {
        f32 horizontal = x / 3.0f - 0.5f;
        for (y = 0; y < 4; y++) {
            u8* texel = (u8*)gNewShadowReflectionGradientTexture + (x & 3) * 2;
            int packedHorizontal;
            texel += (x >> 2) * 0x20;
            texel += (y & 3) * 8;
            texel += (y >> 2) * 0x20;
            packedHorizontal = ((int)(255.0f * horizontal + 128.0f) & 0xff) << 8;
            *(u16*)(texel + sizeof(Texture)) =
                (u16)(packedHorizontal | ((int)(255.0f * (y / 3.0f - 0.5f) + 128.0f) & 0xff));
        }
    }
}

void allocLotsOfTextures(void) {
    int i;
    int j;
    f32 rc2;
    Texture* frameTexture;
    f32 rc;
    NewShadowData* shadowData = (NewShadowData*)gNewShadowEntries;
    Texture** renderTargets = shadowData->castTextures;
    Texture** frameTextures = shadowData->frameTextures;
    f32 cy;
    int off;
    f32 cx;
    f32 d2;
    f32 v;
    int bumpRowOff;

    u8 saved = mmSetForceHeap3Only(1);

    renderTargets[0] = textureAlloc(0x100, 0x100, 0, 0, 0, 0, 0, 1, 1);
    renderTargets[1] = textureAlloc(0x100, 0x100, 1, 0, 0, 0, 0, 0, 0);
    renderTargets[2] = renderTargets[1];
    renderTargets[3] = renderTargets[1];
    renderTargets[4] = renderTargets[1];
    renderTargets[5] = renderTargets[1];
    renderTargets[6] = renderTargets[1];
    renderTargets[7] = renderTargets[1];
    memset(renderTargets[0] + 1, 0, renderTargets[0]->dataSize);
    DCFlushRange(renderTargets[0] + 1, renderTargets[0]->dataSize);

    gNewShadowReflectionTexture = textureAlloc(0x140, 0xf0, 4, 0, 0, 0, 0, 1, 1);
    gNewShadowReflectionSmallTexture = (int)textureAlloc(0x50, 0x3c, 4, 0, 0, 0, 0, 1, 1);
    gNewShadowReflectionTexture2 = (int)textureAlloc(0x140, 0xf0, 1, 0, 0, 0, 0, 1, 1);

    gNewShadowDiskTexture = (int)textureAlloc(0x20, 0x20, 1, 0, 0, 0, 0, 1, 1);
    fillDiskTexture();
    DCFlushRange((Texture*)gNewShadowDiskTexture + 1, ((Texture*)gNewShadowDiskTexture)->dataSize);

    gNewShadowSmallDiskTexture = (int)textureAlloc(0x10, 0x10, 1, 0, 0, 0, 0, 1, 1);
    fillSmallDiskTexture();
    DCFlushRange((Texture*)gNewShadowSmallDiskTexture + 1, ((Texture*)gNewShadowSmallDiskTexture)->dataSize);

    gNewShadowBumpTexture = (int)textureAlloc(0x40, 0x40, 5, 0, 0, 0, 0, 1, 1);
    {
        f32 mx = 0.0f;
        for (i = 0; i < 0x40; i++) {
            f32 fi, fi2;
            j = 0;
            fi = i - 32.0f;
            fi2 = (f32)(i + 1) - 32.0f;
            for (; j < 0x40; j++) {
                f32 cc;
                f32 d1, d2, cc2, d3, n1, b;
                f64 n2, n3;
                f32 a;
                rc = fi / 32.0f;
                rc2 = fi2 / 32.0f;
                cc = ((f32)j - 32.0f) / 32.0f;
                cc = cc * cc;
                d1 = sqrtf(rc * rc + cc);
                d2 = sqrtf(rc2 * rc2 + cc);
                cc2 = (f32)(j + 1) - 32.0f;
                cc2 = cc2 / 32.0f;
                cc2 = cc2 * cc2;
                rc = fi / 32.0f;
                d3 = sqrtf(rc * rc + cc2);
                n1 = -mathCosfHighPrecision(18.852f * d1);
                n2 = __fabs(mathCosfHighPrecision(18.852f * d2));
                n3 = __fabs(mathCosfHighPrecision(18.852f * d3));
                a = n1 - (f32)n2;
                b = n1 - (f32)n3;
                if (a > mx) {
                    mx = a;
                }
                if (b > mx) {
                    mx = b;
                }
            }
        }
        {
            f32 inv = 1.0f / mx;
            for (j = 0; j < 0x40; j++) {
                int lowoff;
                f32 fj, fj2;
                i = 0;
                bumpRowOff = (j >> 2) * 0x20;
                lowoff = (j & 3) * 2;
                fj = j - 32.0f;
                fj2 = (f32)(j + 1) - 32.0f;
                for (; i < 0x40; i++) {
                    int dst = gNewShadowBumpTexture + lowoff;
                    f32 cc, d1, d2, cc2, d3, n1, n2, n3, a, b, rowCoord;
                    f32 c;
                    int bi, ci, ai;
                    rowCoord = fj / 32.0f;
                    rc2 = fj2 / 32.0f;
                    dst += bumpRowOff;
                    dst += (i & 3) * 8;
                    dst += (i >> 2) * 0x200;
                    cc = (f32)i - 32.0f;
                    cc = cc / 32.0f;
                    cc = cc * cc;
                    d1 = sqrtf(rowCoord * rowCoord + cc);
                    d2 = sqrtf(rc2 * rc2 + cc);
                    cc2 = (f32)(i + 1) - 32.0f;
                    cc2 = cc2 / 32.0f;
                    cc2 = cc2 * cc2;
                    rowCoord = fj / 32.0f;
                    d3 = sqrtf(rowCoord * rowCoord + cc2);
                    n1 = -mathCosfHighPrecision(18.852f * d1);
                    n2 = -mathCosfHighPrecision(18.852f * d2);
                    n3 = -mathCosfHighPrecision(18.852f * d3);
                    a = inv * (127.0f * (n1 - n2)) + 127.0f;
                    b = inv * (127.0f * (n1 - n3)) + 127.0f;
                    if (d1 < 1.0f) {
                        d1 = sqrtf(1.0f - d1);
                    } else {
                        d1 = 0.0f;
                    }
                    c = 32.0f * d1;
                    if (c > 15.0f) {
                        c = 15.0f;
                    }
                    a = a / 32.0f;
                    b = b / 16.0f;
                    bi = (int)b & 0xf;
                    ci = ((u16)(int)c & 0xf) << 4;
                    ai = ((u16)(int)a & 7) << 12;
                    *(u16*)(dst + sizeof(Texture)) = (u16)(ci | ai | bi);
                }
            }
        }
    }
    DCFlushRange((Texture*)gNewShadowBumpTexture + 1, ((Texture*)gNewShadowBumpTexture)->dataSize);

    gNewShadowWhirlpoolTexture = (u32)textureLoadAsset(0x5b0);
    gNewShadowHeatHazeTexture = textureLoadAsset(0x600);
    gNewShadowSnowFlashTexture = (u32)textureLoadAsset(0xc18);

    gNewShadowRampTexture = (int)textureAlloc(0x100, 4, 1, 0, 0, 0, 0, 0, 0);
    fillRampTexture();
    DCFlushRange((Texture*)gNewShadowRampTexture + 1, ((Texture*)gNewShadowRampTexture)->dataSize);

    gNewShadowInverseRampTexture = (int)textureAlloc(0x100, 4, 1, 0, 0, 0, 0, 1, 1);
    fillInverseRampTexture();
    DCFlushRange((Texture*)gNewShadowInverseRampTexture + 1, ((Texture*)gNewShadowInverseRampTexture)->dataSize);

    gNewShadowFalloffTexture = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    fillFalloffTexture();
    DCFlushRange((Texture*)gNewShadowFalloffTexture + 1, ((Texture*)gNewShadowFalloffTexture)->dataSize);

    gNewShadowRadialTexture = textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x80; i++) {
        int rowoff;
        int lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - 64.0f;
        lowoff += rowoff;
        for (; j < 0x80; j++) {
            u8* base = (u8*)gNewShadowRadialTexture;
            int off2;
            f32 cyScaled = cy / 64.0f;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x200;
            off2 = off + sizeof(Texture);
            cx = __fabsf(((f32)j - 64.0f) / 64.0f);
            cx = cx * cx;
            d2 = sqrtf(__fabsf(cyScaled) * __fabsf(cyScaled) + cx);
            v = 1.0f - d2;
            if (v < 0.0f) {
                v = 0.0f;
            }
            base[off2] = 255.0f * v;
        }
    }
    DCFlushRange((u8*)gNewShadowRadialTexture + sizeof(Texture), gNewShadowRadialTexture->dataSize);

    gNewShadowHeavyFogTexture = textureAlloc(0x40, 0x40, 1, 0, 0, 0, 0, 1, 1);
    DCInvalidateRange((u8*)gNewShadowHeavyFogTexture + sizeof(Texture), gNewShadowHeavyFogTexture->dataSize);
    updateHeavyFogTexture(0);

    gNewShadowLightningTexture = textureAlloc(0x20, 4, 1, 0, 0, 0, 0, 1, 1);
    fillLightningTexture();
    DCFlushRange((u8*)gNewShadowLightningTexture + sizeof(Texture), gNewShadowLightningTexture->dataSize);

    gNewShadowRingTexture = textureAlloc(0x80, 0x80, 1, 0, 0, 1, 1, 1, 1);
    fillRingTexture();
    DCFlushRange((u8*)gNewShadowRingTexture + sizeof(Texture), gNewShadowRingTexture->dataSize);

    gNewShadowReflectionGradientTexture = (int)textureAlloc(4, 4, 3, 0, 0, 0, 0, 1, 1);
    fillReflectionGradientTexture();
    DCFlushRange((Texture*)gNewShadowReflectionGradientTexture + 1,
                 ((Texture*)gNewShadowReflectionGradientTexture)->dataSize);

    frameTexture = textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    memset(frameTexture + 1, 0, frameTexture->dataSize);
    frameTexture->refCount = 1;
    DCFlushRange(frameTexture + 1, frameTexture->dataSize);
    frameTextures[0] = frameTexture;
    frameTexture = textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    memset(frameTexture + 1, 0, frameTexture->dataSize);
    frameTexture->refCount = 1;
    DCFlushRange(frameTexture + 1, frameTexture->dataSize);
    frameTextures[1] = frameTexture;
    frameTexture = textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    memset(frameTexture + 1, 0, frameTexture->dataSize);
    frameTexture->refCount = 1;
    DCFlushRange(frameTexture + 1, frameTexture->dataSize);
    frameTextures[2] = frameTexture;
    GXTexModeSync();

    {
        u8* entryBytes;
        for (i = 0, entryBytes = (u8*)shadowData; i < 0x20; i += 0x10) {
            entryBytes[0x010] = 0;
            entryBytes[0x011] = 1;
            entryBytes[0x024] = 0;
            entryBytes[0x025] = 1;
            entryBytes[0x038] = 0;
            entryBytes[0x039] = 1;
            entryBytes[0x04c] = 0;
            entryBytes[0x04d] = 1;
            entryBytes[0x060] = 0;
            entryBytes[0x061] = 1;
            entryBytes[0x074] = 0;
            entryBytes[0x075] = 1;
            entryBytes[0x088] = 0;
            entryBytes[0x089] = 1;
            entryBytes[0x09c] = 0;
            entryBytes[0x09d] = 1;
            entryBytes[0x0b0] = 0;
            entryBytes[0x0b1] = 1;
            entryBytes[0x0c4] = 0;
            entryBytes[0x0c5] = 1;
            entryBytes[0x0d8] = 0;
            entryBytes[0x0d9] = 1;
            entryBytes[0x0ec] = 0;
            entryBytes[0x0ed] = 1;
            entryBytes[0x100] = 0;
            entryBytes[0x101] = 1;
            entryBytes[0x114] = 0;
            entryBytes[0x115] = 1;
            entryBytes[0x128] = 0;
            entryBytes[0x129] = 1;
            entryBytes[0x13c] = 0;
            entryBytes[0x13d] = 1;
            entryBytes += 0x140;
        }
        entryBytes = (u8*)shadowData + i * 0x14;
        for (; i < 0x21; i++) {
            int k;
            for (k = 0; k < 2; k++) {
                entryBytes[0x10 + k] = (u8)k;
            }
            entryBytes += 0x14;
        }
    }
    GXInvalidateTexAll();
    mmSetForceHeap3Only(saved);
}

int surfaceSfxSelectTrigger(u8 surfaceType, u8 soundId) {
    SurfaceSfxTable* table = &gSurfaceSfxTable;
    u16* soundBank = table->triggers[0];
    int surfaceIndex = (u8)surfaceType;
    int surfaceEntry;
    u8 triggerIndex;
    if (surfaceIndex < 0 || surfaceIndex >= SURFACE_SFX_SURFACE_TYPE_COUNT) {
        surfaceEntry = 0;
    } else {
        surfaceEntry = table->surfaceColumns[surfaceIndex];
    }
    triggerIndex = surfaceEntry;
    switch (soundId) {
    case 1:
        triggerIndex = surfaceEntry;
        break;
    case 3:
        soundBank = table->triggers[1];
        break;
    case 4:
        soundBank = table->triggers[3];
        break;
    case 5:
        soundBank = table->triggers[5];
        break;
    case 6:
        soundBank = table->triggers[4];
        break;
    case 8:
        soundBank = table->triggers[6];
        break;
    case 0xa:
        soundBank = table->triggers[7];
        break;
    case 9:
        soundBank = table->triggers[8];
        break;
    case 7:
        soundBank = table->triggers[2];
        break;
    default:
        soundBank = table->triggers[2];
        break;
    }
    return soundBank[triggerIndex];
}

void objAudioDispatchEventMask(GameObject* obj, int eventMask, u8 type, void* points, CurvesCollisionState* collision,
                               f32 speed, f32 scale) {
    ObjAnimEventList events;
    int bit;
    memset(&events, 0, sizeof(events));
    for (bit = 0; bit < 32; bit++) {
        if ((eventMask >> bit) & 1) {
            events.triggeredIds[events.triggerCount] = bit;
            events.triggerCount++;
        }
    }
    objAudioDispatchAnimEvents(obj, &events, type, points, collision, speed, scale);
}

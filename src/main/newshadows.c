#define OBJHITS_STATE_INDEX_S8
#define TEX_SETSHADER_U8
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
#define TRACK_BBOX_MASK_TYPE s8
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
#include "main/newshadows.h"
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

#define READ_TEXTURE_U16(address) (*(u16*)(address))
#define WRITE_TEXTURE_U16(address, value) (*(u16*)(address) = (value))

void blendTextures(Texture* src1, Texture* src2, f32 blend, Texture* dst)
{
    u32 fmt;
    u32 w;
    u32 h;
    u8 wA;
    u8 wB;
    int pixelB;
    int pixelA;
    int redB;
    int redA;
    int blue;
    int red;
    int green;
    u16 outputPixel;

    if (src1 == NULL)
        return;
    if (src2 == NULL)
        return;
    if (dst == NULL)
        return;
    fmt = src1->format;
    if (fmt != GX_TF_RGB565 && fmt != GX_TF_RGBA8)
        return;
    if (src2->format != fmt)
        return;
    if (dst->format != fmt)
        return;
    w = src1->width;
    if (w != src2->width)
        return;
    h = src1->height;
    if (h != src2->height)
        return;
    if (w != dst->width || h != dst->height)
    {
        return;
    }
    {
        wA = (int)(255.0f * blend) & 0xff;
        wB = (0xff - wA) & 0xff;
        if (fmt == GX_TF_RGB565)
        {
            int i, j;
            for (i = 0; i < src1->height; i++)
            {
                u8* pa;
                u8* pb;
                u8* pc;
                u32 wd;
                int rowDataOffset;
                int tileColumnOffset;
                int pixelColumnOffset;
                j = 0;
                w = i & 0xfffffffc;
                h = (i & 3) * 8;
                for (; j < (int)(wd = src1->width); j++)
                {
                    pixelColumnOffset = (j & 3) * 2;
                    pa = (u8*)src1 + pixelColumnOffset;
                    tileColumnOffset = (j >> 2) * 0x20;
                    pa += h;
                    pa += tileColumnOffset;
                    rowDataOffset = w * (int)wd * 2;
                    pa += rowDataOffset;
                    pixelA = READ_TEXTURE_U16(pa + 0x60);
                    redA = (pixelA & 0xf800) >> 8;
                    redA = (u8)(redA | ((pixelA & 0xe000) >> 13));
                    pb = (u8*)src2 + pixelColumnOffset;
                    pb += h;
                    pb += tileColumnOffset;
                    pb += rowDataOffset;
                    pixelB = READ_TEXTURE_U16(pb + 0x60);
                    redB = (pixelB & 0xf800) >> 8;
                    redB = (u8)(redB | ((pixelB & 0xe000) >> 13));
                    blue = ((u8)(((int)(wA * (u8)(((pixelA & 0x1f) << 3) | ((pixelA & 0x1c) >> 2))) >> 8) +
                               ((int)(wB * (u8)(((pixelB & 0x1f) << 3) | ((pixelB & 0x1c) >> 2))) >> 8)) &
                           0xf8) >>
                          3;
                    red = ((u8)(((int)(redB * wB) >> 8) + ((int)(redA * wA) >> 8)) & 0xf8) << 8;
                    green = ((u8)(((int)(wA * (u8)(((pixelA & 0x7e0) >> 3) | ((pixelA & 0x600) >> 9))) >> 8) +
                               ((int)(wB * (u8)(((pixelB & 0x7e0) >> 3) | ((pixelB & 0x600) >> 9))) >> 8)) &
                            0xfc)
                           << 3;
                    outputPixel = blue | (red | green);
                    pc = (u8*)dst + pixelColumnOffset + tileColumnOffset + h + rowDataOffset;
                    WRITE_TEXTURE_U16(pc + 0x60, outputPixel);
                }
            }
        }
        else
        {
            int i, j;
            for (i = 0; i < src1->height; i++)
            {
                u32 wd;
                j = 0;
                w = (i >> 2) * 8;
                h = (i & 3) * 8;
                for (; j < (int)(wd = src1->width); j++)
                {
                    int rowDataOffset;
                    int pixelColumnOffset = (j & 3) * 2;
                    int tileColumnOffset;
                    int pixelA, pixelB;
                    u8 *ad, *bd, *ct, *cd;
                    int aLo, bLo, aHi, bHi;
                    ad = (u8*)src1 + pixelColumnOffset;
                    tileColumnOffset = (j >> 2) * 0x40;
                    ad += tileColumnOffset;
                    ad += h;
                    rowDataOffset = (int)wd * w * 2;
                    ad += rowDataOffset;
                    bd = (u8*)src2 + pixelColumnOffset;
                    bd += tileColumnOffset;
                    bd += h;
                    bd += rowDataOffset;
                    aLo = READ_TEXTURE_U16(ad + 0x60);
                    aLo = (u8)aLo;
                    bLo = READ_TEXTURE_U16(bd + 0x60);
                    bLo = (u8)bLo;
                    pixelA = READ_TEXTURE_U16(ad + 0x80);
                    aHi = (pixelA & 0xff00) >> 8;
                    aHi = (u8)aHi;
                    pixelB = READ_TEXTURE_U16(bd + 0x80);
                    bHi = (pixelB & 0xff00) >> 8;
                    bHi = (u8)bHi;
                    ct = (u8*)dst + pixelColumnOffset;
                    ct += tileColumnOffset;
                    ct += h;
                    cd = ct + 0x60;
                    WRITE_TEXTURE_U16(cd + rowDataOffset,
                                      (u8)(((int)(aLo * wA) >> 8) + ((int)(bLo * wB) >> 8)));
                    WRITE_TEXTURE_U16(cd + src1->width * w * 2 + 0x20,
                                      ((u8)(((int)(aHi * wA) >> 8) + ((int)(bHi * wB) >> 8)) << 8) |
                                          (u8)(((int)(wA * (u8)pixelA) >> 8) +
                                               ((int)(wB * (u8)pixelB) >> 8)));
                }
            }
        }
        DCStoreRange((u8*)dst + sizeof(Texture), dst->dataSize);
    }
}

#undef READ_TEXTURE_U16
#undef WRITE_TEXTURE_U16

void updateHeavyFogTexture(int intensity)
{
    u8* cache;
    u32 hi, mid;
    u32 scaled;
    u32 j;
    int row;

    cache = getCache();
    for (row = 0; (u32)row < 0x40; row++)
    {
        j = 0;
        hi = ((u32)row >> 2) << 8;
        mid = (row & 3) << 3;
        scaled = (row + intensity) * 0xff;
        for (; j < 0x40; j++)
        {
            int idx;
            u32 s;
            s = (j & 7) + ((j >> 3) << 5);
            s += mid;
            idx = s + hi;
            s = scaled;
            if (s > 0x3fc0)
            {
                s = 0x3fc0;
            }
            cache[idx] = (s * j) >> 12;
        }
    }
    memcpyToCache((u8*)gNewShadowHeavyFogTexture + 0x60, cache, 0);
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

extern u32 gNewShadowFrameTextures[NEW_SHADOW_FRAME_COUNT];
extern Texture* gNewShadowNoiseTexFrames[0x10];
extern f32 gNewShadowPlacements[0x112];
u8 gSurfaceSfxTable[0xD8] = {
    0x03, 0x46, 0x03, 0x46, 0x03, 0x46, 0x03, 0x47, 0x03, 0x48, 0x03, 0x49, 0x03, 0x4A, 0x03, 0x4B,
    0x03, 0x46, 0x03, 0x4C, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00, 0x04,
    0x00, 0x05, 0x00, 0x06, 0x00, 0x01, 0x03, 0x3A, 0x01, 0x2E, 0x01, 0x2E, 0x01, 0x2E, 0x01, 0x2E,
    0x01, 0x2E, 0x01, 0x2E, 0x01, 0x2E, 0x01, 0x2E, 0x01, 0x2E, 0x01, 0x2E, 0x00, 0x07, 0x00, 0x07,
    0x00, 0x07, 0x00, 0x08, 0x00, 0x09, 0x00, 0x0A, 0x00, 0x0B, 0x00, 0x0C, 0x00, 0x07, 0x03, 0x3B,
    0x03, 0x21, 0x03, 0x21, 0x03, 0x21, 0x03, 0x22, 0x03, 0x23, 0x03, 0x25, 0x03, 0x24, 0x03, 0x26,
    0x03, 0x21, 0x03, 0x3C, 0x02, 0x1D, 0x02, 0x1D, 0x02, 0x1D, 0x02, 0x1E, 0x02, 0x1F, 0x02, 0x20,
    0x02, 0x21, 0x02, 0x22, 0x02, 0x1D, 0x03, 0x3D, 0x03, 0x85, 0x03, 0x85, 0x03, 0x85, 0x03, 0x84,
    0x03, 0x85, 0x00, 0x0A, 0x03, 0x85, 0x03, 0x84, 0x03, 0x85, 0x03, 0x85, 0x03, 0x85, 0x03, 0x85,
    0x03, 0x85, 0x03, 0x84, 0x03, 0x85, 0x00, 0x0A, 0x03, 0x85, 0x03, 0x84, 0x03, 0x85, 0x03, 0x85,
    0x03, 0x84, 0x04, 0x4A, 0x04, 0x4A, 0x03, 0x84, 0x03, 0xA4, 0x04, 0x4A, 0x04, 0x4A, 0x03, 0x84,
    0x03, 0x84, 0x04, 0x4A, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00,
    0x00, 0x07, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x05, 0x00, 0x04, 0x06, 0x00, 0x07,
    0x00, 0x00, 0x00, 0x00, 0x08, 0x00, 0x09, 0x00,
};

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

extern const f32 lbl_803DED38;
extern const f32 lbl_803DED40;
extern const f32 lbl_803DEDC0;
extern const f32 lbl_803DEDD0;
extern const f32 lbl_803DEDE0;
extern const f32 lbl_803DEDF0;
extern const f32 lbl_803DEDF4;
extern const f32 lbl_803DEDFC;
extern const f32 lbl_803DEE14;
extern const f32 lbl_803DEE18;
extern const f32 lbl_803DEE1C;

static inline void boxBlurRow(u8* row, u8* blurred, int size, int window)
{
    u32 sum;
    int k;

    sum = 0;
    for (k = 0; k < window; k++)
    {
        sum += row[k];
    }
    for (k = 0; k < size; k++)
    {
        blurred[k] = sum / window;
        sum -= row[k];
        sum += row[window + k];
    }
}

typedef union ShadowBlurOutput
{
    u8 bytes[128];
    u16 halfwords[64];
    u32 words[32];
} ShadowBlurOutput;

typedef union ShadowBlurRow
{
    u8 bytes[152];
    u16 halfwords[76];
    u32 words[38];
} ShadowBlurRow;

static void boxBlurTexture(u8* texData, int size, int window, u32 fill) {
    ShadowBlurOutput blurred;
    ShadowBlurRow row;
    u8* data;
    u32 i;

    data = texData + 0x60;
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

void renderObjectShadowTexture(GameObject* obj)
{
    f32 mtx[12];
    f32 vA, vB, vC, vD, vE, vF;
    f32 sc, objScale, saved, nx, ny, m;
    Obj_BuildWorldTransformMatrix(obj, mtx, 0);
    Camera_ProjectWorldSphere(obj->anim.localPosX - playerMapOffsetX, obj->anim.localPosY,
                              obj->anim.localPosZ - playerMapOffsetZ,
                              1.3f * (obj->anim.hitboxScale * obj->anim.rootMotionScale),
                              &vA, &vB, &vC, &vD, &vE, &vF);
    vD = 320.0f * vD + 8.0f;
    vE = 240.0f * vE + 8.0f;
    if (vD > vE)
        m = vD;
    else
        m = vE;
    sc = 64.0f / m;
    objScale = obj->anim.rootMotionScale * sc;
    nx = -vA;
    ny = vB;
    GXSetViewport(320.0f * nx, 240.0f * ny, 640.0f, 480.0f,
                  0.0f, 1.0f);
    if (vC < 0.0f)
    {
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
        GXCopyTex((Texture*)gNewShadowFrameTextures[gNewShadowFrameIndex] + 1, GX_TRUE);
        boxBlurTexture((u8*)gNewShadowFrameTextures[(gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT], 0x80,
                       0x10, 0);
        obj->anim.modelState->shadowScale = 1.0f / sc;
    }
    else
    {
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

static void sortShadowEntriesDescending(ShadowSortEntry* arr, int count) {
    int gap = 1;
    int i, j;
    ShadowSortEntry tmp;
    int limit = (count - 1) / 9;
    while (gap <= limit) {
        gap = gap * 3 + 1;
    }
    while (gap > 0) {
        for (i = gap + 1; i <= count; i++) {
            tmp = arr[i - 1];
            j = i;
            while (j > gap && arr[j - gap - 1].dist < tmp.dist) {
                arr[j - 1] = arr[j - gap - 1];
                j -= gap;
            }
            arr[j - 1] = tmp;
        }
        gap /= 3;
    }
}
extern NewShadowEntry gNewShadowEntries[0x294 / sizeof(NewShadowEntry)];

void renderShadows(int unused0, int unused1, int unused2)
{
    NewShadowCaster* casterPtr;
    f32 *mc54p;
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

    if (gNewShadowCasterCount == 0)
        return;
    CameraShake_Disable();
    sortShadowEntriesDescending((ShadowSortEntry*)shadowData->casters, gNewShadowCasterCount);
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
    for (; casterIdx < gNewShadowCasterCount && casterIdx < NEW_SHADOW_MAX_CASTERS; casterPtr++, casterIdx++)
    {
        u8 alpha;
        u8 kind;
        obj = casterPtr->obj;
        modelState = obj->anim.modelState;
        Camera_SetCurrentViewIndex(0);
        alpha = objShadowUpdateAlpha(obj, framesThisStep);
        Camera_SetCurrentViewIndex(1);
        if (alpha <= 4)
            continue;
        if ((modelState->flags & 0x20) != 0)
        {
            memcpy(mc48, &obj->anim.localPos, sizeof(Vec3f));
            memcpy(mc54p, &obj->anim.worldPos, sizeof(Vec3f));
            memcpy(&obj->anim.localPos, &modelState->overrideWorldPosX, sizeof(Vec3f));
            memcpy(&obj->anim.worldPos, &modelState->overrideWorldPosX, sizeof(Vec3f));
        }
        castSlot = (NewShadowCastSlot*)(((u8)slotIdx * sizeof(NewShadowCastSlot) + offsetof(NewShadowData, castSlots)) +
                                         (int)shadowData);
        castSlot->alpha = alpha;
        if ((u8)texIdx < NEW_SHADOW_MAX_CAST_TEXTURES && (kind = casterPtr->flags) != 0)
        {
            int screenW;
            if ((u8)texIdx < 3)
            {
                w = 0x100;
                orthoHalf = 0.5f;
            }
            else if ((u8)texIdx < 5)
            {
                w = 0x80;
                orthoHalf = 0.25f;
            }
            else
            {
                w = 0x40;
                orthoHalf = 0.125f;
            }
            if ((u8)texIdx == 0)
                screenW = w << 1;
            else
                screenW = w;
            if (kind == 2)
            {
                w = obj->anim.modelState->shadowTexture->width;
                screenW = w;
            }
            skyGetObjectLightDirection(obj, &vA.x, vAyp, vAzp);
            dot24.x = -modelState->shadowOffsetX;
            dot24.y = -modelState->shadowOffsetY;
            dot24.z = -modelState->shadowOffsetZ;
            {
                f32 dot = PSVECDotProduct(&dot24, &vA);
                if (dot < 1.0f && dot > -1.0f)
                {
                    f32 mag;
                    proj.x = 0.9f * dot24.x + 0.1f * vA.x;
                    proj.y = 0.9f * dot24.y + 0.1f * vA.y;
                    proj.z = 0.9f * dot24.z + 0.1f * vA.z;
                    mag = PSVECMag(&proj);
                    if (mag > 0.0f)
                    {
                        mag = 1.0f / mag;
                        PSVECScale(&proj, &vA, mag);
                    }
                }
            }
            if (vA.y > (-0.707f))
            {
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
                if (mag > 0.0f)
                {
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
            if (obj->anim.parent == NULL)
            {
                slot->x += gMapSavedPlayerOffsetX;
                slot->z += gMapSavedPlayerOffsetZ;
            }
            vAz = modelState->shadowScale;
            vAx = -vAz;
            if (obj->anim.parent != NULL)
            {
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
                    if (casterPtr->flags == 2)
                    {
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
                    }
                    else
                    {
                        if ((u8)texIdx == 0)
                        {
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
        }
        else
        {
            f32 fx, fz;
            castSlot->texture = obj->anim.modelState->shadowTexture;
            fx = obj->anim.localPosX;
            fz = obj->anim.localPosZ;
            if (obj->anim.parent == NULL)
            {
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
        if ((modelState->flags & 0x20) != 0)
        {
            memcpy(&obj->anim.localPos, mc48, sizeof(Vec3f));
            memcpy(&obj->anim.worldPos, mc54p, sizeof(Vec3f));
        }
    }
    if ((u8)texIdx > 1)
    {
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
    if (isDrawDistanceEnabled() != 0)
    {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        if (isWidescreen() != 0)
            Camera_SetAspectRatio(2.25f);
        else
            Camera_SetAspectRatio(1.66f);
        Camera_UpdateProjection(NULL, 0);
    }
    else if (isWidescreen() != 0)
    {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        Camera_SetAspectRatio(1.7777778f);
        Camera_UpdateProjection(NULL, 0);
    }
    else
    {
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

void queueObjectShadow(GameObject* obj)
{
    f32 dx, dy, dz, dist2;
    if (gNewShadowCasterCount < NEW_SHADOW_MAX_QUEUED_CASTERS)
    {
        gNewShadowCasterTable[gNewShadowCasterCount].obj = obj;
        dx = obj->anim.worldPosX - gNewShadowCurrentViewSlot->x;
        dy = obj->anim.worldPosY - gNewShadowCurrentViewSlot->y;
        dz = obj->anim.worldPosZ - gNewShadowCurrentViewSlot->z;
        dist2 = dx * dx + dy * dy + dz * dz;
        if (dist2 > 0.0f)
        {
            double guess = __frsqrte((double)dist2);
            volatile f32 root;
            guess = 0.5 * guess * (3.0 - guess * guess * dist2);
            guess = 0.5 * guess * (3.0 - guess * guess * dist2);
            guess = 0.5 * guess * (3.0 - guess * guess * dist2);
            root = (f32)(dist2 * guess);
            dist2 = root;
        }
        gNewShadowCasterTable[gNewShadowCasterCount].scale = obj->anim.modelState->shadowScale / dist2;
        if (obj->anim.modelInstance->shadowType == OBJ_SHADOW_TYPE_MODEL_GEOMETRIC)
        {
            gNewShadowCasterTable[gNewShadowCasterCount].flags = 1;
            if (obj->anim.modelInstance->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW)
            {
                gNewShadowCasterTable[gNewShadowCasterCount].flags = 2;
                gNewShadowCasterTable[gNewShadowCasterCount].scale = 3.4028235e+38f;
            }
        }
        else
        {
            gNewShadowCasterTable[gNewShadowCasterCount].flags = 0;
        }
        gNewShadowCasterCount++;
    }
}
extern Texture* gNewShadowTextureTable[8][4];

void newshadows_getShadowTextureTable4x8(Texture*** tableOut, int* columnsOut, int* rowsOut)
{
    *tableOut = &gNewShadowTextureTable[0][0];
    *columnsOut = 4;
    *rowsOut = 8;
}

void getNewShadowNoiseTextureFrames(Texture*** tableOut, int* frameCountOut)
{
    *tableOut = gNewShadowNoiseTexFrames;
    *frameCountOut = 0x10;
}

void getNewShadowSnowFlashTexture(u32* p)
{
    *p = gNewShadowSnowFlashTexture;
}
void getNewShadowHeatHazeTexture(Texture** p)
{
    *p = gNewShadowHeatHazeTexture;
}
void getNewShadowRingTexture(Texture** out)
{
    *out = gNewShadowRingTexture;
}
void getNewShadowLightningTexture(Texture** p)
{
    *p = gNewShadowLightningTexture;
}
void getNewShadowHeavyFogTexture(Texture** p)
{
    *p = gNewShadowHeavyFogTexture;
}
void getNewShadowDistortionTexture(Texture** out)
{
    *out = gNewShadowDistortionTexture;
}
void getNewShadowRadialTexture(Texture** out)
{
    *out = gNewShadowRadialTexture;
}

void* textureAlloc512(void)
{
    Texture* tex = (Texture*)textureAlloc(0x200, 0x200, 1, 0, 0, 0, 0, 0, 0);
    tex->refCount = 1;
    DCFlushRange((char*)tex + 0x60, tex->dataSize);
    return tex;
}
void getNewShadowRampTexture(u32* out)
{
    *out = gNewShadowRampTexture;
}

u32 getNewShadowSmallDiskTexture(void)
{
    return gNewShadowSmallDiskTexture;
}
void getNewShadowDiskTexture(u32* out)
{
    *out = gNewShadowDiskTexture;
}
void getReflectionTexture2(u32* p)
{
    *p = gNewShadowReflectionTexture2;
}
void getNewShadowCausticTexture(u32* p)
{
    *p = (u32)gNewShadowCausticTexture;
}


void getObjectShadowDrawParams(GameObject* obj, u32* outTexture, f32* outScale, int* outX, int* outY)
{
    int idx = (gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT;
    *outTexture = gNewShadowFrameTextures[idx];
    *outScale = obj->anim.modelState->shadowScale;
    *outX = (int)obj->anim.modelState->shadowOffsetX;
    *outY = (int)obj->anim.modelState->shadowOffsetY;
}


f32 getNewShadowDistortionWaveOffset(void)
{
    return gNewShadowDistortionWaveOffset;
}

void loadNewShadowBumpTexture(int texMapId)
{
    GXLoadTexObj(textureGetGXTexObj((Texture*)gNewShadowBumpTexture), texMapId);
}

void selectWhirlpoolTexture(int id)
{
    register int idCopy = id;
    Texture* p = (Texture*)gNewShadowWhirlpoolTexture;
    if (p->preloaded != 0)
    {
        struct _GXTexObj* obj = textureGetGXTexObj(p);
        GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(p), idCopy);
    }
    else
    {
        GXLoadTexObj(textureGetGXTexObj(p), idCopy);
    }
}

void selectReflectionTexture(int id)
{
    register int idCopy = id;
    Texture* p = gNewShadowReflectionTexture;
    if (p->preloaded != 0)
    {
        struct _GXTexObj* obj = textureGetGXTexObj(p);
        GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(p), idCopy);
    }
    else
    {
        GXLoadTexObj(textureGetGXTexObj(p), idCopy);
    }
}
u32 getReflectionTexture1(void)
{
    return (u32)gNewShadowReflectionTexture;
}

NewShadowEntry gNewShadowEntries[0x294 / sizeof(NewShadowEntry)];
u32 getNewShadowReflectionGradientTexture(void)
{
    return gNewShadowReflectionGradientTexture;
}

u32 getNewShadowInverseRampTexture(void)
{
    return gNewShadowInverseRampTexture;
}
u32 getNewShadowFalloffTexture(void)
{
    return gNewShadowFalloffTexture;
}

void loadNewShadowSmallReflectionTexture(int id)
{
    register int idCopy = id;
    Texture* p = (Texture*)gNewShadowReflectionSmallTexture;
    if (p->preloaded != 0)
    {
        struct _GXTexObj* obj = textureGetGXTexObj(p);
        GXLoadTexObjPreLoaded(obj, textureGetGXTexRegion(p), idCopy);
    }
    else
    {
        GXLoadTexObj(textureGetGXTexObj(p), idCopy);
    }
}
void drawReflectionTexture(void)
{
    char* texture = (char*)gNewShadowReflectionTexture;
    drawTexture(texture, 0.0f, 0.0f, 0xff, 0x40);
    GXSetTexCopySrc(0, 0, 0x50, 0x3c);
    GXSetTexCopyDst(0x50, 0x3c, GX_TF_RGB565, GX_FALSE);
    GXCopyTex((char*)gNewShadowReflectionSmallTexture + 0x60, GX_TRUE);
    if (((Texture*)gNewShadowReflectionSmallTexture)->preloaded != 0)
    {
        GXTexObj* obj = textureGetGXTexObj((Texture*)gNewShadowReflectionSmallTexture);
        GXPreLoadEntireTexture(obj, textureGetGXTexRegion((Texture*)gNewShadowReflectionSmallTexture));
    }
}

void updateReflectionTextures(void)
{
    GXSetTexCopySrc(0, 0, 0x280, 0x1e0);
    GXSetTexCopyDst(0x140, 0xf0, GX_TF_RGB565, GX_TRUE);
    GXCopyTex((char*)gNewShadowReflectionTexture + 0x60, GX_FALSE);
    GXSetTexCopySrc(0, 0, 0x280, 0x1e0);
    GXSetTexCopyDst(0x140, 0xf0, GX_TF_Z8, GX_TRUE);
    GXCopyTex((char*)gNewShadowReflectionTexture2 + 0x60, GX_FALSE);
    if (gNewShadowReflectionTexture->preloaded != 0)
    {
        GXTexObj* obj = textureGetGXTexObj(gNewShadowReflectionTexture);
        GXPreLoadEntireTexture(obj, textureGetGXTexRegion(gNewShadowReflectionTexture));
    }
    if (((Texture*)gNewShadowReflectionTexture2)->preloaded != 0)
    {
        GXTexObj* obj = textureGetGXTexObj((Texture*)gNewShadowReflectionTexture2);
        GXPreLoadEntireTexture(obj, textureGetGXTexRegion((Texture*)gNewShadowReflectionTexture2));
    }
    if (gNewShadowReflectionTexture->preloaded == 0 ||
        ((Texture*)gNewShadowReflectionTexture2)->preloaded == 0)
    {
        GXInvalidateTexAll();
    }
    GXPixModeSync();
}

void newShadowsBeginFrame(void)
{
    f32 hi, lo;
    if (getHudHiddenFrameCount() == 0)
    {
        gNewShadowReflectionScrollX = 0.0084f * timeDelta + gNewShadowReflectionScrollX;
        gNewShadowReflectionScrollY = 0.003f * timeDelta + gNewShadowReflectionScrollY;
        if (gNewShadowReflectionScrollX > 256.0f)
            gNewShadowReflectionScrollX = gNewShadowReflectionScrollX - 256.0f;
        if (gNewShadowReflectionScrollY > 256.0f)
            gNewShadowReflectionScrollY = gNewShadowReflectionScrollY - 256.0f;
    }
    gNewShadowCasterCount = 0;
    gNewShadowCurrentViewSlot = Camera_GetCurrent();
    gNewShadowDistortionWavePhase = gNewShadowDistortionWavePhase + framesThisStep * 0x28a;
    gNewShadowDistortionWaveOffset = 0.2f * mathSinfHighPrecision(6.284f * (f32)(u32)gNewShadowDistortionWavePhase / 65536.0f);
    mapClearBlockEdgeFlags();
    gNewShadowFrameIndex = (gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT;
    if (isHeavyFogEnabled())
    {
        f32 z = Camera_GetInverseViewMatrix()[7];
        int v;
        getHeavyFogRange(&hi, &lo);
        if (z >= hi)
            v = 0;
        else if (z <= lo)
            v = 0x40;
        else
            v = (int)(64.0f * (hi - z) / (hi - lo));
        if ((u8)v != gNewShadowHeavyFogIntensity)
            updateHeavyFogTexture((u8)v);
    }
}


void newshadows_getReflectionScrollOffsets(f32* outScrollX, f32* outScrollY)
{
    *outScrollX = gNewShadowReflectionScrollX;
    *outScrollY = gNewShadowReflectionScrollY;
}


/* Builds the animated water-noise assets: scatters up to 50 non-overlapping random
   placements ([0]=lifetime 8..16 frames, [1..2]=pos, [3]=outer size, [4]=inner size),
   renders 16 noise animation frames through evalNoisePlacements, then the caustic texture. */

void findSomething(void* needle)
{
    int i;
    for (i = 0; i < NEW_SHADOW_ENTRY_CAPACITY; ++i)
    {
        if (gNewShadowEntries[i].isActive != 0 && &gNewShadowEntries[i] == needle)
        {
            gNewShadowEntries[i].isActive = 0;
            return;
        }
    }
}

void freeNewShadowDistortionTexture(void)
{
    mm_free(gNewShadowDistortionTexture);
    gNewShadowDistortionTexture = 0;
}

void createNewShadowDistortionTexture(void)
{
    int yhi;
    int ylo;
    int y, x;
    f32 dirX, dirY;
    f32 dist;
    f32 s;
    f32 t;
    f32 normY;
    gNewShadowDistortionTexture = textureAlloc(0x100, 0x100, 3, 0, 0, 0, 0, 1, 1);
    for (y = 0; y < 0x100; y++)
    {
        x = 0;
        yhi = (y >> 2) * 0x20;
        ylo = (y & 3) * 2;
        for (; x < 0x100; x++)
        {
            u8* rowBase;
            u8* tileRow;
            u8* texel;
            rowBase = (u8*)gNewShadowDistortionTexture;
            rowBase += ylo;
            tileRow = rowBase + yhi;
            tileRow += (x & 3) * 8;
            texel = tileRow + (x >> 2) * 0x800;
            dirY = y - 127.5f;
            dirX = x - 127.5f;
            dist = sqrtf(dirY * dirY + dirX * dirX);
            normY = dirY / dist;
            dirX /= dist;
            if (dist <= 112.0f)
            {
                t = 2.0f * (100.799995f - 0.9f * dist);
                s = t * 0.00390625f;
            }
            else
            {
                s = 0.0f;
            }
            normY *= s;
            dirX *= s;
            normY = lbl_803DEDC0 * normY + 128.0f;
            dirX = lbl_803DEDC0 * dirX + 128.0f;
            ((NewShadowVectorTexel*)(texel + 0x60))->packedXY =
                (u16)((int)dirX | (((int)normY & 0xffff) << 8));
        }
    }
    DCFlushRange(gNewShadowDistortionTexture + 1, gNewShadowDistortionTexture->dataSize);
}
/* Sample the animated noise field built from gNewShadowPlacements: sums the
   contribution of every active placement at texel (px,pz) for animation frame
   `frame`. out2 = sparkle intensity (0..1), out1 = accumulated shift term. */
static void evalNoisePlacements(f32 px, f32 pz, f32 frame, f32* placements, int count, f32* out1, f32* out2)
{
    f32* place;
    int i;
    f32 acc5;
    f32 acc6;

    acc5 = acc6 = 0.0f;
    place = placements;
    for (i = 0; i < count; i++, place += 5)
    {
        f32 over = 0.0f;
        if (frame < place[0])
        {
            f32 mx, mz, t, s0, tmp, p2lo, sq, ratio, frac, depth;
            t = 0.25f + (place[0] - frame) / place[0];
            if (t > 1.0f)
                t = 1.0f;
            s0 = sqrtf(t);

            mx = __fabsf(place[1] - px);
            tmp = __fabsf((1.0f + place[1]) - px);
            if (tmp < mx)
                mx = tmp;
            tmp = __fabsf((place[1] - 1.0f) - px);
            if (tmp < mx)
                mx = tmp;

            mz = __fabsf(place[2] - pz);
            if (pz > place[2])
                over = pz - place[2];
            tmp = __fabsf((1.0f + place[2]) - pz);
            if (tmp < mz)
            {
                mz = tmp;
                over = 0.0f;
            }
            p2lo = place[2] - 1.0f;
            tmp = __fabsf(p2lo - pz);
            if (tmp < mz)
            {
                mz = tmp;
                if (pz > p2lo)
                    over = pz - p2lo;
            }

            sq = sqrtf(mx * mx + mz * mz);

            ratio = frame / place[0];
            frac = sqrtf(ratio);
            depth = place[3] - frac * (place[3] - place[4]);
            if (sq <= depth)
            {
                f32 sqd = sq / depth;
                f32 g;
                sqd = 1.0f - sqd;
                g = sqrtf(sqd);
                acc5 = s0 * g + acc5;
                over = over / depth;
                acc6 = acc6 + over;
                acc6 = lbl_803DED38 * (1.0f - frame * lbl_803DEDD0) + acc6;
            }
        }
    }
    if (acc5 > 1.0f)
        acc5 = 1.0f;
    if (acc6 > 1.0f)
        acc6 = 1.0f;
    *out1 = lbl_803DED40 * acc6 + 0.4375f;
    *out2 = acc5;
}
void newShadowsInitProceduralTextures(void)
{
    u8 savedHeap;
    int placementAttempts;
    int row;
    f32* placementZ;
    f32* otherPlacement;
    f32* placementRadius;
    f32* placement;
    f32* placementX;
    u8 overlaps;
    int otherIndex;
    int placedCount;
    int frame;

    savedHeap = mmSetDelay(1);
    placedCount = 0;
    placementAttempts = 0;
    placement = gNewShadowPlacements;
    while (placedCount < 0x32 && placementAttempts < 10000u)
    {
        placement[0] = randomGetRange(8, 0x10);
        placement[3] = 0.01f * randomGetRange(5, 10);
        placement[4] = placement[3] * (0.01f * randomGetRange(0x14, 0x32));
        placementAttempts = 0;
        placementX = &placement[1];
        placementZ = &placement[2];
        placementRadius = &placement[4];
        do
        {
            *placementX = 0.001f * randomGetRange(0, 999);
            *placementZ = 0.001f * randomGetRange(0, 999);
            overlaps = 0;
            otherIndex = 0;
            otherPlacement = gNewShadowPlacements;
            while (otherIndex < placedCount && !overlaps)
            {
                f32 xDistance, zDistance, wrappedDistance;
                xDistance = __fabsf(*placementX - otherPlacement[1]);
                wrappedDistance = __fabsf((1.0f + *placementX) - otherPlacement[1]);
                if (wrappedDistance < xDistance)
                    xDistance = wrappedDistance;
                wrappedDistance = __fabsf((*placementX - 1.0f) - otherPlacement[1]);
                if (wrappedDistance < xDistance)
                    xDistance = wrappedDistance;
                zDistance = __fabsf(*placementZ - otherPlacement[2]);
                wrappedDistance = __fabsf((1.0f + *placementZ) - otherPlacement[2]);
                if (wrappedDistance < zDistance)
                    zDistance = wrappedDistance;
                wrappedDistance = __fabsf((*placementZ - 1.0f) - otherPlacement[2]);
                if (wrappedDistance < zDistance)
                    zDistance = wrappedDistance;
                wrappedDistance = zDistance * zDistance;
                zDistance = xDistance * xDistance + wrappedDistance;
                zDistance = sqrtf(zDistance);
                if (zDistance < *placementRadius + otherPlacement[3])
                    overlaps = 1;
                otherPlacement += 5;
                otherIndex++;
            }
            placementAttempts++;
        } while (overlaps && placementAttempts < 10000u);
        placement += 5;
        placedCount++;
    }

    {
        u32 noisePlacementCount = placedCount;

        frame = 0;
        for (; frame < 0x10; frame++)
        {
            gNewShadowNoiseTexFrames[frame] = textureAlloc(0x40, 0x40, 3, 0, 0, 1, 1, 1, 1);
            for (row = 0; row < 0x40; row++)
            {
                int rowPixelOffset;
                int column, h;
                column = 0;
                h = (row >> 2) * 0x20;
                rowPixelOffset = (row & 3) * 2;
                for (; column < 0x40; column++)
                {
                    int highByte, lowByte;
                    int texelAddress = (int)gNewShadowNoiseTexFrames[frame] + h + rowPixelOffset;
                    f32 shift, intensity;
                    f32 rowCoord, columnCoord;
                    texelAddress += (column & 3) * 8;
                    texelAddress += (column >> 2) * 0x200;
                    rowCoord = row * lbl_803DEDE0;
                    columnCoord = column * lbl_803DEDE0;
                    evalNoisePlacements(rowCoord, columnCoord, frame,
                                gNewShadowPlacements, noisePlacementCount, &shift, &intensity);
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
    for (row = 0; row < 0x40; row++)
    {
        int column;
        int h, rowPixelOffset;
        f32 rowPhase;
        column = 0;
        h = (row >> 2) * 0x20;
        rowPixelOffset = (row & 3) * 2;
        rowPhase = 0.0981875f * row;
        for (; column < 0x40; column++)
        {
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
            ((NewShadowVectorTexel*)(texel + 0x60))->packedXY =
                lowByte | ((highByte & 0xffff) << 8);
        }
    }
    DCFlushRange(gNewShadowCausticTexture + 1, gNewShadowCausticTexture->dataSize);

    gNewShadowReflectionScrollX = 0.0f;
    gNewShadowReflectionScrollY = 0.0f;
    mmSetDelay(savedHeap);
}


f32 gNewShadowPlacements[0x112];
u32 gNewShadowCastTextures[NEW_SHADOW_MAX_CAST_TEXTURES];
NewShadowCastSlot gNewShadowCastSlots[NEW_SHADOW_MAX_CASTERS];
NewShadowCaster gNewShadowCasterTable[NEW_SHADOW_MAX_QUEUED_CASTERS];
Texture* gNewShadowNoiseTexFrames[0x10];
Texture* gNewShadowTextureTable[8][4];
u32 gNewShadowFrameTextures[NEW_SHADOW_FRAME_COUNT];


static inline void fillDiskTexture(void)
{
    int j;
    int i;
    f32 cy;
    u8* base;
    for (i = 0; i < 0x20; i++)
    {
        int rowoff;
        int lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - 16.0f;
        lowoff += rowoff;
        for (; j < 0x20; j++)
        {
            int off;
            int off2;
            f32 dx, dz, d2;
            base = (u8*)gNewShadowDiskTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x80;
            off2 = off + 0x60;
            dx = cy * lbl_803DEDD0;
            dz = (f32)j - 16.0f;
            dz = dz * lbl_803DEDD0;
            dx = dx * lbl_803DEDF0;
            dz = dz * lbl_803DEDF0;
            d2 = dx * dx + dz * dz;
            base[off2] = 255.0f * ((d2 > 1.0f) ? 0.0f : (1.0f - d2));
        }
    }
}

static inline void fillSmallDiskTexture(void)
{
    int j;
    int i;
    f32 cy;
    u8* base;
    for (i = 0; i < 0x10; i++)
    {
        int rowoff;
        int lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - 8.0f;
        lowoff += rowoff;
        for (; j < 0x10; j++)
        {
            int off;
            int off2;
            f32 dx, dz, d2;
            base = (u8*)gNewShadowSmallDiskTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x40;
            off2 = off + 0x60;
            dx = cy * lbl_803DED40;
            dz = (f32)j - 8.0f;
            dz = dz * lbl_803DED40;
            dx = dx * lbl_803DEDF4;
            dz = dz * lbl_803DEDF4;
            d2 = dx * dx + dz * dz;
            if (d2 > 1.0f)
            {
                d2 = 0.0f;
            }
            else
            {
                d2 = sqrtf(1.0f - d2);
            }
            base[off2] = 255.0f * d2;
        }
    }
}

static inline void fillRampTexture(void)
{
    int i;
    for (i = 0; i < 0x100; i++)
    {
        u8* t;
        t = (u8*)gNewShadowRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        t[0x60] = i;
        t = (u8*)gNewShadowRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        t[0x68] = i;
        t = (u8*)gNewShadowRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        t[0x70] = i;
        t = (u8*)gNewShadowRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        t[0x78] = i;
    }
}

static inline void fillFalloffTexture(void)
{
    int j;
    int i;
    f32 cy;
    u8* base;
    for (i = 0; i < 0x80; i++)
    {
        int rowoff;
        int lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - 64.0f;
        lowoff += rowoff;
        for (; j < 0x80; j++)
        {
            int off;
            int off2;
            u8 val;
            f32 cx, dy, d2;
            base = (u8*)gNewShadowFalloffTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x200;
            off2 = off + 0x60;
            dy = cy * lbl_803DEDE0;
            cx = ((f32)j - 64.0f) * lbl_803DEDE0;
            d2 = sqrtf(dy * dy + cx * cx);
            if (d2 < lbl_803DED38)
            {
                val = 0xa0;
            }
            else if (d2 > 1.0f)
            {
                val = 0;
            }
            else
            {
                val = 160.0f * (1.0f - (d2 - lbl_803DED38) / lbl_803DED38);
            }
            base[off2] = val;
        }
    }
}

static inline void fillLightningTexture(void)
{
    int j;
    int i;
    u8* base;
    for (i = 0; i < 0x20; i++)
    {
        int rowoff;
        int lowoff;
        f32 c0;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        c0 = i - 16.0f;
        lowoff += rowoff;
        for (; j < 4; j++)
        {
            int off;
            int off2;
            f32 v;
            base = (u8*)gNewShadowLightningTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x80;
            off2 = off + 0x60;
            v = sqrtf(__fabsf(c0 * lbl_803DEDD0));
            v = sqrtf(v);
            base[off2] = 255.0f * (1.0f - v);
        }
    }
}

static inline void fillRingTexture(void)
{
    int j;
    int i;
    f32 cy;
    u8* base;
    for (i = 0; i < 0x80; i++)
    {
        int rowoff;
        int lowoff;
        f32 cy2;
        cy = ((f32)i - 64.0f) * lbl_803DEDE0;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy2 = cy * cy;
        lowoff += rowoff;
        for (; j < 0x80; j++)
        {
            int off;
            int off2;
            f32 cx, d2;
            base = (u8*)gNewShadowRingTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x200;
            off2 = off + 0x60;
            cx = ((f32)j - 64.0f) * lbl_803DEDE0;
            d2 = sqrtf(cx * cx + cy2);
            if (d2 < 0.25f || d2 > 0.75f)
            {
                d2 = 0.0f;
            }
            else
            {
                f32 t = 2.0f * (d2 - 0.25f);
                if (t > lbl_803DED38)
                {
                    d2 = -(2.0f * (t - lbl_803DED38) - 1.0f);
                }
                else
                {
                    d2 = -(2.0f * (lbl_803DED38 - t) - 1.0f);
                }
                d2 = sqrtf(d2);
            }
            base[off2] = 16.0f * d2;
        }
    }
}

static inline void fillInverseRampTexture(void)
{
    int i;
    for (i = 0; i < 0x100; i++)
    {
        u8* t;
        t = (u8*)gNewShadowInverseRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        t[0x60] = (u8)(255 - i);
        t = (u8*)gNewShadowInverseRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        t[0x68] = (u8)(255 - i);
        t = (u8*)gNewShadowInverseRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        t[0x70] = (u8)(255 - i);
        t = (u8*)gNewShadowInverseRampTexture + (i & 7);
        t += (i >> 3) * 0x20;
        t[0x78] = (u8)(255 - i);
    }
}

void allocLotsOfTextures(void)
{
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

    u8 saved = mmSetDelay(1);

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
        for (i = 0; i < 0x40; i++)
        {
            f32 fi, fi2;
            j = 0;
            fi = i - 32.0f;
            fi2 = (f32)(i + 1) - 32.0f;
            for (; j < 0x40; j++)
            {
                f32 cc;
                f32 d1, d2, cc2, d3, n1, b;
                f64 n2, n3;
                f32 a;
                rc = fi * lbl_803DEDFC;
                rc2 = fi2 * lbl_803DEDFC;
                cc = ((f32)j - 32.0f) * lbl_803DEDFC;
                cc = cc * cc;
                d1 = sqrtf(rc * rc + cc);
                d2 = sqrtf(rc2 * rc2 + cc);
                cc2 = (f32)(j + 1) - 32.0f;
                cc2 = cc2 * lbl_803DEDFC;
                cc2 = cc2 * cc2;
                rc = fi * lbl_803DEDFC;
                d3 = sqrtf(rc * rc + cc2);
                n1 = -mathCosfHighPrecision(18.852f * d1);
                n2 = __fabs(mathCosfHighPrecision(18.852f * d2));
                n3 = __fabs(mathCosfHighPrecision(18.852f * d3));
                a = n1 - (f32)n2;
                b = n1 - (f32)n3;
                if (a > mx)
                    mx = a;
                if (b > mx)
                    mx = b;
            }
        }
        {
            f32 inv = 1.0f / mx;
            for (j = 0; j < 0x40; j++)
            {
                int lowoff;
                f32 fj, fj2;
                i = 0;
                bumpRowOff = (j >> 2) * 0x20;
                lowoff = (j & 3) * 2;
                fj = j - 32.0f;
                fj2 = (f32)(j + 1) - 32.0f;
                for (; i < 0x40; i++)
                {
                    int dst = gNewShadowBumpTexture + lowoff;
                    f32 cc, d1, d2, cc2, d3, n1, n2, n3, a, b, rowCoord;
                    f32 c;
                    int bi, ci, ai;
                    rowCoord = fj * lbl_803DEDFC;
                    rc2 = fj2 * lbl_803DEDFC;
                    dst += bumpRowOff;
                    dst += (i & 3) * 8;
                    dst += (i >> 2) * 0x200;
                    cc = (f32)i - 32.0f;
                    cc = cc * lbl_803DEDFC;
                    cc = cc * cc;
                    d1 = sqrtf(rowCoord * rowCoord + cc);
                    d2 = sqrtf(rc2 * rc2 + cc);
                    cc2 = (f32)(i + 1) - 32.0f;
                    cc2 = cc2 * lbl_803DEDFC;
                    cc2 = cc2 * cc2;
                    rowCoord = fj * lbl_803DEDFC;
                    d3 = sqrtf(rowCoord * rowCoord + cc2);
                    n1 = -mathCosfHighPrecision(18.852f * d1);
                    n2 = -mathCosfHighPrecision(18.852f * d2);
                    n3 = -mathCosfHighPrecision(18.852f * d3);
                    a = inv * (lbl_803DEDC0 * (n1 - n2)) + lbl_803DEDC0;
                    b = inv * (lbl_803DEDC0 * (n1 - n3)) + lbl_803DEDC0;
                    if (d1 < 1.0f)
                    {
                        d1 = sqrtf(1.0f - d1);
                    }
                    else
                    {
                        d1 = 0.0f;
                    }
                    c = 32.0f * d1;
                    if (c > 15.0f)
                        c = 15.0f;
                    a = a * lbl_803DEDFC;
                    b = b * lbl_803DEDD0;
                    bi = (int)b & 0xf;
                    ci = ((u16)(int)c & 0xf) << 4;
                    ai = ((u16)(int)a & 7) << 12;
                    *(u16*)(dst + 0x60) = (u16)(ci | ai | bi);
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
    for (i = 0; i < 0x80; i++)
    {
        int rowoff;
        int lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - 64.0f;
        lowoff += rowoff;
        for (; j < 0x80; j++)
        {
            u8* base = (u8*)gNewShadowRadialTexture;
            int off2;
            f32 cyScaled = cy * lbl_803DEDE0;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x200;
            off2 = off + 0x60;
            cx = __fabsf(((f32)j - 64.0f) * lbl_803DEDE0);
            cx = cx * cx;
            d2 = sqrtf(__fabsf(cyScaled) * __fabsf(cyScaled) + cx);
            v = 1.0f - d2;
            if (v < 0.0f)
                v = 0.0f;
            base[off2] = 255.0f * v;
        }
    }
    DCFlushRange((u8*)gNewShadowRadialTexture + 0x60, gNewShadowRadialTexture->dataSize);

    gNewShadowHeavyFogTexture = textureAlloc(0x40, 0x40, 1, 0, 0, 0, 0, 1, 1);
    DCInvalidateRange((u8*)gNewShadowHeavyFogTexture + 0x60, gNewShadowHeavyFogTexture->dataSize);
    updateHeavyFogTexture(0);

    gNewShadowLightningTexture = textureAlloc(0x20, 4, 1, 0, 0, 0, 0, 1, 1);
    fillLightningTexture();
    DCFlushRange((u8*)gNewShadowLightningTexture + 0x60, gNewShadowLightningTexture->dataSize);

    gNewShadowRingTexture = textureAlloc(0x80, 0x80, 1, 0, 0, 1, 1, 1, 1);
    fillRingTexture();
    DCFlushRange((u8*)gNewShadowRingTexture + 0x60, gNewShadowRingTexture->dataSize);

    gNewShadowReflectionGradientTexture = (int)textureAlloc(4, 4, 3, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 4; i++)
    {
        f32 x = i / 3.0f;
        int hi;
        int t;
        u16 v;
        x -= lbl_803DED38;
        t = gNewShadowReflectionGradientTexture + (i & 3) * 2;
        t += (i >> 2) * 0x20;
        hi = ((int)(255.0f * x + 128.0f) & 0xff) << 8;
        *(u16*)(t + 0x60) = (u16)(hi | ((int)lbl_803DED38 & 0xff));
        t = gNewShadowReflectionGradientTexture + (i & 3) * 2;
        t += (i >> 2) * 0x20;
        *(u16*)(t + 0x68) = (u16)(hi | ((int)lbl_803DEE14 & 0xff));
        t = gNewShadowReflectionGradientTexture + (i & 3) * 2;
        t += (i >> 2) * 0x20;
        *(u16*)(t + 0x70) = (u16)(hi | ((int)lbl_803DEE18 & 0xff));
        v = (u16)(hi | ((int)lbl_803DEE1C & 0xff));
        t = gNewShadowReflectionGradientTexture + (i & 3) * 2;
        t += (i >> 2) * 0x20;
        *(u16*)(t + 0x78) = v;
    }
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
        for (i = 0, entryBytes = (u8*)shadowData; i < 0x20; i += 0x10)
        {
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
        for (; i < 0x21; i++)
        {
            int k;
            for (k = 0; k < 2; k++)
            {
                entryBytes[0x10 + k] = (u8)k;
            }
            entryBytes += 0x14;
        }
    }
    GXInvalidateTexAll();
    mmSetDelay(saved);
}

int surfaceSfxSelectTrigger(u8 a, u8 b)
{
    u8* base = gSurfaceSfxTable;
    int idx = (u8)a;
    int t;
    u8 v;
    if (idx < 0 || idx >= 0x23)
        t = 0;
    else
        t = base[idx + 0xb4];
    v = t;
    switch (b)
    {
    case 1:
        v = t;
        break;
    case 3:
        base += 0x14;
        break;
    case 4:
        base += 0x3c;
        break;
    case 5:
        base += 0x64;
        break;
    case 6:
        base += 0x50;
        break;
    case 8:
        base += 0x78;
        break;
    case 0xa:
        base += 0x8c;
        break;
    case 9:
        base += 0xa0;
        break;
    case 7:
        base += 0x28;
        break;
    default:
        base += 0x28;
        break;
    }
    return *(u16*)(base + v * 2);
}

void objAudioDispatchEventMask(GameObject* obj, int eventMask, u8 type, void* points, void* state, f32 unused,
                               f32 scale)
{
    ObjAnimEventList events;
    int bit;
    memset(&events, 0, sizeof(events));
    for (bit = 0; bit < 32; bit++)
    {
        if ((eventMask >> bit) & 1)
        {
            events.triggeredIds[events.triggerCount] = bit;
            events.triggerCount++;
        }
    }
    objAudioDispatchAnimEvents(obj, &events, type, points, state, unused, scale);
}

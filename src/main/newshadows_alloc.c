#include "main/game_object.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_hud_api.h"
#include "track/intersect_screen_api.h"
#include "main/hud_visibility_api.h"
#include "main/object_api.h"
#include "main/model.h"
#include "main/objprint_render_api.h"
#include "main/newshadows_audio_api.h"
#include "main/newshadows.h"
#include "main/texture.h"
#include "main/newshadows_shadow_api.h"
#include "main/rcp_dolphin_api.h"
#include "main/mm.h"
#include "dolphin/os/OSCache.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/gx/GXManage.h"
#include "dolphin/gx/GXCull.h"
#include "dolphin/gx/GXTransformLegacy.h"
#include "dolphin/gx/GXStruct.h"
#include "dolphin/gx/GXTexture.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/lightmap_api.h"
#include "main/pi_dolphin.h"
#include "main/track_dolphin_api.h"
#include "main/track_dolphin_shadow_api.h"
#include "main/shader_api.h"
#include "main/sky_api.h"
#include "main/track_dolphin.h"
#include "main/objprint_render_api.h"
#include "main/shader_dolphin.h"
#include "main/dll/modgfx.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "string.h"
#include "main/newshadows_internal.h"
extern NewShadowEntry gNewShadowEntries[0x294 / sizeof(NewShadowEntry)];
extern u8 lbl_8030E8B0[0xD8];
extern const double lbl_803DED58;
extern const double lbl_803DED60;
extern const f32 lbl_803DED28;

extern u32 gNewShadowReflectionSmallTexture;
extern u32 gNewShadowReflectionTexture2;
extern u32 gNewShadowDiskTexture;
extern u32 gNewShadowSmallDiskTexture;
extern u32 gNewShadowBumpTexture;
extern u32 lbl_803DCFCC;
extern Texture* lbl_803DCFC8;
extern u32 gNewShadowSnowFlashTexture;
extern Texture* gNewShadowRadialTexture;
extern Texture* gNewShadowHeavyFogTexture;
extern Texture* gNewShadowLightningTexture;
extern Texture* gNewShadowRingTexture;
extern u32 gNewShadowRampTexture;
extern u32 gNewShadowInverseRampTexture;
extern u32 gNewShadowReflectionGradientTexture;
extern u32 gNewShadowFalloffTexture;
extern Texture* gNewShadowReflectionTexture;
extern const f32 lbl_803DED28;
extern const f32 lbl_803DED38;
extern const f32 lbl_803DED40;
extern const f32 lbl_803DED2C;
extern const f32 lbl_803DEDC0;
extern const f32 lbl_803DEDD0;
extern const f32 lbl_803DEE00;
extern const f32 lbl_803DEDE0;
extern const f32 lbl_803DED10;
extern const f32 lbl_803DED1C;
extern const f32 lbl_803DEDEC;
extern const f32 lbl_803DEDF0;
extern const f32 lbl_803DEDF4;
extern const f32 lbl_803DEDF8;
extern const f32 lbl_803DEDFC;
extern const f32 lbl_803DEE04;
extern const f32 lbl_803DEE14;
extern const f32 lbl_803DEE18;
extern const f32 lbl_803DEE1C;

extern inline float sqrtf(float x)
{
    volatile float y;
    if (x > lbl_803DED28)
    {
        double guess = __frsqrte((double)x);
        guess = lbl_803DED58 * guess * (lbl_803DED60 - guess * guess * x);
        guess = lbl_803DED58 * guess * (lbl_803DED60 - guess * guess * x);
        guess = lbl_803DED58 * guess * (lbl_803DED60 - guess * guess * x);
        y = (float)(x * guess);
        return y;
    }
    return x;
}

static inline void fillDiskTexture(void)
{
    int j;
    int i;
    f32 cy;
    u8* base;
    for (i = 0; i < 0x20; i++)
    {
        int lowoff;
        j = 0;
        lowoff = (i >> 3) * 0x20;
        cy = i - lbl_803DEDEC;
        lowoff += i & 7;
        for (; j < 0x20; j++)
        {
            int off;
            f32 dx, dz, d2;
            base = (u8*)gNewShadowDiskTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x80 + 0x60;
            dx = cy * lbl_803DEDD0;
            dz = (f32)j - lbl_803DEDEC;
            dz = dz * lbl_803DEDD0;
            dx = dx * lbl_803DEDF0;
            dz = dz * lbl_803DEDF0;
            d2 = dx * dx + dz * dz;
            base[off] = 255.0f * ((d2 > lbl_803DED2C) ? lbl_803DED28 : (lbl_803DED2C - d2));
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
        int lowoff;
        j = 0;
        lowoff = (i >> 3) * 0x20 + (i & 7);
        cy = i - lbl_803DED10;
        for (; j < 0x10; j++)
        {
            int off;
            f32 dx, dz, d2;
            base = (u8*)gNewShadowSmallDiskTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x40 + 0x60;
            dx = cy * lbl_803DED40;
            dz = (f32)j - lbl_803DED10;
            dz = dz * lbl_803DED40;
            dx = dx * lbl_803DEDF4;
            dz = dz * lbl_803DEDF4;
            d2 = dx * dx + dz * dz;
            if (d2 > lbl_803DED2C)
            {
                d2 = lbl_803DED28;
            }
            else
            {
                d2 = sqrtf(lbl_803DED2C - d2);
            }
            base[off] = 255.0f * d2;
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
        int lowoff;
        j = 0;
        lowoff = (i >> 3) * 0x20 + (i & 7);
        cy = i - lbl_803DED1C;
        cy = cy * lbl_803DEDE0;
        for (; j < 0x80; j++)
        {
            int off;
            f32 cx, d2;
            base = (u8*)gNewShadowFalloffTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x200 + 0x60;
            cx = ((f32)j - lbl_803DED1C) * lbl_803DEDE0;
            d2 = sqrtf(cx * cx + cy * cy);
            base[off] =
                (d2 < lbl_803DED38)
                    ? 0xa0
                    : ((d2 > lbl_803DED2C)
                           ? 0
                           : (int)(160.0f * (lbl_803DED2C - (d2 - lbl_803DED38) / lbl_803DED38)));
        }
    }
}

static inline void fillTextureCFB4(void)
{
    int j;
    int i;
    u8* base;
    for (i = 0; i < 0x20; i++)
    {
        int lowoff;
        f32 c0;
        j = 0;
        lowoff = (i >> 3) * 0x20 + (i & 7);
        c0 = i - 16.0f;
        c0 = c0 * 0.0625f;
        c0 = __fabsf(c0);
        for (; j < 4; j++)
        {
            int off;
            f32 v;
            base = (u8*)gNewShadowLightningTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x80 + 0x60;
            v = sqrtf(c0);
            v = sqrtf(v);
            base[off] = 255.0f * (1.0f - v);
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
        int lowoff;
        f32 cy2;
        cy = ((f32)i - 64.0f) * lbl_803DEDE0;
        j = 0;
        lowoff = (i >> 3) * 0x20 + (i & 7);
        cy2 = cy * cy;
        for (; j < 0x80; j++)
        {
            int off;
            f32 cx, d2;
            base = (u8*)gNewShadowRingTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x200 + 0x60;
            cx = ((f32)j - 64.0f) * lbl_803DEDE0;
            d2 = sqrtf(cx * cx + cy2);
            if (d2 < 0.25f || d2 > 0.75f)
            {
                d2 = 0.0f;
            }
            else
            {
                f32 t = 2.0f * (d2 - 0.25f);
                if (t > 0.5f)
                {
                    d2 = -(2.0f * (t - 0.5f) - 1.0f);
                }
                else
                {
                    d2 = -(2.0f * (0.5f - t) - 1.0f);
                }
                d2 = sqrtf(d2);
            }
            base[off] = 16.0f * d2;
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
    f32 rc2;
    int i;
    int j;
    Texture* frameTexture;
    f32 rc;
    NewShadowData* shadowData = (NewShadowData*)gNewShadowEntries;
    Texture** renderTargets = shadowData->castTextures;
    Texture** frameTextures = shadowData->frameTextures;
    f32 cy;

    u8 saved = testAndSet_onlyUseHeap3(1);

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
    DCFlushRange((void*)(gNewShadowDiskTexture + 0x60), ((Texture*)gNewShadowDiskTexture)->dataSize);

    gNewShadowSmallDiskTexture = (int)textureAlloc(0x10, 0x10, 1, 0, 0, 0, 0, 1, 1);
    fillSmallDiskTexture();
    DCFlushRange((void*)(gNewShadowSmallDiskTexture + 0x60), ((Texture*)gNewShadowSmallDiskTexture)->dataSize);

    gNewShadowBumpTexture = (int)textureAlloc(0x40, 0x40, 5, 0, 0, 0, 0, 1, 1);
    {
        f32 mx = lbl_803DED28;
        for (i = 0; i < 0x40; i++)
        {
            f32 fi, fi2;
            j = 0;
            fi = i - lbl_803DEDF8;
            fi2 = (f32)(i + 1) - lbl_803DEDF8;
            for (; j < 0x40; j++)
            {
                f32 cc = (f32)j - lbl_803DEDF8;
                f32 d1, d2, cc2, d3, n1, a, b;
                f64 n2, n3;
                rc = fi * lbl_803DEDFC;
                rc2 = fi2 * lbl_803DEDFC;
                cc = cc * lbl_803DEDFC;
                cc = cc * cc;
                d1 = sqrtf(rc * rc + cc);
                d2 = sqrtf(rc2 * rc2 + cc);
                cc2 = (f32)(j + 1) - lbl_803DEDF8;
                cc2 = cc2 * lbl_803DEDFC;
                cc2 = cc2 * cc2;
                rc = fi * lbl_803DEDFC;
                d3 = sqrtf(rc * rc + cc2);
                n1 = -mathCosfHighPrecision(lbl_803DEE00 * d1);
                n2 = __fabs(mathCosfHighPrecision(lbl_803DEE00 * d2));
                n3 = __fabs(mathCosfHighPrecision(lbl_803DEE00 * d3));
                a = n1 - (f32)n2;
                b = n1 - (f32)n3;
                if (a > mx)
                    mx = a;
                if (b > mx)
                    mx = b;
            }
        }
        {
            f32 inv = lbl_803DED2C / mx;
            for (j = 0; j < 0x40; j++)
            {
                int rowoff, lowoff;
                f32 fj, fj2;
                i = 0;
                rowoff = (j >> 2) * 0x20;
                lowoff = (j & 3) * 2;
                fj = j - lbl_803DEDF8;
                fj2 = (f32)(j + 1) - lbl_803DEDF8;
                for (; i < 0x40; i++)
                {
                    int dst = gNewShadowBumpTexture + lowoff;
                    f32 cc, d1, d2, cc2, d3, n1, n2, n3, a, b;
                    f32 c;
                    int bi, ci, ai;
                    rc = fj * lbl_803DEDFC;
                    rc2 = fj2 * lbl_803DEDFC;
                    dst += rowoff;
                    dst += (i & 3) * 8;
                    dst += (i >> 2) * 0x200;
                    cc = (f32)i - lbl_803DEDF8;
                    cc = cc * lbl_803DEDFC;
                    cc = cc * cc;
                    d1 = sqrtf(rc * rc + cc);
                    d2 = sqrtf(rc2 * rc2 + cc);
                    cc2 = (f32)(i + 1) - lbl_803DEDF8;
                    cc2 = cc2 * lbl_803DEDFC;
                    cc2 = cc2 * cc2;
                    rc = fj * lbl_803DEDFC;
                    d3 = sqrtf(rc * rc + cc2);
                    n1 = -mathCosfHighPrecision(lbl_803DEE00 * d1);
                    n2 = -mathCosfHighPrecision(lbl_803DEE00 * d2);
                    n3 = -mathCosfHighPrecision(lbl_803DEE00 * d3);
                    a = inv * (lbl_803DEDC0 * (n1 - n2)) + lbl_803DEDC0;
                    b = inv * (lbl_803DEDC0 * (n1 - n3)) + lbl_803DEDC0;
                    if (d1 < lbl_803DED2C)
                    {
                        d1 = sqrtf(lbl_803DED2C - d1);
                    }
                    else
                    {
                        d1 = lbl_803DED28;
                    }
                    c = lbl_803DEDF8 * d1;
                    if (c > lbl_803DEE04)
                        c = lbl_803DEE04;
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
    DCFlushRange((void*)(gNewShadowBumpTexture + 0x60), ((Texture*)gNewShadowBumpTexture)->dataSize);

    lbl_803DCFCC = (u32)textureLoadAsset(0x5b0);
    lbl_803DCFC8 = textureLoadAsset(0x600);
    gNewShadowSnowFlashTexture = (u32)textureLoadAsset(0xc18);

    gNewShadowRampTexture = (int)textureAlloc(0x100, 4, 1, 0, 0, 0, 0, 0, 0);
    fillRampTexture();
    DCFlushRange((void*)(gNewShadowRampTexture + 0x60), ((Texture*)gNewShadowRampTexture)->dataSize);

    gNewShadowInverseRampTexture = (int)textureAlloc(0x100, 4, 1, 0, 0, 0, 0, 1, 1);
    fillInverseRampTexture();
    DCFlushRange((void*)(gNewShadowInverseRampTexture + 0x60), ((Texture*)gNewShadowInverseRampTexture)->dataSize);

    gNewShadowFalloffTexture = (int)textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    fillFalloffTexture();
    DCFlushRange((void*)(gNewShadowFalloffTexture + 0x60), ((Texture*)gNewShadowFalloffTexture)->dataSize);

    gNewShadowRadialTexture = textureAlloc(0x80, 0x80, 1, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 0x80; i++)
    {
        int lowoff;
        j = 0;
        lowoff = (i >> 3) * 0x20;
        cy = i - lbl_803DED1C;
        lowoff += i & 7;
        cy = cy * lbl_803DEDE0;
        cy = __fabsf(cy);
        for (; j < 0x80; j++)
        {
            u8* base = (u8*)gNewShadowRadialTexture;
            int off = lowoff + (j & 3) * 8 + (j >> 2) * 0x200 + 0x60;
            f32 cx = __fabsf(((f32)j - lbl_803DED1C) * lbl_803DEDE0);
            f32 d2;
            f32 v;
            cx = cx * cx;
            d2 = sqrtf(cy * cy + cx);
            v = lbl_803DED2C - d2;
            if (v < lbl_803DED28)
                v = lbl_803DED28;
            base[off] = 255.0f * v;
        }
    }
    DCFlushRange((u8*)gNewShadowRadialTexture + 0x60, gNewShadowRadialTexture->dataSize);

    gNewShadowHeavyFogTexture = textureAlloc(0x40, 0x40, 1, 0, 0, 0, 0, 1, 1);
    DCInvalidateRange((u8*)gNewShadowHeavyFogTexture + 0x60, gNewShadowHeavyFogTexture->dataSize);
    updateHeavyFogTexture(0);

    gNewShadowLightningTexture = textureAlloc(0x20, 4, 1, 0, 0, 0, 0, 1, 1);
    fillTextureCFB4();
    DCFlushRange((u8*)gNewShadowLightningTexture + 0x60, gNewShadowLightningTexture->dataSize);

    gNewShadowRingTexture = textureAlloc(0x80, 0x80, 1, 0, 0, 1, 1, 1, 1);
    fillRingTexture();
    DCFlushRange((u8*)gNewShadowRingTexture + 0x60, gNewShadowRingTexture->dataSize);

    gNewShadowReflectionGradientTexture = (int)textureAlloc(4, 4, 3, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 4; i++)
    {
        f32 x = i / 3.0f - lbl_803DED38;
        int lowoff = (i & 3) * 2;
        int t;
        t = gNewShadowReflectionGradientTexture + lowoff;
        t += (i >> 2) * 0x20;
        *(u16*)(t + 0x60) = (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)lbl_803DED38 & 0xff));
        t = gNewShadowReflectionGradientTexture + lowoff;
        t += (i >> 2) * 0x20;
        *(u16*)(t + 0x68) = (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)lbl_803DEE14 & 0xff));
        t = gNewShadowReflectionGradientTexture + lowoff;
        t += (i >> 2) * 0x20;
        *(u16*)(t + 0x70) = (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)lbl_803DEE18 & 0xff));
        t = gNewShadowReflectionGradientTexture + lowoff;
        t += (i >> 2) * 0x20;
        *(u16*)(t + 0x78) = (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)lbl_803DEE1C & 0xff));
    }
    DCFlushRange((void*)(gNewShadowReflectionGradientTexture + 0x60),
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
    testAndSet_onlyUseHeap3(saved);
}


int audioPickSoundEffect_8006ed24(u8 a, u8 b)
{
    u8* base = lbl_8030E8B0;
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


void objAudioFn_8006edcc(GameObject* obj, int eventMask, u8 type, void* points, void* state, f32 unused, f32 scale)
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
    objAudioFn_8006ef38(obj, &events, type, points, state, unused, scale);
}

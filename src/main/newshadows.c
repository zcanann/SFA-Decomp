#include "main/game_object.h"
#include "track/intersect_depth_state_api.h"
#include "track/intersect_hud_api.h"
#define INTERSECT_SCREEN_DIRECT_SIGNED_WIDTH_CALL
#include "track/intersect_screen_api.h"
#undef INTERSECT_SCREEN_DIRECT_SIGNED_WIDTH_CALL
#include "main/hud_visibility_api.h"
#include "main/object_api.h"
#include "main/model.h"
#include "main/objprint_render_api.h"
#include "main/newshadows_audio_api.h"
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
#include "main/objprint_ext.h"
#include "main/pi_dolphin_fileload_api.h"
#include "main/dll/modgfx.h"
#include "dolphin/gx/GXFrameBuffer.h"
#include "string.h"

CameraViewSlot* gNewShadowCurrentViewSlot;
u32 gNewShadowReflectionSmallTexture;
Texture* gNewShadowCausticTexture;
u32 gNewShadowReflectionTexture2;
u32 gNewShadowDiskTexture;
u32 gNewShadowSmallDiskTexture;
u32 gNewShadowBumpTexture;
u32 lbl_803DCFCC;
Texture* lbl_803DCFC8;
u32 lbl_803DCFC4;
Texture* gNewShadowRadialTexture;
Texture* lbl_803DCFBC;
Texture* lbl_803DCFB8;
Texture* lbl_803DCFB4;
Texture* gNewShadowRingTexture;
f32 gNewShadowReflectionScrollX;
f32 gNewShadowReflectionScrollY;
f32 lbl_803DCFA4;
u16 lbl_803DCFA0;
u32 gNewShadowRampTexture;
u32 gNewShadowInverseRampTexture;
u32 lbl_803DCF94;
u32 gNewShadowFalloffTexture;
u8 gNewShadowFrameIndex;
int gNewShadowLightAngleY;
int gNewShadowLightAngleX;
u8 lbl_803DCF80;
char* gNewShadowReflectionTexture;
u8 gNewShadowCasterCount;

u8 lbl_803DB668[8] = {0xFF, 7, 6, 5, 4, 3, 2, 1};
f32 lbl_803DB670 = 1.3333334f;

typedef struct NewShadowEntry
{
    u8 pad00[0x10];
    u8 isActive;
    u8 pad11[0x3];
} NewShadowEntry;

typedef struct
{
    int id;
    f32 dist;
    int flags;
} ShadowSortEntry;

typedef struct
{
    GameObject* obj;
    f32 scale;
    u8 flags;
} NewShadowCaster;

typedef struct
{
    u16 packedXY;
} NewShadowVectorTexel;

#define NEW_SHADOW_MAX_QUEUED_CASTERS 300
#define NEW_SHADOW_MAX_CASTERS 100
#define NEW_SHADOW_MAX_CAST_TEXTURES 8
#define NEW_SHADOW_FRAME_COUNT 3

typedef struct
{
    f32 modelMtx[12];
    f32 texMtx[12];
    Texture* texture;
    u8 lod;
    u8 dirIndex;
    u8 pad66[2];
} NewShadowCastSlot;

typedef struct
{
    NewShadowEntry entries[0x21];
    Texture* frameTextures[NEW_SHADOW_FRAME_COUNT];
    u8 pad2A0[0x360 - 0x2A0];
    NewShadowCaster casters[NEW_SHADOW_MAX_QUEUED_CASTERS];
    NewShadowCastSlot castSlots[NEW_SHADOW_MAX_CASTERS];
    Texture* castTextures[NEW_SHADOW_MAX_CAST_TEXTURES];
} NewShadowData;

/* Linear search by pointer identity through the shadow entry table.
 * Clears the active flag when the entry matches the needle. */
#define NEW_SHADOW_ENTRY_CAPACITY 0x25

extern u32 gNewShadowFrameTextures[NEW_SHADOW_FRAME_COUNT];
extern Texture* gNewShadowNoiseTexFrames[0x10];
extern const f64 lbl_803DED58;
extern const f64 lbl_803DED60;
extern u32 gNewShadowSmallDiskTexture;
extern char* gNewShadowReflectionTexture;
extern u32 lbl_803DCF94;
extern u32 gNewShadowInverseRampTexture;
extern u32 gNewShadowFalloffTexture;
extern u32 lbl_803DCFC4;
extern Texture* lbl_803DCFC8;
extern Texture* gNewShadowRingTexture;
extern Texture* lbl_803DCFB4;
extern Texture* lbl_803DCFB8;
extern Texture* lbl_803DCFBC;
extern Texture* gNewShadowRadialTexture;
extern u32 gNewShadowRampTexture;
extern u32 gNewShadowDiskTexture;
extern u32 gNewShadowReflectionTexture2;
extern Texture* gNewShadowCausticTexture;
extern f32 gNewShadowReflectionScrollY;
extern f32 lbl_803DCFA4;
extern u32 gNewShadowBumpTexture;
extern u32 lbl_803DCFCC;
extern u32 gNewShadowReflectionSmallTexture;
extern u8 gNewShadowFrameIndex;
extern const f32 lbl_803DED28;
u8 lbl_8030E8B0[0xD8] = {
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
extern u8 gNewShadowCasterCount;
extern CameraViewSlot* gNewShadowCurrentViewSlot;
extern f32 gNewShadowReflectionScrollY, gNewShadowReflectionScrollX;
extern u8 lbl_803DCF80;
extern u16 lbl_803DCFA0;
extern int gNewShadowLightAngleX, gNewShadowLightAngleY;
extern const double lbl_803DED58;

extern const double lbl_803DED60;

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

extern const f32 lbl_803DED80;
extern const f32 lbl_803DED90;
extern const double lbl_803DED58;
extern const double lbl_803DED60;
extern const f32 lbl_803DED38;
extern const f32 lbl_803DED3C, lbl_803DED40;
extern const f32 lbl_803DED2C;
extern const f32 lbl_803DEDC0;
extern const f32 lbl_803DEDD0;
extern const f32 lbl_803DEDD4;
extern const f32 lbl_803DEE00;
extern const f32 lbl_803DEDE0;
extern const f32 lbl_803DEDE4, lbl_803DEDE8;
extern const f32 lbl_803DEDD8, lbl_803DEDDC;
extern const f32 lbl_803DED10;
extern const f32 lbl_803DED1C;
extern const f32 lbl_803DEDEC, lbl_803DEDF0, lbl_803DEDF4, lbl_803DEDF8, lbl_803DEDFC;
extern const f32 lbl_803DEE04;
extern const f32 lbl_803DEE14, lbl_803DEE18, lbl_803DEE1C;
extern const f32 lbl_803DED0C;
extern const f32 lbl_803DED14, lbl_803DED18;
extern const f32 lbl_803DED20, lbl_803DED24;
extern const f32 lbl_803DED34, lbl_803DED48;
extern const f32 lbl_803DEDAC, lbl_803DEDB0, lbl_803DEDB4, lbl_803DEDB8, lbl_803DEDBC;
extern const f32 gNewShadowFovY;
extern const f32 lbl_803DED70, lbl_803DED74, gNewShadowAspectWide, gNewShadowAspectNarrow;
extern const f32 lbl_803DED44, lbl_803DED4C, lbl_803DED50;
extern const f32 lbl_803DED68;
extern const f32 lbl_803DED6C;
extern f32 gMapSavedPlayerOffsetX, gMapSavedPlayerOffsetZ;

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

void fn_8006A028(u8* texData, int size, int window, u32 fill)
{
    ShadowBlurOutput blurred;
    ShadowBlurRow row;
    u8* data;
    u32 i;

    data = texData + 0x60;
    if (window % 8 == 0)
    {
        int nfill = window >> 3;
        u32 y;

        for (y = 0; y < size; y++)
        {
            u32* tile = (u32*)(data + ((y & 3) * 8 + (y >> 2) * 4 * size));
            u32* dst = row.words;
            u32* src;
            u32* wp;
            u32 x;

            for (i = 0; i < nfill; i++)
            {
                dst[0] = fill;
                dst++;
            }
            src = tile;
            for (x = 0; x < size; x += 8)
            {
                dst[0] = src[0];
                dst[1] = src[1];
                dst += 2;
                src += 8;
            }
            for (i = 0; i < nfill; i++)
            {
                dst[0] = fill;
                dst++;
            }
            boxBlurRow(row.bytes, blurred.bytes, size, window);
            src = blurred.words;
            wp = tile;
            for (x = 0; x < size; x += 8)
            {
                wp[0] = src[0];
                wp[1] = src[1];
                src += 2;
                wp += 8;
            }
        }
        {
            u32 x;

            for (x = 0; x < size; x++)
            {
                u8* col = data + ((x & 7) + (x >> 3) * 32);
                u32* dst = row.words;
                u8* gp;
                u8* bp;
                u32 yy;

                for (i = 0; i < nfill; i++)
                {
                    dst[0] = fill;
                    dst++;
                }
                gp = col;
                bp = row.bytes + (window >> 1);
                for (yy = 0; yy < size; yy += 4)
                {
                    bp[0] = gp[0];
                    bp[1] = gp[8];
                    bp[2] = gp[16];
                    bp[3] = gp[24];
                    bp += 4;
                    gp += (size >> 3) * 32;
                }
                dst = (u32*)(row.bytes + (size + (window >> 1)));
                for (i = 0; i < nfill; i++)
                {
                    dst[0] = fill;
                    dst++;
                }
                boxBlurRow(row.bytes, blurred.bytes, size, window);
                bp = blurred.bytes;
                for (yy = 0; yy < size; yy += 4)
                {
                    col[0] = bp[0];
                    col[8] = bp[1];
                    col[16] = bp[2];
                    col[24] = bp[3];
                    bp += 4;
                    col += (size >> 3) * 32;
                }
            }
        }
    }
    else
    {
        int nfill = window >> 2;
        u16 fillhw = fill;
        u32 y;

        for (y = 0; y < size; y++)
        {
            u16* tile = (u16*)(data + ((y & 3) * 8 + (y >> 2) * 4 * size));
            u16* dst = row.halfwords;
            u16* src;
            u32 x;

            for (i = 0; i < nfill; i++)
            {
                dst[0] = fillhw;
                dst++;
            }
            src = tile;
            for (x = 0; x < size; x += 8)
            {
                dst[0] = src[0];
                dst[1] = src[1];
                dst[2] = src[2];
                dst[3] = src[3];
                dst += 4;
                src += 16;
            }
            for (i = 0; i < nfill; i++)
            {
                dst[0] = fillhw;
                dst++;
            }
            boxBlurRow(row.bytes, blurred.bytes, size, window);
            src = blurred.halfwords;
            for (x = 0; x < size; x += 8)
            {
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

            for (x = 0; x < size; x++)
            {
                u8* col = data + ((x & 7) + (x >> 3) * 32);
                u16* dst = row.halfwords;
                u8* gp;
                u8* bp;
                u32 yy;

                for (i = 0; i < nfill; i++)
                {
                    dst[0] = fillhw;
                    dst++;
                }
                gp = col;
                bp = row.bytes + (window >> 1);
                for (yy = 0; yy < size; yy += 4)
                {
                    bp[0] = gp[0];
                    bp[1] = gp[8];
                    bp[2] = gp[16];
                    bp[3] = gp[24];
                    bp += 4;
                    gp += (size >> 3) * 32;
                }
                dst = (u16*)(row.bytes + (size + (window >> 1)));
                for (i = 0; i < nfill; i++)
                {
                    dst[0] = fillhw;
                    dst++;
                }
                boxBlurRow(row.bytes, blurred.bytes, size, window);
                bp = blurred.bytes;
                for (yy = 0; yy < size; yy += 4)
                {
                    col[0] = bp[0];
                    col[8] = bp[1];
                    col[16] = bp[2];
                    col[24] = bp[3];
                    bp += 4;
                    col += (size >> 3) * 32;
                }
            }
        }
    }
    DCFlushRange(data, size * size);
}


extern u32 gNewShadowFrameTextures[NEW_SHADOW_FRAME_COUNT];

void shadowRenderFn_8006b558(int* obj)
{
    f32 mtx[12];
    f32 vA, vB, vC, vD, vE, vF;
    f32 sc, objScale, saved, nx, ny, m;
    Obj_BuildWorldTransformMatrix((GameObject*)obj, mtx, 0);
    Camera_ProjectWorldSphere(((GameObject*)obj)->anim.localPosX - playerMapOffsetX, ((GameObject*)obj)->anim.localPosY,
                              ((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ,
                              lbl_803DED0C *
                                  (((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale),
                              &vA, &vB, &vC, &vD, &vE, &vF);
    vD = lbl_803DED14 * vD + lbl_803DED10;
    vE = lbl_803DED18 * vE + lbl_803DED10;
    if (vD > vE)
        m = vD;
    else
        m = vE;
    sc = lbl_803DED1C / m;
    objScale = ((GameObject*)obj)->anim.rootMotionScale * sc;
    nx = -vA;
    ny = vB;
    GXSetViewport(*(f32*)&lbl_803DED14 * nx, *(f32*)&lbl_803DED18 * ny, lbl_803DED20, lbl_803DED24,
                  lbl_803DED28, lbl_803DED2C);
    if (vC < *(f32*)&lbl_803DED28)
    {
        int* model;
        saved = ((GameObject*)obj)->anim.rootMotionScale;
        ((GameObject*)obj)->anim.rootMotionScale = objScale;
        set_shadowFlag_803dcc29(1);
        objRender(0, 0, 0, 0, (GameObject*)obj, 1);
        set_shadowFlag_803dcc29(0);
        ((GameObject*)obj)->anim.rootMotionScale = saved;
        model = (int*)Obj_GetActiveModel((GameObject*)obj);
        ((ObjModel*)model)->bufferFlags &= ~0x8;
        gxSetZMode_(1, GX_LEQUAL, 1);
        GXSetTexCopySrc(0x100, 0xb0, 0x80, 0x80);
        GXSetTexCopyDst(0x80, 0x80, GX_CTF_B8, GX_FALSE);
        GXCopyTex((void*)(gNewShadowFrameTextures[gNewShadowFrameIndex] + 0x60), GX_TRUE);
        fn_8006A028((u8*)gNewShadowFrameTextures[(gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT], 0x80, 0x10, 0);
        *(f32*)obj[0x64 / 4] = lbl_803DED2C / sc;
    }
    else
    {
        *(f32*)obj[0x64 / 4] = lbl_803DED28;
    }
    Camera_ApplyFullViewport();
    ((f32*)obj[0x64 / 4])[5] = lbl_803DED14 * (-nx);
    ((f32*)obj[0x64 / 4])[6] = lbl_803DED18 * (-ny);
    ((f32*)obj[0x64 / 4])[5] = ((f32*)obj[0x64 / 4])[5] + lbl_803DED14;
    ((f32*)obj[0x64 / 4])[6] = ((f32*)obj[0x64 / 4])[6] + lbl_803DED18;
    ((f32*)obj[0x64 / 4])[5] = ((f32*)obj[0x64 / 4])[5] - lbl_803DED1C * ((f32*)obj[0x64 / 4])[0];
    ((f32*)obj[0x64 / 4])[6] = ((f32*)obj[0x64 / 4])[6] - lbl_803DED1C * ((f32*)obj[0x64 / 4])[0];
}

void sortShadowEntriesDescending(ShadowSortEntry* arr, int count)
{
    int gap = 1;
    int i, j;
    ShadowSortEntry tmp;
    int limit = (count - 1) / 9;
    while (gap <= limit)
        gap = gap * 3 + 1;
    while (gap > 0)
    {
        for (i = gap + 1; i <= count; i++)
        {
            tmp = arr[i - 1];
            j = i;
            while (j > gap && arr[j - gap - 1].dist < tmp.dist)
            {
                arr[j - 1] = arr[j - gap - 1];
                j -= gap;
            }
            arr[j - 1] = tmp;
        }
        gap /= 3;
    }
}
extern NewShadowEntry gNewShadowEntries[0x294 / sizeof(NewShadowEntry)];

static inline void fillDiskTexture(void)
{
    int j;
    int i;
    f32 cy;
    u8* base;
    for (i = 0; i < 0x20; i++)
    {
        int rowoff, lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - lbl_803DEDEC;
        lowoff += rowoff;
        for (; j < 0x20; j++)
        {
            int off;
            f32 dx, dz, d2;
            base = (u8*)gNewShadowDiskTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x80;
            off += 0x60;
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
        int rowoff, lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - lbl_803DED10;
        lowoff += rowoff;
        for (; j < 0x10; j++)
        {
            int off;
            f32 dx, dz, d2;
            base = (u8*)gNewShadowSmallDiskTexture;
            off = lowoff + (j & 3) * 8;
            off += (j >> 2) * 0x40;
            off += 0x60;
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
        int rowoff, lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - lbl_803DED1C;
        lowoff += rowoff;
        cy = cy * lbl_803DEDE0;
        for (; j < 0x80; j++)
        {
            int off;
            f32 cx, d2;
            base = (u8*)gNewShadowFalloffTexture;
            off = lowoff + (j & 3) * 8 + (j >> 2) * 0x200 + 0x60;
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
        int rowoff, lowoff;
        f32 c0;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        c0 = i - 16.0f;
        lowoff += rowoff;
        c0 = c0 * 0.0625f;
        c0 = __fabsf(c0);
        for (; j < 4; j++)
        {
            int off;
            f32 v;
            base = (u8*)lbl_803DCFB4;
            off = lowoff + (j & 3) * 8 + (j >> 2) * 0x80 + 0x60;
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
        int rowoff, lowoff;
        f32 cy2;
        cy = ((f32)i - lbl_803DED1C) * lbl_803DEDE0;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy2 = cy * cy;
        lowoff += rowoff;
        for (; j < 0x80; j++)
        {
            int off;
            f32 cx, d2;
            base = (u8*)gNewShadowRingTexture;
            off = lowoff + (j & 3) * 8 + (j >> 2) * 0x200 + 0x60;
            cx = ((f32)j - lbl_803DED1C) * lbl_803DEDE0;
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

extern NewShadowEntry gNewShadowEntries[0x294 / sizeof(NewShadowEntry)];

void sortShadowEntriesDescending(ShadowSortEntry* arr, int count);

void renderShadows(int unused0, int unused1, int unused2)
{
    NewShadowCaster* casterPtr;
    f32 *mc54p, *vAp2, *vAp1;
    f32 dirY, dirZ, vAy, dirX, sCamX, sCamY;
    int savedRotY;
    s16 savedRotX, savedRotZ;
    f32 om100[24];
    f32 mTrans[12], mScale[12], mOrtho[16];
    f32 mc54[3], mc48[3];
    f32 vA[3], v30[3];
    f32 dot24[3], proj[3];
    CameraViewSlot* slot;
    NewShadowData* shadowData = (NewShadowData*)gNewShadowEntries;
    void* blkArr;
    u32 blkCount;
    s8 casterIdx;
    f32 sCamZ, savedFovY, vAx, vAz, orthoHalf;
    int texIdx, slotIdx;

    if (gNewShadowCasterCount == 0)
        return;
    Camera_DisableViewYOffset();
    sortShadowEntriesDescending((ShadowSortEntry*)shadowData->casters, gNewShadowCasterCount);
    Camera_SetCurrentViewIndex(1);
    slot = Camera_GetCurrentViewSlot();
    savedFovY = Camera_GetFovY();
    Camera_SetFovY(gNewShadowFovY);
    Camera_SetAspectRatio(lbl_803DED2C);
    sCamX = slot->x;
    sCamY = slot->y;
    sCamZ = slot->z;
    savedRotY = slot->pitch;
    savedRotX = slot->yaw;
    savedRotZ = slot->roll;
    slot->pitch = 0;
    v30[0] = lbl_803DED28;
    v30[1] = lbl_803DED2C;
    v30[2] = lbl_803DED28;
    fn_80061094(v30, om100, lbl_803DED34);
    mapGetBlocks(&blkArr, &blkCount);
    texIdx = 0;
    slotIdx = 0;
    casterIdx = 0;
    casterPtr = shadowData->casters;
    mc54p = &mc54[0];
    vAp2 = &vA[2];
    vAp1 = &vA[1];
    for (; casterIdx < gNewShadowCasterCount && casterIdx < NEW_SHADOW_MAX_CASTERS; casterPtr++, casterIdx++)
    {
        GameObject* obj = casterPtr->obj;
        ObjModelState* modelState = obj->anim.modelState;
        u8 lod;
        u8 kind;
        int screenW = 0, w = 0;
        NewShadowCastSlot* castSlot;
        Camera_SetCurrentViewIndex(0);
        lod = fn_800626C8(obj, framesThisStep);
        Camera_SetCurrentViewIndex(1);
        if (lod <= 4)
            continue;
        if ((modelState->flags & 0x20) != 0)
        {
            memcpy(mc48, &obj->anim.localPos, sizeof(Vec3f));
            memcpy(mc54p, &obj->anim.worldPos, sizeof(Vec3f));
            memcpy(&obj->anim.localPos, &modelState->overrideWorldPosX, sizeof(Vec3f));
            memcpy(&obj->anim.worldPos, &modelState->overrideWorldPosX, sizeof(Vec3f));
        }
        castSlot = &shadowData->castSlots[(u8)slotIdx];
        castSlot->lod = lod;
        if ((u8)texIdx < NEW_SHADOW_MAX_CAST_TEXTURES && (kind = casterPtr->flags) != 0)
        {
            if ((u8)texIdx < 3)
            {
                w = 0x100;
                orthoHalf = lbl_803DED38;
            }
            else if ((u8)texIdx < 5)
            {
                w = 0x80;
                orthoHalf = lbl_803DED3C;
            }
            else
            {
                w = 0x40;
                orthoHalf = lbl_803DED40;
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
            fn_8008923C(obj, vA, vAp1, vAp2);
            dot24[0] = -modelState->shadowOffsetX;
            dot24[1] = -modelState->shadowOffsetY;
            dot24[2] = -modelState->shadowOffsetZ;
            {
                f32 dot = PSVECDotProduct(dot24, vA);
                if (dot < lbl_803DED2C && dot > lbl_803DED44)
                {
                    f32 mag;
                    proj[0] = lbl_803DED48 * dot24[0] + lbl_803DED4C * vA[0];
                    proj[1] = lbl_803DED48 * dot24[1] + lbl_803DED4C * vA[1];
                    proj[2] = lbl_803DED48 * dot24[2] + lbl_803DED4C * vA[2];
                    mag = PSVECMag(proj);
                    if (mag > lbl_803DED28)
                    {
                        mag = lbl_803DED2C / mag;
                        PSVECScale(proj, vA, mag);
                    }
                }
            }
            if (vA[1] > lbl_803DED50)
            {
                vA[1] = lbl_803DED50;
                PSVECNormalize(vA, vA);
            }
            vAx = vA[0];
            dirX = -vAx;
            vAy = vA[1];
            dirY = -vAy;
            vAz = vA[2];
            dirZ = -vAz;
            gNewShadowLightAngleX = (u16)getAngle(dirX, vAz);
            {
                f32 sqA = vAx * vAx;
                f32 sqB = vAz * vAz;
                gNewShadowLightAngleY = (u16)getAngle(sqrtf(sqA + sqB), vAy) - 0x3fc8;
            }
            slot->pitch = gNewShadowLightAngleY;
            slot->yaw = gNewShadowLightAngleX;
            {
                f32 mag = sqrtf(dirX * dirX + dirY * dirY + dirZ * dirZ);
                if (mag > lbl_803DED28)
                {
                    f32 inv = lbl_803DED68 / mag;
                    dirX *= inv;
                    dirY *= inv;
                    dirZ *= inv;
                }
            }
            slot->parentObject = NULL;
            modelState->shadowOffsetX = -vA[0];
            modelState->shadowOffsetY = -vA[1];
            modelState->shadowOffsetZ = -vA[2];
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
            GXSetViewport(lbl_803DED28, lbl_803DED28, (f32)(u32)screenW, (f32)(u32)screenW, lbl_803DED28, lbl_803DED2C);
            C_MTXOrtho(mOrtho, vAx, vAz, vAx, vAz, lbl_803DED2C, lbl_803DED6C);
            GXSetProjection(mOrtho, GX_ORTHOGRAPHIC);
            Camera_UpdateViewMatrices();
            C_MTXLightOrtho(castSlot->modelMtx, vAz, vAx, vAx, vAz, orthoHalf, orthoHalf, orthoHalf, orthoHalf);
            {
                f32* vm = Camera_GetViewMatrix();
                PSMTXCopy(vm, castSlot->texMtx);
                PSMTXConcat(castSlot->modelMtx, vm, castSlot->modelMtx);
                obj->anim.modelState->shadowCastSlot = castSlot;
                {
                    Texture** texturePool = shadowData->castTextures;
                    Texture** texture = texturePool + (u8)texIdx;
                    castSlot->texture = *texture;
                    castSlot->dirIndex = lbl_803DB668[(u8)texIdx];
                    objRenderShadowIfVisible(obj, 0, 0, 0, 0, 0);
                    if (casterPtr->flags == 2)
                    {
                        gxSetZMode_(1, GX_LEQUAL, 1);
                        PSMTXScale(castSlot->texMtx, lbl_803DED28, lbl_803DED28, lbl_803DED28);
                        castSlot->texMtx[2] = lbl_803DED70;
                        castSlot->texMtx[3] = lbl_803DED74;
                        castSlot->texMtx[11] = lbl_803DED2C;
                        PSMTXConcat(castSlot->texMtx, vm, castSlot->texMtx);
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
                f32 s = lbl_803DED38 / modelState->shadowScale;
                mScale[0] = s;
                mScale[1] = lbl_803DED28;
                mScale[2] = lbl_803DED28;
                mScale[3] = lbl_803DED38;
                mScale[4] = lbl_803DED28;
                mScale[5] = lbl_803DED28;
                mScale[6] = s;
                mScale[7] = lbl_803DED38;
                mScale[8] = lbl_803DED28;
                mScale[9] = lbl_803DED28;
                mScale[10] = lbl_803DED28;
                mScale[11] = lbl_803DED2C;
            }
            PSMTXConcat(mScale, mTrans, castSlot->modelMtx);
            modelState->shadowOffsetX = v30[0];
            modelState->shadowOffsetY = v30[1];
            modelState->shadowOffsetZ = v30[2];
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
    if (getDrawDistanceFlag_8005cd48() != 0)
    {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        if (isWidescreen() != 0)
            Camera_SetAspectRatio(gNewShadowAspectWide);
        else
            Camera_SetAspectRatio(gNewShadowAspectNarrow);
        Camera_UpdateProjection(NULL, 0);
    }
    else if (isWidescreen() != 0)
    {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        Camera_SetAspectRatio(lbl_803DED80);
        Camera_UpdateProjection(NULL, 0);
    }
    else
    {
        Camera_SetCurrentViewIndex(0);
        Camera_SetFovY(savedFovY);
        Camera_SetAspectRatio(lbl_803DB670);
        Camera_UpdateProjection(NULL, 0);
    }
    Camera_UpdateViewMatrices();
    Camera_RebuildProjectionMatrix();
    Camera_ApplyFullViewport();
    Camera_EnableViewYOffset();
}

extern NewShadowCaster gNewShadowCasterTable[NEW_SHADOW_MAX_QUEUED_CASTERS];

void shadowCreate(int* obj)
{
    CameraViewSlot* cam;
    f32 dx, dy, dz, dist2;
    if (gNewShadowCasterCount < NEW_SHADOW_MAX_QUEUED_CASTERS)
    {
        gNewShadowCasterTable[gNewShadowCasterCount].obj = (GameObject*)obj;
        cam = gNewShadowCurrentViewSlot;
        dx = ((GameObject*)obj)->anim.worldPosX - cam->x;
        dy = ((GameObject*)obj)->anim.worldPosY - cam->y;
        dz = ((GameObject*)obj)->anim.worldPosZ - cam->z;
        dist2 = dx * dx + dy * dy + dz * dz;
        if (dist2 > lbl_803DED28)
        {
            double guess = __frsqrte((double)dist2);
            volatile f32 root;
            guess = lbl_803DED58 * guess * (lbl_803DED60 - guess * guess * dist2);
            guess = lbl_803DED58 * guess * (lbl_803DED60 - guess * guess * dist2);
            guess = lbl_803DED58 * guess * (lbl_803DED60 - guess * guess * dist2);
            root = (f32)(dist2 * guess);
            dist2 = root;
        }
        gNewShadowCasterTable[gNewShadowCasterCount].scale = ((GameObject*)obj)->anim.modelState->shadowScale / dist2;
        if (((ObjAnimComponent*)obj)->modelInstance->shadowType == OBJ_SHADOW_TYPE_MODEL_GEOMETRIC)
        {
            gNewShadowCasterTable[gNewShadowCasterCount].flags = 1;
            if (((ObjAnimComponent*)obj)->modelInstance->renderFlags & OBJDEF_RENDERFLAG_PROJECTED_SHADOW)
            {
                gNewShadowCasterTable[gNewShadowCasterCount].flags = 2;
                gNewShadowCasterTable[gNewShadowCasterCount].scale = lbl_803DED90;
            }
        }
        else
        {
            gNewShadowCasterTable[gNewShadowCasterCount].flags = 0;
        }
        gNewShadowCasterCount++;
    }
}
extern u8 lbl_8038E1E8[0x80];

void newshadows_getShadowTextureTable4x8(int* p1, int* p2, int* p3)
{
    *p1 = (int)lbl_8038E1E8;
    *p2 = 4;
    *p3 = 8;
}

extern Texture* gNewShadowNoiseTexFrames[0x10];

void textureFn_8006c4e0(int* p1, int* p2)
{
    *p1 = (int)gNewShadowNoiseTexFrames;
    *p2 = 0x10;
}

void fn_8006C4F8(u32* p)
{
    *p = lbl_803DCFC4;
}
void fn_8006C504(Texture** p)
{
    *p = lbl_803DCFC8;
}
void fn_8006C510(Texture** p)
{
    *p = gNewShadowRingTexture;
}
void fn_8006C51C(Texture** p)
{
    *p = lbl_803DCFB4;
}
void fn_8006C528(Texture** p)
{
    *p = lbl_803DCFB8;
}
void fn_8006C534(Texture** p)
{
    *p = lbl_803DCFBC;
}
void fn_8006C540(Texture** p)
{
    *p = gNewShadowRadialTexture;
}

void* textureAlloc512(void)
{
    Texture* tex = (Texture*)textureAlloc(0x200, 0x200, 1, 0, 0, 0, 0, 0, 0);
    tex->refCount = 1;
    DCFlushRange((char*)tex + 0x60, tex->dataSize);
    return tex;
}
void fn_8006C5B8(u32* p)
{
    *p = gNewShadowRampTexture;
}

u32 textureFn_8006c5c4(void)
{
    return gNewShadowSmallDiskTexture;
}
void fn_8006C5CC(u32* p)
{
    *p = gNewShadowDiskTexture;
}
void getReflectionTexture2(u32* p)
{
    *p = gNewShadowReflectionTexture2;
}
void getTextureFn_8006c5e4(u32* p)
{
    *p = (u32)gNewShadowCausticTexture;
}

u8 lbl_8038E1E8[0x80];

void objShadowFn_8006c5f0(GameObject* obj, u32* outTable, f32* outF, int* outX, int* outY)
{
    int idx = (gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT;
    *outTable = gNewShadowFrameTextures[idx];
    *outF = obj->anim.modelState->shadowScale;
    *outX = (int)obj->anim.modelState->shadowOffsetX;
    *outY = (int)obj->anim.modelState->shadowOffsetY;
}

Texture* gNewShadowNoiseTexFrames[0x10];

f32 fn_8006C670(void)
{
    return lbl_803DCFA4;
}

void fn_8006C678(int id)
{
    GXLoadTexObj(textureGetGXTexObj((Texture*)gNewShadowBumpTexture), id);
}

void fn_8006C6A4(int id)
{
    register int idCopy = id;
    Texture* p = (Texture*)lbl_803DCFCC;
    if (p->preloaded != 0)
    {
        GXLoadTexObjPreLoaded(textureGetGXTexObj(p), textureGetGXTexRegion(p), idCopy);
    }
    else
    {
        GXLoadTexObj(textureGetGXTexObj(p), idCopy);
    }
}

void selectReflectionTexture(int id)
{
    register int idCopy = id;
    Texture* p = (Texture*)gNewShadowReflectionTexture;
    if (p->preloaded != 0)
    {
        GXLoadTexObjPreLoaded(textureGetGXTexObj(p), textureGetGXTexRegion(p), idCopy);
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
u32 getTextureFn_8006c744(void)
{
    return lbl_803DCF94;
}

u32 gNewShadowFrameTextures[NEW_SHADOW_FRAME_COUNT];
u32 fn_8006C74C(void)
{
    return gNewShadowInverseRampTexture;
}
u32 fn_8006C754(void)
{
    return gNewShadowFalloffTexture;
}


void textureFn_8006c75c(int id)
{
    register int idCopy = id;
    Texture* p = (Texture*)gNewShadowReflectionSmallTexture;
    if (p->preloaded != 0)
    {
        GXLoadTexObjPreLoaded(textureGetGXTexObj(p), textureGetGXTexRegion(p), idCopy);
    }
    else
    {
        GXLoadTexObj(textureGetGXTexObj(p), idCopy);
    }
}
void drawReflectionTexture(void)
{
    char* texture = gNewShadowReflectionTexture;
    drawTexture(texture, 0.0f, 0.0f, 0xff, 0x40);
    GXSetTexCopySrc(0, 0, 0x50, 0x3c);
    GXSetTexCopyDst(0x50, 0x3c, GX_TF_RGB565, GX_FALSE);
    GXCopyTex((char*)gNewShadowReflectionSmallTexture + 0x60, GX_TRUE);
    if (((Texture*)gNewShadowReflectionSmallTexture)->preloaded != 0)
    {
        GXPreLoadEntireTexture(textureGetGXTexObj((Texture*)gNewShadowReflectionSmallTexture),
                               textureGetGXTexRegion((Texture*)gNewShadowReflectionSmallTexture));
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
    if (((Texture*)gNewShadowReflectionTexture)->preloaded != 0)
    {
        GXPreLoadEntireTexture(textureGetGXTexObj((Texture*)gNewShadowReflectionTexture),
                               textureGetGXTexRegion((Texture*)gNewShadowReflectionTexture));
    }
    if (((Texture*)gNewShadowReflectionTexture2)->preloaded != 0)
    {
        GXPreLoadEntireTexture(textureGetGXTexObj((Texture*)gNewShadowReflectionTexture2),
                               textureGetGXTexRegion((Texture*)gNewShadowReflectionTexture2));
    }
    if (((Texture*)gNewShadowReflectionTexture)->preloaded == 0 ||
        ((Texture*)gNewShadowReflectionTexture2)->preloaded == 0)
    {
        GXInvalidateTexAll();
    }
    GXPixModeSync();
}

void maybeHudFn_8006c91c(void)
{
    f32 hi, lo;
    if (getHudHiddenFrameCount() == 0)
    {
        f32 d = timeDelta;
        gNewShadowReflectionScrollX = 0.0084f * d + gNewShadowReflectionScrollX;
        gNewShadowReflectionScrollY = 0.003f * d + gNewShadowReflectionScrollY;
        if (gNewShadowReflectionScrollX > 256.0f)
            gNewShadowReflectionScrollX = gNewShadowReflectionScrollX - 256.0f;
        if (gNewShadowReflectionScrollY > 256.0f)
            gNewShadowReflectionScrollY = gNewShadowReflectionScrollY - 256.0f;
    }
    gNewShadowCasterCount = 0;
    gNewShadowCurrentViewSlot = Camera_GetCurrentViewSlot();
    lbl_803DCFA0 = (u16)(lbl_803DCFA0 + framesThisStep * 0x28a);
    lbl_803DCFA4 = 0.2f * mathSinfHighPrecision(6.284f * (f32)(u32)lbl_803DCFA0 / 65536.0f);
    fn_80060BB0();
    gNewShadowFrameIndex = (gNewShadowFrameIndex + 1) % NEW_SHADOW_FRAME_COUNT;
    if (isHeavyFogEnabled())
    {
        f32 z = Camera_GetInverseViewMatrix()[7];
        int v;
        fn_8004C234(&hi, &lo);
        if (z >= hi)
            v = 0;
        else if (z <= lo)
            v = 0x40;
        else
            v = (int)(lbl_803DED1C * (hi - z) / (hi - lo));
        if ((u8)v != lbl_803DCF80)
            fn_80069EB8((u8)v);
    }
}

NewShadowCaster gNewShadowCasterTable[NEW_SHADOW_MAX_QUEUED_CASTERS];
NewShadowCastSlot gNewShadowCastSlots[NEW_SHADOW_MAX_CASTERS];
u32 gNewShadowCastTextures[NEW_SHADOW_MAX_CAST_TEXTURES];



void newshadows_getReflectionScrollOffsets(f32* outScrollX, f32* outScrollY)
{
    *outScrollX = gNewShadowReflectionScrollX;
    *outScrollY = gNewShadowReflectionScrollY;
}

f32 gNewShadowPlacements[0x112];

/* Builds the animated water-noise assets: scatters up to 50 non-overlapping random
   placements ([0]=lifetime 8..16 frames, [1..2]=pos, [3]=outer size, [4]=inner size),
   renders 16 noise animation frames through fn_8006CD20, then the caustic texture. */

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


void fn_8006CB24(void)
{
    mm_free(lbl_803DCFBC);
    lbl_803DCFBC = 0;
}
void fn_8006CB50(void)
{
    int yhi;
    int ylo;
    int y, x;
    f32 fy;
    f32 fx;
    f32 dist;
    f32 ny;
    f32 s;
    f32 t;
    f32 py;
    f32 px;
    lbl_803DCFBC = textureAlloc(0x100, 0x100, 3, 0, 0, 0, 0, 1, 1);
    for (y = 0; y < 0x100; y++)
    {
        x = 0;
        yhi = (y >> 2) * 0x20;
        ylo = (y & 3) * 2;
        fy = y - lbl_803DEDAC;
        for (; x < 0x100; x++)
        {
            u8* rowBase;
            u8* row;
            u8* addr;
            rowBase = (u8*)lbl_803DCFBC + ylo;
            row = rowBase + yhi;
            row += (x & 3) * 8;
            addr = row + (x >> 2) * 0x800;
            fx = x - lbl_803DEDAC;
            dist = sqrtf(fx * fx + fy * fy);
            ny = fy / dist;
            fx /= dist;
            if (dist <= lbl_803DEDB8)
            {
                t = lbl_803DED34 * (lbl_803DEDB0 - lbl_803DED48 * dist);
                s = t * lbl_803DEDB4;
            }
            else
            {
                s = lbl_803DED28;
            }
            {
                ny = ny * s;
                fx = fx * s;
                py = lbl_803DEDC0 * ny + lbl_803DEDBC;
                px = lbl_803DEDC0 * fx + lbl_803DEDBC;
                ((NewShadowVectorTexel*)(addr + 0x60))->packedXY =
                    (u16)((int)px | (((int)py & 0xffff) << 8));
            }
        }
    }
    DCFlushRange(lbl_803DCFBC + 1, lbl_803DCFBC->dataSize);
}
/* Sample the animated noise field built from gNewShadowPlacements: sums the
   contribution of every active placement at texel (px,pz) for animation frame
   `frame`. out2 = sparkle intensity (0..1), out1 = accumulated shift term. */
void fn_8006CD20(f32 px, f32 pz, f32 frame, f32* placements, int count, f32* out1, f32* out2)
{
    f32* place;
    int i;
    f32 acc5;
    f32 acc6;

    acc5 = acc6 = lbl_803DED28;
    place = placements;
    for (i = 0; i < count; i++, place += 5)
    {
        f32 over = *(f32*)&lbl_803DED28;
        if (frame < place[0])
        {
            f32 mx, mz, t, s0, tmp, p2lo, d2, sq, ratio, frac, depth;
            t = lbl_803DED3C + (place[0] - frame) / place[0];
            if (t > lbl_803DED2C)
                t = lbl_803DED2C;
            s0 = sqrtf(t);

            mx = __fabsf(place[1] - px);
            tmp = __fabsf((lbl_803DED2C + place[1]) - px);
            if (tmp < mx)
                mx = tmp;
            tmp = __fabsf((place[1] - lbl_803DED2C) - px);
            if (tmp < mx)
                mx = tmp;

            mz = __fabsf(place[2] - pz);
            if (pz > place[2])
                over = pz - place[2];
            tmp = __fabsf((lbl_803DED2C + place[2]) - pz);
            if (tmp < mz)
            {
                mz = tmp;
                over = lbl_803DED28;
            }
            p2lo = place[2] - lbl_803DED2C;
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
                sqd = lbl_803DED2C - sqd;
                g = sqrtf(sqd);
                acc5 = s0 * g + acc5;
                over = over / depth;
                acc6 = acc6 + over;
                acc6 = lbl_803DED38 * (lbl_803DED2C - frame * lbl_803DEDD0) + acc6;
            }
        }
    }
    if (acc5 > lbl_803DED2C)
        acc5 = lbl_803DED2C;
    if (acc6 > *(f32*)&lbl_803DED2C)
        acc6 = *(f32*)&lbl_803DED2C;
    *out1 = lbl_803DED40 * acc6 + lbl_803DEDD4;
    *out2 = acc5;
}
void initFn_8006d020(void)
{
    u8 saved;
    int count;
    int col;
    f32* e;
    int placed;
    int attempts;
    int j;
    u8 collide;
    int row;
    int tex;

    saved = testAndSet_onlyUseHeap3(1);
    attempts = 0;
    placed = 0;
    e = gNewShadowPlacements;
    while (placed < 0x32 && attempts < 10000u)
    {
        f32 *px, *pz, *prad;
        e[0] = (f32)randomGetRange(8, 0x10);
        e[3] = lbl_803DEDD8 * (f32)randomGetRange(5, 10);
        e[4] = e[3] * (lbl_803DEDD8 * (f32)randomGetRange(0x14, 0x32));
        attempts = 0;
        px = &e[1];
        pz = &e[2];
        prad = &e[4];
        do
        {
            f32* o;
            *px = lbl_803DEDDC * (f32)randomGetRange(0, 999);
            *pz = lbl_803DEDDC * (f32)randomGetRange(0, 999);
            collide = 0;
            j = 0;
            o = gNewShadowPlacements;
            while (j < placed && !collide)
            {
                f32 mx, mz, tmp, d;
                mx = __fabsf(*px - o[1]);
                tmp = __fabsf((lbl_803DED2C + *px) - o[1]);
                if (tmp < mx)
                    mx = tmp;
                tmp = __fabsf((*px - lbl_803DED2C) - o[1]);
                if (tmp < mx)
                    mx = tmp;
                mz = __fabsf(*pz - o[2]);
                tmp = __fabsf((lbl_803DED2C + *pz) - o[2]);
                if (tmp < mz)
                    mz = tmp;
                tmp = __fabsf((*pz - lbl_803DED2C) - o[2]);
                if (tmp < mz)
                    mz = tmp;
                d = sqrtf(mx * mx + mz * mz);
                if (d < *prad + o[3])
                    collide = 1;
                o += 5;
                j++;
            }
            attempts++;
        } while (collide && attempts < 10000u);
        e += 5;
        placed++;
    }

    count = placed;
    tex = 0;
    for (; tex < 0x10; tex++)
    {
        gNewShadowNoiseTexFrames[tex] = textureAlloc(0x40, 0x40, 3, 0, 0, 1, 1, 1, 1);
        for (row = 0; row < 0x40; row++)
        {
            int rowoff, lowoff;
            col = 0;
            rowoff = (row >> 2) * 0x20;
            lowoff = (row & 3) * 2;
            for (; col < 0x40; col++)
            {
                f32 o1, o2;
                int hi, lo;
                int dst = (int)gNewShadowNoiseTexFrames[tex] + lowoff + rowoff;
                dst += (col & 3) * 8;
                dst += (col >> 2) * 0x200;
                fn_8006CD20(row * lbl_803DEDE0, col * lbl_803DEDE0, tex, gNewShadowPlacements, count, &o1, &o2);
                hi = (int)(255.0f * o2);
                lo = (int)(255.0f * o1);
                *(u16*)(dst + 0x60) = ((hi & 0xffff) << 8) | lo;
            }
        }
        DCFlushRange(gNewShadowNoiseTexFrames[tex] + 1, gNewShadowNoiseTexFrames[tex]->dataSize);
    }

    gNewShadowCausticTexture = textureAlloc(0x40, 0x40, 3, 0, 0, 1, 1, 1, 1);
    for (row = 0; row < 0x40; row++)
    {
        int rowoff, lowoff;
        f32 rv;
        col = 0;
        rowoff = (row >> 2) * 0x20;
        lowoff = (row & 3) * 2;
        rv = lbl_803DEDE4 * row;
        for (; col < 0x40; col++)
        {
            f32 cv, n1, n2, prod, fa;
            int hi, lo;
            u8* dst = (u8*)gNewShadowCausticTexture + lowoff;
            dst += rowoff;
            dst += (col & 3) * 8;
            dst += (col >> 2) * 0x200;
            cv = lbl_803DEDE8 * col;
            n1 = mathCosfHighPrecision(lbl_803DED38 * mathSinfHighPrecision(cv) + rv);
            n2 = mathCosfHighPrecision(cv);
            prod = n1 * n2;
            prod = lbl_803DEDC0 * prod + lbl_803DEDC0;
            fa = lbl_803DEDC0 * n1 + lbl_803DEDC0;
            lo = fa;
            hi = prod;
            *(u16*)(dst + 0x60) = lo | ((hi & 0xffff) << 8);
        }
    }
    DCFlushRange(gNewShadowCausticTexture + 1, gNewShadowCausticTexture->dataSize);

    gNewShadowReflectionScrollX = lbl_803DED28;
    gNewShadowReflectionScrollY = lbl_803DED28;
    testAndSet_onlyUseHeap3(saved);
}

void allocLotsOfTextures(void)
{
    f32 rc2;
    u8 saved;
    int i;
    int j;
    Texture* frameTexture;
    f32 rc;
    char* shadowData = (char*)(int)gNewShadowEntries;
    Texture** renderTargets = (Texture**)(shadowData + 0x3a10);
    Texture** frameTextures = (Texture**)(shadowData + 0x294);
    f32 cy;

    saved = testAndSet_onlyUseHeap3(1);

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
            rc = fi * lbl_803DEDFC;
            rc2 = fi2 * lbl_803DEDFC;
            for (; j < 0x40; j++)
            {
                f32 cc = (f32)j - lbl_803DEDF8;
                f32 d1, d2, cc2, d3, n1, a, b;
                f64 n2, n3;
                cc = cc * lbl_803DEDFC;
                cc = cc * cc;
                d1 = sqrtf(rc * rc + cc);
                d2 = sqrtf(rc2 * rc2 + cc);
                cc2 = (f32)(j + 1) - lbl_803DEDF8;
                cc2 = cc2 * lbl_803DEDFC;
                cc2 = cc2 * cc2;
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
                rc = fj * lbl_803DEDFC;
                rc2 = fj2 * lbl_803DEDFC;
                for (; i < 0x40; i++)
                {
                    int dst = gNewShadowBumpTexture + lowoff;
                    f32 cc, d1, d2, cc2, d3, n1, n2, n3, a, b;
                    f32 c;
                    int bi, ci, ai;
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
    lbl_803DCFC4 = (u32)textureLoadAsset(0xc18);

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
        int rowoff, lowoff;
        j = 0;
        rowoff = (i >> 3) * 0x20;
        lowoff = i & 7;
        cy = i - lbl_803DED1C;
        lowoff += rowoff;
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

    lbl_803DCFB8 = textureAlloc(0x40, 0x40, 1, 0, 0, 0, 0, 1, 1);
    DCInvalidateRange((u8*)lbl_803DCFB8 + 0x60, lbl_803DCFB8->dataSize);
    fn_80069EB8(0);

    lbl_803DCFB4 = textureAlloc(0x20, 4, 1, 0, 0, 0, 0, 1, 1);
    fillTextureCFB4();
    DCFlushRange((u8*)lbl_803DCFB4 + 0x60, lbl_803DCFB4->dataSize);

    gNewShadowRingTexture = textureAlloc(0x80, 0x80, 1, 0, 0, 1, 1, 1, 1);
    fillRingTexture();
    DCFlushRange((u8*)gNewShadowRingTexture + 0x60, gNewShadowRingTexture->dataSize);

    lbl_803DCF94 = (int)textureAlloc(4, 4, 3, 0, 0, 0, 0, 1, 1);
    for (i = 0; i < 4; i++)
    {
        f32 x = i / 3.0f - lbl_803DED38;
        int lowoff = (i & 3) * 2;
        int rowoff = (i >> 2) * 0x20;
        int t;
        t = lbl_803DCF94 + lowoff;
        t += rowoff;
        *(u16*)(t + 0x60) = (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)lbl_803DED38 & 0xff));
        t = lbl_803DCF94 + lowoff;
        t += rowoff;
        *(u16*)(t + 0x68) = (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)lbl_803DEE14 & 0xff));
        t = lbl_803DCF94 + lowoff;
        t += rowoff;
        *(u16*)(t + 0x70) = (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)lbl_803DEE18 & 0xff));
        t = lbl_803DCF94 + lowoff;
        t += rowoff;
        *(u16*)(t + 0x78) = (u16)((((int)(255.0f * x + 128.0f) & 0xff) << 8) | ((int)lbl_803DEE1C & 0xff));
    }
    DCFlushRange((void*)(lbl_803DCF94 + 0x60), ((Texture*)lbl_803DCF94)->dataSize);

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
        for (i = 0, entryBytes = (u8*)(int)gNewShadowEntries; i < 0x20; i += 0x10)
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
        entryBytes = (u8*)(int)gNewShadowEntries + i * 0x14;
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

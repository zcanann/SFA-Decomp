#include "main/newclouds_state.h"
#include "main/audio/sfx.h"
#include "main/cloud_action_runtime.h"
#include "main/cloud_layer_state.h"
#include "main/object_transform.h"
#include "main/objtexture.h"
#include "main/sky_interface.h"
#include "main/mm.h"
#include "main/camera.h"
#include "main/gameplay_runtime.h"
#include "main/texture.h"
#include "dolphin/gx/GXDispList.h"
#include "dolphin/gx/GXEnum.h"
#include "dolphin/os/OSCache.h"
#include "main/sky_state.h"
#include "sfa_light_decls.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/music_trigger_ids.h"

typedef struct LightningEffect
{
    f32 start[3];
    f32 end[3];
    f32 radiusX;
    f32 radiusY;
    u16 timer;
    u16 lifetime;
    u16 seed;
    u8 width;
    u8 flags;
} LightningEffect;

extern void* Obj_GetActiveModel(void* obj);
extern void PSMTXConcat(f32 a[3][4], f32 b[3][4], f32 out[3][4]);
extern void lightningRender(void* state);
extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803DF1A0;
extern const f32 lbl_803DF1D8;
extern const f32 lbl_803DF1DC;
extern u8 gNewCloudBlizzardActive;
extern u8* lbl_803DD19C;
extern u8 gNewCloudInitialized;
extern void PSVECNormalize(void* src, void* dst);

void lightningRenderActive(void)
{
    if (lbl_803DD19C != NULL)
    {
        lightningRender(lbl_803DD19C);
    }
}

#pragma dont_inline on
void snowCloudBuildBoxVerts(f32* out, f32 height, f32 scale)
{
    f32 side;
    f32 zero;
    f32 scaledHeight;
    f32 edge;

    side = lbl_803DF1D8 * scale;
    out[0] = side;
    zero = lbl_803DF1A0;
    out[1] = zero;
    out[2] = side;
    out[3] = side;
    scaledHeight = height * scale;
    out[4] = scaledHeight;
    out[5] = side;
    edge = lbl_803DF1DC * scale;
    out[6] = edge;
    out[7] = scaledHeight;
    out[8] = side;
    out[9] = edge;
    out[10] = zero;
    out[11] = side;
    out[12] = side;
    out[13] = zero;
    out[14] = edge;
    out[15] = side;
    out[16] = scaledHeight;
    out[17] = edge;
    out[18] = edge;
    out[19] = scaledHeight;
    out[20] = edge;
    out[21] = edge;
    out[22] = zero;
    out[23] = edge;
}

#pragma dont_inline off
void mm_free_(void* ptr)
{
    mm_free(ptr);
}

void dll_07_func09(void)
{
    Camera_GetCurrentViewSlot();
    randomGetRange(5, 5);
}

int dll_07_func08(void)
{
    return gNewCloudBlizzardActive;
}

void newclouds_initialise(void)
{
    gNewCloudInitialized = 0;
}

void dll_07_func0A_nop(void)
{
}

void cloudClearOverridePosition(void)
{
    gCloudOverridePositionValid = 0;
}

void cloudSetOverridePosition(f32 a, f32 b, f32 c)
{
    gCloudOverridePositionValid = 1;
    gCloudOverridePositionX = a;
    gCloudOverridePositionY = b;
    gCloudOverridePositionZ = c;
}

extern void ModelLightStruct_free(void* p);
extern void Music_Trigger(int id, int arg);
void* gNewCloudLayerTextures[4];
void* gNewClouds[8];
extern void* lbl_803DD1C8;
extern void* lbl_803DD1C4;
extern void* gNewCloudModelLight;
extern const f32 lbl_803DF1A4;
extern f32 gNewCloudOvercastFadeLevel;
extern f32 lbl_803DB764;
extern f32 lbl_803DB768;
extern f32 gNewCloudScrollPhaseA;
extern f32 gNewCloudScrollPhaseB;
extern f32 gNewCloudScrollPhaseC;
extern f32 lbl_803DD190;
extern f32 gNewCloudOvercastFadeRate;
extern u8 gNewCloudSnowFlashAlpha;
extern u8 lbl_803DD199;
extern u8 lbl_803DD19A;
extern u8 gNewCloudBlizzardActivePrev;
void snowFreeSnowCloud(int index);

void newclouds_release(void)
{
    int i;

    if (lbl_803DD1C8 != NULL)
    {
        textureFree(lbl_803DD1C8);
        lbl_803DD1C8 = NULL;
    }
    for (i = 0; i < 4; i++)
    {
        if (gNewCloudLayerTextures[i] != NULL)
        {
            textureFree(gNewCloudLayerTextures[i]);
            gNewCloudLayerTextures[i] = NULL;
        }
    }
    if (lbl_803DD1C4 != NULL)
    {
        textureFree(lbl_803DD1C4);
        lbl_803DD1C4 = NULL;
    }
    if (gNewCloudModelLight != NULL)
    {
        ModelLightStruct_free(gNewCloudModelLight);
    }
    gNewCloudInitialized = 0;
}

void newclouds_onMapSetup(void)
{
    int i;
    f32 a;
    f32 b;

    for (i = 0; i < 8; i++)
    {
        if (gNewClouds[i] != NULL)
        {
            snowFreeSnowCloud(i);
        }
        gNewClouds[i] = NULL;
    }
    a = lbl_803DF1A0;
    gNewCloudScrollPhaseA = a;
    gNewCloudScrollPhaseB = a;
    gNewCloudScrollPhaseC = a;
    lbl_803DD190 = a;
    b = (gNewCloudOvercastFadeLevel = lbl_803DF1A4);
    gNewCloudOvercastFadeRate = a;
    gNewCloudSnowFlashAlpha = 0;
    lbl_803DB764 = b;
    lbl_803DD199 = 0;
    lbl_803DD19A = 0;
    lbl_803DB768 = b;
    gNewCloudBlizzardActivePrev = 0;
    Music_Trigger(MUSICTRIG_crun_dungeon, 0);
}

extern void setTextColor(int unused, int a, int b, int c, int d);

#pragma dont_inline on
void* lightningCreate(f32* a, f32* b, f32 c, f32 d, s16 e, u8 f, u8 g)
{
    LightningEffect* p = mmAlloc(40, 23, 0);

    if (p == NULL)
    {
        return NULL;
    }
    p->start[0] = a[0];
    p->start[1] = a[1];
    p->start[2] = a[2];
    p->end[0] = b[0];
    p->end[1] = b[1];
    p->end[2] = b[2];
    p->radiusX = c;
    p->radiusY = d;
    *(s16*)&p->lifetime = e;
    p->width = f;
    p->timer = 0;
    p->seed = 0xFFFF;
    p->flags = g;
    return p;
}

extern float mathSinf(float x);
extern float mathCosf(float x);

typedef struct FogColor
{
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} FogColor;

extern void GXSetFog(int type, f32 startz, f32 endz, f32 nearz, f32 farz, FogColor color);
extern int snowPrintSnowCloud(int arg, int x);
extern void drawFn_80079e64(double s1, u8 mtxIdx, void* vec, double s2, u8 a0, u8 a1, double s3);
f32 lbl_8039A8F0[4];
extern int gNewCloudSnowFogColor;

typedef struct
{
    s16 uv[6];
} SnowFlakeUVs;

extern const SnowFlakeUVs lbl_802C1FCC;

#pragma dont_inline off
void dll_07_func07(int arg)
{
    int i;
    int total;
    NewCloud* snow;

    GXSetFog(0, 0.0f, 0.0f, 0.0f, 0.0f,
             *(FogColor*)&gNewCloudSnowFogColor);
    for (i = 0, total = 0; i < 8; i++)
    {
        snow = gNewClouds[i];
        if (snow != NULL && snow->finished == 0)
        {
            total += snowPrintSnowCloud(arg, snow->cloudId);
        }
    }
    if (gNewCloudSnowFlashAlpha != 0)
    {
        drawFn_80079e64(lbl_803DD190, gNewCloudSnowFlashAlpha, lbl_8039A8F0, lbl_803DB764,
                        lbl_803DD199, lbl_803DD19A, lbl_803DB768);
    }
}

extern char sSnowKillSnowCloudInvalidCloudId[];
extern void debugPrintf(char* fmt, ...);

#pragma dont_inline on
void newclouds_snowKillSnowCloud(int cloudId, int flag)
{
    void* p;
    int i;

    if (flag == 0)
    {
        if (cloudId == -1)
        {
            for (i = 0; i < 8; i++)
            {
                snowFreeSnowCloud(i);
            }
        }
        else
        {
            snowFreeSnowCloud(cloudId);
        }
        return;
    }
    for (i = 0; i < 8; i++)
    {
        p = gNewClouds[i];
        if (p != NULL && cloudId == ((NewCloud*)p)->cloudId)
        {
            break;
        }
    }
    if (gNewClouds[i] == NULL || i == 8)
    {
        return;
    }
    if (cloudId != ((NewCloud*)gNewClouds[i])->cloudId)
    {
        debugPrintf(sSnowKillSnowCloudInvalidCloudId, cloudId);
        return;
    }
    ((NewCloud*)gNewClouds[i])->despawning = 1;
    ((NewCloud*)gNewClouds[i])->flakeDrainRate =
        -((f32)flag / (f32)((NewCloud*)gNewClouds[i])->flakeCount);
}

extern int ObjModel_GetRenderOp(int model, int x);
extern int Shader_getLayer(int renderOp, int x);
extern const f32 lbl_803DF2B0;
extern f32 lbl_803DF2B4;

#pragma dont_inline off
void* cloudGetLayerTextureSize(f32* out1, f32* out2)
{
    ObjTextureRuntimeSlot* tex;
    int* layer;

    if (lbl_8039AB28.mainCloudObj != NULL)
    {
        layer = (int*)Shader_getLayer(
            ObjModel_GetRenderOp(*(int*)Obj_GetActiveModel(lbl_8039AB28.mainCloudObj), 0), 0);
        tex = objFindTexture(lbl_8039AB28.mainCloudObj, 0, 0);
        if (tex != NULL)
        {
            f32 scale = lbl_803DF2B0;
            *out1 = scale * tex->offsetS;
            *out2 = scale * tex->offsetT;
        }
        else
        {
            f32 d = lbl_803DF2B4;
            *out1 = d;
            *out2 = d;
        }
        return textureIdxToPtr(*layer);
    }
    {
        f32 d = lbl_803DF2B4;
        *out1 = d;
        *out2 = d;
    }
    return NULL;
}

extern void* memset(void* dst, int c, int n);


extern char sSnowFreeSnowCloudInvalidCloudId[];

#pragma dont_inline on
void snowFreeSnowCloud(int cloudId)
{
    u8* env;
    u8* p;
    int i;

    env = saveGameGetEnvState();
    if (cloudId >= 0 && cloudId <= 2 && getSaveGameLoadStatus() == 0)
    {
        ((s16*)(env + 0xe))[cloudId] = -1;
        ((s8*)(env + 0x41))[cloudId] = -1;
    }
    for (i = 0; i < 8; i++)
    {
        p = gNewClouds[i];
        if (p != NULL && cloudId == ((NewCloud*)p)->cloudId)
        {
            break;
        }
    }
    p = gNewClouds[i];
    if (p == NULL || i == 8)
    {
        return;
    }
    if (cloudId != ((NewCloud*)p)->cloudId)
    {
        debugPrintf(sSnowFreeSnowCloudInvalidCloudId, cloudId);
        return;
    }
    if (*(u8**)(p + 4) != NULL)
    {
        mm_free(*(u8**)(p + 4));
        *(u8**)((u8*)gNewClouds[i] + 4) = NULL;
    }
    if (gNewClouds[i] != NULL)
    {
        mm_free(gNewClouds[i]);
        gNewClouds[i] = NULL;
    }
}

extern inline float sqrtf__inline(float x)
{
    static const double _half = .5;
    static const double _three = 3.0;
    volatile float y;
    if (x > 0.0f)
    {
        double guess = __frsqrte((double)x);
        guess = _half * guess * (_three - guess * guess * x);
        guess = _half * guess * (_three - guess * guess * x);
        guess = _half * guess * (_three - guess * guess * x);
        y = (float)(x * guess);
        return y;
    }
    return x;
}

typedef struct WindSource
{
    s32 x;
    s32 z;
    f32 vx;
    f32 vy;
    f32 vz;
    f32 scale;
    s16 flag;
    s16 pad1a;
} WindSource;

#define NEWCLOUD_WIND_SOURCE_COUNT 6
WindSource gNewCloudWindSources[NEWCLOUD_WIND_SOURCE_COUNT];
extern s16 renderModeSetOrGet(int mode);
extern void normalize(f32 * x, f32 * y, f32 * z);

#pragma dont_inline off
void snowCloudComputeDrift(f32* out, f32* pos, f32 scale)
{
    f32 accX;
    f32 accZ;
    f32 d;
    f32 dxSq;
    f32 dSq;
    f32 dists[NEWCLOUD_WIND_SOURCE_COUNT];
    int i;

    if (renderModeSetOrGet(-1) == 1)
    {
        return;
    }
    accX = 0.0f;
    accZ = 0.0f;
    for (i = 0; i < NEWCLOUD_WIND_SOURCE_COUNT; i++)
    {
        d = gNewCloudWindSources[i].x - pos[0];
        dxSq = d * d;
        d = gNewCloudWindSources[i].z - pos[2];
        d = d * d;
        dSq = dxSq + d;
        if (dSq)
        {
            dists[i] = sqrtf__inline(dSq);
        }
        else
        {
            dists[i] = 0.0f;
        }
        if (dists[i] < 50.0f)
        {
            dists[i] = 50.0f;
        }
    }
    for (i = 0; i < NEWCLOUD_WIND_SOURCE_COUNT; i++)
    {
        dists[i] = 1.0f / sqrtf__inline(dists[i]);
    }
    for (i = 0; i < NEWCLOUD_WIND_SOURCE_COUNT; i++)
    {
        accX += gNewCloudWindSources[i].vx * dists[i];
        accZ += gNewCloudWindSources[i].vz * dists[i];
    }
    out[0] = -accX;
    out[2] = -accZ;
    out[1] = 0.0f;
    normalize(out, out + 1, out + 2);
    out[0] = out[0] * scale;
    out[1] = 0.0f;
    out[2] = out[2] * scale;
}

extern void GXSetCullMode(int mode);


extern void GXSetVtxDesc(int attr, int type);



extern void fn_800788DC(void);
extern void fn_8006C51C(void* out);
extern void selectTexture(char* tex, int slot);

extern void GXLoadPosMtxImm(f32* matrix, s32 slot);
extern void GXSetCurrentMtx(u32 id);

extern void srand(int seed);
extern void PSVECSubtract(f32 * a, f32 * b, f32 * ab);
extern f32 PSVECMag(f32 * v);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int gNewCloudLightningFogColor;
extern const f32 lbl_803DF1D4;

void lightningDrawBolt(f32* start, f32* end, int width, f32 c, f32 d, int* seed, int e, int f);

void lightningRender(void* state)
{
    LightningEffect* p = state;
    f32 start[3];
    f32 end[3];
    f32 diff[3];
    char* tex;
    int savedSeed;
    FogColor color;
    int a;
    int b;
    int half;

    color = *(FogColor*)&gNewCloudLightningFogColor;
    start[0] = p->start[0] - playerMapOffsetX;
    start[1] = p->start[1];
    start[2] = p->start[2] - playerMapOffsetZ;
    end[0] = p->end[0] - playerMapOffsetX;
    end[1] = p->end[1];
    end[2] = p->end[2] - playerMapOffsetZ;
    a = p->timer;
    b = p->lifetime;
    half = (u32)b >> 1;
    if (a <= half)
    {
        _gxSetTevColor2(0x80, 0x80, 0xff, 0xff);
    }
    else
    {
        _gxSetTevColor2(0x80, 0x80, 0xff,
                        (int)((lbl_803DF1D4 * (b - a)) / half));
    }
    GXSetCullMode(GX_CULL_NONE);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    textureSetupFn_800799c0();
    gxTextureFn_800794e0();
    textRenderSetupFn_80079804();
    fn_800788DC();
    fn_8006C51C(&tex);
    selectTexture(tex, 0);
    GXSetFog(0, 0.0f, 0.0f, 0.0f, 0.0f, color);
    Camera_UpdateViewMatrices();
    GXLoadPosMtxImm(Camera_GetViewMatrix(), 0);
    GXSetCurrentMtx(0);
    savedSeed = rand();
    if (p->seed == 0xffff)
    {
        p->seed = savedSeed;
    }
    srand(p->seed);
    PSVECSubtract(end, start, diff);
    PSVECMag(diff);
    lightningDrawBolt(start, end, p->width, p->radiusX, p->radiusY, &savedSeed, 0,
                      p->flags);
    srand(savedSeed);
}

extern s16 gSnowFlakeWaveAngle;
extern f32 gSnowFlakeWaveValue;
extern f32 lbl_803DD1B0;
extern const f32 gSnowFlakeWaveAmpScale;
extern const f32 gSnowFlakeSize;
extern const f32 gSnowFlakeSizeLarge;
extern const f32 lbl_803DF1EC;
extern const f32 gNewCloudPi;
extern const f32 lbl_803DF1F4;
extern const f32 lbl_803DF1F8;

void snowCloudInitFlakes(f32* buf, f32 a, f32 b, int cloudId)
{
    u8* p;
    SnowQuad* e;
    f32* dst;
    int i;
    int j;
    int widx;
    f32 amp;
    f32 halfNeg;
    f32 negSize;
    f32 size;
    f32 ab;

    ab = a * b;
    amp = ab * gSnowFlakeWaveAmpScale;
    for (i = 0; i < 8; i++)
    {
        p = gNewClouds[i];
        if (p != NULL && cloudId == ((NewCloud*)p)->cloudId)
        {
            break;
        }
    }
    p = gNewClouds[i];
    if (p == NULL || gSnowFlakeSize == gSnowFlakeWaveValue)
    {
        return;
    }
    if (cloudId != ((NewCloud*)p)->cloudId)
    {
        debugPrintf(sSnowFreeSnowCloudInvalidCloudId, cloudId);
        return;
    }
    if (((NewCloud*)p)->cloudType == 4)
    {
        size = gSnowFlakeSize;
    }
    else
    {
        size = gSnowFlakeSizeLarge;
    }
    j = 0;
    e = (SnowQuad*)(p + 0x1008);
    negSize = -size;
    halfNeg = lbl_803DF1EC * negSize;
    for (; j < 20; j++)
    {
        e->verts[0] = negSize;
        e->verts[6] = 0.0f;
        e->verts[1] = size;
        e->verts[7] = 0.0f;
        e->verts[2] = 0.0f;
        e->verts[8] = 0.0f;
        if (((NewCloud*)gNewClouds[i])->cloudType == 0)
        {
            e->verts[3] = negSize;
            e->verts[4] = negSize;
            e->verts[5] = size;
        }
        else
        {
            e->verts[3] = negSize;
            e->verts[4] = negSize;
            e->verts[5] = halfNeg;
        }
        e->angA = randomGetRange(0, 0xffff);
        e->angB = randomGetRange(0, 0xffff);
        e->angVelA = randomGetRange(0x96, 0x1f4);
        e->angVelB = randomGetRange(0x96, 0x1f4);
        e += 1;
    }
    widx = ((NewCloud*)gNewClouds[i])->waveWriteIdx;
    dst = buf + widx;
    while (widx < ((NewCloud*)gNewClouds[i])->waveWriteIdx + 0xfa0)
    {
        if (widx == 0x400)
        {
            ((NewCloud*)gNewClouds[i])->active = 0;
            ((NewCloud*)gNewClouds[i])->waveWriteIdx = 0;
            return;
        }
        if (widx == 0)
        {
            gSnowFlakeWaveAngle = 0;
            gSnowFlakeWaveValue = 0.0f;
            lbl_803DD1B0 = 0.0f;
        }
        mathSinf((gNewCloudPi * gSnowFlakeWaveAngle) / lbl_803DF1F4);
        mathCosf((gNewCloudPi * gSnowFlakeWaveAngle) / lbl_803DF1F4);
        *dst = gSnowFlakeWaveValue * amp;
        gSnowFlakeWaveAngle = gSnowFlakeWaveAngle + lbl_803DF1F8;
        gSnowFlakeWaveValue = gSnowFlakeWaveValue + lbl_803DF1A4;
        dst++;
        widx++;
    }
    ((NewCloud*)gNewClouds[i])->waveWriteIdx = ((NewCloud*)gNewClouds[i])->waveWriteIdx + 0xfa0;
}


extern void fn_800790AC(void);


extern void GXSetPointSize(int size, int fmt);
extern int gNewCloudStarFogColor;
extern u8 gNewCloudStarAlphaRanges[8];
extern u8 gNewCloudStarColorRanges[];
u16 gNewCloudStarDisplayListSizes[0x5C];
void* gNewCloudStarDisplayLists[0x5C];
extern char* gNewCloudStarTextureA;
extern char* gNewCloudStarTextureB;
extern const f32 gNewCloudStarFadeInTime;
extern const f32 lbl_803DF284;
extern const f32 gNewCloudStarFadeOutTime;
extern const f32 lbl_803DF28C;

#pragma opt_common_subs off
#pragma opt_common_subs off
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
    if (isOvercast() != 0)
    {
        if (timeOk != 0)
        {
            if (t > gNewCloudStarFadeInTime)
            {
                alpha = 0xff;
            }
            else
            {
                alpha = (lbl_803DF284 * (t / gNewCloudStarFadeInTime));
            }
        }
        else
        {
            if (t > gNewCloudStarFadeOutTime || lbl_803DF28C == t)
            {
                return;
            }
            alpha = (lbl_803DF284 - lbl_803DF284 * (t / gNewCloudStarFadeOutTime));
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
    GXSetFog(0, 0.0f, 0.0f, 0.0f, 0.0f, color);
    Camera_UpdateViewMatrices();
    GXLoadPosMtxImm(Camera_GetViewRotationMatrix(), 0);
    GXSetCurrentMtx(0);
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
            selectTexture(gNewCloudStarTextureA, 0);
            textureSetupFn_800799c0();
            textRenderSetupFn_800795e8();
            textRenderSetupFn_80079804();
        }
        else if (i == 0x54)
        {
            selectTexture(gNewCloudStarTextureB, 0);
        }
        if (i < 0x4c)
        {
            GXSetPointSize((u8)randomGetRange(0xc, 0xc), 5);
        }
        else if (i & 4)
        {
            GXSetPointSize((u8)(randomGetRange(0x30, 0x3c) / div), 5);
        }
        else
        {
            GXSetPointSize((u8)(randomGetRange(0x48, 0x60) / div), 5);
        }
        GXCallDisplayList(gNewCloudStarDisplayLists[i], gNewCloudStarDisplayListSizes[i]);
    }
}
#pragma opt_common_subs reset

#pragma opt_common_subs reset


typedef union PPCWGPipe2
{
    u8 u8;
    u16 u16;
    u32 u32;
    s8 s8;
    s16 s16;
    s32 s32;
    f32 f32;
    f64 f64;
} PPCWGPipe2;

PPCWGPipe2 GXWGFifo : (0xCC008000);


extern void PSVECScale(f32* in, f32* out, f32 scale);
extern void PSVECCrossProduct(f32 * a, f32 * b, f32 * axb);
extern void PSMTXRotAxisRad(f32* mtx, f32* axis, f32 rad);
extern void PSMTXMultVecSR(f32 * mtx, f32 * src, f32 * dst);
extern void GXSetLineWidth(int width, int fmt);
extern void GXBegin(int prim, int fmt, u16 count);
extern const f32 gNewCloudUpVectorThreshold;
extern f32 lbl_803DF1BC;
extern const f32 lbl_803DF1C0;
extern const f32 lbl_803DF1C4;
extern const f32 lbl_803DF1C8;
extern const f32 lbl_803DF1CC;

void lightningDrawStrand(f32* from, f32* to, int width, f32 segScale, int* seed)
{
    int segs;
    int savedRand;
    int i;
    f32 total;
    f32 len;
    f32 px;
    f32 py;
    f32 pz;
    f32 weight;
    f32 step;
    f32 mtx[12];
    f32 dir[3];
    f32 scaled[3];
    f32 up[3];
    f32 side[3];
    f32 offset[3];

    if (getHudHiddenFrameCount() == 0)
    {
        savedRand = rand();
        srand(*seed);
    }
    PSVECSubtract(to, from, dir);
    len = PSVECMag(dir);
    PSVECScale(dir, scaled, lbl_803DF1A4 / len);
    if (__fabs(scaled[0]) < gNewCloudUpVectorThreshold)
    {
        up[0] = lbl_803DF1A4;
        up[1] = lbl_803DF1A0;
        up[2] = lbl_803DF1A0;
    }
    else
    {
        up[0] = lbl_803DF1A0;
        up[1] = lbl_803DF1A0;
        up[2] = lbl_803DF1A4;
    }
    PSVECCrossProduct(scaled, up, side);
    PSVECCrossProduct(side, scaled, up);
    PSVECNormalize(up, up);
    segs = (len * segScale);
    if (segs > 10)
    {
        segs = 10;
    }
    if (segs == 0)
    {
        segs = 1;
    }
    total = lbl_803DF1A0;
    for (i = 0; i < segs; i++)
    {
        total += (i + 1);
    }
    weight = lbl_803DF1A4 / total;
    GXSetLineWidth(width, 5);
    GXBegin(0xb0, 2, segs + 1);
    for (i = 0; i <= segs; i++)
    {
        if (i == 0)
        {
            f32 a0, a1, a2;
            a2 = from[2];
            a1 = from[1];
            a0 = from[0];
            GXWGFifo.f32 = a0;
            GXWGFifo.f32 = a1;
            GXWGFifo.f32 = a2;
            GXWGFifo.f32 = lbl_803DF1A0;
            GXWGFifo.f32 = lbl_803DF1A0;
            px = from[0];
            py = from[1];
            pz = from[2];
        }
        else if (i < segs)
        {
            f32 e0, e1, e2;
            PSVECScale(up, offset,
                       lbl_803DF1BC *
                       (lbl_803DF1C0 * (len * randomGetRange(1, 100))
            )
            )
            ;
            PSMTXRotAxisRad(
                mtx, scaled,
                lbl_803DF1C4 *
                (lbl_803DF1C8 * (lbl_803DF1CC * randomGetRange(0, 1000))
            )
            )
            ;
            PSMTXMultVecSR(mtx, offset, offset);
            px += scaled[0] * (step = weight * (len * (segs - i)));
            py += scaled[1] * step;
            pz += scaled[2] * step;
            e2 = pz;
            e2 += offset[2];
            e1 = py;
            e1 += offset[1];
            e0 = px;
            e0 += offset[0];
            GXWGFifo.f32 = e0;
            GXWGFifo.f32 = e1;
            GXWGFifo.f32 = e2;
            GXWGFifo.f32 = lbl_803DF1A0;
            GXWGFifo.f32 = lbl_803DF1A0;
        }
        else
        {
            f32 b0, b1, b2;
            b2 = to[2];
            b1 = to[1];
            b0 = to[0];
            GXWGFifo.f32 = b0;
            GXWGFifo.f32 = b1;
            GXWGFifo.f32 = b2;
            GXWGFifo.f32 = lbl_803DF1A0;
            GXWGFifo.f32 = lbl_803DF1A0;
        }
    }
    if (getHudHiddenFrameCount() == 0)
    {
        *seed = rand();
        srand(savedRand);
    }
}

void snowCloudUpdateFlakes(u8* snow)
{
    s16* cam;
    SnowQuad* e;
    f32* m;
    int i;
    int c;
    f32 c1;
    f32 s1;
    f32 c2;
    f32 s2;
    f32 c3;
    f32 s3;

    cam = Camera_GetCurrentViewSlot();
    e = (SnowQuad*)(snow + 0x1008);
    if (((NewCloud*)snow)->cloudType == 0)
    {
        for (i = 0; i < 20; i++)
        {
            f32 size = gSnowFlakeSizeLarge;
            f32 negSize = -size;
            m = e->verts;
            m[0] = negSize;
            m[3] = negSize;
            m[6] = 0.0f;
            m[1] = size;
            m[4] = negSize;
            m[7] = 0.0f;
            m[2] = 0.0f;
            m[5] = size;
            m[8] = 0.0f;
            e->angA =
                timeDelta * (f32)e->angVelA + (f32)e->angA;
            e->angB =
                timeDelta * (f32)e->angVelB + (f32)e->angB;
            angleToVec2((u16)(0xffff - *cam), &c1, &s1);
            angleToVec2(e->angA, &c2, &s2);
            angleToVec2(e->angB, &c3, &s3);
            for (c = 0; c < 3; c++)
            {
                f32 t2;
                f32 m0 = m[c];
                f32 m1 = m[c + 3];
                f32 m2 = m[c + 6];
                f32 t1 = m0 * s3 - m1 * c3;
                t2 = m0 * c3 + m1 * s3;
                m[c] = t1 * s1 + c1 * (t2 * c2) + c1 * (m2 * s2);
                m[c + 3] = t2 * s2 + -m2 * c2;
                m[c + 6] = -t1 * c1 + s1 * (t2 * c2) + s1 * (m2 * s2);
            }
            e += 1;
        }
    }
    else
    {
        f32 size2;
        f32 negSize2;
        angleToVec2((u16)(0xffff - *cam), &c1, &s1);
        size2 = gSnowFlakeSize;
        negSize2 = -size2;
        m = e->verts;
        for (i = 0; i < 20; i++)
        {
            m[0] = negSize2 * s1;
            m[6] = size2 * c1;
            m[1] = size2 * s1;
            m[7] = size2 * -c1;
            m += 0xb;
        }
    }
}

extern void PSVECAdd(f32 * a, f32 * b, f32 * ab);
extern const f32 lbl_803DF1D0;

void lightningDrawBolt(f32* start, f32* end, int width, f32 segScale, f32 d, int* seed, int depth,
                       int flags)
{
    f32 len;
    f32 total;
    f32 py;
    f32 pz;
    f32 nx;
    f32 ny;
    f32 nz;
    f32 px;
    f32 weight;
    f32 progress;
    f32 step;
    f32 bfrac;
    int i;
    int halfWidth;
    int oddFlag;
    int segs;
    f32 mtx[12];
    f32 dir[3];
    f32 scaled[3];
    f32 up[3];
    f32 side[3];
    f32 offset[3];
    f32 cur[3];
    f32 next[3];
    f32 branchEnd[3];

    if ((u32)depth > 2)
    {
        return;
    }
    PSVECSubtract(end, start, dir);
    len = PSVECMag(dir);
    PSVECScale(dir, scaled, lbl_803DF1A4 / len);
    if (__fabs(scaled[0]) < gNewCloudUpVectorThreshold)
    {
        up[0] = lbl_803DF1A4;
        up[1] = lbl_803DF1A0;
        up[2] = lbl_803DF1A0;
    }
    else
    {
        up[0] = lbl_803DF1A0;
        up[1] = lbl_803DF1A0;
        up[2] = lbl_803DF1A4;
    }
    PSVECCrossProduct(scaled, up, side);
    PSVECCrossProduct(side, scaled, up);
    PSVECNormalize(up, up);
    segs = (len * segScale);
    if (segs > 10)
    {
        segs = 10;
    }
    if (segs == 0)
    {
        return;
    }
    total = lbl_803DF1A0;
    for (i = 0; i < segs; i++)
    {
        total += (i + 1);
    }
    weight = lbl_803DF1A4 / total;
    px = start[0];
    py = start[1];
    pz = start[2];
    cur[0] = px;
    cur[1] = py;
    cur[2] = pz;
    progress = *(f32*)&lbl_803DF1A0;
    i = 0;
    oddFlag = (u8)flags & 1;
    halfWidth = (u8)width >> 1;
    for (; i <= segs; i++)
    {
        if (i < segs)
        {
            PSVECScale(up, offset,
                       lbl_803DF1BC *
                       (lbl_803DF1C0 * (len * randomGetRange(1, 100))
            )
            )
            ;
            PSMTXRotAxisRad(
                mtx, scaled,
                lbl_803DF1C4 *
                (lbl_803DF1C8 * (lbl_803DF1CC * randomGetRange(0, 1000))
            )
            )
            ;
            PSMTXMultVecSR(mtx, offset, offset);
            progress += weight * (segs - i);
            step = weight * (len * (segs - i));
            nx = px + scaled[0] * step;
            ny = py + scaled[1] * step;
            nz = pz + scaled[2] * step;
            next[0] = nx + offset[0];
            next[1] = ny + offset[1];
            next[2] = nz + offset[2];
            if (randomGetRange(1, 3) == 1 && (u8)width >= 0xc && oddFlag == 0)
            {
                PSVECScale(up, offset,
                           lbl_803DF1BC * (lbl_803DF1D0 *
                               (len * randomGetRange(0x32, 0x64))
                )
                )
                ;
                PSMTXRotAxisRad(mtx, scaled,
                                lbl_803DF1C4 *
                                (lbl_803DF1C8 *
                                    (lbl_803DF1CC * randomGetRange(0, 1000))
                )
                )
                ;
                PSMTXMultVecSR(mtx, offset, offset);
                bfrac = lbl_803DF1CC * ((lbl_803DF1A4 - progress) *
                            randomGetRange(0, 1000)) +
                    progress;
                PSVECScale(scaled, branchEnd, bfrac * len);
                PSVECAdd(start, branchEnd, branchEnd);
                PSVECAdd(branchEnd, offset, branchEnd);
                lightningDrawBolt(next, branchEnd, halfWidth, segScale, d, seed, depth + 1,
                                  flags);
            }
        }
        else
        {
            next[0] = end[0];
            next[1] = end[1];
            next[2] = end[2];
        }
        lightningDrawStrand(cur, next, width, d, seed);
        px = nx;
        py = ny;
        pz = nz;
        cur[0] = next[0];
        cur[1] = next[1];
        cur[2] = next[2];
    }
}

extern void GXSetMisc(int token, u32 val);

extern void PSMTXRotRad(f32* mtx, int axis, f32 rad);
extern u8 gNewCloudStarsInitialized;
extern const f32 gNewCloudStarRadius;
extern const f32 gNewCloudStarAxisThreshold;
extern const f32 lbl_803DF298;
extern const f32 lbl_803DF29C;
extern const f32 lbl_803DF2A0;
extern const f32 lbl_803DF2A4;

void titleScreenDrawFn_80093db4(void)
{
    int k;
    f32* cp;
    int i;
    int j;
    f32* constellation;
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
        PSVECScale(v, v, gNewCloudStarRadius);
        cp[0] = v[0];
        cp[1] = v[1];
        cp[2] = v[2];
        cp += 3;
    }
    gNewCloudStarsInitialized = 1;
    gNewCloudStarTextureA = textureLoadAsset(0xc21);
    gNewCloudStarTextureB = textureLoadAsset(0xc22);
    for (k = 0; k < 0x5c; k++)
    {
        gNewCloudStarDisplayLists[k] = mmAlloc(0x220, 0x7f7f7fff, 0);
        DCInvalidateRange(gNewCloudStarDisplayLists[k], 0x220);
        GXBeginDisplayList(gNewCloudStarDisplayLists[k], 0x220);
        GXResetWriteGatherPipe();
        GXBegin(0xb8, 0, 0x32);
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
                PSVECScale(v, v, gNewCloudStarRadius);
            }
            else
            {
                idx = randomGetRange(0, 0x63);
                v[0] = constellation[idx * 3];
                v[1] = constellation[idx * 3 + 1];
                v[2] = constellation[idx * 3 + 2];
                if (__fabs(v[0]) > gNewCloudStarAxisThreshold)
                {
                    PSMTXRotRad(mtx1, 0x79,
                                (lbl_803DF298 *
                                    (lbl_803DF29C *
                                        (lbl_803DF2A0 *
                                            randomGetRange(-0x8000, 0x8000))
                    )
                    )
                    /
                    lbl_803DF2A4
                    )
                    ;
                    PSMTXRotRad(mtx2, 0x7a,
                                (lbl_803DF298 *
                                    (lbl_803DF29C *
                                        (lbl_803DF2A0 *
                                            randomGetRange(-0x8000, 0x8000))
                    )
                    )
                    /
                    lbl_803DF2A4
                    )
                    ;
                }
                else if (__fabs(v[1]) > gNewCloudStarAxisThreshold)
                {
                    PSMTXRotRad(mtx1, 0x78,
                                (lbl_803DF298 *
                                    (lbl_803DF29C *
                                        (lbl_803DF2A0 *
                                            randomGetRange(-0x8000, 0x8000))
                    )
                    )
                    /
                    lbl_803DF2A4
                    )
                    ;
                    PSMTXRotRad(mtx2, 0x7a,
                                (lbl_803DF298 *
                                    (lbl_803DF29C *
                                        (lbl_803DF2A0 *
                                            randomGetRange(-0x8000, 0x8000))
                    )
                    )
                    /
                    lbl_803DF2A4
                    )
                    ;
                }
                else
                {
                    PSMTXRotRad(mtx1, 0x78,
                                (lbl_803DF298 *
                                    (lbl_803DF29C *
                                        (lbl_803DF2A0 *
                                            randomGetRange(-0x8000, 0x8000))
                    )
                    )
                    /
                    lbl_803DF2A4
                    )
                    ;
                    PSMTXRotRad(mtx2, 0x79,
                                (lbl_803DF298 *
                                    (lbl_803DF29C *
                                        (lbl_803DF2A0 *
                                            randomGetRange(-0x8000, 0x8000))
                    )
                    )
                    /
                    lbl_803DF2A4
                    )
                    ;
                }
                PSMTXConcat((void*)mtx2, (void*)mtx1, (void*)mtx1);
                PSMTXMultVecSR(mtx1, v, v);
            }
            GXWGFifo.s16 = v[0];
            GXWGFifo.s16 = v[1];
            GXWGFifo.s16 = v[2];
            GXWGFifo.s16 = 0;
            GXWGFifo.s16 = 0;
        }
        gNewCloudStarDisplayListSizes[k] = GXEndDisplayList();
    }
    mm_free(constellation);
    GXSetMisc(1, 8);
}

extern char lbl_8030F670[];
extern const f32 lbl_803DF228;
extern const f32 gNewCloudLightningForwardDist;
extern f32 gNewCloudLightningRadius;

void snowReposSnowCloud(int cloudId)
{
    u8* p;
    SnowFlake* part;
    f32* cam;
    f32* m;
    u8* q;
    int i;
    int j;
    int dx;
    int dy;
    int dz;
    int distSq;
    u8 fl;
    struct
    {
        s16 f8;
        s16 fa;
        s16 fc;
        s16 pad_e;
        f32 f10;
        f32 f14;
        f32 f18;
        f32 f1c;
    } args;
    f32 dir[3] = {0.0f, 0.0f, 0.0f};
    f32 fwd[3];
    f32 from[3];
    f32 to[3];

    if (renderModeSetOrGet(-1) == 1)
    {
        return;
    }
    srand(randomGetRange(1, 0xffff));
    for (i = 0; i < 8; i++)
    {
        p = gNewClouds[i];
        if (p != NULL && cloudId == ((NewCloud*)p)->cloudId)
        {
            break;
        }
    }
    p = gNewClouds[i];
    if (p == NULL || i == 8)
    {
        return;
    }
    if (cloudId != ((NewCloud*)p)->cloudId)
    {
        debugPrintf(lbl_8030F670, cloudId);
        return;
    }
    part = *(SnowFlake**)(p + 4);
    cam = (f32*)Camera_GetCurrentViewSlot();
    dx = cam[0x44 / 4] - ((NewCloud*)gNewClouds[i])->worldPosX;
    dy = cam[0x48 / 4] - ((NewCloud*)gNewClouds[i])->worldPosY;
    dz = cam[0x4c / 4] - ((NewCloud*)gNewClouds[i])->worldPosZ;
    distSq = dx * dx + dy * dy + dz * dz;
    sqrtf__inline((f32)distSq);
    ((NewCloud*)gNewClouds[i])->lightningTimer =
        (f32)((NewCloud*)gNewClouds[i])->lightningTimer - timeDelta;
    q = gNewClouds[cloudId];
    if (((NewCloud*)q)->cloudType == 4 && (((NewCloud*)q)->unk144B & 0x38) != 0 &&
        ((NewCloud*)q)->lightningTimer <= 0 && ((NewCloud*)q)->stationary == 0 && lbl_803DD19C == 0)
    {
        if (((NewCloud*)q)->followCamera != 0 && cam != NULL)
        {
            dir[0] = lbl_803DF1A0;
            dir[1] = lbl_803DF1A0;
            dir[2] = lbl_803DF228;
            args.f14 = lbl_803DF1A0;
            args.f18 = lbl_803DF1A0;
            args.f1c = lbl_803DF1A0;
            args.f10 = lbl_803DF1A4;
            args.fc = 0;
            args.fa = 0;
            args.f8 = 0xffff - (*(s16*)cam + randomGetRange(-5000, 5000));
            vecRotateZXY(&args.f8, dir);
        }
        args.f14 = dir[0];
        args.f18 = dir[1];
        args.f1c = dir[2];
        args.f10 = lbl_803DF1A4;
        args.f8 = 0;
        args.fc = 0;
        args.fa = 0;
        m = Camera_GetViewMatrix();
        fwd[0] = m[8];
        fwd[1] = m[9];
        fwd[2] = m[10];
        PSVECNormalize(fwd, fwd);
        from[0] = (cam[0x44 / 4] + (int)
        randomGetRange(-3000, 3000)
        )
        -
            gNewCloudLightningForwardDist * fwd[0];
        from[1] = (cam[0x48 / 4] + (int)
        randomGetRange(2000, 4000)
        )
        -
            gNewCloudLightningForwardDist * fwd[1];
        from[2] = (cam[0x4c / 4] + (int)
        randomGetRange(-3000, 3000)
        )
        -
            gNewCloudLightningForwardDist * fwd[2];
        to[0] = (cam[0x44 / 4] + (int)
        randomGetRange(-3000, 3000)
        )
        -
            gNewCloudLightningForwardDist * fwd[0];
        to[1] = (cam[0x48 / 4] - (int)
        randomGetRange(2000, 4000)
        )
        -
            gNewCloudLightningForwardDist * fwd[1];
        to[2] = (cam[0x4c / 4] + (int)
        randomGetRange(-3000, 3000)
        )
        -
            gNewCloudLightningForwardDist * fwd[2];
        lbl_803DD19C = lightningCreate(from, to, gNewCloudLightningRadius, lbl_803DF1BC, 0xf, 0xc0, 0);
        {
            extern void Sfx_PlayAtPositionFromObject(int obj, f32 x, f32 y, f32 z, int sfxId);
            Sfx_PlayAtPositionFromObject(0, from[0], from[1], from[2], SFXTRIG_barrelgrabber_suck);
        }
        fl = ((NewCloud*)gNewClouds[cloudId])->unk144B;
        if (fl & 8)
        {
            ((NewCloud*)gNewClouds[cloudId])->lightningTimer = randomGetRange(0x78, 0xf0);
        }
        else if (fl & 0x10)
        {
            ((NewCloud*)gNewClouds[cloudId])->lightningTimer = randomGetRange(0x78, 0xf0);
        }
        else if (fl & 0x20)
        {
            ((NewCloud*)gNewClouds[cloudId])->lightningTimer = randomGetRange(0x5a, 0xb4);
        }
    }
    snowCloudUpdateFlakes(gNewClouds[i]);
    for (j = 0; j < ((NewCloud*)gNewClouds[i])->flakeCount; j++)
    {
        if (((NewCloud*)gNewClouds[i])->cloudType == 0)
        {
            part->angle =
                part->angle + part->size * framesThisStep;
            if ((int)part->angle > 0x3ff)
            {
                part->angle -= 0x3ff;
            }
        }
        else if (((NewCloud*)gNewClouds[i])->cloudType == 4)
        {
            part->angle = part->angle +
                framesThisStep * (part->size + part->size);
            if ((int)part->angle > 0x3ff)
            {
                part->angle -= 0x3ff;
            }
        }
        part += 1;
    }
}

extern char lbl_8030F500[];
extern int gNewCloudWindSourcesInit;
extern const f32 lbl_803DF1FC;
extern const f32 lbl_803DF214;
extern const f32 gNewCloudType0Height;
extern const f32 gNewCloudType0Scale;
extern const f32 lbl_803DF23C;
extern const f32 lbl_803DF240;
extern const f32 lbl_803DF244;

#define NC_CLOUD ((u8 *)gNewClouds[id])
#define NC_PARTS ((SnowFlake *)*(void **)(NC_CLOUD + 4))

void newClouds(CloudSpawnParams* params, void* owner, f32 x, f32 y, f32 z)
{
    char* strs;
    int id;
    int ok;
    int i;
    u8 fl;
    WindSource* w;
    int (*sizeRange)[2];
    int (*spinRange)[2];

    strs = lbl_8030F500;
    ok = 1;
    id = params->cloudIndex;
    if (gNewClouds[id] != NULL)
    {
        snowFreeSnowCloud(id);
    }
    gNewClouds[id] = mmAlloc(0x1454, 0x17, 0);
    if (gNewClouds[id] == NULL)
    {
        debugPrintf(strs + 0x1b0);
        return;
    }
    memset(gNewClouds[id], 0, 0x1454);
    ((NewCloud*)NC_CLOUD)->cloudId = id;
    ((NewCloud*)NC_CLOUD)->posInitialized = 0;
    ((NewCloud*)NC_CLOUD)->cloudType = params->cloudType;
    *(void**)(NC_CLOUD + 0x0) = owner;
    ((NewCloud*)NC_CLOUD)->flags144A = params->flags58;
    ((NewCloud*)NC_CLOUD)->unk144B = params->flags59;
    ((NewCloud*)NC_CLOUD)->worldPosX = x;
    ((NewCloud*)NC_CLOUD)->worldPosY = y;
    ((NewCloud*)NC_CLOUD)->worldPosZ = z;
    if (params->flags58 & 1)
    {
        ((NewCloud*)NC_CLOUD)->spinEnabled = 1;
    }
    if (params->flags58 & 0x10)
    {
        ((NewCloud*)NC_CLOUD)->unk144E = 1;
    }
    ((NewCloud*)NC_CLOUD)->followCamera = 1;
    ((NewCloud*)NC_CLOUD)->stationary = params->stationaryInit;
    if (((NewCloud*)NC_CLOUD)->cloudType == 0)
    {
        ((NewCloud*)NC_CLOUD)->flakeCount = params->flakeCount << 3;
    }
    else
    {
        ((NewCloud*)NC_CLOUD)->flakeCount = params->flakeCount;
    }
    if (params->fillDivisor != 0)
    {
        ((NewCloud*)NC_CLOUD)->flakeFillRate =
            (f32)((NewCloud*)NC_CLOUD)->flakeCount / (f32)params->fillDivisor;
    }
    else
    {
        ((NewCloud*)NC_CLOUD)->flakeFillRate = ((NewCloud*)NC_CLOUD)->flakeCount;
    }
    if (params->drainDivisor != 0)
    {
        ((NewCloud*)NC_CLOUD)->flakeDrainRate =
            (f32)((NewCloud*)NC_CLOUD)->flakeCount / (f32)params->drainDivisor;
    }
    else
    {
        ((NewCloud*)NC_CLOUD)->flakeDrainRate = ((NewCloud*)NC_CLOUD)->flakeCount;
    }
    ((NewCloud*)NC_CLOUD)->driftScale = params->driftMax;
    if (((NewCloud*)NC_CLOUD)->cloudType == 0)
    {
        ((NewCloud*)NC_CLOUD)->cloudHeight = gNewCloudType0Height;
        ((NewCloud*)NC_CLOUD)->scale = gNewCloudType0Scale;
    }
    else
    {
        ((NewCloud*)NC_CLOUD)->cloudHeight = params->heightBase;
        ((NewCloud*)NC_CLOUD)->scale = gSnowFlakeSize * params->driftBase;
    }
    if (params->driftMax < lbl_803DF1A4)
    {
        params->driftMax = lbl_803DF1A0;
    }
    if (lbl_803DF1A0 != params->driftMax)
    {
        ((NewCloud*)NC_CLOUD)->driftRate = lbl_803DF23C;
        {
            int r = randomGetRange(1, params->driftMax);
            ((NewCloud*)NC_CLOUD)->driftLimit = r * lbl_803DF214;
        }
    }
    ((NewCloud*)NC_CLOUD)->active = 1;
    fl = ((NewCloud*)NC_CLOUD)->unk144B;
    if (fl & 8)
    {
        ((NewCloud*)NC_CLOUD)->lightningTimer = 0x320;
    }
    else if (fl & 0x10)
    {
        ((NewCloud*)NC_CLOUD)->lightningTimer = 0xc8;
    }
    else if (fl & 0x20)
    {
        ((NewCloud*)NC_CLOUD)->lightningTimer = 0x64;
    }
    snowCloudInitFlakes((f32*)(NC_CLOUD + 8), ((NewCloud*)NC_CLOUD)->cloudHeight,
                        ((NewCloud*)NC_CLOUD)->scale, id);
    snowCloudBuildBoxVerts(&((NewCloud*)NC_CLOUD)->flakeMinX, ((NewCloud*)NC_CLOUD)->cloudHeight,
                           ((NewCloud*)NC_CLOUD)->scale);
    *(void**)(NC_CLOUD + 4) = mmAlloc(((NewCloud*)NC_CLOUD)->flakeCount * 0x18, 0x17, 0);
    if (*(void**)(NC_CLOUD + 4) == NULL)
    {
        ok = 0;
    }
    if (ok == 0)
    {
        debugPrintf(strs + 0x1f0);
        mm_free(gNewClouds[id]);
        gNewClouds[id] = NULL;
        return;
    }
    for (i = 0; i < ((NewCloud*)NC_CLOUD)->flakeCount; i++)
    {
        NC_PARTS[i].x =
            (int)
        randomGetRange((int)((NewCloud*)NC_CLOUD)->flakeMinX,
                       ((NewCloud*)NC_CLOUD)->flakeMaxX);
        NC_PARTS[i].y = ((NewCloud*)NC_CLOUD)->unk1388;
        NC_PARTS[i].z =
            (int)
        randomGetRange((int)((NewCloud*)NC_CLOUD)->flakeMinZ,
                       ((NewCloud*)NC_CLOUD)->flakeMaxZ);
        NC_PARTS[i].angle = randomGetRange(0, 0x3d0);
        NC_PARTS[i].quadIndex = randomGetRange(0, 0x13);
        if (((NewCloud*)NC_CLOUD)->cloudType == 0)
        {
            sizeRange = (int(*)[2])(strs + 0x58);
            NC_PARTS[i].size =
                (randomGetRange(sizeRange[params->unk5A][0], sizeRange[params->unk5A][1]) /
                    4);
            NC_PARTS[i].fallSpeed =
                (int)
            randomGetRange(0x4b, 0x64) / lbl_803DF1FC;
            NC_PARTS[i].texLayer =
                (i / (((NewCloud*)NC_CLOUD)->flakeCount / 4));
        }
        else
        {
            sizeRange = (int(*)[2])(strs + 0x58);
            NC_PARTS[i].size =
                (randomGetRange(sizeRange[params->unk5A][0], sizeRange[params->unk5A][1]) *
                    2);
            NC_PARTS[i].fallSpeed = lbl_803DF1A4;
            NC_PARTS[i].texLayer = 0;
        }
        if (NC_PARTS[i].size < 1)
        {
            NC_PARTS[i].size = 1;
        }
        spinRange = (int(*)[2])(strs + 0x30);
        NC_PARTS[i].spin =
            (((int(*)[2])(strs + 0x30))[params->unk5B][1] / 2 -
                randomGetRange(spinRange[params->unk5B][0], spinRange[params->unk5B][1]));
    }
    if (gNewCloudWindSourcesInit != 0)
    {
        gNewCloudWindSources[0].x = 0x31e;
        gNewCloudWindSources[0].z = 0xa9c;
        gNewCloudWindSources[0].vx = lbl_803DF240;
        gNewCloudWindSources[0].vy = lbl_803DF1A0;
        gNewCloudWindSources[0].vz = lbl_803DF1A0;
        normalize(&gNewCloudWindSources[0].vx, &gNewCloudWindSources[0].vy, &gNewCloudWindSources[0].vz);
        gNewCloudWindSources[0].scale = lbl_803DF1A4;
        gNewCloudWindSources[0].flag = 0;
        gNewCloudWindSources[1].x = 0x3c5;
        gNewCloudWindSources[1].z = 0xb72;
        gNewCloudWindSources[1].vx = lbl_803DF1A0;
        gNewCloudWindSources[1].vy = lbl_803DF1A0;
        gNewCloudWindSources[1].vz = lbl_803DF240;
        normalize(&gNewCloudWindSources[1].vx, &gNewCloudWindSources[1].vy, &gNewCloudWindSources[1].vz);
        gNewCloudWindSources[1].scale = lbl_803DF1A4;
        gNewCloudWindSources[1].flag = 0;
        gNewCloudWindSources[2].x = 0x335;
        gNewCloudWindSources[2].z = 0xe13;
        gNewCloudWindSources[2].vx = lbl_803DF1FC;
        gNewCloudWindSources[2].vy = lbl_803DF1A0;
        gNewCloudWindSources[2].vz = lbl_803DF1A0;
        normalize(&gNewCloudWindSources[2].vx, &gNewCloudWindSources[2].vy, &gNewCloudWindSources[2].vz);
        gNewCloudWindSources[2].scale = lbl_803DF1A4;
        gNewCloudWindSources[2].flag = 0;
        gNewCloudWindSources[3].x = 0x254;
        gNewCloudWindSources[3].z = 0xc70;
        gNewCloudWindSources[3].vx = lbl_803DF1A0;
        gNewCloudWindSources[3].vy = lbl_803DF1A0;
        gNewCloudWindSources[3].vz = lbl_803DF1FC;
        normalize(&gNewCloudWindSources[3].vx, &gNewCloudWindSources[3].vy, &gNewCloudWindSources[3].vz);
        gNewCloudWindSources[3].scale = lbl_803DF1A4;
        gNewCloudWindSources[3].flag = 0;
        gNewCloudWindSources[4].x = 0x107;
        gNewCloudWindSources[4].z = 0xb4a;
        gNewCloudWindSources[4].vx = lbl_803DF1FC;
        gNewCloudWindSources[4].vy = lbl_803DF1A0;
        gNewCloudWindSources[4].vz = lbl_803DF1CC;
        normalize(&gNewCloudWindSources[4].vx, &gNewCloudWindSources[4].vy, &gNewCloudWindSources[4].vz);
        gNewCloudWindSources[4].scale = lbl_803DF1A4;
        gNewCloudWindSources[4].flag = 0;
        gNewCloudWindSources[5].x = 0x68;
        gNewCloudWindSources[5].z = 0xdf6;
        gNewCloudWindSources[5].vx = lbl_803DF1A0;
        gNewCloudWindSources[5].vy = lbl_803DF1A0;
        gNewCloudWindSources[5].vz = lbl_803DF240;
        normalize(&gNewCloudWindSources[5].vx, &gNewCloudWindSources[5].vy, &gNewCloudWindSources[5].vz);
        gNewCloudWindSources[5].scale = lbl_803DF1A4;
        gNewCloudWindSources[5].flag = 0;
        gNewCloudWindSources[0].x = 0x31e;
        gNewCloudWindSources[0].z = 0xa9c;
        gNewCloudWindSources[0].vx = lbl_803DF1A0;
        gNewCloudWindSources[0].vy = lbl_803DF1A0;
        gNewCloudWindSources[0].vz = lbl_803DF1A0;
        gNewCloudWindSources[0].scale = lbl_803DF1A0;
        gNewCloudWindSources[0].flag = 0;
        gNewCloudWindSources[1].x = 0x3c5;
        gNewCloudWindSources[1].z = 0xb72;
        gNewCloudWindSources[1].vx = lbl_803DF1A0;
        gNewCloudWindSources[1].vy = lbl_803DF1A0;
        gNewCloudWindSources[1].vz = lbl_803DF1A0;
        gNewCloudWindSources[1].scale = lbl_803DF1A0;
        gNewCloudWindSources[1].flag = 0;
        gNewCloudWindSources[2].x = 0x335;
        gNewCloudWindSources[2].z = 0xe13;
        gNewCloudWindSources[2].vx = lbl_803DF1A0;
        gNewCloudWindSources[2].vy = lbl_803DF1A0;
        gNewCloudWindSources[2].vz = lbl_803DF1A0;
        gNewCloudWindSources[2].scale = lbl_803DF1A0;
        gNewCloudWindSources[2].flag = 0;
        gNewCloudWindSources[3].x = 0x254;
        gNewCloudWindSources[3].z = 0xc70;
        gNewCloudWindSources[3].vx = lbl_803DF1A0;
        gNewCloudWindSources[3].vy = lbl_803DF1A0;
        gNewCloudWindSources[3].vz = lbl_803DF1A0;
        gNewCloudWindSources[3].scale = lbl_803DF1A0;
        gNewCloudWindSources[3].flag = 0;
        gNewCloudWindSources[4].x = 0x107;
        gNewCloudWindSources[4].z = 0xb4a;
        gNewCloudWindSources[4].vx = lbl_803DF1A0;
        gNewCloudWindSources[4].vy = lbl_803DF1A0;
        gNewCloudWindSources[4].vz = lbl_803DF1A0;
        gNewCloudWindSources[4].scale = lbl_803DF1A0;
        gNewCloudWindSources[4].flag = 0;
        gNewCloudWindSources[5].x = 0;
        gNewCloudWindSources[5].z = 0x7d0;
        gNewCloudWindSources[5].vx = lbl_803DF1A0;
        gNewCloudWindSources[5].vy = lbl_803DF1A0;
        gNewCloudWindSources[5].vz = lbl_803DF244;
        normalize(&gNewCloudWindSources[5].vx, &gNewCloudWindSources[5].vy, &gNewCloudWindSources[5].vz);
        gNewCloudWindSources[5].scale = lbl_803DF1FC;
        gNewCloudWindSources[5].flag = 0;
        gNewCloudWindSourcesInit = 0;
    }
}

extern int gNewCloudMusicIdByType[];
extern const f32 lbl_803DF27C;

#undef NC_CLOUD
#define NC_CLOUD ((u8 *)gNewClouds[*(u16 *)(params + 0x26)])

/*
 * `params` kept as raw u8* here (not CloudSpawnParams*): the NC_CLOUD macro
 * and env slot writes index it as `params + 0x26` / `params + 0x26 * 0xc`
 * byte arithmetic; retyping shifts the index/CSE codegen. `env` is the
 * cross-TU saveGameGetEnvState() blob (would need a shared header).
 */
void newclouds_update(u8* objA, u8* objB, u8* params)
{
    u8* env;
    NewCloud* cloud;
    u8 fl;
    struct
    {
        s16 f8;
        s16 fa;
        s16 fc;
        s16 pad_e;
        f32 f10;
        f32 f14;
        f32 f18;
        f32 f1c;
    } args;
    f32 posA[3] = {0.0f, 0.0f, 0.0f};
    f32 posB[3] = {0.0f, 0.0f, 0.0f};
    f32 vec[3];

    env = saveGameGetEnvState();
    if (params == NULL)
    {
        return;
    }
    if (objA != NULL)
    {
        posA[0] = ((GameObject*)objA)->anim.worldPosX;
        posA[1] = ((GameObject*)objA)->anim.worldPosY;
        posA[2] = ((GameObject*)objA)->anim.worldPosZ;
    }
    if (objB != NULL)
    {
        posB[0] = ((GameObject*)objB)->anim.worldPosX;
        posB[1] = ((GameObject*)objB)->anim.worldPosY;
        posB[2] = ((GameObject*)objB)->anim.worldPosZ;
    }
    if ((u32)*(u16*)(params + 0x26) > 8)
    {
        return;
    }
    cloud = (NewCloud*)NC_CLOUD;
    if (cloud == NULL)
    {
        fl = params[0x58];
        if (!(fl & 4) && !(fl & 8) && !(fl & 0x20))
        {
            if ((fl & 2) && (fl & 0x10) && params[0x5d] != 0)
            {
                newClouds((CloudSpawnParams*)params, objB, posA[0], posA[1], posA[2]);
            }
            else if ((fl & 2) && (fl & 0x10))
            {
                newClouds((CloudSpawnParams*)params, objB, posB[0], posB[1], posB[2]);
            }
            else if (fl & 2)
            {
                newClouds((CloudSpawnParams*)params, objB, posA[0], posA[1], posA[2]);
            }
        }
        if (params[0x58] & 2)
        {
            if (params[0x5c] == 0 || params[0x5c] == 4)
            {
                switch (*(u16*)(params + 0x26))
                {
                case 0:
                    *(s16*)(env + 0xe) = (s16) * (u16*)(params + 0x24) - 1;
                    *(int*)(env + 0x14) = posA[0];
                    *(int*)(env + 0x18) = posA[1];
                    *(int*)(env + 0x1c) = posA[2];
                    if ((s8)env[*(u16*)(params + 0x26) + 0x41] == -1)
                    {
                        return;
                    }
                    ((NewCloud*)NC_CLOUD)->stationary = 1 - env[*(u16*)(params + 0x26) + 0x41];
                    if ((s8)env[*(u16*)(params + 0x26) + 0x41] != 0)
                    {
                        return;
                    }
                    {
                        u8* p14 = env + 0x14;
                        u8* p18 = env + 0x18;
                        u8* p1c = env + 0x1c;
                        ((NewCloud*)NC_CLOUD)->worldPosX =
                            (f32) * (int*)(p14 + *(u16*)(params + 0x26) * 0xc);
                        ((NewCloud*)NC_CLOUD)->worldPosY =
                            (f32) * (int*)(p18 + *(u16*)(params + 0x26) * 0xc);
                        ((NewCloud*)NC_CLOUD)->worldPosZ =
                            (f32) * (int*)(p1c + *(u16*)(params + 0x26) * 0xc);
                    }
                    break;
                case 1:
                    *(s16*)(env + 0x10) = (s16) * (u16*)(params + 0x24) - 1;
                    *(int*)(env + 0x20) = posA[0];
                    *(int*)(env + 0x24) = posA[1];
                    *(int*)(env + 0x28) = posA[2];
                    if ((s8)env[*(u16*)(params + 0x26) + 0x41] == -1)
                    {
                        return;
                    }
                    ((NewCloud*)NC_CLOUD)->stationary = 1 - env[*(u16*)(params + 0x26) + 0x41];
                    if ((s8)env[*(u16*)(params + 0x26) + 0x41] != 0)
                    {
                        return;
                    }
                    {
                        u8* p14 = env + 0x14;
                        u8* p18 = env + 0x18;
                        u8* p1c = env + 0x1c;
                        ((NewCloud*)NC_CLOUD)->worldPosX =
                            (f32) * (int*)(p14 + *(u16*)(params + 0x26) * 0xc);
                        ((NewCloud*)NC_CLOUD)->worldPosY =
                            (f32) * (int*)(p18 + *(u16*)(params + 0x26) * 0xc);
                        ((NewCloud*)NC_CLOUD)->worldPosZ =
                            (f32) * (int*)(p1c + *(u16*)(params + 0x26) * 0xc);
                    }
                    break;
                case 2:
                    *(s16*)(env + 0x12) = (s16) * (u16*)(params + 0x24) - 1;
                    *(int*)(env + 0x2c) = posA[0];
                    *(int*)(env + 0x30) = posA[1];
                    *(int*)(env + 0x34) = posA[2];
                    if ((s8)env[*(u16*)(params + 0x26) + 0x41] == -1)
                    {
                        return;
                    }
                    ((NewCloud*)NC_CLOUD)->stationary = 1 - env[*(u16*)(params + 0x26) + 0x41];
                    if ((s8)env[*(u16*)(params + 0x26) + 0x41] != 0)
                    {
                        return;
                    }
                    {
                        u8* p14 = env + 0x14;
                        u8* p18 = env + 0x18;
                        u8* p1c = env + 0x1c;
                        ((NewCloud*)NC_CLOUD)->worldPosX =
                            (f32) * (int*)(p14 + *(u16*)(params + 0x26) * 0xc);
                        ((NewCloud*)NC_CLOUD)->worldPosY =
                            (f32) * (int*)(p18 + *(u16*)(params + 0x26) * 0xc);
                        ((NewCloud*)NC_CLOUD)->worldPosZ =
                            (f32) * (int*)(p1c + *(u16*)(params + 0x26) * 0xc);
                    }
                    break;
                }
            }
        }
        return;
    }
    if (cloud == NULL)
    {
        return;
    }
    fl = params[0x58];
    if (fl & 2)
    {
        return;
    }
    if ((fl & 8) && cloud->unk144E != 0)
    {
        ((s8*)(env + 0x41))[*(u16*)(params + 0x26)] = cloud->stationary;
        ((NewCloud*)NC_CLOUD)->stationary = 1 - ((NewCloud*)NC_CLOUD)->stationary;
        if (((NewCloud*)NC_CLOUD)->stationary == 1)
        {
            vec[0] = lbl_803DF1A0;
            vec[1] = lbl_803DF1A0;
            vec[2] = lbl_803DF1A0;
            args.f14 = lbl_803DF1A0;
            args.f18 = lbl_803DF1A0;
            args.f1c = lbl_803DF1A0;
            args.f10 = lbl_803DF1A4;
            args.fc = 0;
            args.fa = 0;
            args.f8 = *(s16*)objA;
            vecRotateZXY(&args.f8, vec);
            ((NewCloud*)NC_CLOUD)->worldPosX = vec[0] + ((GameObject*)objA)->anim.worldPosX;
            ((NewCloud*)NC_CLOUD)->worldPosY = vec[1] + ((GameObject*)objA)->anim.worldPosY;
            ((NewCloud*)NC_CLOUD)->worldPosZ = vec[2] + ((GameObject*)objA)->anim.worldPosZ;
            if (((NewCloud*)NC_CLOUD)->driftScale > lbl_803DF27C)
            {
                Music_Trigger(gNewCloudMusicIdByType[((NewCloud*)NC_CLOUD)->cloudType], 0);
            }
        }
        else
        {
            if (((NewCloud*)NC_CLOUD)->driftScale > lbl_803DF27C)
            {
                Music_Trigger(gNewCloudMusicIdByType[((NewCloud*)NC_CLOUD)->cloudType], 1);
            }
        }
        if ((s8)env[*(u16*)(params + 0x26) + 0x41] == 0)
        {
            u8* p14 = env + 0x14;
            u8* p18 = env + 0x18;
            u8* p1c = env + 0x1c;
            *(int*)(p14 + *(u16*)(params + 0x26) * 0xc) = posA[0];
            *(int*)(p18 + *(u16*)(params + 0x26) * 0xc) = posA[1];
            *(int*)(p1c + *(u16*)(params + 0x26) * 0xc) = posA[2];
        }
    }
    else if (fl & 0x20)
    {
        newclouds_snowKillSnowCloud(*(u16*)(params + 0x26), 0);
    }
    else if (fl & 4)
    {
        if (cloud->finished != 0)
        {
            cloud->finished = 0;
        }
        ((NewCloud*)NC_CLOUD)->despawning = 1 - ((NewCloud*)NC_CLOUD)->despawning;
        if (*(u16*)(params + 0x2a) != 0)
        {
            ((NewCloud*)NC_CLOUD)->flakeFillRate =
                (f32)((NewCloud*)NC_CLOUD)->flakeCount / (f32) * (u16*)(params + 0x2a);
        }
        else
        {
            ((NewCloud*)NC_CLOUD)->flakeFillRate = (((NewCloud*)NC_CLOUD)->flakeCount - 1);
        }
        if (*(u16*)(params + 0x2c) != 0)
        {
            ((NewCloud*)NC_CLOUD)->flakeDrainRate =
                -((f32)((NewCloud*)NC_CLOUD)->flakeCount / (f32) * (u16*)(params + 0x2c));
        }
        else
        {
            ((NewCloud*)NC_CLOUD)->flakeDrainRate = (-(((NewCloud*)NC_CLOUD)->flakeCount - 1));
        }
    }
}

extern void PSMTXIdentity(f32 * m);
extern void PSMTXMultVec(f32 * matrix, f32 * in, f32 * out);
extern const f32 lbl_803DF200;
extern const f32 lbl_803DF208;
extern const f32 lbl_803DF20C;
extern const f32 lbl_803DF210;
extern const f32 gNewCloudNearestInit;
extern const f32 gNewCloudCameraYOffset;
extern const f32 lbl_803DF250;
extern const f32 lbl_803DF254;
extern const f32 gNewCloudScrollWrap;
extern const f32 lbl_803DF25C;
extern const f32 lbl_803DF260;
extern const f32 gNewCloudScrollWrapNeg;
extern const f32 gNewCloudFlashRotScale;
extern const f32 lbl_803DF26C;
extern const f32 lbl_803DF270;
extern const f32 lbl_803DF274;
extern const f32 lbl_803DF278;

#define D7_CLOUD (*pp)

#pragma opt_propagation off
void dll_07_func06(void)
{
    s16* cam;
    void** clouds;
    u8** pp;
    int i;
    u8* nearestCloud;
    u8 activeCount;
    int off;
    u8* p;
    f32* m;
    f32 wrap;
    f32 mag;
    f32 t;
    f32 rot;
    f32 nearest;
    f32 inpos[3];
    f32 wind[3];
    f32 pos[3];
    f32 vec[3];
    f32 d[3];
    struct
    {
        s16 f8;
        s16 fa;
        s16 fc;
        s16 pad_e;
        f32 f10;
        f32 f14;
        f32 f18;
        f32 f1c;
    } args;
    f32 mtx[12];

    clouds = gNewCloudLayerTextures;
    i = 0;
    off = 0;
    cam = Camera_GetCurrentViewSlot();
    activeCount = 0;
    nearestCloud = NULL;
    nearest = gNewCloudNearestInit;
    if (gNewCloudInitialized == 0)
    {
        lbl_803DD1C8 = textureLoadAsset(0x16a);
        clouds[0] = textureLoadAsset(0x5da);
        clouds[1] = textureLoadAsset(0x63f);
        clouds[2] = textureLoadAsset(0x640);
        clouds[3] = textureLoadAsset(0x641);
        lbl_803DD1C4 = textureLoadAsset(0x151);
        gNewCloudInitialized = 1;
    }
    if (renderModeSetOrGet(-1) == 1)
    {
        return;
    }
    gNewCloudBlizzardActivePrev = gNewCloudBlizzardActive;
    gNewCloudBlizzardActive = 0;
    while (i < 8)
    {
        pp = (u8**)((u8*)clouds + off);
        pp += 4;
        p = *pp;
        if (p != NULL &&
            (*(u8**)p == NULL || (*(u16*)(*(u8**)p + 0xb0) & 0x40)))
        {
            snowFreeSnowCloud(((NewCloud*)p)->cloudId);
            i++;
            off += 4;
            continue;
        }
        if (p != NULL && ((NewCloud*)p)->active != 0)
        {
            snowCloudInitFlakes((f32*)(p + 8), ((NewCloud*)p)->cloudHeight,
                                ((NewCloud*)p)->scale, i);
        }
        else if (p != NULL && ((NewCloud*)p)->finished == 0)
        {
            if (((NewCloud*)p)->cloudType == 4)
            {
                gNewCloudBlizzardActive = 1;
            }
            if (((NewCloud*)p)->despawning != 0)
            {
                ((NewCloud*)p)->activeFlakes =
                    framesThisStep * ((NewCloud*)p)->flakeDrainRate + ((NewCloud*)p)->activeFlakes;
                if (((NewCloud*)D7_CLOUD)->activeFlakes <= lbl_803DF1A0)
                {
                    ((NewCloud*)D7_CLOUD)->finished = 1;
                }
            }
            else
            {
                if ((int)((NewCloud*)p)->activeFlakes < ((NewCloud*)p)->flakeCount)
                {
                    ((NewCloud*)p)->activeFlakes = framesThisStep * ((NewCloud*)p)->flakeFillRate +
                        ((NewCloud*)p)->activeFlakes;
                }
            }
            if ((int)((NewCloud*)D7_CLOUD)->activeFlakes > ((NewCloud*)D7_CLOUD)->flakeCount)
            {
                ((NewCloud*)D7_CLOUD)->activeFlakes = ((NewCloud*)D7_CLOUD)->flakeCount;
            }
            if (((NewCloud*)D7_CLOUD)->activeFlakes < *(f32*)&lbl_803DF1A0)
            {
                ((NewCloud*)D7_CLOUD)->activeFlakes = lbl_803DF1A0;
            }
            if (*(u8**)D7_CLOUD != NULL)
            {
                Obj_GetWorldPosition((u32)*(u8 **)D7_CLOUD, &pos[0], &pos[1], &pos[2]);
            }
            if (((NewCloud*)D7_CLOUD)->followCamera != 0 && cam != NULL)
            {
                if (((NewCloud*)D7_CLOUD)->cloudType == 4)
                {
                    vec[0] = lbl_803DF1A0;
                    vec[1] = lbl_803DF1A0;
                    vec[2] = lbl_803DF1FC;
                    args.f14 = lbl_803DF1A0;
                    args.f18 = lbl_803DF1A0;
                    args.f1c = lbl_803DF1A0;
                    args.f10 = lbl_803DF1A4;
                    args.fc = 0;
                    args.fa = 0;
                    args.f8 = 0xffff - *cam;
                    vecRotateZXY(&args.f8, vec);
                    pos[0] = *(f32*)((u8*)cam + 0x44) + vec[0];
                    t = *(f32*)((u8*)cam + 0x48) - gNewCloudCameraYOffset;
                    pos[1] = t + vec[1];
                    pos[2] = *(f32*)((u8*)cam + 0x4c) + vec[2];
                }
                else
                {
                    pos[0] = *(f32*)((u8*)cam + 0x44);
                    pos[1] = *(f32*)((u8*)cam + 0x48) - gNewCloudCameraYOffset;
                    pos[2] = *(f32*)((u8*)cam + 0x4c);
                }
            }
            ((NewCloud*)D7_CLOUD)->driftOffset = framesThisStep * ((NewCloud*)D7_CLOUD)->driftRate +
                ((NewCloud*)D7_CLOUD)->driftOffset;
            if (lbl_803DF1A0 != ((NewCloud*)D7_CLOUD)->driftScale)
            {
                if (((NewCloud*)D7_CLOUD)->driftOffset > ((NewCloud*)D7_CLOUD)->driftLimit)
                {
                    ((NewCloud*)D7_CLOUD)->driftRate =
                        ((NewCloud*)D7_CLOUD)->driftRate * lbl_803DF244;
                    ((NewCloud*)D7_CLOUD)->driftOffset = ((NewCloud*)D7_CLOUD)->driftLimit;
                }
                else if (((NewCloud*)D7_CLOUD)->driftOffset < lbl_803DF1A0)
                {
                    ((NewCloud*)D7_CLOUD)->driftRate =
                        ((NewCloud*)D7_CLOUD)->driftRate * lbl_803DF244;
                    ((NewCloud*)D7_CLOUD)->driftLimit = (int)
                    randomGetRange(
                        1, (lbl_803DF1C8 * ((NewCloud*)D7_CLOUD)->driftScale));
                    ((NewCloud*)D7_CLOUD)->driftOffset = lbl_803DF1A0;
                }
            }
            if (((NewCloud*)D7_CLOUD)->stationary == 0)
            {
                inpos[0] = pos[0];
                inpos[1] = pos[1];
                inpos[2] = pos[2];
                snowCloudComputeDrift(wind, inpos, ((NewCloud*)D7_CLOUD)->driftScale);
                if (((NewCloud*)D7_CLOUD)->cloudType == 0)
                {
                    ((NewCloud*)D7_CLOUD)->windVelX = -wind[0];
                    ((NewCloud*)D7_CLOUD)->windVelZ = -wind[2];
                }
                else
                {
                    ((NewCloud*)D7_CLOUD)->windVelX =
                        -(wind[0] + ((NewCloud*)D7_CLOUD)->driftOffset);
                    ((NewCloud*)D7_CLOUD)->windVelZ =
                        -(wind[2] + ((NewCloud*)D7_CLOUD)->driftOffset);
                    ((NewCloud*)D7_CLOUD)->unk1428 = lbl_803DF1A0;
                }
                ((NewCloud*)D7_CLOUD)->worldPosX = pos[0];
                ((NewCloud*)D7_CLOUD)->worldPosY = pos[1];
                ((NewCloud*)D7_CLOUD)->worldPosZ = pos[2];
            }
            else
            {
                inpos[0] = ((NewCloud*)D7_CLOUD)->worldPosX;
                inpos[1] = ((NewCloud*)D7_CLOUD)->worldPosY;
                inpos[2] = ((NewCloud*)D7_CLOUD)->worldPosZ;
                snowCloudComputeDrift(wind, inpos, ((NewCloud*)D7_CLOUD)->driftScale);
                ((NewCloud*)D7_CLOUD)->windVelX = -wind[0] + ((NewCloud*)D7_CLOUD)->driftOffset;
                ((NewCloud*)D7_CLOUD)->windVelZ = -wind[2] + ((NewCloud*)D7_CLOUD)->driftOffset;
                ((NewCloud*)D7_CLOUD)->unk1428 = lbl_803DF1A0;
            }
            if (((NewCloud*)D7_CLOUD)->posInitialized != 0)
            {
                ((NewCloud*)D7_CLOUD)->curPosX = ((NewCloud*)D7_CLOUD)->lastPosX;
                ((NewCloud*)D7_CLOUD)->curPosY = ((NewCloud*)D7_CLOUD)->lastPosY;
                ((NewCloud*)D7_CLOUD)->curPosZ = ((NewCloud*)D7_CLOUD)->lastPosZ;
            }
            else
            {
                ((NewCloud*)D7_CLOUD)->curPosX = pos[0];
                ((NewCloud*)D7_CLOUD)->curPosY = pos[1];
                ((NewCloud*)D7_CLOUD)->curPosZ = pos[2];
                ((NewCloud*)D7_CLOUD)->posInitialized = 1;
            }
            ((NewCloud*)D7_CLOUD)->lastPosX = pos[0];
            ((NewCloud*)D7_CLOUD)->lastPosY = pos[1];
            ((NewCloud*)D7_CLOUD)->lastPosZ = pos[2];
            snowReposSnowCloud(((NewCloud*)D7_CLOUD)->cloudId);
            if (((NewCloud*)D7_CLOUD)->activeFlakes > lbl_803DF1A0)
            {
                d[0] = ((NewCloud*)D7_CLOUD)->worldPosX - *(f32*)((u8*)cam + 0xc);
                d[1] = ((NewCloud*)D7_CLOUD)->worldPosY - *(f32*)((u8*)cam + 0x10);
                d[2] = ((NewCloud*)D7_CLOUD)->worldPosZ - *(f32*)((u8*)cam + 0x14);
                mag = PSVECMag(d);
                if (mag < nearest)
                {
                    nearest = mag;
                    nearestCloud = D7_CLOUD;
                }
            }
        }
        if (D7_CLOUD != NULL && ((NewCloud*)D7_CLOUD)->cloudType == 4 &&
            ((NewCloud*)D7_CLOUD)->stationary == 0)
        {
            activeCount++;
        }
        i++;
        off += 4;
    }
    if (activeCount != 0)
    {
        gNewCloudOvercastFadeRate = lbl_803DF1BC;
    }
    else
    {
        gNewCloudOvercastFadeRate = lbl_803DF250;
    }
    if (lbl_803DD19C != NULL)
    {
        ((LightningEffect*)lbl_803DD19C)->timer += 1;
        if (((LightningEffect*)lbl_803DD19C)->timer >= ((LightningEffect*)lbl_803DD19C)->lifetime)
        {
            mm_free(lbl_803DD19C);
            lbl_803DD19C = NULL;
        }
    }
    gNewCloudScrollPhaseA += lbl_803DF254 * timeDelta;
    wrap = *(f32*)&gNewCloudScrollWrap;
    if (gNewCloudScrollPhaseA > wrap)
    {
        gNewCloudScrollPhaseA -= wrap;
    }
    gNewCloudScrollPhaseB += lbl_803DF25C * timeDelta;
    wrap = *(f32*)&gNewCloudScrollWrap;
    if (gNewCloudScrollPhaseB > wrap)
    {
        gNewCloudScrollPhaseB -= wrap;
    }
    t = gNewCloudScrollPhaseC - lbl_803DF260 * timeDelta;
    gNewCloudScrollPhaseC = t;
    if (t < gNewCloudScrollWrapNeg)
    {
        gNewCloudScrollPhaseC = t + *(f32*)&gNewCloudScrollWrap;
    }
    t = gNewCloudOvercastFadeLevel + gNewCloudOvercastFadeRate;
    gNewCloudOvercastFadeLevel = t;
    if (t > lbl_803DF1A4)
    {
        gNewCloudOvercastFadeLevel = lbl_803DF1A4;
    }
    else if (t < lbl_803DF1A0)
    {
        gNewCloudOvercastFadeLevel = lbl_803DF1A0;
    }
    gNewCloudSnowFlashAlpha = 0;
    if (nearestCloud != NULL && ((NewCloud*)nearestCloud)->cloudType == 4)
    {
        gNewCloudSnowFlashAlpha = lbl_803DF1D4 * gNewCloudOvercastFadeLevel;
        if (gNewCloudSnowFlashAlpha != 0)
        {
            rot = lbl_803DF1C4 *
                (lbl_803DF1C8 *
                    -(lbl_803DF20C * (((NewCloud*)nearestCloud)->driftOffset / lbl_803DF210) +
                        lbl_803DF208)) /
                gNewCloudFlashRotScale;
            ((f32*)clouds)[54] = lbl_803DF1A0;
            ((f32*)clouds)[55] = lbl_803DF244;
            ((f32*)clouds)[56] = lbl_803DF1A0;
            m = Camera_GetViewRotationMatrix();
            if (((NewCloud*)nearestCloud)->cloudType == 0)
            {
                lbl_803DD190 = lbl_803DF200 * (lbl_803DF26C * timeDelta) + lbl_803DD190;
                lbl_803DB764 = lbl_803DF270;
                lbl_803DD199 = 0xf9;
                lbl_803DD19A = 0xfd;
                lbl_803DB768 = lbl_803DF274;
                PSMTXIdentity(mtx);
            }
            else
            {
                lbl_803DD190 = lbl_803DF26C * timeDelta + lbl_803DD190;
                lbl_803DB764 = lbl_803DF1A4;
                lbl_803DD199 = 0xf8;
                lbl_803DD19A = 0xfc;
                lbl_803DB768 = lbl_803DF1A4;
                PSMTXRotRad(mtx, 0x7a, rot);
            }
            PSMTXConcat((void*)m, (void*)mtx, (void*)mtx);
            PSMTXMultVec(mtx, (f32*)((u32)clouds + 0xd8),
                         (f32*)((u32)clouds + 0xd8));
            if (lbl_803DD190 < lbl_803DF278)
            {
                lbl_803DD190 = lbl_803DD190 + gSnowFlakeSizeLarge;
            }
        }
    }
    if (gNewCloudBlizzardActive != 0 && gNewCloudBlizzardActivePrev == 0)
    {
        Music_Trigger(MUSICTRIG_crun_dungeon, 1);
    }
    else if (gNewCloudBlizzardActive == 0 && gNewCloudBlizzardActivePrev != 0)
    {
        Music_Trigger(MUSICTRIG_crun_dungeon, 0);
    }
}
#pragma opt_propagation reset

extern char sSnowPrintSnowCloudInvalidCloudId[];
extern void initRotationMtx(f32* mtx, f32 xScale, f32 yScale, f32 zScale);
extern void mtx44_mult(f32* a, f32* b, f32* out);
extern void mtx44Transpose(f32* src, f32* dst);

extern int gNewCloudFlashRotAngle;
extern const f32 lbl_803DF204;

#pragma opt_loop_invariants off
#pragma opt_common_subs off
#pragma opt_dead_assignments off
int snowPrintSnowCloud(int arg, int cloudId)
{
    u8* p;
    SnowFlake* part;
    int i;
    int j;
    u8 hudHidden;
    int texIdx;
    int ct;
    u8 cr;
    u8 cg;
    u8 cb;
    f32 scale;
    f32 driftX;
    f32 driftZ;
    f32 stepX;
    f32 stepZ;
    f32 yb;
    f32 size;
    int base;
    f32 mtxB[16];
    f32 mtxT[12];
    f32 mtxA[16];
    f32 mtxOut[16];
    volatile f32 vx[3];
    volatile f32 vy[3];
    volatile f32 vz[3];
    volatile SnowFlakeUVs uvs;

    uvs = lbl_802C1FCC;
    scale = lbl_803DF1A4;
    if (renderModeSetOrGet(-1) == 1)
    {
        return 0;
    }
    for (i = 0; i < 8; i++)
    {
        p = gNewClouds[i];
        if (p != NULL && cloudId == ((NewCloud*)p)->cloudId)
        {
            break;
        }
    }
    p = gNewClouds[i];
    if (p == NULL || i == 8)
    {
        return 0;
    }
    if (cloudId != ((NewCloud*)p)->cloudId)
    {
        debugPrintf(sSnowPrintSnowCloudInvalidCloudId, cloudId);
        return 0;
    }
    gNewCloudFlashRotAngle = lbl_803DF1FC * timeDelta + gNewCloudFlashRotAngle;
    if (gNewCloudFlashRotAngle > 0xffff)
    {
        gNewCloudFlashRotAngle = 0;
    }
    scale = scale * lbl_803DF200;
    initRotationMtx(mtxA, scale, scale, scale);
    memset(mtxB, 0, 0x40);
    mtxB[0] = lbl_803DF1A4;
    mtxB[5] = lbl_803DF1A4;
    mtxB[10] = lbl_803DF1A4;
    mtxB[15] = lbl_803DF1A4;
    ct = ((NewCloud*)p)->cloudType;
    if (ct != 4 && ((NewCloud*)p)->spinEnabled != 0)
    {
        mtxB[0] = mathCosf((gNewCloudPi * gNewCloudFlashRotAngle) / lbl_803DF1F4);
        mtxB[1] = -mathSinf((gNewCloudPi * gNewCloudFlashRotAngle) / lbl_803DF1F4);
        mtxB[4] = mathSinf((gNewCloudPi * gNewCloudFlashRotAngle) / lbl_803DF1F4);
        mtxB[5] = mathCosf((gNewCloudPi * gNewCloudFlashRotAngle) / lbl_803DF1F4);
    }
    else if (ct == 4)
    {
        if (((NewCloud*)p)->flags144A & 0x80)
        {
            mtxB[0] = mathCosf(lbl_803DF204);
            mtxB[1] = -mathSinf(lbl_803DF204);
            mtxB[4] = mathSinf(lbl_803DF204);
            mtxB[5] = mathCosf(lbl_803DF204);
        }
        else if (((NewCloud*)p)->spinEnabled != 0)
        {
            gNewCloudFlashRotAngle =
                lbl_803DF20C * (((NewCloud*)p)->driftOffset / lbl_803DF210) + lbl_803DF208;
            mtxB[0] = mathCosf((gNewCloudPi *  - gNewCloudFlashRotAngle) / lbl_803DF1F4);
            mtxB[1] = -mathSinf((gNewCloudPi *  - gNewCloudFlashRotAngle) / lbl_803DF1F4);
            mtxB[4] = mathSinf((gNewCloudPi *  - gNewCloudFlashRotAngle) / lbl_803DF1F4);
            mtxB[5] = mathCosf((gNewCloudPi *  - gNewCloudFlashRotAngle) / lbl_803DF1F4);
        }
    }
    mtxB[12] = ((NewCloud*)p)->worldPosX - playerMapOffsetX;
    mtxB[13] = ((NewCloud*)p)->worldPosY;
    mtxB[14] = ((NewCloud*)p)->worldPosZ - playerMapOffsetZ;
    mtx44_mult(mtxA, mtxB, mtxOut);
    mtx44Transpose(mtxOut, mtxT);
    PSMTXConcat((void*)Camera_GetViewMatrix(), (void*)mtxT, (void*)mtxT);
    GXLoadPosMtxImm(mtxT, 0);
    texIdx = 0;
    selectTexture(((NewCloud*)p)->cloudType == 0 ? gNewCloudLayerTextures[0] : lbl_803DD1C4, 0);
    GXSetCullMode(GX_CULL_NONE);
    textureSetupFn_800799c0();
    textRenderSetupFn_800795e8();
    textRenderSetupFn_80079804();
    if (((NewCloud*)p)->cloudType == 4)
    {
        setTextColor(arg, 0x7d, 0x7d, 0x9b, 0xff);
    }
    else if (((NewCloud*)p)->cloudType == 0)
    {
        getAmbientColor(0, &cr, &cg, &cb);
        setTextColor(arg, cr, cg, cb, 0xff);
    }
    gxBlendFn_80078b4c();
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_PNMTXIDX, GX_DIRECT);
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_CLR0, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    GXSetCurrentMtx(0);
    GXClearVtxDesc();
    GXSetVtxDesc(GX_VA_POS, GX_DIRECT);
    GXSetVtxDesc(GX_VA_TEX0, GX_DIRECT);
    hudHidden = getHudHiddenFrameCount();
    driftX = gSnowFlakeSize * (((NewCloud*)p)->curPosX - ((NewCloud*)p)->lastPosX);
    stepX = (driftX < lbl_803DF214 * ((NewCloud*)p)->flakeMinX)
                ? lbl_803DF214 * ((NewCloud*)p)->flakeMinX
                : ((driftX > lbl_803DF214 * ((NewCloud*)p)->driftSpeed)
                       ? lbl_803DF214 * ((NewCloud*)p)->driftSpeed
                       : driftX);
    driftZ = gSnowFlakeSize * (((NewCloud*)p)->curPosZ - ((NewCloud*)p)->lastPosZ);
    stepZ = (driftZ < lbl_803DF214 * ((NewCloud*)p)->flakeMinZ)
                ? lbl_803DF214 * ((NewCloud*)p)->flakeMinZ
                : ((driftZ > lbl_803DF214 * ((NewCloud*)p)->flakeMaxZ)
                       ? lbl_803DF214 * ((NewCloud*)p)->flakeMaxZ
                       : driftZ);
    if (((NewCloud*)p)->cloudType == 4)
    {
        GXBegin(0x90, 4, (((NewCloud*)p)->flakeCount * 3));
    }
    else
    {
        GXBegin(0x90, 4, (((NewCloud*)p)->flakeCount * 3 / 4));
    }
    for (j = 0, part = *(SnowFlake**)(p + 4); j < ((NewCloud*)p)->flakeCount; j++)
    {
        if (part->texLayer != (u8)texIdx)
        {
            texIdx = part->texLayer;
            selectTexture(gNewCloudLayerTextures[texIdx], 0);
            GXBegin(0x90, 4, (((NewCloud*)p)->flakeCount * 3 / 4));
        }
        if (hudHidden == 0)
        {
            if (((NewCloud*)p)->stationary == 0)
            {
                part->x = part->x + stepX;
                part->z = part->z + stepZ;
            }
            part->x = ((NewCloud*)p)->windVelX * timeDelta + part->x;
            part->z = ((NewCloud*)p)->windVelZ * timeDelta + part->z;
            if (part->x < ((NewCloud*)p)->flakeMinX)
            {
                part->x = lbl_803DF1C8 * ((NewCloud*)p)->driftSpeed + part->x;
            }
            else if (part->x > ((NewCloud*)p)->driftSpeed)
            {
                part->x = part->x - lbl_803DF1C8 * ((NewCloud*)p)->driftSpeed;
            }
            if (part->z < ((NewCloud*)p)->flakeMinZ)
            {
                part->z =
                    lbl_803DF1C8 * ((NewCloud*)p)->flakeMaxZ + part->z;
            }
            else if (part->z > ((NewCloud*)p)->flakeMaxZ)
            {
                part->z =
                    part->z - lbl_803DF1C8 * ((NewCloud*)p)->flakeMaxZ;
            }
        }
        yb = part->y - *(f32*)(p + part->angle * 4 + 8);
        base = part->quadIndex * 0x2c;
        size = part->fallSpeed;
        vx[0] = *(f32*)(p + base + 0x1008) * size + part->x;
        vy[0] = *(f32*)(p + base + 0x1014) * size + yb;
        vz[0] = *(f32*)(p + base + 0x1020) * size + part->z;
        vx[1] = *(f32*)(p + base + 0x100c) * size + part->x;
        vy[1] = *(f32*)(p + base + 0x1018) * size + yb;
        vz[1] = *(f32*)(p + base + 0x1024) * size + part->z;
        vx[2] = *(f32*)(p + base + 0x1010) * size + part->x;
        vy[2] = *(f32*)(p + base + 0x101c) * size + yb;
        vz[2] = *(f32*)(p + base + 0x1028) * size + part->z;
        GXWGFifo.f32 = vx[0];
        GXWGFifo.f32 = vy[0];
        GXWGFifo.f32 = vz[0];
        GXWGFifo.s16 = uvs.uv[0];
        GXWGFifo.s16 = uvs.uv[1];
        GXWGFifo.f32 = vx[1];
        GXWGFifo.f32 = vy[1];
        GXWGFifo.f32 = vz[1];
        GXWGFifo.s16 = uvs.uv[2];
        GXWGFifo.s16 = uvs.uv[3];
        GXWGFifo.f32 = vx[2];
        GXWGFifo.f32 = vy[2];
        GXWGFifo.f32 = vz[2];
        GXWGFifo.s16 = uvs.uv[4];
        GXWGFifo.s16 = uvs.uv[5];
        part += 1;
    }
    return 0;
}
#pragma opt_dead_assignments reset
#pragma opt_common_subs reset
#pragma opt_loop_invariants reset

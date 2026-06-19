#include "main/newclouds_state.h"
#include "main/audio/sfx.h"
#include "main/cloud_action_runtime.h"
#include "main/cloud_layer_state.h"
#include "main/object_transform.h"
#include "main/objtexture.h"
#include "main/sky_interface.h"

typedef struct LightningEffect
{
    f32 start[3];
    f32 end[3];
    f32 radiusX;
    f32 radiusY;
    u16 timer;
    u16 lifetime;
    u16 seed;
    u8 unk26;
    u8 unk27;
} LightningEffect;

extern void* mmAlloc(int size, int heap, int flags);
extern void mm_free(void* ptr);
extern void* Obj_GetActiveModel(void* obj);
extern void PSMTXConcat(f32 a[3][4], f32 b[3][4], f32 out[3][4]);
extern void lightningRender(void* state);
extern s16* Camera_GetCurrentViewSlot(void);
extern int randomGetRange(int min, int max);

extern u8 framesThisStep;
extern f32 timeDelta;
extern f32 lbl_803DF1A0;
extern const f32 lbl_803DF1D8;
extern const f32 lbl_803DF1DC;
extern u8 lbl_803DD19B;
extern u8* lbl_803DD19C;
extern u8 lbl_803DD1C0;
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
    return lbl_803DD19B;
}

void newclouds_initialise(void)
{
    lbl_803DD1C0 = 0;
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

extern void* textureLoadAsset(int);

extern void textureFree(void* handle);
extern void ModelLightStruct_free(void* p);
extern void Music_Trigger(int id, int restart);
extern void* lbl_8039A818[];
extern void* lbl_8039A828[];
extern void* lbl_803DD1C8;
extern void* lbl_803DD1C4;
extern void* lbl_803DD1A0;
extern const f32 lbl_803DF1A4;
extern f32 lbl_803DB760;
extern f32 lbl_803DB764;
extern f32 lbl_803DB768;
extern f32 lbl_803DD1BC;
extern f32 lbl_803DD1B8;
extern f32 lbl_803DD1B4;
extern f32 lbl_803DD190;
extern f32 lbl_803DD194;
extern u8 lbl_803DD198;
extern u8 lbl_803DD199;
extern u8 lbl_803DD19A;
extern u8 lbl_803DD1CC;
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
        if (lbl_8039A818[i] != NULL)
        {
            textureFree(lbl_8039A818[i]);
            lbl_8039A818[i] = NULL;
        }
    }
    if (lbl_803DD1C4 != NULL)
    {
        textureFree(lbl_803DD1C4);
        lbl_803DD1C4 = NULL;
    }
    if (lbl_803DD1A0 != NULL)
    {
        ModelLightStruct_free(lbl_803DD1A0);
    }
    lbl_803DD1C0 = 0;
}

void newclouds_onMapSetup(void)
{
    int i;
    f32 a;
    f32 b;

    for (i = 0; i < 8; i++)
    {
        if (lbl_8039A828[i] != NULL)
        {
            snowFreeSnowCloud(i);
        }
        lbl_8039A828[i] = NULL;
    }
    a = lbl_803DF1A0;
    lbl_803DD1BC = a;
    lbl_803DD1B8 = a;
    lbl_803DD1B4 = a;
    lbl_803DD190 = a;
    b = lbl_803DF1A4;
    lbl_803DB760 = b;
    lbl_803DD194 = a;
    lbl_803DD198 = 0;
    lbl_803DB764 = b;
    lbl_803DD199 = 0;
    lbl_803DD19A = 0;
    lbl_803DB768 = b;
    lbl_803DD1CC = 0;
    Music_Trigger(235, 0);
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
    p->unk26 = f;
    p->timer = 0;
    p->seed = 0xFFFF;
    p->unk27 = g;
    return p;
}

extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);

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
extern f32 lbl_8039A8F0[];
extern int lbl_803DF198;

#pragma dont_inline off
void dll_07_func07(int arg)
{
    int i;
    int total;
    u8* snow;

    GXSetFog(0, lbl_803DF1A0, lbl_803DF1A0, lbl_803DF1A0, lbl_803DF1A0,
             *(FogColor*)&lbl_803DF198);
    for (i = 0, total = 0; i < 8; i++)
    {
        snow = (u8*)lbl_8039A828[i];
        if (snow != NULL && snow[0x144F] == 0)
        {
            total += snowPrintSnowCloud(arg, *(int*)(snow + 0x13F0));
        }
    }
    if (lbl_803DD198 != 0)
    {
        drawFn_80079e64(lbl_803DD190, lbl_803DD198, lbl_8039A8F0, lbl_803DB764,
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
        p = lbl_8039A828[i];
        if (p != NULL && cloudId == *(int*)((char*)p + 0x13f0))
        {
            break;
        }
    }
    p = lbl_8039A828[i];
    if (p == NULL)
    {
        return;
    }
    if (i == 8)
    {
        return;
    }
    if (cloudId != *(int*)((char*)p + 0x13f0))
    {
        debugPrintf(sSnowKillSnowCloudInvalidCloudId, cloudId);
        return;
    }
    *(int*)((char*)p + 0x13f8) = 1;
    p = lbl_8039A828[i];
    *(f32*)((char*)p + 0x1430) =
        -((f32)flag / (f32) * (int*)((char*)p + 0x13fc));
}

extern int ObjModel_GetRenderOp(int model, int x);
extern int Shader_getLayer(int renderOp, int x);
extern void* textureIdxToPtr(int idx);
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
            *out1 = scale * (f32)tex->offsetS;
            *out2 = scale * (f32)tex->offsetT;
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

extern u8* saveGameGetEnvState(void);
extern int getSaveGameLoadStatus(void);

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
        *(s16*)(env + cloudId * 2 + 0xe) = -1;
        ((s8*)env)[cloudId + 0x41] = -1;
    }
    for (i = 0; i < 8; i++)
    {
        p = lbl_8039A828[i];
        if (p != NULL && cloudId == ((NewCloud*)p)->cloudId)
        {
            break;
        }
    }
    p = lbl_8039A828[i];
    if (p == NULL)
    {
        return;
    }
    if (i == 8)
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
        *(u8**)((u8*)lbl_8039A828[i] + 4) = NULL;
    }
    if (lbl_8039A828[i] != NULL)
    {
        mm_free(lbl_8039A828[i]);
        lbl_8039A828[i] = NULL;
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

extern WindSource lbl_8039A848[];
extern s16 renderModeSetOrGet(int mode);
extern void normalize(f32 * x, f32 * y, f32 * z);

#pragma dont_inline off
void snowCloudComputeDrift(f32* out, f32* pos, f32 scale)
{
    f32 accX;
    f32 accZ;
    f32 dx;
    f32 dz;
    f32 dSq;
    f32 dists[6];
    int i;

    if (renderModeSetOrGet(-1) == 1)
    {
        return;
    }
    accX = 0.0f;
    accZ = 0.0f;
    for (i = 0; i < 6; i++)
    {
        dx = (f32)lbl_8039A848[i].x - pos[0];
        dSq = dx * dx;
        dz = (f32)lbl_8039A848[i].z - pos[2];
        dz = dz * dz;
        dSq = dSq + dz;
        if (dSq != 0.0f)
        {
            dists[i] = sqrtf__inline(dSq);
        }
        else
        {
            dists[i] = 0.0f;
        }
        if (dists[i] < lbl_803DF1DC)
        {
            dists[i] = lbl_803DF1DC;
        }
    }
    for (i = 0; i < 6; i++)
    {
        dists[i] = lbl_803DF1A4 / sqrtf__inline(dists[i]);
    }
    for (i = 0; i < 6; i++)
    {
        accX += lbl_8039A848[i].vx * dists[i];
        accZ += lbl_8039A848[i].vz * dists[i];
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
extern void Camera_RebuildProjectionMatrix(void);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int attr, int type);
extern void textureSetupFn_800799c0(void);
extern void gxTextureFn_800794e0(void);
extern void textRenderSetupFn_80079804(void);
extern void fn_800788DC(void);
extern void fn_8006C51C(void* out);
extern void selectTexture(char* tex, int slot);
extern void Camera_UpdateViewMatrices(void);
extern f32* Camera_GetViewMatrix(void);
extern void GXLoadPosMtxImm(f32* matrix, s32 slot);
extern void GXSetCurrentMtx(int slot);
extern int rand(void);
extern void srand(int seed);
extern void PSVECSubtract(f32 * a, f32 * b, f32 * ab);
extern f32 PSVECMag(f32 * v);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern int lbl_803DF19C;
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

    color = *(FogColor*)&lbl_803DF19C;
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
                        (int)((lbl_803DF1D4 * (f32)(b - a)) / (f32)half));
    }
    GXSetCullMode(0);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    textureSetupFn_800799c0();
    gxTextureFn_800794e0();
    textRenderSetupFn_80079804();
    fn_800788DC();
    fn_8006C51C(&tex);
    selectTexture(tex, 0);
    GXSetFog(0, lbl_803DF1A0, lbl_803DF1A0, lbl_803DF1A0, lbl_803DF1A0, color);
    Camera_UpdateViewMatrices();
    GXLoadPosMtxImm(Camera_GetViewMatrix(), 0);
    GXSetCurrentMtx(0);
    savedSeed = rand();
    if (p->seed == 0xffff)
    {
        p->seed = (u16)savedSeed;
    }
    srand(p->seed);
    PSVECSubtract(end, start, diff);
    PSVECMag(diff);
    lightningDrawBolt(start, end, p->unk26, p->radiusX, p->radiusY, &savedSeed, 0,
                      p->unk27);
    srand(savedSeed);
}

extern s16 lbl_803DD1A8;
extern f32 lbl_803DD1AC;
extern f32 lbl_803DD1B0;
extern const f32 lbl_803DF1E0;
extern const f32 lbl_803DF1E4;
extern const f32 lbl_803DF1E8;
extern const f32 lbl_803DF1EC;
extern const f32 lbl_803DF1F0;
extern const f32 lbl_803DF1F4;
extern const f32 lbl_803DF1F8;

void snowCloudInitFlakes(f32* buf, int cloudId, f32 a, f32 b)
{
    u8* p;
    u8* e;
    f32* dst;
    int i;
    int j;
    int widx;
    f32 amp;
    f32 size;
    f32 negSize;
    f32 halfNeg;

    amp = a * b * lbl_803DF1E0;
    for (i = 0; i < 8; i++)
    {
        p = lbl_8039A828[i];
        if (p != NULL && cloudId == ((NewCloud*)p)->cloudId)
        {
            break;
        }
    }
    p = lbl_8039A828[i];
    if (p == NULL)
    {
        return;
    }
    if (lbl_803DF1E4 == lbl_803DD1AC)
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
        size = lbl_803DF1E4;
    }
    else
    {
        size = lbl_803DF1E8;
    }
    e = p + 0x1008;
    negSize = -size;
    halfNeg = lbl_803DF1EC * negSize;
    for (j = 0; j < 20; j++)
    {
        *(f32*)(e + 0x0) = negSize;
        *(f32*)(e + 0x18) = 0.0f;
        *(f32*)(e + 0x4) = size;
        *(f32*)(e + 0x1c) = 0.0f;
        *(f32*)(e + 0x8) = 0.0f;
        *(f32*)(e + 0x20) = 0.0f;
        if (*(int*)((u8*)lbl_8039A828[i] + 0x13f4) == 0)
        {
            *(f32*)(e + 0xc) = negSize;
            *(f32*)(e + 0x10) = negSize;
            *(f32*)(e + 0x14) = size;
        }
        else
        {
            *(f32*)(e + 0xc) = negSize;
            *(f32*)(e + 0x10) = negSize;
            *(f32*)(e + 0x14) = halfNeg;
        }
        *(u16*)(e + 0x28) = (u16)randomGetRange(0, 0xffff);
        *(u16*)(e + 0x2a) = (u16)randomGetRange(0, 0xffff);
        *(u16*)(e + 0x24) = (u16)randomGetRange(0x96, 0x1f4);
        *(u16*)(e + 0x26) = (u16)randomGetRange(0x96, 0x1f4);
        e += 0x2c;
    }
    widx = *(int*)((u8*)lbl_8039A828[i] + 0x1408);
    dst = buf + widx;
    while (widx < *(int*)((u8*)lbl_8039A828[i] + 0x1408) + 0xfa0)
    {
        if (widx == 0x400)
        {
            *(int*)((u8*)lbl_8039A828[i] + 0x1400) = 0;
            *(int*)((u8*)lbl_8039A828[i] + 0x1408) = 0;
            return;
        }
        if (widx == 0)
        {
            lbl_803DD1A8 = 0;
            lbl_803DD1AC = 0.0f;
            lbl_803DD1B0 = 0.0f;
        }
        mathSinf((lbl_803DF1F0 * (f32)lbl_803DD1A8) / lbl_803DF1F4);
        mathCosf((lbl_803DF1F0 * (f32)lbl_803DD1A8) / lbl_803DF1F4);
        *dst = lbl_803DD1AC * amp;
        lbl_803DD1A8 = (f32)lbl_803DD1A8 + lbl_803DF1F8;
        lbl_803DD1AC = lbl_803DD1AC + lbl_803DF1A4;
        dst++;
        widx++;
    }
    *(int*)((u8*)lbl_8039A828[i] + 0x1408) = *(int*)((u8*)lbl_8039A828[i] + 0x1408) + 0xfa0;
}

extern u8 isOvercast(void);
extern void fn_800790AC(void);
extern void gxBlendFn_800789ac(void);
extern void textRenderSetupFn_800795e8(void);
extern f32* Camera_GetViewRotationMatrix(void);
extern void GXSetPointSize(int size, int fmt);
extern void GXCallDisplayList(void* list, int size);
extern int lbl_803DB778;
extern u8 lbl_803DB770[8];
extern u8 lbl_8030F770[];
extern u16 lbl_8039A900[];
extern void* lbl_8039A9B8[];
extern char* lbl_803DD1D0;
extern char* lbl_803DD1D4;
extern const f32 lbl_803DF280;
extern const f32 lbl_803DF284;
extern const f32 lbl_803DF288;
extern f32 lbl_803DF28C;

void drawSkyStars(void)
{
    int timeOk;
    int start;
    int alpha;
    int div;
    int i;
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
            if (t > lbl_803DF280)
            {
                alpha = 0xff;
            }
            else
            {
                alpha = (int)(lbl_803DF284 * (t / lbl_803DF280));
            }
        }
        else
        {
            if (t > lbl_803DF288 || lbl_803DF28C == t)
            {
                return;
            }
            alpha = (int)(lbl_803DF284 - lbl_803DF284 * (t / lbl_803DF288));
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
    GXSetCullMode(0);
    Camera_RebuildProjectionMatrix();
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    textureSetupFn_800799c0();
    fn_800790AC();
    textRenderSetupFn_80079804();
    gxBlendFn_800789ac();
    color = *(FogColor*)&lbl_803DB778;
    GXSetFog(0, lbl_803DF28C, lbl_803DF28C, lbl_803DF28C, lbl_803DF28C, color);
    Camera_UpdateViewMatrices();
    GXLoadPosMtxImm(Camera_GetViewRotationMatrix(), 0);
    GXSetCurrentMtx(0);
    for (i = start; i < 0x5c; i++)
    {
        colRange = &lbl_8030F770[(i & 3) * 6];
        red = randomGetRange(colRange[0], colRange[1]);
        green = randomGetRange(colRange[2], colRange[3]);
        blue = randomGetRange(colRange[4], colRange[5]);
        if (i < 0x4c)
        {
            a = (alpha * randomGetRange(lbl_803DB770[((i & 0xc) >> 2) * 2],
                                        lbl_803DB770[((i & 0xc) >> 2) * 2 + 1])) >>
                8;
        }
        else
        {
            a = alpha;
        }
        _gxSetTevColor2((u8)red, (u8)green, (u8)blue, (u8)a);
        if (i == 0x4c)
        {
            selectTexture(lbl_803DD1D0, 0);
            textureSetupFn_800799c0();
            textRenderSetupFn_800795e8();
            textRenderSetupFn_80079804();
        }
        else if (i == 0x54)
        {
            selectTexture(lbl_803DD1D4, 0);
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
        GXCallDisplayList(lbl_8039A9B8[i], lbl_8039A900[i]);
    }
}

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

volatile PPCWGPipe2 GXWGFifo : (0xCC008000);

extern int getHudHiddenFrameCount(void);
extern void PSVECScale(f32* in, f32* out, f32 scale);
extern void PSVECCrossProduct(f32 * a, f32 * b, f32 * axb);
extern void PSMTXRotAxisRad(f32* mtx, f32* axis, f32 rad);
extern void PSMTXMultVecSR(f32 * mtx, f32 * src, f32 * dst);
extern void GXSetLineWidth(int width, int fmt);
extern void GXBegin(int prim, int fmt, u16 count);
extern const f32 lbl_803DF1B8;
extern f32 lbl_803DF1BC;
extern const f32 lbl_803DF1C0;
extern const f32 lbl_803DF1C4;
extern const f32 lbl_803DF1C8;
extern const f32 lbl_803DF1CC;

void lightningDrawStrand(f32* from, f32* to, int width, f32 segScale, int* seed)
{
    int savedRand;
    int segs;
    int i;
    f32 total;
    f32 len;
    f32 weight;
    f32 px;
    f32 py;
    f32 pz;
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
    if (__fabs(scaled[0]) < lbl_803DF1B8)
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
    segs = (int)(len * segScale);
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
        total += (f32)(i + 1);
    }
    weight = lbl_803DF1A4 / total;
    GXSetLineWidth(width, 5);
    GXBegin(0xb0, 2, segs + 1);
    for (i = 0; i <= segs; i++)
    {
        if (i == 0)
        {
            GXWGFifo.f32 = from[0];
            GXWGFifo.f32 = from[1];
            GXWGFifo.f32 = from[2];
            GXWGFifo.f32 = lbl_803DF1A0;
            GXWGFifo.f32 = lbl_803DF1A0;
            px = from[0];
            py = from[1];
            pz = from[2];
        }
        else if (i < segs)
        {
            PSVECScale(up, offset,
                       lbl_803DF1BC *
                       (lbl_803DF1C0 * (len * (f32)(int)randomGetRange(1, 100))
            )
            )
            ;
            PSMTXRotAxisRad(
                mtx, scaled,
                lbl_803DF1C4 *
                (lbl_803DF1C8 * (lbl_803DF1CC * (f32)(int)randomGetRange(0, 1000))
            )
            )
            ;
            PSMTXMultVecSR(mtx, offset, offset);
            step = weight * (len * (f32)(segs - i));
            px += scaled[0] * step;
            py += scaled[1] * step;
            pz += scaled[2] * step;
            GXWGFifo.f32 = px + offset[0];
            GXWGFifo.f32 = py + offset[1];
            GXWGFifo.f32 = pz + offset[2];
            GXWGFifo.f32 = lbl_803DF1A0;
            GXWGFifo.f32 = lbl_803DF1A0;
        }
        else
        {
            GXWGFifo.f32 = to[0];
            GXWGFifo.f32 = to[1];
            GXWGFifo.f32 = to[2];
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
    u8* e;
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
    e = snow + 0x1008;
    if (*(int*)(snow + 0x13f4) == 0)
    {
        f32 size = 16.0f;
        f32 negSize = -size;
        for (i = 0; i < 20; i++)
        {
            m = (f32*)e;
            m[0] = negSize;
            m[3] = negSize;
            m[6] = 0.0f;
            m[1] = size;
            m[4] = negSize;
            m[7] = 0.0f;
            m[2] = 0.0f;
            m[5] = size;
            m[8] = 0.0f;
            *(u16*)(e + 0x28) =
                timeDelta * (f32) * (u16*)(e + 0x24) + (f32) * (u16*)(e + 0x28);
            *(u16*)(e + 0x2a) =
                timeDelta * (f32) * (u16*)(e + 0x26) + (f32) * (u16*)(e + 0x2a);
            angleToVec2((u16)(0xffff - *cam), &c1, &s1);
            angleToVec2(*(u16*)(e + 0x28), &c2, &s2);
            angleToVec2(*(u16*)(e + 0x2a), &c3, &s3);
            for (c = 0; c < 3; c++)
            {
                f32 m0 = m[c];
                f32 m1 = m[c + 3];
                f32 m2 = m[c + 6];
                f32 t1 = m0 * s3 - m1 * c3;
                f32 t2 = m0 * c3 + m1 * s3;
                m[c] = t1 * s1 + c1 * (t2 * c2) + c1 * (m2 * s2);
                m[c + 3] = -m2 * c2 + t2 * s2;
                m[c + 6] = -t1 * c1 + s1 * (t2 * c2) + s1 * (m2 * s2);
            }
            e += 0x2c;
        }
    }
    else
    {
        f32 size2;
        f32 negSize2;
        angleToVec2((u16)(0xffff - *cam), &c1, &s1);
        size2 = lbl_803DF1E4;
        negSize2 = -size2;
        m = (f32*)e;
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
    int segs;
    f32 total;
    f32 weight;
    f32 px;
    f32 py;
    f32 pz;
    f32 nx;
    f32 ny;
    f32 nz;
    f32 progress;
    f32 step;
    int i;
    int oddFlag;
    int halfWidth;
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
    if (__fabs(scaled[0]) < lbl_803DF1B8)
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
    segs = (int)(len * segScale);
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
        total += (f32)(i + 1);
    }
    weight = lbl_803DF1A4 / total;
    px = start[0];
    py = start[1];
    pz = start[2];
    cur[0] = px;
    cur[1] = py;
    cur[2] = pz;
    progress = lbl_803DF1A0;
    oddFlag = (u8)flags & 1;
    halfWidth = (u8)width >> 1;
    for (i = 0; i <= segs; i++)
    {
        if (i < segs)
        {
            PSVECScale(up, offset,
                       lbl_803DF1BC *
                       (lbl_803DF1C0 * (len * (f32)(int)randomGetRange(1, 100))
            )
            )
            ;
            PSMTXRotAxisRad(
                mtx, scaled,
                lbl_803DF1C4 *
                (lbl_803DF1C8 * (lbl_803DF1CC * (f32)(int)randomGetRange(0, 1000))
            )
            )
            ;
            PSMTXMultVecSR(mtx, offset, offset);
            progress += weight * (f32)(segs - i);
            step = weight * (len * (f32)(segs - i));
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
                               (len * (f32)(int)randomGetRange(0x32, 0x64))
                )
                )
                ;
                PSMTXRotAxisRad(mtx, scaled,
                                lbl_803DF1C4 *
                                (lbl_803DF1C8 *
                                    (lbl_803DF1CC * (f32)(int)randomGetRange(0, 1000))
                )
                )
                ;
                PSMTXMultVecSR(mtx, offset, offset);
                PSVECScale(scaled, branchEnd,
                           (lbl_803DF1CC * ((lbl_803DF1A4 - progress) *
                               (f32)(int)randomGetRange(0, 1000)) +
                    progress
                )
                *
                    len
                )
                ;
                PSVECAdd(start, branchEnd, branchEnd);
                PSVECAdd(branchEnd, offset, branchEnd);
                lightningDrawBolt(next, branchEnd, (u8)halfWidth, segScale, d, seed, depth + 1,
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
extern void DCInvalidateRange(void* addr, u32 nBytes);
extern int GXBeginDisplayList(void* list, u32 size);
extern u32 GXEndDisplayList(void);
extern void GXResetWriteGatherPipe(void);
extern void PSMTXRotRad(f32* mtx, int axis, f32 rad);
extern u8 lbl_803DD1D8;
extern const f32 lbl_803DF290;
extern const f32 lbl_803DF294;
extern const f32 lbl_803DF298;
extern const f32 lbl_803DF29C;
extern const f32 lbl_803DF2A0;
extern const f32 lbl_803DF2A4;

void titleScreenDrawFn_80093db4(void)
{
    f32* constellation;
    f32* cp;
    int i;
    int j;
    int k;
    int idx;
    f32 zero;
    f32 v[3];
    f32 mtx2[12];
    f32 mtx1[12];

    GXSetMisc(1, 0);
    testAndSet_onlyUseHeap3(0);
    constellation = mmAlloc(0x4b0, 0x7f7f7fff, 0);
    testAndSet_onlyUseHeap3(1);
    cp = constellation;
    zero = lbl_803DF28C;
    for (i = 0; i < 0x64; i++)
    {
        do
        {
            v[0] = (f32)(int)
            randomGetRange(-5000, 5000);
            v[1] = (f32)(int)
            randomGetRange(-5000, 5000);
            v[2] = (f32)(int)
            randomGetRange(-5000, 5000);
        }
        while (zero == v[0] && zero == v[1] && zero == v[2]);
        PSVECNormalize(v, v);
        PSVECScale(v, v, lbl_803DF290);
        cp[0] = v[0];
        cp[1] = v[1];
        cp[2] = v[2];
        cp += 3;
    }
    lbl_803DD1D8 = 1;
    lbl_803DD1D0 = textureLoadAsset(0xc21);
    lbl_803DD1D4 = textureLoadAsset(0xc22);
    for (k = 0; k < 0x5c; k++)
    {
        lbl_8039A9B8[k] = mmAlloc(0x220, 0x7f7f7fff, 0);
        DCInvalidateRange(lbl_8039A9B8[k], 0x220);
        GXBeginDisplayList(lbl_8039A9B8[k], 0x220);
        GXResetWriteGatherPipe();
        GXBegin(0xb8, 0, 0x32);
        for (j = 0; j < 0x32; j++)
        {
            if (randomGetRange(0, 9) < 5)
            {
                f32 z2 = lbl_803DF28C;
                do
                {
                    v[0] = (f32)(int)
                    randomGetRange(-5000, 5000);
                    v[1] = (f32)(int)
                    randomGetRange(-5000, 5000);
                    v[2] = (f32)(int)
                    randomGetRange(-5000, 5000);
                }
                while (z2 == v[0] && z2 == v[1] && z2 == v[2]);
                PSVECNormalize(v, v);
                PSVECScale(v, v, lbl_803DF290);
            }
            else
            {
                idx = randomGetRange(0, 0x63);
                v[0] = constellation[idx * 3];
                v[1] = constellation[idx * 3 + 1];
                v[2] = constellation[idx * 3 + 2];
                if (__fabs(v[0]) > lbl_803DF294)
                {
                    PSMTXRotRad(mtx1, 0x79,
                                (lbl_803DF298 *
                                    (lbl_803DF29C *
                                        (lbl_803DF2A0 *
                                            (f32)(int)randomGetRange(-0x8000, 0x8000))
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
                                            (f32)(int)randomGetRange(-0x8000, 0x8000))
                    )
                    )
                    /
                    lbl_803DF2A4
                    )
                    ;
                }
                else if (__fabs(v[1]) > lbl_803DF294)
                {
                    PSMTXRotRad(mtx1, 0x78,
                                (lbl_803DF298 *
                                    (lbl_803DF29C *
                                        (lbl_803DF2A0 *
                                            (f32)(int)randomGetRange(-0x8000, 0x8000))
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
                                            (f32)(int)randomGetRange(-0x8000, 0x8000))
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
                                            (f32)(int)randomGetRange(-0x8000, 0x8000))
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
                                            (f32)(int)randomGetRange(-0x8000, 0x8000))
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
        lbl_8039A900[k] = (u16)GXEndDisplayList();
    }
    mm_free(constellation);
    GXSetMisc(1, 8);
}

extern char lbl_8030F670[];
extern const f32 lbl_803DF228;
extern const f32 lbl_803DF22C;
extern f32 lbl_803DF230;

void snowReposSnowCloud(int cloudId)
{
    u8* p;
    u8* part;
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
        p = lbl_8039A828[i];
        if (p != NULL && cloudId == ((NewCloud*)p)->cloudId)
        {
            break;
        }
    }
    p = lbl_8039A828[i];
    if (p == NULL)
    {
        return;
    }
    if (i == 8)
    {
        return;
    }
    if (cloudId != ((NewCloud*)p)->cloudId)
    {
        debugPrintf(lbl_8030F670, cloudId);
        return;
    }
    part = *(u8**)(p + 4);
    cam = (f32*)Camera_GetCurrentViewSlot();
    dx = cam[0x44 / 4] - *(f32*)((u8*)lbl_8039A828[i] + 0x140c);
    dy = cam[0x48 / 4] - *(f32*)((u8*)lbl_8039A828[i] + 0x1410);
    dz = cam[0x4c / 4] - *(f32*)((u8*)lbl_8039A828[i] + 0x1414);
    distSq = dx * dx + (dy * dy + dz * dz);
    sqrtf__inline((f32)distSq);
    *(s16*)((u8*)lbl_8039A828[i] + 0x1448) =
        (f32) * (s16*)((u8*)lbl_8039A828[i] + 0x1448) - timeDelta;
    q = lbl_8039A828[cloudId];
    if (*(int*)(q + 0x13f4) == 4 && (q[0x144b] & 0x38) != 0 &&
        *(s16*)(q + 0x1448) <= 0 && q[0x144d] == 0 && lbl_803DD19C == 0)
    {
        if (q[0x1452] != 0 && cam != NULL)
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
        from[0] = (cam[0x44 / 4] + (f32)(int)
        randomGetRange(-3000, 3000)
        )
        -
            lbl_803DF22C * fwd[0];
        from[1] = (cam[0x48 / 4] + (f32)(int)
        randomGetRange(2000, 4000)
        )
        -
            lbl_803DF22C * fwd[1];
        from[2] = (cam[0x4c / 4] + (f32)(int)
        randomGetRange(-3000, 3000)
        )
        -
            lbl_803DF22C * fwd[2];
        to[0] = (cam[0x44 / 4] + (f32)(int)
        randomGetRange(-3000, 3000)
        )
        -
            lbl_803DF22C * fwd[0];
        to[1] = (cam[0x48 / 4] - (f32)(int)
        randomGetRange(2000, 4000)
        )
        -
            lbl_803DF22C * fwd[1];
        to[2] = (cam[0x4c / 4] + (f32)(int)
        randomGetRange(-3000, 3000)
        )
        -
            lbl_803DF22C * fwd[2];
        lbl_803DD19C = (u8*)lightningCreate(from, to, lbl_803DF230, lbl_803DF1BC, 0xf, 0xc0, 0);
        Sfx_PlayAtPositionFromObject(from[0], from[1], from[2], 0, 0x2c9);
        fl = ((u8*)lbl_8039A828[cloudId])[0x144b];
        if (fl & 8)
        {
            *(s16*)((u8*)lbl_8039A828[cloudId] + 0x1448) = (s16)randomGetRange(0x78, 0xf0);
        }
        else if (fl & 0x10)
        {
            *(s16*)((u8*)lbl_8039A828[cloudId] + 0x1448) = (s16)randomGetRange(0x78, 0xf0);
        }
        else if (fl & 0x20)
        {
            *(s16*)((u8*)lbl_8039A828[cloudId] + 0x1448) = (s16)randomGetRange(0x5a, 0xb4);
        }
    }
    snowCloudUpdateFlakes(lbl_8039A828[i]);
    for (j = 0; j < *(int*)((u8*)lbl_8039A828[i] + 0x13fc); j++)
    {
        if (*(int*)((u8*)lbl_8039A828[i] + 0x13f4) == 0)
        {
            *(u16*)(part + 0x10) =
                *(u16*)(part + 0x10) + (s8)part[0x14] * framesThisStep;
            if ((int)*(u16*)(part + 0x10) > 0x3ff)
            {
                *(u16*)(part + 0x10) -= 0x3ff;
            }
        }
        else if (*(int*)((u8*)lbl_8039A828[i] + 0x13f4) == 4)
        {
            *(u16*)(part + 0x10) = *(u16*)(part + 0x10) +
                framesThisStep * ((s8)part[0x14] + (s8)part[0x14]);
            if ((int)*(u16*)(part + 0x10) > 0x3ff)
            {
                *(u16*)(part + 0x10) -= 0x3ff;
            }
        }
        part += 0x18;
    }
}

extern char lbl_8030F500[];
extern int lbl_803DB76C;
extern const f32 lbl_803DF1FC;
extern const f32 lbl_803DF214;
extern const f32 lbl_803DF234;
extern const f32 lbl_803DF238;
extern const f32 lbl_803DF23C;
extern const f32 lbl_803DF240;
extern const f32 lbl_803DF244;

#define NC_CLOUD ((u8 *)lbl_8039A828[id])
#define NC_PARTS ((u8 *)*(void **)(NC_CLOUD + 4))

void newClouds(u8* params, void* owner, f32 x, f32 y, f32 z)
{
    char* strs;
    int ok;
    int id;
    int i;
    u8 fl;
    WindSource* w;

    strs = lbl_8030F500;
    ok = 1;
    id = *(u16*)(params + 0x26);
    if (lbl_8039A828[id] != NULL)
    {
        snowFreeSnowCloud(id);
    }
    lbl_8039A828[id] = mmAlloc(0x1454, 0x17, 0);
    if (lbl_8039A828[id] == NULL)
    {
        debugPrintf(strs + 0x1b0);
        return;
    }
    memset(lbl_8039A828[id], 0, 0x1454);
    ((NewCloud*)NC_CLOUD)->cloudId = id;
    NC_CLOUD[0x1453] = 0;
    ((NewCloud*)NC_CLOUD)->cloudType = params[0x5c];
    *(void**)(NC_CLOUD + 0x0) = owner;
    NC_CLOUD[0x144a] = params[0x58];
    NC_CLOUD[0x144b] = params[0x59];
    ((NewCloud*)NC_CLOUD)->worldPosX = x;
    ((NewCloud*)NC_CLOUD)->worldPosY = y;
    ((NewCloud*)NC_CLOUD)->worldPosZ = z;
    if (params[0x58] & 1)
    {
        NC_CLOUD[0x1451] = 1;
    }
    if (params[0x58] & 0x10)
    {
        NC_CLOUD[0x144e] = 1;
    }
    NC_CLOUD[0x1452] = 1;
    NC_CLOUD[0x144d] = params[0x5d];
    if (((NewCloud*)NC_CLOUD)->cloudType == 0)
    {
        ((NewCloud*)NC_CLOUD)->flakeCount = *(u16*)(params + 0x28) << 3;
    }
    else
    {
        ((NewCloud*)NC_CLOUD)->flakeCount = *(u16*)(params + 0x28);
    }
    if (*(u16*)(params + 0x2a) != 0)
    {
        ((NewCloud*)NC_CLOUD)->unk142C =
            (f32)((NewCloud*)NC_CLOUD)->flakeCount / (f32) * (u16*)(params + 0x2a);
    }
    else
    {
        ((NewCloud*)NC_CLOUD)->unk142C = (f32)((NewCloud*)NC_CLOUD)->flakeCount;
    }
    if (*(u16*)(params + 0x2c) != 0)
    {
        ((NewCloud*)NC_CLOUD)->unk1430 =
            (f32)((NewCloud*)NC_CLOUD)->flakeCount / (f32) * (u16*)(params + 0x2c);
    }
    else
    {
        ((NewCloud*)NC_CLOUD)->unk1430 = (f32)((NewCloud*)NC_CLOUD)->flakeCount;
    }
    ((NewCloud*)NC_CLOUD)->unk1438 = *(f32*)(params + 8);
    if (((NewCloud*)NC_CLOUD)->cloudType == 0)
    {
        ((NewCloud*)NC_CLOUD)->cloudHeight = lbl_803DF234;
        ((NewCloud*)NC_CLOUD)->scale = lbl_803DF238;
    }
    else
    {
        ((NewCloud*)NC_CLOUD)->cloudHeight = *(f32*)(params + 4);
        ((NewCloud*)NC_CLOUD)->scale = lbl_803DF1E4 * *(f32*)(params + 0);
    }
    if (*(f32*)(params + 8) < lbl_803DF1A4)
    {
        *(f32*)(params + 8) = lbl_803DF1A0;
    }
    if (lbl_803DF1A0 != *(f32*)(params + 8))
    {
        ((NewCloud*)NC_CLOUD)->unk1444 = lbl_803DF23C;
        ((NewCloud*)NC_CLOUD)->unk143C =
            (f32)(int)
        randomGetRange(1, (int)*(f32*)(params + 8)) * lbl_803DF214;
    }
    ((NewCloud*)NC_CLOUD)->unk1400 = 1;
    fl = NC_CLOUD[0x144b];
    if (fl & 8)
    {
        ((NewCloud*)NC_CLOUD)->unk1448 = 0x320;
    }
    else if (fl & 0x10)
    {
        ((NewCloud*)NC_CLOUD)->unk1448 = 0xc8;
    }
    else if (fl & 0x20)
    {
        ((NewCloud*)NC_CLOUD)->unk1448 = 0x64;
    }
    snowCloudInitFlakes((f32*)(NC_CLOUD + 8), id, ((NewCloud*)NC_CLOUD)->cloudHeight,
                        ((NewCloud*)NC_CLOUD)->scale);
    snowCloudBuildBoxVerts((f32*)(NC_CLOUD + 0x1378), ((NewCloud*)NC_CLOUD)->cloudHeight,
                           ((NewCloud*)NC_CLOUD)->scale);
    *(void**)(NC_CLOUD + 4) = mmAlloc(((NewCloud*)NC_CLOUD)->flakeCount * 0x18, 0x17, 0);
    if (*(void**)(NC_CLOUD + 4) == NULL)
    {
        ok = 0;
    }
    if (ok == 0)
    {
        debugPrintf(strs + 0x1f0);
        mm_free(lbl_8039A828[id]);
        lbl_8039A828[id] = NULL;
        return;
    }
    for (i = 0; i < ((NewCloud*)NC_CLOUD)->flakeCount; i++)
    {
        *(f32*)(NC_PARTS + i * 0x18) =
            (f32)(int)
        randomGetRange((int)((NewCloud*)NC_CLOUD)->flakeMinX,
                       (int)((NewCloud*)NC_CLOUD)->flakeMaxX);
        *(f32*)(NC_PARTS + i * 0x18 + 4) = ((NewCloud*)NC_CLOUD)->unk1388;
        *(f32*)(NC_PARTS + i * 0x18 + 8) =
            (f32)(int)
        randomGetRange((int)((NewCloud*)NC_CLOUD)->flakeMinZ,
                       (int)((NewCloud*)NC_CLOUD)->flakeMaxZ);
        *(u16*)(NC_PARTS + i * 0x18 + 0x10) = (u16)randomGetRange(0, 0x3d0);
        *(u16*)(NC_PARTS + i * 0x18 + 0x12) = (u16)randomGetRange(0, 0x13);
        if (((NewCloud*)NC_CLOUD)->cloudType == 0)
        {
            *(s8*)(NC_PARTS + i * 0x18 + 0x14) =
                (s8)(randomGetRange(*(int*)(strs + params[0x5a] * 8 + 0x58),
                                    *(int*)(strs + params[0x5a] * 8 + 0x5c)) /
                    4);
            *(f32*)(NC_PARTS + i * 0x18 + 0xc) =
                (f32)(int)
            randomGetRange(0x4b, 0x64) / lbl_803DF1FC;
            *(u8*)(NC_PARTS + i * 0x18 + 0x16) =
                (u8)(i / (((NewCloud*)NC_CLOUD)->flakeCount / 4));
        }
        else
        {
            *(s8*)(NC_PARTS + i * 0x18 + 0x14) =
                (s8)(randomGetRange(*(int*)(strs + params[0x5a] * 8 + 0x58),
                                    *(int*)(strs + params[0x5a] * 8 + 0x5c)) *
                    2);
            *(f32*)(NC_PARTS + i * 0x18 + 0xc) = lbl_803DF1A4;
            *(u8*)(NC_PARTS + i * 0x18 + 0x16) = 0;
        }
        if (*(s8*)(NC_PARTS + i * 0x18 + 0x14) < 1)
        {
            *(s8*)(NC_PARTS + i * 0x18 + 0x14) = 1;
        }
        *(s8*)(NC_PARTS + i * 0x18 + 0x15) =
            (s8)(*(int*)(strs + params[0x5b] * 8 + 0x34) / 2 -
                randomGetRange(*(int*)(strs + params[0x5b] * 8 + 0x30),
                               *(int*)(strs + params[0x5b] * 8 + 0x34)));
    }
    if (lbl_803DB76C != 0)
    {
        lbl_8039A848[0].x = 0x31e;
        lbl_8039A848[0].z = 0xa9c;
        lbl_8039A848[0].vx = lbl_803DF240;
        lbl_8039A848[0].vy = lbl_803DF1A0;
        lbl_8039A848[0].vz = lbl_803DF1A0;
        normalize(&lbl_8039A848[0].vx, &lbl_8039A848[0].vy, &lbl_8039A848[0].vz);
        lbl_8039A848[0].scale = lbl_803DF1A4;
        lbl_8039A848[0].flag = 0;
        lbl_8039A848[1].x = 0x3c5;
        lbl_8039A848[1].z = 0xb72;
        lbl_8039A848[1].vx = lbl_803DF1A0;
        lbl_8039A848[1].vy = lbl_803DF1A0;
        lbl_8039A848[1].vz = lbl_803DF240;
        normalize(&lbl_8039A848[1].vx, &lbl_8039A848[1].vy, &lbl_8039A848[1].vz);
        lbl_8039A848[1].scale = lbl_803DF1A4;
        lbl_8039A848[1].flag = 0;
        lbl_8039A848[2].x = 0x335;
        lbl_8039A848[2].z = 0xe13;
        lbl_8039A848[2].vx = lbl_803DF1FC;
        lbl_8039A848[2].vy = lbl_803DF1A0;
        lbl_8039A848[2].vz = lbl_803DF1A0;
        normalize(&lbl_8039A848[2].vx, &lbl_8039A848[2].vy, &lbl_8039A848[2].vz);
        lbl_8039A848[2].scale = lbl_803DF1A4;
        lbl_8039A848[2].flag = 0;
        lbl_8039A848[3].x = 0x254;
        lbl_8039A848[3].z = 0xc70;
        lbl_8039A848[3].vx = lbl_803DF1A0;
        lbl_8039A848[3].vy = lbl_803DF1A0;
        lbl_8039A848[3].vz = lbl_803DF1FC;
        normalize(&lbl_8039A848[3].vx, &lbl_8039A848[3].vy, &lbl_8039A848[3].vz);
        lbl_8039A848[3].scale = lbl_803DF1A4;
        lbl_8039A848[3].flag = 0;
        lbl_8039A848[4].x = 0x107;
        lbl_8039A848[4].z = 0xb4a;
        lbl_8039A848[4].vx = lbl_803DF1FC;
        lbl_8039A848[4].vy = lbl_803DF1A0;
        lbl_8039A848[4].vz = lbl_803DF1CC;
        normalize(&lbl_8039A848[4].vx, &lbl_8039A848[4].vy, &lbl_8039A848[4].vz);
        lbl_8039A848[4].scale = lbl_803DF1A4;
        lbl_8039A848[4].flag = 0;
        lbl_8039A848[5].x = 0x68;
        lbl_8039A848[5].z = 0xdf6;
        lbl_8039A848[5].vx = lbl_803DF1A0;
        lbl_8039A848[5].vy = lbl_803DF1A0;
        lbl_8039A848[5].vz = lbl_803DF240;
        normalize(&lbl_8039A848[5].vx, &lbl_8039A848[5].vy, &lbl_8039A848[5].vz);
        lbl_8039A848[5].scale = lbl_803DF1A4;
        lbl_8039A848[5].flag = 0;
        lbl_8039A848[0].x = 0x31e;
        lbl_8039A848[0].z = 0xa9c;
        lbl_8039A848[0].vx = lbl_803DF1A0;
        lbl_8039A848[0].vy = lbl_803DF1A0;
        lbl_8039A848[0].vz = lbl_803DF1A0;
        lbl_8039A848[0].scale = lbl_803DF1A0;
        lbl_8039A848[0].flag = 0;
        lbl_8039A848[1].x = 0x3c5;
        lbl_8039A848[1].z = 0xb72;
        lbl_8039A848[1].vx = lbl_803DF1A0;
        lbl_8039A848[1].vy = lbl_803DF1A0;
        lbl_8039A848[1].vz = lbl_803DF1A0;
        lbl_8039A848[1].scale = lbl_803DF1A0;
        lbl_8039A848[1].flag = 0;
        lbl_8039A848[2].x = 0x335;
        lbl_8039A848[2].z = 0xe13;
        lbl_8039A848[2].vx = lbl_803DF1A0;
        lbl_8039A848[2].vy = lbl_803DF1A0;
        lbl_8039A848[2].vz = lbl_803DF1A0;
        lbl_8039A848[2].scale = lbl_803DF1A0;
        lbl_8039A848[2].flag = 0;
        lbl_8039A848[3].x = 0x254;
        lbl_8039A848[3].z = 0xc70;
        lbl_8039A848[3].vx = lbl_803DF1A0;
        lbl_8039A848[3].vy = lbl_803DF1A0;
        lbl_8039A848[3].vz = lbl_803DF1A0;
        lbl_8039A848[3].scale = lbl_803DF1A0;
        lbl_8039A848[3].flag = 0;
        lbl_8039A848[4].x = 0x107;
        lbl_8039A848[4].z = 0xb4a;
        lbl_8039A848[4].vx = lbl_803DF1A0;
        lbl_8039A848[4].vy = lbl_803DF1A0;
        lbl_8039A848[4].vz = lbl_803DF1A0;
        lbl_8039A848[4].scale = lbl_803DF1A0;
        lbl_8039A848[4].flag = 0;
        lbl_8039A848[5].x = 0;
        lbl_8039A848[5].z = 0x7d0;
        lbl_8039A848[5].vx = lbl_803DF1A0;
        lbl_8039A848[5].vy = lbl_803DF1A0;
        lbl_8039A848[5].vz = lbl_803DF244;
        normalize(&lbl_8039A848[5].vx, &lbl_8039A848[5].vy, &lbl_8039A848[5].vz);
        lbl_8039A848[5].scale = lbl_803DF1FC;
        lbl_8039A848[5].flag = 0;
        lbl_803DB76C = 0;
    }
}

extern int lbl_8030F5A0[];
extern const f32 lbl_803DF27C;

#undef NC_CLOUD
#define NC_CLOUD ((u8 *)lbl_8039A828[*(u16 *)(params + 0x26)])

void newclouds_update(u8* objA, u8* objB, u8* params)
{
    u8* env;
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
        posA[0] = *(f32*)(objA + 0x18);
        posA[1] = *(f32*)(objA + 0x1c);
        posA[2] = *(f32*)(objA + 0x20);
    }
    if (objB != NULL)
    {
        posB[0] = *(f32*)(objB + 0x18);
        posB[1] = *(f32*)(objB + 0x1c);
        posB[2] = *(f32*)(objB + 0x20);
    }
    if ((u32)*(u16*)(params + 0x26) > 8)
    {
        return;
    }
    if (NC_CLOUD == NULL)
    {
        fl = params[0x58];
        if (!(fl & 4) && !(fl & 8) && !(fl & 0x20))
        {
            if ((fl & 2) && (fl & 0x10) && params[0x5d] != 0)
            {
                newClouds(params, objB, posA[0], posA[1], posA[2]);
            }
            else if ((fl & 2) && (fl & 0x10))
            {
                newClouds(params, objB, posB[0], posB[1], posB[2]);
            }
            else if (fl & 2)
            {
                newClouds(params, objB, posA[0], posA[1], posA[2]);
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
                    NC_CLOUD[0x144d] = 1 - env[*(u16*)(params + 0x26) + 0x41];
                    if ((s8)env[*(u16*)(params + 0x26) + 0x41] != 0)
                    {
                        return;
                    }
                    ((NewCloud*)NC_CLOUD)->worldPosX =
                        (f32) * (int*)(env + *(u16*)(params + 0x26) * 0xc + 0x14);
                    ((NewCloud*)NC_CLOUD)->worldPosY =
                        (f32) * (int*)(env + *(u16*)(params + 0x26) * 0xc + 0x18);
                    ((NewCloud*)NC_CLOUD)->worldPosZ =
                        (f32) * (int*)(env + *(u16*)(params + 0x26) * 0xc + 0x1c);
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
                    NC_CLOUD[0x144d] = 1 - env[*(u16*)(params + 0x26) + 0x41];
                    if ((s8)env[*(u16*)(params + 0x26) + 0x41] != 0)
                    {
                        return;
                    }
                    ((NewCloud*)NC_CLOUD)->worldPosX =
                        (f32) * (int*)(env + *(u16*)(params + 0x26) * 0xc + 0x14);
                    ((NewCloud*)NC_CLOUD)->worldPosY =
                        (f32) * (int*)(env + *(u16*)(params + 0x26) * 0xc + 0x18);
                    ((NewCloud*)NC_CLOUD)->worldPosZ =
                        (f32) * (int*)(env + *(u16*)(params + 0x26) * 0xc + 0x1c);
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
                    NC_CLOUD[0x144d] = 1 - env[*(u16*)(params + 0x26) + 0x41];
                    if ((s8)env[*(u16*)(params + 0x26) + 0x41] != 0)
                    {
                        return;
                    }
                    ((NewCloud*)NC_CLOUD)->worldPosX =
                        (f32) * (int*)(env + *(u16*)(params + 0x26) * 0xc + 0x14);
                    ((NewCloud*)NC_CLOUD)->worldPosY =
                        (f32) * (int*)(env + *(u16*)(params + 0x26) * 0xc + 0x18);
                    ((NewCloud*)NC_CLOUD)->worldPosZ =
                        (f32) * (int*)(env + *(u16*)(params + 0x26) * 0xc + 0x1c);
                    break;
                }
            }
        }
    }
    if (NC_CLOUD == NULL)
    {
        return;
    }
    fl = params[0x58];
    if (fl & 2)
    {
        return;
    }
    if ((fl & 8) && NC_CLOUD[0x144e] != 0)
    {
        env[*(u16*)(params + 0x26) + 0x41] = (s8)NC_CLOUD[0x144d];
        NC_CLOUD[0x144d] = 1 - NC_CLOUD[0x144d];
        if (NC_CLOUD[0x144d] == 1)
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
            ((NewCloud*)NC_CLOUD)->worldPosX = vec[0] + *(f32*)(objA + 0x18);
            ((NewCloud*)NC_CLOUD)->worldPosY = vec[1] + *(f32*)(objA + 0x1c);
            ((NewCloud*)NC_CLOUD)->worldPosZ = vec[2] + *(f32*)(objA + 0x20);
            if (((NewCloud*)NC_CLOUD)->unk1438 > lbl_803DF27C)
            {
                Music_Trigger(lbl_8030F5A0[((NewCloud*)NC_CLOUD)->cloudType], 0);
            }
        }
        else
        {
            if (((NewCloud*)NC_CLOUD)->unk1438 > lbl_803DF27C)
            {
                Music_Trigger(lbl_8030F5A0[((NewCloud*)NC_CLOUD)->cloudType], 1);
            }
        }
        if ((s8)env[*(u16*)(params + 0x26) + 0x41] == 0)
        {
            *(int*)(env + *(u16*)(params + 0x26) * 0xc + 0x14) = posA[0];
            *(int*)(env + *(u16*)(params + 0x26) * 0xc + 0x18) = posA[1];
            *(int*)(env + *(u16*)(params + 0x26) * 0xc + 0x1c) = posA[2];
        }
    }
    else if (fl & 0x20)
    {
        newclouds_snowKillSnowCloud(*(u16*)(params + 0x26), 0);
    }
    else if (fl & 4)
    {
        if (NC_CLOUD[0x144f] != 0)
        {
            NC_CLOUD[0x144f] = 0;
        }
        ((NewCloud*)NC_CLOUD)->unk13F8 = 1 - ((NewCloud*)NC_CLOUD)->unk13F8;
        if (*(u16*)(params + 0x2a) != 0)
        {
            ((NewCloud*)NC_CLOUD)->unk142C =
                (f32)((NewCloud*)NC_CLOUD)->flakeCount / (f32) * (u16*)(params + 0x2a);
        }
        else
        {
            ((NewCloud*)NC_CLOUD)->unk142C = (f32)(((NewCloud*)NC_CLOUD)->flakeCount - 1);
        }
        if (*(u16*)(params + 0x2c) != 0)
        {
            ((NewCloud*)NC_CLOUD)->unk1430 =
                -((f32)((NewCloud*)NC_CLOUD)->flakeCount / (f32) * (u16*)(params + 0x2c));
        }
        else
        {
            ((NewCloud*)NC_CLOUD)->unk1430 = (f32)(-(((NewCloud*)NC_CLOUD)->flakeCount - 1));
        }
    }
}

extern void PSMTXIdentity(f32 * m);
extern void PSMTXMultVec(f32 * matrix, f32 * in, f32 * out);
extern const f32 lbl_803DF200;
extern const f32 lbl_803DF208;
extern const f32 lbl_803DF20C;
extern const f32 lbl_803DF210;
extern const f32 lbl_803DF248;
extern const f32 lbl_803DF24C;
extern const f32 lbl_803DF250;
extern const f32 lbl_803DF254;
extern const f32 lbl_803DF258;
extern const f32 lbl_803DF25C;
extern const f32 lbl_803DF260;
extern const f32 lbl_803DF264;
extern const f32 lbl_803DF268;
extern const f32 lbl_803DF26C;
extern const f32 lbl_803DF270;
extern const f32 lbl_803DF274;
extern const f32 lbl_803DF278;

#define D7_CLOUD ((u8 *)clouds[i + 4])

void dll_07_func06(void)
{
    s16* cam;
    u8* p;
    u8* nearestCloud;
    u8 activeCount;
    int i;
    f32* m;
    f32* py;
    f32* pz;
    f32 nearest;
    f32 mag;
    f32 t;
    f32 rot;
    void** clouds;
    f32 d[3];
    f32 vec[3];
    f32 pos[3];
    f32 wind[3];
    f32 inpos[3];
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

    clouds = lbl_8039A818;
    nearestCloud = NULL;
    cam = Camera_GetCurrentViewSlot();
    activeCount = 0;
    nearest = lbl_803DF248;
    if (lbl_803DD1C0 == 0)
    {
        lbl_803DD1C8 = textureLoadAsset(0x16a);
        clouds[0] = textureLoadAsset(0x5da);
        clouds[1] = textureLoadAsset(0x63f);
        clouds[2] = textureLoadAsset(0x640);
        clouds[3] = textureLoadAsset(0x641);
        lbl_803DD1C4 = textureLoadAsset(0x151);
        lbl_803DD1C0 = 1;
    }
    if (renderModeSetOrGet(-1) == 1)
    {
        return;
    }
    lbl_803DD1CC = lbl_803DD19B;
    lbl_803DD19B = 0;
    py = &pos[1];
    pz = &pos[2];
    for (i = 0; i < 8; i++)
    {
        p = D7_CLOUD;
        if (p != NULL &&
            (*(u8**)p == NULL || !(*(u16*)(*(u8**)p + 0xb0) & 0x40)))
        {
            snowFreeSnowCloud(((NewCloud*)p)->cloudId);
            continue;
        }
        if (p != NULL && ((NewCloud*)p)->unk1400 != 0)
        {
            snowCloudInitFlakes((f32*)(p + 8), i, ((NewCloud*)p)->cloudHeight,
                                ((NewCloud*)p)->scale);
        }
        else if (p != NULL && p[0x144f] == 0)
        {
            if (((NewCloud*)p)->cloudType == 4)
            {
                lbl_803DD19B = 1;
            }
            if (((NewCloud*)p)->unk13F8 != 0)
            {
                ((NewCloud*)p)->unk1434 =
                    (f32)framesThisStep * ((NewCloud*)p)->unk1430 + ((NewCloud*)p)->unk1434;
                if (((NewCloud*)D7_CLOUD)->unk1434 <= lbl_803DF1A0)
                {
                    D7_CLOUD[0x144f] = 1;
                }
            }
            else
            {
                if ((int)((NewCloud*)p)->unk1434 < ((NewCloud*)p)->flakeCount)
                {
                    ((NewCloud*)p)->unk1434 = (f32)framesThisStep * ((NewCloud*)p)->unk142C +
                        ((NewCloud*)p)->unk1434;
                }
            }
            if ((int)((NewCloud*)D7_CLOUD)->unk1434 > ((NewCloud*)D7_CLOUD)->flakeCount)
            {
                ((NewCloud*)D7_CLOUD)->unk1434 = (f32)((NewCloud*)D7_CLOUD)->flakeCount;
            }
            if (((NewCloud*)D7_CLOUD)->unk1434 < lbl_803DF1A0)
            {
                ((NewCloud*)D7_CLOUD)->unk1434 = lbl_803DF1A0;
            }
            if (*(u8**)D7_CLOUD != NULL)
            {
                Obj_GetWorldPosition((u32)*(u8 **)D7_CLOUD, &pos[0], py, pz);
            }
            if (D7_CLOUD[0x1452] != 0 && cam != NULL)
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
                    pos[1] = (*(f32*)((u8*)cam + 0x48) - lbl_803DF24C) + vec[1];
                    pos[2] = *(f32*)((u8*)cam + 0x4c) + vec[2];
                }
                else
                {
                    pos[0] = *(f32*)((u8*)cam + 0x44);
                    pos[1] = *(f32*)((u8*)cam + 0x48) - lbl_803DF24C;
                    pos[2] = *(f32*)((u8*)cam + 0x4c);
                }
            }
            ((NewCloud*)D7_CLOUD)->unk1440 = (f32)framesThisStep * ((NewCloud*)D7_CLOUD)->unk1444 +
                ((NewCloud*)D7_CLOUD)->unk1440;
            if (lbl_803DF1A0 != ((NewCloud*)D7_CLOUD)->unk1438)
            {
                if (((NewCloud*)D7_CLOUD)->unk1440 > ((NewCloud*)D7_CLOUD)->unk143C)
                {
                    ((NewCloud*)D7_CLOUD)->unk1444 =
                        ((NewCloud*)D7_CLOUD)->unk1444 * lbl_803DF244;
                    ((NewCloud*)D7_CLOUD)->unk1440 = ((NewCloud*)D7_CLOUD)->unk143C;
                }
                else if (((NewCloud*)D7_CLOUD)->unk1440 < lbl_803DF1A0)
                {
                    ((NewCloud*)D7_CLOUD)->unk1444 =
                        ((NewCloud*)D7_CLOUD)->unk1444 * lbl_803DF244;
                    ((NewCloud*)D7_CLOUD)->unk143C = (f32)(int)
                    randomGetRange(
                        1, (int)(lbl_803DF1C8 * ((NewCloud*)D7_CLOUD)->unk1438));
                    ((NewCloud*)D7_CLOUD)->unk1440 = lbl_803DF1A0;
                }
            }
            if (D7_CLOUD[0x144d] == 0)
            {
                inpos[0] = pos[0];
                inpos[1] = pos[1];
                inpos[2] = pos[2];
                snowCloudComputeDrift(wind, inpos, ((NewCloud*)D7_CLOUD)->unk1438);
                if (((NewCloud*)D7_CLOUD)->cloudType == 0)
                {
                    ((NewCloud*)D7_CLOUD)->windVelX = -wind[0];
                    ((NewCloud*)D7_CLOUD)->windVelZ = -wind[2];
                }
                else
                {
                    ((NewCloud*)D7_CLOUD)->windVelX =
                        -(wind[0] + ((NewCloud*)D7_CLOUD)->unk1440);
                    ((NewCloud*)D7_CLOUD)->windVelZ =
                        -(wind[2] + ((NewCloud*)D7_CLOUD)->unk1440);
                    ((NewCloud*)D7_CLOUD)->unk1428 = lbl_803DF1A0;
                }
                ((NewCloud*)D7_CLOUD)->worldPosX = pos[0];
                ((NewCloud*)D7_CLOUD)->worldPosY = pos[1];
                ((NewCloud*)D7_CLOUD)->worldPosZ = pos[2];
            }
            else
            {
                inpos[0] = ((NewCloud*)p)->worldPosX;
                inpos[1] = ((NewCloud*)p)->worldPosY;
                inpos[2] = ((NewCloud*)p)->worldPosZ;
                snowCloudComputeDrift(wind, inpos, ((NewCloud*)p)->unk1438);
                ((NewCloud*)D7_CLOUD)->windVelX = -wind[0] + ((NewCloud*)D7_CLOUD)->unk1440;
                ((NewCloud*)D7_CLOUD)->windVelZ = -wind[2] + ((NewCloud*)D7_CLOUD)->unk1440;
                ((NewCloud*)D7_CLOUD)->unk1428 = lbl_803DF1A0;
            }
            if (D7_CLOUD[0x1453] != 0)
            {
                ((NewCloud*)D7_CLOUD)->unk13E4 = ((NewCloud*)D7_CLOUD)->unk13D8;
                ((NewCloud*)D7_CLOUD)->unk13E8 = ((NewCloud*)D7_CLOUD)->unk13DC;
                ((NewCloud*)D7_CLOUD)->unk13EC = ((NewCloud*)D7_CLOUD)->unk13E0;
            }
            else
            {
                ((NewCloud*)D7_CLOUD)->unk13E4 = pos[0];
                ((NewCloud*)D7_CLOUD)->unk13E8 = pos[1];
                ((NewCloud*)D7_CLOUD)->unk13EC = pos[2];
                D7_CLOUD[0x1453] = 1;
            }
            ((NewCloud*)D7_CLOUD)->unk13D8 = pos[0];
            ((NewCloud*)D7_CLOUD)->unk13DC = pos[1];
            ((NewCloud*)D7_CLOUD)->unk13E0 = pos[2];
            snowReposSnowCloud(((NewCloud*)D7_CLOUD)->cloudId);
            if (((NewCloud*)D7_CLOUD)->unk1434 > lbl_803DF1A0)
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
            D7_CLOUD[0x144d] == 0)
        {
            activeCount++;
        }
    }
    if (activeCount != 0)
    {
        lbl_803DD194 = lbl_803DF1BC;
    }
    else
    {
        lbl_803DD194 = lbl_803DF250;
    }
    if (lbl_803DD19C != NULL)
    {
        ((LightningEffect*)lbl_803DD19C)->timer = ((LightningEffect*)lbl_803DD19C)->timer + 1;
        if (((LightningEffect*)lbl_803DD19C)->timer >= ((LightningEffect*)lbl_803DD19C)->lifetime)
        {
            mm_free(lbl_803DD19C);
            lbl_803DD19C = NULL;
        }
    }
    t = lbl_803DF254 * timeDelta + lbl_803DD1BC;
    lbl_803DD1BC = t;
    if (t > lbl_803DF258)
    {
        lbl_803DD1BC = t - lbl_803DF258;
    }
    t = lbl_803DF25C * timeDelta + lbl_803DD1B8;
    lbl_803DD1B8 = t;
    if (t > lbl_803DF258)
    {
        lbl_803DD1B8 = t - lbl_803DF258;
    }
    t = lbl_803DD1B4 - lbl_803DF260 * timeDelta;
    lbl_803DD1B4 = t;
    if (t < lbl_803DF264)
    {
        lbl_803DD1B4 = t + lbl_803DF258;
    }
    t = lbl_803DB760 + lbl_803DD194;
    lbl_803DB760 = t;
    if (t > lbl_803DF1A4)
    {
        lbl_803DB760 = lbl_803DF1A4;
    }
    else if (t < lbl_803DF1A0)
    {
        lbl_803DB760 = lbl_803DF1A0;
    }
    lbl_803DD198 = 0;
    if (nearestCloud != NULL && *(int*)(nearestCloud + 0x13f4) == 4)
    {
        lbl_803DD198 = lbl_803DF1D4 * lbl_803DB760;
        if (lbl_803DD198 != 0)
        {
            rot = lbl_803DF1C4 *
                (lbl_803DF1C8 *
                    -(lbl_803DF20C * (*(f32*)(nearestCloud + 0x1440) / lbl_803DF210) +
                        lbl_803DF208)) /
                lbl_803DF268;
            *(f32*)((u8*)lbl_8039A818 + 0xd8) = lbl_803DF1A0;
            *(f32*)((u8*)lbl_8039A818 + 0xdc) = lbl_803DF244;
            *(f32*)((u8*)lbl_8039A818 + 0xe0) = lbl_803DF1A0;
            m = Camera_GetViewRotationMatrix();
            if (*(int*)(nearestCloud + 0x13f4) == 0)
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
            PSMTXMultVec(mtx, (f32*)((u8*)lbl_8039A818 + 0xd8),
                         (f32*)((u8*)lbl_8039A818 + 0xd8));
            if (lbl_803DD190 < lbl_803DF278)
            {
                lbl_803DD190 = lbl_803DD190 + lbl_803DF1E8;
            }
        }
    }
    if (lbl_803DD19B != 0 && lbl_803DD1CC == 0)
    {
        Music_Trigger(0xeb, 1);
    }
    else if (lbl_803DD19B == 0 && lbl_803DD1CC != 0)
    {
        Music_Trigger(0xeb, 0);
    }
}

extern char sSnowPrintSnowCloudInvalidCloudId[];
extern void initRotationMtx(f32* mtx, f32 xScale, f32 yScale, f32 zScale);
extern void mtx44_mult(f32 * a, f32 * b, f32 * out);
extern void mtx44Transpose(f32 * in, f32 * out);
extern void getAmbientColor(int mode, u8* r, u8* g, u8* b);
extern void gxBlendFn_80078b4c(void);
extern int lbl_803DD1A4;
extern const f32 lbl_803DF204;

int snowPrintSnowCloud(int arg, int cloudId)
{
    u8* p;
    u8* part;
    int i;
    int j;
    int texIdx;
    u8 hudHidden;
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
    f32 mtxA[16];
    f32 mtxB[16];
    f32 mtxOut[16];
    f32 mtxT[12];
    f32 vx[3];
    f32 vy[3];
    f32 vz[3];
    s16 uvs[6] = {-0x30, 0, 0xb0, 0, 0x40, 0x100};

    scale = lbl_803DF1A4;
    if (renderModeSetOrGet(-1) == 1)
    {
        return 0;
    }
    for (i = 0; i < 8; i++)
    {
        p = lbl_8039A828[i];
        if (p != NULL && cloudId == ((NewCloud*)p)->cloudId)
        {
            break;
        }
    }
    p = lbl_8039A828[i];
    if (p == NULL || i == 8)
    {
        return 0;
    }
    if (cloudId != ((NewCloud*)p)->cloudId)
    {
        debugPrintf(sSnowPrintSnowCloudInvalidCloudId, cloudId);
        return 0;
    }
    lbl_803DD1A4 = lbl_803DF1FC * timeDelta + (f32)lbl_803DD1A4;
    if (lbl_803DD1A4 > 0xffff)
    {
        lbl_803DD1A4 = 0;
    }
    scale = scale * lbl_803DF200;
    initRotationMtx(mtxA, scale, scale, scale);
    memset(mtxB, 0, 0x40);
    mtxB[0] = lbl_803DF1A4;
    mtxB[5] = lbl_803DF1A4;
    mtxB[10] = lbl_803DF1A4;
    mtxB[15] = lbl_803DF1A4;
    if (((NewCloud*)p)->cloudType != 4 && p[0x1451] != 0)
    {
        mtxB[0] = mathCosf((lbl_803DF1F0 * (f32)lbl_803DD1A4) / lbl_803DF1F4);
        mtxB[1] = -mathSinf((lbl_803DF1F0 * (f32)lbl_803DD1A4) / lbl_803DF1F4);
        mtxB[4] = mathSinf((lbl_803DF1F0 * (f32)lbl_803DD1A4) / lbl_803DF1F4);
        mtxB[5] = mathCosf((lbl_803DF1F0 * (f32)lbl_803DD1A4) / lbl_803DF1F4);
    }
    else if (((NewCloud*)p)->cloudType == 4)
    {
        if (p[0x144a] & 0x80)
        {
            mtxB[0] = mathCosf(lbl_803DF204);
            mtxB[1] = -mathSinf(lbl_803DF204);
            mtxB[4] = mathSinf(lbl_803DF204);
            mtxB[5] = mathCosf(lbl_803DF204);
        }
        else if (p[0x1451] != 0)
        {
            lbl_803DD1A4 =
                lbl_803DF20C * (((NewCloud*)p)->unk1440 / lbl_803DF210) + lbl_803DF208;
            mtxB[0] = mathCosf((lbl_803DF1F0 * (f32) - lbl_803DD1A4) / lbl_803DF1F4);
            mtxB[1] = -mathSinf((lbl_803DF1F0 * (f32) - lbl_803DD1A4) / lbl_803DF1F4);
            mtxB[4] = mathSinf((lbl_803DF1F0 * (f32) - lbl_803DD1A4) / lbl_803DF1F4);
            mtxB[5] = mathCosf((lbl_803DF1F0 * (f32) - lbl_803DD1A4) / lbl_803DF1F4);
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
    selectTexture(((NewCloud*)p)->cloudType == 0 ? lbl_8039A818[0] : lbl_803DD1C4, 0);
    GXSetCullMode(0);
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
    GXSetVtxDesc(0, 1);
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xb, 1);
    GXSetVtxDesc(0xd, 1);
    GXSetCurrentMtx(0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(0xd, 1);
    hudHidden = getHudHiddenFrameCount();
    driftX = lbl_803DF1E4 * (((NewCloud*)p)->unk13E4 - ((NewCloud*)p)->unk13D8);
    stepX = (driftX < lbl_803DF214 * ((NewCloud*)p)->flakeMinX)
                ? lbl_803DF214 * ((NewCloud*)p)->flakeMinX
                : ((driftX > lbl_803DF214 * ((NewCloud*)p)->unk1390)
                       ? lbl_803DF214 * ((NewCloud*)p)->unk1390
                       : driftX);
    driftZ = lbl_803DF1E4 * (((NewCloud*)p)->unk13EC - ((NewCloud*)p)->unk13E0);
    stepZ = (driftZ < lbl_803DF214 * ((NewCloud*)p)->flakeMinZ)
                ? lbl_803DF214 * ((NewCloud*)p)->flakeMinZ
                : ((driftZ > lbl_803DF214 * ((NewCloud*)p)->flakeMaxZ)
                       ? lbl_803DF214 * ((NewCloud*)p)->flakeMaxZ
                       : driftZ);
    if (((NewCloud*)p)->cloudType == 4)
    {
        GXBegin(0x90, 4, (u16)(((NewCloud*)p)->flakeCount * 3));
    }
    else
    {
        GXBegin(0x90, 4, (u16)(((NewCloud*)p)->flakeCount * 3 / 4));
    }
    part = *(u8**)(p + 4);
    for (j = 0; j < ((NewCloud*)p)->flakeCount; j++)
    {
        if (part[0x16] != (u8)texIdx)
        {
            texIdx = part[0x16];
            selectTexture(lbl_8039A818[texIdx], 0);
            GXBegin(0x90, 4, (u16)(((NewCloud*)p)->flakeCount * 3 / 4));
        }
        if (hudHidden == 0)
        {
            if (p[0x144d] == 0)
            {
                *(f32*)part = *(f32*)part + stepX;
                *(f32*)(part + 8) = *(f32*)(part + 8) + stepZ;
            }
            *(f32*)part = ((NewCloud*)p)->windVelX * timeDelta + *(f32*)part;
            *(f32*)(part + 8) = ((NewCloud*)p)->windVelZ * timeDelta + *(f32*)(part + 8);
            if (*(f32*)part < ((NewCloud*)p)->flakeMinX)
            {
                *(f32*)part = lbl_803DF1C8 * ((NewCloud*)p)->unk1390 + *(f32*)part;
            }
            else if (*(f32*)part > ((NewCloud*)p)->unk1390)
            {
                *(f32*)part = *(f32*)part - lbl_803DF1C8 * ((NewCloud*)p)->unk1390;
            }
            if (*(f32*)(part + 8) < ((NewCloud*)p)->flakeMinZ)
            {
                *(f32*)(part + 8) =
                    lbl_803DF1C8 * ((NewCloud*)p)->flakeMaxZ + *(f32*)(part + 8);
            }
            else if (*(f32*)(part + 8) > ((NewCloud*)p)->flakeMaxZ)
            {
                *(f32*)(part + 8) =
                    *(f32*)(part + 8) - lbl_803DF1C8 * ((NewCloud*)p)->flakeMaxZ;
            }
        }
        yb = *(f32*)(part + 4) - *(f32*)(p + *(u16*)(part + 0x10) * 4 + 8);
        base = *(u16*)(part + 0x12) * 0x2c;
        size = *(f32*)(part + 0xc);
        vx[0] = *(f32*)(p + base + 0x1008) * size + *(f32*)part;
        vy[0] = *(f32*)(p + base + 0x1014) * size + yb;
        vz[0] = *(f32*)(p + base + 0x1020) * size + *(f32*)(part + 8);
        vx[1] = *(f32*)(p + base + 0x100c) * size + *(f32*)part;
        vy[1] = *(f32*)(p + base + 0x1018) * size + yb;
        vz[1] = *(f32*)(p + base + 0x1024) * size + *(f32*)(part + 8);
        vx[2] = *(f32*)(p + base + 0x1010) * size + *(f32*)part;
        vy[2] = *(f32*)(p + base + 0x101c) * size + yb;
        vz[2] = *(f32*)(p + base + 0x1028) * size + *(f32*)(part + 8);
        GXWGFifo.f32 = vx[0];
        GXWGFifo.f32 = vy[0];
        GXWGFifo.f32 = vz[0];
        GXWGFifo.s16 = uvs[0];
        GXWGFifo.s16 = uvs[1];
        GXWGFifo.f32 = vx[1];
        GXWGFifo.f32 = vy[1];
        GXWGFifo.f32 = vz[1];
        GXWGFifo.s16 = uvs[2];
        GXWGFifo.s16 = uvs[3];
        GXWGFifo.f32 = vx[2];
        GXWGFifo.f32 = vy[2];
        GXWGFifo.f32 = vz[2];
        GXWGFifo.s16 = uvs[4];
        GXWGFifo.s16 = uvs[5];
        part += 0x18;
    }
    return 0;
}

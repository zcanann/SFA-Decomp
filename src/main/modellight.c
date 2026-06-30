#include "main/game_object.h"
#include "main/dll/ivec3_struct.h"
#include "main/model_light.h"
#include "main/gameplay_runtime.h"
#include "main/mm.h"
#include "main/camera.h"
#include "main/texture.h"
#include "main/modellight.h"
#define GX_COLOR0 0
#define GX_DF_NONE 0
#define GX_FALSE 0
#define GX_SRC_REG 0
#define GX_COLOR1 1
#define GX_AF_NONE 2
#define GX_ALPHA0 2
#define GX_ALPHA1 3
#define GX_COLOR0A0 4
#define GX_COLOR1A1 5
#define GX_DA_MEDIUM 2

u16*
FUN_80017460(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
             , int param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    return 0;
}

u16*
FUN_80017468(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
             , u32 param_10, u32 param_11, u32 param_12, u32 param_13,
             u32 param_14, u32 param_15, u32 param_16)
{
    return 0;
}

extern f32 timeDelta;

u32
FUN_80017500(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, int param_9)
{
    return 0;
}

u32
FUN_8001786c(u64 param_1, double param_2, double param_3, u64 param_4, u64 param_5,
             u64 param_6, u64 param_7, u64 param_8, u32 param_9,
             u32 param_10, u32 param_11, u32 param_12)
{
    return 0;
}

u8*
FUN_80017998(u64 param_1, u64 param_2, u64 param_3, u64 param_4,
             u64 param_5, u64 param_6, u64 param_7, u64 param_8, u32 param_9
)
{
    return 0;
}

void objSetEventName(u8* obj, void* name)
{
    ((GameObject*)obj)->anim.eventTable = name;
}

void modelLightStruct_setGlowProjectionRadius(ModelLightStruct* light, f32 radius)
{
    light->glowProjectionRadius = radius;
}

f32* modelLightStruct_getProjectionTexMtx(ModelLightStruct* p)
{
    return p->projectionTexMtx;
}

void* modelLightStruct_getProjectionTexture(ModelLightStruct* p)
{
    return p->projectionTexture;
}

void modelLightStruct_setProjectionTexture(ModelLightStruct* p, void* v)
{
    p->projectionTexture = v;
}

int modelLightStruct_getProjectedLightChannelPreference(ModelLightStruct* p)
{
    return p->projectedLightChannelPreference;
}

void modelLightStruct_setProjectedLightChannelPreference(ModelLightStruct* p, int v)
{
    p->projectedLightChannelPreference = v;
}

void modelLightStruct_setSelectionPriority(ModelLightStruct* p, u8 v)
{
    p->selectionPriority = v;
}

int modelLightStruct_getActiveState(ModelLightStruct* p)
{
    return p->activeState;
}

f32 modelLightStruct_getRadius(ModelLightStruct* p)
{
    return p->attenuationFar;
}

void modelLightStruct_setAffectsAabbLightSelection(ModelLightStruct* p, u8 v)
{
    p->affectsAabbLightSelection = v;
}

void lightSetField4D(ModelLightStruct* p, u8 v)
{
    p->field4D = v;
}

void lightSetFieldBC_8001db14(ModelLightStruct* p, u8 v)
{
    p->fieldBC = v;
}

void modelLightStruct_setLightKind(ModelLightStruct* p, int v)
{
    p->lightKind = v;
}

extern u8 gModelLightCount;
extern void* gModelLightList[];

extern void GXInitLightDistAttn(u8* lt_obj, f32 ref_dist, f32 ref_br, int dist_func);
extern void GXGetLightAttnK(u8 * lt_obj, f32 * k0, f32 * k1, f32 * k2);
extern void GXInitLightAttnA(u8* lt_obj, f32 a0, f32 a1, f32 a2);
extern void GXInitLightAttn(u8* lt_obj, f32 a0, f32 a1, f32 a2, f32 k0, f32 k1, f32 k2);
extern void* memset(void* dst, int val, int n);
extern void PSMTXMultVec(f32 * mtx, f32 * in, f32 * out);
extern void PSMTXMultVecSR(f32 * mtx, f32 * in, f32 * out);
extern void Vec_normalize(f32 * dst, f32 * src);
extern void Obj_TransformLocalPointByWorldMatrix(u8* obj, f32* src, f32* dst, u8 flag);
extern void Obj_TransformLocalVectorByWorldMatrix(void* obj, f32* src, f32* dst);
extern void Obj_BuildInverseWorldTransformMatrix(u8* obj, f32* out);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803DE750;
extern f32 lbl_803DE754;
extern f32 lbl_803DE758;
extern f32 lbl_803DE760;
extern f32 lbl_803DE75C;
extern f32 lbl_803DE76C;
extern f32 lbl_803DE790;
extern f32 lbl_803DE79C;
extern f32 lbl_803DE7A0;

void* objCreateLight(int arg, u8 addToList)
{
    void* light;
    if (addToList)
    {
        if (gModelLightCount >= 0x32)
        {
            return NULL;
        }
        light = objAllocLight((void*)arg);
        if (light == NULL)
        {
            return NULL;
        }
        {
            int i = gModelLightCount++;
            gModelLightList[i] = light;
        }
        return light;
    }
    light = objAllocLight((void*)arg);
    if (light != NULL)
    {
        return light;
    }
    return NULL;
}

void modelLightStruct_freeSlot(void** lightSlot)
{
    int i;
    int count;
    ModelLightStruct* light;

    light = *lightSlot;
    if (light != NULL)
    {
        for (i = 0; i < (count = gModelLightCount); i++)
        {
            if (gModelLightList[i] == light)
            {
                break;
            }
        }

        if (i < count)
        {
            while (i < count - 1)
            {
                gModelLightList[i] = gModelLightList[i + 1];
                i++;
            }
            gModelLightCount--;
        }

        if (light->glowType == 2 && light->glowTexture != NULL)
        {
            textureFree(light->glowTexture);
        }
        mm_free(light);
        *lightSlot = NULL;
    }
}

void ModelLightStruct_free(ModelLightStruct* light)
{
    int count;
    int i;

    for (i = 0; i < (count = gModelLightCount); i++)
    {
        if (gModelLightList[i] == light)
        {
            break;
        }
    }

    if (i < count)
    {
        while (i < count - 1)
        {
            gModelLightList[i] = gModelLightList[i + 1];
            i++;
        }
        gModelLightCount--;
    }

    if (light->glowType == 2 && light->glowTexture != NULL)
    {
        textureFree(light->glowTexture);
    }
    mm_free(light);
}

void* modelLightStruct_createPointLight(int unused, u8 red, u8 green, u8 blue, u8 setFlag)
{
    u8* light;
    u8* newLight;

    if (gModelLightCount >= 0x32)
    {
        light = NULL;
    }
    else
    {
        newLight = objAllocLight((void*)unused);
        if (newLight == NULL)
        {
            light = NULL;
        }
        else
        {
            int index = gModelLightCount++;
            gModelLightList[index] = newLight;
            light = newLight;
        }
    }

    if (light != NULL)
    {
        ((ModelLightStruct*)light)->lightKind = 2;
        light[0xac] = red;
        light[0xa8] = red;
        light[0xad] = green;
        light[0xa9] = green;
        light[0xae] = blue;
        light[0xaa] = blue;
        light[0xaf] = 0;
        light[0xab] = 0;
        light[0xbc] = 1;
        ((ModelLightStruct*)light)->attenuationNear = lbl_803DE750;
        ((ModelLightStruct*)light)->attenuationFar = lbl_803DE754;
        GXInitLightDistAttn(light + 0x68, ((ModelLightStruct*)light)->attenuationNear, lbl_803DE758, GX_DA_MEDIUM);
        GXGetLightAttnK(light + 0x68, (f32*)(light + 0x124), (f32*)(light + 0x128),
                        (f32*)(light + 0x12c));
        if (setFlag != 0)
        {
            light[0x2fb] = 1;
        }
    }

    return light;
}

void* objAllocLight(void* owner)
{
    u8* light;
    f32 tmp[3];
    f32* view;
    f32 zero;
    f32 atten;

    light = mmAlloc(0x300, 0x1a, 0);
    if (light == NULL)
    {
        return NULL;
    }

    memset(light, 0, 0x300);
    *(void**)light = owner;

    if (*(void**)light != NULL)
    {
        zero = lbl_803DE75C;
        ((ModelLightStruct*)light)->localX = zero;
        ((ModelLightStruct*)light)->localY = zero;
        ((ModelLightStruct*)light)->localZ = zero;
        Obj_TransformLocalPointByWorldMatrix(*(u8**)light, (f32*)(light + 4), (f32*)(light + 0x10), 1);
    }
    else
    {
        zero = lbl_803DE75C;
        ((ModelLightStruct*)light)->worldX = zero;
        ((ModelLightStruct*)light)->worldY = zero;
        ((ModelLightStruct*)light)->worldZ = zero;
    }

    view = Camera_GetViewMatrix();
    if (((ModelLightStruct*)light)->transformMode == 0)
    {
        tmp[0] = ((ModelLightStruct*)light)->worldX - playerMapOffsetX;
        tmp[1] = ((ModelLightStruct*)light)->worldY;
        tmp[2] = ((ModelLightStruct*)light)->worldZ - playerMapOffsetZ;
        PSMTXMultVec(view, tmp, (f32*)(light + 0x1c));
    }
    else
    {
        *(IVec3*)(light + 0x1c) = *(IVec3*)(light + 0x10);
    }

    if (*(void**)light != NULL)
    {
        zero = lbl_803DE75C;
        ((ModelLightStruct*)light)->localDirX = zero;
        ((ModelLightStruct*)light)->localDirY = zero;
        ((ModelLightStruct*)light)->localDirZ = lbl_803DE760;
        Vec_normalize((f32*)(light + 0x28), (f32*)(light + 0x28));
        Obj_TransformLocalVectorByWorldMatrix(*(void**)light, (f32*)(light + 0x28), (f32*)(light + 0x34));
    }
    else
    {
        zero = lbl_803DE75C;
        ((ModelLightStruct*)light)->worldDirX = zero;
        ((ModelLightStruct*)light)->worldDirY = zero;
        ((ModelLightStruct*)light)->worldDirZ = lbl_803DE760;
        Vec_normalize((f32*)(light + 0x34), (f32*)(light + 0x34));
    }

    view = Camera_GetViewMatrix();
    if (((ModelLightStruct*)light)->transformMode == 0)
    {
        PSMTXMultVecSR(view, (f32*)(light + 0x34), (f32*)(light + 0x40));
    }
    else
    {
        *(IVec3*)(light + 0x40) = *(IVec3*)(light + 0x34);
    }

    modelLightStruct_setEnabled((ModelLightStruct*)light, 1, lbl_803DE75C);
    ((ModelLightStruct*)light)->lightKind = 4;
    ((ModelLightStruct*)light)->projectedLightChannelPreference = 1;
    ((ModelLightStruct*)light)->attenuationNear = lbl_803DE750;
    ((ModelLightStruct*)light)->attenuationFar = lbl_803DE754;
    GXInitLightDistAttn(light + 0x68, ((ModelLightStruct*)light)->attenuationNear, lbl_803DE758, GX_DA_MEDIUM);
    GXGetLightAttnK(light + 0x68, (f32*)(light + 0x124), (f32*)(light + 0x128), (f32*)(light + 0x12c));
    zero = lbl_803DE75C;
    ((ModelLightStruct*)light)->attenuationFar = zero;
    light[0x2fc] = 0x7f;
    ((ModelLightStruct*)light)->objectLightMaskIndex = 0;
    light[0x64] = 1;
    ((ModelLightStruct*)light)->transformMode = 0;
    light[0x4d] = 0;
    light[0xbc] = 0;
    light[0xac] = 0xff;
    light[0xa8] = 0xff;
    light[0xad] = 0xff;
    light[0xa9] = 0xff;
    light[0xae] = 0xff;
    light[0xaa] = 0xff;
    light[0xaf] = 0xff;
    light[0xab] = 0xff;
    ((ModelLightStruct*)light)->spotCutoff = lbl_803DE79C;
    ((ModelLightStruct*)light)->spotFunction = 0;
    GXInitLightAttnA(light + 0x68, lbl_803DE760, zero, zero);
    light[0x114] = 0;
    light[0x104] = 0xff;
    light[0x100] = 0xff;
    light[0x105] = 0xff;
    light[0x101] = 0xff;
    light[0x106] = 0xff;
    light[0x102] = 0xff;
    light[0x107] = 0xff;
    light[0x103] = 0xff;
    ((ModelLightStruct*)light)->specularAttenuationScale = lbl_803DE7A0;
    ((ModelLightStruct*)light)->specularBrightness = lbl_803DE76C;
    atten = ((ModelLightStruct*)light)->specularAttenuationScale * lbl_803DE790;
    zero = lbl_803DE75C;
    GXInitLightAttn(light + 0xc0, zero, zero, lbl_803DE760, atten, zero,
                    *(f32*)&lbl_803DE760 - atten);
    modelLightStruct_startColorFade((ModelLightStruct*)light, 0, 0);
    light[0xb0] = 0xff;
    light[0xb1] = 0xff;
    light[0xb2] = 0xff;
    light[0xb3] = 0xff;
    light[0x108] = 0xff;
    light[0x109] = 0xff;
    light[0x10a] = 0xff;
    light[0x10b] = 0xff;
    if (*(void**)light != NULL)
    {
        Obj_BuildInverseWorldTransformMatrix(*(u8**)light, (f32*)(light + 0x170));
    }
    atten = lbl_803DE760;
    ((ModelLightStruct*)light)->lightAmount = atten;
    ((ModelLightStruct*)light)->attenuationK0 = atten;
    zero = lbl_803DE75C;
    ((ModelLightStruct*)light)->attenuationK1 = zero;
    ((ModelLightStruct*)light)->attenuationK2 = zero;
    return light;
}

void modelLightStruct_setProjectionTevModes(ModelLightStruct* p, void* a, void* b)
{
    p->projectionTevColorMode = (int)a;
    p->projectionTevAlphaMode = (int)b;
}

extern u8 gModelLightColorTable;

void modelLightStruct_setGlowColor(ModelLightStruct* light, u8 red, u8 green, u8 blue, u8 alpha)
{
    light->glowColor[0] = red;
    light->glowColor[1] = green;
    light->glowColor[2] = blue;
    light->glowColor[3] = alpha;
}

void modelLightStruct_getProjectionTevModes(ModelLightStruct* p, void** a, void** b)
{
    *a = (void*)p->projectionTevColorMode;
    *b = (void*)p->projectionTevAlphaMode;
}

void modelLightStruct_setSpecularTargetColor(ModelLightStruct* p, u8 a, u8 b, u8 c, u8 d)
{
    p->specularFadeTargetColor[0] = a;
    p->specularFadeTargetColor[1] = b;
    p->specularFadeTargetColor[2] = c;
    p->specularFadeTargetColor[3] = d;
}

void modelLightStruct_setDiffuseTargetColor(ModelLightStruct* p, u8 a, u8 b, u8 c, u8 d)
{
    p->diffuseFadeTargetColor[0] = a;
    p->diffuseFadeTargetColor[1] = b;
    p->diffuseFadeTargetColor[2] = c;
    p->diffuseFadeTargetColor[3] = d;
}

void modelLightStruct_getPosition(ModelLightStruct* p, f32* a, f32* b, f32* c)
{
    *a = p->viewX;
    *b = p->viewY;
    *c = p->viewZ;
}

void modelLightStruct_getWorldPosition(ModelLightStruct* p, f32* a, f32* b, f32* c)
{
    *a = p->worldX;
    *b = p->worldY;
    *c = p->worldZ;
}

void lightSetColor(int i, u8 a, u8 b, u8 c)
{
    u8* base = &gModelLightColorTable;
    base[i * 4] = a;
    base[i * 4 + 1] = b;
    base[i * 4 + 2] = c;
}

void modelLightStruct_setObjectLightMaskIndex(ModelLightStruct* p, int n)
{
    p->objectLightMaskIndex = n;
    p->objectLightMask = (u8)(1 << n);
}

extern f32 lbl_803DE764;
extern f32 lbl_803DE778;
extern f32 lbl_803DE78C;
extern f32 lbl_803DE788;
extern f32 lbl_803DE794;
extern f32 lbl_803DE798;

void modelLightStruct_getSpecularColor(ModelLightStruct* p, u8* a, u8* b, u8* c, u8* d)
{
    *a = p->specularColor[0];
    *b = p->specularColor[1];
    *c = p->specularColor[2];
    *d = p->specularColor[3];
}

void modelLightStruct_getDiffuseColor(ModelLightStruct* p, u8* a, u8* b, u8* c, u8* d)
{
    *a = p->diffuseColor[0];
    *b = p->diffuseColor[1];
    *c = p->diffuseColor[2];
    *d = p->diffuseColor[3];
}

void modelLightStruct_setAngularAttenuation(ModelLightStruct* p, f32 a, f32 b, f32 c)
{
    GXInitLightAttnA((u8*)p + 0x68, a, b, c);
}

void modelLightStruct_setSpecularColor(ModelLightStruct* p, u8 a, u8 b, u8 c, u8 d)
{
    p->specularFadeStartColor[0] = a;
    p->specularColor[0] = a;
    p->specularFadeStartColor[1] = b;
    p->specularColor[1] = b;
    p->specularFadeStartColor[2] = c;
    p->specularColor[2] = c;
    p->specularFadeStartColor[3] = d;
    p->specularColor[3] = d;
}

void modelLightStruct_setDiffuseColor(ModelLightStruct* p, u8 a, u8 b, u8 c, u8 d)
{
    p->diffuseFadeStartColor[0] = a;
    p->diffuseColor[0] = a;
    p->diffuseFadeStartColor[1] = b;
    p->diffuseColor[1] = b;
    p->diffuseFadeStartColor[2] = c;
    p->diffuseColor[2] = c;
    p->diffuseFadeStartColor[3] = d;
    p->diffuseColor[3] = d;
}

void lightGetColor(int i, u8* a, u8* b, u8* c)
{
    u8* base = &gModelLightColorTable;
    *a = base[i * 4];
    *b = base[i * 4 + 1];
    *c = base[i * 4 + 2];
}

void modelLightStruct_updateColorFade(ModelLightStruct* light)
{
    f32 progress;
    int mode;

    mode = light->colorFadeMode;
    switch (mode)
    {
    case 1:
        light->colorFadeTimer += light->colorFadeStep * timeDelta;
        if (light->colorFadeTimer >= lbl_803DE760)
        {
            light->colorFadeProgress = randomGetRange(0, 100) / lbl_803DE778;
            light->colorFadeTimer = lbl_803DE75C;
        }
        break;
    case 2:
        light->colorFadeProgress += light->colorFadeStep * timeDelta;
        break;
    }

    progress = light->colorFadeProgress;
    if (progress > lbl_803DE760)
    {
        light->colorFadeProgress = lbl_803DE760 - (progress - lbl_803DE760);
        light->colorFadeStep = -light->colorFadeStep;
    }
    else if (progress < lbl_803DE75C)
    {
        light->colorFadeProgress = -progress;
        light->colorFadeStep = -light->colorFadeStep;
    }

    light->diffuseColor[0] = (light->colorFadeProgress * (f32)(
        light->diffuseFadeTargetColor[0] - light->diffuseFadeStartColor[0]) + light->diffuseFadeStartColor[0]);
    light->diffuseColor[1] = (light->colorFadeProgress * (f32)(
        light->diffuseFadeTargetColor[1] - light->diffuseFadeStartColor[1]) + light->diffuseFadeStartColor[1]);
    light->diffuseColor[2] = (light->colorFadeProgress * (f32)(
        light->diffuseFadeTargetColor[2] - light->diffuseFadeStartColor[2]) + light->diffuseFadeStartColor[2]);
    light->diffuseColor[3] = (light->colorFadeProgress * (f32)(
        light->diffuseFadeTargetColor[3] - light->diffuseFadeStartColor[3]) + light->diffuseFadeStartColor[3]);

    light->diffuseColor[0] = ((f32)light->diffuseColor[0] * light->activeIntensity);
    light->diffuseColor[1] = ((f32)light->diffuseColor[1] * light->activeIntensity);
    light->diffuseColor[2] = ((f32)light->diffuseColor[2] * light->activeIntensity);
    light->diffuseColor[3] = ((f32)light->diffuseColor[3] * light->activeIntensity);

    light->specularColor[0] = (light->colorFadeProgress * (f32)(
        light->specularFadeTargetColor[0] - light->specularFadeStartColor[0]) + light->specularFadeStartColor[0]);
    light->specularColor[1] = (light->colorFadeProgress * (f32)(
        light->specularFadeTargetColor[1] - light->specularFadeStartColor[1]) + light->specularFadeStartColor[1]);
    light->specularColor[2] = (light->colorFadeProgress * (f32)(
        light->specularFadeTargetColor[2] - light->specularFadeStartColor[2]) + light->specularFadeStartColor[2]);
    light->specularColor[3] = (light->colorFadeProgress * (f32)(
        light->specularFadeTargetColor[3] - light->specularFadeStartColor[3]) + light->specularFadeStartColor[3]);

    light->specularColor[0] = ((f32)light->specularColor[0] * light->activeIntensity);
    light->specularColor[1] = ((f32)light->specularColor[1] * light->activeIntensity);
    light->specularColor[2] = ((f32)light->specularColor[2] * light->activeIntensity);
    light->specularColor[3] = ((f32)light->specularColor[3] * light->activeIntensity);
}

void modelLightStruct_startColorFade(ModelLightStruct* light, int mode, s16 frames)
{
    f32 denom;

    light->colorFadeMode = mode;
    if (mode != 0)
    {
        if (frames != 0)
        {
            denom = frames;
        }
        else
        {
            denom = lbl_803DE760;
        }
        light->colorFadeStep = lbl_803DE760 / denom;
        light->diffuseFadeStartColor[0] = light->diffuseColor[0];
        light->diffuseFadeStartColor[1] = light->diffuseColor[1];
        light->diffuseFadeStartColor[2] = light->diffuseColor[2];
        light->specularFadeStartColor[0] = light->specularColor[0];
        light->specularFadeStartColor[1] = light->specularColor[1];
        light->specularFadeStartColor[2] = light->specularColor[2];
        denom = lbl_803DE75C;
        light->colorFadeProgress = denom;
        light->colorFadeTimer = denom;
    }
}

void modelLightStruct_setupGlow(ModelLightStruct* light, u32 textureId, u8 red, u8 green, u8 blue, u8 alpha, f32 scale)
{
    void* texture;

    if (textureId != 0)
    {
        texture = textureLoadAsset(textureId);
        light->glowTexture = texture;
        if (texture != NULL)
        {
            light->glowType = 2;
        }
    }
    else
    {
        texture = textureLoadAsset(0x605);
        light->glowTexture = texture;
        if (texture != NULL)
        {
            light->glowType = 2;
        }
    }
    light->glowColor[0] = red;
    light->glowColor[1] = green;
    light->glowColor[2] = blue;
    light->glowColor[3] = alpha;
    light->glowScale = scale;
    light->glowAlpha = 0;
    light->glowAlphaStep = 0;
    light->glowProjectionRadius = lbl_803DE788 * light->glowScale;
}

void modelLightStruct_setEnabled(ModelLightStruct* light, u8 enabled, f32 duration)
{
    f32 zero;

    zero = lbl_803DE75C;
    if (zero == duration)
    {
        if (enabled != 0)
        {
            light->activeState = 2;
            light->activeIntensity = lbl_803DE760;
        }
        else
        {
            light->activeState = 0;
            light->activeIntensity = zero;
        }
        light->enabled = enabled;
        return;
    }

    if (enabled != 0)
    {
        if (light->activeState == 0 || light->activeState == 3)
        {
            light->activeState = 1;
            light->activeIntensityStep = lbl_803DE760 / (lbl_803DE794 * duration);
            light->activeIntensity = lbl_803DE75C;
        }
        light->enabled = 1;
        return;
    }

    if (light->activeState != 2 && light->activeState != 1)
    {
        return;
    }
    light->activeState = 3;
    light->activeIntensityStep = lbl_803DE798 / (lbl_803DE794 * duration);
    light->activeIntensity = lbl_803DE760;
}

void modelLightStruct_setProjectionFarZ(ModelLightStruct* p, f32 v)
{
    p->projectionFarZ = (v < p->projectionNearZ) ? p->projectionNearZ : ((v > lbl_803DE764) ? lbl_803DE764 : v);
}

void modelLightStruct_setProjectionNearZ(ModelLightStruct* p, f32 v)
{
    p->projectionNearZ = (v < lbl_803DE78C) ? lbl_803DE78C : ((v > p->projectionFarZ) ? p->projectionFarZ : v);
}

extern u8 gModelLightUseModelRelativePositions;
extern int gModelLightNextGXLightId;

typedef struct
{
    u8 active;
    u8 _1[3];
    int lightMask;
    int mode;
    int matSrc;
} ModelLightChannelState;

extern ModelLightChannelState gModelLightChannelStates[];


void modelLightChannel_configure(int i, int a, int b)
{
    gModelLightChannelStates[i].mode = a;
    gModelLightChannelStates[i].lightMask = 0;
    gModelLightChannelStates[i].matSrc = b;
    gModelLightChannelStates[i].active = 1;
}

void modelLightChannels_reset(u8 v)
{
    gModelLightUseModelRelativePositions = v;
    gModelLightNextGXLightId = 1;
    gModelLightChannelStates[0].active = 0;
    gModelLightChannelStates[1].active = 0;
    gModelLightChannelStates[2].active = 0;
    gModelLightChannelStates[3].active = 0;
    gModelLightChannelStates[4].active = 0;
    gModelLightChannelStates[5].active = 0;
}

typedef f32 Mtx[3][4];
extern void PSVECSubtract(f32 * a, f32 * b, f32 * out);
extern void PSVECNormalize(f32 * src, f32 * dst);

void Obj_TransformLocalVectorByWorldMatrix(void* obj, f32* src, f32* dst);

void Obj_TransformLocalPointByWorldMatrix(u8* obj, f32* src, f32* dst, u8 flag);

void modelLightStruct_setDirection(ModelLightStruct* s, f32 x, f32 y, f32 z)
{
    f32* view;
    if (s->owner != NULL)
    {
        s->localDirX = x;
        s->localDirY = y;
        s->localDirZ = z;
        Vec_normalize(&s->localDirX, &s->localDirX);
        Obj_TransformLocalVectorByWorldMatrix(s->owner, &s->localDirX, &s->worldDirX);
    }
    else
    {
        s->worldDirX = x;
        s->worldDirY = y;
        s->worldDirZ = z;
        Vec_normalize(&s->worldDirX, &s->worldDirX);
    }
    view = Camera_GetViewMatrix();
    if (s->transformMode == 0)
    {
        PSMTXMultVecSR(view, &s->worldDirX, &s->viewDirX);
    }
    else
    {
        {
            
            *(IVec3*)&s->viewDirX = *(IVec3*)&s->worldDirX;
        }
    }
}

void modelLightStruct_setPosition(ModelLightStruct* s, f32 x, f32 y, f32 z)
{
    f32 tmp[3];
    f32* view;
    if (s->owner != NULL)
    {
        s->localX = x;
        s->localY = y;
        s->localZ = z;
        Obj_TransformLocalPointByWorldMatrix(s->owner, &s->localX, &s->worldX, 1);
    }
    else
    {
        s->worldX = x;
        s->worldY = y;
        s->worldZ = z;
    }
    view = Camera_GetViewMatrix();
    if (s->transformMode == 0)
    {
        tmp[0] = s->worldX - playerMapOffsetX;
        tmp[1] = s->worldY;
        tmp[2] = s->worldZ - playerMapOffsetZ;
        PSMTXMultVec(view, tmp, &s->viewX);
    }
    else
    {
        {
            
            *(IVec3*)&s->viewX = *(IVec3*)&s->worldX;
        }
    }
}

extern void GXInitSpecularDir(u8* lt_obj, f32 x, f32 y, f32 z);
extern void GXInitLightColor(u8* lt_obj, void* color);
extern void GXLoadLightObjImm(u8* lt_obj, int lightId);
extern void GXInitLightPos(u8* lt_obj, f32 x, f32 y, f32 z);
extern void GXInitLightDir(u8* lt_obj, f32 x, f32 y, f32 z);
extern void GXInitLightAttnK(u8* lt_obj, f32 k0, f32 k1, f32 k2);
extern void GXSetChanCtrl(int channel, int enable, int ambSrc, int matSrc, int lightMask, int diffFn,
                          int attnFn);
extern void GXSetNumChans(u8 nChans);
extern void PSVECScale(f32* src, f32* dst, f32 scale);
extern void PSVECAdd(f32 * a, f32 * b, f32 * out);
extern f32 lbl_803DE7A4;
extern f32* Camera_GetInverseViewMatrix(void);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * ab);

void modelLightStruct_loadDiffuseGXLight(u8* light, u8* obj, int lightId)
{
    f32 viewPos[3];
    f32* view;
    int lightType;

    view = Camera_GetViewMatrix();
    lightType = ((ModelLightStruct*)light)->lightKind;
    switch (lightType)
    {
    case 2:
    case 8:
        if (gModelLightUseModelRelativePositions != 0)
        {
            f32 worldPos[3];
            if (((ModelLightStruct*)light)->transformMode == 0)
            {
                worldPos[0] = ((GameObject*)obj)->anim.localPosX - playerMapOffsetX;
                worldPos[1] = ((GameObject*)obj)->anim.localPosY;
                worldPos[2] = ((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ;
                PSMTXMultVec(view, worldPos, viewPos);
            }
            else
            {
                *(IVec3*)viewPos = *(IVec3*)(obj + 0xc);
            }
            PSVECSubtract(&((ModelLightStruct*)light)->viewX, viewPos, viewPos);
            GXInitLightPos(light + 0x68, viewPos[0], viewPos[1], viewPos[2]);
        }
        else
        {
            GXInitLightPos(light + 0x68, ((ModelLightStruct*)light)->viewX, ((ModelLightStruct*)light)->viewY,
                           ((ModelLightStruct*)light)->viewZ);
        }
        GXInitLightDir(light + 0x68, ((ModelLightStruct*)light)->viewDirX, ((ModelLightStruct*)light)->viewDirY,
                       ((ModelLightStruct*)light)->viewDirZ);
        if (obj != NULL && (((ObjAnimComponent*)obj)->modelInstance->flags & 0x10) == 0)
        {
            u8 rgba[4];
            u32 color;
            f32 amt;
            rgba[0] = light[0xa8] * (amt = ((ModelLightStruct*)light)->lightAmount);
            rgba[1] = light[0xa9] * amt;
            rgba[2] = light[0xaa] * amt;
            rgba[3] = light[0xab] * amt;
            color = *(u32*)rgba;
            GXInitLightColor(light + 0x68, &color);
            GXInitLightAttnK(light + 0x68, lbl_803DE760, lbl_803DE75C, *(f32*)&lbl_803DE75C);
        }
        else
        {
            u32 color;
            color = *(u32*)(light + 0xa8);
            GXInitLightColor(light + 0x68, &color);
            GXInitLightAttnK(light + 0x68, ((ModelLightStruct*)light)->attenuationK0, ((ModelLightStruct*)light)->attenuationK1,
                             ((ModelLightStruct*)light)->attenuationK2);
        }
        break;
    case 4:
        {
            f32 worldPos[3];
            u32 color;
            if (obj != NULL)
            {
                if (((ModelLightStruct*)light)->transformMode == 0)
                {
                    worldPos[0] = ((GameObject*)obj)->anim.localPosX - playerMapOffsetX;
                    worldPos[1] = ((GameObject*)obj)->anim.localPosY;
                    worldPos[2] = ((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ;
                    PSMTXMultVec(view, worldPos, viewPos);
                }
                else
                {
                    *(IVec3*)viewPos = *(IVec3*)(obj + 0xc);
                }
            }
            else
            {
                viewPos[0] = lbl_803DE75C;
                viewPos[1] = lbl_803DE75C;
                viewPos[2] = lbl_803DE75C;
            }
            PSVECScale((f32*)(light + 0x40), (f32*)(light + 0x1c), lbl_803DE7A4);
            PSVECAdd((f32*)(light + 0x1c), viewPos, viewPos);
            GXInitLightPos(light + 0x68, viewPos[0], viewPos[1], viewPos[2]);
            color = *(u32*)(light + 0xa8);
            GXInitLightColor(light + 0x68, &color);
            GXInitLightAttnK(light + 0x68, lbl_803DE760, lbl_803DE75C, *(f32*)&lbl_803DE75C);
            break;
        }
    }
    GXLoadLightObjImm(light + 0x68, lightId);
}

void modelLightStruct_loadChannelLight(int channel, u8* light, u8* obj)
{
    f32 viewDir[3];
    f32 localDir[3];
    u32 color;
    int lightId;
    f32* view;
    int lightType;

    if (gModelLightChannelStates[channel].mode == 0 || gModelLightChannelStates[channel].mode == 2)
    {
        modelLightStruct_loadDiffuseGXLight(light, obj, gModelLightNextGXLightId);
    }
    else
    {
        lightId = gModelLightNextGXLightId;
        view = Camera_GetViewMatrix();
        lightType = ((ModelLightStruct*)light)->lightKind;
        switch (lightType)
        {
        case 2:
            PSVECSubtract(&((GameObject*)obj)->anim.localPosX, (f32*)(light + 0x10), localDir);
            PSVECNormalize(localDir, localDir);
            if (((ModelLightStruct*)light)->transformMode == 0)
            {
                PSMTXMultVecSR(view, localDir, viewDir);
            }
            else
            {
                
                *(IVec3*)viewDir = *(IVec3*)localDir;
            }
            GXInitSpecularDir(light + 0xc0, viewDir[0], viewDir[1], viewDir[2]);
            break;
        case 3:
            break;
        case 4:
            GXInitSpecularDir(light + 0xc0, ((ModelLightStruct*)light)->viewDirX, ((ModelLightStruct*)light)->viewDirY,
                              ((ModelLightStruct*)light)->viewDirZ);
            break;
        }
        color = *(u32*)(light + 0x100);
        GXInitLightColor(light + 0xc0, &color);
        GXLoadLightObjImm(light + 0xc0, lightId);
    }
    gModelLightChannelStates[channel].lightMask |= gModelLightNextGXLightId;
    gModelLightNextGXLightId <<= 1;
}

#pragma optimization_level 2
void modelLightChannels_applyGXControls(void)
{
    ModelLightChannelState* entry;
    int channel;
    u8 activeMask;
    int lightMask;
    int attnFn;

    activeMask = 0;
    channel = 0;
    entry = gModelLightChannelStates;
    do
    {
        if (entry->active != 0)
        {
            if (entry->mode == 0)
            {
                lightMask = entry->lightMask;
                attnFn = lightMask != 0 ? 1 : 2;
                GXSetChanCtrl(channel, lightMask != 0, GX_SRC_REG, entry->matSrc, lightMask, lightMask != 0 ? 2 : 0,
                              attnFn);
            }
            else if (entry->mode == 2)
            {
                lightMask = entry->lightMask;
                attnFn = lightMask != 0 ? 1 : 2;
                GXSetChanCtrl(channel, lightMask != 0, GX_SRC_REG, entry->matSrc, lightMask, GX_DF_NONE, attnFn);
            }
            else
            {
                lightMask = entry->lightMask;
                attnFn = lightMask != 0 ? 0 : 2;
                GXSetChanCtrl(channel, lightMask != 0, GX_SRC_REG, entry->matSrc, lightMask, GX_DF_NONE, attnFn);
            }
            activeMask = (activeMask | (1 << channel)) & 0xff;
        }
        entry++;
        channel++;
    }
    while (channel <= 5);

    activeMask &= 0xff;

    if ((activeMask & 1) != 0 && (activeMask & 4) == 0)
    {
        GXSetChanCtrl(GX_ALPHA0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
    }
    else if ((activeMask & 1) == 0 && (activeMask & 4) != 0)
    {
        GXSetChanCtrl(GX_COLOR0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
    }

    if ((activeMask & 2) != 0 && (activeMask & 8) == 0)
    {
        GXSetChanCtrl(GX_ALPHA1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
    }
    else if ((activeMask & 2) == 0 && (activeMask & 8) != 0)
    {
        GXSetChanCtrl(GX_COLOR1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
    }

    if ((activeMask & 0x2a) != 0)
    {
        GXSetNumChans(2);
    }
    else if ((activeMask & 0x15) != 0)
    {
        GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
        GXSetNumChans(1);
    }
    else
    {
        GXSetChanCtrl(GX_COLOR0A0, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
        GXSetChanCtrl(GX_COLOR1A1, GX_FALSE, GX_SRC_REG, GX_SRC_REG, 0, GX_DF_NONE, GX_AF_NONE);
        GXSetNumChans(0);
    }
}
#pragma optimization_level reset

void updateLights(void)
{
    f32 viewPos[3];
    f32 concatMtx[16];
    u8* light;
    f32* view;
    int i;
    int fadeState;

    view = Camera_GetViewMatrix();
    for (i = 0; i < gModelLightCount; i++)
    {
        light = gModelLightList[i];
        fadeState = ((ModelLightStruct*)light)->activeState;
        if (fadeState == 1)
        {
            ((ModelLightStruct*)light)->activeIntensity += ((ModelLightStruct*)light)->activeIntensityStep;
            if (((ModelLightStruct*)light)->activeIntensity >= lbl_803DE760)
            {
                ((ModelLightStruct*)light)->activeIntensity = *(f32*)&lbl_803DE760;
                ((ModelLightStruct*)light)->activeState = 2;
            }
        }
        else if (fadeState == 3)
        {
            ((ModelLightStruct*)light)->activeIntensity += ((ModelLightStruct*)light)->activeIntensityStep;
            if (((ModelLightStruct*)light)->activeIntensity <= lbl_803DE788)
            {
                ((ModelLightStruct*)light)->activeIntensity = *(f32*)&lbl_803DE788;
                ((ModelLightStruct*)light)->activeState = 0;
                light[0x4c] = 0;
            }
        }

        if (light[0x4c] != 0)
        {
            if (((ModelLightStruct*)light)->lightKind != 4)
            {
                if (*(void**)light != NULL)
                {
                    Obj_TransformLocalPointByWorldMatrix(*(u8**)light, (f32*)(light + 4), (f32*)(light + 0x10),
                                                         1);
                }
                if (((ModelLightStruct*)light)->transformMode == 0)
                {
                    viewPos[0] = ((ModelLightStruct*)light)->worldX - playerMapOffsetX;
                    viewPos[1] = ((ModelLightStruct*)light)->worldY;
                    viewPos[2] = ((ModelLightStruct*)light)->worldZ - playerMapOffsetZ;
                    PSMTXMultVec(view, viewPos, (f32*)(light + 0x1c));
                }
                else
                {
                    *(IVec3*)(light + 0x1c) = *(IVec3*)(light + 0x10);
                }
            }

            if (*(void**)light != NULL)
            {
                Obj_TransformLocalVectorByWorldMatrix(*(void**)light, (f32*)(light + 0x28),
                                                      (f32*)(light + 0x34));
            }
            if (((ModelLightStruct*)light)->transformMode == 0)
            {
                PSMTXMultVecSR(view, (f32*)(light + 0x34), (f32*)(light + 0x40));
            }
            else
            {
                *(IVec3*)(light + 0x40) = *(IVec3*)(light + 0x34);
            }

            if (((ModelLightStruct*)light)->colorFadeMode != 0)
            {
                modelLightStruct_updateColorFade((ModelLightStruct*)light);
            }
            else
            {
                light[0xa8] = ((f32)light[0xac] * ((ModelLightStruct*)light)->activeIntensity);
                light[0xa9] = ((f32)light[0xad] * ((ModelLightStruct*)light)->activeIntensity);
                light[0xaa] = ((f32)light[0xae] * ((ModelLightStruct*)light)->activeIntensity);
                light[0xab] = ((f32)light[0xaf] * ((ModelLightStruct*)light)->activeIntensity);
                light[0x100] = ((f32)light[0x104] * ((ModelLightStruct*)light)->activeIntensity);
                light[0x101] = ((f32)light[0x105] * ((ModelLightStruct*)light)->activeIntensity);
                light[0x102] = ((f32)light[0x106] * ((ModelLightStruct*)light)->activeIntensity);
                light[0x103] = ((f32)light[0x107] * ((ModelLightStruct*)light)->activeIntensity);
            }

            if (((ModelLightStruct*)light)->lightKind == 8)
            {
                Obj_BuildInverseWorldTransformMatrix(*(u8**)light, (f32*)(light + 0x170));
                PSMTXConcat((f32*)(light + 0x170), Camera_GetInverseViewMatrix(), concatMtx);
                PSMTXConcat((f32*)(light + 0x1b0), concatMtx, (f32*)(light + 0x230));
            }
        }
    }
}

extern void GXInitLightSpot(u8* lt_obj, f32 cutoff, int spot_func);
extern f32 PSVECMag(f32 * v);
extern f32 PSVECDotProduct(f32 * a, f32 * b);
extern f32 lbl_803DE768;
extern f32 gModelLightCornerBlock[];

void modelLightStruct_setSpotAttenuation(ModelLightStruct* obj, f32 cutoff, int mode)
{
    obj->spotCutoff = cutoff;
    obj->spotFunction = mode;
    if (mode == 0)
    {
        GXInitLightAttnA((u8*)obj + 0x68, lbl_803DE760, lbl_803DE75C, *(f32*)&lbl_803DE75C);
    }
    else
    {
        GXInitLightSpot((u8*)obj + 0x68, obj->spotCutoff, obj->spotFunction);
    }
}

void modelLightStruct_setDistanceAttenuation(u8* obj, f32 a, f32 b)
{
    ((ModelLightStruct*)obj)->attenuationNear = a;
    ((ModelLightStruct*)obj)->attenuationFar = b;
    GXInitLightDistAttn(obj + 0x68, ((ModelLightStruct*)obj)->attenuationNear, lbl_803DE758, GX_DA_MEDIUM);
    GXGetLightAttnK(obj + 0x68, &((ModelLightStruct*)obj)->attenuationK0, &((ModelLightStruct*)obj)->attenuationK1,
                    &((ModelLightStruct*)obj)->attenuationK2);
}

typedef struct ModelLightCornerBlock
{
    f32 v[24];
} ModelLightCornerBlock;

u8 modelLightStruct_projectedLightIntersectsObject(u8* light, u8* obj)
{
    f32 localPos[3];
    f32 projected[3];
    f32 worldPos[3];
    ModelLightCornerBlock cornerBlock;
    f32 extent;
    f32 scaledExtent;
    u8 clipMask;
    f32* cv;
    int i;
    u8 combinedClipMask;
    f32 zero;

    scaledExtent = ((GameObject*)obj)->anim.rootMotionScale * ((GameObject*)obj)->anim.hitboxScale;
    cornerBlock = *(ModelLightCornerBlock*)gModelLightCornerBlock;

    worldPos[0] = ((GameObject*)obj)->anim.localPosX - playerMapOffsetX;
    worldPos[1] = ((GameObject*)obj)->anim.localPosY;
    worldPos[2] = ((GameObject*)obj)->anim.localPosZ - playerMapOffsetZ;
    PSMTXMultVec((f32*)(light + 0x170), worldPos, localPos);

    if (((ModelLightStruct*)light)->projectionType == 0)
    {
        if (localPos[0] - (extent = ((GameObject*)obj)->anim.hitboxScale) > ((ModelLightStruct*)light)->projectionRight ||
            localPos[0] + scaledExtent < ((ModelLightStruct*)light)->projectionLeft ||
            localPos[1] - extent > ((ModelLightStruct*)light)->projectionTop ||
            localPos[1] + scaledExtent < ((ModelLightStruct*)light)->projectionBottom ||
            localPos[2] - extent > ((ModelLightStruct*)light)->projectionFarZ ||
            localPos[2] + scaledExtent < ((ModelLightStruct*)light)->projectionNearZ)
        {
            return 0;
        }
        goto found;
    }

    if (localPos[2] - ((GameObject*)obj)->anim.hitboxScale > ((ModelLightStruct*)light)->projectionFarZ ||
        localPos[2] + scaledExtent < ((ModelLightStruct*)light)->projectionNearZ)
    {
        return 0;
    }

    combinedClipMask = 0x3f;
    i = 0;
    cv = cornerBlock.v;
    zero = lbl_803DE75C;
    for (; i < 8; i++)
    {
        worldPos[0] = localPos[0] + scaledExtent * cv[0];
        worldPos[1] = localPos[1] + scaledExtent * cv[1];
        worldPos[2] = localPos[2] + scaledExtent * cv[2];
        PSMTXMultVec((f32*)(light + 0x1f0), worldPos, projected);
        if (zero != projected[2])
        {
            projected[0] /= projected[2];
            projected[1] /= projected[2];
        }

        clipMask = 0;
        if (worldPos[2] < ((ModelLightStruct*)light)->projectionNearZ)
        {
            clipMask |= 0x10;
        }
        if (worldPos[2] > ((ModelLightStruct*)light)->projectionFarZ)
        {
            clipMask |= 0x20;
        }
        if (projected[0] < zero)
        {
            clipMask |= 1;
        }
        else if (projected[0] > lbl_803DE760)
        {
            clipMask |= 2;
        }
        if (projected[1] < zero)
        {
            clipMask |= 4;
        }
        else if (projected[1] > lbl_803DE760)
        {
            clipMask |= 8;
        }
        if (clipMask == 0)
        {
            return 1;
        }
        combinedClipMask &= clipMask;
        if (combinedClipMask == 0)
        {
            return 1;
        }
        cv += 3;
    }

    return 0;

found:
    return 1;
}

#pragma dont_inline on
f32 modelLightStruct_getObjectIntensity(u8* light, u8* obj)
{
    f32 delta[3];
    f32 dist;
    f32 amount;

    if (((GameObject*)obj)->ownerObj != NULL)
    {
        obj = ((GameObject*)obj)->ownerObj;
    }

    PSVECSubtract(&((GameObject*)obj)->anim.worldPosX, (f32*)(light + 0x10), delta);
    dist = PSVECMag(delta) - ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale;
    if (dist > lbl_803DE768 || dist > ((ModelLightStruct*)light)->attenuationFar)
    {
        return lbl_803DE75C;
    }

    if (dist < ((ModelLightStruct*)light)->attenuationNear)
    {
        amount = lbl_803DE760;
    }
    else
    {
        amount = lbl_803DE760 - (dist - ((ModelLightStruct*)light)->attenuationNear) /
            (((ModelLightStruct*)light)->attenuationFar - ((ModelLightStruct*)light)->attenuationNear);
    }

    if (((ModelLightStruct*)light)->spotFunction != 0)
    {
        PSVECScale(delta, delta, lbl_803DE760 / dist);
        PSVECDotProduct((f32*)(light + 0x34), delta);
    }

    return amount;
}

#pragma dont_inline off
void modelLightStruct_selectBrightestAabbLights(f32 minX, f32 minY, f32 minZ, f32 maxX, f32 maxY, f32 maxZ,
                                                u8** outLights, int maxLights, int* outCount)
{
    int i;
    f32 delta[3];
    f32 center[3];
    u8* candidates[20];
    u8* light;
    f32 dist;
    f32 intensity;
    f32 red;
    f32 green;
    f32 blue;
    int candidateCount;
    int selectedCount;

    center[0] = lbl_803DE790 * (minX + maxX);
    center[1] = lbl_803DE790 * (minY + maxY);
    center[2] = lbl_803DE790 * (minZ + maxZ);

    candidateCount = 0;
    for (i = 0; i < gModelLightCount; i++)
    {
        light = gModelLightList[i];
        if (light[0x4c] != 0 && ((ModelLightStruct*)light)->lightKind == 2 && ((ModelLightStruct*)light)->attenuationFar > lbl_803DE75C &&
            light[0x2fb] != 0)
        {
            PSVECSubtract(center, (f32*)(light + 0x10), delta);
            dist = PSVECMag(delta);
            if (*(f32*)(light + 0x10) + ((ModelLightStruct*)light)->attenuationFar >= minX &&
                ((ModelLightStruct*)light)->worldY + ((ModelLightStruct*)light)->attenuationFar >= minY &&
                ((ModelLightStruct*)light)->worldZ + ((ModelLightStruct*)light)->attenuationFar >= minZ &&
                *(f32*)(light + 0x10) - ((ModelLightStruct*)light)->attenuationFar <= maxX &&
                ((ModelLightStruct*)light)->worldY - ((ModelLightStruct*)light)->attenuationFar <= maxY &&
                ((ModelLightStruct*)light)->worldZ - ((ModelLightStruct*)light)->attenuationFar <= maxZ)
            {
                intensity = lbl_803DE760 /
                (((ModelLightStruct*)light)->attenuationK0 +
                    (dist * (((ModelLightStruct*)light)->attenuationK2 * dist) + ((ModelLightStruct*)light)->attenuationK1 * dist));
                red = intensity * light[0xa8];
                red = (red < 0.0f)
                          ? 0.0f
                          : ((red > 255.0f) ? 255.0f : red);
                green = intensity * light[0xa9];
                green = (green < 0.0f)
                            ? 0.0f
                            : ((green > 255.0f) ? 255.0f : green);
                blue = intensity * light[0xaa];
                blue = (blue < 0.0f)
                           ? 0.0f
                           : ((blue > 255.0f) ? 255.0f : blue);
                green = (red < green) ? green : red;
                ((ModelLightStruct*)light)->selectionScore = green;
                blue = (((ModelLightStruct*)light)->selectionScore > blue) ? ((ModelLightStruct*)light)->selectionScore : blue;
                ((ModelLightStruct*)light)->selectionScore = blue;

                selectedCount = candidateCount;
                candidateCount++;
                candidates[selectedCount] = light;
                if (candidateCount >= 20)
                {
                    break;
                }
            }
        }
    }

    if (maxLights > candidateCount)
    {
        maxLights = candidateCount;
    }

    *outCount = 0;
    dist = lbl_803DE75C;
    while (*outCount < maxLights)
    {
        intensity = lbl_803DE75C;
        for (i = 0; i < candidateCount; i++)
        {
            if (((ModelLightStruct*)candidates[i])->selectionScore > intensity)
            {
                intensity = ((ModelLightStruct*)candidates[i])->selectionScore;
                light = candidates[i];
            }
        }
        outLights[(*outCount)++] = light;
        ((ModelLightStruct*)light)->selectionScore = dist;
    }
}

void modelLightStruct_selectObjectLights(u8* obj, u8** outLights, int maxLights, int* outCount, int typeMask)
{
    f32 delta[3];
    u8* candidates[20];
    int i;
    u8* light;
    f32 intensity;
    f32 dist;
    f32 red;
    f32 green;
    f32 blue;
    u8 objectLightMask;
    int candidateCount;
    int selectedCount;
    int lightType;

    if (obj != NULL)
    {
        objectLightMask = 1 << ((GameObject*)obj)->anim.modelInstance->modelLightMaskIndex;
    }
    else
    {
        objectLightMask = 1;
    }

    candidateCount = 0;
    for (i = 0; i < gModelLightCount; i++)
    {
        light = gModelLightList[i];
        if (light[0x4c] != 0 && (((ModelLightStruct*)light)->lightKind & typeMask) != 0 &&
            (light[0x64] & objectLightMask) != 0)
        {
            lightType = ((ModelLightStruct*)light)->lightKind;
            if (lightType == 4)
            {
                ((ModelLightStruct*)light)->selectionScore = lbl_803DE768;
            }
            else if (lightType == 8)
            {
                if (*(void**)(light + 0x16c) != NULL && modelLightStruct_projectedLightIntersectsObject(light, obj) !=
                    0)
                {
                    PSVECSubtract((f32*)(obj + 0x18), &((ModelLightStruct*)light)->worldX, delta);
                    dist = PSVECMag(delta);
                    intensity = lbl_803DE764;
                    ((ModelLightStruct*)light)->selectionScore = intensity + intensity / dist;
                    ((ModelLightStruct*)light)->lightAmount = modelLightStruct_getObjectIntensity(light, obj);
                }
                else
                {
                    ((ModelLightStruct*)light)->selectionScore = lbl_803DE75C;
                }
            }
            else
            {
                intensity = modelLightStruct_getObjectIntensity(light, obj);
                ((ModelLightStruct*)light)->lightAmount = intensity;
                red = ((ModelLightStruct*)light)->lightAmount * light[0xa8];
                red = (red < 0.0f)
                          ? 0.0f
                          : ((red > 255.0f) ? 255.0f : red);
                green = ((ModelLightStruct*)light)->lightAmount * light[0xa9];
                green = (green < 0.0f)
                            ? 0.0f
                            : ((green > 255.0f) ? 255.0f : green);
                blue = ((ModelLightStruct*)light)->lightAmount * light[0xaa];
                blue = (blue < 0.0f)
                           ? 0.0f
                           : ((blue > 255.0f) ? 255.0f : blue);
                green = (red < green) ? green : red;
                ((ModelLightStruct*)light)->selectionScore = green;
                blue = (((ModelLightStruct*)light)->selectionScore > blue) ? ((ModelLightStruct*)light)->selectionScore : blue;
                ((ModelLightStruct*)light)->selectionScore = blue;
            }

            if (((ModelLightStruct*)light)->selectionScore > lbl_803DE75C)
            {
                ((ModelLightStruct*)light)->selectionScore += (f32)((int)light[0x2fc] << 8);
                selectedCount = candidateCount;
                candidateCount++;
                candidates[selectedCount] = light;
                if (candidateCount >= 20)
                {
                    break;
                }
            }
        }
    }

    if (maxLights > candidateCount)
    {
        maxLights = candidateCount;
    }

    *outCount = 0;
    while (*outCount < maxLights)
    {
        intensity = lbl_803DE75C;
        for (i = 0; i < candidateCount; i++)
        {
            if (((ModelLightStruct*)candidates[i])->selectionScore > intensity)
            {
                intensity = ((ModelLightStruct*)candidates[i])->selectionScore;
                light = candidates[i];
            }
        }
        outLights[(*outCount)++] = light;
        ((ModelLightStruct*)light)->selectionScore = -((ModelLightStruct*)light)->selectionScore;
    }
}

void modelLightStruct_updateGlowAlpha(ModelLightStruct* light)
{
    s16 v;

    if (light->glowType == 0)
    {
        return;
    }
    if (light->enabled == 0)
    {
        return;
    }
    v = light->glowAlpha + light->glowAlphaStep;
    if (v < 0)
    {
        v = 0;
        light->glowAlphaStep = 0;
    }
    else if (v > 0xff)
    {
        v = 0xff;
        light->glowAlphaStep = 0;
    }
    light->glowAlpha = v;
}


extern void C_MTXLightPerspective(f32* m, f32 fovY, f32 aspect, f32 scaleS, f32 scaleT, f32 transS, f32 transT);

#pragma opt_common_subs off
void modelLightStruct_setupPerspectiveProjection(ModelLightStruct* obj, f32 a, f32 b)
{
    f32 z;
    obj->projectionFovY = a;
    obj->projectionAspect = b;
    obj->projectionType = 1;
    z = lbl_803DE790;
    C_MTXLightPerspective(obj->lightProjectionTexMtx, obj->projectionFovY, obj->projectionAspect,
                          z, z, z, z);
    z = lbl_803DE790;
    C_MTXLightPerspective(obj->lightProjectionClipMtx, obj->projectionFovY, obj->projectionAspect,
                          z, z, z, z);
}
#pragma opt_common_subs reset

extern void C_MTXLightOrtho(f32* m, f32 t, f32 b, f32 l, f32 r, f32 scaleS, f32 scaleT,
                            f32 transS, f32 transT);

#pragma opt_common_subs off
void modelLightStruct_setupOrthoProjection(ModelLightStruct* obj, f32 a, f32 b, f32 c, f32 d, f32 e, f32 f)
{
    f32 fScale;
    f32 eScale;
    f32 unit;

    obj->projectionTop = a;
    obj->projectionBottom = b;
    obj->projectionLeft = c;
    obj->projectionRight = d;
    obj->projectionType = 0;
    fScale = f * lbl_803DE790;
    eScale = e * lbl_803DE790;
    C_MTXLightOrtho(obj->lightProjectionTexMtx, obj->projectionTop, obj->projectionBottom,
                    obj->projectionLeft, obj->projectionRight, fScale, eScale, fScale,
                    eScale);
    unit = lbl_803DE790;
    C_MTXLightOrtho(obj->lightProjectionClipMtx, obj->projectionTop, obj->projectionBottom,
                    obj->projectionLeft, obj->projectionRight, unit, unit, unit, unit);
}
#pragma opt_common_subs reset

#pragma opt_propagation off
void modelLightStruct_setSpecularAttenuation(ModelLightStruct* obj, f32 a, f32 b)
{
    u8* lightObj;
    f32 zero;
    f32 atten;

    obj->specularAttenuationScale = a;
    obj->specularBrightness = b;
    atten = obj->specularAttenuationScale * lbl_803DE790;
    lightObj = (u8*)obj + 0xc0;
    zero = lbl_803DE75C;
    GXInitLightAttn(lightObj, zero, zero, lbl_803DE760, atten, zero, *(f32*)&lbl_803DE760 - atten);
}
#pragma opt_propagation reset
void Obj_BuildInverseWorldTransformMatrix(u8 * obj, f32 * out);


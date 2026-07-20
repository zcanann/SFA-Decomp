#include "main/game_object.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/shader_api.h"
#include "main/dll/ivec3_struct.h"
#include "main/model_light.h"
#include "main/modellight_api.h"
#include "main/modellight_internal.h"
#include "main/mm.h"
#include "main/camera.h"
#include "main/texture.h"
#include "main/frame_timing.h"
#include "main/object_transform.h"
#include "main/object_api.h"
#include "dolphin/gx/GXGet.h"
#include "dolphin/gx/GXLegacyDecls.h"
#include "dolphin/gx/GXLighting.h"
#include "string.h"

int gModelLightNextGXLightId;
u8 gModelLightUseModelRelativePositions;
u8 gModelLightCount;

typedef struct
{
    u8 active;
    u8 _1[3];
    int lightMask;
    int mode;
    int matSrc;
} ModelLightChannelState;

typedef f32 Mtx[3][4];

typedef struct ModelLightCornerBlock
{
    f32 v[24];
} ModelLightCornerBlock;

STATIC_ASSERT(sizeof(ModelLightCornerBlock) == 0x60);

#define MODELLIGHT_DEFAULT_GLOW_TEXTURE_ID 0x605

/* per-corner outcode bits for the light-projection frustum clip test */
#define LIGHTCLIP_LEFT   0x01 /* projected X < 0 */
#define LIGHTCLIP_RIGHT  0x02 /* projected X > max */
#define LIGHTCLIP_BOTTOM 0x04 /* projected Y < 0 */
#define LIGHTCLIP_TOP    0x08 /* projected Y > max */
#define LIGHTCLIP_NEAR   0x10 /* worldZ < nearZ */
#define LIGHTCLIP_FAR    0x20 /* worldZ > farZ */

extern f32 lbl_803DE750;
extern f32 lbl_803DE754;
extern f32 lbl_803DE758;
extern f32 lbl_803DE760;
extern f32 lbl_803DE75C;
extern f32 lbl_803DE76C;
extern f32 lbl_803DE790;
extern f32 lbl_803DE79C;
extern f32 lbl_803DE7A0;
u8 gModelLightColorTable[8] = {0};
extern f32 lbl_803DE764;
extern f32 lbl_803DE778;
extern f32 lbl_803DE78C;
extern f32 lbl_803DE788;
extern f32 lbl_803DE794;
extern f32 lbl_803DE798;
extern f32 lbl_803DE7A4;
extern f32 lbl_803DE768;
const ModelLightCornerBlock gModelLightCornerBlock = {{
    1.0f, 1.0f, 1.0f, 1.0f, 1.0f, -1.0f, 1.0f, -1.0f,
    -1.0f, 1.0f, -1.0f, 1.0f, -1.0f, -1.0f, -1.0f, -1.0f,
    -1.0f, 1.0f, -1.0f, 1.0f, 1.0f, -1.0f, 1.0f, -1.0f}};

extern void* gModelLightList[0x32];

static inline void modelLightRemoveAndFree(ModelLightStruct* light)
{
    int i;
    int count;

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
        textureFree((Texture*)(light->glowTexture));
    }
    mm_free(light);
}

void modelLightStruct_freeSlot(ModelLightStruct** lightSlot)
{
    ModelLightStruct* light;

    light = *lightSlot;
    if (light != NULL)
    {
        modelLightRemoveAndFree(light);
        *lightSlot = NULL;
    }
}

ModelLightStruct* modelLightStruct_createPointLight(void* owner, u8 red, u8 green, u8 blue, u8 setFlag)
{
    ModelLightStruct* light;
    ModelLightStruct* newLight;

    if (gModelLightCount >= 0x32)
    {
        light = NULL;
    }
    else
    {
        newLight = objAllocLight(owner);
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
        light->lightKind = MODEL_LIGHT_KIND_POINT;
        light->diffuseFadeStartColor[0] = red;
        light->diffuseColor[0] = red;
        light->diffuseFadeStartColor[1] = green;
        light->diffuseColor[1] = green;
        light->diffuseFadeStartColor[2] = blue;
        light->diffuseColor[2] = blue;
        light->diffuseFadeStartColor[3] = 0;
        light->diffuseColor[3] = 0;
        light->fieldBC = 1;
        light->attenuationNear = lbl_803DE750;
        light->attenuationFar = lbl_803DE754;
        GXInitLightDistAttn(&light->diffuseLightObj, light->attenuationNear, lbl_803DE758, GX_DA_MEDIUM);
        GXGetLightAttnK(&light->diffuseLightObj, &light->attenuationK0, &light->attenuationK1,
                        &light->attenuationK2);
        if (setFlag != 0)
        {
            light->affectsAabbLightSelection = 1;
        }
    }

    return light;
}

u8 modelLightStruct_projectedLightIntersectsObject(ModelLightStruct* light, GameObject* obj)
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

    scaledExtent = obj->anim.rootMotionScale * obj->anim.hitboxScale;
    cornerBlock = gModelLightCornerBlock;

    worldPos[0] = obj->anim.localPosX - playerMapOffsetX;
    worldPos[1] = obj->anim.localPosY;
    worldPos[2] = obj->anim.localPosZ - playerMapOffsetZ;
    PSMTXMultVec(light->inverseWorldProjectionMtx, worldPos, localPos);

    if (light->projectionType == 0)
    {
        if (localPos[0] - (extent = obj->anim.hitboxScale) > light->projectionRight ||
            localPos[0] + scaledExtent < light->projectionLeft || localPos[1] - extent > light->projectionTop ||
            localPos[1] + scaledExtent < light->projectionBottom || localPos[2] - extent > light->projectionFarZ ||
            localPos[2] + scaledExtent < light->projectionNearZ)
        {
            return 0;
        }
    }
    else
    {
        if (localPos[2] - obj->anim.hitboxScale > light->projectionFarZ ||
            localPos[2] + scaledExtent < light->projectionNearZ)
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
            PSMTXMultVec(light->lightProjectionClipMtx, worldPos, projected);
            if (zero != projected[2])
            {
                projected[0] /= projected[2];
                projected[1] /= projected[2];
            }

            clipMask = 0;
            if (worldPos[2] < light->projectionNearZ)
            {
                clipMask |= LIGHTCLIP_NEAR;
            }
            if (worldPos[2] > light->projectionFarZ)
            {
                clipMask |= LIGHTCLIP_FAR;
            }
            if (projected[0] < zero)
            {
                clipMask |= LIGHTCLIP_LEFT;
            }
            else if (projected[0] > lbl_803DE760)
            {
                clipMask |= LIGHTCLIP_RIGHT;
            }
            if (projected[1] < zero)
            {
                clipMask |= LIGHTCLIP_BOTTOM;
            }
            else if (projected[1] > lbl_803DE760)
            {
                clipMask |= LIGHTCLIP_TOP;
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
    }

    return 1;
}

f32 modelLightStruct_getObjectIntensity(ModelLightStruct* light, GameObject* obj)
{
    f32 delta[3];
    f32 dist;
    f32 amount;

    if (obj->ownerObj != NULL)
    {
        obj = obj->ownerObj;
    }

    PSVECSubtract(&obj->anim.worldPosX, &light->worldX, delta);
    dist = PSVECMag(delta) - obj->anim.hitboxScale * obj->anim.rootMotionScale;
    if (dist > lbl_803DE768 || dist > light->attenuationFar)
    {
        return lbl_803DE75C;
    }

    if (dist < light->attenuationNear)
    {
        amount = lbl_803DE760;
    }
    else
    {
        amount = lbl_803DE760 -
                 (dist - light->attenuationNear) / (light->attenuationFar - light->attenuationNear);
    }

    if (light->spotFunction != 0)
    {
        PSVECScale(delta, delta, lbl_803DE760 / dist);
        PSVECDotProduct(&light->worldDirX, delta);
    }

    return amount;
}
f32 modelLightStruct_getObjectIntensity(ModelLightStruct* light, GameObject* obj);

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

    light->diffuseColor[0] =
        (light->colorFadeProgress * (f32)(light->diffuseFadeTargetColor[0] - light->diffuseFadeStartColor[0]) +
         light->diffuseFadeStartColor[0]);
    light->diffuseColor[1] =
        (light->colorFadeProgress * (f32)(light->diffuseFadeTargetColor[1] - light->diffuseFadeStartColor[1]) +
         light->diffuseFadeStartColor[1]);
    light->diffuseColor[2] =
        (light->colorFadeProgress * (f32)(light->diffuseFadeTargetColor[2] - light->diffuseFadeStartColor[2]) +
         light->diffuseFadeStartColor[2]);
    light->diffuseColor[3] =
        (light->colorFadeProgress * (f32)(light->diffuseFadeTargetColor[3] - light->diffuseFadeStartColor[3]) +
         light->diffuseFadeStartColor[3]);

    light->diffuseColor[0] = ((f32)light->diffuseColor[0] * light->activeIntensity);
    light->diffuseColor[1] = ((f32)light->diffuseColor[1] * light->activeIntensity);
    light->diffuseColor[2] = ((f32)light->diffuseColor[2] * light->activeIntensity);
    light->diffuseColor[3] = ((f32)light->diffuseColor[3] * light->activeIntensity);

    light->specularColor[0] =
        (light->colorFadeProgress * (f32)(light->specularFadeTargetColor[0] - light->specularFadeStartColor[0]) +
         light->specularFadeStartColor[0]);
    light->specularColor[1] =
        (light->colorFadeProgress * (f32)(light->specularFadeTargetColor[1] - light->specularFadeStartColor[1]) +
         light->specularFadeStartColor[1]);
    light->specularColor[2] =
        (light->colorFadeProgress * (f32)(light->specularFadeTargetColor[2] - light->specularFadeStartColor[2]) +
         light->specularFadeStartColor[2]);
    light->specularColor[3] =
        (light->colorFadeProgress * (f32)(light->specularFadeTargetColor[3] - light->specularFadeStartColor[3]) +
         light->specularFadeStartColor[3]);

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

void modelLightStruct_startColorFade(ModelLightStruct* light, int mode, s16 frames);

void modelLightStruct_updateGlowAlpha(ModelLightStruct* light)
{
    s16 newAlpha;

    if (light->glowType == 0)
    {
        return;
    }
    if (light->enabled == 0)
    {
        return;
    }
    newAlpha = light->glowAlpha + light->glowAlphaStep;
    if (newAlpha < 0)
    {
        newAlpha = 0;
        light->glowAlphaStep = 0;
    }
    else if (newAlpha > 0xff)
    {
        newAlpha = 0xff;
        light->glowAlphaStep = 0;
    }
    light->glowAlpha = newAlpha;
}

void modelLightStruct_setGlowProjectionRadius(ModelLightStruct* light, f32 radius)
{
    light->glowProjectionRadius = radius;
}

void modelLightStruct_setGlowColor(ModelLightStruct* light, u8 red, u8 green, u8 blue, u8 alpha)
{
    light->glowColor[0] = red;
    light->glowColor[1] = green;
    light->glowColor[2] = blue;
    light->glowColor[3] = alpha;
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
        texture = textureLoadAsset(MODELLIGHT_DEFAULT_GLOW_TEXTURE_ID);
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

void modelLightStruct_getProjectionTevModes(ModelLightStruct* p, int* a, int* b)
{
    *a = p->projectionTevColorMode;
    *b = p->projectionTevAlphaMode;
}

void modelLightStruct_setProjectionTevModes(ModelLightStruct* p, int a, int b)
{
    p->projectionTevColorMode = a;
    p->projectionTevAlphaMode = b;
}

f32* modelLightStruct_getProjectionTexMtx(ModelLightStruct* p)
{
    return p->projectionTexMtx;
}

void modelLightStruct_setProjectionFarZ(ModelLightStruct* p, f32 v)
{
    p->projectionFarZ = (v < p->projectionNearZ) ? p->projectionNearZ : ((v > lbl_803DE764) ? lbl_803DE764 : v);
}

void* gModelLightList[0x32];

void modelLightStruct_setProjectionNearZ(ModelLightStruct* p, f32 v)
{
    p->projectionNearZ = (v < lbl_803DE78C) ? lbl_803DE78C : ((v > p->projectionFarZ) ? p->projectionFarZ : v);
}

void modelLightStruct_setupPerspectiveProjection(ModelLightStruct* obj, f32 fovY, f32 aspect)
{
    obj->projectionFovY = fovY;
    obj->projectionAspect = aspect;
    obj->projectionType = 1;
    C_MTXLightPerspective(obj->lightProjectionTexMtx, obj->projectionFovY, obj->projectionAspect, 0.5f, 0.5f, 0.5f,
                          0.5f);
    C_MTXLightPerspective(obj->lightProjectionClipMtx, obj->projectionFovY, obj->projectionAspect, 0.5f, 0.5f, 0.5f,
                          0.5f);
}
void modelLightStruct_setupOrthoProjection(ModelLightStruct* obj, f32 top, f32 bottom, f32 left, f32 right, f32 scaleT,
                                           f32 scaleS)
{
    f32 fScale;
    f32 eScale;

    obj->projectionTop = top;
    obj->projectionBottom = bottom;
    obj->projectionLeft = left;
    obj->projectionRight = right;
    obj->projectionType = 0;
    fScale = scaleS * lbl_803DE790;
    eScale = scaleT * lbl_803DE790;
    C_MTXLightOrtho(obj->lightProjectionTexMtx, obj->projectionTop, obj->projectionBottom, obj->projectionLeft,
                    obj->projectionRight, fScale, eScale, fScale, eScale);
    C_MTXLightOrtho(obj->lightProjectionClipMtx, obj->projectionTop, obj->projectionBottom, obj->projectionLeft,
                    obj->projectionRight, 0.5f, 0.5f, 0.5f, 0.5f);
}

void* modelLightStruct_getProjectionTexture(ModelLightStruct* p)
{
    return p->projectionTexture;
}


void modelLightStruct_setProjectionTexture(ModelLightStruct* p, void* v)
{
    p->projectionTexture = v;
}
void modelLightStruct_setSpecularAttenuation(ModelLightStruct* obj, f32 scale, f32 brightness)
{
    f32 atten;

    obj->specularAttenuationScale = scale;
    obj->specularBrightness = brightness;
    atten = obj->specularAttenuationScale * lbl_803DE790;
    GXInitLightAttn(&obj->specularLightObj, 0.0f, 0.0f, 1.0f, atten, 0.0f, 1.0f - atten);
}

void modelLightStruct_setSpecularTargetColor(ModelLightStruct* p, u8 r, u8 g, u8 b, u8 a)
{
    p->specularFadeTargetColor[0] = r;
    p->specularFadeTargetColor[1] = g;
    p->specularFadeTargetColor[2] = b;
    p->specularFadeTargetColor[3] = a;
}

void modelLightStruct_getSpecularColor(ModelLightStruct* p, u8* r, u8* g, u8* b, u8* a)
{
    *r = p->specularColor[0];
    *g = p->specularColor[1];
    *b = p->specularColor[2];
    *a = p->specularColor[3];
}

void modelLightStruct_setSpecularColor(ModelLightStruct* p, u8 r, u8 g, u8 b, u8 a)
{
    p->specularFadeStartColor[0] = r;
    p->specularColor[0] = r;
    p->specularFadeStartColor[1] = g;
    p->specularColor[1] = g;
    p->specularFadeStartColor[2] = b;
    p->specularColor[2] = b;
    p->specularFadeStartColor[3] = a;
    p->specularColor[3] = a;
}

void modelLightStruct_setAngularAttenuation(ModelLightStruct* p, f32 a, f32 b, f32 c)
{
    GXInitLightAttnA(&p->diffuseLightObj, a, b, c);
}

void modelLightStruct_setSpotAttenuation(ModelLightStruct* obj, f32 cutoff, int mode)
{
    obj->spotCutoff = cutoff;
    obj->spotFunction = mode;
    if (mode == 0)
    {
        GXInitLightAttnA(&obj->diffuseLightObj, lbl_803DE760, lbl_803DE75C, *(f32*)&lbl_803DE75C);
    }
    else
    {
        GXInitLightSpot(&obj->diffuseLightObj, obj->spotCutoff, obj->spotFunction);
    }
}

void modelLightStruct_setDiffuseTargetColor(p, r, g, b, a)
ModelLightStruct* p;
u8 r;
u8 g;
u8 b;
u8 a;
{
    p->diffuseFadeTargetColor[0] = r;
    p->diffuseFadeTargetColor[1] = g;
    p->diffuseFadeTargetColor[2] = b;
    p->diffuseFadeTargetColor[3] = a;
}

void modelLightStruct_getDiffuseColor(ModelLightStruct* p, u8* r, u8* g, u8* b, u8* a)
{
    *r = p->diffuseColor[0];
    *g = p->diffuseColor[1];
    *b = p->diffuseColor[2];
    *a = p->diffuseColor[3];
}

void modelLightStruct_setDiffuseColor(p, r, g, b, a)
ModelLightStruct* p;
u8 r;
u8 g;
u8 b;
u8 a;
{
    p->diffuseFadeStartColor[0] = r;
    p->diffuseColor[0] = r;
    p->diffuseFadeStartColor[1] = g;
    p->diffuseColor[1] = g;
    p->diffuseFadeStartColor[2] = b;
    p->diffuseColor[2] = b;
    p->diffuseFadeStartColor[3] = a;
    p->diffuseColor[3] = a;
}

void lightSetFieldBC_8001db14(ModelLightStruct* p, u8 v)
{
    p->fieldBC = v;
}

int modelLightStruct_getProjectedLightChannelPreference(ModelLightStruct* p)
{
    return p->projectedLightChannelPreference;
}

void modelLightStruct_setProjectedLightChannelPreference(ModelLightStruct* p, int v)
{
    p->projectedLightChannelPreference = v;
}

void modelLightStruct_setLightKind(ModelLightStruct* p, int v)
{
    p->lightKind = v;
}

void objSetEventName(ModelLightStruct* light, int name)
{
    ((GameObject*)light)->anim.eventTable = (void*)name;
}

void modelLightStruct_setObjectLightMaskIndex(ModelLightStruct* p, int n)
{
    p->objectLightMaskIndex = n;
    p->objectLightMask = (u8)(1 << n);
}

void lightSetField4D(ModelLightStruct* p, u8 v)
{
    p->field4D = v;
}

void modelLightStruct_setSelectionPriority(ModelLightStruct* p, u8 v)
{
    p->selectionPriority = v;
}

int modelLightStruct_getActiveState(ModelLightStruct* p)
{
    return p->activeState;
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

void modelLightStruct_setDistanceAttenuation(ModelLightStruct* light, f32 near, f32 far)
{
    light->attenuationNear = near;
    light->attenuationFar = far;
    GXInitLightDistAttn(&light->diffuseLightObj, light->attenuationNear, lbl_803DE758, GX_DA_MEDIUM);
    GXGetLightAttnK(&light->diffuseLightObj, &light->attenuationK0, &light->attenuationK1, &light->attenuationK2);
}

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

ModelLightChannelState gModelLightChannelStates[0x60 / sizeof(ModelLightChannelState)];

void modelLightStruct_setAffectsAabbLightSelection(ModelLightStruct* p, u8 v)
{
    p->affectsAabbLightSelection = v;
}

f32 modelLightStruct_getRadius(ModelLightStruct* p)
{
    return p->attenuationFar;
}

void modelLightStruct_getPosition(ModelLightStruct* p, f32* x, f32* y, f32* z)
{
    *x = p->viewX;
    *y = p->viewY;
    *z = p->viewZ;
}

void modelLightStruct_getWorldPosition(ModelLightStruct* p, f32* x, f32* y, f32* z)
{
    *x = p->worldX;
    *y = p->worldY;
    *z = p->worldZ;
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
ModelLightStruct* objAllocLight(void* owner)
{
    ModelLightStruct* light;
    f32 tmp[3];
    f32* view;
    f32 zero;
    f32 atten;

    light = mmAlloc(sizeof(ModelLightStruct), 0x1a, 0);
    if (light == NULL)
    {
        return NULL;
    }

    memset(light, 0, sizeof(ModelLightStruct));
    light->owner = owner;

    if (light->owner != NULL)
    {
        zero = lbl_803DE75C;
        light->localX = zero;
        light->localY = zero;
        light->localZ = zero;
        Obj_TransformLocalPointByWorldMatrix(light->owner, &light->localX, &light->worldX, 1);
    }
    else
    {
        zero = lbl_803DE75C;
        light->worldX = zero;
        light->worldY = zero;
        light->worldZ = zero;
    }

    view = Camera_GetViewMatrix();
    if (light->transformMode == 0)
    {
        tmp[0] = light->worldX - playerMapOffsetX;
        tmp[1] = light->worldY;
        tmp[2] = light->worldZ - playerMapOffsetZ;
        PSMTXMultVec(view, tmp, &light->viewX);
    }
    else
    {
        *(IVec3*)&light->viewX = *(IVec3*)&light->worldX;
    }

    if (light->owner != NULL)
    {
        zero = lbl_803DE75C;
        light->localDirX = zero;
        light->localDirY = zero;
        light->localDirZ = lbl_803DE760;
        Vec_normalize(&light->localDirX, &light->localDirX);
        Obj_TransformLocalVectorByWorldMatrix(light->owner, &light->localDirX, &light->worldDirX);
    }
    else
    {
        zero = lbl_803DE75C;
        light->worldDirX = zero;
        light->worldDirY = zero;
        light->worldDirZ = lbl_803DE760;
        Vec_normalize(&light->worldDirX, &light->worldDirX);
    }

    view = Camera_GetViewMatrix();
    if (light->transformMode == 0)
    {
        PSMTXMultVecSR(view, &light->worldDirX, &light->viewDirX);
    }
    else
    {
        *(IVec3*)&light->viewDirX = *(IVec3*)&light->worldDirX;
    }

    modelLightStruct_setEnabled(light, 1, lbl_803DE75C);
    light->lightKind = MODEL_LIGHT_KIND_DIRECTIONAL;
    light->projectedLightChannelPreference = 1;
    light->attenuationNear = lbl_803DE750;
    light->attenuationFar = lbl_803DE754;
    GXInitLightDistAttn(&light->diffuseLightObj, light->attenuationNear, lbl_803DE758, GX_DA_MEDIUM);
    GXGetLightAttnK(&light->diffuseLightObj, &light->attenuationK0, &light->attenuationK1, &light->attenuationK2);
    zero = lbl_803DE75C;
    light->attenuationFar = zero;
    light->selectionPriority = 0x7f;
    light->objectLightMaskIndex = 0;
    light->objectLightMask = 1;
    light->transformMode = 0;
    light->field4D = 0;
    light->fieldBC = 0;
    light->diffuseFadeStartColor[0] = 0xff;
    light->diffuseColor[0] = 0xff;
    light->diffuseFadeStartColor[1] = 0xff;
    light->diffuseColor[1] = 0xff;
    light->diffuseFadeStartColor[2] = 0xff;
    light->diffuseColor[2] = 0xff;
    light->diffuseFadeStartColor[3] = 0xff;
    light->diffuseColor[3] = 0xff;
    light->spotCutoff = lbl_803DE79C;
    light->spotFunction = 0;
    GXInitLightAttnA(&light->diffuseLightObj, lbl_803DE760, zero, zero);
    light->field114 = 0;
    light->specularFadeStartColor[0] = 0xff;
    light->specularColor[0] = 0xff;
    light->specularFadeStartColor[1] = 0xff;
    light->specularColor[1] = 0xff;
    light->specularFadeStartColor[2] = 0xff;
    light->specularColor[2] = 0xff;
    light->specularFadeStartColor[3] = 0xff;
    light->specularColor[3] = 0xff;
    light->specularAttenuationScale = lbl_803DE7A0;
    light->specularBrightness = lbl_803DE76C;
    atten = light->specularAttenuationScale * lbl_803DE790;
    GXInitLightAttn(&light->specularLightObj, 0.0f, 0.0f, 1.0f, atten, 0.0f, 1.0f - atten);
    modelLightStruct_startColorFade(light, 0, 0);
    light->diffuseFadeTargetColor[0] = 0xff;
    light->diffuseFadeTargetColor[1] = 0xff;
    light->diffuseFadeTargetColor[2] = 0xff;
    light->diffuseFadeTargetColor[3] = 0xff;
    light->specularFadeTargetColor[0] = 0xff;
    light->specularFadeTargetColor[1] = 0xff;
    light->specularFadeTargetColor[2] = 0xff;
    light->specularFadeTargetColor[3] = 0xff;
    if (light->owner != NULL)
    {
        Obj_BuildInverseWorldTransformMatrix((GameObject*)light->owner, light->inverseWorldProjectionMtx);
    }
    atten = lbl_803DE760;
    light->lightAmount = atten;
    light->attenuationK0 = atten;
    zero = lbl_803DE75C;
    light->attenuationK1 = zero;
    light->attenuationK2 = zero;
    return light;
}

void modelLightStruct_loadDiffuseGXLight(ModelLightStruct* light, GameObject* obj, GXLightID lightId)
{
    f32 viewPos[3];
    f32* view;
    int lightType;

    view = Camera_GetViewMatrix();
    lightType = light->lightKind;
    switch (lightType)
    {
    case 2:
    case 8:
        if (gModelLightUseModelRelativePositions != 0)
        {
            f32 worldPos[3];
            if (light->transformMode == 0)
            {
                worldPos[0] = obj->anim.localPosX - playerMapOffsetX;
                worldPos[1] = obj->anim.localPosY;
                worldPos[2] = obj->anim.localPosZ - playerMapOffsetZ;
                PSMTXMultVec(view, worldPos, viewPos);
            }
            else
            {
                *(IVec3*)viewPos = *(IVec3*)&obj->anim.localPosX;
            }
            PSVECSubtract(&light->viewX, viewPos, viewPos);
            GXInitLightPos(&light->diffuseLightObj, viewPos[0], viewPos[1], viewPos[2]);
        }
        else
        {
            GXInitLightPos(&light->diffuseLightObj, light->viewX, light->viewY, light->viewZ);
        }
        GXInitLightDir(&light->diffuseLightObj, light->viewDirX, light->viewDirY, light->viewDirZ);
        if (obj != NULL && (obj->anim.modelInstance->flags & 0x10) == 0)
        {
            GXColor color;
            f32 amt;
            color.r = light->diffuseColor[0] * (amt = light->lightAmount);
            color.g = light->diffuseColor[1] * amt;
            color.b = light->diffuseColor[2] * amt;
            color.a = light->diffuseColor[3] * amt;
            GXInitLightColor(&light->diffuseLightObj, color);
            GXInitLightAttnK(&light->diffuseLightObj, lbl_803DE760, lbl_803DE75C, *(f32*)&lbl_803DE75C);
        }
        else
        {
            GXColor color;
            color = *(GXColor*)light->diffuseColor;
            GXInitLightColor(&light->diffuseLightObj, color);
            GXInitLightAttnK(&light->diffuseLightObj, light->attenuationK0, light->attenuationK1,
                             light->attenuationK2);
        }
        break;
    case 4:
    {
        f32 worldPos[3];
        GXColor color;
        if (obj != NULL)
        {
            if (light->transformMode == 0)
            {
                worldPos[0] = obj->anim.localPosX - playerMapOffsetX;
                worldPos[1] = obj->anim.localPosY;
                worldPos[2] = obj->anim.localPosZ - playerMapOffsetZ;
                PSMTXMultVec(view, worldPos, viewPos);
            }
            else
            {
                *(IVec3*)viewPos = *(IVec3*)&obj->anim.localPosX;
            }
        }
        else
        {
            viewPos[0] = lbl_803DE75C;
            viewPos[1] = lbl_803DE75C;
            viewPos[2] = lbl_803DE75C;
        }
        PSVECScale(&light->viewDirX, &light->viewX, lbl_803DE7A4);
        PSVECAdd(&light->viewX, viewPos, viewPos);
        GXInitLightPos(&light->diffuseLightObj, viewPos[0], viewPos[1], viewPos[2]);
        color = *(GXColor*)light->diffuseColor;
        GXInitLightColor(&light->diffuseLightObj, color);
        GXInitLightAttnK(&light->diffuseLightObj, lbl_803DE760, lbl_803DE75C, *(f32*)&lbl_803DE75C);
        break;
    }
    }
    GXLoadLightObjImm(&light->diffuseLightObj, lightId);
}

void modelLightStruct_loadChannelLight(int channel, ModelLightStruct* light, GameObject* obj)
{
    f32 viewDir[3];
    f32 localDir[3];
    GXColor color;
    int lightId[1];
    f32* view[1];
    int lightType;

    view[0] = NULL;
    lightId[0] = 0;
    if (gModelLightChannelStates[channel].mode == 0 || gModelLightChannelStates[channel].mode == 2)
    {
        modelLightStruct_loadDiffuseGXLight(light, obj, gModelLightNextGXLightId);
    }
    else
    {
        lightId[0] = gModelLightNextGXLightId;
        view[0] = Camera_GetViewMatrix();
        lightType = light->lightKind;
        switch (lightType)
        {
        case 2:
            PSVECSubtract(&obj->anim.localPosX, &light->worldX, localDir);
            PSVECNormalize(localDir, localDir);
            if (light->transformMode == 0)
            {
                PSMTXMultVecSR(view[0], localDir, viewDir);
            }
            else
            {

                *(IVec3*)viewDir = *(IVec3*)localDir;
            }
            GXInitSpecularDir(&light->specularLightObj, viewDir[0], viewDir[1], viewDir[2]);
            break;
        case 3:
            break;
        case 4:
            GXInitSpecularDir(&light->specularLightObj, light->viewDirX, light->viewDirY, light->viewDirZ);
            break;
        }
        color = *(GXColor*)light->specularColor;
        GXInitLightColor(&light->specularLightObj, color);
        GXLoadLightObjImm(&light->specularLightObj, lightId[0]);
    }
    gModelLightChannelStates[channel].lightMask |= gModelLightNextGXLightId;
    gModelLightNextGXLightId <<= 1;
}

void modelLightChannel_configure(int i, int mode, int matSrc)
{
    gModelLightChannelStates[i].mode = mode;
    gModelLightChannelStates[i].lightMask = 0;
    gModelLightChannelStates[i].matSrc = matSrc;
    gModelLightChannelStates[i].active = 1;
}
void modelLightChannels_applyGXControls(void)
{
    ModelLightChannelState* entry;
    int channel;
    u8 activeMask;
    int attnFn;

    activeMask = 0;
    for (channel = 0; channel <= 5; channel++)
    {
        entry = &gModelLightChannelStates[channel];
        if (entry->active != 0)
        {
            if (entry->mode == 0)
            {
                attnFn = entry->lightMask != 0 ? 1 : 2;
                GXSetChanCtrl(channel, entry->lightMask != 0, GX_SRC_REG, entry->matSrc, entry->lightMask,
                              entry->lightMask != 0 ? GX_DF_CLAMP : GX_DF_NONE, attnFn);
            }
            else if (entry->mode == 2)
            {
                attnFn = entry->lightMask != 0 ? 1 : 2;
                GXSetChanCtrl(channel, entry->lightMask != 0, GX_SRC_REG, entry->matSrc, entry->lightMask, GX_DF_NONE, attnFn);
            }
            else
            {
                attnFn = entry->lightMask != 0 ? 0 : 2;
                GXSetChanCtrl(channel, entry->lightMask != 0, GX_SRC_REG, entry->matSrc, entry->lightMask, GX_DF_NONE, attnFn);
            }
            activeMask |= 1 << channel;
        }
    }

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

void modelLightChannels_reset(u8 useModelRelative)
{
    gModelLightUseModelRelativePositions = useModelRelative;
    gModelLightNextGXLightId = 1;
    gModelLightChannelStates[0].active = 0;
    gModelLightChannelStates[1].active = 0;
    gModelLightChannelStates[2].active = 0;
    gModelLightChannelStates[3].active = 0;
    gModelLightChannelStates[4].active = 0;
    gModelLightChannelStates[5].active = 0;
}

void modelLightStruct_selectBrightestAabbLights(f32 minX, f32 minY, f32 minZ, f32 maxX, f32 maxY, f32 maxZ,
                                                ModelLightStruct** outLights, int maxLights, int* outCount)
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
        if (((ModelLightStruct*)light)->enabled != 0 && ((ModelLightStruct*)light)->lightKind == 2 &&
            ((ModelLightStruct*)light)->attenuationFar > lbl_803DE75C &&
            ((ModelLightStruct*)light)->affectsAabbLightSelection != 0)
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
                intensity = lbl_803DE760 / (((ModelLightStruct*)light)->attenuationK0 +
                                            (dist * (((ModelLightStruct*)light)->attenuationK2 * dist) +
                                             ((ModelLightStruct*)light)->attenuationK1 * dist));
                red = intensity * light[0xa8];
                red = (red < 0.0f) ? 0.0f : ((red > 255.0f) ? 255.0f : red);
                green = intensity * light[0xa9];
                green = (green < 0.0f) ? 0.0f : ((green > 255.0f) ? 255.0f : green);
                blue = intensity * light[0xaa];
                blue = (blue < 0.0f) ? 0.0f : ((blue > 255.0f) ? 255.0f : blue);
                green = (red < green) ? green : red;
                ((ModelLightStruct*)light)->selectionScore = green;
                blue = (((ModelLightStruct*)light)->selectionScore > blue) ? ((ModelLightStruct*)light)->selectionScore
                                                                           : blue;
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
        outLights[(*outCount)++] = (ModelLightStruct*)light;
        ((ModelLightStruct*)light)->selectionScore = dist;
    }
}


void modelLightStruct_selectObjectLights(GameObject* obj, ModelLightStruct** outLights, int maxLights, s32* outCount,
                                         int typeMask)
{
    f32 delta[3];
    ModelLightStruct* candidates[20];
    int i;
    ModelLightStruct* light;
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
        objectLightMask = 1 << obj->anim.modelInstance->modelLightMaskIndex;
    }
    else
    {
        objectLightMask = 1;
    }

    candidateCount = 0;
    for (i = 0; i < gModelLightCount; i++)
    {
        light = (ModelLightStruct*)gModelLightList[i];
        if (light->enabled != 0 && (light->lightKind & typeMask) != 0 &&
            (light->objectLightMask & objectLightMask) != 0)
        {
            lightType = light->lightKind;
            if (lightType == 4)
            {
                light->selectionScore = lbl_803DE768;
            }
            else if (lightType == 8)
            {
                if (light->projectionTexture != NULL &&
                    modelLightStruct_projectedLightIntersectsObject(light, obj) != 0)
                {
                    PSVECSubtract(&obj->anim.worldPosX, &light->worldX, delta);
                    dist = PSVECMag(delta);
                    intensity = lbl_803DE764;
                    light->selectionScore = intensity + intensity / dist;
                    light->lightAmount = modelLightStruct_getObjectIntensity(light, obj);
                }
                else
                {
                    light->selectionScore = lbl_803DE75C;
                }
            }
            else
            {
                intensity = modelLightStruct_getObjectIntensity(light, obj);
                light->lightAmount = intensity;
                red = light->lightAmount * light->diffuseColor[0];
                red = (red < 0.0f) ? 0.0f : ((red > 255.0f) ? 255.0f : red);
                green = light->lightAmount * light->diffuseColor[1];
                green = (green < 0.0f) ? 0.0f : ((green > 255.0f) ? 255.0f : green);
                blue = light->lightAmount * light->diffuseColor[2];
                blue = (blue < 0.0f) ? 0.0f : ((blue > 255.0f) ? 255.0f : blue);
                red = (red > green) ? red : green;
                light->selectionScore = red;
                blue = (light->selectionScore > blue) ? light->selectionScore : blue;
                light->selectionScore = blue;
            }

            if (light->selectionScore > lbl_803DE75C)
            {
                light->selectionScore += (f32)((int)light->selectionPriority << 8);
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
            if (candidates[i]->selectionScore > intensity)
            {
                intensity = candidates[i]->selectionScore;
                light = candidates[i];
            }
        }
        outLights[(*outCount)++] = light;
        light->selectionScore = -light->selectionScore;
    }
}

void lightGetColor(int i, u8* r, u8* g, u8* b)
{
    u8* base = gModelLightColorTable;
    *r = base[i * 4];
    *g = base[i * 4 + 1];
    *b = base[i * 4 + 2];
}

void lightSetColor(int i, u8 r, u8 g, u8 b)
{
    u8* base = gModelLightColorTable;
    base[i * 4] = r;
    base[i * 4 + 1] = g;
    base[i * 4 + 2] = b;
}


void updateLights(void)
{
    f32 viewPos[3];
    f32 concatMtx[16];
    ModelLightStruct* light;
    f32* view;
    int i;
    int fadeState;

    view = Camera_GetViewMatrix();
    for (i = 0; i < gModelLightCount; i++)
    {
        light = gModelLightList[i];
        fadeState = light->activeState;
        if (fadeState == 1)
        {
            light->activeIntensity += light->activeIntensityStep;
            if (light->activeIntensity >= lbl_803DE760)
            {
                light->activeIntensity = *(f32*)&lbl_803DE760;
                light->activeState = 2;
            }
        }
        else if (fadeState == 3)
        {
            light->activeIntensity += light->activeIntensityStep;
            if (light->activeIntensity <= lbl_803DE788)
            {
                light->activeIntensity = *(f32*)&lbl_803DE788;
                light->activeState = 0;
                light->enabled = 0;
            }
        }

        if (light->enabled != 0)
        {
            if (light->lightKind != MODEL_LIGHT_KIND_DIRECTIONAL)
            {
                if (light->owner != NULL)
                {
                    Obj_TransformLocalPointByWorldMatrix(light->owner, &light->localX, &light->worldX, 1);
                }
                if (light->transformMode == 0)
                {
                    viewPos[0] = light->worldX - playerMapOffsetX;
                    viewPos[1] = light->worldY;
                    viewPos[2] = light->worldZ - playerMapOffsetZ;
                    PSMTXMultVec(view, viewPos, &light->viewX);
                }
                else
                {
                    *(IVec3*)&light->viewX = *(IVec3*)&light->worldX;
                }
            }

            if (light->owner != NULL)
            {
                Obj_TransformLocalVectorByWorldMatrix(light->owner, &light->localDirX, &light->worldDirX);
            }
            if (light->transformMode == 0)
            {
                PSMTXMultVecSR(view, &light->worldDirX, &light->viewDirX);
            }
            else
            {
                *(IVec3*)&light->viewDirX = *(IVec3*)&light->worldDirX;
            }

            if (light->colorFadeMode != 0)
            {
                modelLightStruct_updateColorFade(light);
            }
            else
            {
                light->diffuseColor[0] = (f32)light->diffuseFadeStartColor[0] * light->activeIntensity;
                light->diffuseColor[1] = (f32)light->diffuseFadeStartColor[1] * light->activeIntensity;
                light->diffuseColor[2] = (f32)light->diffuseFadeStartColor[2] * light->activeIntensity;
                light->diffuseColor[3] = (f32)light->diffuseFadeStartColor[3] * light->activeIntensity;
                light->specularColor[0] = (f32)light->specularFadeStartColor[0] * light->activeIntensity;
                light->specularColor[1] = (f32)light->specularFadeStartColor[1] * light->activeIntensity;
                light->specularColor[2] = (f32)light->specularFadeStartColor[2] * light->activeIntensity;
                light->specularColor[3] = (f32)light->specularFadeStartColor[3] * light->activeIntensity;
            }

            if (light->lightKind == MODEL_LIGHT_KIND_PROJECTED)
            {
                Obj_BuildInverseWorldTransformMatrix((GameObject*)light->owner, light->inverseWorldProjectionMtx);
                PSMTXConcat(light->inverseWorldProjectionMtx, Camera_GetInverseViewMatrix(), concatMtx);
                PSMTXConcat(light->lightProjectionTexMtx, concatMtx, light->projectionTexMtx);
            }
        }
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
        textureFree((Texture*)(light->glowTexture));
    }
    mm_free(light);
}


ModelLightStruct* objCreateLight(void* owner, u8 addToList)
{
    ModelLightStruct* light;
    if (addToList)
    {
        if (gModelLightCount >= 0x32)
        {
            return NULL;
        }
        light = objAllocLight(owner);
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
    light = objAllocLight(owner);
    if (light != NULL)
    {
        return light;
    }
    return NULL;
}

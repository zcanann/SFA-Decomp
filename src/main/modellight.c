#include "main/model_light.h"

typedef struct {
    int x, y, z;
} IVec3;

extern void mm_free(void *ptr);

/*
 * --INFO--
 *
 * Function: gameTextSetWindow
 * EN v1.0 Address: 0x80017434
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001746C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
/* moved below GameTextSlot/global declarations */

/*
 * --INFO--
 *
 * Function: FUN_80017460
 * EN v1.0 Address: 0x80017460
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800191FC
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 *
FUN_80017460(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,int param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017468
 * EN v1.0 Address: 0x80017468
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001947C
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined2 *
FUN_80017468(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            ,undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: textRenderStr
 * EN v1.0 Address: 0x800174D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8001AE18
 * EN v1.1 Size: 1760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

extern f32 timeDelta;

#pragma push
#pragma scheduling off

#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

/*
 * --INFO--
 *
 * Function: FUN_80017500
 * EN v1.0 Address: 0x80017500
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8001BD8C
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80017500(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_8001786c
 * EN v1.0 Address: 0x8001786C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80024F40
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8001786c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80017998
 * EN v1.0 Address: 0x80017998
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80029260
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined *
FUN_80017998(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
            undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9
            )
{
    return 0;
}

/* Pattern wrappers. */
#pragma dont_inline on
#pragma dont_inline reset

/* ObjModel/model-file accessors. */

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole off
#pragma peephole reset

#pragma pop

/* Global game-state / text accessors. */

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole off

#pragma peephole reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

void objSetEventName(u8 *obj, void *name) {
    *(void **)(obj + 0x60) = name;
}

#pragma peephole off

#pragma dont_inline on

#pragma dont_inline reset
#pragma peephole reset

/* Simple field/global accessors. */

void modelLightStruct_setGlowProjectionRadius(ModelLightStruct *light, f32 radius) {
    light->glowProjectionRadius = radius;
}

f32 *modelLightStruct_getProjectionTexMtx(ModelLightStruct *p) {
    return p->projectionTexMtx;
}

void *modelLightStruct_getProjectionTexture(ModelLightStruct *p) {
    return p->projectionTexture;
}

void modelLightStruct_setProjectionTexture(ModelLightStruct *p, void *v) {
    p->projectionTexture = v;
}

int modelLightStruct_getProjectedLightChannelPreference(ModelLightStruct *p) {
    return p->projectedLightChannelPreference;
}

void modelLightStruct_setProjectedLightChannelPreference(ModelLightStruct *p, int v) {
    p->projectedLightChannelPreference = v;
}

void modelLightStruct_setSelectionPriority(ModelLightStruct *p, u8 v) {
    p->selectionPriority = v;
}

int modelLightStruct_getActiveState(ModelLightStruct *p) {
    return p->activeState;
}

f32 modelLightStruct_getRadius(ModelLightStruct *p) {
    return p->attenuationFar;
}

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

void modelLightStruct_setAffectsAabbLightSelection(ModelLightStruct *p, u8 v) {
    p->affectsAabbLightSelection = v;
}

void lightSetField4D(ModelLightStruct *p, u8 v) {
    p->field4D = v;
}

void lightSetFieldBC_8001db14(ModelLightStruct *p, u8 v) {
    p->fieldBC = v;
}

void modelLightStruct_setLightKind(ModelLightStruct *p, int v) {
    p->lightKind = v;
}

extern u8 gModelLightCount;
extern void *gModelLightList[];
extern void *objAllocLight(void *owner);
extern void GXInitLightDistAttn(u8 *lt_obj, f32 ref_dist, f32 ref_br, int dist_func);
extern void GXGetLightAttnK(u8 *lt_obj, f32 *k0, f32 *k1, f32 *k2);
extern void GXInitLightAttnA(u8 *lt_obj, f32 a0, f32 a1, f32 a2);
extern void GXInitLightAttn(u8 *lt_obj, f32 a0, f32 a1, f32 a2, f32 k0, f32 k1, f32 k2);
extern void *mmAlloc(int size, int type, int flag);
extern void *memset(void *dst, int val, int n);
extern f32 *Camera_GetViewMatrix(void);
extern void PSMTXMultVec(f32 *mtx, f32 *in, f32 *out);
extern void PSMTXMultVecSR(f32 *mtx, f32 *in, f32 *out);
extern void Vec_normalize(f32 *dst, f32 *src);
extern void Obj_TransformLocalPointByWorldMatrix(u8 *obj, f32 *src, f32 *dst, u8 flag);
extern void Obj_TransformLocalVectorByWorldMatrix(void *obj, f32 *src, f32 *dst);
extern void Obj_BuildInverseWorldTransformMatrix(u8 *obj, f32 *out);
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
extern void textureFree(void *tex);

#pragma peephole off
#pragma scheduling off
void *objCreateLight(int arg, u8 addToList) {
    void *light;
    if (addToList) {
        if (gModelLightCount >= 0x32) {
            return NULL;
        }
        light = objAllocLight((void *)arg);
        if (light == NULL) {
            return NULL;
        }
        {
            int i = gModelLightCount++;
            gModelLightList[i] = light;
        }
        return light;
    }
    light = objAllocLight((void *)arg);
    if (light != NULL) {
        return light;
    }
    return NULL;
}
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off
void modelLightStruct_freeSlot(void **lightSlot) {
    int count;
    int i;
    ModelLightStruct *light;

    light = *lightSlot;
    if (light != NULL) {
        for (i = 0; i < (count = gModelLightCount); i++) {
            if (gModelLightList[i] == light) {
                break;
            }
        }

        if (i < count) {
            while (i < count - 1) {
                gModelLightList[i] = gModelLightList[i + 1];
                i++;
            }
            gModelLightCount--;
        }

        if (light->glowType == 2 && light->glowTexture != NULL) {
            textureFree(light->glowTexture);
        }
        mm_free(light);
        *lightSlot = NULL;
    }
}

void ModelLightStruct_free(ModelLightStruct *light) {
    int count;
    int i;

    for (i = 0; i < (count = gModelLightCount); i++) {
        if (gModelLightList[i] == light) {
            break;
        }
    }

    if (i < count) {
        while (i < count - 1) {
            gModelLightList[i] = gModelLightList[i + 1];
            i++;
        }
        gModelLightCount--;
    }

    if (light->glowType == 2 && light->glowTexture != NULL) {
        textureFree(light->glowTexture);
    }
    mm_free(light);
}

void *modelLightStruct_createPointLight(int unused, u8 red, u8 green, u8 blue, u8 setFlag) {
    u8 *light;
    u8 *newLight;

    if (gModelLightCount >= 0x32) {
        light = NULL;
    } else {
        newLight = objAllocLight((void *)unused);
        if (newLight == NULL) {
            light = NULL;
        } else {
            int index = gModelLightCount++;
            gModelLightList[index] = newLight;
            light = newLight;
        }
    }

    if (light != NULL) {
        *(int *)(light + 0x50) = 2;
        light[0xac] = red;
        light[0xa8] = red;
        light[0xad] = green;
        light[0xa9] = green;
        light[0xae] = blue;
        light[0xaa] = blue;
        light[0xaf] = 0;
        light[0xab] = 0;
        light[0xbc] = 1;
        *(f32 *)(light + 0x140) = lbl_803DE750;
        *(f32 *)(light + 0x144) = lbl_803DE754;
        GXInitLightDistAttn(light + 0x68, *(f32 *)(light + 0x140), lbl_803DE758, 2);
        GXGetLightAttnK(light + 0x68, (f32 *)(light + 0x124), (f32 *)(light + 0x128),
                        (f32 *)(light + 0x12c));
        if (setFlag != 0) {
            light[0x2fb] = 1;
        }
    }

    return light;
}
#pragma pop

#pragma dont_inline on
#pragma push
#pragma scheduling off
#pragma peephole off
void *objAllocLight(void *owner) {
    u8 *light;
    f32 tmp[3];
    f32 *view;
    f32 zero;
    f32 atten;

    light = mmAlloc(0x300, 0x1a, 0);
    if (light == NULL) {
        return NULL;
    }

    memset(light, 0, 0x300);
    *(void **)light = owner;

    if (*(void **)light != NULL) {
        zero = lbl_803DE75C;
        *(f32 *)(light + 4) = zero;
        *(f32 *)(light + 8) = zero;
        *(f32 *)(light + 0xc) = zero;
        Obj_TransformLocalPointByWorldMatrix(*(u8 **)light, (f32 *)(light + 4), (f32 *)(light + 0x10), 1);
    } else {
        zero = lbl_803DE75C;
        *(f32 *)(light + 0x10) = zero;
        *(f32 *)(light + 0x14) = zero;
        *(f32 *)(light + 0x18) = zero;
    }

    view = Camera_GetViewMatrix();
    if (*(int *)(light + 0x60) == 0) {
        tmp[0] = *(f32 *)(light + 0x10) - playerMapOffsetX;
        tmp[1] = *(f32 *)(light + 0x14);
        tmp[2] = *(f32 *)(light + 0x18) - playerMapOffsetZ;
        PSMTXMultVec(view, tmp, (f32 *)(light + 0x1c));
    } else {
        *(IVec3 *)(light + 0x1c) = *(IVec3 *)(light + 0x10);
    }

    if (*(void **)light != NULL) {
        zero = lbl_803DE75C;
        *(f32 *)(light + 0x28) = zero;
        *(f32 *)(light + 0x2c) = zero;
        *(f32 *)(light + 0x30) = lbl_803DE760;
        Vec_normalize((f32 *)(light + 0x28), (f32 *)(light + 0x28));
        Obj_TransformLocalVectorByWorldMatrix(*(void **)light, (f32 *)(light + 0x28), (f32 *)(light + 0x34));
    } else {
        zero = lbl_803DE75C;
        *(f32 *)(light + 0x34) = zero;
        *(f32 *)(light + 0x38) = zero;
        *(f32 *)(light + 0x3c) = lbl_803DE760;
        Vec_normalize((f32 *)(light + 0x34), (f32 *)(light + 0x34));
    }

    view = Camera_GetViewMatrix();
    if (*(int *)(light + 0x60) == 0) {
        PSMTXMultVecSR(view, (f32 *)(light + 0x34), (f32 *)(light + 0x40));
    } else {
        *(IVec3 *)(light + 0x40) = *(IVec3 *)(light + 0x34);
    }

    modelLightStruct_setEnabled((ModelLightStruct *)light, 1, lbl_803DE75C);
    *(int *)(light + 0x50) = 4;
    *(int *)(light + 0x54) = 1;
    *(f32 *)(light + 0x140) = lbl_803DE750;
    *(f32 *)(light + 0x144) = lbl_803DE754;
    GXInitLightDistAttn(light + 0x68, *(f32 *)(light + 0x140), lbl_803DE758, 2);
    GXGetLightAttnK(light + 0x68, (f32 *)(light + 0x124), (f32 *)(light + 0x128), (f32 *)(light + 0x12c));
    zero = lbl_803DE75C;
    *(f32 *)(light + 0x144) = zero;
    light[0x2fc] = 0x7f;
    *(int *)(light + 0x5c) = 0;
    light[0x64] = 1;
    *(int *)(light + 0x60) = 0;
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
    *(f32 *)(light + 0xb4) = lbl_803DE79C;
    *(int *)(light + 0xb8) = 0;
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
    *(f32 *)(light + 0x10c) = lbl_803DE7A0;
    *(f32 *)(light + 0x110) = lbl_803DE76C;
    atten = *(f32 *)(light + 0x10c) * lbl_803DE790;
    zero = lbl_803DE75C;
    GXInitLightAttn(light + 0xc0, zero, zero, lbl_803DE760, atten, zero,
                    lbl_803DE760 - atten);
    modelLightStruct_startColorFade((ModelLightStruct *)light, 0, 0);
    light[0xb0] = 0xff;
    light[0xb1] = 0xff;
    light[0xb2] = 0xff;
    light[0xb3] = 0xff;
    light[0x108] = 0xff;
    light[0x109] = 0xff;
    light[0x10a] = 0xff;
    light[0x10b] = 0xff;
    if (*(void **)light != NULL) {
        Obj_BuildInverseWorldTransformMatrix(*(u8 **)light, (f32 *)(light + 0x170));
    }
    atten = lbl_803DE760;
    *(f32 *)(light + 0x134) = atten;
    *(f32 *)(light + 0x124) = atten;
    zero = lbl_803DE75C;
    *(f32 *)(light + 0x128) = zero;
    *(f32 *)(light + 0x12c) = zero;
    return light;
}
#pragma pop
#pragma dont_inline reset

void modelLightStruct_setProjectionTevModes(ModelLightStruct *p, void *a, void *b) {
    p->projectionTevColorMode = (int)a;
    p->projectionTevAlphaMode = (int)b;
}

#pragma peephole off
#pragma peephole reset

extern u8 lbl_803DB408;

#pragma push
#pragma scheduling off
#pragma peephole off
void modelLightStruct_setGlowColor(ModelLightStruct *light, u8 red, u8 green, u8 blue, u8 alpha) {
    light->glowColor[0] = red;
    light->glowColor[1] = green;
    light->glowColor[2] = blue;
    light->glowColor[3] = alpha;
}

void modelLightStruct_getProjectionTevModes(ModelLightStruct *p, void **a, void **b) {
    *a = (void *)p->projectionTevColorMode;
    *b = (void *)p->projectionTevAlphaMode;
}

void modelLightStruct_setSpecularTargetColor(ModelLightStruct *p, u8 a, u8 b, u8 c, u8 d) {
    p->specularFadeTargetColor[0] = a;
    p->specularFadeTargetColor[1] = b;
    p->specularFadeTargetColor[2] = c;
    p->specularFadeTargetColor[3] = d;
}

void modelLightStruct_setDiffuseTargetColor(ModelLightStruct *p, u8 a, u8 b, u8 c, u8 d) {
    p->diffuseFadeTargetColor[0] = a;
    p->diffuseFadeTargetColor[1] = b;
    p->diffuseFadeTargetColor[2] = c;
    p->diffuseFadeTargetColor[3] = d;
}

#pragma dont_inline on
#pragma dont_inline reset

void modelLightStruct_getPosition(ModelLightStruct *p, f32 *a, f32 *b, f32 *c) {
    *a = p->viewX;
    *b = p->viewY;
    *c = p->viewZ;
}

void modelLightStruct_getWorldPosition(ModelLightStruct *p, f32 *a, f32 *b, f32 *c) {
    *a = p->worldX;
    *b = p->worldY;
    *c = p->worldZ;
}

#pragma peephole on
#pragma peephole reset

#pragma dont_inline on

#pragma dont_inline reset

void lightSetColor(int i, u8 a, u8 b, u8 c) {
    u8 *base = &lbl_803DB408;
    base[i * 4] = a;
    base[i * 4 + 1] = b;
    base[i * 4 + 2] = c;
}

void modelLightStruct_setObjectLightMaskIndex(ModelLightStruct *p, int n) {
    p->objectLightMaskIndex = n;
    p->objectLightMask = (u8)(1 << n);
}

#pragma pop

extern f32 lbl_803DE764;
extern f32 lbl_803DE778;
extern f32 lbl_803DE78C;
extern f32 lbl_803DE788;
extern f32 lbl_803DE794;
extern f32 lbl_803DE798;
extern void *textureLoadAsset(int assetId);
extern int randomGetRange(int lo, int hi);

#pragma push
#pragma scheduling off
#pragma peephole off
void modelLightStruct_getSpecularColor(ModelLightStruct *p, u8 *a, u8 *b, u8 *c, u8 *d) {
    *a = p->specularColor[0];
    *b = p->specularColor[1];
    *c = p->specularColor[2];
    *d = p->specularColor[3];
}

void modelLightStruct_getDiffuseColor(ModelLightStruct *p, u8 *a, u8 *b, u8 *c, u8 *d) {
    *a = p->diffuseColor[0];
    *b = p->diffuseColor[1];
    *c = p->diffuseColor[2];
    *d = p->diffuseColor[3];
}

void modelLightStruct_setAngularAttenuation(ModelLightStruct *p, f32 a, f32 b, f32 c) {
    GXInitLightAttnA((u8 *)p + 0x68, a, b, c);
}

void modelLightStruct_setSpecularColor(ModelLightStruct *p, u8 a, u8 b, u8 c, u8 d) {
    p->specularFadeStartColor[0] = a;
    p->specularColor[0] = a;
    p->specularFadeStartColor[1] = b;
    p->specularColor[1] = b;
    p->specularFadeStartColor[2] = c;
    p->specularColor[2] = c;
    p->specularFadeStartColor[3] = d;
    p->specularColor[3] = d;
}

void modelLightStruct_setDiffuseColor(ModelLightStruct *p, u8 a, u8 b, u8 c, u8 d) {
    p->diffuseFadeStartColor[0] = a;
    p->diffuseColor[0] = a;
    p->diffuseFadeStartColor[1] = b;
    p->diffuseColor[1] = b;
    p->diffuseFadeStartColor[2] = c;
    p->diffuseColor[2] = c;
    p->diffuseFadeStartColor[3] = d;
    p->diffuseColor[3] = d;
}

void lightGetColor(int i, u8 *a, u8 *b, u8 *c) {
    u8 *base = &lbl_803DB408;
    *a = base[i * 4];
    *b = base[i * 4 + 1];
    *c = base[i * 4 + 2];
}

#pragma dont_inline on
#pragma dont_inline reset

void modelLightStruct_updateColorFade(ModelLightStruct *light) {
    f32 progress;
    f32 intensity;
    int mode;

    mode = light->colorFadeMode;
    if (mode == 2) {
        light->colorFadeProgress += light->colorFadeStep * timeDelta;
    } else if (mode > 0 && mode < 2) {
        light->colorFadeTimer += light->colorFadeStep * timeDelta;
        if (light->colorFadeTimer >= lbl_803DE760) {
            light->colorFadeProgress = (f32)randomGetRange(0, 100) / lbl_803DE778;
            light->colorFadeTimer = lbl_803DE75C;
        }
    }

    progress = light->colorFadeProgress;
    if (progress > lbl_803DE760) {
        light->colorFadeProgress = lbl_803DE760 - (progress - lbl_803DE760);
        light->colorFadeStep = -light->colorFadeStep;
    } else if (progress < lbl_803DE75C) {
        light->colorFadeProgress = -progress;
        light->colorFadeStep = -light->colorFadeStep;
    }

    progress = light->colorFadeProgress;
    light->diffuseColor[0] = (u8)(int)(progress * (f32)(light->diffuseFadeTargetColor[0] - light->diffuseFadeStartColor[0]) + (f32)light->diffuseFadeStartColor[0]);
    light->diffuseColor[1] = (u8)(int)(progress * (f32)(light->diffuseFadeTargetColor[1] - light->diffuseFadeStartColor[1]) + (f32)light->diffuseFadeStartColor[1]);
    light->diffuseColor[2] = (u8)(int)(progress * (f32)(light->diffuseFadeTargetColor[2] - light->diffuseFadeStartColor[2]) + (f32)light->diffuseFadeStartColor[2]);
    light->diffuseColor[3] = (u8)(int)(progress * (f32)(light->diffuseFadeTargetColor[3] - light->diffuseFadeStartColor[3]) + (f32)light->diffuseFadeStartColor[3]);

    intensity = light->activeIntensity;
    light->diffuseColor[0] = (u8)(int)((f32)light->diffuseColor[0] * intensity);
    light->diffuseColor[1] = (u8)(int)((f32)light->diffuseColor[1] * intensity);
    light->diffuseColor[2] = (u8)(int)((f32)light->diffuseColor[2] * intensity);
    light->diffuseColor[3] = (u8)(int)((f32)light->diffuseColor[3] * intensity);

    light->specularColor[0] = (u8)(int)(progress * (f32)(light->specularFadeTargetColor[0] - light->specularFadeStartColor[0]) + (f32)light->specularFadeStartColor[0]);
    light->specularColor[1] = (u8)(int)(progress * (f32)(light->specularFadeTargetColor[1] - light->specularFadeStartColor[1]) + (f32)light->specularFadeStartColor[1]);
    light->specularColor[2] = (u8)(int)(progress * (f32)(light->specularFadeTargetColor[2] - light->specularFadeStartColor[2]) + (f32)light->specularFadeStartColor[2]);
    light->specularColor[3] = (u8)(int)(progress * (f32)(light->specularFadeTargetColor[3] - light->specularFadeStartColor[3]) + (f32)light->specularFadeStartColor[3]);

    light->specularColor[0] = (u8)(int)((f32)light->specularColor[0] * intensity);
    light->specularColor[1] = (u8)(int)((f32)light->specularColor[1] * intensity);
    light->specularColor[2] = (u8)(int)((f32)light->specularColor[2] * intensity);
    light->specularColor[3] = (u8)(int)((f32)light->specularColor[3] * intensity);
}

void modelLightStruct_startColorFade(ModelLightStruct *light, int mode, s16 frames) {
    f32 denom;

    light->colorFadeMode = mode;
    if (mode != 0) {
        if (frames != 0) {
            denom = frames;
        } else {
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

void modelLightStruct_setupGlow(ModelLightStruct *light, u32 textureId, u8 red, u8 green, u8 blue, u8 alpha, f32 scale) {
    void *texture;

    if (textureId != 0) {
        texture = textureLoadAsset(textureId);
        light->glowTexture = texture;
        if (texture != NULL) {
            light->glowType = 2;
        }
    } else {
        texture = textureLoadAsset(0x605);
        light->glowTexture = texture;
        if (texture != NULL) {
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

void modelLightStruct_setEnabled(ModelLightStruct *light, u8 enabled, f32 duration) {
    f32 zero;

    zero = lbl_803DE75C;
    if (zero == duration) {
        if (enabled != 0) {
            light->activeState = 2;
            light->activeIntensity = lbl_803DE760;
        } else {
            light->activeState = 0;
            light->activeIntensity = zero;
        }
        light->enabled = enabled;
        return;
    }

    if (enabled != 0) {
        if (light->activeState == 0 || light->activeState == 3) {
            light->activeState = 1;
            light->activeIntensityStep = lbl_803DE760 / (lbl_803DE794 * duration);
            light->activeIntensity = lbl_803DE75C;
        }
        light->enabled = 1;
        return;
    }

    if (light->activeState != 2 && light->activeState != 1) {
        return;
    }
    light->activeState = 3;
    light->activeIntensityStep = lbl_803DE798 / (lbl_803DE794 * duration);
    light->activeIntensity = lbl_803DE760;
}

void modelLightStruct_setProjectionFarZ(ModelLightStruct *p, f32 v) {
    p->projectionFarZ = (v < p->projectionNearZ) ? p->projectionNearZ : ((v > lbl_803DE764) ? lbl_803DE764 : v);
}

void modelLightStruct_setProjectionNearZ(ModelLightStruct *p, f32 v) {
    p->projectionNearZ = (v < lbl_803DE78C) ? lbl_803DE78C : ((v > p->projectionFarZ) ? p->projectionFarZ : v);
}

#pragma peephole on

#pragma peephole reset
#pragma pop

extern u8 gModelLightUseModelRelativePositions;
extern int gModelLightNextGXLightId;

typedef struct {
    u8 active;
    u8 _1[3];
    int lightMask;
    int mode;
    int matSrc;
} ModelLightChannelState;
extern ModelLightChannelState gModelLightChannelStates[];

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
void mm_free(void *p);
#pragma dont_inline reset

void modelLightChannel_configure(int i, int a, int b) {
    gModelLightChannelStates[i].mode = a;
    gModelLightChannelStates[i].lightMask = 0;
    gModelLightChannelStates[i].matSrc = b;
    gModelLightChannelStates[i].active = 1;
}

#pragma peephole off
void modelLightChannels_reset(u8 v) {
    gModelLightUseModelRelativePositions = v;
    gModelLightNextGXLightId = 1;
    gModelLightChannelStates[0].active = 0;
    gModelLightChannelStates[1].active = 0;
    gModelLightChannelStates[2].active = 0;
    gModelLightChannelStates[3].active = 0;
    gModelLightChannelStates[4].active = 0;
    gModelLightChannelStates[5].active = 0;
}
#pragma peephole reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on

#pragma dont_inline reset

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on

#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma pop

typedef f32 Mtx[3][4];
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern void PSVECNormalize(f32 *src, f32 *dst);

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma dont_inline on
void Obj_TransformLocalVectorByWorldMatrix(void *obj, f32 *src, f32 *dst);
#pragma dont_inline reset


#pragma dont_inline on
void Obj_TransformLocalPointByWorldMatrix(u8 *obj, f32 *src, f32 *dst, u8 flag);
#pragma dont_inline reset


void modelLightStruct_setDirection(ModelLightStruct *s, f32 x, f32 y, f32 z) {
    f32 *view;
    if (s->owner != NULL) {
        s->localDirX = x;
        s->localDirY = y;
        s->localDirZ = z;
        Vec_normalize(&s->localDirX, &s->localDirX);
        Obj_TransformLocalVectorByWorldMatrix(s->owner, &s->localDirX, &s->worldDirX);
    } else {
        s->worldDirX = x;
        s->worldDirY = y;
        s->worldDirZ = z;
        Vec_normalize(&s->worldDirX, &s->worldDirX);
    }
    view = Camera_GetViewMatrix();
    if (s->transformMode == 0) {
        PSMTXMultVecSR(view, &s->worldDirX, &s->viewDirX);
    } else {
        {
            typedef struct { int x, y, z; } IVec3;
            *(IVec3 *)&s->viewDirX = *(IVec3 *)&s->worldDirX;
        }
    }
}

void modelLightStruct_setPosition(ModelLightStruct *s, f32 x, f32 y, f32 z) {
    f32 tmp[3];
    f32 *view;
    if (s->owner != NULL) {
        s->localX = x;
        s->localY = y;
        s->localZ = z;
        Obj_TransformLocalPointByWorldMatrix(s->owner, &s->localX, &s->worldX, 1);
    } else {
        s->worldX = x;
        s->worldY = y;
        s->worldZ = z;
    }
    view = Camera_GetViewMatrix();
    if (s->transformMode == 0) {
        tmp[0] = s->worldX - playerMapOffsetX;
        tmp[1] = s->worldY;
        tmp[2] = s->worldZ - playerMapOffsetZ;
        PSMTXMultVec(view, tmp, &s->viewX);
    } else {
        {
            typedef struct { int x, y, z; } IVec3;
            *(IVec3 *)&s->viewX = *(IVec3 *)&s->worldX;
        }
    }
}

extern void GXInitSpecularDir(u8 *lt_obj, f32 x, f32 y, f32 z);
extern void GXInitLightColor(u8 *lt_obj, void *color);
extern void GXLoadLightObjImm(u8 *lt_obj, int lightId);
extern void GXInitLightPos(u8 *lt_obj, f32 x, f32 y, f32 z);
extern void GXInitLightDir(u8 *lt_obj, f32 x, f32 y, f32 z);
extern void GXInitLightAttnK(u8 *lt_obj, f32 k0, f32 k1, f32 k2);
extern void GXSetChanCtrl(int channel, int enable, int ambSrc, int matSrc, int lightMask, int diffFn,
                          int attnFn);
extern void GXSetNumChans(int numChannels);
extern void PSVECScale(f32 *src, f32 *dst, f32 scale);
extern void PSVECAdd(f32 *a, f32 *b, f32 *out);
extern f32 lbl_803DE7A4;
extern f32 *Camera_GetInverseViewMatrix(void);
extern void PSMTXConcat(f32 *a, f32 *b, f32 *ab);

#pragma push
#pragma scheduling off
#pragma peephole off
void modelLightStruct_loadDiffuseGXLight(u8 *light, u8 *obj, int lightId) {
    f32 viewPos[3];
    f32 *view;
    int lightType;

    view = Camera_GetViewMatrix();
    lightType = *(int *)(light + 0x50);
    switch (lightType) {
    case 2:
    case 8:
        if (gModelLightUseModelRelativePositions != 0) {
            f32 worldPos[3];
            if (*(int *)(light + 0x60) == 0) {
                worldPos[0] = *(f32 *)(obj + 0xc) - playerMapOffsetX;
                worldPos[1] = *(f32 *)(obj + 0x10);
                worldPos[2] = *(f32 *)(obj + 0x14) - playerMapOffsetZ;
                PSMTXMultVec(view, worldPos, viewPos);
            } else {
                *(IVec3 *)viewPos = *(IVec3 *)(obj + 0xc);
            }
            PSVECSubtract((f32 *)(light + 0x1c), viewPos, viewPos);
            GXInitLightPos(light + 0x68, viewPos[0], viewPos[1], viewPos[2]);
        } else {
            GXInitLightPos(light + 0x68, *(f32 *)(light + 0x1c), *(f32 *)(light + 0x20),
                           *(f32 *)(light + 0x24));
        }
        GXInitLightDir(light + 0x68, *(f32 *)(light + 0x40), *(f32 *)(light + 0x44),
                       *(f32 *)(light + 0x48));
        if (obj != NULL && (*(u32 *)(*(int *)(obj + 0x50) + 0x44) & 0x10) == 0) {
            u8 rgba[4];
            u32 color;
            rgba[0] = (f32)light[0xa8] * *(f32 *)(light + 0x134);
            rgba[1] = (f32)light[0xa9] * *(f32 *)(light + 0x134);
            rgba[2] = (f32)light[0xaa] * *(f32 *)(light + 0x134);
            rgba[3] = (f32)light[0xab] * *(f32 *)(light + 0x134);
            color = *(u32 *)rgba;
            GXInitLightColor(light + 0x68, &color);
            GXInitLightAttnK(light + 0x68, lbl_803DE760, lbl_803DE75C, lbl_803DE75C);
        } else {
            u32 color;
            color = *(u32 *)(light + 0xa8);
            GXInitLightColor(light + 0x68, &color);
            GXInitLightAttnK(light + 0x68, *(f32 *)(light + 0x124), *(f32 *)(light + 0x128),
                             *(f32 *)(light + 0x12c));
        }
        break;
    case 4: {
        f32 worldPos[3];
        u32 color;
        if (obj != NULL) {
            if (*(int *)(light + 0x60) == 0) {
                worldPos[0] = *(f32 *)(obj + 0xc) - playerMapOffsetX;
                worldPos[1] = *(f32 *)(obj + 0x10);
                worldPos[2] = *(f32 *)(obj + 0x14) - playerMapOffsetZ;
                PSMTXMultVec(view, worldPos, viewPos);
            } else {
                *(IVec3 *)viewPos = *(IVec3 *)(obj + 0xc);
            }
        } else {
            viewPos[0] = lbl_803DE75C;
            viewPos[1] = lbl_803DE75C;
            viewPos[2] = lbl_803DE75C;
        }
        PSVECScale((f32 *)(light + 0x40), (f32 *)(light + 0x1c), lbl_803DE7A4);
        PSVECAdd((f32 *)(light + 0x1c), viewPos, viewPos);
        GXInitLightPos(light + 0x68, viewPos[0], viewPos[1], viewPos[2]);
        color = *(u32 *)(light + 0xa8);
        GXInitLightColor(light + 0x68, &color);
        GXInitLightAttnK(light + 0x68, lbl_803DE760, lbl_803DE75C, lbl_803DE75C);
        break;
    }
    }
    GXLoadLightObjImm(light + 0x68, lightId);
}
#pragma pop

void modelLightStruct_loadChannelLight(int channel, u8 *light, u8 *obj) {
    f32 viewDir[3];
    f32 localDir[3];
    u32 color;
    int lightId;
    f32 *view;
    int lightType;

    if (gModelLightChannelStates[channel].mode == 0 || gModelLightChannelStates[channel].mode == 2) {
        modelLightStruct_loadDiffuseGXLight(light, obj, gModelLightNextGXLightId);
    } else {
        lightId = gModelLightNextGXLightId;
        view = Camera_GetViewMatrix();
        lightType = *(int *)(light + 0x50);
        switch (lightType) {
        case 2:
            PSVECSubtract((f32 *)(obj + 0xc), (f32 *)(light + 0x10), localDir);
            PSVECNormalize(localDir, localDir);
            if (*(int *)(light + 0x60) == 0) {
                PSMTXMultVecSR(view, localDir, viewDir);
            } else {
                typedef struct { int x, y, z; } IVec3;
                *(IVec3 *)viewDir = *(IVec3 *)localDir;
            }
            GXInitSpecularDir(light + 0xc0, viewDir[0], viewDir[1], viewDir[2]);
            break;
        case 3:
            break;
        case 4:
            GXInitSpecularDir(light + 0xc0, *(f32 *)(light + 0x40), *(f32 *)(light + 0x44),
                              *(f32 *)(light + 0x48));
            break;
        }
        color = *(u32 *)(light + 0x100);
        GXInitLightColor(light + 0xc0, &color);
        GXLoadLightObjImm(light + 0xc0, lightId);
    }
    gModelLightChannelStates[channel].lightMask |= gModelLightNextGXLightId;
    gModelLightNextGXLightId <<= 1;
}

void modelLightChannels_applyGXControls(void) {
    int activeMask;
    int lightMask;
    int channel;
    int attnFn;
    ModelLightChannelState *entry;

    activeMask = 0;
    channel = 0;
    entry = gModelLightChannelStates;
    do {
        if (entry->active != 0) {
            if (entry->mode == 0) {
                lightMask = entry->lightMask;
                if (lightMask != 0) {
                    attnFn = 1;
                } else {
                    attnFn = 2;
                }
                GXSetChanCtrl(channel, lightMask != 0, 0, entry->matSrc, lightMask, lightMask != 0 ? 2 : 0,
                              attnFn);
            } else if (entry->mode == 2) {
                lightMask = entry->lightMask;
                attnFn = lightMask != 0 ? 1 : 2;
                GXSetChanCtrl(channel, lightMask != 0, 0, entry->matSrc, lightMask, 0, attnFn);
            } else {
                lightMask = entry->lightMask;
                attnFn = lightMask != 0 ? 0 : 2;
                GXSetChanCtrl(channel, lightMask != 0, 0, entry->matSrc, lightMask, 0, attnFn);
            }
            activeMask = (activeMask | (1 << channel)) & 0xff;
        }
        entry++;
        channel++;
    } while (channel <= 5);

    activeMask &= 0xff;

    if ((activeMask & 1) != 0) {
        if ((activeMask & 4) == 0) {
            GXSetChanCtrl(2, 0, 0, 0, 0, 0, 2);
        }
    } else if ((activeMask & 4) != 0) {
        GXSetChanCtrl(0, 0, 0, 0, 0, 0, 2);
    }

    if ((activeMask & 2) != 0) {
        if ((activeMask & 8) == 0) {
            GXSetChanCtrl(3, 0, 0, 0, 0, 0, 2);
        }
    } else if ((activeMask & 8) != 0) {
        GXSetChanCtrl(1, 0, 0, 0, 0, 0, 2);
    }

    if ((activeMask & 0x2a) != 0) {
        GXSetNumChans(2);
    } else if ((activeMask & 0x15) != 0) {
        GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
        GXSetNumChans(1);
    } else {
        GXSetChanCtrl(4, 0, 0, 0, 0, 0, 2);
        GXSetChanCtrl(5, 0, 0, 0, 0, 0, 2);
        GXSetNumChans(0);
    }
}

void updateLights(void) {
    f32 viewPos[3];
    f32 concatMtx[16];
    f32 *view;
    u8 *light;
    int i;
    int fadeState;

    view = Camera_GetViewMatrix();
    for (i = 0; i < gModelLightCount; i++) {
        light = gModelLightList[i];
        fadeState = *(int *)(light + 0x58);
        if (fadeState == 1) {
            *(f32 *)(light + 0x138) += *(f32 *)(light + 0x13c);
            if (*(f32 *)(light + 0x138) >= lbl_803DE760) {
                *(f32 *)(light + 0x138) = lbl_803DE760;
                *(int *)(light + 0x58) = 2;
            }
        } else if (fadeState == 3) {
            *(f32 *)(light + 0x138) += *(f32 *)(light + 0x13c);
            if (*(f32 *)(light + 0x138) <= lbl_803DE788) {
                *(f32 *)(light + 0x138) = lbl_803DE788;
                *(int *)(light + 0x58) = 0;
                light[0x4c] = 0;
            }
        }

        if (light[0x4c] != 0) {
            if (*(int *)(light + 0x50) != 4) {
                if (*(void **)light != NULL) {
                    Obj_TransformLocalPointByWorldMatrix(*(u8 **)light, (f32 *)(light + 4), (f32 *)(light + 0x10),
                                                         1);
                }
                if (*(int *)(light + 0x60) == 0) {
                    viewPos[0] = *(f32 *)(light + 0x10) - playerMapOffsetX;
                    viewPos[1] = *(f32 *)(light + 0x14);
                    viewPos[2] = *(f32 *)(light + 0x18) - playerMapOffsetZ;
                    PSMTXMultVec(view, viewPos, (f32 *)(light + 0x1c));
                } else {
                    *(int *)(light + 0x1c) = *(int *)(light + 0x10);
                    *(int *)(light + 0x20) = *(int *)(light + 0x14);
                    *(int *)(light + 0x24) = *(int *)(light + 0x18);
                }
            }

            if (*(void **)light != NULL) {
                Obj_TransformLocalVectorByWorldMatrix(*(void **)light, (f32 *)(light + 0x28),
                                                       (f32 *)(light + 0x34));
            }
            if (*(int *)(light + 0x60) == 0) {
                PSMTXMultVecSR(view, (f32 *)(light + 0x34), (f32 *)(light + 0x40));
            } else {
                *(int *)(light + 0x40) = *(int *)(light + 0x34);
                *(int *)(light + 0x44) = *(int *)(light + 0x38);
                *(int *)(light + 0x48) = *(int *)(light + 0x3c);
            }

            if (*(int *)(light + 0x2d8) != 0) {
                modelLightStruct_updateColorFade((ModelLightStruct *)light);
            } else {
                light[0xa8] = (u8)(int)((f32)light[0xac] * *(f32 *)(light + 0x138));
                light[0xa9] = (u8)(int)((f32)light[0xad] * *(f32 *)(light + 0x138));
                light[0xaa] = (u8)(int)((f32)light[0xae] * *(f32 *)(light + 0x138));
                light[0xab] = (u8)(int)((f32)light[0xaf] * *(f32 *)(light + 0x138));
                light[0x100] = (u8)(int)((f32)light[0x104] * *(f32 *)(light + 0x138));
                light[0x101] = (u8)(int)((f32)light[0x105] * *(f32 *)(light + 0x138));
                light[0x102] = (u8)(int)((f32)light[0x106] * *(f32 *)(light + 0x138));
                light[0x103] = (u8)(int)((f32)light[0x107] * *(f32 *)(light + 0x138));
            }

            if (*(int *)(light + 0x50) == 8) {
                Obj_BuildInverseWorldTransformMatrix(*(u8 **)light, (f32 *)(light + 0x170));
        PSMTXConcat((f32 *)(light + 0x170), Camera_GetInverseViewMatrix(), concatMtx);
        PSMTXConcat((f32 *)(light + 0x1b0), concatMtx, (f32 *)(light + 0x230));
            }
        }
    }
}

#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma peephole reset


#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma peephole on
#pragma peephole reset

#pragma pop

extern void GXInitLightSpot(u8 *lt_obj, f32 cutoff, int spot_func);
extern f32 PSVECMag(f32 *v);
extern f32 PSVECDotProduct(f32 *a, f32 *b);
extern f32 lbl_803DE768;
extern f32 lbl_802C1A88[];

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset

void modelLightStruct_setSpotAttenuation(ModelLightStruct *obj, f32 cutoff, int mode) {
    obj->spotCutoff = cutoff;
    obj->spotFunction = mode;
    if (mode == 0) {
        GXInitLightAttnA((u8 *)obj + 0x68, lbl_803DE760, lbl_803DE75C, lbl_803DE75C);
    } else {
        GXInitLightSpot((u8 *)obj + 0x68, obj->spotCutoff, obj->spotFunction);
    }
}

void modelLightStruct_setDistanceAttenuation(u8 *obj, f32 a, f32 b) {
    *(f32 *)(obj + 0x140) = a;
    *(f32 *)(obj + 0x144) = b;
    GXInitLightDistAttn(obj + 0x68, *(f32 *)(obj + 0x140), lbl_803DE758, 2);
    GXGetLightAttnK(obj + 0x68, (f32 *)(obj + 0x124), (f32 *)(obj + 0x128), (f32 *)(obj + 0x12c));
}

#pragma dont_inline on
u8 modelLightStruct_projectedLightIntersectsObject(u8 *light, u8 *obj) {
    f32 localPos[3];
    f32 worldPos[3];
    f32 projected[3];
    f32 cornerPos[3];
    f32 corners[24];
    f32 extent;
    f32 scaledExtent;
    u32 clipMask;
    u32 combinedClipMask;
    u32 *cornerWords;
    u32 *sourceWords;
    int i;

    extent = *(f32 *)(obj + 0xa8);
    scaledExtent = *(f32 *)(obj + 8) * extent;
    cornerWords = (u32 *)corners;
    sourceWords = (u32 *)lbl_802C1A88;
    i = 12;
    do {
        cornerWords[0] = sourceWords[0];
        cornerWords[1] = sourceWords[1];
        cornerWords += 2;
        sourceWords += 2;
    } while (--i != 0);

    worldPos[0] = *(f32 *)(obj + 0xc) - playerMapOffsetX;
    worldPos[1] = *(f32 *)(obj + 0x10);
    worldPos[2] = *(f32 *)(obj + 0x14) - playerMapOffsetZ;
    PSMTXMultVec((f32 *)(light + 0x170), worldPos, localPos);

    if (*(int *)(light + 0x168) == 0) {
        if (*(f32 *)(light + 0x15c) < localPos[0] - extent ||
            localPos[0] + scaledExtent < *(f32 *)(light + 0x158) ||
            *(f32 *)(light + 0x150) < localPos[1] - extent ||
            localPos[1] + scaledExtent < *(f32 *)(light + 0x154) ||
            *(f32 *)(light + 0x164) < localPos[2] - extent ||
            localPos[2] + scaledExtent < *(f32 *)(light + 0x160)) {
            return 0;
        }
        return 1;
    }

    if (*(f32 *)(light + 0x164) < localPos[2] - extent ||
        localPos[2] + scaledExtent < *(f32 *)(light + 0x160)) {
        return 0;
    }

    combinedClipMask = 0x3f;
    for (i = 0; i < 8; i++) {
        cornerPos[0] = localPos[0] + scaledExtent * corners[i * 3 + 0];
        cornerPos[1] = localPos[1] + scaledExtent * corners[i * 3 + 1];
        cornerPos[2] = localPos[2] + scaledExtent * corners[i * 3 + 2];
        PSMTXMultVec((f32 *)(light + 0x1f0), cornerPos, projected);
        if (projected[2] != lbl_803DE75C) {
            projected[0] /= projected[2];
            projected[1] /= projected[2];
        }

        clipMask = 0;
        if (cornerPos[2] < *(f32 *)(light + 0x160)) {
            clipMask |= 0x10;
        }
        if (*(f32 *)(light + 0x164) < cornerPos[2]) {
            clipMask |= 0x20;
        }
        if (projected[0] < lbl_803DE75C) {
            clipMask |= 1;
        } else if (projected[0] > lbl_803DE760) {
            clipMask |= 2;
        }
        if (projected[1] < lbl_803DE75C) {
            clipMask |= 4;
        } else if (projected[1] > lbl_803DE760) {
            clipMask |= 8;
        }
        if (clipMask == 0) {
            return 1;
        }
        combinedClipMask &= clipMask;
        if (combinedClipMask == 0) {
            return 1;
        }
    }

    return 0;
}
#pragma dont_inline reset

#pragma dont_inline on
f32 modelLightStruct_getObjectIntensity(u8 *light, u8 *obj) {
    f32 delta[3];
    f32 dist;
    f32 amount;

    if (*(void **)(obj + 0xc4) != NULL) {
        obj = *(u8 **)(obj + 0xc4);
    }

    PSVECSubtract((f32 *)(obj + 0x18), (f32 *)(light + 0x10), delta);
    dist = PSVECMag(delta) - *(f32 *)(obj + 0xa8) * *(f32 *)(obj + 8);
    if (dist > lbl_803DE768 || dist > *(f32 *)(light + 0x144)) {
        return lbl_803DE75C;
    }

    if (dist < *(f32 *)(light + 0x140)) {
        amount = lbl_803DE760;
    } else {
        amount = lbl_803DE760 - (dist - *(f32 *)(light + 0x140)) /
                                    (*(f32 *)(light + 0x144) - *(f32 *)(light + 0x140));
    }

    if (*(int *)(light + 0xb8) != 0) {
        PSVECScale(delta, delta, lbl_803DE760 / dist);
        PSVECDotProduct((f32 *)(light + 0x34), delta);
    }

    return amount;
}
#pragma dont_inline reset

#pragma dont_inline on
void modelLightStruct_selectBrightestAabbLights(f32 minX, f32 minY, f32 minZ, f32 maxX, f32 maxY, f32 maxZ,
                 u8 **outLights, int maxLights, int *outCount) {
    int i;
    f32 delta[3];
    f32 center[3];
    u8 *candidates[20];
    u8 *light;
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
    for (i = 0; i < gModelLightCount; i++) {
        light = gModelLightList[i];
        if (light[0x4c] != 0 && *(int *)(light + 0x50) == 2 && *(f32 *)(light + 0x144) > lbl_803DE75C &&
            light[0x2fb] != 0) {
            PSVECSubtract(center, (f32 *)(light + 0x10), delta);
            dist = PSVECMag(delta);
            if (*(f32 *)(light + 0x10) + *(f32 *)(light + 0x144) >= minX &&
                *(f32 *)(light + 0x14) + *(f32 *)(light + 0x144) >= minY &&
                *(f32 *)(light + 0x18) + *(f32 *)(light + 0x144) >= minZ &&
                *(f32 *)(light + 0x10) - *(f32 *)(light + 0x144) <= maxX &&
                *(f32 *)(light + 0x14) - *(f32 *)(light + 0x144) <= maxY &&
                *(f32 *)(light + 0x18) - *(f32 *)(light + 0x144) <= maxZ) {
                intensity = lbl_803DE760 /
                            (*(f32 *)(light + 0x124) +
                             (dist * (*(f32 *)(light + 0x12c) * dist) + *(f32 *)(light + 0x128) * dist));
                red = intensity * (f32)light[0xa8];
                red = (red < 0.0f) ? 0.0f
                     : ((red > 255.0f) ? 255.0f : red);
                green = intensity * (f32)light[0xa9];
                green = (green < 0.0f) ? 0.0f
                     : ((green > 255.0f) ? 255.0f : green);
                blue = intensity * (f32)light[0xaa];
                blue = (blue < 0.0f) ? 0.0f
                     : ((blue > 255.0f) ? 255.0f : blue);
                if (green < red) {
                    green = red;
                }
                *(f32 *)(light + 0x130) = green;
                if (blue < *(f32 *)(light + 0x130)) {
                    blue = *(f32 *)(light + 0x130);
                }
                *(f32 *)(light + 0x130) = blue;

                selectedCount = candidateCount;
                candidateCount++;
                candidates[selectedCount] = light;
                if (candidateCount >= 20) {
                    break;
                }
            }
        }
    }

    if (maxLights > candidateCount) {
        maxLights = candidateCount;
    }

    *outCount = 0;
    while (*outCount < maxLights) {
        intensity = lbl_803DE75C;
        for (i = 0; i < candidateCount; i++) {
            if (*(f32 *)(candidates[i] + 0x130) > intensity) {
                light = candidates[i];
                intensity = *(f32 *)(light + 0x130);
            }
        }
        outLights[(*outCount)++] = light;
        *(f32 *)(light + 0x130) = lbl_803DE75C;
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void modelLightStruct_selectObjectLights(u8 *obj, u8 **outLights, int maxLights, int *outCount, int typeMask) {
    f32 delta[3];
    u8 *candidates[20];
    int i;
    u8 *light;
    f32 intensity;
    f32 dist;
    f32 red;
    f32 green;
    f32 blue;
    u8 objectLightMask;
    int candidateCount;
    int selectedCount;
    int lightType;

    if (obj != NULL) {
        objectLightMask = 1 << *(u8 *)(*(u32 *)(obj + 0x50) + 0x8d);
    } else {
        objectLightMask = 1;
    }

    candidateCount = 0;
    for (i = 0; i < gModelLightCount; i++) {
        light = gModelLightList[i];
        if (light[0x4c] != 0 && (typeMask & (lightType = *(int *)(light + 0x50))) != 0 &&
            (light[0x64] & objectLightMask) != 0) {
            if (lightType == 4) {
                *(f32 *)(light + 0x130) = lbl_803DE768;
            } else if (lightType == 8) {
                if (*(void **)(light + 0x16c) != NULL && modelLightStruct_projectedLightIntersectsObject(light, obj) != 0) {
                    PSVECSubtract((f32 *)(obj + 0x18), (f32 *)(light + 0x10), delta);
                    dist = PSVECMag(delta);
                    intensity = lbl_803DE764;
                    *(f32 *)(light + 0x130) = intensity + intensity / dist;
                    *(f32 *)(light + 0x134) = modelLightStruct_getObjectIntensity(light, obj);
                } else {
                    *(f32 *)(light + 0x130) = lbl_803DE75C;
                }
            } else {
                intensity = modelLightStruct_getObjectIntensity(light, obj);
                *(f32 *)(light + 0x134) = intensity;
                red = *(f32 *)(light + 0x134) * (f32)light[0xa8];
                red = (red < 0.0f) ? 0.0f
                     : ((red > 255.0f) ? 255.0f : red);
                green = intensity * (f32)light[0xa9];
                green = (green < 0.0f) ? 0.0f
                     : ((green > 255.0f) ? 255.0f : green);
                blue = intensity * (f32)light[0xaa];
                blue = (blue < 0.0f) ? 0.0f
                     : ((blue > 255.0f) ? 255.0f : blue);
                if (green < red) {
                    green = red;
                }
                *(f32 *)(light + 0x130) = green;
                if (blue < *(f32 *)(light + 0x130)) {
                    blue = *(f32 *)(light + 0x130);
                }
                *(f32 *)(light + 0x130) = blue;
            }

            if (*(f32 *)(light + 0x130) > lbl_803DE75C) {
                *(f32 *)(light + 0x130) += (f32)((int)light[0x2fc] << 8);
                selectedCount = candidateCount;
                candidateCount++;
                candidates[selectedCount] = light;
                if (candidateCount >= 20) {
                    break;
                }
            }
        }
    }

    if (maxLights > candidateCount) {
        maxLights = candidateCount;
    }

    *outCount = 0;
    while (*outCount < maxLights) {
        intensity = lbl_803DE75C;
        for (i = 0; i < candidateCount; i++) {
            if (*(f32 *)(candidates[i] + 0x130) > intensity) {
                light = candidates[i];
                intensity = *(f32 *)(light + 0x130);
            }
        }
        outLights[(*outCount)++] = light;
        *(f32 *)(light + 0x130) = -*(f32 *)(light + 0x130);
    }
}
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset


#pragma dont_inline on
#pragma dont_inline reset

void modelLightStruct_updateGlowAlpha(ModelLightStruct *light) {
    s16 v;

    if (light->glowType == 0) {
        return;
    }
    if (light->enabled == 0) {
        return;
    }
    v = light->glowAlpha + light->glowAlphaStep;
    if (v < 0) {
        v = 0;
        light->glowAlphaStep = 0;
    } else if (v > 0xff) {
        v = 0xff;
        light->glowAlphaStep = 0;
    }
    light->glowAlpha = v;
}

#pragma dont_inline on
#pragma dont_inline reset

#pragma pop


#pragma push
#pragma scheduling off
#pragma peephole off
#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma dont_inline on

#pragma dont_inline reset

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma dont_inline on
int randomGetRange(int lo, int hi);
#pragma dont_inline reset

#pragma dont_inline on
#pragma dont_inline reset

#pragma pop

extern void C_MTXLightPerspective(f32 *m, f32 fovY, f32 aspect, f32 scaleS, f32 scaleT, f32 transS, f32 transT);

#pragma push
#pragma scheduling off
#pragma peephole off
void modelLightStruct_setupPerspectiveProjection(ModelLightStruct *obj, f32 a, f32 b) {
    obj->projectionFovY = a;
    obj->projectionAspect = b;
    obj->projectionType = 1;
    C_MTXLightPerspective(obj->lightProjectionTexMtx, obj->projectionFovY, obj->projectionAspect,
                          lbl_803DE790, lbl_803DE790, lbl_803DE790, lbl_803DE790);
    C_MTXLightPerspective(obj->lightProjectionClipMtx, obj->projectionFovY, obj->projectionAspect,
                          lbl_803DE790, lbl_803DE790, lbl_803DE790, lbl_803DE790);
}

extern void C_MTXLightOrtho(f32 *m, f32 t, f32 b, f32 l, f32 r, f32 scaleS, f32 scaleT,
                            f32 transS, f32 transT);

void modelLightStruct_setupOrthoProjection(ModelLightStruct *obj, f32 a, f32 b, f32 c, f32 d, f32 e, f32 f) {
    f32 fScale;
    f32 eScale;

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
    C_MTXLightOrtho(obj->lightProjectionClipMtx, obj->projectionTop, obj->projectionBottom,
                    obj->projectionLeft, obj->projectionRight, lbl_803DE790, lbl_803DE790,
                    lbl_803DE790, lbl_803DE790);
}

#pragma dont_inline on
#pragma dont_inline reset
#pragma pop


#pragma push
#pragma scheduling off
#pragma peephole off

void modelLightStruct_setSpecularAttenuation(ModelLightStruct *obj, f32 a, f32 b) {
    u8 *lightObj;
    f32 zero;
    f32 one;
    f32 atten;

    obj->specularAttenuationScale = a;
    obj->specularBrightness = b;
    atten = obj->specularAttenuationScale * lbl_803DE790;
    lightObj = (u8 *)obj + 0xc0;
    zero = lbl_803DE75C;
    one = lbl_803DE760;
    GXInitLightAttn(lightObj, zero, zero, one, atten, zero, one - atten);
}
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma scheduling off
#pragma peephole off
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma peephole off
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma peephole off
#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset
#pragma peephole reset

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop


#pragma push
#pragma scheduling off
#pragma peephole off

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma optimize_for_size on
#pragma optimize_for_size reset

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
void Obj_BuildInverseWorldTransformMatrix(u8 *obj, f32 *out);
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma fp_contract off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on

#pragma peephole off
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma opt_loop_invariants off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
void *mmAlloc(int size, int type, int flag);
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma opt_strength_reduction off
#pragma opt_loop_invariants off
#pragma opt_loop_invariants reset
#pragma opt_strength_reduction reset
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline on
#pragma dont_inline reset
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma opt_common_subs off
#pragma opt_common_subs reset
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma dont_inline on
#pragma dont_inline reset
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma opt_strength_reduction off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma fp_contract off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma optimization_level 1
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off

#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop


#pragma dont_inline off

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

#pragma push
#pragma scheduling off
#pragma peephole off
#pragma pop

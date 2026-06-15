#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/xyzanimator.h"
#include "main/objhits.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_800175cc();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8008112c();
extern void queueGlowRender(void* light);

extern f64 DOUBLE_803e3d80;
extern f32 lbl_803E3D78;
extern f32 timeDelta;
extern f32 lbl_803E30E0;

int kaldachompme_getExtraSize(void);

int kaldachompme_getObjectTypeId(void);

void kaldachompme_free(void);

void kaldachompme_render(undefined4 param_1, undefined4 param_2, undefined4 param_3, undefined4 param_4, undefined4 param_5, s8 renderFlag);

void kaldachompme_hitDetect(void);

void kaldachompme_update(int obj);

void kaldachompme_init(int obj, int params);

void kaldachompme_release(void);

void kaldachompme_initialise(void);

ObjectDescriptor gKaldaChompMeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)kaldachompme_initialise,
    (ObjectDescriptorCallback)kaldachompme_release,
    0,
    (ObjectDescriptorCallback)kaldachompme_init,
    (ObjectDescriptorCallback)kaldachompme_update,
    (ObjectDescriptorCallback)kaldachompme_hitDetect,
    (ObjectDescriptorCallback)kaldachompme_render,
    (ObjectDescriptorCallback)kaldachompme_free,
    (ObjectDescriptorCallback)kaldachompme_getObjectTypeId,
    kaldachompme_getExtraSize,
};

#pragma scheduling on
#pragma peephole on
extern void ModelLightStruct_free(void* p);
extern void modelLightStruct_setEnabled(int light, int onoff, f32 intensity);
extern void spawnExplosion(int obj, f32 scale, int a, int b, int c, int d, int e, int f, int g);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Sfx_SetObjectChannelVolume(int obj, int channel, u8 vol, f32 scale);
extern int Obj_FreeObject(int obj);
extern int getAngle(f32 a, f32 b);
extern f32 sqrtf(f32 x);
extern void fn_80098B18(int obj, f32 scale, int a, int b, int c, int d);
extern f32 lbl_803E30F0;
extern f32 lbl_803E30F4;
extern f32 lbl_803E30F8;
extern f32 lbl_803E30FC;
extern void* objCreateLight(int obj, int kind);
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int alpha, f32 radius);
extern void modelLightStruct_setDiffuseTargetColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void lightSetField4D(int light, int v);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);
extern void modelLightStruct_startColorFade(int light, int a, int b);
extern f32 lbl_803E3108;
extern f32 lbl_803E310C;
extern void spawnExplosion(int obj, f32 scale, int p3, int p4, int p5, int p6, int p7, int p8, int p9);

void FUN_8016980c(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

void FUN_80169a44(undefined8 param_1, double param_2, double param_3, undefined8 param_4,
                  undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8,
                  uint param_9)
{
    uint uVar1;
    int* piVar2;
    ObjHitsPriorityState* hitState;
    int local_18[2];
    undefined4 local_10;
    uint uStack_c;

    piVar2 = ((GameObject*)param_9)->extra;
    hitState = (ObjHitsPriorityState*)((GameObject*)param_9)->anim.hitReactState;
    ((GameObject*)param_9)->anim.alpha = 0;
    *(undefined4*)(param_9 + 0xf4) = 0xdc;
    hitState->flags &= ~1;
    if (*piVar2 != 0)
    {
        FUN_800175cc((double)lbl_803E3D78, *piVar2, '\0');
    }
    if (((GameObject*)param_9)->anim.seqId == 0x869)
    {
        uVar1 = randomGetRange(0, 1);
        uStack_c = randomGetRange(0x32, 0x3c);
        FUN_8008112c((double)(float)((double)CONCAT44(0x43300000, uStack_c) - DOUBLE_803e3d80), param_2,
                     param_3, param_4, param_5, param_6, param_7, param_8, param_9, 1, 1, 0, uVar1 & 0xff, 0, 1, 0);
    }
    else
    {
        for (local_18[0] = 0; local_18[0] < 0x19; local_18[0] = local_18[0] + 1)
        {
            (*gPartfxInterface)->spawnObject((void*)param_9, 0x715, NULL, 1, -1, local_18);
        }
        FUN_80006824(param_9, SFXsc_attack03);
    }
    return;
}

#pragma scheduling off
#pragma peephole off
void kaldachompspit_hitDetect(void)
{
}

int kaldachompspit_getExtraSize(void) { return 0x4; }
int kaldachompspit_getObjectTypeId(void) { return 0x0; }

void kaldachompspit_free(int* obj)
{
    void* p = *(void**)((GameObject*)obj)->extra;
    if (p != NULL)
    {
        ModelLightStruct_free(p);
    }
}

void kaldachompspit_render(void* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void objRenderFn_8003b8f4(double scale); /* #57 */
    u8* light = **(u8***)&((GameObject*)obj)->extra;
    if (light != NULL && light[0x2f8] != 0 && light[0x4c] != 0)
    {
        queueGlowRender(light);
    }
    if (visible != 0)
    {
        ((void (*)(void*, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E30E0);
    }
}

void kaldachompspit_burst(int obj);

void kaldachompspit_update(int obj)
{
    extern int getTrickyObject(void); /* #57 */
    extern int Obj_GetPlayerObject(void); /* #57 */
    extern int objMove(int obj, f32 vx, f32 vy, f32 vz); /* #57 */
    ObjAnimComponent* objAnim;
    u32* state;
    f32 vx;
    u32 ptr;
    int rnd;
    f32 vy;
    f32 vz;
    s16 v;
    f32 t;

    objAnim = &((GameObject*)obj)->anim;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->unkF4 = (int)((f32)((GameObject*)obj)->unkF4 - timeDelta);
    if (((GameObject*)obj)->unkF4 < 0)
    {
        Sfx_StopObjectChannel(obj, 0x7f);
        Obj_FreeObject(obj);
    }
    else if (objAnim->alpha != 0)
    {
        if (((GameObject*)obj)->unkF4 < 0x11b)
        {
            ((GameObject*)obj)->anim.velocityY = -(lbl_803E30F0 * timeDelta - ((GameObject*)obj)->anim.velocityY);
            if ((f32)(u32)objAnim->alpha - (t = lbl_803E30F4 * timeDelta) > lbl_803E30F8
            )
            {
                objAnim->alpha = (f32)(u32)
                objAnim->alpha - t;
            }
            else
            {
                Sfx_StopObjectChannel(obj, 0x7f);
                objAnim->alpha = 0;
            }
            Sfx_SetObjectChannelVolume(obj, 0x40, (u8)(objAnim->alpha >> 1), lbl_803E30FC);
        }
        vx = ((GameObject*)obj)->anim.velocityX * timeDelta;
        vy = ((GameObject*)obj)->anim.velocityY * timeDelta;
        vz = ((GameObject*)obj)->anim.velocityZ * timeDelta;
        objMove(obj, vx, vy, vz);
        if (((GameObject*)obj)->anim.seqId == 0x869)
        {
            ObjHits_SetHitVolumeSlot((u32)obj, 0x1f, 1, 0);
            ((GameObject*)obj)->anim.rotX += 0x100;
            ((GameObject*)obj)->anim.rotY += 0x800;
        }
        else
        {
            ObjHits_SetHitVolumeSlot((u32)obj, 0xa, 1, 0);
            ((GameObject*)obj)->anim.rotX = getAngle(vx, vz) - 0x8000;
            ((GameObject*)obj)->anim.rotY = 0x4000 - getAngle(sqrtf(vx * vx + vz * vz), vy);
        }
        ObjHits_EnableObject((u32)obj);
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0)
        {
            if (((GameObject*)obj)->unkF4 < 0x17c)
            {
                kaldachompspit_burst(obj);
                return;
            }
            if ((((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject == Obj_GetPlayerObject()) ||
                (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject == getTrickyObject()))
            {
                kaldachompspit_burst(obj);
                return;
            }
        }
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
        {
            kaldachompspit_burst(obj);
        }
        else
        {
            if (((GameObject*)obj)->anim.seqId == 0x869)
            {
                fn_80098B18(obj, lbl_803E30E0, 1, 0, 0, 0);
            }
            else
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x714, NULL, 2, -1,
                                                 &objAnim->alpha);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x715, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, 0x715, NULL, 1, -1, NULL);
            }
            ptr = *state;
            if ((ptr != 0) && (*(u8*)(ptr + 0x2f8) != 0) && (*(u8*)(ptr + 0x4c) != 0))
            {
                rnd = randomGetRange(-0x19, 0x19);
                ptr = *state;
                v = *(u8*)(ptr + 0x2f9) + *(s8*)(ptr + 0x2fa) + rnd;
                if (v < 0)
                {
                    v = 0;
                    *(u8*)(ptr + 0x2fa) = 0;
                }
                else if (v > 0xff)
                {
                    v = 0xff;
                    *(u8*)(ptr + 0x2fa) = 0;
                }
                *(u8*)(*state + 0x2f9) = v;
            }
        }
    }
}

void kaldachompspit_burst(int obj)
{
    extern void Sfx_PlayFromObject(int obj, u32 sfxId); /* #57 */
    int i;
    u32* state;
    ObjHitsPriorityState* hitState;
    u8 rnd;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.alpha = 0;
    ((GameObject*)obj)->unkF4 = 0xdc;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->flags &= ~1;
    if (*state != 0)
    {
        modelLightStruct_setEnabled(*state, 0, lbl_803E30E0);
    }
    if (((GameObject*)obj)->anim.seqId == 0x869)
    {
        rnd = randomGetRange(0, 1);
        spawnExplosion(obj, (f32)(int)randomGetRange(0x32, 0x3c), 1, 1, 0, rnd, 0, 1, 0);
    }
    else
    {
        for (i = 0; i < 0x19; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 0x715, NULL, 1, -1, &i);
        }
        Sfx_PlayFromObject(obj, 0x279);
    }
}

void kaldachompspit_init(int obj)
{
    extern void Sfx_PlayFromObject(int obj, int sfxId); /* #57 */
    int* extra;

    extra = *(int**)&((GameObject*)obj)->extra;
    ((GameObject*)obj)->unkF4 = 400;
    ObjHits_DisableObject((u32)obj);
    ((GameObject*)obj)->anim.alpha = 0xff;
    Sfx_PlayFromObject(obj, 0x278);
    ((GameObject*)obj)->objectFlags |= 0x2000;
    if (*(void**)extra == NULL)
    {
        *extra = (int)objCreateLight(obj, 1);
        if (*(void**)extra != NULL)
        {
            modelLightStruct_setLightKind(*extra, 2);
        }
    }
    if (*(void**)extra != NULL)
    {
        f32 k = lbl_803E30F8;
        modelLightStruct_setPosition(*extra, k, k, k);
        if (((GameObject*)obj)->anim.seqId == 0x869)
        {
            modelLightStruct_setDiffuseColor(*extra, 0xff, 0xc0, 0, 0xff);
            modelLightStruct_setSpecularColor(*extra, 0xff, 0xc0, 0, 0xff);
            modelLightStruct_setupGlow(*extra, 0, 0xff, 0xc0, 0, 0x7f,
                                       lbl_803E3108 * (lbl_803E310C * ((GameObject*)obj)->anim.rootMotionScale));
            modelLightStruct_setDiffuseTargetColor(*extra, 0xff, 0xd2, 0, 0xff);
        }
        else
        {
            modelLightStruct_setDiffuseColor(*extra, 0, 0xff, 0, 0xff);
            modelLightStruct_setSpecularColor(*extra, 0, 0xff, 0, 0xff);
            modelLightStruct_setupGlow(*extra, 0, 0, 0xff, 0, 0x28,
                                       lbl_803E310C * ((GameObject*)obj)->anim.rootMotionScale);
            modelLightStruct_setDiffuseTargetColor(*extra, 0, 0xff, 0, 0xff);
        }
        {
            int a = (int)(lbl_803E310C * ((GameObject*)obj)->anim.rootMotionScale);
            modelLightStruct_setDistanceAttenuation(*extra, (f32)a, (f32)(a + 0x28));
        }
        lightSetField4D(*extra, 1);
        modelLightStruct_setEnabled(*extra, 1, lbl_803E30E0);
        modelLightStruct_startColorFade(*extra, 1, 3);
    }
}

void kaldachompspit_release(void)
{
}

void kaldachompspit_initialise(void)
{
}

void mikabomb_hitDetect(void);

ObjectDescriptor gKaldaChompSpitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)kaldachompspit_initialise,
    (ObjectDescriptorCallback)kaldachompspit_release,
    0,
    (ObjectDescriptorCallback)kaldachompspit_init,
    (ObjectDescriptorCallback)kaldachompspit_update,
    (ObjectDescriptorCallback)kaldachompspit_hitDetect,
    (ObjectDescriptorCallback)kaldachompspit_render,
    (ObjectDescriptorCallback)kaldachompspit_free,
    (ObjectDescriptorCallback)kaldachompspit_getObjectTypeId,
    kaldachompspit_getExtraSize,
};

ObjectDescriptor gPinPonSpikeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pinponspike_initialise,
    (ObjectDescriptorCallback)pinponspike_release,
    0,
    (ObjectDescriptorCallback)pinponspike_init,
    (ObjectDescriptorCallback)pinponspike_update,
    (ObjectDescriptorCallback)pinponspike_hitDetect,
    (ObjectDescriptorCallback)pinponspike_render,
    (ObjectDescriptorCallback)pinponspike_free,
    (ObjectDescriptorCallback)pinponspike_getObjectTypeId,
    pinponspike_getExtraSize,
};

ObjectDescriptor gPollenObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollen_initialise,
    (ObjectDescriptorCallback)pollen_release,
    0,
    (ObjectDescriptorCallback)pollen_init,
    (ObjectDescriptorCallback)pollen_update,
    (ObjectDescriptorCallback)pollen_hitDetect,
    (ObjectDescriptorCallback)pollen_render,
    (ObjectDescriptorCallback)pollen_free,
    (ObjectDescriptorCallback)pollen_getObjectTypeId,
    pollen_getExtraSize,
};

PollenFragmentConfig lbl_80320538 = {
    0x0000,
    0x049F,
    0x00B9,
    0x04BA,
    0x04BA,
    -1,
    0.2f,
    0x0000,
    0xC000,
};

PollenFragmentConfig lbl_8032054C = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x7000,
};

PollenFragmentConfig lbl_80320560 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x2000,
};

PollenFragmentConfig lbl_80320574 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    -1,
    0.2f,
    0x0000,
    0x2000,
};

PollenFragmentConfig lbl_80320588 = {
    0x02FA,
    0x02FB,
    0x0496,
    0x068F,
    0x068F,
    0x068F,
    0.4f,
    0x0026,
    0x3000,
};

PollenFragmentConfig* lbl_8032059C[] = {
    &lbl_80320538,
    &lbl_8032054C,
    &lbl_80320560,
    &lbl_80320574,
    &lbl_80320588,
};

ObjectDescriptor gPollenFragmentObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)pollenfragment_initialise,
    (ObjectDescriptorCallback)pollenfragment_release,
    0,
    (ObjectDescriptorCallback)pollenfragment_init,
    (ObjectDescriptorCallback)pollenfragment_update,
    (ObjectDescriptorCallback)pollenfragment_hitDetect,
    (ObjectDescriptorCallback)pollenfragment_render,
    (ObjectDescriptorCallback)pollenfragment_free,
    (ObjectDescriptorCallback)pollenfragment_getObjectTypeId,
    pollenfragment_getExtraSize,
};

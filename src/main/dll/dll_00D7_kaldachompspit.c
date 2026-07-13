/*
 * kaldachompspit (DLL 0x00D7) - the projectile spat by the KaldaChomp
 * plant. The object flies ballistically (gravity on velocityY), spins,
 * carries a glow light, and bursts on contact. Two variants keyed on
 * anim.seqId: 0x869 is the explosive variant (orange glow, spawnExplosion
 * on burst, fast spin), the default is the green poison spit (green glow,
 * particle fx 0x714/0x715, sfx 0x278 on init / 0x279 on burst). It bursts
 * early when its hit-react target is the player or Tricky, on any contact,
 * or once its unkF4 lifetime runs out, then frees itself.
 *
 * This TU also houses the object descriptors for the sibling objects
 * built from xyzanimator.h (kaldachompme, pinponspike, pollen,
 * pollenfragment) plus the PollenFragmentConfig tables.
 */
#include "main/effect_interfaces.h"
#include "main/object_render_legacy.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/modellight_api.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/dll/xyzanimator.h"
#include "main/objhits.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"

#define KALDACHOMPSPIT_HIT_VOLUME_SLOT_EXPLOSIVE 0x1f
#define KALDACHOMPSPIT_HIT_VOLUME_SLOT_DEFAULT   0xa

#define KALDACHOMPSPIT_OBJFLAG_HITDETECT_DISABLED 0x2000

/* anim.seqId of the explosive variant (docblock: "0x869 is the explosive variant"). */
#define KALDACHOMPSPIT_SEQID_EXPLOSIVE 0x869

/* green poison spit particle fx (docblock: "particle fx 0x714/0x715"). */
#define KALDACHOMPSPIT_PARTFX_POISON_TRAIL 0x714
#define KALDACHOMPSPIT_PARTFX_POISON_BURST 0x715

#define MODEL_LIGHT_KIND_POINT 2

extern f32 lbl_803E30E0;
extern f32 lbl_803E30F0;
extern f32 lbl_803E30F4;
extern f32 lbl_803E30F8;
extern f32 lbl_803E30FC;
extern f32 lbl_803E3108;
extern f32 lbl_803E310C;

extern void queueGlowRender(void* light);
extern void ModelLightStruct_free(void* p);
extern void* objCreateLight(int arg, u8 addToList);
extern void modelLightStruct_setLightKind(int light, int value);
extern void modelLightStruct_setPosition(int light, f32 x, f32 y, f32 z);
extern void modelLightStruct_setDiffuseColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int alpha, f32 radius);
extern void modelLightStruct_setDiffuseTargetColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 near, f32 far);
extern void modelLightStruct_setEnabled(int light, int enabled, f32 scale);
extern void modelLightStruct_startColorFade(int light, int a, int b);
extern void Sfx_StopObjectChannel(u32 obj, u32 channel);
extern void Sfx_SetObjectChannelVolume(u32 obj, u32 channel, u8 volume, f32 volumeScale);
extern void Sfx_PlayFromObject(int obj, u16 sfxId);
int KaldaChompMe_getExtraSize(void);
int KaldaChompMe_getObjectTypeId(void);
void KaldaChompMe_free(void);
void KaldaChompMe_render(int p1, int p2, int p3, int p4, int p5, s8 renderFlag);
void KaldaChompMe_hitDetect(void);
void KaldaChompMe_update(GameObject* obj);
void KaldaChompMe_init(GameObject* obj, int params);
void KaldaChompMe_release(void);
void KaldaChompMe_initialise(void);

ObjectDescriptor gKaldaChompMeObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)KaldaChompMe_initialise,
    (ObjectDescriptorCallback)KaldaChompMe_release,
    0,
    (ObjectDescriptorCallback)KaldaChompMe_init,
    (ObjectDescriptorCallback)KaldaChompMe_update,
    (ObjectDescriptorCallback)KaldaChompMe_hitDetect,
    (ObjectDescriptorCallback)KaldaChompMe_render,
    (ObjectDescriptorCallback)KaldaChompMe_free,
    (ObjectDescriptorCallback)KaldaChompMe_getObjectTypeId,
    KaldaChompMe_getExtraSize,
};

#pragma dont_inline on
void kaldachompspit_burst(GameObject* obj)
{
    int i;
    u32* state;
    ObjHitsPriorityState* hitState;
    u8 rnd;

    state = (obj)->extra;
    (obj)->anim.alpha = 0;
    (obj)->unkF4 = 0xdc;
    hitState = (ObjHitsPriorityState*)(obj)->anim.hitReactState;
    hitState->flags &= ~1;
    if (*state != 0)
    {
        modelLightStruct_setEnabled(*state, 0, lbl_803E30E0);
    }
    if ((obj)->anim.seqId == KALDACHOMPSPIT_SEQID_EXPLOSIVE)
    {
        rnd = randomGetRange(0, 1);
        spawnExplosionLegacy((int)obj, (f32)(int)randomGetRange(0x32, 0x3c), 1, 1, 0, rnd, 0, 1, 0);
    }
    else
    {
        for (i = 0; i < 0x19; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, KALDACHOMPSPIT_PARTFX_POISON_BURST, NULL, 1, -1, &i);
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_lummy311);
    }
}
#pragma dont_inline reset

int KaldaChompSpit_getExtraSize(void)
{
    return 0x4;
}
int KaldaChompSpit_getObjectTypeId(void)
{
    return 0x0;
}

void KaldaChompSpit_free(int* obj)
{
    void* light = *(void**)((GameObject*)obj)->extra;
    if (light != NULL)
    {
        ModelLightStruct_free(light);
    }
}

void KaldaChompSpit_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    u8* light = **(u8***)&obj->extra;
    if (light != NULL && light[0x2f8] != 0 && light[0x4c] != 0)
    {
        queueGlowRender(light);
    }
    if (visible != 0)
    {
        ((void (*)(void*, int, int, int, int, f32))objRenderModelAndHitVolumes)(obj, p2, p3, p4, p5, lbl_803E30E0);
    }
}

void KaldaChompSpit_hitDetect(void)
{
}

void KaldaChompSpit_update(int obj)
{
    ObjAnimComponent* objAnim;
    u32* state;
    f32 vx;
    u32 ptr;
    int rnd;
    f32 vy;
    f32 vz;
    s16 color;
    f32 alphaDecay;

    objAnim = &((GameObject*)obj)->anim;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->unkF4 = (int)((f32)((GameObject*)obj)->unkF4 - timeDelta);
    if (((GameObject*)obj)->unkF4 < 0)
    {
        Sfx_StopObjectChannel(obj, 0x7f);
        Obj_FreeObject((GameObject*)obj);
    }
    else if (objAnim->alpha != 0)
    {
        if (((GameObject*)obj)->unkF4 < 0x11b)
        {
            ((GameObject*)obj)->anim.velocityY = -(lbl_803E30F0 * timeDelta - ((GameObject*)obj)->anim.velocityY);
            if ((f32)(u32)objAnim->alpha - (alphaDecay = lbl_803E30F4 * timeDelta) > lbl_803E30F8)
            {
                objAnim->alpha = (f32)(u32)objAnim->alpha - alphaDecay;
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
        objMove((GameObject*)obj, vx, vy, vz);
        if (((GameObject*)obj)->anim.seqId == KALDACHOMPSPIT_SEQID_EXPLOSIVE)
        {
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, KALDACHOMPSPIT_HIT_VOLUME_SLOT_EXPLOSIVE, 1, 0);
            ((GameObject*)obj)->anim.rotX += 0x100;
            ((GameObject*)obj)->anim.rotY += 0x800;
        }
        else
        {
            ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, KALDACHOMPSPIT_HIT_VOLUME_SLOT_DEFAULT, 1, 0);
            ((GameObject*)obj)->anim.rotX = getAngle(vx, vz) - 0x8000;
            ((GameObject*)obj)->anim.rotY = 0x4000 - getAngle(sqrtf(vx * vx + vz * vz), vy);
        }
        ObjHits_EnableObject((u32)obj);
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0)
        {
            if (((GameObject*)obj)->unkF4 < 0x17c)
            {
                kaldachompspit_burst((GameObject*)(obj));
                return;
            }
            if ((((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject ==
                 (int)Obj_GetPlayerObject()) ||
                (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject ==
                 (u32)getTrickyObject()))
            {
                kaldachompspit_burst((GameObject*)(obj));
                return;
            }
        }
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
        {
            kaldachompspit_burst((GameObject*)(obj));
        }
        else
        {
            if (((GameObject*)obj)->anim.seqId == KALDACHOMPSPIT_SEQID_EXPLOSIVE)
            {
                fn_80098B18Legacy(obj, lbl_803E30E0, 1, 0, 0, 0);
            }
            else
            {
                (*gPartfxInterface)
                    ->spawnObject((void*)obj, KALDACHOMPSPIT_PARTFX_POISON_TRAIL, NULL, 2, -1, &objAnim->alpha);
                (*gPartfxInterface)->spawnObject((void*)obj, KALDACHOMPSPIT_PARTFX_POISON_BURST, NULL, 1, -1, NULL);
                (*gPartfxInterface)->spawnObject((void*)obj, KALDACHOMPSPIT_PARTFX_POISON_BURST, NULL, 1, -1, NULL);
            }
            ptr = *state;
            if ((ptr != 0) && (*(u8*)(ptr + 0x2f8) != 0) && (*(u8*)(ptr + 0x4c) != 0))
            {
                rnd = randomGetRange(-0x19, 0x19);
                ptr = *state;
                color = *(u8*)(ptr + 0x2f9) + *(s8*)(ptr + 0x2fa) + rnd;
                if (color < 0)
                {
                    color = 0;
                    *(u8*)(ptr + 0x2fa) = 0;
                }
                else if (color > 0xff)
                {
                    color = 0xff;
                    *(u8*)(ptr + 0x2fa) = 0;
                }
                *(u8*)(*state + 0x2f9) = color;
            }
        }
    }
}

void KaldaChompSpit_init(GameObject* obj)
{
    int* extra;

    extra = *(int**)&(obj)->extra;
    (obj)->unkF4 = 400;
    ObjHits_DisableObject((u32)obj);
    (obj)->anim.alpha = 0xff;
    Sfx_PlayFromObject((int)obj, SFXTRIG_whiz3_c);
    (obj)->objectFlags |= KALDACHOMPSPIT_OBJFLAG_HITDETECT_DISABLED;
    if (*(void**)extra == NULL)
    {
        *extra = (int)objCreateLight((int)obj, 1);
        if (*(void**)extra != NULL)
        {
            modelLightStruct_setLightKind(*extra, MODEL_LIGHT_KIND_POINT);
        }
    }
    if (*(void**)extra != NULL)
    {
        f32 lightPos = lbl_803E30F8;
        modelLightStruct_setPosition(*extra, lightPos, lightPos, lightPos);
        if ((obj)->anim.seqId == KALDACHOMPSPIT_SEQID_EXPLOSIVE)
        {
            modelLightStruct_setDiffuseColor(*extra, 0xff, 0xc0, 0, 0xff);
            modelLightStruct_setSpecularColor(*extra, 0xff, 0xc0, 0, 0xff);
            modelLightStruct_setupGlow(*extra, 0, 0xff, 0xc0, 0, 0x7f,
                                       lbl_803E3108 * (lbl_803E310C * (obj)->anim.rootMotionScale));
            modelLightStruct_setDiffuseTargetColor(*extra, 0xff, 0xd2, 0, 0xff);
        }
        else
        {
            modelLightStruct_setDiffuseColor(*extra, 0, 0xff, 0, 0xff);
            modelLightStruct_setSpecularColor(*extra, 0, 0xff, 0, 0xff);
            modelLightStruct_setupGlow(*extra, 0, 0, 0xff, 0, 0x28, lbl_803E310C * (obj)->anim.rootMotionScale);
            modelLightStruct_setDiffuseTargetColor(*extra, 0, 0xff, 0, 0xff);
        }
        {
            int nearDist = (int)(lbl_803E310C * (obj)->anim.rootMotionScale);
            modelLightStruct_setDistanceAttenuation(*extra, nearDist, (f32)(nearDist + 0x28));
        }
        lightSetField4D((ModelLightStruct*)*extra, 1);
        modelLightStruct_setEnabled(*extra, 1, lbl_803E30E0);
        modelLightStruct_startColorFade(*extra, 1, 3);
    }
}

void KaldaChompSpit_release(void)
{
}

void KaldaChompSpit_initialise(void)
{
}

ObjectDescriptor gKaldaChompSpitObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)KaldaChompSpit_initialise,
    (ObjectDescriptorCallback)KaldaChompSpit_release,
    0,
    (ObjectDescriptorCallback)KaldaChompSpit_init,
    (ObjectDescriptorCallback)KaldaChompSpit_update,
    (ObjectDescriptorCallback)KaldaChompSpit_hitDetect,
    (ObjectDescriptorCallback)KaldaChompSpit_render,
    (ObjectDescriptorCallback)KaldaChompSpit_free,
    (ObjectDescriptorCallback)KaldaChompSpit_getObjectTypeId,
    KaldaChompSpit_getExtraSize,
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
    (ObjectDescriptorCallback)Pollen_initialise,
    (ObjectDescriptorCallback)Pollen_release,
    0,
    (ObjectDescriptorCallback)Pollen_init,
    (ObjectDescriptorCallback)Pollen_update,
    (ObjectDescriptorCallback)Pollen_hitDetect,
    (ObjectDescriptorCallback)Pollen_render,
    (ObjectDescriptorCallback)Pollen_free,
    (ObjectDescriptorCallback)Pollen_getObjectTypeId,
    Pollen_getExtraSize,
};

PollenFragmentConfig lbl_80320538 = {
    0x0000, 0x049F, 0x00B9, 0x04BA, 0x04BA, -1, 0.2f, 0x0000, 0xC000,
};

PollenFragmentConfig lbl_8032054C = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, 0x068F, 0.4f, 0x0026, 0x7000,
};

PollenFragmentConfig lbl_80320560 = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, 0x068F, 0.4f, 0x0026, 0x2000,
};

PollenFragmentConfig lbl_80320574 = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, -1, 0.2f, 0x0000, 0x2000,
};

PollenFragmentConfig lbl_80320588 = {
    0x02FA, 0x02FB, 0x0496, 0x068F, 0x068F, 0x068F, 0.4f, 0x0026, 0x3000,
};

PollenFragmentConfig* lbl_8032059C[] = {
    &lbl_80320538, &lbl_8032054C, &lbl_80320560, &lbl_80320574, &lbl_80320588,
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

/*
 * pollen (DLL 0x00D9)
 *
 * A drifting pollen mote. It falls under gravity (anim.velocityY ramped by
 * lbl_803E3140 * timeDelta each frame); when its descent passes through zero
 * (prev velocityY >= 0 and the new one <= 0) it bursts: Pollen_burst spawns a
 * fixed batch of pollen-fragment objects (POLLEN_FRAGMENT_OBJECT_ID), plays
 * sfx 0xb7 and hides the mote. The mote also collides: a hit against the
 * player or Tricky triggers a small camera offset + shake (sfx 0xb6) and
 * arms a 60-frame despawn timer; Pollen_hitDetect snaps the mote to the
 * contact point and freezes it. Visible motes emit a particle (fx 0x4ba)
 * each frame. The object frees itself once hidden and idle.
 *
 * This TU also hosts the ObjectDescriptors for the kaldachompspit, pinponspike
 * and pollenfragment sibling DLLs that share the xyzanimator code.
 */
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/dll/xyzanimator.h"
#include "main/dll_000A_expgfx.h"
#include "main/audio/sfx.h"
#include "main/camera.h"
#include "main/effect_interfaces.h"
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/gameplay_runtime.h"
#include "main/objhits.h"
#include "main/objlib.h"
#include "main/vecmath.h"
#include "main/dll/genprops.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_ids.h"
#define POLLEN_HIT_VOLUME_SLOT 0x16
extern f32 lbl_803E313C;
extern f32 lbl_803E3138;
extern f32 lbl_803E3140;
extern f32 lbl_803E3148;
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern void objMove(int obj, f32 x, f32 y, f32 z);

#define POLLEN_PARTFX_MOTE 0x4ba

#pragma dont_inline on
void Pollen_burst(GameObject* obj)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern void* Obj_AllocObjectSetup(int size, int b);
    extern u8* Obj_SetupObject(u8 * obj, int a, int b, int c, int d);
    extern f32 lbl_803E3144;
    int burstCounter;
    PollenExtra* extra;
    u8* fragment;

    extra = *(PollenExtra**)&(obj)->extra;
    if (Obj_IsLoadingLocked() == 0)
    {
        return;
    }
    burstCounter = POLLEN_FRAGMENT_BURST_COUNTER_START;
    do
    {
        fragment = Obj_AllocObjectSetup(POLLEN_FRAGMENT_SETUP_SIZE, POLLEN_FRAGMENT_OBJECT_ID);
        ((GameObject*)fragment)->anim.rootMotionScale = (obj)->anim.localPosX;
        ((GameObject*)fragment)->anim.localPosX = (obj)->anim.localPosY;
        ((GameObject*)fragment)->anim.localPosY = (obj)->anim.localPosZ;
        *(u8*)&((GameObject*)fragment)->anim.rotZ = 1;
        *(u8*)(fragment + 5) = 1;
        *(u8*)&((GameObject*)fragment)->anim.flags = 0xff;
        *(u8*)(fragment + 7) = 0xff;
        fragment = Obj_SetupObject(fragment, POLLEN_FRAGMENT_SETUP_KIND, -1, -1, 0);
        if (fragment != 0)
        {
            ((GameObject*)fragment)->anim.rotY = 0;
            ((GameObject*)fragment)->anim.rotX = randomGetRange(0, POLLEN_FRAGMENT_RANDOM_ANGLE_MAX);
            ((GameObject*)fragment)->anim.velocityX =
                lbl_803E3144 *
                    (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN, POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                (obj)->anim.velocityX;
            ((GameObject*)fragment)->anim.velocityY =
                lbl_803E3148 *
                    (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN, POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                (obj)->anim.velocityY;
            ((GameObject*)fragment)->anim.velocityZ =
                lbl_803E3144 *
                    (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN, POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                (obj)->anim.velocityZ;
            *(int*)(fragment + POLLEN_FRAGMENT_PARENT_OBJECT_OFFSET) = (int)obj;
        }
    } while (burstCounter-- != 0);
    extra->fragmentSpawnTimer = POLLEN_FRAGMENT_SPAWN_TIMER_FRAMES;
}
#pragma dont_inline reset

void Pollen_release(void)
{
}

void Pollen_initialise(void)
{
}

void Pollen_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void Pollen_hitDetect(GameObject* obj)
{
    if ((*(ObjHitsPriorityState**)&obj->anim.hitReactState)->contactFlags != 0)
    {
        f32 fz;
        obj->anim.localPosX = (*(ObjHitsPriorityState**)&obj->anim.hitReactState)->contactPosX;
        obj->anim.localPosY = (*(ObjHitsPriorityState**)&obj->anim.hitReactState)->contactPosY;
        obj->anim.localPosZ = (*(ObjHitsPriorityState**)&obj->anim.hitReactState)->contactPosZ;
        fz = lbl_803E313C;
        obj->anim.velocityX = fz;
        obj->anim.velocityY = fz;
        obj->anim.velocityZ = fz;
        obj->anim.alpha = 0;
        ObjHits_DisableObject((u32)obj);
    }
}

int Pollen_getExtraSize(void)
{
    return sizeof(PollenExtra);
}
int Pollen_getObjectTypeId(void)
{
    return 0x0;
}

void Pollen_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3138);
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

void Pollen_init(GameObject* obj)
{
    PollenExtra* extra = *(PollenExtra**)&obj->extra;
    extra->phaseX = randomGetRange(-0x8000, 0x7fff);
    extra->driftVelocity = lbl_803E3148 * (f32)(s32)randomGetRange(0xfa0, 0x1388);
    extra->phaseY = randomGetRange(-0x8000, 0x7fff);
    extra->settleVelocity = lbl_803E313C;
    extra->phaseSpeed = randomGetRange(0xe6, 0x1f4);
    extra->unk10 = 0;
    extra->fragmentSpawnTimer = 0;
    obj->anim.alpha = 0xff;
    ObjHits_DisableObject((u32)obj);
    {
        int* p = *(int**)&obj->anim.modelState;
        if (p != NULL)
        {
            *(int*)&((ObjModelState*)p)->flags = *(int*)&((ObjModelState*)p)->flags | 0x810;
        }
    }
}

void Pollen_update(int obj)
{
    PollenExtra* extra;
    int i;

    extra = *(PollenExtra**)&((GameObject*)obj)->extra;
    if (extra->fragmentSpawnTimer != 0)
    {
        extra->fragmentSpawnTimer -= 1;
    }
    else
    {
        f32 prev = ((GameObject*)obj)->anim.velocityY;
        ((GameObject*)obj)->anim.velocityY = -(lbl_803E3140 * timeDelta - prev);
        if (prev >= lbl_803E313C && ((GameObject*)obj)->anim.velocityY <= lbl_803E313C)
        {
            Pollen_burst((GameObject*)(obj));
            Sfx_PlayFromObject(obj, SFXTRIG_majring2);
            ((GameObject*)obj)->anim.alpha = 0;
        }
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, POLLEN_HIT_VOLUME_SLOT, 1, 0);
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, 7);
        ObjHits_EnableObject((u32)obj);
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0 &&
            (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject ==
                 (int)Obj_GetPlayerObject() ||
             ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)getTrickyObject()))
        {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(lbl_803E3138);
            Sfx_PlayFromObject(obj, SFXTRIG_id_b6);
            ((GameObject*)obj)->anim.alpha = 0;
            extra->fragmentSpawnTimer = 0x3c;
            ObjHits_DisableObject((u32)obj);
        }
        if (((GameObject*)obj)->anim.alpha == 0xff)
        {
            i = 2;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, POLLEN_PARTFX_MOTE, NULL, 1, -1, NULL);
            } while (i-- != 0);
        }
    }
    if (((GameObject*)obj)->anim.alpha == 0 && extra->fragmentSpawnTimer == 0)
    {
        Obj_FreeObject((GameObject*)obj);
    }
}

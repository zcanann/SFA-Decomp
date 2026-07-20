/*
 * pollen (DLL 0x00D9)
 *
 * A drifting pollen mote. It falls under gravity (anim.velocityY ramped by
 * 0.045f * timeDelta each frame); when its descent passes through zero
 * (prev velocityY >= 0 and the new one <= 0) it bursts: Pollen_burst spawns a
 * fixed batch of pollen-fragment objects (POLLEN_FRAGMENT_OBJECT_ID), plays
 * sfx 0xb7 and hides the mote. The mote also collides: a hit against the
 * player or Tricky triggers a small camera offset + shake (sfx 0xb6) and
 * arms a 60-frame despawn timer; Pollen_hitDetect snaps the mote to the
 * contact point and freezes it. Visible motes emit a particle (fx 0x4ba)
 * each frame. The object frees itself once hidden and idle.
 */
#include "main/dll/partfx_interface.h"
#include "main/dll/MMP/MMP_asteroid.h"
#include "main/object_api.h"
#include "main/object_render.h"
#include "main/dll/dll_00D9_pollen_api.h"
#include "main/dll/dll_00DA_pollenfragment_api.h"
#include "main/dll_000A_expgfx.h"
#include "main/audio/sfx.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/audio/sfx_ids.h"
#include "main/object_descriptor.h"

typedef struct PollenExtra
{
    s16 phaseX;
    s16 unk02;
    s16 phaseY;
    s16 phaseSpeed;
    f32 settleVelocity;
    f32 driftVelocity;
    s16 unk10;
    s16 fragmentSpawnTimer;
} PollenExtra;

STATIC_ASSERT(offsetof(PollenExtra, phaseX) == 0x0);
STATIC_ASSERT(offsetof(PollenExtra, phaseY) == 0x4);
STATIC_ASSERT(offsetof(PollenExtra, phaseSpeed) == 0x6);
STATIC_ASSERT(offsetof(PollenExtra, settleVelocity) == 0x8);
STATIC_ASSERT(offsetof(PollenExtra, driftVelocity) == 0xC);
STATIC_ASSERT(offsetof(PollenExtra, fragmentSpawnTimer) == 0x12);
STATIC_ASSERT(sizeof(PollenExtra) == 0x14);

#define POLLEN_FRAGMENT_SETUP_SIZE           0x24
#define POLLEN_FRAGMENT_SETUP_KIND           5
#define POLLEN_FRAGMENT_BURST_COUNTER_START  5
#define POLLEN_FRAGMENT_RANDOM_ANGLE_MAX     0xffff
#define POLLEN_FRAGMENT_RANDOM_OFFSET_MIN    -50
#define POLLEN_FRAGMENT_RANDOM_OFFSET_MAX    50
#define POLLEN_FRAGMENT_SPAWN_TIMER_FRAMES   60
#define POLLEN_FRAGMENT_PARENT_OBJECT_OFFSET 0xc4

#define POLLEN_HIT_VOLUME_SLOT 0x16
#define POLLEN_PARTFX_MOTE 0x4ba

u8 Pollen_burst(GameObject* obj);


int Pollen_getExtraSize(void)
{
    return sizeof(PollenExtra);
}
int Pollen_getObjectTypeId(void)
{
    return 0x0;
}

void Pollen_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void Pollen_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void Pollen_hitDetect(GameObject* obj)
{
    if ((*(ObjHitsPriorityState**)&obj->anim.hitReactState)->contactFlags != 0)
    {
        f32 fz;
        obj->anim.localPosX = (*(ObjHitsPriorityState**)&obj->anim.hitReactState)->contactPosX;
        obj->anim.localPosY = (*(ObjHitsPriorityState**)&obj->anim.hitReactState)->contactPosY;
        obj->anim.localPosZ = (*(ObjHitsPriorityState**)&obj->anim.hitReactState)->contactPosZ;
        fz = 0.0f;
        obj->anim.velocityX = fz;
        obj->anim.velocityY = fz;
        obj->anim.velocityZ = fz;
        obj->anim.alpha = 0;
        ObjHits_DisableObject(obj);
    }
}

void Pollen_update(GameObject* obj)
{
    PollenExtra* extra;
    int i;

    extra = obj->extra;
    if (extra->fragmentSpawnTimer != 0)
    {
        extra->fragmentSpawnTimer -= 1;
    }
    else
    {
        f32 prev = obj->anim.velocityY;
        obj->anim.velocityY = -(0.045f * timeDelta - prev);
        if (prev >= 0.0f && obj->anim.velocityY <= 0.0f)
        {
            Pollen_burst(obj);
            Sfx_PlayFromObject((int)obj, SFXTRIG_majring2);
            obj->anim.alpha = 0;
        }
        objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                obj->anim.velocityZ * timeDelta);
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, POLLEN_HIT_VOLUME_SLOT, 1, 0);
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, 7);
        ObjHits_EnableObject(obj);
        if (((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject != 0 &&
            (((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject ==
                 (int)Obj_GetPlayerObject() ||
             ((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject == (int)getTrickyObject()))
        {
            Camera_EnableViewYOffset();
            CameraShake_SetAllMagnitudes(1.0f);
            Sfx_PlayFromObject((int)obj, SFXTRIG_id_b6);
            obj->anim.alpha = 0;
            extra->fragmentSpawnTimer = 0x3c;
            ObjHits_DisableObject(obj);
        }
        if (obj->anim.alpha == 0xff)
        {
            i = 2;
            do
            {
                (*gPartfxInterface)->spawnObject((void*)obj, POLLEN_PARTFX_MOTE, NULL, 1, -1, NULL);
            } while (i-- != 0);
        }
    }
    if (obj->anim.alpha == 0 && extra->fragmentSpawnTimer == 0)
    {
        Obj_FreeObject(obj);
    }
}
u8 Pollen_burst(GameObject* obj)
{
    int burstCounter;
    PollenExtra* extra;
    u8* fragment;
    u8 loadingLocked;

    extra = obj->extra;
    loadingLocked = Obj_IsLoadingLocked();
    if (loadingLocked == 0)
    {
        return loadingLocked;
    }
    burstCounter = POLLEN_FRAGMENT_BURST_COUNTER_START;
    do
    {
        fragment = (u8*)Obj_AllocObjectSetup(POLLEN_FRAGMENT_SETUP_SIZE, POLLEN_FRAGMENT_OBJECT_ID);
        ((GameObject*)fragment)->anim.rootMotionScale = (obj)->anim.localPosX;
        ((GameObject*)fragment)->anim.localPosX = (obj)->anim.localPosY;
        ((GameObject*)fragment)->anim.localPosY = (obj)->anim.localPosZ;
        *(u8*)&((GameObject*)fragment)->anim.rotZ = 1;
        *(u8*)(fragment + 5) = 1;
        *(u8*)&((GameObject*)fragment)->anim.flags = 0xff;
        *(u8*)(fragment + 7) = 0xff;
        fragment = (u8*)Obj_SetupObject((ObjPlacement*)fragment, POLLEN_FRAGMENT_SETUP_KIND, -1, -1, NULL);
        if (fragment != 0)
        {
            ((GameObject*)fragment)->anim.rotY = 0;
            ((GameObject*)fragment)->anim.rotX = randomGetRange(0, POLLEN_FRAGMENT_RANDOM_ANGLE_MAX);
            ((GameObject*)fragment)->anim.velocityX =
                0.03f *
                    (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN, POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                (obj)->anim.velocityX;
            ((GameObject*)fragment)->anim.velocityY =
                0.01f *
                    (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN, POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                (obj)->anim.velocityY;
            ((GameObject*)fragment)->anim.velocityZ =
                0.03f *
                    (f32)(s32)randomGetRange(POLLEN_FRAGMENT_RANDOM_OFFSET_MIN, POLLEN_FRAGMENT_RANDOM_OFFSET_MAX) +
                (obj)->anim.velocityZ;
            *(int*)(fragment + POLLEN_FRAGMENT_PARENT_OBJECT_OFFSET) = (int)obj;
        }
    } while (burstCounter-- != 0);
    extra->fragmentSpawnTimer = POLLEN_FRAGMENT_SPAWN_TIMER_FRAMES;
}

void Pollen_init(GameObject* obj)
{
    PollenExtra* extra = obj->extra;
    extra->phaseX = randomGetRange(-0x8000, 0x7fff);
    extra->driftVelocity = 0.01f * (f32)(s32)randomGetRange(0xfa0, 0x1388);
    extra->phaseY = randomGetRange(-0x8000, 0x7fff);
    extra->settleVelocity = 0.0f;
    extra->phaseSpeed = randomGetRange(0xe6, 0x1f4);
    extra->unk10 = 0;
    extra->fragmentSpawnTimer = 0;
    obj->anim.alpha = 0xff;
    ObjHits_DisableObject(obj);
    {
        int* p = *(int**)&obj->anim.modelState;
        if (p != NULL)
        {
            *(int*)&((ObjModelState*)p)->flags = *(int*)&((ObjModelState*)p)->flags | 0x810;
        }
    }
}

void Pollen_release(void)
{
}

void Pollen_initialise(void)
{
}

ObjectDescriptor gPollenObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Pollen_initialise, (ObjectDescriptorCallback)Pollen_release, 0,
    (ObjectDescriptorCallback)Pollen_init, (ObjectDescriptorCallback)Pollen_update,
    (ObjectDescriptorCallback)Pollen_hitDetect, (ObjectDescriptorCallback)Pollen_render,
    (ObjectDescriptorCallback)Pollen_free, (ObjectDescriptorCallback)Pollen_getObjectTypeId,
    Pollen_getExtraSize,
};

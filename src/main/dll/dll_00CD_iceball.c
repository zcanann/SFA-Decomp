/*
 * iceball (DLL 0x00CD) - the ChukChuk ice-spitter's projectile.
 *
 * IceBall_update integrates the iceball each frame: an userData1 lifetime timer,
 * primed to 0xb4 (180 frames), counts down by timeDelta (freeing the object at
 * <0), gravity (0.07f) and drag (0.97f) are applied to the Y
 * velocity, the model is spun (rotX/rotY/rotZ += 910), and it is moved + given
 * a radius-5 hit sphere.
 * On contact it plays an impact effect and goes invisible for 120 frames
 * before freeing:
 *   - iceBall_handleCharacterImpact runs when the iceball strikes the player or Tricky: it
 *     notifies the owning ChukChuk (vtable msg 0x80) and bursts particles,
 *     keyed by the obj's seqId (0x2cb / 100 / 0x30a).
 *   - iceBall_handleSurfaceImpact runs for any other contact: a Krazoa-impact burst keyed by
 *     seqId (0x2cb / 100 / 0x30a).
 * IceBall_init primes the lifetime (0xb4) and full alpha; render/free toggle
 * the camera view-Y offset for the impact shake.
 */
#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/obj_list.h"
#include "main/object_render.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objhits.h"
#include "main/camera.h"
#include "main/frame_timing.h"
#include "main/dll/dll_00CD_iceball.h"
#include "main/dll/dll_00CB_dllcb.h"

#define ICEBALL_HIT_VOLUME_SLOT 10
#define ICEBALL_PARTICLE_COUNT 25
#define ICEBALL_LIFETIME_FRAMES 180
#define ICEBALL_IMPACT_FRAMES 120

#define ICEBALL_MSG_NOTIFY_OWNER 0x80 /* vtable msg notifying the owning ChukChuk on impact */




static inline u8 iceBall_isOwnerActive(GameObject* owner)
{
    int i;
    int count;
    int* objs = ObjList_GetObjects(&i, &count);
    while (i < count)
    {
        if (owner == (GameObject*)objs[i++])
        {
            return 1;
        }
    }
    return 0;
}

void iceBall_handleSurfaceImpact(GameObject* obj)
{

    s16 projectileType = obj->anim.seqId;
    int i;

    if (projectileType == 0x2cb)
    {
        for (i = 0; i < ICEBALL_PARTICLE_COUNT; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 834, NULL, 1, -1, NULL);
        }
    }
    else if (projectileType == 100 || projectileType == 0x30a)
    {
        for (i = 0; i < ICEBALL_PARTICLE_COUNT; i++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 836, NULL, 1, -1, NULL);
        }
    }

    Sfx_PlayFromObject(obj, SFXTRIG_mn_lummy311_26a);
    Camera_EnableViewYOffset();
    CameraShake_SetAllMagnitudes(1.0f);
}

void iceBall_handleCharacterImpact(GameObject* obj)
{

    s16 projectileType;
    int particleIdx;

    Camera_EnableViewYOffset();
    CameraShake_SetAllMagnitudes(1.0f);
    Sfx_PlayFromObject(obj, SFXTRIG_mn_lummy311_26a);
    projectileType = obj->anim.seqId;
    if (projectileType == 0x2cb)
    {
        if ((obj)->ownerObj != NULL)
        {
            if (iceBall_isOwnerActive(obj->ownerObj))
            {
                (*(void (**)(void*, int))(**(int**)(*(int*)&(obj)->ownerObj + 0x68) + 0x20))((obj)->ownerObj,
                                                                                             ICEBALL_MSG_NOTIFY_OWNER);
            }
        }
        for (particleIdx = 0; particleIdx < ICEBALL_PARTICLE_COUNT; particleIdx++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 832, NULL, 1, -1, NULL);
        }
    }
    else if (projectileType == 100)
    {
        if ((obj)->ownerObj != NULL)
        {
            if (iceBall_isOwnerActive(obj->ownerObj))
            {
                (*(void (**)(void*, int))(**(int**)(*(int*)&(obj)->ownerObj + 0x68) + 0x24))((obj)->ownerObj,
                                                                                             ICEBALL_MSG_NOTIFY_OWNER);
            }
        }
        for (particleIdx = 0; particleIdx < ICEBALL_PARTICLE_COUNT; particleIdx++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 835, NULL, 1, -1, NULL);
        }
    }
    else if (projectileType == 0x30a)
    {
        if ((obj)->ownerObj != NULL)
        {
            if (iceBall_isOwnerActive(obj->ownerObj))
            {
                (*(void (**)(void*, int, int))(**(int**)(*(int*)&(obj)->ownerObj + 0x68) + 0x24))(
                    (obj)->ownerObj, ICEBALL_MSG_NOTIFY_OWNER, 0);
            }
        }
        for (particleIdx = 0; particleIdx < ICEBALL_PARTICLE_COUNT; particleIdx++)
        {
            (*gPartfxInterface)->spawnObject((void*)obj, 835, NULL, 1, -1, NULL);
        }
    }
}


int IceBall_getExtraSize(void)
{
    return 0x2;
}
int IceBall_getObjectTypeId(void)
{
    return 0x0;
}

void IceBall_free(GameObject* obj)
{
    Camera_DisableViewYOffset();
}

void IceBall_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 visible32 = visible;
    if (visible32 != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void IceBall_hitDetect(GameObject* obj)
{
}

void IceBall_update(GameObject* obj)
{
    int objInt;

    objInt = (int)obj;
    ((GameObject*)objInt)->userData1 = (s32)((f32)((GameObject*)objInt)->userData1 - timeDelta);
    if (((GameObject*)objInt)->userData1 < 0)
    {
        Obj_FreeObject((GameObject*)objInt);
        return;
    }
    if (((GameObject*)objInt)->anim.alpha == 0)
    {
        return;
    }
    ((GameObject*)objInt)->anim.velocityY -= 0.07f * timeDelta;
    ((GameObject*)objInt)->anim.velocityY *= 0.97f;
    ((GameObject*)objInt)->anim.rotX += 910;
    ((GameObject*)objInt)->anim.rotZ += 910;
    ((GameObject*)objInt)->anim.rotY += 910;
    objMove((GameObject*)objInt, ((GameObject*)objInt)->anim.velocityX * timeDelta,
            ((GameObject*)objInt)->anim.velocityY * timeDelta, ((GameObject*)objInt)->anim.velocityZ * timeDelta);
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)objInt, ICEBALL_HIT_VOLUME_SLOT, 1, 0);
    ObjHitbox_SetSphereRadius((ObjAnimComponent*)objInt, 5);
    ObjHits_EnableObject((GameObject*)objInt);
    if ((*(ObjHitsPriorityState**)&((GameObject*)objInt)->anim.hitReactState)->lastHitObject != 0 &&
        ((*(ObjHitsPriorityState**)&((GameObject*)objInt)->anim.hitReactState)->lastHitObject ==
             (int)Obj_GetPlayerObject() ||
         (*(ObjHitsPriorityState**)&((GameObject*)objInt)->anim.hitReactState)->lastHitObject ==
             (u32)getTrickyObject()))
    {
        iceBall_handleCharacterImpact((GameObject*)(objInt));
        ((GameObject*)objInt)->anim.alpha = 0;
        ((GameObject*)objInt)->userData1 = ICEBALL_IMPACT_FRAMES;
        (*(ObjHitsPriorityState**)&((GameObject*)objInt)->anim.hitReactState)->flags &= ~1;
    }
    else if ((*(ObjHitsPriorityState**)&((GameObject*)objInt)->anim.hitReactState)->contactFlags != 0)
    {
        iceBall_handleSurfaceImpact((GameObject*)(objInt));
        ((GameObject*)objInt)->anim.alpha = 0;
        ((GameObject*)objInt)->userData1 = ICEBALL_IMPACT_FRAMES;
        (*(ObjHitsPriorityState**)&((GameObject*)objInt)->anim.hitReactState)->flags &= ~1;
    }
}

void IceBall_init(GameObject* obj)
{
    obj->userData1 = ICEBALL_LIFETIME_FRAMES;
    ObjHits_DisableObject(obj);
    obj->anim.alpha = 0xff;
}

void IceBall_release(void)
{
}

void IceBall_initialise(void)
{
}

ObjectDescriptor gIceBallObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)IceBall_initialise,
    (ObjectDescriptorCallback)IceBall_release,
    0,
    (ObjectDescriptorCallback)IceBall_init,
    (ObjectDescriptorCallback)IceBall_update,
    (ObjectDescriptorCallback)IceBall_hitDetect,
    (ObjectDescriptorCallback)IceBall_render,
    (ObjectDescriptorCallback)IceBall_free,
    (ObjectDescriptorCallback)IceBall_getObjectTypeId,
    IceBall_getExtraSize,
};

int lbl_80320008[30] = {
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
    2, 2, 2, 2, 2, 2, 2, 2, 2, 2,
};
u8 lbl_80320080[32] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                       255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0,   0};
void* dll_CB[16] = {(void*)0x00000000,      (void*)0x00000000,
                    (void*)0x00000000,      (void*)0x000B0000,
                    dll_CB_initialise,      dll_CB_release_nop,
                    (void*)0x00000000,      dll_CB_init,
                    dll_CB_update,          dll_CB_hitDetect,
                    dll_CB_render,          dll_CB_free,
                    dll_CB_getObjectTypeId, dll_CB_getExtraSize_ret_1040,
                    dll_CB_setScale,        dll_CB_func0B_nop};
int lbl_803200E0[30] = {
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
};
u8 lbl_80320158[32] = {255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                       255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 0,   0};

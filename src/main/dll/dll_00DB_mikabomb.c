/*
 * mikabomb (DLL 0x00DB) - the Mika bomb projectile.
 *
 * mikabomb: a thrown bomb that arcs under gravity (velocity * timeDelta
 * each tick, vertical speed clamped), fades its alpha out over its
 * lifetime, and on impact with the player (or when it reaches the ground
 * plane sampled at init) plays SFXen_weetinklp22, expands its hit sphere,
 * kicks a camera shake and spawns its explosion effect before freeing.
 * Resource 0x5b is acquired at init.
 */
#include "main/dll/dll_00DB_mikabomb_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_stop_channel_api.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/frame_timing.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/dll_005B_modgfxfunc03.h"
#include "main/dll/modgfx_interface.h"
#include "main/resource.h"
#include "main/object_render.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/camera_shake_api.h"
#include "main/track_dolphin_api.h"
#include "main/dll/dll_00DC_mikabombshadow_api.h"
#define MIKABOMB_HIT_VOLUME_SLOT 5

/* Shadow-bomb object spawned at init, cached into MikabombState.shadowObj. */
#define MIKABOMB_CHILD_OBJ_SHADOW 0xc

extern f32 lbl_803E31C0;
extern u32 lbl_803E31A0;
extern f32 gMikaBombHitSphereRadiusScale;
extern f32 gMikaBombCameraShakeMagnitude;
extern f32 gMikaBombCameraShakeDuration;
extern f32 gMikaBombCameraShakeFalloff;
extern f32 lbl_803E31C4;
extern f32 lbl_803E31C8;
extern f32 lbl_803E31D4;

typedef struct MikabombState
{
    GameObject* shadowObj; /* 0x00: spawned shadow-bomb object */
    f32 groundY;    /* 0x04: ground-plane Y sampled at init */
    ModgfxFunc03Interface** resource; /* 0x08: Resource_Acquire(0x5b) handle */
    u8 exploded;    /* 0x0C: set once the bomb has detonated */
    u8 padD[3];
} MikabombState;

STATIC_ASSERT(offsetof(MikabombState, shadowObj) == 0x0);
STATIC_ASSERT(offsetof(MikabombState, groundY) == 0x4);
STATIC_ASSERT(offsetof(MikabombState, resource) == 0x8);
STATIC_ASSERT(offsetof(MikabombState, exploded) == 0xC);
STATIC_ASSERT(sizeof(MikabombState) == 0x10);

int MikaBomb_getExtraSize(void)
{
    return 0x10;
}
int MikaBomb_getObjectTypeId(void)
{
    return 0x0;
}

void MikaBomb_free(GameObject* obj, int mode)
{
    MikabombState* state = obj->extra;
    if (state->shadowObj != NULL && mode == 0)
    {
        Obj_FreeObject(state->shadowObj);
        state->shadowObj = NULL;
    }
    (*gModgfxInterface)->detachSource((void*)obj);
}

void MikaBomb_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E31C0);
}

void MikaBomb_hitDetect(void)
{
}

void MikaBomb_update(GameObject* obj)
{
    MikabombState* state = obj->extra;
    u32 timer = obj->anim.alpha;

    if (timer < 0xff)
    {
        f32 t = timer;
        f32 dec;
        if (t - (dec = lbl_803E31C4 * timeDelta) > lbl_803E31C8)
        {
            obj->anim.alpha = timer - dec;
        }
        else
        {
            Sfx_StopObjectChannel((int)obj, 0x7f);
            obj->anim.alpha = 0;
            Obj_FreeObject(obj);
            return;
        }
    }
    else
    {
        obj->anim.velocityY -= gMikaBombGravityAccel * timeDelta;
        if (obj->anim.velocityY < *(f32*)&gMikaBombMinFallVelocity)
        {
            obj->anim.velocityY = gMikaBombMinFallVelocity;
        }
        objMove(obj, obj->anim.velocityX * timeDelta, obj->anim.velocityY * timeDelta,
                obj->anim.velocityZ * timeDelta);
    }

    if (obj->anim.alpha == 0xff || state->exploded != 0)
    {
        ModgfxSpawnCountRange localB;
        ModgfxSpawnCountRange localA;
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, MIKABOMB_HIT_VOLUME_SLOT, 1, 0);
        ObjHits_EnableObject(obj);
        if (((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject != 0 &&
            ((ObjHitsPriorityState*)obj->anim.hitReactState)->lastHitObject ==
                (int)Obj_GetPlayerObject())
        {
            if (obj->anim.alpha == 0xff)
            {
                MikabombState* st = obj->extra;
                u32 rnd;
                localB.packed = lbl_803E31A0;
                Sfx_PlayFromObject((u32)obj, SFXTRIG_dsmk2_c);
                rnd = randomGetRange(0, 2);
                (*st->resource)->spawn(obj, rnd, NULL, 2, -1, &localB);
                ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                          (s32)(gMikaBombHitSphereRadiusScale *
                                                (f32)(u32)obj->anim.modelInstance->primaryHitboxRadius));
                CameraShake_Start(gMikaBombCameraShakeMagnitude, gMikaBombCameraShakeDuration,
                                  gMikaBombCameraShakeFalloff);
                obj->anim.alpha = 0xfe;
                Obj_FreeObject(st->shadowObj);
                st->shadowObj = NULL;
            }
            ObjHits_DisableObject(obj);
        }
        else
        {
            if (obj->anim.localPosY <= state->groundY &&
                obj->anim.alpha == 0xff)
            {
                MikabombState* st = obj->extra;
                u32 rnd;
                localA.packed = lbl_803E31A0;
                Sfx_PlayFromObject((u32)obj, SFXTRIG_dsmk2_c);
                rnd = randomGetRange(0, 2);
                (*st->resource)->spawn(obj, rnd, NULL, 2, -1, &localA);
                ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                          (s32)(gMikaBombHitSphereRadiusScale *
                                                (f32)(u32)obj->anim.modelInstance->primaryHitboxRadius));
                CameraShake_Start(gMikaBombCameraShakeMagnitude, gMikaBombCameraShakeDuration,
                                  gMikaBombCameraShakeFalloff);
                obj->anim.alpha = 0xfe;
                Obj_FreeObject(st->shadowObj);
                st->shadowObj = NULL;
                state->exploded = 1;
            }
        }
    }
}

void MikaBomb_init(GameObject* obj)
{
    MikabombState* state = obj->extra;
    f32 out;
    ObjPlacement* alloc;
    f32 fz;

    ObjHits_DisableObject(obj);
    obj->anim.alpha = 0xff;
    fz = lbl_803E31C8;
    obj->anim.velocityX = fz;
    obj->anim.velocityY = lbl_803E31D4;
    obj->anim.velocityZ = fz;
    obj->anim.rotY = -0x4000;
    obj->anim.rotX = 0;
    obj->anim.rotZ = 0;
    fn_80065684(obj, obj->anim.localPosX, obj->anim.localPosY,
                obj->anim.localPosZ, &out, 0);
    state->groundY = obj->anim.localPosY - out;
    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        alloc = Obj_AllocObjectSetup(0x20, MIKABOMB_CHILD_OBJ_SHADOW);
        alloc->posX = obj->anim.localPosX;
        alloc->posY = obj->anim.localPosY;
        alloc->posZ = obj->anim.localPosZ;
        alloc->color[0] = 1;
        alloc->color[1] = 1;
        alloc->color[2] = 0xff;
        alloc->color[3] = 0xff;
        state->shadowObj = loadObjectAtObject(obj, alloc);
        state->shadowObj->ownerObj = obj;
    }
    else
    {
        state->shadowObj = NULL;
    }
    state->resource = Resource_Acquire(0x5b, 1);
    state->exploded = 0;
}

void MikaBomb_release(void)
{
}

void MikaBomb_initialise(void)
{
}

ObjectDescriptor gMikaBombObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)MikaBomb_initialise,
    (ObjectDescriptorCallback)MikaBomb_release,
    0,
    (ObjectDescriptorCallback)MikaBomb_init,
    (ObjectDescriptorCallback)MikaBomb_update,
    (ObjectDescriptorCallback)MikaBomb_hitDetect,
    (ObjectDescriptorCallback)MikaBomb_render,
    (ObjectDescriptorCallback)MikaBomb_free,
    (ObjectDescriptorCallback)MikaBomb_getObjectTypeId,
    MikaBomb_getExtraSize,
};

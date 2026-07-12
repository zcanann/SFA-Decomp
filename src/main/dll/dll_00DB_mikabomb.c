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
#include "main/dll/xyzanimator.h"
#include "main/vecmath.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/genprops.h"
#include "main/dll_000A_expgfx.h"
#include "main/resource.h"
#include "main/objprint.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#define MIKABOMB_HIT_VOLUME_SLOT 5

/* Shadow-bomb object spawned at init, cached into MikabombState.shadowObj. */
#define MIKABOMB_CHILD_OBJ_SHADOW 0xc

extern ModgfxInterface** gModgfxInterface;
extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern f32 lbl_803E31C0;
extern f32 timeDelta;
extern void* Obj_GetPlayerObject(void);
extern int Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern void Sfx_StopObjectChannel(int* obj, int channel);
extern int fn_80065684(int a, f32 b, f32 val, f32 d, f32* out, int e);
extern u32 lbl_803E31A0;
extern f32 gMikaBombHitSphereRadiusScale;
extern f32 gMikaBombCameraShakeMagnitude;
extern f32 gMikaBombCameraShakeDuration;
extern f32 gMikaBombCameraShakeFalloff;
extern f32 lbl_803E31C4;
extern f32 lbl_803E31C8;
extern f32 gMikaBombGravityAccel;
extern f32 gMikaBombMinFallVelocity;
extern f32 lbl_803E31D4;
extern void CameraShake_Start(f32 magnitude, f32 duration, f32 falloff);
extern int loadObjectAtObject(int* obj, void* params);

typedef struct MikabombState
{
    int* shadowObj; /* 0x00: spawned shadow-bomb object */
    f32 groundY;    /* 0x04: ground-plane Y sampled at init */
    void* resource; /* 0x08: Resource_Acquire(0x5b) handle (effect vtable) */
    u8 exploded;    /* 0x0C: set once the bomb has detonated */
    u8 padD[0x18 - 0xD];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x70 - 0x54];
    u8 unk70;
    u8 pad71[0xAA - 0x71];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xB8 - 0xB2];
} MikabombState;

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
    void** inner = (obj)->extra;
    if (inner[0] != NULL && mode == 0)
    {
        Obj_FreeObject(inner[0]);
        inner[0] = NULL;
    }
    (*gModgfxInterface)->detachSource((void*)obj);
}

void MikaBomb_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E31C0);
}

void MikaBomb_hitDetect(void)
{
}

void MikaBomb_update(int* obj)
{
    extern void objMove(int* obj, f32 x, f32 y, f32 z);
    extern void Sfx_PlayFromObject(int* obj, int sfx);
    extern void Obj_FreeObject(int* obj);
    extern void ObjHits_EnableObject();
    extern void ObjHits_DisableObject();
    int* state = ((GameObject*)obj)->extra;
    u32 timer = ((GameObject*)obj)->anim.alpha;

    if (timer < 0xff)
    {
        f32 t = timer;
        f32 dec;
        if (t - (dec = lbl_803E31C4 * timeDelta) > lbl_803E31C8)
        {
            ((GameObject*)obj)->anim.alpha = timer - dec;
        }
        else
        {
            Sfx_StopObjectChannel(obj, 0x7f);
            ((GameObject*)obj)->anim.alpha = 0;
            Obj_FreeObject(obj);
            return;
        }
    }
    else
    {
        ((GameObject*)obj)->anim.velocityY -= gMikaBombGravityAccel * timeDelta;
        if (((GameObject*)obj)->anim.velocityY < *(f32*)&gMikaBombMinFallVelocity)
        {
            ((GameObject*)obj)->anim.velocityY = gMikaBombMinFallVelocity;
        }
        objMove(obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
    }

    if (((GameObject*)obj)->anim.alpha == 0xff || ((MikabombState*)state)->exploded != 0)
    {
        u32 localB;
        u32 localA;
        ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, MIKABOMB_HIT_VOLUME_SLOT, 1, 0);
        ObjHits_EnableObject(obj);
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0 &&
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject ==
                (int)Obj_GetPlayerObject())
        {
            if (((GameObject*)obj)->anim.alpha == 0xff)
            {
                int* st = ((GameObject*)obj)->extra;
                u32 rnd;
                localB = lbl_803E31A0;
                Sfx_PlayFromObject(obj, SFXTRIG_dsmk2_c);
                rnd = randomGetRange(0, 2);
                ((void (*)(int*, u32, int, int, int, u32*))((int*)*(int**)((MikabombState*)st)->resource)[1])(
                    obj, rnd, 0, 2, -1, &localB);
                ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                          (s32)(gMikaBombHitSphereRadiusScale *
                                                (f32)(u32)((GameObject*)obj)->anim.modelInstance->primaryHitboxRadius));
                CameraShake_Start(gMikaBombCameraShakeMagnitude, gMikaBombCameraShakeDuration,
                                  gMikaBombCameraShakeFalloff);
                ((GameObject*)obj)->anim.alpha = 0xfe;
                Obj_FreeObject((int*)*st);
                *st = 0;
            }
            ObjHits_DisableObject((u32)obj);
        }
        else
        {
            if (((GameObject*)obj)->anim.localPosY <= ((MikabombState*)state)->groundY &&
                ((GameObject*)obj)->anim.alpha == 0xff)
            {
                int* st = ((GameObject*)obj)->extra;
                u32 rnd;
                localA = lbl_803E31A0;
                Sfx_PlayFromObject(obj, SFXTRIG_dsmk2_c);
                rnd = randomGetRange(0, 2);
                ((void (*)(int*, u32, int, int, int, u32*))((int*)*(int**)((MikabombState*)st)->resource)[1])(
                    obj, rnd, 0, 2, -1, &localA);
                ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                          (s32)(gMikaBombHitSphereRadiusScale *
                                                (f32)(u32)((GameObject*)obj)->anim.modelInstance->primaryHitboxRadius));
                CameraShake_Start(gMikaBombCameraShakeMagnitude, gMikaBombCameraShakeDuration,
                                  gMikaBombCameraShakeFalloff);
                ((GameObject*)obj)->anim.alpha = 0xfe;
                Obj_FreeObject((int*)*st);
                *st = 0;
                ((MikabombState*)state)->exploded = 1;
            }
        }
    }
}

void MikaBomb_init(int* obj)
{
    extern u64 ObjHits_DisableObject();
    int* state = ((GameObject*)obj)->extra;
    f32 out;
    ObjPlacement* alloc;
    f32 fz;

    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0xff;
    fz = lbl_803E31C8;
    ((GameObject*)obj)->anim.velocityX = fz;
    ((GameObject*)obj)->anim.velocityY = lbl_803E31D4;
    ((GameObject*)obj)->anim.velocityZ = fz;
    ((GameObject*)obj)->anim.rotY = -0x4000;
    ((GameObject*)obj)->anim.rotX = 0;
    ((GameObject*)obj)->anim.rotZ = 0;
    fn_80065684((int)obj, ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                ((GameObject*)obj)->anim.localPosZ, &out, 0);
    ((MikabombState*)state)->groundY = ((GameObject*)obj)->anim.localPosY - out;
    if ((u8)Obj_IsLoadingLocked() != 0)
    {
        alloc = Obj_AllocObjectSetup(0x20, MIKABOMB_CHILD_OBJ_SHADOW);
        alloc->posX = ((GameObject*)obj)->anim.localPosX;
        alloc->posY = ((GameObject*)obj)->anim.localPosY;
        alloc->posZ = ((GameObject*)obj)->anim.localPosZ;
        alloc->color[0] = 1;
        alloc->color[1] = 1;
        alloc->color[2] = 0xff;
        alloc->color[3] = 0xff;
        *state = loadObjectAtObject(obj, alloc);
        ((GameObject*)*state)->ownerObj = obj;
    }
    else
    {
        *state = 0;
    }
    ((MikabombState*)state)->resource = Resource_Acquire(0x5b, 1);
    ((MikabombState*)state)->exploded = 0;
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

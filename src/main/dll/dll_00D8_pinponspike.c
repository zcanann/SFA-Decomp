/*
 * pinponspike (DLL 0x0D8) - a thrown spike projectile.
 *
 * On init the object disables its hits, goes fully opaque, plays the
 * attack02 launch sfx and sets objectFlags 0x6000. Each update it
 * ballistically integrates velocity * timeDelta through objMove,
 * applies gravity (clamped to a terminal fall speed) and orients rotX/
 * rotY to the velocity heading. While alive it re-enables a hit volume;
 * on striking the player or Tricky (or any contact hit) it goes
 * invisible, starts a 0x78-frame free countdown, bursts 0x19 impact fx
 * (0x715) and plays the attack03 hit sfx, then frees itself once the
 * countdown elapses or it falls below the kill plane.
 *
 * fn_80169EF4 computes the launch angle that lands a projectile of the
 * given speed under gravity at a target offset (used cross-TU by duster).
 *
 * This TU also hosts the object descriptors for the sibling
 * kaldachompspit / pollen / pollenfragment objects (their code lives in
 * the neighbouring DLLs) plus the pollen-fragment spawn config table.
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/xyzanimator.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/dll/genprops.h"
#include "main/dll/fx_800944A0_shared.h"
extern void Sfx_PlayFromObject(int obj, int sfxId);

#define PINPONSPIKE_OBJFLAG_HIDDEN 0x4000
#define PINPONSPIKE_OBJFLAG_HITDETECT_DISABLED 0x2000

/* sibling kaldachompspit descriptor callbacks (code in a neighbouring DLL);
   the remaining callbacks (render/hitDetect/init/release/initialise) are in xyzanimator.h */

extern f32 lbl_803E3110;
extern f32 lbl_803E3114;
extern f32 lbl_803E3118;
extern f32 lbl_803E311C;
extern f32 lbl_803E3120;
extern f32 lbl_803E3124;
extern f32 lbl_803E3128;
extern f32 lbl_803E312C;

extern int getAngle(float y, float x);
extern void objMove(int obj, f32 x, f32 y, f32 z);


extern void* getTrickyObject(void);

void pinponspike_render(void)
{
}

void pinponspike_hitDetect(void)
{
}

void pinponspike_release(void)
{
}

void pinponspike_initialise(void)
{
}

void pinponspike_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void pinponspike_init(int obj)
{
    ((GameObject*)obj)->unkF4 = 0;
    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0xff;
    Sfx_PlayFromObject(obj, SFXsc_attack02);
    ((GameObject*)obj)->objectFlags |= (PINPONSPIKE_OBJFLAG_HIDDEN | PINPONSPIKE_OBJFLAG_HITDETECT_DISABLED);
}

int pinponspike_getExtraSize(void) { return 0x0; }
int pinponspike_getObjectTypeId(void) { return 0x0; }

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

int fn_80169EF4(f32* from, f32* to, f32 speed, u8 flag, f32 grav)
{
    f32 sp2;
    f32 dist;
    f32 a;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 t;
    f32 disc;

    dx = from[0] - to[0];
    dz = from[2] - to[2];
    dist = sqrtf(dx * dx + dz * dz);
    dy = from[1] - to[1];
    dist = dist * lbl_803E3110;
    sp2 = lbl_803E3114 * grav;
    a = sp2 * grav;
    {
        f32 vel = -(grav * dy) - (sp2 = speed * speed); /* sp2 is speed^2 */
        disc = vel * vel - (lbl_803E3118 * a) * (dy * dy + dist * dist);
        if (disc >= lbl_803E311C)
        {
            if (flag)
            {
                t = (lbl_803E3120 * (-vel + sqrtf(disc))) / a;
            }
            else
            {
                t = (lbl_803E3120 * (-vel - sqrtf(disc))) / a;
            }
            t = sqrtf(t);
            a = dist / t; /* a is now the horizontal velocity */
            return getAngle(sqrtf(-(a * a - sp2)), a);
        }
    }
    return 0x2000;
}

void pinponspike_update(int obj)
{
    f32 vx;
    f32 vy;
    f32 vz;

    if (((GameObject*)obj)->unkF4 > 0)
    {
        ((GameObject*)obj)->unkF4 = (int)((f32)((GameObject*)obj)->unkF4 - timeDelta);
        if (((GameObject*)obj)->unkF4 <= 0)
        {
            Obj_FreeObject(obj);
            return;
        }
    }
    if (((GameObject*)obj)->anim.alpha != 0)
    {
        vx = ((GameObject*)obj)->anim.velocityX * timeDelta;
        vy = ((GameObject*)obj)->anim.velocityY * timeDelta;
        vz = ((GameObject*)obj)->anim.velocityZ * timeDelta;
        objMove(obj, vx, vy, vz);
        ((GameObject*)obj)->anim.velocityY += lbl_803E3124 * timeDelta;
        if (((GameObject*)obj)->anim.velocityY < *(f32*)&lbl_803E3128)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E3128;
        }
        ((GameObject*)obj)->anim.rotX = getAngle(vx, vz) - 0x8000;
        ((GameObject*)obj)->anim.rotY = 0x4000 - getAngle(sqrtf(vx * vx + vz * vz), vy);
        ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
        ObjHits_EnableObject(obj);
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0 &&
            (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)Obj_GetPlayerObject() ||
             ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)getTrickyObject()))
        {
            int i;
            ((GameObject*)obj)->anim.alpha = 0;
            ((GameObject*)obj)->unkF4 = 0x78;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            for (i = 0; i < 0x19; i++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x715, NULL, 1, -1, &i);
            }
            Sfx_PlayFromObject(obj, SFXsc_attack03);
        }
        else if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->contactFlags != 0)
        {
            int i;
            ((GameObject*)obj)->anim.alpha = 0;
            ((GameObject*)obj)->unkF4 = 0x78;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            for (i = 0; i < 0x19; i++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x715, NULL, 1, -1, &i);
            }
            Sfx_PlayFromObject(obj, SFXsc_attack03);
        }
        else if (((GameObject*)obj)->anim.localPosY < lbl_803E312C)
        {
            Obj_FreeObject(obj);
        }
    }
}

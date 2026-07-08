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
 */
#include "main/audio/sfx_ids.h"
#include "main/dll/xyzanimator.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/dll/genprops.h"
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx.h"

#define PINPONSPIKE_HIT_VOLUME_SLOT 10

#define PINPONSPIKE_PARTFX                     0x715
#define PINPONSPIKE_OBJFLAG_HIDDEN             0x4000
#define PINPONSPIKE_OBJFLAG_HITDETECT_DISABLED 0x2000

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

int fn_80169EF4(f32* from, f32* to, f32 speed, u8 flag, f32 grav)
{
    f32 sp2;
    f32 dist;
    f32 coeff;
    f32 dx;
    f32 dy;
    f32 dz;
    f32 time;
    f32 disc;

    dx = from[0] - to[0];
    dz = from[2] - to[2];
    dist = sqrtf(dx * dx + dz * dz);
    dy = from[1] - to[1];
    dist = dist * lbl_803E3110;
    sp2 = lbl_803E3114 * grav;
    coeff = sp2 * grav;
    {
        f32 vel = -(grav * dy) - (sp2 = speed * speed); /* sp2 is speed^2 */
        disc = vel * vel - (lbl_803E3118 * coeff) * (dy * dy + dist * dist);
        if (disc >= lbl_803E311C)
        {
            if (flag)
            {
                time = (lbl_803E3120 * (-vel + sqrtf(disc))) / coeff;
            }
            else
            {
                time = (lbl_803E3120 * (-vel - sqrtf(disc))) / coeff;
            }
            time = sqrtf(time);
            coeff = dist / time; /* coeff is now the horizontal velocity */
            return getAngle(sqrtf(-(coeff * coeff - sp2)), coeff);
        }
    }
    return 0x2000;
}

int pinponspike_getExtraSize(void)
{
    return 0x0;
}

int pinponspike_getObjectTypeId(void)
{
    return 0x0;
}

void pinponspike_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void pinponspike_render(void)
{
}

void pinponspike_hitDetect(void)
{
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
        ObjHits_SetHitVolumeSlot(obj, PINPONSPIKE_HIT_VOLUME_SLOT, 1, 0);
        ObjHits_EnableObject(obj);
        if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject != 0 &&
            (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject ==
                 (int)Obj_GetPlayerObject() ||
             ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->lastHitObject == (int)getTrickyObject()))
        {
            int i;
            ((GameObject*)obj)->anim.alpha = 0;
            ((GameObject*)obj)->unkF4 = 0x78;
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->flags &= ~OBJHITS_PRIORITY_STATE_ENABLED;
            for (i = 0; i < 0x19; i++)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, PINPONSPIKE_PARTFX, NULL, 1, -1, &i);
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
                (*gPartfxInterface)->spawnObject((void*)obj, PINPONSPIKE_PARTFX, NULL, 1, -1, &i);
            }
            Sfx_PlayFromObject(obj, SFXsc_attack03);
        }
        else if (((GameObject*)obj)->anim.localPosY < lbl_803E312C)
        {
            Obj_FreeObject(obj);
        }
    }
}

void pinponspike_init(int obj)
{
    ((GameObject*)obj)->unkF4 = 0;
    ObjHits_DisableObject(obj);
    ((GameObject*)obj)->anim.alpha = 0xff;
    Sfx_PlayFromObject(obj, SFXsc_attack02);
    ((GameObject*)obj)->objectFlags |= (PINPONSPIKE_OBJFLAG_HIDDEN | PINPONSPIKE_OBJFLAG_HITDETECT_DISABLED);
}

void pinponspike_release(void)
{
}

void pinponspike_initialise(void)
{
}

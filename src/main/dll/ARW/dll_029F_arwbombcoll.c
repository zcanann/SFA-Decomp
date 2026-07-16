/*
 * arwbombcoll (DLL 0x29F) - the in-flight pickups and rings collected by
 * the Arwing in the on-rails sections. A pickup fades in once the Arwing is
 * close ahead, can oscillate along the X or Y axis (route modes 1/3 and
 * 4/5), spins, and watches for the Arwing passing through it. The reward on
 * collection depends on the object's seqId (health, max-health, score,
 * ring, laser upgrade, bomb, and the 0x6D8-0x6DB collectibles) and on the
 * pickup's "mode" (handled in Ring_onCollect). Rings also feed
 * the ring-count gate driven by arwlevelcon. Collision is checked two ways:
 * an axis-aligned proximity test (flag bit10) or a plane-crossing test that
 * compares the Arwing's current and previous Z against the pickup's Z.
 */
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/vecmath.h"
#include "main/object_api.h"
#include "main/objfx.h"
#include "main/dll/headdisplay.h"
#include "main/dll/ARW/dll_029F_arwbombcoll.h"
#include "main/dll/ARW/dll_029A_arwarwing.h"
#include "main/gameloop_api.h"
#include "main/dll/dll_02A0_ring.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/object_render_legacy.h"

#define ARWBOMBCOLL_HIT_VOLUME_SLOT 0x13

void arwbombcoll_setLifetime(GameObject* obj, int lifetime)
{
    ARWBombCollState* state = obj->extra;
    state->lifetime = lifetime;
}


__declspec(section ".sdata2") f32 lbl_803E7078 = 1.0f;
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E707C = 0.0f;
#pragma explicit_zero_data reset
__declspec(section ".sdata2") f32 gArwBombCollActivateDistanceZ = 3840.0f;
__declspec(section ".sdata2") f32 gArwBombCollAlphaFadeRate = 3.0f;
__declspec(section ".sdata2") f32 gArwBombCollSpinRate = 600.0f;
__declspec(section ".sdata2") f32 lbl_803E708C = 100.0f;

int ARWBombColl_getExtraSize(void)
{
    return 8;
}


int ARWBombColl_getObjectTypeId(void)
{
    return 0;
}


void ARWBombColl_free(void)
{
}


void ARWBombColl_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7078);
}


void ARWBombColl_hitDetect(void)
{
}


#pragma opt_common_subs off
void ARWBombColl_update(int obj)
{
    GameObject* arw;
    ObjAnimComponent* objAnim;
    ArwBombFlags* flags;
    ARWBombCollState* state;
    GameObject* arwingCheck;
    f32 minLifetime;

    arw = getArwing();
    objAnim = &((GameObject*)obj)->anim;
    state = ((GameObject*)obj)->extra;
    flags = &state->flags;

    {
        f32 lt = state->lifetime;
        if (lt > (minLifetime = lbl_803E707C))
        {
            state->lifetime = lt - timeDelta;
            if (state->lifetime <= minLifetime)
            {
                Obj_FreeObject((GameObject*)obj);
                return;
            }
        }
    }

    if (arw != NULL && arwarwing_isExplodingOrWarping(arw) != 0)
    {
        flags->b80 = 0;
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject(obj);
        return;
    }

    if (flags->b80 == 0)
    {
        arwingCheck = getArwing();
        if (((arwingCheck != NULL)
                 ? (((GameObject*)obj)->anim.localPosZ - arwingCheck->anim.localPosZ <
                    gArwBombCollActivateDistanceZ)
                 : 0) != 0)
        {
            goto active;
        }
    }
    ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
    objAnim->alpha = 0;
    return;
active:
{
    int alpha;

    alpha = (int)(gArwBombCollAlphaFadeRate * timeDelta + (f32)(u32)objAnim->alpha);
    if (alpha > 0xff)
    {
        alpha = 0xff;
    }
    objAnim->alpha = alpha;
    ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
    ((GameObject*)obj)->anim.rotX = gArwBombCollSpinRate * timeDelta + (f32) * &((GameObject*)obj)->anim.rotX;
    ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, ARWBOMBCOLL_HIT_VOLUME_SLOT, 0, 0);
    if (flags->b40 != 0)
    {
        if ((u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject != 0 &&
            (u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject == (u32)getArwing())
        {
            arwarwing_addScore(arw, 0x19);
            flags->b80 = 1;
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
        }
    }
    else
    {
        int hit;
        if (ObjHits_GetPriorityHit((GameObject*)(obj), &hit, 0, 0) != 0 && (u32)hit != 0 &&
            (((GameObject*)hit)->anim.seqId == 0x604 || ((GameObject*)hit)->anim.seqId == 0x605))
        {
            arwarwing_addScore(arw, 0xf);
            flags->b40 = 1;
            Obj_SetActiveModelIndex((GameObject*)obj, 1);
            spawnExplosionLegacy(obj, lbl_803E708C, 1, 0, 0, 0, 0, 0, 2);
        }
        if ((u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject != 0 &&
            (u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject == (u32)getArwing())
        {
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
            spawnExplosionLegacy(obj, lbl_803E708C, 1, 0, 0, 0, 0, 0, 2);
        }
    }
    if (arw != NULL && flags->b80 != 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x609:
            Sfx_PlayFromObject(obj, SFXTRIG_ar_ring_pickup);
            arwarwing_upgradeLaserLevel(arw);
            break;
        case 0x608:
            Sfx_PlayFromObject(obj, SFXTRIG_ar_largeenergy_pickup);
            arwarwing_addBomb(arw);
            break;
        case 0x60a:
            break;
        case 0x6d8:
            Sfx_PlayFromObject(obj, SFXTRIG_ar_smallenergy_pickup);
            arwarwing_incrementPickup6D8Count(arw);
            break;
        case 0x6d9:
            Sfx_PlayFromObject(obj, SFXTRIG_ar_smallenergy_pickup);
            arwarwing_incrementPickup6D9Count(arw);
            break;
        case 0x6db:
            Sfx_PlayFromObject(obj, SFXTRIG_ar_smallenergy_pickup);
            arwarwing_incrementPickup6DBCount(arw);
            break;
        case 0x6da:
            Sfx_PlayFromObject(obj, SFXTRIG_ar_smallenergy_pickup);
            arwarwing_incrementPickup6DACount(arw);
            break;
        }
    }
}
}

#pragma opt_common_subs reset

void ARWBombColl_init(GameObject* obj, ARWBombCollSetup* setup)
{
    ObjAnimComponent* objAnim = &obj->anim;
    ARWBombCollSetup* mapData = setup;

    obj->anim.rotX = (s16)(mapData->rotX << 8);
    objAnim->alpha = 0;
}


void ARWBombColl_release(void)
{
}


void ARWBombColl_initialise(void)
{
}


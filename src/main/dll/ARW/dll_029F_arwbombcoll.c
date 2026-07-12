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
#include "main/dll/dll_80220608_shared.h"
#include "main/dll/headdisplay.h"
#include "main/dll/ARW/dll_029F_arwbombcoll.h"
#include "main/dll/dll_02A0_ring.h"

#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"

#define ARWBOMBCOLL_HIT_VOLUME_SLOT 0x13

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

void ARWBombColl_hitDetect(void)
{
}

void ARWBombColl_render(int obj, int p2, int p3, int p4, int p5, f32 scale)
{
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E7078);
}

void ARWBombColl_init(GameObject* obj, int setup)
{
    ObjAnimComponent* objAnim = &obj->anim;
    ARWBombCollSetup* mapData = (ARWBombCollSetup*)setup;

    obj->anim.rotX = (s16)(mapData->rotX << 8);
    objAnim->alpha = 0;
}

void ARWBombColl_release(void)
{
}

void ARWBombColl_initialise(void)
{
}

void arwbombcoll_updateMovingAxis(GameObject* obj, RingState* state)
{
    u8 mode = state->route;
    if (mode == 1 || mode == 3)
    {
        f32 edge, cur, lim;
        obj->anim.localPosX = state->pullHeight * timeDelta + obj->anim.localPosX;
        cur = obj->anim.localPosX;
        lim = state->origX;
        edge = lim + (f32)(u32)state->linkId;
        if (cur > edge)
        {
            obj->anim.localPosX = edge - (cur - edge);
            state->pullHeight = -state->pullHeight;
        }
        else
        {
            edge = lim - (f32)(u32)state->linkId;
            if (cur < edge)
            {
                obj->anim.localPosX = edge - (cur - edge);
                state->pullHeight = -state->pullHeight;
            }
        }
    }
    else if (mode == 4 || mode == 5)
    {
        f32 edge, cur, lim;
        obj->anim.localPosY = state->pullHeight * timeDelta + obj->anim.localPosY;
        cur = obj->anim.localPosY;
        lim = state->origY;
        edge = lim + (f32)(u32)state->linkId;
        if (cur > edge)
        {
            obj->anim.localPosY = edge - (cur - edge);
            state->pullHeight = -state->pullHeight;
        }
        else
        {
            edge = lim - (f32)(u32)state->linkId;
            if (cur < edge)
            {
                obj->anim.localPosY = edge - (cur - edge);
                state->pullHeight = -state->pullHeight;
            }
        }
    }
}

void Ring_onCollect(GameObject* obj, RingState* state, int arwing)
{
    GameObject* arwingObj = (GameObject*)arwing;
    int setup = *(int*)&obj->anim.placementData;
    u8 mode = state->mode;
    if (mode == 0)
    {
        Sfx_PlayFromObject(arwing, SFXTRIG_ar_lsrhitobj16);
        if (arwingObj->anim.seqId == 0x601)
        {
            arwarwing_addHealth(arwing, 1);
            arwarwing_addScore(arwing, 0xa);
        }
    }
    else if (mode == 1)
    {
        Sfx_PlayFromObject(arwing, SFXTRIG_ar_lsrhitobj16);
        if (arwingObj->anim.seqId == 0x601)
        {
            arwarwing_addMaxHealth(arwing, 1);
            arwarwing_addHealth(arwing, arwarwing_getMaxHealth(arwing));
        }
    }
    else if (mode == 3 || mode == 4)
    {
        Sfx_PlayFromObject(arwing, SFXTRIG_ar_lsrhitobj16);
        gameBitIncrement(((ArwbombcollHandleArwingHitPlacement*)setup)->eventId);
    }
    else
    {
        Sfx_PlayFromObject(arwing, SFXTRIG_ar_laser216);
        if (arwingObj->anim.seqId == 0x601)
        {
            int seg;
            int collected;
            arwarwing_incrementCollectedRingCount(arwing);
            arwarwing_addHealth(arwing, 1);
            arwarwing_addScore(arwing, 0x14);
            seg = arwarwing_getRequiredRingCount(arwing);
            collected = arwarwing_getCollectedRingCount(arwing);
            if (collected == seg)
            {
                if (state->flags.bit20)
                    gameTextFn_80125ba4(7);
            }
            else
            {
                if (state->flags.bit20)
                    gameTextFn_80125ba4(9);
            }
        }
    }
    state->phase = 2;
}

int arwbombcoll_checkArwingCollision(GameObject* obj, RingState* state, int arwing)
{
    ObjAnimComponent* objAnim = &obj->anim;
    ObjAnimComponent* arwingAnim = &((GameObject*)arwing)->anim;
    RingFlags* f = &state->flags;
    if (f->bit10)
    {
        f32 dx = objAnim->localPosX - arwingAnim->localPosX;
        f32 dy = objAnim->localPosY - arwingAnim->localPosY;
        f32 dz;
        if (dy < lbl_803E70A0)
            dy = -dy;
        dz = objAnim->localPosZ - arwingAnim->localPosZ;
        if (dy <= gArwBombCollHitToleranceY)
        {
            if (dx * dx + dz * dz < gArwBombCollHitRadiusSq)
                return 1;
        }
    }
    else
    {
        f32 objZ;
        f32 currentZDelta = (objZ = objAnim->localPosZ) - arwingAnim->localPosZ;
        f32 previousZDelta = objZ - arwingAnim->previousLocalPosZ;
        if (currentZDelta <= lbl_803E70A0 && previousZDelta >= *(f32*)&lbl_803E70A0)
        {
            f32 dx = objAnim->localPosX - arwingAnim->localPosX;
            f32 dy = objAnim->localPosY - arwingAnim->localPosY;
            if (sqrtf(dx * dx + dy * dy) < gArwBombCollPlaneHitRadius)
                return 1;
            if (state->mode == 2 && f->bit20)
                gameTextFn_80125ba4(0xa);
        }
    }
    return 0;
}

#pragma opt_common_subs off
void ARWBombColl_update(int obj)
{
    int arw;
    ObjAnimComponent* objAnim;
    ArwBombFlags* flags;
    ARWBombCollState* state;
    int arwingCheck;
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

    if ((u32)arw != 0 && arwarwing_isExplodingOrWarping(arw) != 0)
    {
        flags->b80 = 0;
        ((GameObject*)obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
        ObjHits_EnableObject(obj);
        return;
    }

    if (flags->b80 == 0)
    {
        arwingCheck = getArwing();
        if ((((u32)arwingCheck != 0)
                 ? (((GameObject*)obj)->anim.localPosZ - ((GameObject*)arwingCheck)->anim.localPosZ <
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
            (u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject == getArwing())
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
            Obj_SetActiveModelIndex(obj, 1);
            spawnExplosion(obj, lbl_803E708C, 1, 0, 0, 0, 0, 0, 2);
        }
        if ((u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject != 0 &&
            (u32)((ObjHitsPriorityState*)objAnim->hitReactState)->lastHitObject == getArwing())
        {
            ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            ObjHits_DisableObject(obj);
            spawnExplosion(obj, lbl_803E708C, 1, 0, 0, 0, 0, 0, 2);
        }
    }
    if ((u32)arw != 0 && flags->b80 != 0)
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

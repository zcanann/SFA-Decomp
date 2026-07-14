/*
 * drakordthornbush (DLL 0x24E) - the thorn/bramble hazard objects from the
 * Drakor boss arena. The object's anim seqId selects one of two variants:
 *   - THORNBUSH_SEQ_THORN (0x727): a thorn cluster that grows in, can be hit
 *     to spawn an explosion, and (when the placement carries no respawn data)
 *     frees itself.
 *   - THORNBUSH_SEQ_LIGHTNING (0x709): a lightning bramble that additionally
 *     drives an Obj_UpdateLightningCluster effect, plays lightning sfx, and
 *     damages the player on proximity.
 * Common behaviour: it grows from a placement-driven scale, registers a hit
 * sphere, counts down a regrow timer, and on death either respawns from the
 * placement's regrow value, frees itself, or hides + drops off the update
 * list. Lightning state holds an objCreateLight model light freed on object
 * free.
 *
 * This TU has no .data section; the ObjectDescriptor wiring these handlers is
 * defined in another DR DLL translation unit.
 */
#include "main/dll/DR/dll_80209FE0_shared.h"
#include "main/object_descriptor.h"
#include "main/dll/player_api.h"
#include "main/maketex_api.h"
#include "main/maketex_timer_api.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/obj_placement.h"
#include "main/object_render.h"
#include "main/object_update_list.h"
#include "main/game_object.h"
#include "main/model_light.h"
#include "main/objfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_024E_drakordthornbush.h"

/* object def numbers selecting the two thornbush variants (anim.seqId) */
#define THORNBUSH_SEQ_LIGHTNING          0x709
#define THORNBUSH_SEQ_THORN              0x727
#define DRAKORDTHORNBUSH_HIT_VOLUME_SLOT 0xe

int drakord_thornbush_getExtraSize(void)
{
    return 0x7c;
}

int drakord_thornbush_getObjectTypeId(void)
{
    return 0;
}

#pragma opt_common_subs off

void drakord_thornbush_free(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == THORNBUSH_SEQ_LIGHTNING)
    {
        Obj_UpdateLightningCluster((GameObject*)obj, ((DrakordThornbushState*)inner)->lightningEntries, 3,
                                   lbl_803E6588, &((DrakordThornbushState*)inner)->light);
    }
    if (((DrakordThornbushState*)inner)->light != NULL)
    {
        ModelLightStruct_free(((DrakordThornbushState*)inner)->light);
    }
}

void drakord_thornbush_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    int inner = *(int*)&((GameObject*)p1)->extra;
    f32 lightScale;
    if (((GameObject*)p1)->anim.seqId == THORNBUSH_SEQ_LIGHTNING)
    {
        lightScale = ((DrakordThornbushState*)inner)->lightScale;
        if (lightScale < lbl_803E6590)
        {
            lightScale = gThornBushLightScaleMax;
        }
        Obj_UpdateLightningCluster((GameObject*)p1, ((DrakordThornbushState*)inner)->lightningEntries, 3, lightScale,
                                   &((DrakordThornbushState*)inner)->light);
    }
    ((void (*)(GameObject*, int, int, int, int, f32))objRenderModelAndHitVolumes)(
        (GameObject*)p1, p2, p3, p4, p5, lbl_803E6594);
}

void drakord_thornbush_hitDetect(int obj)
{
    int inner = *(int*)&((GameObject*)obj)->extra;
    f32 hitPosZ;
    f32 hitPosY;
    f32 hitPosX;
    int damage;
    int hitObj;
    int destroyed;
    int hit;
    int setup;
    if (((DrakordThornbushState*)inner)->health != 0)
    {
        destroyed = timerCountDown((f32*)((char*)inner + 0x10));
        hit = ObjHits_GetPriorityHitWithPosition((GameObject*)(obj), &hitObj, 0, (u32*)&damage, &hitPosX, &hitPosY,
                                                 &hitPosZ);
        if (hit != 0)
        {
            if (((GameObject*)hitObj)->anim.seqId != 0x35f &&
                *(void**)&((DrakordThornbushState*)inner)->lastHitObj != (void*)hitObj &&
                arrayIndexOf(((DrakordThornbushState*)inner)->hitTable, 2, hit) != -1)
            {
                ((DrakordThornbushState*)inner)->lastHitObj = hitObj;
                Obj_SpawnHitLightAndFade((GameObject*)obj, (const Vec3f*)&hitPosX, lbl_803E6598);
                ((DrakordThornbushState*)inner)->health -= damage;
                if (((DrakordThornbushState*)inner)->health <= 0)
                {
                    destroyed = 1;
                }
                else
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_wmap_nameoff_496);
                }
            }
        }
        else
        {
            ((DrakordThornbushState*)inner)->lastHitObj = 0;
        }
        if (destroyed != 0)
        {
            setup = *(int*)&((GameObject*)obj)->anim.placementData;
            ((DrakordThornbushState*)inner)->health = 0;
            switch (((GameObject*)obj)->anim.seqId)
            {
            case THORNBUSH_SEQ_THORN:
                spawnExplosionLegacy((int*)obj, (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius, 1, 0, 0,
                                     0, 0, 1, 1);
                break;
            case THORNBUSH_SEQ_LIGHTNING:
                Sfx_PlayFromObject(obj, SFXTRIG_awghitobj16);
                spawnExplosionLegacy((int*)obj, (f32)(s32)(((DrakordThornbushState*)inner)->radius << 1), 1, 1, 1,
                                     1, 0, 1, 0);
                Obj_UpdateLightningCluster((GameObject*)obj, ((DrakordThornbushState*)inner)->lightningEntries, 3,
                                           lbl_803E6588, &((DrakordThornbushState*)inner)->light);
                break;
            }
            if (((DrakordThornbushPlacement*)setup)->regrowDelay != 0)
            {
                s16toFloat(&((DrakordThornbushState*)inner)->growth,
                           ((DrakordThornbushPlacement*)setup)->regrowDelay);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject((u32)obj);
            }
            else if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xffffffff)
            {
                Obj_FreeObject((GameObject*)obj);
            }
            else
            {
                Obj_RemoveFromUpdateList((u8*)obj);
                ObjHits_DisableObject((u32)obj);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}

void drakord_thornbush_update(GameObject* obj)
{
    int inner = *(int*)&(obj)->extra;
    int setup = *(int*)&(obj)->anim.placementData;
    int setup2;
    if (fn_80080150(&((DrakordThornbushState*)inner)->growth) != 0)
    {
        if (((DrakordThornbushState*)inner)->growth < (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius)
        {
            ObjHits_EnableObject((u32)obj);
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                      (int)(lbl_803E65A8 + (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius -
                                            ((DrakordThornbushState*)inner)->growth));
        }
        if (timerCountDown(&((DrakordThornbushState*)inner)->growth) != 0)
        {
            (obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ((DrakorFlags*)((char*)inner + 0x79))->b80 = 1;
            if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xffffffff)
            {
                Obj_FreeObject((GameObject*)obj);
            }
        }
    }
    else
    {
        Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_drak_pain2);
        if (((DrakorFlags*)((char*)inner + 0x79))->b80)
        {
            ((DrakorFlags*)((char*)inner + 0x79))->b80 = 0;
        }
        switch ((obj)->anim.seqId)
        {
        case THORNBUSH_SEQ_THORN:
            if (playerGetFocusObject(Obj_GetPlayerObject()) != NULL)
            {
                ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
                ObjHits_EnableObject((u32)obj);
            }
            else
            {
                ObjHits_SetHitVolumeSlot((ObjAnimComponent*)obj, DRAKORDTHORNBUSH_HIT_VOLUME_SLOT, 1, 0);
            }
            break;
        case THORNBUSH_SEQ_LIGHTNING:
            if (Vec_distance(&((GameObject*)Obj_GetPlayerObject())->anim.worldPosX, &(obj)->anim.worldPosX) <
                (f32)(s32)(((DrakordThornbushPlacement*)setup)->baseRadius << 1))
            {
                ObjHits_RecordObjectHit((int)Obj_GetPlayerObject(), (int)obj, 5, 1, 0);
            }
            break;
        }
        if (((DrakordThornbushState*)inner)->health == 0)
        {
            setup2 = *(int*)&(obj)->anim.placementData;
            ObjHits_EnableObject((u32)obj);
            ((DrakordThornbushState*)inner)->health = ((DrakordThornbushPlacement*)setup2)->spawnHealth;
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, (s16)((DrakordThornbushState*)inner)->radius);
        }
        if ((obj)->anim.seqId == THORNBUSH_SEQ_LIGHTNING)
        {
            if (((DrakordThornbushState*)inner)->lightScale < gThornBushLightScaleMax)
            {
                ((DrakordThornbushState*)inner)->lightScale =
                    gThornBushLightScaleRate * (f32)(u32)framesThisStep + ((DrakordThornbushState*)inner)->lightScale;
                (obj)->anim.rootMotionScale = ((DrakordThornbushState*)inner)->lightScale *
                                              ((obj)->anim.modelInstance->rootMotionScaleBase *
                                               (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius) /
                                              lbl_803E65B0;
            }
        }
    }
}

void drakord_thornbush_init(GameObject* obj, u8* init)
{
    int inner = *(int*)&(obj)->extra;
    ((DrakordThornbushState*)inner)->health = 0;
        ObjHits_SetTargetMask((int)obj, 4);
    (obj)->anim.rotY = (s16)((s8)init[0x18] << 8);
    if (*(u32*)&((ObjPlacement*)init)->mapId == 0xffffffff)
    {
        ((DrakorFlags*)((char*)inner + 0x79))->b80 = 1;
    }
    storeZeroToFloatParam(&((DrakordThornbushState*)inner)->growth);
    storeZeroToFloatParam((f32*)((char*)inner + 0x10));
    ((DrakordThornbushState*)inner)->lastHitObj = 0;
    switch ((obj)->anim.seqId)
    {
    case THORNBUSH_SEQ_THORN:
        ((DrakordThornbushState*)inner)->hitTable = &gThornBushThornHitTable;
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, ((DrakordThornbushPlacement*)init)->baseRadius);
        ((DrakordThornbushState*)inner)->radius = ((DrakordThornbushPlacement*)init)->baseRadius;
        ((DrakordThornbushState*)inner)->baseScale = lbl_803E65C0;
        (obj)->anim.rootMotionScale = (obj)->anim.modelInstance->rootMotionScaleBase *
                                      (f32)(s32)((DrakordThornbushPlacement*)init)->baseRadius / lbl_803E6590;
        break;
    case THORNBUSH_SEQ_LIGHTNING:
        ((DrakordThornbushState*)inner)->hitTable = &gThornBushLightningHitTable;
        (obj)->anim.rootMotionScale = (obj)->anim.modelInstance->rootMotionScaleBase *
                                      (f32)(s32)((DrakordThornbushPlacement*)init)->baseRadius / lbl_803E65C4;
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                  (s16)(((DrakordThornbushPlacement*)init)->baseRadius / 7));
        s16toFloat((f32*)((char*)inner + 0x10), gThornBushLightningTimerInit);
        ((DrakordThornbushState*)inner)->baseScale = lbl_803E65C8;
        ((DrakordThornbushState*)inner)->radius = ((DrakordThornbushPlacement*)init)->baseRadius / 5;
        ((DrakordThornbushState*)inner)->lightScale = lbl_803E6594;
        break;
    }
}

#pragma opt_common_subs reset

void drakord_thornbush_release(void)
{
}

void drakord_thornbush_initialise(void)
{
}

ObjectDescriptor gDrakorDThornBushObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)drakord_thornbush_initialise,
    (ObjectDescriptorCallback)drakord_thornbush_release,
    0,
    (ObjectDescriptorCallback)drakord_thornbush_init,
    (ObjectDescriptorCallback)drakord_thornbush_update,
    (ObjectDescriptorCallback)drakord_thornbush_hitDetect,
    (ObjectDescriptorCallback)drakord_thornbush_render,
    (ObjectDescriptorCallback)drakord_thornbush_free,
    (ObjectDescriptorCallback)drakord_thornbush_getObjectTypeId,
    (ObjectDescriptorExtraSizeCallback)drakord_thornbush_getExtraSize,
};

u32 lbl_8032A110[12] = {0xFFFFFFFF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

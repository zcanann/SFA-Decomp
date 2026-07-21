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
#include "main/object_api.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/audio/sfx.h"
#include "main/objhits.h"
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

int gThornBushLightningHitTable[2] = {15, 14};
int gThornBushThornHitTable[2] = {5, 5};
f32 gThornBushLightningTimerInit = 300.0f;
static int lbl_803DC1B4[1] = {0};

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


void drakord_thornbush_free(int obj)
{
    DrakordThornbushState* inner = (DrakordThornbushState*)((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == THORNBUSH_SEQ_LIGHTNING)
    {
        Obj_UpdateLightningCluster((GameObject*)obj, inner->lightningEntries, 3,
                                   0.0f, &inner->light);
    }
    if (inner->light != NULL)
    {
        ModelLightStruct_free(inner->light);
    }
}

void drakord_thornbush_render(int p1, int p2, int p3, int p4, int p5, s8 vis)
{
    DrakordThornbushState* inner = (DrakordThornbushState*)((GameObject*)p1)->extra;
    f32 lightScale;
    if (((GameObject*)p1)->anim.seqId == THORNBUSH_SEQ_LIGHTNING)
    {
        lightScale = inner->lightScale;
        if (lightScale < 10.0f)
        {
            lightScale = 150.0f;
        }
        Obj_UpdateLightningCluster((GameObject*)p1, inner->lightningEntries, 3, lightScale,
                                   &inner->light);
    }
    objRenderModelAndHitVolumes((GameObject*)p1, p2, p3, p4, p5, 1.0f);
}

void drakord_thornbush_hitDetect(int obj)
{
    DrakordThornbushState* inner = (DrakordThornbushState*)((GameObject*)obj)->extra;
    f32 hitPosZ;
    f32 hitPosY;
    f32 hitPosX;
    int damage;
    int hitObj;
    int destroyed;
    int hit;
    int setup;
    if (inner->health != 0)
    {
        destroyed = timerCountDown(&inner->regrowTimer);
        hit = ObjHits_GetPriorityHitWithPosition((GameObject*)(obj), &hitObj, 0, (u32*)&damage, &hitPosX, &hitPosY,
                                                 &hitPosZ);
        if (hit != 0)
        {
            if (((GameObject*)hitObj)->anim.seqId != 0x35f &&
                *(void**)&inner->lastHitObj != (void*)hitObj &&
                arrayIndexOf(inner->hitTable, 2, hit) != -1)
            {
                inner->lastHitObj = hitObj;
                Obj_SpawnHitLightAndFade((GameObject*)obj, (const Vec3f*)&hitPosX, 50.0f);
                inner->health -= damage;
                if (inner->health <= 0)
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
            inner->lastHitObj = 0;
        }
        if (destroyed != 0)
        {
            setup = *(int*)&((GameObject*)obj)->anim.placementData;
            inner->health = 0;
            switch (((GameObject*)obj)->anim.seqId)
            {
            case THORNBUSH_SEQ_THORN:
                spawnExplosion((GameObject*)(int*)obj, (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius, 1, 0, 0,
                                     0, 0, 1, 1);
                break;
            case THORNBUSH_SEQ_LIGHTNING:
                Sfx_PlayFromObject(obj, SFXTRIG_awghitobj16);
                spawnExplosion((GameObject*)(int*)obj, (f32)(s32)(inner->radius << 1), 1, 1, 1,
                                     1, 0, 1, 0);
                Obj_UpdateLightningCluster((GameObject*)obj, inner->lightningEntries, 3,
                                           0.0f, &inner->light);
                break;
            }
            if (((DrakordThornbushPlacement*)setup)->regrowDelay != 0)
            {
                s16toFloat(&inner->growth,
                           ((DrakordThornbushPlacement*)setup)->regrowDelay);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject((GameObject*)obj);
            }
            else if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xffffffff)
            {
                Obj_FreeObject((GameObject*)obj);
            }
            else
            {
                Obj_RemoveFromUpdateList((GameObject*)obj);
                ObjHits_DisableObject((GameObject*)obj);
                ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}

void drakord_thornbush_update(GameObject* obj)
{
    DrakordThornbushState* inner = (DrakordThornbushState*)(obj)->extra;
    int setup = *(int*)&(obj)->anim.placementData;
    int setup2;
    if (fn_80080150(&inner->growth) != 0)
    {
        if (inner->growth < (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius)
        {
            ObjHits_EnableObject(obj);
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                      (int)(0.1f + (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius -
                                            inner->growth));
        }
        if (timerCountDown(&inner->growth) != 0)
        {
            (obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            ((ThornBushFlags*)((char*)inner + 0x79))->b80 = 1;
            if (*(u32*)&((ObjPlacement*)setup)->mapId == 0xffffffff)
            {
                Obj_FreeObject((GameObject*)obj);
            }
        }
    }
    else
    {
        Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_drak_pain2);
        if (((ThornBushFlags*)((char*)inner + 0x79))->b80)
        {
            ((ThornBushFlags*)((char*)inner + 0x79))->b80 = 0;
        }
        switch ((obj)->anim.seqId)
        {
        case THORNBUSH_SEQ_THORN:
            if (playerGetFocusObject(Obj_GetPlayerObject()) != NULL)
            {
                ObjHits_ClearHitVolumes((ObjAnimComponent*)obj);
                ObjHits_EnableObject(obj);
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
                ObjHits_RecordObjectHit(Obj_GetPlayerObject(), obj, 5, 1, 0);
            }
            break;
        }
        if (inner->health == 0)
        {
            setup2 = *(int*)&(obj)->anim.placementData;
            ObjHits_EnableObject(obj);
            inner->health = ((DrakordThornbushPlacement*)setup2)->spawnHealth;
            ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, (s16)inner->radius);
        }
        if ((obj)->anim.seqId == THORNBUSH_SEQ_LIGHTNING)
        {
            if (inner->lightScale < 150.0f)
            {
                inner->lightScale =
                    4.0f * (f32)(u32)framesThisStep + inner->lightScale;
                (obj)->anim.rootMotionScale = inner->lightScale *
                                              ((obj)->anim.modelInstance->rootMotionScaleBase *
                                               (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius) /
                                              12000.0f;
            }
        }
    }
}

void drakord_thornbush_init(GameObject* obj, u8* init)
{
    DrakordThornbushState* inner = (DrakordThornbushState*)(obj)->extra;
    inner->health = 0;
        ObjHits_SetTargetMask(obj, 4);
    (obj)->anim.rotY = (s16)((s8)init[0x18] << 8);
    if (*(u32*)&((ObjPlacement*)init)->mapId == 0xffffffff)
    {
        ((ThornBushFlags*)((char*)inner + 0x79))->b80 = 1;
    }
    storeZeroToFloatParam(&inner->growth);
    storeZeroToFloatParam(&inner->regrowTimer);
    inner->lastHitObj = 0;
    switch ((obj)->anim.seqId)
    {
    case THORNBUSH_SEQ_THORN:
        inner->hitTable = &gThornBushThornHitTable;
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj, ((DrakordThornbushPlacement*)init)->baseRadius);
        inner->radius = ((DrakordThornbushPlacement*)init)->baseRadius;
        inner->baseScale = 0.01f;
        (obj)->anim.rootMotionScale = (obj)->anim.modelInstance->rootMotionScaleBase *
                                      (f32)(s32)((DrakordThornbushPlacement*)init)->baseRadius / 10.0f;
        break;
    case THORNBUSH_SEQ_LIGHTNING:
        inner->hitTable = &gThornBushLightningHitTable;
        (obj)->anim.rootMotionScale = (obj)->anim.modelInstance->rootMotionScaleBase *
                                      (f32)(s32)((DrakordThornbushPlacement*)init)->baseRadius / 60.0f;
        ObjHitbox_SetSphereRadius((ObjAnimComponent*)obj,
                                  (s16)(((DrakordThornbushPlacement*)init)->baseRadius / 7));
        s16toFloat(&inner->regrowTimer, gThornBushLightningTimerInit);
        inner->baseScale = 0.04f;
        inner->radius = ((DrakordThornbushPlacement*)init)->baseRadius / 5;
        inner->lightScale = 1.0f;
        break;
    }
}


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

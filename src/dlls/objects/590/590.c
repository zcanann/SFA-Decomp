/*
 * drakordthornbush (DLL 0x24E) - the thorn/bramble hazard objects from the
 * Drakor boss arena. The object's anim romDefNo selects one of two variants:
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
 */
#include "sys/objects.h"
#include "main/frame_timing.h"
#include "main/vecmath.h"
#include "main/dll/player_api.h"
#include "main/maketex_timer_api.h"
#include "main/dll/dll_0282_barrelgener.h"
#include "main/object_render.h"
#include "main/objfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/dll_024E_drakordthornbush.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_play_api.h"
#include "main/maketex_api.h"
#include "main/object_update_list.h"
#include "main/objhits.h"
#include "sys/objects/lifecycle.h"
#include "main/model_light.h"

int gThornBushLightningHitTable[2] = {15, 14};
int gThornBushThornHitTable[2] = {5, 5};
f32 gThornBushLightningTimerInit = 300.0f;
static int lbl_803DC1B4[1] = {0};

/* object def numbers selecting the two thornbush variants (anim.romDefNo) */
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


void drakord_thornbush_free(GameObject* obj)
{
    DrakordThornbushState* inner = obj->extra;
    if (obj->anim.romDefNo == THORNBUSH_SEQ_LIGHTNING)
    {
        Obj_UpdateLightningCluster(obj, inner->lightningEntries, 3,
                                   0.0f, &inner->light);
    }
    if (inner->light != NULL)
    {
        ModelLightStruct_free(inner->light);
    }
}

void drakord_thornbush_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 vis)
{
    DrakordThornbushState* inner = obj->extra;
    f32 lightScale;
    if (obj->anim.romDefNo == THORNBUSH_SEQ_LIGHTNING)
    {
        lightScale = inner->lightScale;
        if (lightScale < 10.0f)
        {
            lightScale = 150.0f;
        }
        Obj_UpdateLightningCluster(obj, inner->lightningEntries, 3, lightScale,
                                   &inner->light);
    }
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void drakord_thornbush_hitDetect(GameObject* obj)
{
    DrakordThornbushState* inner = (DrakordThornbushState*)obj->extra;
    f32 hitPosZ;
    f32 hitPosY;
    f32 hitPosX;
    int damage;
    GameObject* hitObj;
    int destroyed;
    int hit;
    DrakordThornbushPlacement* setup;
    if (inner->health != 0)
    {
        destroyed = timerCountDown(&inner->regrowTimer);
        hit = ObjHits_GetPriorityHitWithPosition(obj, &hitObj, 0, (u32*)&damage, &hitPosX, &hitPosY,
                                                 &hitPosZ);
        if (hit != 0)
        {
            if (hitObj->anim.romDefNo != 0x35f &&
                (void*)inner->lastHitObj != (void*)hitObj &&
                arrayIndexOf(inner->hitTable, 2, hit) != -1)
            {
                inner->lastHitObj = (int)hitObj;
                Obj_SpawnHitLightAndFade(obj, (const Vec3f*)&hitPosX, 50.0f);
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
            setup = (DrakordThornbushPlacement*)obj->anim.placementData;
            inner->health = 0;
            switch (obj->anim.romDefNo)
            {
            case THORNBUSH_SEQ_THORN:
                spawnExplosion(obj, (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius, 1, 0, 0,
                                     0, 0, 1, 1);
                break;
            case THORNBUSH_SEQ_LIGHTNING:
                Sfx_PlayFromObject(obj, SFXTRIG_awghitobj16);
                spawnExplosion(obj, (f32)(s32)(inner->radius << 1), 1, 1, 1,
                                     1, 0, 1, 0);
                Obj_UpdateLightningCluster(obj, inner->lightningEntries, 3,
                                           0.0f, &inner->light);
                break;
            }
            if (((DrakordThornbushPlacement*)setup)->regrowDelay != 0)
            {
                s16toFloat(&inner->growth,
                           ((DrakordThornbushPlacement*)setup)->regrowDelay);
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
                ObjHits_DisableObject(obj);
            }
            else if (*(u32*)&((ObjPlacement*)setup)->ident == 0xffffffff)
            {
                Obj_FreeObject(obj);
            }
            else
            {
                Obj_RemoveFromUpdateList(obj);
                ObjHits_DisableObject(obj);
                obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
            }
        }
    }
}

void drakord_thornbush_update(GameObject* obj)
{
    DrakordThornbushState* inner = (DrakordThornbushState*)obj->extra;
    int setup = (obj)->anim.placementDataAddress;
    DrakordThornbushPlacement* setup2;
    if (timerIsActive(&inner->growth) != 0)
    {
        if (inner->growth < (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius)
        {
            ObjHits_EnableObject(obj);
            ObjHitbox_SetSphereRadius(&obj->anim,
                                      (int)(0.1f + (f32)(s32)((DrakordThornbushPlacement*)setup)->baseRadius -
                                            inner->growth));
        }
        if (timerCountDown(&inner->growth) != 0)
        {
            (obj)->anim.flags &= ~OBJANIM_FLAG_HIDDEN;
            inner->flags79.b80 = 1;
            if (*(u32*)&((ObjPlacement*)setup)->ident == 0xffffffff)
            {
                Obj_FreeObject(obj);
            }
        }
    }
    else
    {
        Sfx_KeepAliveLoopedObjectSound(obj, SFXTRIG_drak_pain2);
        if (inner->flags79.b80)
        {
            inner->flags79.b80 = 0;
        }
        switch ((obj)->anim.romDefNo)
        {
        case THORNBUSH_SEQ_THORN:
            if (playerGetFocusObject(Obj_GetPlayerObject()) != NULL)
            {
                ObjHits_ClearHitVolumes(&obj->anim);
                ObjHits_EnableObject(obj);
            }
            else
            {
                ObjHits_SetHitVolumeSlot(&obj->anim, DRAKORDTHORNBUSH_HIT_VOLUME_SLOT, 1, 0);
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
            setup2 = (DrakordThornbushPlacement*)((obj)->anim.placementDataAddress);
            ObjHits_EnableObject(obj);
            inner->health = setup2->spawnHealth;
            ObjHitbox_SetSphereRadius(&obj->anim, (s16)inner->radius);
        }
        if ((obj)->anim.romDefNo == THORNBUSH_SEQ_LIGHTNING)
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
    DrakordThornbushState* inner = (DrakordThornbushState*)obj->extra;
    inner->health = 0;
        ObjHits_SetTargetMask(obj, 4);
    (obj)->anim.rotY = (s16)(((DrakordThornbushPlacement*)init)->rotYByte << 8);
    if (*(u32*)&((ObjPlacement*)init)->ident == 0xffffffff)
    {
        inner->flags79.b80 = 1;
    }
    storeZeroToFloatParam(&inner->growth);
    storeZeroToFloatParam(&inner->regrowTimer);
    inner->lastHitObj = 0;
    switch ((obj)->anim.romDefNo)
    {
    case THORNBUSH_SEQ_THORN:
        inner->hitTable = &gThornBushThornHitTable;
        ObjHitbox_SetSphereRadius(&obj->anim, ((DrakordThornbushPlacement*)init)->baseRadius);
        inner->radius = ((DrakordThornbushPlacement*)init)->baseRadius;
        inner->baseScale = 0.01f;
        (obj)->anim.rootMotionScale = (obj)->anim.modelInstance->rootMotionScaleBase *
                                      (f32)(s32)((DrakordThornbushPlacement*)init)->baseRadius / 10.0f;
        break;
    case THORNBUSH_SEQ_LIGHTNING:
        inner->hitTable = &gThornBushLightningHitTable;
        (obj)->anim.rootMotionScale = (obj)->anim.modelInstance->rootMotionScaleBase *
                                      (f32)(s32)((DrakordThornbushPlacement*)init)->baseRadius / 60.0f;
        ObjHitbox_SetSphereRadius(&obj->anim,
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

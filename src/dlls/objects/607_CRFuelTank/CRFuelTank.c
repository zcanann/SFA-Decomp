/* CRFuelTank (DLL 607): CloudRunner fuel-tank object callbacks. */

#include "dlls/objects/607_CRFuelTank.h"

#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebits.h"
#include "main/audio/sfx_play_api.h"
#include "main/maketex_timer_api.h"
#include "main/objhits.h"
#include "sys/objects.h"

#define CRFUELTANK_HIT_PRIORITY 0x1d
#define CRFUELTANK_RESPAWN_FRAMES 0x708

/* only the CloudRunner snowbike detonates a fuel tank; retail OBJECTS.bin name
   "CRSnowBike" (DLL 0x255) */
#define CRFUELTANK_TRIGGER_OBJ 0x38c

static inline int crfueltank_hitVolumeId(CrFuelTankPlacementPrefix* def)
{
    return def->hitVolumeIdTimes10 / 10;
}

int crfueltank_getExtraSize(void)
{
    return sizeof(CrFuelTankState);
}

int crfueltank_getObjectTypeId(void)
{
    return 0;
}

void crfueltank_free(void)
{
    return;
}

void crfueltank_render(void)
{
    return;
}

void crfueltank_hitDetect(GameObject* obj)
{
    CrFuelTankPlacementPrefix* def;
    ObjHitsPriorityState* hitState;
    GameObject* hitObj;

    hitState = (ObjHitsPriorityState*)obj->anim.hitReactState;
    def = (CrFuelTankPlacementPrefix*)obj->anim.placementData;
    if ((hitState != NULL) && (hitState->lastHitObject != 0))
    {
        hitObj = (GameObject*)hitState->lastHitObject;
        if (hitObj->anim.romDefNo == CRFUELTANK_TRIGGER_OBJ)
        {
            ObjHits_DisableObject(obj);
            Sfx_PlayFromObject(Obj_GetPlayerObject(), SFXTRIG_ar_barrel16);
            obj->anim.alpha = 0xfa;
            obj->userData2 = 1;
            if (def->hitGameBit != -1)
            {
                mainSetBits(def->hitGameBit, 1);
            }
            obj->anim.velocityX = hitObj->anim.velocityX;
            obj->anim.velocityY = 0.07f + hitObj->anim.velocityY;
            obj->anim.velocityZ = hitObj->anim.velocityZ;
        }
    }
    return;
}

void crfueltank_update(GameObject* obj)
{
    CrFuelTankPlacementPrefix* def;
    CrFuelTankState* state;

    def = (CrFuelTankPlacementPrefix*)obj->anim.placementData;
    state = obj->extra;
    if (timerIsActive(&state->respawnTimer) != 0)
    {
        if (timerCountDown(&state->respawnTimer) != 0)
        {
            ObjHits_EnableObject(obj);
            obj->anim.flags = (s16)(obj->anim.flags & ~OBJANIM_FLAG_HIDDEN);
            obj->anim.alpha = 0xff;
        }
    }
    else
    {
        if (obj->anim.alpha < 0xff)
        {
            obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
            s16toFloat(&state->respawnTimer, CRFUELTANK_RESPAWN_FRAMES);
        }
        else
        {
            ObjHits_SetHitVolumeSlot(&obj->anim, CRFUELTANK_HIT_PRIORITY, crfueltank_hitVolumeId(def), 0);
        }
    }
    return;
}

void crfueltank_init(GameObject* obj, CrFuelTankPlacementPrefix* def)
{
    CrFuelTankState* state;

    state = obj->extra;
    ObjHits_EnableObject(obj);
    ObjHits_SetHitVolumeSlot(&obj->anim, CRFUELTANK_HIT_PRIORITY, crfueltank_hitVolumeId(def), 0);
    storeZeroToFloatParam(&state->respawnTimer);
    if ((def->hitGameBit != -1) && (mainGetBit(def->hitGameBit) != 0))
    {
        s16toFloat(&state->respawnTimer, CRFUELTANK_RESPAWN_FRAMES);
        ObjHits_DisableObject(obj);
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        obj->anim.alpha = 0;
    }
    return;
}

void crfueltank_release(void)
{
    return;
}

void crfueltank_initialise(void)
{
    return;
}

ObjectDescriptor gCrFuelTankObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)crfueltank_initialise,
    (ObjectDescriptorCallback)crfueltank_release,
    0,
    (ObjectDescriptorCallback)crfueltank_init,
    (ObjectDescriptorCallback)crfueltank_update,
    (ObjectDescriptorCallback)crfueltank_hitDetect,
    (ObjectDescriptorCallback)crfueltank_render,
    (ObjectDescriptorCallback)crfueltank_free,
    (ObjectDescriptorCallback)crfueltank_getObjectTypeId,
    crfueltank_getExtraSize,
};

#include "main/audio/sfx_ids.h"
#include "main/crfueltank.h"
#include "main/gamebits.h"
#include "main/dll/fx_800944A0_shared.h"

/* GameObject anim.flags bit (== OBJANIM_FLAG_HIDDEN): hides the tank from
   render/update; toggled with the hit-volume enable/disable. */
#define CRFUELTANK_OBJFLAG_HIDDEN 0x4000

extern void Sfx_PlayFromObject(void* obj, u16 sfxId);
extern void ObjHits_DisableObject(void* obj);
extern void ObjHits_EnableObject(void* obj);
extern void ObjHits_SetHitVolumeSlot(void* obj, int hitVolume, int hitType, int sourceSlot);


extern int fn_80080150(void* timer);
extern void storeZeroToFloatParam(void* timer);
extern void s16toFloat(void* timer, int duration);
extern int timerCountDown(void* timer);

extern f32 lbl_803E6760;

static inline int crfueltank_animFrame(CrFuelTankDef* def)
{
    return def->idleFrameCount / 10;
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

void crfueltank_hitDetect(CrFuelTankObject* obj)
{
    CrFuelTankDef* def;
    CrFuelTankCollider* collider;
    CrFuelTankHitObj* hitObj;

    collider = obj->collider;
    def = obj->def;
    if ((collider != NULL) && (collider->hitObj != NULL))
    {
        hitObj = collider->hitObj;
        if (hitObj->objType == 0x38c)
        {
            ObjHits_DisableObject(obj);
            Sfx_PlayFromObject(Obj_GetPlayerObject(), SFXsp_sabrepush162);
            obj->fadeTimer = 0xfa;
            obj->triggered = 1;
            if (def->hitEvent != -1)
            {
                GameBit_Set(def->hitEvent, 1);
            }
            obj->posX = hitObj->posX;
            obj->posY = lbl_803E6760 + hitObj->posY;
            obj->posZ = hitObj->posZ;
        }
    }
    return;
}

void crfueltank_update(CrFuelTankObject* obj)
{
    CrFuelTankDef* def;
    CrFuelTankState* state;

    def = obj->def;
    state = obj->state;
    if (fn_80080150(state->timer) != 0)
    {
        if (timerCountDown(state->timer) != 0)
        {
            ObjHits_EnableObject(obj);
            obj->flags = (s16)(obj->flags & ~CRFUELTANK_OBJFLAG_HIDDEN);
            obj->fadeTimer = 0xff;
        }
    }
    else
    {
        if (obj->fadeTimer < 0xff)
        {
            obj->flags = (s16)(obj->flags | CRFUELTANK_OBJFLAG_HIDDEN);
            s16toFloat(state->timer, 0x708);
        }
        else
        {
            ObjHits_SetHitVolumeSlot(obj, 0x1d, crfueltank_animFrame(def), 0);
        }
    }
    return;
}

void crfueltank_init(CrFuelTankObject* obj, CrFuelTankDef* def)
{
    CrFuelTankState* state;

    state = obj->state;
    ObjHits_EnableObject(obj);
    ObjHits_SetHitVolumeSlot(obj, 0x1d, crfueltank_animFrame(def), 0);
    storeZeroToFloatParam(state->timer);
    if ((def->hitEvent != -1) && (GameBit_Get(def->hitEvent) != 0))
    {
        s16toFloat(state->timer, 0x708);
        ObjHits_DisableObject(obj);
        obj->flags = (s16)(obj->flags | CRFUELTANK_OBJFLAG_HIDDEN);
        obj->fadeTimer = 0;
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

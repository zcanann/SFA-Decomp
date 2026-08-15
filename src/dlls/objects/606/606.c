/* DLL 606: SpellStone-family object callbacks. */

#include "main/mapEvent.h"
#include "main/spellstone.h"
#include "main/object_render.h"
#include "sys/objects.h"
#include "main/vecmath.h"
#include "main/gamebits_api.h"
#include "main/object_update_list.h"
#include "main/objhits.h"
#include "main/objtype.h"
#include "main/spellstone_idle.h"
#include "main/mapEventTypes.h"

int spellstone_idleCallback(void)
{
    return 0x0;
}

s16 gSpellStoneEventGameBits[2] = {0x49A, 0x49A};

/* object group this object joins while active */
#define SPELLSTONE_OBJGROUP 0x1e

int spellstone_getState(GameObject* obj)
{
    return ((SpellStoneState*)obj->extra)->state != SPELLSTONE_STATE_ACTIVE;
}

int spellstone_setState(GameObject* obj, int state)
{
    SpellStoneState* extra;
    u8 oldState;

    extra = obj->extra;
    oldState = extra->state;
    extra->state = state;
    if (state == SPELLSTONE_STATE_ACTIVE)
    {
        obj->anim.localPosY += 4.0f;
    }
    return oldState != SPELLSTONE_STATE_IDLE;
}

int spellstone_getExtraSize(void)
{
    return sizeof(SpellStoneState);
}

int spellstone_getObjectTypeId(void)
{
    return 0;
}

void spellstone_free(GameObject* obj)
{
    objFreeObjectType(obj, SPELLSTONE_OBJGROUP);
    return;
}

void spellstone_render(GameObject* obj, u32 p2, u32 p3, u32 p4, u32 p5, char visible)
{
    SpellStoneState* state;

    state = obj->extra;
    if ((visible != 0) && (state->state != SPELLSTONE_STATE_HIDDEN))
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)1.0f);
    }
    return;
}

void spellstone_hitDetect(void)
{
    return;
}

void spellstone_update(GameObject* obj)
{
    u32 eventActive;
    GameObject* playerObj;
    SpellStoneState* state;
    SpellStoneDef* def;

    state = obj->extra;
    def = (SpellStoneDef*)obj->anim.placementData;
    if (state->state == SPELLSTONE_STATE_ACTIVE)
    {
        obj->anim.rotY = 0;
        obj->anim.rotX += 0x100;
        obj->anim.rotZ = 0;
    }
    eventActive = mainGetBit(def->completeEvent);
    if (eventActive != 0)
    {
        mainSetBits(*(gSpellStoneEventGameBits + def->eventIndex), 1);
        obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
        Obj_RemoveFromUpdateList(obj);
        (*gMapEventInterface)->setMapAct(0x1d, 2);
    }
    else
    {
        eventActive = mainGetBit(def->activeEvent);
        if (eventActive != 0)
        {
            obj->anim.flags = (s16)(obj->anim.flags | OBJANIM_FLAG_HIDDEN);
            Obj_RemoveFromUpdateList(obj);
        }
        if (state->state == SPELLSTONE_STATE_ACTIVE)
        {
            playerObj = Obj_GetPlayerObject();
            if (Vec_distance(&obj->anim.worldPosX, &playerObj->anim.worldPosX) < 105.0f)
            {
                mainSetBits(def->completeEvent, 1);
            }
        }
        if (state->state == SPELLSTONE_STATE_HIDDEN)
        {
            ObjHits_DisableObject(obj);
            if (obj->ownerObj != NULL)
            {
                obj->anim.localPosX = ((GameObject*)obj->ownerObj)->anim.localPosX;
                obj->anim.localPosY = ((GameObject*)obj->ownerObj)->anim.localPosY;
                obj->anim.localPosZ = ((GameObject*)obj->ownerObj)->anim.localPosZ;
            }
        }
        else
        {
            ObjHits_EnableObject(obj);
        }
    }
    return;
}

void spellstone_init(GameObject* obj)
{
    SpellStoneState* state;

    state = obj->extra;
    objAddObjectType(obj, SPELLSTONE_OBJGROUP);
    state->state = SPELLSTONE_STATE_IDLE;
    obj->animEventCallback = spellstone_idleCallback;
    return;
}

void spellstone_release(void)
{
    return;
}

void spellstone_initialise(void)
{
    return;
}

ObjectDescriptor12 gSpellStoneObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    (ObjectDescriptorCallback)spellstone_initialise,
    (ObjectDescriptorCallback)spellstone_release,
    0,
    (ObjectDescriptorCallback)spellstone_init,
    (ObjectDescriptorCallback)spellstone_update,
    (ObjectDescriptorCallback)spellstone_hitDetect,
    (ObjectDescriptorCallback)spellstone_render,
    (ObjectDescriptorCallback)spellstone_free,
    (ObjectDescriptorCallback)spellstone_getObjectTypeId,
    spellstone_getExtraSize,
    (ObjectDescriptorCallback)spellstone_setState,
    (ObjectDescriptorCallback)spellstone_getState,
};

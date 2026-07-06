#include "main/gamebits.h"
#include "main/mapEvent.h"
#include "main/spellstone.h"
#include "main/objlib.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/fx_800944A0_shared.h"

/* object group this object joins while active */
#define SPELLSTONE_OBJGROUP 0x1e

/* GameObject anim.flags bit (== OBJANIM_FLAG_HIDDEN): stops the object being
   rendered/updated; set when the stone's map event completes. */
#define SPELLSTONE_OBJFLAG_HIDDEN 0x4000

extern f32 Vec_distance(void* posA, void* posB);

extern void Obj_RemoveFromUpdateList(void* obj);
extern void objRenderModelAndHitVolumes(void* obj, u32 fwdArg2, u32 fwdArg3, u32 fwdArg4,
                                 u32 fwdArg5, double scale);


extern s16 lbl_803DC228;
extern f32 lbl_803E6750;
extern f32 lbl_803E6754;
extern f32 lbl_803E6758;


int spellstone_getState(SpellStoneObject* obj)
{
    return obj->state->state != SPELLSTONE_STATE_ACTIVE;
}

int spellstone_setState(SpellStoneObject* obj, int state)
{
    SpellStoneState* extra;
    u8 oldState;

    extra = obj->state;
    oldState = extra->state;
    extra->state = state;
    if (state == SPELLSTONE_STATE_ACTIVE)
    {
        obj->posY += lbl_803E6750;
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

void spellstone_free(SpellStoneObject* obj)
{
    ObjGroup_RemoveObject((u32)obj, SPELLSTONE_OBJGROUP);
    return;
}

void spellstone_render(SpellStoneObject* obj, u32 p2, u32 p3,
                       u32 p4, u32 p5, char visible)
{
    SpellStoneState* state;

    state = obj->state;
    if ((visible != 0) && (state->state != SPELLSTONE_STATE_HIDDEN))
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, (double)lbl_803E6754);
    }
    return;
}

void spellstone_hitDetect(void)
{
    return;
}

void spellstone_update(SpellStoneObject* obj)
{
    u32 eventActive;
    void* playerObj;
    SpellStoneState* state;
    SpellStoneDef* def;

    state = obj->state;
    def = obj->def;
    if (state->state == SPELLSTONE_STATE_ACTIVE)
    {
        obj->rotY = 0;
        obj->rotX += 0x100;
        obj->rotZ = 0;
    }
    eventActive = GameBit_Get(def->completeEvent);
    if (eventActive != 0)
    {
        GameBit_Set(*(&lbl_803DC228 + def->eventIndex), 1);
        obj->flags = (s16)(obj->flags | SPELLSTONE_OBJFLAG_HIDDEN);
        Obj_RemoveFromUpdateList(obj);
        (*gMapEventInterface)->setMapAct(0x1d, 2);
    }
    else
    {
        eventActive = GameBit_Get(def->activeEvent);
        if (eventActive != 0)
        {
            obj->flags = (s16)(obj->flags | SPELLSTONE_OBJFLAG_HIDDEN);
            Obj_RemoveFromUpdateList(obj);
        }
        if (state->state == SPELLSTONE_STATE_ACTIVE)
        {
            playerObj = Obj_GetPlayerObject();
            if (Vec_distance(&obj->worldPosX, (u8*)playerObj + 0x18) < lbl_803E6758)
            {
                GameBit_Set(def->completeEvent, 1);
            }
        }
        if (state->state == SPELLSTONE_STATE_HIDDEN)
        {
            ObjHits_DisableObject((u32)obj);
            if (obj->followTarget != NULL)
            {
                obj->posX = ((GameObject*)obj->followTarget)->anim.localPosX;
                obj->posY = ((GameObject*)obj->followTarget)->anim.localPosY;
                obj->posZ = ((GameObject*)obj->followTarget)->anim.localPosZ;
            }
        }
        else
        {
            ObjHits_EnableObject((u32)obj);
        }
    }
    return;
}

void spellstone_init(SpellStoneObject* obj)
{
    SpellStoneState* state;

    state = obj->state;
    ObjGroup_AddObject((u32)obj, SPELLSTONE_OBJGROUP);
    state->state = SPELLSTONE_STATE_IDLE;
    obj->callback = spellstone_idleCallback;
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


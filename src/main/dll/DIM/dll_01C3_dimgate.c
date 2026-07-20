/*
 * dimgate (DLL 0x1C3) - mission gate object for Dinosaur Island.
 * Opens (hitbox state 0->2) once sequence object 399 appears in the trigger
 * list, latching a gamebit so the gate stays open on reload.
 */
#include "main/dll/DIM/dll_01C3_dimgate.h"
#include "main/gamebits.h"
#include "main/objhits.h"
#include "main/object_render.h"

#define DIMGATE_TRIGGER_SEQ_ID 399

int dimgate_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate) { return 0x0; }
int dimgate_getExtraSize(void) { return 0x1; }
int dimgate_getObjectTypeId(void) { return 0x0; }

void dimgate_free(void)
{
}

void dimgate_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dimgate_hitDetect(void)
{
}


void dimgate_update(GameObject* obj)
{
    DimgateState* state = obj->extra;
    DimgateSetup* setup = (DimgateSetup*)obj->anim.placementData;
    switch (state->mode)
    {
    case DIMGATE_MODE_CLOSED:
        {
            int found;
            int i;
            if (*(s8*)&((ObjHitsPriorityState*)obj->anim.hitReactState)->stateIndex != DIMGATE_MODE_OPENING)
            {
                ObjHitbox_SetStateIndex(obj, obj->anim.hitReactState, DIMGATE_MODE_OPENING);
            }
            found = 0;
            for (i = 0; i < obj->anim.proximityList->count; i++)
            {
                GameObject* other = obj->anim.proximityList->objects[i];
                if (other->anim.seqId == DIMGATE_TRIGGER_SEQ_ID)
                {
                    found = 1;
                    break;
                }
            }
            if (found)
            {
                mainSetBits(setup->gateGameBit, 1);
                if (*(s8*)&((ObjHitsPriorityState*)obj->anim.hitReactState)->stateIndex != DIMGATE_MODE_OPEN)
                {
                    ObjHitbox_SetStateIndex(obj, obj->anim.hitReactState, DIMGATE_MODE_OPEN);
                }
                state->mode = DIMGATE_MODE_OPEN;
            }
            break;
        }
    case DIMGATE_MODE_OPENING:
        break;
    case DIMGATE_MODE_OPEN:
        {
            if (*(s8*)&((ObjHitsPriorityState*)obj->anim.hitReactState)->stateIndex != DIMGATE_MODE_OPEN)
            {
                ObjHitbox_SetStateIndex(obj, obj->anim.hitReactState, DIMGATE_MODE_OPEN);
            }
            break;
        }
    }
}

void dimgate_init(GameObject *obj, DimgateSetup* unusedSetup)
{
    DimgateState* state;
    DimgateSetup* setup;
    setup = (DimgateSetup*)obj->anim.placementData;
    state = obj->extra;
    if (mainGetBit(setup->gateGameBit) != 0)
    {
        state->mode = DIMGATE_MODE_OPEN;
        obj->anim.currentMoveProgress = 1.0f;
    }
    else
    {
        state->mode = DIMGATE_MODE_CLOSED;
    }
    obj->animEventCallback = dimgate_SeqFn;
    obj->anim.rotX = (s16)(setup->rotX << 8);
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}


void dimgate_release(void)
{
}

void dimgate_initialise(void)
{
}

ObjectDescriptor gDIMGateObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimgate_initialise,
    (ObjectDescriptorCallback)dimgate_release,
    0,
    (ObjectDescriptorCallback)dimgate_init,
    (ObjectDescriptorCallback)dimgate_update,
    (ObjectDescriptorCallback)dimgate_hitDetect,
    (ObjectDescriptorCallback)dimgate_render,
    (ObjectDescriptorCallback)dimgate_free,
    (ObjectDescriptorCallback)dimgate_getObjectTypeId,
    dimgate_getExtraSize,
};

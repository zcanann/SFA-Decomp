/*
 * dimbridgecogmai (DLL 0x1C8) - bridge cog main object for Dinosaur Island
 * Mission 2.  Watches one or more gamebits and, when they become set, either
 * hides the cog or triggers an animation sequence depending on the gamebit
 * value; also fires sequence events from the SeqFn callback.
 */
#include "main/dll/DIM/dll_01C8_dimbridgecogmai.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/object_descriptor.h"
#include "main/obj_group.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/object_render.h"

/* Cog-puzzle gamebits for DIM2 bridge puzzle */
#define COGBIT_PANEL_A     0x17a
#define COGBIT_PANEL_B     0x181
#define COGBIT_BRIDGE      0x1e3
#define COGBIT_SLOT_0      0x182
#define COGBIT_SLOT_1      0x183
#define COGBIT_SLOT_2      0x184

#define DIMBRIDGECOG_GROUP 0xf
#define DIMBRIDGECOG_FLAG_WAIT_FOR_SEQUENCE 0x2

int dimbridgecogmai_SeqFn(GameObject *obj, int unused, ObjAnimUpdateState* animUpdate)
{
    DimbridgecogmaiPlacement* placement = (DimbridgecogmaiPlacement*)obj->anim.placementData;
    animUpdate->sequenceEventActive = 0;
    if ((placement->flags & DIMBRIDGECOG_FLAG_WAIT_FOR_SEQUENCE) != 0 && animUpdate->triggerCommand == 1)
    {
        mainSetBits(placement->doneGameBit, 1);
        animUpdate->triggerCommand = 0;
    }
    return 0;
}

int dimbridgecogmai_getExtraSize(void) { return sizeof(DimbridgecogmaiState); }
int dimbridgecogmai_getObjectTypeId(void) { return 0x0; }

void dimbridgecogmai_free(GameObject* obj) { ObjGroup_RemoveObject((int)obj, DIMBRIDGECOG_GROUP); }

void dimbridgecogmai_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void dimbridgecogmai_hitDetect(void)
{
}

void dimbridgecogmai_update(GameObject* obj)
{
    DimbridgecogmaiPlacement* placement;
    int sequenceId;
    u8 bits;
    int sequenceSlot;

    placement = (DimbridgecogmaiPlacement*)obj->anim.placementData;
    if (mainGetBit(placement->watchGameBit) != 0)
    {
        if (placement->sequenceGate != -1)
        {
            switch (placement->watchGameBit)
            {
            case COGBIT_PANEL_A:
                if (mainGetBit(COGBIT_PANEL_B) != 0)
                {
                    obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED;
                    sequenceId = -1;
                    sequenceSlot = 0;
                }
                else
                {
                    mainSetBits(placement->watchGameBit, 0);
                    sequenceId = 0x1f;
                    sequenceSlot = 1;
                }
                break;
            case COGBIT_BRIDGE:
                bits = mainGetBit(COGBIT_SLOT_0);
                bits |= mainGetBit(COGBIT_SLOT_1) << 1;
                bits |= mainGetBit(COGBIT_SLOT_2) << 2;
                if (bits == 7)
                {
                    obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED;
                    sequenceId = -1;
                    sequenceSlot = 2;
                }
                else
                {
                    mainSetBits(placement->watchGameBit, 0);
                    sequenceId = 0x1d;
                    if ((bits & 4) != 0)
                    {
                        sequenceId |= 2;
                        if ((bits & 2) != 0)
                        {
                            sequenceId |= 0x20;
                        }
                    }
                    sequenceSlot = 1;
                }
                break;
            default:
                sequenceSlot = 0;
                break;
            }
            (*gObjectTriggerInterface)->runSequence(sequenceSlot, (int*)obj, sequenceId);
        }
        if ((placement->flags & DIMBRIDGECOG_FLAG_WAIT_FOR_SEQUENCE) == 0)
        {
            mainSetBits(placement->doneGameBit, 1);
        }
    }
}

void dimbridgecogmai_init(GameObject* obj, DimbridgecogmaiInitDef* def)
{
    DimbridgecogmaiState* state = obj->extra;
    state->unk0 = 100;
    obj->anim.rotX = (s16)((u32)def->rotationAngle << 8);
    obj->animEventCallback = dimbridgecogmai_SeqFn;
    ObjGroup_AddObject((u32)obj, DIMBRIDGECOG_GROUP);
    if ((u8)mainGetBit(def->watchGameBit) != 0)
    {
        obj->objectFlags |= OBJECT_OBJFLAG_UPDATE_DISABLED;
    }
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
}

void dimbridgecogmai_release(void)
{
}

void dimbridgecogmai_initialise(void)
{
}

ObjectDescriptor gDIMBridgeCogMaiObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dimbridgecogmai_initialise,
    (ObjectDescriptorCallback)dimbridgecogmai_release,
    0,
    (ObjectDescriptorCallback)dimbridgecogmai_init,
    (ObjectDescriptorCallback)dimbridgecogmai_update,
    (ObjectDescriptorCallback)dimbridgecogmai_hitDetect,
    (ObjectDescriptorCallback)dimbridgecogmai_render,
    (ObjectDescriptorCallback)dimbridgecogmai_free,
    (ObjectDescriptorCallback)dimbridgecogmai_getObjectTypeId,
    dimbridgecogmai_getExtraSize,
};

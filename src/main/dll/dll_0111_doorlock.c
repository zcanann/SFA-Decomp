/*
 * DLL 0x0111 - door-lock objects [8017AC2C-8017ADB4).
 *
 * A lockable door/gate placed from a DoorLockPlacement. Its
 * lock state mirrors a per-instance game bit (DoorLockPlacement::lockGameBit):
 * when set, the door is hidden (alpha 0) or its hittable flag (userData2) cleared,
 * depending on the placement mode flags at def+0x1B / modeFlags.
 *
 * Lock_DoorLock_update polls trigger conditions (ObjTrigger_IsSet[ById] against the
 * placement's prerequisite bits) and, when satisfied, fires the unlock trigger
 * sequence at def+0x20, sets the lock bit, and disables the A-button prompt.
 * The locked path can yield/preempt a queued sequence (def+0x24) and forwards
 * placement flag bits 0x20/0x40/0x80 as runSequence flags 2/4/8. Lock_DoorLock_SeqFn
 * is the trigger callback: command 1 sets the lock bit (when flag bit 4 is set),
 * command 2 yields the queued sequence. GameBit 0x930 gates a one-shot global
 * unlock sequence.
 */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objprint_render_api.h"
#include "main/obj_group.h"
#include "main/obj_trigger.h"
#include "main/objseq.h"
#include "main/dll/dll_0111_doorlock.h"
#include "main/gamebits.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"
#include "main/pad.h"


#define PAD_BUTTON_A 0x100

/* one-shot global "doors unlocked" game bit gating the bulk unlock sequence */
#define GAMEBIT_DOORLOCK_UNLOCKED 0x930
#define DOORLOCK_OBJGROUP         0xf


int Lock_DoorLock_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    DoorLockPlacement* placement;

    placement = (DoorLockPlacement*)obj->anim.placementData;
    if (animUpdate->triggerCommand != 0)
    {
        if (((placement->flags & 4) != 0) && (animUpdate->triggerCommand == 1))
        {
            mainSetBits(placement->lockGameBit, 1);
        }
        if ((animUpdate->triggerCommand == 2) && (placement->queuedSequenceId != 0))
        {
            (*gObjectTriggerInterface)->yield((ObjSeqState*)animUpdate, placement->queuedSequenceId);
        }
        animUpdate->triggerCommand = 0;
    }
    obj->userData2 = 0;
    return 0;
}

int Lock_DoorLock_getExtraSize(void)
{
    return 0x1;
}

void Lock_DoorLock_free(GameObject* obj)
{
    ObjGroup_RemoveObject((int)obj, DOORLOCK_OBJGROUP);
}

void Lock_DoorLock_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0 || obj->userData2 != 0)
    {
        if (obj->userData2 == 0)
        {
            return;
        }
        objRenderFn_80041018(obj);
        return;
    }
    objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
}

void Lock_DoorLock_update(GameObject* obj)
{
    DoorLockState* state;
    DoorLockPlacement* placement;
    int seqFlags;
    u8 placeFlags;

    state = (DoorLockState*)(obj)->extra;
    placement = (DoorLockPlacement*)obj->anim.placementData;
    if (((*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0) &&
        (mainGetBit(GAMEBIT_DOORLOCK_UNLOCKED) == 0))
    {
        buttonDisable(0, PAD_BUTTON_A);
        (*gObjectTriggerInterface)->setRunSequenceWorldSpace((int)obj, 0);
        (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        mainSetBits(GAMEBIT_DOORLOCK_UNLOCKED, 1);
    }
    else
    {
        state->unlocked = mainGetBit(placement->lockGameBit);
        if ((placement->flags & 1) != 0)
        {
            if (state->unlocked != 0)
            {
                (obj)->anim.alpha = 0;
            }
        }
        else if ((placement->modeFlags & 1) != 0)
        {
            if (state->unlocked != 0)
            {
                (obj)->userData2 = 0;
            }
            else
            {
                (obj)->userData2 = 1;
            }
        }
        if (state->unlocked == 0)
        {
            *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            *(u8*)&(obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
            if ((placement->prereqGameBit1 != -1) &&
                (mainGetBit(placement->prereqGameBit1) == 0))
            {
                *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                if ((placement->flags & 0x10) != 0)
                {
                    *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
            }
            if ((placement->prereqGameBit0 != -1) &&
                (mainGetBit(placement->prereqGameBit0) == 0))
            {
                *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
            }
            if (((placement->prereqGameBit0 != -1) &&
                 (ObjTrigger_IsSetById((int)obj, placement->prereqGameBit0) != 0)) ||
                ((placement->prereqGameBit0 == -1) && (ObjTrigger_IsSet((int)obj) != 0)))
            {
                if (placement->unlockSequenceId != -1)
                {
                    (*gObjectTriggerInterface)
                        ->runSequence((int)placement->unlockSequenceId, (void*)obj, -1);
                }
                if ((placement->flags & 4) == 0)
                {
                    mainSetBits(placement->lockGameBit, 1);
                }
                if ((placement->flags & 8) != 0)
                {
                    mainSetBits(placement->prereqGameBit1, 0);
                }
                else
                {
                    state->unlocked = 1;
                    (obj)->userData1 = 1;
                }
                buttonDisable(0, PAD_BUTTON_A);
            }
        }
        else
        {
            if ((obj)->userData1 == 0)
            {
                if ((placement->unlockSequenceId != -1) &&
                    (placement->queuedSequenceId != 0))
                {
                    (*gObjectTriggerInterface)->preempt((int)obj, placement->queuedSequenceId);
                    seqFlags = 1;
                    placeFlags = placement->flags;
                    if ((placeFlags & 0x20) != 0)
                    {
                        seqFlags |= 2;
                    }
                    if ((placeFlags & 0x40) != 0)
                    {
                        seqFlags |= 4;
                    }
                    if ((placeFlags & 0x80) != 0)
                    {
                        seqFlags |= 8;
                    }
                    (*gObjectTriggerInterface)
                        ->runSequence((int)placement->unlockSequenceId, (void*)obj, seqFlags);
                }
                (obj)->userData1 = 1;
            }
            *(u8*)&(obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        if (((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0) &&
            (((ObjAnimComponent*)obj)->hitVolumeTransforms != NULL))
        {
            objRenderFn_80041018((GameObject*)obj);
        }
    }
}

void Lock_DoorLock_init(GameObject* obj, DoorLockPlacement* placement)
{
    ObjAnimComponent* objAnim;
    DoorLockState* state;

    objAnim = &obj->anim;
    obj->anim.rotX = (short)((u8)placement->rotXByte << 8);
    obj->anim.rotY = (short)(placement->rotYByte << 8);
    obj->anim.rotZ = (short)(placement->rotZByte << 8);
    obj->animEventCallback = Lock_DoorLock_SeqFn;
    *(u8*)&objAnim->bankIndex = placement->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    state = obj->extra;
    state->unlocked = mainGetBit(placement->lockGameBit);
    ObjGroup_AddObject((int)obj, DOORLOCK_OBJGROUP);
    if ((placement->flags & 1) != 0)
    {
        if (state->unlocked != 0)
        {
            objAnim->alpha = 0;
        }
    }
    else if ((placement->modeFlags & 1) != 0)
    {
        if (state->unlocked != 0)
        {
            obj->userData2 = 0;
        }
        else
        {
            obj->userData2 = 1;
        }
    }
}

ObjectDescriptor gDoorLockObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0, 0, 0,
    (ObjectDescriptorCallback)Lock_DoorLock_init,
    (ObjectDescriptorCallback)Lock_DoorLock_update,
    0,
    (ObjectDescriptorCallback)Lock_DoorLock_render,
    (ObjectDescriptorCallback)Lock_DoorLock_free,
    0,
    Lock_DoorLock_getExtraSize,
};

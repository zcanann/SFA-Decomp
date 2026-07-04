/*
 * DLL 0x0111 - door-lock objects [8017AC2C-8017ADB4).
 *
 * A lockable door/gate placed from a DoorLockPlacement (alphaanim.h). Its
 * lock state mirrors a per-instance game bit (DoorLockPlacement::lockGameBit):
 * when set, the door is hidden (alpha 0) or its hittable flag (unkF8) cleared,
 * depending on the placement mode flags at def+0x1B / modeFlags.
 *
 * doorlock_update polls trigger conditions (ObjTrigger_IsSet[ById] against the
 * placement's prerequisite bits) and, when satisfied, fires the unlock trigger
 * sequence at def+0x20, sets the lock bit, and disables the A-button prompt.
 * The locked path can yield/preempt a queued sequence (def+0x24) and forwards
 * placement flag bits 0x20/0x40/0x80 as runSequence flags 2/4/8. Lock_DoorLock_SeqFn
 * is the trigger callback: command 1 sets the lock bit (when flag bit 4 is set),
 * command 2 yields the queued sequence. GameBit 0x930 gates a one-shot global
 * unlock sequence.
 */
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/dll/doorlockstate_struct.h"
#include "main/dll/alphaanim.h"
#include "main/gamebits.h"
#include "main/sfa_shared_decls.h"

#define PAD_BUTTON_A 0x100

/* placement view used for the def+0xNN byte/halfword derefs in this TU */
typedef struct DoorlockPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    u8 unk1A;              /* 0x1A */
    u8 modeBits;           /* 0x1B: mode flag bits (1,4,8,0x10,0x20,0x40,0x80) */
    s16 lockGameBit;       /* 0x1C */
    s16 prereqGameBit0;    /* 0x1E: prerequisite game bit */
    s8 unlockSequenceId;   /* 0x20: unlock sequence id (signed) */
    u8 pad21[0x22 - 0x21];
    s16 prereqGameBit1;    /* 0x22: prerequisite game bit */
    s16 queuedSequenceId;  /* 0x24: queued sequence id */
    s16 modeFlags;         /* 0x26: mode flags */
} DoorlockPlacement;

/* one-shot global "doors unlocked" game bit gating the bulk unlock sequence */
#define GAMEBIT_DOORLOCK_UNLOCKED 0x930
#define DOORLOCK_OBJGROUP 0xf

extern void ObjGroup_RemoveObject(u32 obj, int group);
extern void ObjGroup_AddObject(u32 obj, int group);
extern void objRenderFn_8003b8f4(int* obj, int p2, int p3, int p4, int p5, f32 scale);
extern void objRenderFn_80041018(int obj);
extern f32 lbl_803E3798;
extern int ObjTrigger_IsSetById(int obj, int id);
extern int ObjTrigger_IsSet(int obj);


int doorlock_getExtraSize(void) { return 0x1; }

void doorlock_free(int x) { ObjGroup_RemoveObject(x, DOORLOCK_OBJGROUP); }

void doorlock_render(int* obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        if (((GameObject*)obj)->unkF8 == 0)
        {
            goto render_basic;
        }
    }
    if (((GameObject*)obj)->unkF8 == 0)
    {
        return;
    }
    objRenderFn_80041018((int)obj);
    return;

render_basic:
    objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E3798);
}

int Lock_DoorLock_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int def;

    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (animUpdate->triggerCommand != 0)
    {
        if (((((DoorlockPlacement*)def)->modeBits & 4) != 0) && (animUpdate->triggerCommand == 1))
        {
            GameBit_Set(((DoorlockPlacement*)def)->lockGameBit, 1);
        }
        if ((animUpdate->triggerCommand == 2) && (((DoorlockPlacement*)def)->queuedSequenceId != 0))
        {
            (*gObjectTriggerInterface)->yield((ObjSeqState*)animUpdate, ((DoorlockPlacement*)def)->queuedSequenceId);
        }
        animUpdate->triggerCommand = 0;
    }
    ((GameObject*)obj)->unkF8 = 0;
    return 0;
}

void doorlock_update(int obj)
{
    DoorLockState* state;
    int def;
    int seqFlags;
    u8 placeFlags;

    state = (DoorLockState*)((GameObject*)obj)->extra;
    def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_IN_RANGE) != 0) && (GameBit_Get(GAMEBIT_DOORLOCK_UNLOCKED) == 0))
    {
        buttonDisable(0, PAD_BUTTON_A);
        (*gObjectTriggerInterface)->setRunSequenceWorldSpace(obj, 0);
        (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
        GameBit_Set(GAMEBIT_DOORLOCK_UNLOCKED, 1);
    }
    else
    {
        state->unlocked = GameBit_Get(((DoorlockPlacement*)def)->lockGameBit);
        if ((((DoorlockPlacement*)def)->modeBits & 1) != 0)
        {
            if (state->unlocked != 0)
            {
                ((GameObject*)obj)->anim.alpha = 0;
            }
        }
        else if ((((DoorlockPlacement*)def)->modeFlags & 1) != 0)
        {
            if (state->unlocked != 0)
            {
                ((GameObject*)obj)->unkF8 = 0;
            }
            else
            {
                ((GameObject*)obj)->unkF8 = 1;
            }
        }
        if (state->unlocked == 0)
        {
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
            if ((((DoorlockPlacement*)def)->prereqGameBit1 != -1) && (GameBit_Get(((DoorlockPlacement*)def)->prereqGameBit1) == 0))
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
                if ((((DoorlockPlacement*)def)->modeBits & 0x10) != 0)
                {
                    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
                }
            }
            if ((((DoorlockPlacement*)def)->prereqGameBit0 != -1) && (GameBit_Get(((DoorlockPlacement*)def)->prereqGameBit0) == 0))
            {
                *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
            }
            if (((((DoorlockPlacement*)def)->prereqGameBit0 != -1) && (ObjTrigger_IsSetById(
                    obj, ((DoorlockPlacement*)def)->prereqGameBit0) != 0)) ||
                ((((DoorlockPlacement*)def)->prereqGameBit0 == -1) && (ObjTrigger_IsSet(obj) != 0)))
            {
                if (((DoorlockPlacement*)def)->unlockSequenceId != -1)
                {
                    (*gObjectTriggerInterface)->runSequence((int)((DoorlockPlacement*)def)->unlockSequenceId, (void*)obj, -1);
                }
                if ((((DoorlockPlacement*)def)->modeBits & 4) == 0)
                {
                    GameBit_Set(((DoorlockPlacement*)def)->lockGameBit, 1);
                }
                if ((((DoorlockPlacement*)def)->modeBits & 8) != 0)
                {
                    GameBit_Set(((DoorlockPlacement*)def)->prereqGameBit1, 0);
                }
                else
                {
                    state->unlocked = 1;
                    ((GameObject*)obj)->unkF4 = 1;
                }
                buttonDisable(0, PAD_BUTTON_A);
            }
        }
        else
        {
            if (((GameObject*)obj)->unkF4 == 0)
            {
                if ((((DoorlockPlacement*)def)->unlockSequenceId != -1) && (((DoorlockPlacement*)def)->queuedSequenceId != 0))
                {
                    (*gObjectTriggerInterface)->preempt(obj, ((DoorlockPlacement*)def)->queuedSequenceId);
                    seqFlags = 1;
                    placeFlags = ((DoorlockPlacement*)def)->modeBits;
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
                    (*gObjectTriggerInterface)->runSequence((int)((DoorlockPlacement*)def)->unlockSequenceId, (void*)obj, seqFlags);
                }
                ((GameObject*)obj)->unkF4 = 1;
            }
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
        }
        if (((((ObjAnimComponent*)obj)->modelInstance->flags & 1) != 0) &&
            (((ObjAnimComponent*)obj)->hitVolumeTransforms != NULL))
        {
            objRenderFn_80041018(obj);
        }
    }
}

void doorlock_init(short* obj, DoorLockPlacement* config)
{
    ObjAnimComponent* objAnim;
    DoorLockState* state;

    objAnim = (ObjAnimComponent*)obj;
    *obj = (short)((u8)config->rotXByte << 8);
    ((GameObject*)obj)->anim.rotY = (short)(config->rotYByte << 8);
    ((GameObject*)obj)->anim.rotZ = (short)(config->rotZByte << 8);
    ((GameObject*)obj)->animEventCallback = Lock_DoorLock_SeqFn;
    *(u8*)&objAnim->bankIndex = config->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    state = ((GameObject*)obj)->extra;
    state->unlocked = GameBit_Get(config->lockGameBit);
    ObjGroup_AddObject((u32)obj, DOORLOCK_OBJGROUP);
    if ((config->flags & 1) != 0)
    {
        if (state->unlocked != 0)
        {
            objAnim->alpha = 0;
        }
    }
    else if ((config->modeFlags & 1) != 0)
    {
        if (state->unlocked != 0)
        {
            ((GameObject*)obj)->unkF8 = 0;
        }
        else
        {
            ((GameObject*)obj)->unkF8 = 1;
        }
    }
}

/*
 * seqobj2 (DLL 0x113) - sequence-triggered placed objects.
 *
 * Hosts three closely-related object behaviours that all drive scripted
 * trigger sequences off game bits:
 *   - seqObject_*  : a generic open/trigger object. Watches openGameBit and
 *     triggerGameBit; on a rising trigger edge it runs the placement's
 *     trigger sequence, then optionally sets/clears bits per the placement
 *     flag byte. State is the SeqObjectState bitfield (SEQOBJECT_STATE_*).
 *   - seqObj2_*    : the SeqObj2 variant (single-byte SeqObj2State), gated on
 *     trigger/open game bits with the same SEQOBJECT_FLAG_* placement flags.
 *   - seqobj2_*    : the SeqObj2 object exported via gSeqObj2ObjDescriptor;
 *     SeqObj2_seqFn handles in-sequence events (op 0 clears the trigger bit,
 *     op 1 sets the open bit) and OSReports the bit usage for debugging.
 *
 * Game bits used here are per-placement (openGameBit/triggerGameBit), not
 * hardcoded; -1 is the "no bit" sentinel.
 */
#include "main/dll/IM/dll_0114_immultiseq.h"
#include "main/dll/dll_0111_doorlock.h"
#include "main/dll/dll_0112_seqobject.h"
#include "main/dll/dll_0113_seqobj2.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/objlib.h"
#include "main/objprint.h"
#include "main/gamebits.h"
#include "main/object_descriptor.h"
#include "dolphin/os.h"

STATIC_ASSERT(sizeof(DoorLockPlacement) == 0x28);
STATIC_ASSERT(offsetof(DoorLockPlacement, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(DoorLockPlacement, rotYByte) == 0x19);
STATIC_ASSERT(offsetof(DoorLockPlacement, rotZByte) == 0x1A);
STATIC_ASSERT(offsetof(DoorLockPlacement, flags) == 0x1B);
STATIC_ASSERT(offsetof(DoorLockPlacement, lockGameBit) == 0x1C);
STATIC_ASSERT(offsetof(DoorLockPlacement, modelBankIndex) == 0x21);
STATIC_ASSERT(offsetof(DoorLockPlacement, modeFlags) == 0x26);
STATIC_ASSERT(sizeof(DoorLockState) == 0x1);
STATIC_ASSERT(sizeof(SeqObjectPlacement) == 0x28);
STATIC_ASSERT(offsetof(SeqObjectPlacement, openGameBit) == 0x18);
STATIC_ASSERT(offsetof(SeqObjectPlacement, triggerGameBit) == 0x1A);
STATIC_ASSERT(offsetof(SeqObjectPlacement, initialYaw) == 0x1C);
STATIC_ASSERT(offsetof(SeqObjectPlacement, flags) == 0x1D);
STATIC_ASSERT(offsetof(SeqObjectPlacement, triggerId) == 0x1E);
STATIC_ASSERT(offsetof(SeqObjectPlacement, modelBankIndex) == 0x1F);
STATIC_ASSERT(offsetof(SeqObjectPlacement, preemptSequenceId) == 0x20);
STATIC_ASSERT(offsetof(SeqObjectPlacement, sequenceParam) == 0x22);
STATIC_ASSERT(offsetof(SeqObjectPlacement, warpMapId) == 0x24);
STATIC_ASSERT(sizeof(IMMultiSeqPlacement) == 0x34);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, completionGameBits) == 0x18);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, activeGameBits) == 0x20);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, initialYaw) == 0x28);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, modelBankIndex) == 0x2A);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, triggerIds) == 0x2C);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, polarityMask) == 0x30);
STATIC_ASSERT(sizeof(SeqObjectState) == 0x3);
STATIC_ASSERT(offsetof(SeqObjectState, triggerBitState) == 0x1);
STATIC_ASSERT(sizeof(SeqObj2State) == 0x1);
STATIC_ASSERT(sizeof(IMMultiSeqState) == 0x2);

/* object group this object joins while active */
#define SEQOBJ2_OBJGROUP 0xf

#define SEQOBJECT_STATE_OPEN             0x01
#define SEQOBJECT_STATE_TRIGGER_SEQUENCE 0x02
#define SEQOBJECT_STATE_SEQUENCE_DONE    0x04

#define SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR     0x01
#define SEQOBJECT_FLAG_SET_SOURCE_ON_SEQUENCE 0x02
#define SEQOBJECT_FLAG_CLEAR_TARGET_ON_DONE   0x04
#define SEQOBJECT_FLAG_SET_SOURCE_ON_DONE     0x08
#define SEQOBJECT_FLAG_USE_TRIGGER_PARAM      0x10
#define SEQOBJECT_FLAG_UNUSED_20              0x20

#define SEQOBJECT_OBJFLAG_HIDDEN             0x4000
#define SEQOBJECT_OBJFLAG_HITDETECT_DISABLED 0x2000

extern const char sSeqObjNeedBitUsedBitFormat[];
extern const char sSeqObjNeedBitClearDuringSequenceFormat[];
extern const char lbl_80321208[];

#include "main/dll/dll_0115_dll115.h"

int SeqObj2_seqFn(int* obj, int* anim, ObjAnimUpdateState* animUpdate)
{
    SeqObjectPlacement* def = (SeqObjectPlacement*)((GameObject*)obj)->anim.placementData;
    SeqObj2State* state = ((GameObject*)obj)->extra;
    int i;
    enum
    {
        SEQOBJ2_SEQEV_CLEAR_TRIGGER = 0,
        SEQOBJ2_SEQEV_SET_OPEN = 1
    };
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        int op = animUpdate->eventIds[i];
        switch (op)
        {
        case SEQOBJ2_SEQEV_CLEAR_TRIGGER:
            mainSetBits(def->triggerGameBit, 0);
            OSReport(sSeqObjNeedBitClearDuringSequenceFormat, def->base.mapId);
            break;
        case SEQOBJ2_SEQEV_SET_OPEN:
            mainSetBits(def->openGameBit, 1);
            OSReport(lbl_80321208, def->base.mapId);
            break;
        }
    }
    state->flags = (u8)(state->flags | SEQOBJECT_STATE_TRIGGER_SEQUENCE);
    return 0;
}

int SeqObj2_getExtraSize(void)
{
    return 0x1;
}
int SeqObj2_getObjectTypeId(void)
{
    return 0x0;
}

void SeqObj2_free(int obj)
{
    ObjGroup_RemoveObject(obj, SEQOBJ2_OBJGROUP);
}

void SeqObj2_render(void)
{
}

void SeqObj2_hitDetect(void)
{
}

void SeqObj2_update(int* obj)
{
    SeqObj2State* state;
    SeqObjectPlacement* def;
    char* strBase;
    u32 bitValue;

    strBase = (char*)&gSeqObj2ObjDescriptor;
    state = ((GameObject*)obj)->extra;
    def = (SeqObjectPlacement*)((GameObject*)obj)->anim.placementData;

    if ((state->flags & SEQOBJECT_STATE_OPEN) != 0)
    {
        if ((def->flags & SEQOBJECT_FLAG_LATCH_SOURCE_CLEAR) != 0)
        {
            mainSetBits(def->triggerGameBit, 0);
            OSReport(strBase + 0x94, def->base.mapId);
        }
        if ((def->flags & SEQOBJECT_FLAG_SET_SOURCE_ON_DONE) != 0)
        {
            mainSetBits(def->openGameBit, 1);
            OSReport(strBase + 0xd0, def->base.mapId);
        }
        OSReport(strBase + 0x108, def->base.mapId, def->sequenceParam);
        (*gObjectTriggerInterface)->preempt((int)obj, def->preemptSequenceId);
        bitValue = def->sequenceParam;
        (*gObjectTriggerInterface)->runSequence(def->triggerId, obj, bitValue);
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_OPEN);
    }
    else if ((state->flags & SEQOBJECT_STATE_TRIGGER_SEQUENCE) != 0)
    {
        if ((def->flags & SEQOBJECT_FLAG_SET_SOURCE_ON_SEQUENCE) != 0)
        {
            mainSetBits(def->triggerGameBit, 0);
            OSReport(strBase + 0x140, def->base.mapId);
        }
        if ((def->flags & SEQOBJECT_FLAG_USE_TRIGGER_PARAM) != 0)
        {
            mainSetBits(def->openGameBit, 1);
            OSReport(strBase + 0x170, def->base.mapId);
        }
        state->flags = (u8)(state->flags & ~SEQOBJECT_STATE_TRIGGER_SEQUENCE);
    }
    else
    {
        if ((def->triggerGameBit == -1 || mainGetBit(def->triggerGameBit) != 0) &&
            (def->openGameBit == -1 || mainGetBit(def->openGameBit) == 0))
        {
            if ((def->flags & SEQOBJECT_FLAG_CLEAR_TARGET_ON_DONE) != 0)
            {
                mainSetBits(def->triggerGameBit, 0);
                OSReport(strBase + 0x19c, def->base.mapId);
            }
            if ((def->flags & SEQOBJECT_FLAG_UNUSED_20) != 0)
            {
                mainSetBits(def->openGameBit, 1);
                OSReport(strBase + 0x1cc, def->base.mapId);
            }
            OSReport(strBase + 0x1f8, def->base.mapId);
            (*gObjectTriggerInterface)->runSequence(def->triggerId, obj, -1);
        }
    }
}

void SeqObj2_init(int* obj, SeqObjectPlacement* def)
{
    SeqObj2State* state = ((GameObject*)obj)->extra;
    OSReport(sSeqObjNeedBitUsedBitFormat, def->base.mapId, def->triggerGameBit, def->openGameBit);
    ((GameObject*)obj)->anim.rotX = (s16)((u32)def->initialYaw << 8);
    ((GameObject*)obj)->animEventCallback = SeqObj2_seqFn;
    if (def->preemptSequenceId > -1)
    {
        s16 slot = def->openGameBit;
        if (slot != -1 && mainGetBit(slot) != 0u)
        {
            state->flags = (u8)(state->flags | SEQOBJECT_STATE_OPEN);
        }
    }
    ObjGroup_AddObject((u32)obj, SEQOBJ2_OBJGROUP);
    ((GameObject*)obj)->objectFlags =
        (u16)(((GameObject*)obj)->objectFlags | (SEQOBJECT_OBJFLAG_HIDDEN | SEQOBJECT_OBJFLAG_HITDETECT_DISABLED));
}

void SeqObj2_release(void)
{
}

void SeqObj2_initialise(void)
{
}

ObjectDescriptor gSeqObj2ObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    SeqObj2_initialise,
    SeqObj2_release,
    0,
    (ObjectDescriptorCallback)SeqObj2_init,
    (ObjectDescriptorCallback)SeqObj2_update,
    SeqObj2_hitDetect,
    SeqObj2_render,
    (ObjectDescriptorCallback)SeqObj2_free,
    (ObjectDescriptorCallback)SeqObj2_getObjectTypeId,
    SeqObj2_getExtraSize,
};

const char sSeqObjNeedBitClearDuringSequenceFormat[] = "newseqobj %d: need bit clear during sequence\n";

const char lbl_80321208[444] =
    "newseqobj %d: used bit set during sequence\n\000newseqobj %d: need bit clear before preempting "
    "sequence\n\000\000\000\000newseqobj %d: used bit set before preempting sequence\n\000\000newseqobj %d: about to "
    "prempt the sequence - objs %d\n\000\000\000newseqobj %d: need bit clear after sequence\n\000\000\000\000newseqobj "
    "%d: used bit set after sequence\n\000\000newseqobj %d: need bit clear before sequence\n\000\000\000newseqobj %d: "
    "used bit set before sequence\n\000newseqobj %d: about to start the sequence\n\000\000";
const char sSeqObjNeedBitUsedBitFormat[40] = "newseqobj %d: Need Bit %d, Used Bit %d\n\000";

/* descriptor/ptr table auto 0x803213f0-0x80321460; 8-aligned union places it at
 * 0x803213F0 after the 4-byte retail pad gap_07_803213EC_data (dll_013F idiom) */
IMMultiSeqDescriptorAlign8 gIMMultiSeqObjDescriptor = {{
    0x00000000,
    0x00000000,
    0x00000000,
    0x00090000,
    (ObjectDescriptorCallback)IMMultiSeq_initialise,
    (ObjectDescriptorCallback)IMMultiSeq_release,
    0x00000000,
    (ObjectDescriptorCallback)IMMultiSeq_init,
    (ObjectDescriptorCallback)IMMultiSeq_update,
    (ObjectDescriptorCallback)IMMultiSeq_hitDetect,
    (ObjectDescriptorCallback)IMMultiSeq_render,
    (ObjectDescriptorCallback)IMMultiSeq_free,
    (ObjectDescriptorCallback)IMMultiSeq_getObjectTypeId,
    IMMultiSeq_getExtraSize,
}};
u32 lbl_80321428[14] = {0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00090000,
                        (u32)dll_115_initialise_nop,
                        (u32)dll_115_release_nop,
                        0x00000000,
                        (u32)dll_115_init,
                        (u32)dll_115_update,
                        (u32)dll_115_hitDetect_nop,
                        (u32)dll_115_render,
                        (u32)dll_115_free,
                        (u32)dll_115_getObjectTypeId,
                        (u32)dll_115_getExtraSize_ret_2};

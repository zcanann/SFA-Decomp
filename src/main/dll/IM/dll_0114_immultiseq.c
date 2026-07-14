/*
 * immultiseq (DLL 0x114) - a multi-sequence controller on the Ice
 * Mountain map. It walks a small step counter (0..4) through up to four
 * scripted sequences, each gated by a pair of game bits in the
 * placement: activeGameBits[] decides whether the step's trigger
 * sequence should run, and completionGameBits[] records that a step has
 * finished. The placement's polarityMask carries the expected bit
 * polarity for each step - the low nibble for the active test, the high
 * nibble (bits 4..7) for the completion test - so a step both advances
 * (when its completion bit flips) and rewinds (when an earlier
 * completion bit clears).
 */
#include "main/dll/IM/dll_0114_immultiseq.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/obj_group.h"
#include "main/object_render_legacy.h"

#pragma force_active on
#pragma explicit_zero_data on
__declspec(section ".sdata2") f32 lbl_803E37A8 = 1.0f;
__declspec(section ".sdata2") f32 lbl_803E37AC = 0.0f;
#pragma explicit_zero_data off
#pragma force_active reset

STATIC_ASSERT(sizeof(IMMultiSeqState) == 0x2);
STATIC_ASSERT(sizeof(IMMultiSeqPlacement) == 0x34);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, completionGameBits) == 0x18);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, activeGameBits) == 0x20);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, initialYaw) == 0x28);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, modelBankIndex) == 0x2A);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, triggerIds) == 0x2C);
STATIC_ASSERT(offsetof(IMMultiSeqPlacement, polarityMask) == 0x30);

#define IMMULTISEQ_OBJGROUP 0xf

/* state->flags: SeqFn latched a step advance for update() to consume */
#define IMMULTISEQ_LATCH_ADVANCE_BIT 0x01

#define IMMULTISEQ_OBJFLAG_HIDDEN             0x4000
#define IMMULTISEQ_OBJFLAG_HITDETECT_DISABLED 0x2000

extern f32 lbl_803E37A8;

/* IMMultiSeq_SeqFn: end-of-sequence predicate. With a valid trigger id,
   peek at the next step's active game bit; if its polarity has flipped
   (GameBit != the polarityMask bit for that step) end the current
   sequence. Always latches the advance bit before returning. */
int IMMultiSeq_SeqFn(int* obj, int* anim, ObjAnimUpdateState* animUpdate)
{
    IMMultiSeqState* state = ((GameObject*)obj)->extra;
    IMMultiSeqPlacement* def = *(IMMultiSeqPlacement**)&((GameObject*)obj)->anim.placementData;
    animUpdate->hitVolumePair = animUpdate->activeHitVolumePair;
    animUpdate->sequenceEventActive = 0;
    if (((GameObject*)obj)->seqIndex == -1)
    {
        return 0;
    }
    {
        int step = state->step;
        if (step != 4)
        {
            int next = step + 1;
            if ((s32)next < 4)
            {
                s16 gbit = def->activeGameBits[next];
                if (gbit != -1)
                {
                    int bitValue = mainGetBit(gbit);
                    int expected = !((def->polarityMask >> next) & 1);
                    if ((u32)expected == bitValue)
                    {
                        (*gObjectTriggerInterface)->endSequence(((GameObject*)obj)->seqIndex);
                    }
                }
            }
        }
    }
    state->flags = (u8)(state->flags | IMMULTISEQ_LATCH_ADVANCE_BIT);
    return 0;
}

int IMMultiSeq_getExtraSize(void)
{
    return 0x2;
}
int IMMultiSeq_getObjectTypeId(void)
{
    return 0x0;
}

void IMMultiSeq_free(int obj)
{
    ObjGroup_RemoveObject(obj, IMMULTISEQ_OBJGROUP);
}

void IMMultiSeq_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E37A8);
}

void IMMultiSeq_hitDetect(void)
{
}

void IMMultiSeq_update(int* obj)
{
    IMMultiSeqState* state;
    IMMultiSeqPlacement* def;
    u8 step;
    int prevStep;
    s16 bitId;

    state = ((GameObject*)obj)->extra;
    def = *(IMMultiSeqPlacement**)&((GameObject*)obj)->anim.placementData;

    if ((state->flags & IMMULTISEQ_LATCH_ADVANCE_BIT) != 0)
    {
        step = state->step;
        bitId = def->completionGameBits[step];
        mainSetBits(bitId, !((def->polarityMask >> (step + 4)) & 1));
        state->flags = (u8)(state->flags & ~IMMULTISEQ_LATCH_ADVANCE_BIT);
        state->step++;
    }

    if ((int)state->step != 4)
    {
        u8 st = state->step;
        bitId = def->activeGameBits[st];
        if (bitId == -1)
        {
            state->step = 4;
        }
        else if ((u32) !((def->polarityMask >> state->step) & 1) == mainGetBit(bitId))
        {
            s8 triggerId = def->triggerIds[state->step];
            if (triggerId != -1)
            {
                (*gObjectTriggerInterface)->runSequence(triggerId, obj, -1);
            }
        }
    }

    prevStep = state->step - 1;
    while (prevStep >= 0)
    {
        bitId = def->completionGameBits[prevStep];
        if (bitId == -1)
        {
            break;
        }
        if (((def->polarityMask >> (prevStep + 4)) & 1) != mainGetBit(bitId))
        {
            break;
        }
        state->step--;
        prevStep--;
    }
}

void IMMultiSeq_init(int* obj, IMMultiSeqPlacement* params)
{
    ObjAnimComponent* objAnim;
    IMMultiSeqState* state;
    int i;

    objAnim = (ObjAnimComponent*)obj;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)(params->initialYaw << 8);
    ((GameObject*)obj)->animEventCallback = IMMultiSeq_SeqFn;
    ((GameObject*)obj)->objectFlags =
        (u16)(((GameObject*)obj)->objectFlags | (IMMULTISEQ_OBJFLAG_HIDDEN | IMMULTISEQ_OBJFLAG_HITDETECT_DISABLED));
    objAnim->bankIndex = params->modelBankIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ObjGroup_AddObject((int)obj, IMMULTISEQ_OBJGROUP);
    i = 0;
    while (i < 4)
    {
        if ((u32)((params->polarityMask >> (i + 4)) & 1) == mainGetBit(params->completionGameBits[i]))
        {
            break;
        }
        i++;
    }
    state->step = i;
}

void IMMultiSeq_release(void)
{
}

void IMMultiSeq_initialise(void)
{
}

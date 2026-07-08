/*
 * vfpladders (DLL 0x21C, VFP_Ladders) - a retractable ladder / climbable
 * prop in the Volcano Force Point Temple.
 *
 * Two behaviours, selected by the object's seq id:
 *  - the trigger variant (seq 0x548) plays raise (sequence 0) / lower
 *    (sequence 1) animations driven by the trigger vs base game bits;
 *  - the sliding variant waits for its trigger bit, then after a short
 *    delay drops from its placed height down by a fixed offset (with a
 *    buzzing sfx) and latches at the bottom.
 */
#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/VF/dll_021C_vfpladders.h"

#define VFPLADDERS_TRIGGER_SEQID 0x548
#define VFPLADDERS_DROP_DELAY    0x5a /* frames between trigger and drop */

#define VFPLADDERS_OBJFLAG_HIDDEN             0x4000
#define VFPLADDERS_OBJFLAG_HITDETECT_DISABLED 0x2000

enum
{
    VFPLADDERS_PHASE_WAIT = 0,
    VFPLADDERS_PHASE_DROPPING = 1,
    VFPLADDERS_PHASE_SETTLED = 2
};

int vfpladders_SeqFn(void)
{
    return 0x0;
}

int VFP_Ladders_getExtraSize(void)
{
    return 0x8;
}

int VFP_Ladders_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_Ladders_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void VFP_Ladders_render(void)
{
}

void VFP_Ladders_hitDetect(void)
{
}

void VFP_Ladders_update(int obj)
{
    VfpLaddersState* state;
    VfpLaddersSetup* setup;

    setup = (VfpLaddersSetup*)((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;

    if (((GameObject*)obj)->anim.seqId == VFPLADDERS_TRIGGER_SEQID)
    {
        if ((u32)mainGetBit(state->triggerGameBit) != 0)
        {
            if ((u32)mainGetBit(state->baseGameBit) == 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            }
        }
        if ((u32)mainGetBit(state->triggerGameBit) == 0)
        {
            if ((u32)mainGetBit(state->baseGameBit) != 0)
            {
                (*gObjectTriggerInterface)->runSequence(1, (void*)obj, -1);
            }
        }
    }
    else
    {
        if (state->delayTimer != 0)
        {
            state->delayTimer -= (s16)timeDelta;
            if (state->delayTimer <= 0)
            {
                state->phase = VFPLADDERS_PHASE_DROPPING;
                Sfx_PlayFromObject(obj, SFXTRIG_mv_bodyf4_c);
                state->delayTimer = 0;
            }
        }
        else
        {
            if (state->phase == VFPLADDERS_PHASE_WAIT && mainGetBit(state->triggerGameBit) != 0)
            {
                state->delayTimer = VFPLADDERS_DROP_DELAY;
            }
            if (state->phase == VFPLADDERS_PHASE_DROPPING && ((GameObject*)obj)->anim.localPosY > setup->baseY - 150.0f)
            {
                ((GameObject*)obj)->anim.localPosY = ((GameObject*)obj)->anim.localPosY - 2.0f * timeDelta;
                if (((GameObject*)obj)->anim.localPosY < setup->baseY - 150.0f)
                {
                    ((GameObject*)obj)->anim.localPosY = setup->baseY - 150.0f;
                    state->phase = VFPLADDERS_PHASE_SETTLED;
                }
            }
        }
    }
}

void VFP_Ladders_init(int* obj, u8* init)
{
    VfpLaddersState* state = ((GameObject*)obj)->extra;
    VfpLaddersSetup* setup = (VfpLaddersSetup*)init;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)init[0x18] << 8);
    state->triggerGameBit = setup->triggerGameBit;
    state->baseGameBit = setup->baseGameBit;
    ((GameObject*)obj)->objectFlags |= (VFPLADDERS_OBJFLAG_HIDDEN | VFPLADDERS_OBJFLAG_HITDETECT_DISABLED);
    ((GameObject*)obj)->animEventCallback = vfpladders_SeqFn;
}

void VFP_Ladders_release(void)
{
}

void VFP_Ladders_initialise(void)
{
}

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
#include "main/frame_timing.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/objseq.h"
#include "main/dll/expgfx_interface.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/dll/VF/dll_021C_vfpladders.h"

#define VFPLADDERS_TRIGGER_SEQID 0x548
#define VFPLADDERS_DROP_DELAY    0x5a /* frames between trigger and drop */

enum
{
    VFPLADDERS_PHASE_WAIT = 0,
    VFPLADDERS_PHASE_DROPPING = 1,
    VFPLADDERS_PHASE_SETTLED = 2
};

int vfpladders_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    return 0x0;
}

int VFP_Ladders_getExtraSize(void)
{
    return sizeof(VfpLaddersState);
}

int VFP_Ladders_getObjectTypeId(void)
{
    return 0x0;
}

void VFP_Ladders_free(GameObject* obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void VFP_Ladders_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible)
{
}

void VFP_Ladders_hitDetect(GameObject* obj)
{
}

void VFP_Ladders_update(GameObject* obj)
{
    VfpLaddersState* state;
    VfpLaddersSetup* setup;

    setup = (VfpLaddersSetup*)(obj)->anim.placementData;
    state = (obj)->extra;

    if ((obj)->anim.seqId == VFPLADDERS_TRIGGER_SEQID)
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
                Sfx_PlayFromObject((int)obj, SFXTRIG_mv_bodyf4_c);
                state->delayTimer = 0;
            }
        }
        else
        {
            if (state->phase == VFPLADDERS_PHASE_WAIT && mainGetBit(state->triggerGameBit) != 0)
            {
                state->delayTimer = VFPLADDERS_DROP_DELAY;
            }
            if (state->phase == VFPLADDERS_PHASE_DROPPING && obj->anim.localPosY > setup->base.posY - 150.0f)
            {
                obj->anim.localPosY = obj->anim.localPosY - 2.0f * timeDelta;
                if (obj->anim.localPosY < setup->base.posY - 150.0f)
                {
                    obj->anim.localPosY = setup->base.posY - 150.0f;
                    state->phase = VFPLADDERS_PHASE_SETTLED;
                }
            }
        }
    }
}

void VFP_Ladders_init(GameObject* obj, VfpLaddersSetup* setup)
{
    VfpLaddersState* state = obj->extra;
    obj->anim.rotX = (s16)(setup->rotX << 8);
    state->triggerGameBit = setup->triggerGameBit;
    state->baseGameBit = setup->baseGameBit;
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    obj->animEventCallback = vfpladders_SeqFn;
}

void VFP_Ladders_release(void)
{
}

void VFP_Ladders_initialise(void)
{
}

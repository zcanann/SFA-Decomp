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

#define VFPLADDERS_TRIGGER_SEQID 0x548
#define VFPLADDERS_DROP_DELAY 0x5a /* frames between trigger and drop */

#define VFPLADDERS_OBJFLAG_HIDDEN 0x4000
#define VFPLADDERS_OBJFLAG_HITDETECT_DISABLED 0x2000

enum
{
    VFPLADDERS_PHASE_WAIT = 0,
    VFPLADDERS_PHASE_DROPPING = 1,
    VFPLADDERS_PHASE_SETTLED = 2
};

extern const f32 lbl_803E60D8; /* drop distance below the placed height */
extern f32 lbl_803E60DC;       /* drop speed */

typedef struct VfpLaddersState
{
    s16 baseGameBit;    /* 0x00 */
    s16 triggerGameBit; /* 0x02 */
    s16 phase;          /* 0x04: VFPLADDERS_PHASE_* */
    s16 delayTimer;     /* 0x06 */
} VfpLaddersState;

typedef struct VfpLaddersSetup
{
    u8 pad00[0x0C];
    f32 baseY; /* 0x0C: placed height */
    u8 pad10[0x1E - 0x10];
    s16 baseGameBit;    /* 0x1E */
    s16 triggerGameBit; /* 0x20 */
} VfpLaddersSetup;

STATIC_ASSERT(sizeof(VfpLaddersState) == 0x08);
STATIC_ASSERT(offsetof(VfpLaddersState, baseGameBit) == 0x00);
STATIC_ASSERT(offsetof(VfpLaddersState, triggerGameBit) == 0x02);
STATIC_ASSERT(offsetof(VfpLaddersState, phase) == 0x04);
STATIC_ASSERT(offsetof(VfpLaddersState, delayTimer) == 0x06);
STATIC_ASSERT(offsetof(VfpLaddersSetup, baseY) == 0x0C);
STATIC_ASSERT(offsetof(VfpLaddersSetup, baseGameBit) == 0x1E);
STATIC_ASSERT(offsetof(VfpLaddersSetup, triggerGameBit) == 0x20);

int vfpladders_SeqFn(void) { return 0x0; }

int vfpladders_getExtraSize(void) { return 0x8; }

int vfpladders_getObjectTypeId(void) { return 0x0; }

void vfpladders_render(void)
{
}

void vfpladders_hitDetect(void)
{
}

void vfpladders_update(int obj)
{
    VfpLaddersState* state;
    VfpLaddersSetup* setup;

    setup = (VfpLaddersSetup*)((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;

    if (((GameObject*)obj)->anim.seqId == VFPLADDERS_TRIGGER_SEQID)
    {
        if ((u32)GameBit_Get(state->triggerGameBit) != 0)
        {
            if ((u32)GameBit_Get(state->baseGameBit) == 0)
            {
                (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            }
        }
        if ((u32)GameBit_Get(state->triggerGameBit) == 0)
        {
            if ((u32)GameBit_Get(state->baseGameBit) != 0)
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
                Sfx_PlayFromObject(obj, SFXen_flybuzz_loop);
                state->delayTimer = 0;
            }
        }
        else
        {
            if (state->phase == VFPLADDERS_PHASE_WAIT && GameBit_Get(state->triggerGameBit) != 0)
            {
                state->delayTimer = VFPLADDERS_DROP_DELAY;
            }
            if (state->phase == VFPLADDERS_PHASE_DROPPING &&
                ((GameObject*)obj)->anim.localPosY > setup->baseY - lbl_803E60D8)
            {
                ((GameObject*)obj)->anim.localPosY =
                    ((GameObject*)obj)->anim.localPosY - lbl_803E60DC * timeDelta;
                if (((GameObject*)obj)->anim.localPosY < setup->baseY - lbl_803E60D8)
                {
                    ((GameObject*)obj)->anim.localPosY = setup->baseY - lbl_803E60D8;
                    state->phase = VFPLADDERS_PHASE_SETTLED;
                }
            }
        }
    }
}

void vfpladders_release(void)
{
}

void vfpladders_initialise(void)
{
}

void vfpladders_init(int* obj, u8* init)
{
    VfpLaddersState* state = ((GameObject*)obj)->extra;
    VfpLaddersSetup* setup = (VfpLaddersSetup*)init;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)init[0x18] << 8);
    state->triggerGameBit = setup->triggerGameBit;
    state->baseGameBit = setup->baseGameBit;
    ((GameObject*)obj)->objectFlags |= (VFPLADDERS_OBJFLAG_HIDDEN | VFPLADDERS_OBJFLAG_HITDETECT_DISABLED);
    ((GameObject*)obj)->animEventCallback = vfpladders_SeqFn;
}

void vfpladders_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

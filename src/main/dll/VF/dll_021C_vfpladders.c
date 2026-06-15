#include "main/dll/VF/vf_shared.h"
#include "main/game_object.h"

#include "main/audio/sfx_ids.h"
extern const f32 lbl_803E60D8;
extern f32 lbl_803E60DC;

typedef struct VfpLaddersState
{
    s16 baseGameBit;
    s16 triggerGameBit;
    s16 phase;
    s16 delayTimer;
} VfpLaddersState;

typedef struct VfpLaddersSetup
{
    u8 pad00[0x0C];
    f32 baseY;
    u8 pad10[0x1E - 0x10];
    s16 baseGameBit;
    s16 triggerGameBit;
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
    int countdown;

    setup = (VfpLaddersSetup*)((GameObject*)obj)->anim.placementData;
    state = ((GameObject*)obj)->extra;

    if (((GameObject*)obj)->anim.seqId == 0x548)
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
                state->phase = 1;
                Sfx_PlayFromObject(obj, SFXen_flybuzz_loop);
                state->delayTimer = 0;
            }
        }
        else
        {
            if (state->phase == 0 && (u32)GameBit_Get(state->triggerGameBit) != 0)
            {
                state->delayTimer = 0x5a;
            }
            if (state->phase == 1 &&
                ((GameObject*)obj)->anim.localPosY > setup->baseY - lbl_803E60D8)
            {
                ((GameObject*)obj)->anim.localPosY =
                    ((GameObject*)obj)->anim.localPosY - lbl_803E60DC * timeDelta;
                if (((GameObject*)obj)->anim.localPosY < setup->baseY - lbl_803E60D8)
                {
                    ((GameObject*)obj)->anim.localPosY = setup->baseY - lbl_803E60D8;
                    state->phase = 2;
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
    *(s16*)obj = (s16)((s8)init[0x18] << 8);
    state->triggerGameBit = setup->triggerGameBit;
    state->baseGameBit = setup->baseGameBit;
    ((GameObject*)obj)->objectFlags |= 0x6000;
    ((GameObject*)obj)->animEventCallback = (void*)vfpladders_SeqFn;
}

void vfpladders_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

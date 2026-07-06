/*
 * wctemple (DLL 0x294) - a temple door/aperture object in the CloudRunner
 * Fortress (WC) area. Each instance counts down a timer and toggles between
 * two trigger sequences (closed→open, open→closed) when the player activates
 * the hitbox interaction flag. The 'type' field from placement sets the
 * object's X rotation.
 */
#include "main/dll/dll_80220608_shared.h"
#include "main/game_object.h"

#define WCTEMPLE_EXTRA_SIZE 8
#define WCTEMPLE_SEQUENCE_SLOT_CLOSED 0
#define WCTEMPLE_SEQUENCE_SLOT_OPEN   1
#define WCTEMPLE_SEQUENCE_INVALID_ARG -1

typedef struct WCTempleSetup
{
    ObjPlacement base;
    s8 type;
    u8 pad19[0x24 - 0x19];
} WCTempleSetup;

typedef struct WCTempleState
{
    f32 timer;
    u8 triggerSlot;
    u8 pad05[3];
} WCTempleState;

STATIC_ASSERT(sizeof(WCTempleState) == WCTEMPLE_EXTRA_SIZE);
STATIC_ASSERT(sizeof(WCTempleSetup) == 0x24);
STATIC_ASSERT(offsetof(WCTempleState, timer) == 0x00);
STATIC_ASSERT(offsetof(WCTempleState, triggerSlot) == 0x04);
STATIC_ASSERT(offsetof(WCTempleSetup, type) == 0x18);

int wctemple_getExtraSize(void) { return WCTEMPLE_EXTRA_SIZE; }

int wctemple_getObjectTypeId(void) { return 0; }

void wctemple_free(void)
{
}

void wctemple_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, lbl_803E6E20);
    }
}

void wctemple_hitDetect(void)
{
}

void wctemple_update(int obj)
{
    WCTempleState* state = ((GameObject*)obj)->extra;

    state->timer -= timeDelta;
    if (state->timer < lbl_803E6E24)
    {
        state->timer = *(f32*)&lbl_803E6E24;
    }

    if (state->triggerSlot == WCTEMPLE_SEQUENCE_SLOT_CLOSED)
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            (*gObjectTriggerInterface)
                ->runSequence(WCTEMPLE_SEQUENCE_SLOT_CLOSED, (void*)obj, WCTEMPLE_SEQUENCE_INVALID_ARG);
            state->triggerSlot = WCTEMPLE_SEQUENCE_SLOT_OPEN;
        }
    }
    else
    {
        if ((*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            (*gObjectTriggerInterface)
                ->runSequence(WCTEMPLE_SEQUENCE_SLOT_OPEN, (void*)obj, WCTEMPLE_SEQUENCE_INVALID_ARG);
            state->triggerSlot = WCTEMPLE_SEQUENCE_SLOT_CLOSED;
        }
    }
}

void wctemple_init(int obj, int setup)
{
    WCTempleSetup* setupData = (WCTempleSetup*)setup;
    int angle = setupData->type;

    ((GameObject*)obj)->anim.rotX = (s16)(angle << 8);
}

void wctemple_release(void)
{
}

void wctemple_initialise(void)
{
}

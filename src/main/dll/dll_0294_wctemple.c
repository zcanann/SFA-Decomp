/*
 * wctemple (DLL 0x294) - a temple door/aperture object in the CloudRunner
 * Fortress (WC) area. Each instance counts down a timer and toggles between
 * two trigger sequences (closed→open, open→closed) when the player activates
 * the hitbox interaction flag. The 'type' field from placement sets the
 * object's X rotation.
 */
#include "main/dll/dll_0294_wctemple.h"
#include "main/frame_timing.h"
#include "main/game_object.h"
#include "main/objseq.h"
#include "main/object_render_legacy.h"

#define WCTEMPLE_EXTRA_SIZE 8
#define WCTEMPLE_SEQUENCE_SLOT_CLOSED 0
#define WCTEMPLE_SEQUENCE_SLOT_OPEN   1
#define WCTEMPLE_SEQUENCE_INVALID_ARG -1

int wctemple_getExtraSize(void) { return WCTEMPLE_EXTRA_SIZE; }

int wctemple_getObjectTypeId(void) { return 0; }

void wctemple_free(void)
{
}

void wctemple_render(GameObject *obj, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, lbl_803E6E20);
    }
}

void wctemple_hitDetect(void)
{
}

void wctemple_update(GameObject *obj)
{
    WCTempleState* state = (obj)->extra;

    state->timer -= timeDelta;
    if (state->timer < lbl_803E6E24)
    {
        state->timer = *(f32*)&lbl_803E6E24;
    }

    if (state->triggerSlot == WCTEMPLE_SEQUENCE_SLOT_CLOSED)
    {
        if ((*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            (*gObjectTriggerInterface)
                ->runSequence(WCTEMPLE_SEQUENCE_SLOT_CLOSED, (void*)obj, WCTEMPLE_SEQUENCE_INVALID_ARG);
            state->triggerSlot = WCTEMPLE_SEQUENCE_SLOT_OPEN;
        }
    }
    else
    {
        if ((*(u8*)&(obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED) != 0)
        {
            (*gObjectTriggerInterface)
                ->runSequence(WCTEMPLE_SEQUENCE_SLOT_OPEN, (void*)obj, WCTEMPLE_SEQUENCE_INVALID_ARG);
            state->triggerSlot = WCTEMPLE_SEQUENCE_SLOT_CLOSED;
        }
    }
}

void wctemple_init(GameObject *obj, WCTempleSetup* setup)
{
    int angle = setup->type;

    (obj)->anim.rotX = (s16)(angle << 8);
}

void wctemple_release(void)
{
}

void wctemple_initialise(void)
{
}

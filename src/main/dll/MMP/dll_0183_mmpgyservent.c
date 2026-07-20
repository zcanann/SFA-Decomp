/*
 * mmpgyservent (DLL 0x183) - Moon Mountain Pass geyser vent.
 *
 * An intermittent steam/geyser emitter. While its placement gamebit is
 * clear the vent cycles: an idle countdown (userData1) re-rolls a random idle
 * delay and a random active duration (userData2) when it lapses; during the
 * active window it spawns geyser particles (effect 0x724) and keeps a
 * looped vent sound (sfx 0x450) alive each frame. Setting the placement
 * gamebit disables the vent entirely.
 */

#include "main/dll/partfx_interface.h"
#include "main/game_object.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/MMP/dll_0183_mmpgyservent.h"
#include "main/object_descriptor.h"

#define MMPGYSERVENT_PARTFX_GEYSER              0x724
#define MMPGYSERVENT_INITIAL_IDLE_MIN            10
#define MMPGYSERVENT_INITIAL_IDLE_MAX            200
#define MMPGYSERVENT_IDLE_MIN                    70
#define MMPGYSERVENT_IDLE_MAX                    240
#define MMPGYSERVENT_ACTIVE_MIN                  30
#define MMPGYSERVENT_ACTIVE_MAX                  60

#define MMPGYSERVENT_IDLE_TIMER(obj)   ((obj)->userData1)
#define MMPGYSERVENT_ACTIVE_TIMER(obj) ((obj)->userData2)

int mmp_gyservent_getExtraSize(void)
{
    return 0x0;
}
int mmp_gyservent_getObjectTypeId(void)
{
    return 0x0;
}

void mmp_gyservent_free(void)
{
}

void mmp_gyservent_render(void)
{
}

void mmp_gyservent_hitDetect(void)
{
}

void mmp_gyservent_update(GameObject* obj)
{
    MmpGyserventPlacement* placement = (MmpGyserventPlacement*)obj->anim.placementData;
    if (mainGetBit(placement->disableBit) != 0)
        return;
    MMPGYSERVENT_IDLE_TIMER(obj) -= framesThisStep;
    if (MMPGYSERVENT_IDLE_TIMER(obj) < 0)
    {
        MMPGYSERVENT_IDLE_TIMER(obj) = randomGetRange(MMPGYSERVENT_IDLE_MIN, MMPGYSERVENT_IDLE_MAX);
        MMPGYSERVENT_ACTIVE_TIMER(obj) = randomGetRange(MMPGYSERVENT_ACTIVE_MIN, MMPGYSERVENT_ACTIVE_MAX);
    }
    if (MMPGYSERVENT_ACTIVE_TIMER(obj) == 0)
        return;
    MMPGYSERVENT_ACTIVE_TIMER(obj) -= framesThisStep;
    if (MMPGYSERVENT_ACTIVE_TIMER(obj) <= 0)
    {
        MMPGYSERVENT_ACTIVE_TIMER(obj) = 0;
    }
    else
    {
        (*gPartfxInterface)->spawnObject((void*)obj, MMPGYSERVENT_PARTFX_GEYSER, NULL, 2, -1, NULL);
        Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_en_diallp_c_450);
    }
}

void mmp_gyservent_init(GameObject* obj)
{
    obj->objectFlags |= (OBJECT_OBJFLAG_HIDDEN | OBJECT_OBJFLAG_HITDETECT_DISABLED);
    MMPGYSERVENT_IDLE_TIMER(obj) = randomGetRange(MMPGYSERVENT_INITIAL_IDLE_MIN, MMPGYSERVENT_INITIAL_IDLE_MAX);
    obj->anim.alpha = 0;
    obj->anim.resetHitboxFlags &= ~INTERACT_FLAG_DISABLED;
}

void mmp_gyservent_release(void)
{
}

void mmp_gyservent_initialise(void)
{
}

ObjectDescriptor gMMP_gyserventObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mmp_gyservent_initialise,
    (ObjectDescriptorCallback)mmp_gyservent_release,
    0,
    (ObjectDescriptorCallback)mmp_gyservent_init,
    (ObjectDescriptorCallback)mmp_gyservent_update,
    (ObjectDescriptorCallback)mmp_gyservent_hitDetect,
    (ObjectDescriptorCallback)mmp_gyservent_render,
    (ObjectDescriptorCallback)mmp_gyservent_free,
    (ObjectDescriptorCallback)mmp_gyservent_getObjectTypeId,
    mmp_gyservent_getExtraSize,
};

/*
 * mmpgyservent (DLL 0x183) - Moon Mountain Pass geyser vent.
 *
 * An intermittent steam/geyser emitter. While its placement gamebit is
 * clear the vent cycles: an idle countdown (unkF4) re-rolls a random idle
 * delay and a random active duration (unkF8) when it lapses; during the
 * active window it spawns geyser particles (effect 0x724) and keeps a
 * looped vent sound (sfx 0x450) alive each frame. Setting the placement
 * gamebit disables the vent entirely.
 */

#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/MMP/dll_0183_mmpgyservent.h"

#define MMPGYSERVENT_PARTFX_GEYSER              0x724
#define MMPGYSERVENT_OBJFLAG_HIDDEN             0x4000
#define MMPGYSERVENT_OBJFLAG_HITDETECT_DISABLED 0x2000

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

#pragma scheduling off
#pragma peephole off
void mmp_gyservent_update(GameObject* obj)
{
    int def = *(int*)&(obj)->anim.placementData;
    if (mainGetBit(((MmpGyserventPlacement*)def)->disableBit) != 0)
        return;
    (obj)->unkF4 -= framesThisStep;
    if ((obj)->unkF4 < 0)
    {
        (obj)->unkF4 = randomGetRange(0x46, 0xF0);
        (obj)->unkF8 = randomGetRange(0x1E, 0x3C);
    }
    if ((obj)->unkF8 == 0)
        return;
    (obj)->unkF8 -= framesThisStep;
    if ((obj)->unkF8 <= 0)
    {
        (obj)->unkF8 = 0;
    }
    else
    {
        (*gPartfxInterface)->spawnObject((void*)obj, MMPGYSERVENT_PARTFX_GEYSER, NULL, 2, -1, NULL);
        Sfx_KeepAliveLoopedObjectSound((int)obj, SFXTRIG_en_diallp_c_450);
    }
}

void mmp_gyservent_init(GameObject* obj)
{
    obj->objectFlags |= (MMPGYSERVENT_OBJFLAG_HIDDEN | MMPGYSERVENT_OBJFLAG_HITDETECT_DISABLED);
    *(u32*)&obj->unkF4 = randomGetRange(0xa, 0xc8);
    obj->anim.alpha = 0;
    *(u8*)&obj->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
}

void mmp_gyservent_release(void)
{
}

void mmp_gyservent_initialise(void)
{
}

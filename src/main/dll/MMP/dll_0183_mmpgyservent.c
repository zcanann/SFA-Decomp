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

typedef struct MmpGyserventPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 disableBit;    /* 0x1E: gamebit that switches the vent off */
    u8 unk20;          /* 0x20 */
    u8 pad21[0x28 - 0x21];
} MmpGyserventPlacement;


extern u8 framesThisStep;

void mmp_gyservent_free(void)
{
}

void mmp_gyservent_render(void)
{
}

void mmp_gyservent_hitDetect(void)
{
}

void mmp_gyservent_release(void)
{
}

void mmp_gyservent_initialise(void)
{
}

int mmp_gyservent_getExtraSize(void) { return 0x0; }
int mmp_gyservent_getObjectTypeId(void) { return 0x0; }

#pragma scheduling off
#pragma peephole off
void mmp_gyservent_update(int obj)
{
    int def = *(int*)&((GameObject*)obj)->anim.placementData;
    if (GameBit_Get(((MmpGyserventPlacement*)def)->disableBit) != 0) return;
    ((GameObject*)obj)->unkF4 -= framesThisStep;
    if (((GameObject*)obj)->unkF4 < 0)
    {
        ((GameObject*)obj)->unkF4 = randomGetRange(0x46, 0xF0);
        ((GameObject*)obj)->unkF8 = randomGetRange(0x1E, 0x3C);
    }
    if (((GameObject*)obj)->unkF8 == 0) return;
    ((GameObject*)obj)->unkF8 -= framesThisStep;
    if (((GameObject*)obj)->unkF8 <= 0)
    {
        ((GameObject*)obj)->unkF8 = 0;
    }
    else
    {
        (*gPartfxInterface)->spawnObject((void*)obj, 0x724, NULL, 2, -1, NULL);
        Sfx_KeepAliveLoopedObjectSound(obj, 0x450);
    }
}

void mmp_gyservent_init(int obj)
{
    ((GameObject*)obj)->objectFlags |= 0x6000;
    *(u32*)&((GameObject*)obj)->unkF4 = randomGetRange(0xa, 0xc8);
    ((GameObject*)obj)->anim.alpha = 0;
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_DISABLED;
}

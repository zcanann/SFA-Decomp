/*
 * DLL 0x0240 - GC robot-blast object [0x801FF884-0x801FF9B0).
 *
 * A passive blast-effect object. Its sequence callback (GCRobotBlast_SeqFn)
 * latches the latest anim event id into the blast-fired flag (flags04 bit
 * 0x80); when that flag is set and mode is 0 or 1 it spawns a pair of
 * directional energy bursts each tick. init seeds mode from the placement
 * def byte (def+0x19), clears the fired flag and installs the sequence
 * callback. The remaining descriptor leaves (render/hitDetect/update/
 * free/release/initialise) are no-ops; getExtraSize reports
 * sizeof(GCRobotBlastState).
 */
#include "main/dll/blastflags4_types.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

int GCRobotBlast_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern void objfx_spawnDirectionalBurst(int, int, f32, int, int, int, f32, int, int);
    extern f32 lbl_803E6270;
    extern f32 lbl_803E6274;

    int state = *(int*)&((GameObject*)obj)->extra;
    int i;

    for (i = 0; i < animUpdate->eventCount; i++)
    {
        ((BlastFlags4*)&((GCRobotBlastState*)state)->flags04)->b80 = animUpdate->eventIds[i];
    }
    if (((BlastFlags4*)&((GCRobotBlastState*)state)->flags04)->b80 != 0)
    {
        switch (((GCRobotBlastState*)state)->mode)
        {
        case 0:
        case 1:
            objfx_spawnDirectionalBurst(obj, 7, lbl_803E6270, 5, 6, 0x64, lbl_803E6274, 0, 0x200000);
            objfx_spawnDirectionalBurst(obj, 6, lbl_803E6270, 1, 6, 0x64, lbl_803E6274, 0, 0x200000);
            break;
        }
    }
    return 0;
}

int GCRobotBlast_getExtraSize(void) { return sizeof(GCRobotBlastState); }
int GCRobotBlast_getObjectTypeId(void) { return 0x0; }

void GCRobotBlast_free(void)
{
}

void GCRobotBlast_render(void)
{
}

void GCRobotBlast_hitDetect(void)
{
}

void GCRobotBlast_update(void)
{
}

void GCRobotBlast_init(int obj, s8* def)
{
    GCRobotBlastState* state = ((GameObject*)obj)->extra;
    state->mode = def[0x19];
    ((BlastFlags4*)&state->flags04)->b80 = 0;
    ((GameObject*)obj)->animEventCallback = GCRobotBlast_SeqFn;
}

void GCRobotBlast_release(void)
{
}

void GCRobotBlast_initialise(void)
{
}

/*
 * ccgasvent - Crystal Caves gas-vent emitter (DLL 0x0185). One vent of the
 * gas-vent group (CCGASVENT_GROUP); the controller object (ccgasventcontrol,
 * DLL 0x0186) tracks the whole group. While the room's gas gameBit (0x1C0)
 * is set the vent watches the nearest group-5 object: once it is far enough
 * away (lbl_803E4614) it starts spawning the gas particle effect each tick.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"

extern uint GameBit_Get(int eventId);
extern int ObjGroup_FindNearestObject(int group, uint obj, f32* outDist);

extern f32 lbl_803E4610; /* search radius seed for FindNearestObject */
extern f32 lbl_803E4614; /* distance at which the vent activates */

#define CCGASVENT_GROUP 0x3f
#define CCGASVENT_GAS_GAMEBIT 0x1c0

int ccgasvent_getExtraSize(void) { return 0x1; }

void ccgasvent_render(void)
{
}

#pragma scheduling off
void ccgasvent_free(int obj) { ObjGroup_RemoveObject(obj, CCGASVENT_GROUP); }
#pragma scheduling reset

#pragma scheduling off
void ccgasvent_init(int obj) { ObjGroup_AddObject(obj, CCGASVENT_GROUP); }
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void ccgasvent_update(int* obj)
{
    f32 dist = lbl_803E4610;
    u8* state = ((GameObject*)obj)->extra;
    if (GameBit_Get(CCGASVENT_GAS_GAMEBIT) != 0)
    {
        ObjGroup_FindNearestObject(5, (uint)obj, &dist);
        switch (state[0])
        {
        case 0:
            if (dist >= lbl_803E4614)
            {
                state[0] = 1;
            }
            break;
        case 1:
            if (dist < lbl_803E4614)
            {
                state[0] = 0;
            }
            else
            {
                (*gPartfxInterface)->spawnObject(obj, 0x3df, NULL, 0, -1, NULL);
            }
            break;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

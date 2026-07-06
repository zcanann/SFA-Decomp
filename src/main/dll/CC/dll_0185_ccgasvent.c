/*
 * ccgasvent - Crystal Caves gas-vent emitter (DLL 0x0185). One vent of the
 * gas-vent group (CCGASVENT_GROUP); the controller object (ccgasventcontrol,
 * DLL 0x0186) tracks the whole group. While the room's gas gameBit (0x1C0)
 * is set the vent watches the nearest group-5 object: once it is far enough
 * away (>= 10.0) it starts spawning the gas particle effect each tick.
 */
#include "main/effect_interfaces.h"
#include "main/game_object.h"
#include "main/gamebits.h"
extern int ObjGroup_FindNearestObject(int group, u32 obj, float* maxDistance);

#define CCGASVENT_GROUP 0x3f
#define CCGASVENT_GAS_GAMEBIT 0x1c0

/* ccgasvent_update state machine */
#define CCGASVENT_STATE_IDLE 0     /* player near: dormant, watching distance */
#define CCGASVENT_STATE_SPAWNING 1 /* player far enough: emitting gas each tick */

int ccgasvent_getExtraSize(void) { return 0x1; }

#pragma scheduling off
void ccgasvent_free(int obj) { ObjGroup_RemoveObject(obj, CCGASVENT_GROUP); }
#pragma scheduling reset

void ccgasvent_render(void)
{
}

#pragma scheduling off
#pragma peephole off
void ccgasvent_update(int* obj)
{
    f32 dist = 3.4028235e38f;
    u8* state = ((GameObject*)obj)->extra;
    if (GameBit_Get(CCGASVENT_GAS_GAMEBIT) != 0)
    {
        ObjGroup_FindNearestObject(5, (u32)obj, &dist);
        switch (state[0])
        {
        case CCGASVENT_STATE_IDLE:
            if (dist >= 10.0f)
            {
                state[0] = CCGASVENT_STATE_SPAWNING;
            }
            break;
        case CCGASVENT_STATE_SPAWNING:
            if (dist < 10.0f)
            {
                state[0] = CCGASVENT_STATE_IDLE;
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

#pragma scheduling off
void ccgasvent_init(int obj) { ObjGroup_AddObject(obj, CCGASVENT_GROUP); }
#pragma scheduling reset

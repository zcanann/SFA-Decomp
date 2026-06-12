#ifndef MAIN_DLL_DOOR_TYPES_H_
#define MAIN_DLL_DOOR_TYPES_H_

#include "types.h"

typedef struct DoorLockState
{
    u8 unlocked;
} DoorLockState;

typedef struct DoorF4State
{
    f32 cosYaw; /* cos/sin of spawn yaw; door plane normal */
    f32 sinYaw;
    f32 planeD; /* -(cos*x + sin*z) plane offset */
    f32 openRange; /* per-type approach distance */
    int gameBitA; /* params+0x1E; open latch */
    int gameBitB; /* per-type (68/152/-1) secondary gate */
    int unk18; /* params+0x20 */
    u16 sfxOpen; /* 830 for types 318/890 */
    u16 sfxClose; /* 831 */
    u8 active; /* gamebit-derived open state */
    u8 triggerLatch;
    u8 toggled;
    u8 pad23;
} DoorF4State;

#endif

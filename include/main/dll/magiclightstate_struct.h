#ifndef MAIN_DLL_MAGICLIGHTSTATE_STRUCT_H_
#define MAIN_DLL_MAGICLIGHTSTATE_STRUCT_H_

#include "types.h"

typedef struct MagicLightState
{
    f32 triggerRadius; /* preset by subtype */
    s16 lifetime; /* rand(200,600) at init */
    s16 enterAction; /* L-action when the player enters the radius */
    s16 leaveAction; /* L-action when the player leaves radius + hysteresis */
    u8 pad0A;
    s8 inRange; /* hysteresis latch */
    s8 subtype; /* params+0x1A */
    u8 pad0D[3];
    s16 unk10; /* 301 at init */
    u8 pad12[2];
} MagicLightState;

#endif

#ifndef MAIN_DLL_MAGIC_TYPES_H_
#define MAIN_DLL_MAGIC_TYPES_H_

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

typedef struct MagicDustState
{
    u8 unk00[0x6C];
    f32 unk6C;
    u8 unk70[0x25B - 0x70];
    u8 unk25B;
    u8 unk25C[5];
    s8 unk261;
    u8 unk262[6];
    f32 unk268;
    f32 burstTimer; /* counts down to the next 30-particle burst */
    u16 burstEffectId;
    u16 ambientEffectId; /* partfx effect id */
    s16 sfxId; /* collect sfx id */
    s16 unk276;
    s16 ambientTimer;
    u8 flags27A; /* bits 8/0x10/0x40 observed; &0xFA clear on collect */
    u8 bounceCount;
    u8 mode; /* particle color row */
    u8 unk27D[3];
    u16 unk280;
} MagicDustState;

#endif

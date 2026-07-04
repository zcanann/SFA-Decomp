#ifndef MAIN_DLL_MAGICDUSTSTATE_STRUCT_H_
#define MAIN_DLL_MAGICDUSTSTATE_STRUCT_H_

#include "types.h"

/* MagicDustState.flags27A bits (low bits 0x1..0x8 are a burst/despawn state
   progression; 0x3 = "neither burst-1 nor settled" gates free-fall physics) */
#define MAGICDUST_FLAG_BURST1 0x1       /* first burst phase, timed */
#define MAGICDUST_FLAG_SETTLED 0x2      /* at rest after bounces */
#define MAGICDUST_FLAG_BURST2 0x4       /* second burst phase, timed */
#define MAGICDUST_FLAG_COLLECTED 0x8    /* collected / despawn burst */
#define MAGICDUST_FLAG_AMBIENT_FX 0x10  /* proximity ambient fx spawned */
#define MAGICDUST_FLAG_CLAIMED 0x20     /* pickup message sent, gamebit claimed */
#define MAGICDUST_FLAG_COLLECT_LATCH 0x40 /* collect path taken (blocks re-pickup) */

typedef struct MagicDustState
{
    u8 unk00[0x6C];
    f32 unk6C;
    u8 unk70[0x25B - 0x70];
    u8 unk25B;
    u8 unk25C[5];
    s8 unk261;
    u8 unk262[6];
    f32 collectRadius; /* added to base radius; squared for the XZ pickup test */
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
    u16 pickupMsgArg; /* payload word for the 0x7000a pickup message */
} MagicDustState;

#endif

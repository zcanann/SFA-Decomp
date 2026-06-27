#ifndef MAIN_DLL_PUSHCARTSTATE97_TYPES_H_
#define MAIN_DLL_PUSHCARTSTATE97_TYPES_H_

#include "types.h"

typedef struct
{
    u8 flag_80 : 1;
    u8 flag_40 : 1;
    u8 _rest : 6;
} PushcartState97;

typedef struct ShopItemState
{
    u8 pad00[4];
    f32 controlX[4]; /* 0x04: B-spline control ring (address-passed, raw) */
    f32 controlY[4]; /* 0x14 */
    f32 controlZ[4]; /* 0x24 */
    u8 pad34[0xC];
    f32 splineT; /* 0x40 */
    f32 splineSpeed; /* 0x44 */
    u8 pad48[0x20];
    u8 segCounter; /* 0x68 */
    u8 pad69[0x1F];
    s16 msgParam; /* 0x88: ObjMsg payload (address-used, raw) */
    u8 pad8A[6];
    int vendorObj; /* 0x90: nearest group-9 shop manager */
    s16 helpTextId; /* 0x94 */
    u8 pad96;
    u8 flags97; /* 0x97: PushcartState97 overlay */
    int lightningHandles[10]; /* 0x98: per-spark lightning effect handles */
    f32 lightningTimers[10];  /* 0xC0: per-spark age timers */
    u8 flagsE8; /* 0xE8: PushcartState97 overlay (sparkle render path) */
    u8 padE9[0xEC - 0xE9];
} ShopItemState;

#endif

#ifndef MAIN_DLL_SHOPKEEPERSTATE_STRUCT_H_
#define MAIN_DLL_SHOPKEEPERSTATE_STRUCT_H_

#include "types.h"

typedef struct ShopkeeperState
{
    u8 pad000[0x274];
    s16 controlMode; /* 0x274: shared BaddieState control mode (!= 7 gates render) */
    u8 pad276[0x280 - 0x276];
    f32 animSpeed; /* 0x280 */
    u8 pad284[0x35C - 0x284];
    u8 dll2EBlock[0x96D - 0x35C]; /* 0x35c: dll_2E look-controller block (address-used) */
    u8 unk96D; /* 0x96d */
    u8 pad96E[0x980 - 0x96E];
    u8 eyeAnimBlock[0x9B0 - 0x980]; /* 0x980: characterDoEyeAnims block (address-used) */
    void* msgStack; /* 0x9b0: Stack_Free'd on free */
    int vendorObj; /* 0x9b4: nearest group-9 shop manager */
    f32 unk9B8; /* 0x9b8 */
    u8 pad9BC[8];
    f32 textTimer; /* 0x9c4: gameTextShow 0x433 countdown */
    s16 playerMoney; /* 0x9c8 */
    u8 pad9CA[2];
    s16 price; /* 0x9cc */
    s16 unk9CE; /* 0x9ce */
    s16 priceShown; /* 0x9d0 */
    u8 unk9D2; /* 0x9d2 */
    u8 pad9D3;
    u8 flags9D4; /* 0x9d4: 2 purchased-event, 4 facing, 0x10 leave, 0x20 tick */
    u8 amount; /* 0x9d5 */
    u8 opacity; /* 0x9d6: copied to obj alpha */
    u8 pad9D7;
} ShopkeeperState;

#endif

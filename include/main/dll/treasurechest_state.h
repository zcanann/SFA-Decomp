#ifndef MAIN_DLL_TREASURECHEST_STATE_H_
#define MAIN_DLL_TREASURECHEST_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* treasurechest_state_GENERATED
 * TreasureChestState - the obj+0xB8 extra record observed in treasurechest.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct TreasureChestState {
    int unk0;
    u8 unk4[0x25F - 0x4];
    u8 physicsActive;
    u8 unk260[0x270 - 0x260];
    s16 substate;
    u8 unk272[0x274 - 0x272];
    s16 controlMode;
    u8 unk276[0x2C0 - 0x276];
    f32 targetDistance;
    u8 unk2C4[0x2D0 - 0x2C4];
    int targetObj;
    u8 unk2D4[0x349 - 0x2D4];
    u8 hasTarget;
    u8 unk34A[0x354 - 0x34A];
    s8 hitPoints;
    u8 unk355[0x3E0 - 0x355];
    int savedObjC0;
    u8 unk3E4[0x3F4 - 0x3E4];
    s16 gameBitB;
    u8 unk3F6[0x3FE - 0x3F6];
    u16 aggroRange;
    u8 unk400[0x402 - 0x400];
    s16 targetState;
    u8 unk404[0x405 - 0x404];
    u8 subMode;
    u8 unk406[0x40C - 0x406];
} TreasureChestState;

#endif /* MAIN_DLL_TREASURECHEST_STATE_H_ */

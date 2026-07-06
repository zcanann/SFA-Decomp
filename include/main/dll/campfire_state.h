#ifndef MAIN_DLL_CAMPFIRE_STATE_H_
#define MAIN_DLL_CAMPFIRE_STATE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/dll/kaldachom_state.h"

/* campfire_state_GENERATED
 * CampfireState - the obj+0xB8 extra record observed in campfire.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct CampfireState {
    u8 unk0[0x270 - 0x0];
    s16 substate; /* 0x270: CA-family substate; gates map-event re-register when != 3 */
    u8 unk272[0x274 - 0x272];
    s16 controlMode;
    u8 unk276[0x2D0 - 0x276];
    int targetObj;
    u8 unk2D4[0x3F4 - 0x2D4];
    s16 gameBitB;
    u8 unk3F6[0x3FE - 0x3F6];
    u16 aggroRange;
    u8 unk400[0x402 - 0x400];
    s16 targetState;
    u8 unk404[0x40C - 0x404];
    KaldaChomControl *control;
    KaldaChomControl controlData;
} CampfireState;

STATIC_ASSERT(offsetof(CampfireState, controlData) == 0x410);
STATIC_ASSERT(sizeof(CampfireState) == 0x45C);

#endif /* MAIN_DLL_CAMPFIRE_STATE_H_ */

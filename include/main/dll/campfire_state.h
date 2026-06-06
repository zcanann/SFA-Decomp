#ifndef MAIN_DLL_CAMPFIRE_STATE_H_
#define MAIN_DLL_CAMPFIRE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* campfire_state_GENERATED
 * CampfireState - the obj+0xB8 extra record observed in campfire.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct CampfireState {
    u8 unk0[0x270 - 0x0];
    s16 unk270;
    u8 unk272[0x274 - 0x272];
    s16 unk274;
    u8 unk276[0x2D0 - 0x276];
    int unk2D0;
    u8 unk2D4[0x3F4 - 0x2D4];
    s16 unk3F4;
    u8 unk3F6[0x3FE - 0x3F6];
    u16 unk3FE;
    u8 unk400[0x402 - 0x400];
    s16 unk402;
    u8 unk404[0x40C - 0x404];
    int unk40C;
    u8 unk410[0x414 - 0x410];
} CampfireState;

#endif /* MAIN_DLL_CAMPFIRE_STATE_H_ */

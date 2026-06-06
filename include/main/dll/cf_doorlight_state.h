#ifndef MAIN_DLL_CF_DOORLIGHT_STATE_H_
#define MAIN_DLL_CF_DOORLIGHT_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* cf_doorlight_state_GENERATED
 * CfDoorlightState - the obj+0xB8 extra record observed in cf_doorlight.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct CfDoorlightState {
    u8 unk0[0x3E8 - 0x0];
    f32 unk3E8;
    f32 unk3EC;
    s16 unk3F0;
    s16 unk3F2;
    s16 unk3F4;
    u8 unk3F6[0x3FE - 0x3F6];
    u16 unk3FE;
    u16 unk400;
    u8 unk402[0x40C - 0x402];
    int unk40C;
    u8 unk410[0x414 - 0x410];
} CfDoorlightState;

#endif /* MAIN_DLL_CF_DOORLIGHT_STATE_H_ */

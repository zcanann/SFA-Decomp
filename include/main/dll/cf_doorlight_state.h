#ifndef MAIN_DLL_CF_DOORLIGHT_STATE_H_
#define MAIN_DLL_CF_DOORLIGHT_STATE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/dll/kaldachom_state.h"

/* cf_doorlight_state_GENERATED
 * CfDoorlightState - the obj+0xB8 extra record observed in cf_doorlight.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct CfDoorlightState {
    u8 unk0[0x3E8 - 0x0];
    f32 unk3E8;
    f32 unk3EC;
    s16 spawnsLinkedObj; /* 0x3F0: nonzero -> fetch a linked object (baddie interface[0x13], type 6) to reposition on the pull-up burst */
    s16 gameBitA;
    s16 gameBitB;
    u8 unk3F6[0x3FE - 0x3F6];
    u16 aggroRange;
    u16 flags400;
    u8 unk402[0x40C - 0x402];
    KaldaChomControl *control;
    KaldaChomControl controlData;
} CfDoorlightState;

STATIC_ASSERT(offsetof(CfDoorlightState, controlData) == 0x410);
STATIC_ASSERT(sizeof(CfDoorlightState) == 0x45C);

#endif /* MAIN_DLL_CF_DOORLIGHT_STATE_H_ */

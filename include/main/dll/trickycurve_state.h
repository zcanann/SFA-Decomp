#ifndef MAIN_DLL_TRICKYCURVE_STATE_H_
#define MAIN_DLL_TRICKYCURVE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* trickycurve_state_GENERATED
 * TrickyCurveObjState - the obj+0xB8 extra record observed in TrickyCurve.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct TrickyCurveObjState {
    u8 unk0[0x2 - 0x0];
    s16 rangeZ;
    s16 rangeY;
    s16 unk6;
    s16 gateGameBit;
    s16 triggerGameBit;
    u8 unkC[0x10 - 0xC];
} TrickyCurveObjState;

#endif /* MAIN_DLL_TRICKYCURVE_STATE_H_ */

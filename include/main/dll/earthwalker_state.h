#ifndef MAIN_DLL_EARTHWALKER_STATE_H_
#define MAIN_DLL_EARTHWALKER_STATE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/dll/curve_walker.h"

/* earthwalker_state_GENERATED
 * EarthwalkerState - the obj+0xB8 extra record observed in earthwalker.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct EarthwalkerState {
    u8 unk0[0x611 - 0x0];
    u8 unk611; /* OR-set with bit 2 at init */
    u8 unk612[0x9B0 - 0x612];
    RomCurveWalker route;
    f32 unkAB8;
    f32 randomTimer;
    u8 flagsAC0;
    u8 unkAC1[0xAC8 - 0xAC1];
} EarthwalkerState;

STATIC_ASSERT(offsetof(EarthwalkerState, unk611) == 0x611);
STATIC_ASSERT(offsetof(EarthwalkerState, route) == 0x9B0);
STATIC_ASSERT(offsetof(EarthwalkerState, route.posX) == 0xA18);
STATIC_ASSERT(offsetof(EarthwalkerState, unkAB8) == 0xAB8);

#endif /* MAIN_DLL_EARTHWALKER_STATE_H_ */

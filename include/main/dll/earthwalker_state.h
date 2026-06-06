#ifndef MAIN_DLL_EARTHWALKER_STATE_H_
#define MAIN_DLL_EARTHWALKER_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* earthwalker_state_GENERATED
 * EarthwalkerState - the obj+0xB8 extra record observed in earthwalker.c. Field widths
 * mirror the observed deref widths; unobserved ranges are padded. The
 * span covers every observed access - the true allocation may be larger.
 */
typedef struct EarthwalkerState {
    u8 unk0[0xA18 - 0x0];
    f32 nextPosX;
    u8 unkA1C[0xA20 - 0xA1C];
    f32 nextPosZ;
    f32 dirX;
    u8 unkA28[0xA2C - 0xA28];
    f32 dirZ;
    u8 unkA30[0xAB8 - 0xA30];
    f32 unkAB8;
    f32 randomTimer;
    u8 flagsAC0;
    u8 unkAC1[0xAC8 - 0xAC1];
} EarthwalkerState;

#endif /* MAIN_DLL_EARTHWALKER_STATE_H_ */

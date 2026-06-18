#ifndef MAIN_DLL_EARTHWALKER_STATE_H_
#define MAIN_DLL_EARTHWALKER_STATE_H_

#include "ghidra_import.h"
#include "global.h"
#include "main/dll/curve_walker.h"

/* Dll28BAiState - the obj+0xB8 extra block of the DLL 0x28B player-following
 * NPC (extraSize 0xAC4). Although the state-handler functions that touch this
 * record (dll_28B_stateHandlerN / dll_28B_substateHandlerN) are compiled into
 * the dll_028A_wcearthwalker TU, they are installed and driven exclusively by
 * dll_028B's update(); this is NOT the EarthWalker's own 0x660 record
 * (EarthWalkerState in dll_80220608_shared.h). dll_028B.c views the same block
 * through its private Dll28BState. Field widths mirror the observed deref
 * widths; unobserved ranges are padded. */
typedef struct Dll28BAiState {
    u8 unk0[0x611 - 0x0];
    u8 unk611; /* OR-set with bit 2 at init */
    u8 unk612[0x9B0 - 0x612];
    RomCurveWalker route;
    f32 playerDistance; /* 0xAB8: planar distance to the player (== Dll28BState.playerDistance) */
    f32 randomTimer;
    u8 flagsAC0;
    u8 unkAC1[0xAC8 - 0xAC1];
} Dll28BAiState;

STATIC_ASSERT(offsetof(Dll28BAiState, unk611) == 0x611);
STATIC_ASSERT(offsetof(Dll28BAiState, route) == 0x9B0);
STATIC_ASSERT(offsetof(Dll28BAiState, route.posX) == 0xA18);
STATIC_ASSERT(offsetof(Dll28BAiState, playerDistance) == 0xAB8);

#endif /* MAIN_DLL_EARTHWALKER_STATE_H_ */

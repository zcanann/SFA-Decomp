#ifndef MAIN_DLL_DLL1D6STATE_STRUCT_H_
#define MAIN_DLL_DLL1D6STATE_STRUCT_H_

#include "types.h"

typedef struct Dll1D6State
{
    void* actionDataA; /* 0x00: mmAlloc'd 40B LACTIONS.BIN row */
    void* actionDataB; /* 0x04: following LACTIONS.BIN row */
    f32 hitRangeSqA; /* 0x08 */
    f32 hitRangeSqB; /* 0x0c */
    f32 bobPhase; /* 0x10 */
    f32 bobRate; /* 0x14 */
    s16 upTimer; /* 0x18 */
    s16 downTimer; /* 0x1a */
    s8 dizzyTimer; /* 0x1c */
    u8 flags;
    u8 hitRow; /* 0x1e */
    u8 actionSlot; /* 0x1f: index into the gDll1D6SlotInUse slot table */
} Dll1D6State;

#define DLL1D6_STATE_FLAG_DOWN_PHASE  0x01
#define DLL1D6_STATE_FLAG_HIT_ENABLED 0x02
#define DLL1D6_STATE_FLAG_BOB_ACTIVE  0x04

STATIC_ASSERT(offsetof(Dll1D6State, actionDataA) == 0x00);
STATIC_ASSERT(offsetof(Dll1D6State, actionDataB) == 0x04);
STATIC_ASSERT(offsetof(Dll1D6State, hitRangeSqA) == 0x08);
STATIC_ASSERT(offsetof(Dll1D6State, bobPhase) == 0x10);
STATIC_ASSERT(offsetof(Dll1D6State, upTimer) == 0x18);
STATIC_ASSERT(offsetof(Dll1D6State, dizzyTimer) == 0x1C);
STATIC_ASSERT(offsetof(Dll1D6State, flags) == 0x1D);
STATIC_ASSERT(offsetof(Dll1D6State, actionSlot) == 0x1F);
STATIC_ASSERT(sizeof(Dll1D6State) == 0x20);

#endif

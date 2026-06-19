#ifndef MAIN_DLL_DLL1D6STATE_STRUCT_H_
#define MAIN_DLL_DLL1D6STATE_STRUCT_H_

#include "types.h"

typedef struct Dll1D6State
{
    void* bufA; /* 0x00: mmAlloc'd 40B getTabEntry rows */
    void* bufB; /* 0x04 */
    f32 hitRangeSqA; /* 0x08 */
    f32 hitRangeSqB; /* 0x0c */
    f32 bobPhase; /* 0x10 */
    f32 bobRate; /* 0x14 */
    s16 upTimer; /* 0x18 */
    s16 downTimer; /* 0x1a */
    s8 dizzyTimer; /* 0x1c */
    u8 flags1D; /* 0x1d: 1 = raised, 2 = armed, 4 = bobbing */
    u8 hitRow; /* 0x1e */
    u8 slot; /* 0x1f: index into the gDll1D6SlotInUse slot table */
} Dll1D6State;

#endif

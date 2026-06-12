#ifndef MAIN_DLL_MOONSEEDBUSHSTATE_STRUCT_H_
#define MAIN_DLL_MOONSEEDBUSHSTATE_STRUCT_H_

#include "types.h"

typedef struct MoonSeedBushState
{
    u8 seedState; /* gamebit value: 0 unplanted, 2 grown (SeqFn) */
    u8 flags; /* bit 1 = pending update */
} MoonSeedBushState;

#endif

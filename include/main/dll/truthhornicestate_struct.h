#ifndef MAIN_DLL_TRUTHHORNICESTATE_STRUCT_H_
#define MAIN_DLL_TRUTHHORNICESTATE_STRUCT_H_

#include "types.h"

typedef struct TruthHornIceState
{
    s16 gameBit; /* 0x00 */
    s8 hitsLeft; /* 0x02 */
    s8 phase; /* 0x03 */
    f32 timer; /* 0x04 */
} TruthHornIceState;

#endif

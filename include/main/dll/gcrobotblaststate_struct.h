#ifndef MAIN_DLL_GCROBOTBLASTSTATE_STRUCT_H_
#define MAIN_DLL_GCROBOTBLASTSTATE_STRUCT_H_

#include "types.h"

typedef struct GCRobotBlastState
{
    int mode; /* def+0x19 */
    u8 flags04; /* bit 0x80 = blast fired (BlastFlags4 overlay) */
    u8 unk05[3];
} GCRobotBlastState;

#endif

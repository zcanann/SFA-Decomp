#ifndef MAIN_DLL_BLASTFLAGS4_TYPES_H_
#define MAIN_DLL_BLASTFLAGS4_TYPES_H_

#include "types.h"

typedef struct
    {
        u8 b80 : 1;
    } BlastFlags4;

typedef struct GCRobotBlastState
{
    int mode; /* def+0x19 */
    u8 flags04; /* bit 0x80 = blast fired (BlastFlags4 overlay) */
    u8 unk05[3];
} GCRobotBlastState;

#endif

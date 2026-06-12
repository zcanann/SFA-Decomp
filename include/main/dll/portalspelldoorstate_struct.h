#ifndef MAIN_DLL_PORTALSPELLDOORSTATE_STRUCT_H_
#define MAIN_DLL_PORTALSPELLDOORSTATE_STRUCT_H_

#include "types.h"

typedef struct PortalSpellDoorState
{
    u8 pad00[4];
    f32 openAmount; /* 0x04 */
    int openTimer; /* 0x08 */
    u8 flags0C; /* 0x0c: bit 7 = open (via PortalFlags cast) */
    u8 pad0D[3];
} PortalSpellDoorState;

#endif

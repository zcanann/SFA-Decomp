#ifndef MAIN_DLL_DIMWOODDOOR2PLACEMENT_STRUCT_H_
#define MAIN_DLL_DIMWOODDOOR2PLACEMENT_STRUCT_H_

#include "main/obj_placement.h"

/* Retail DIMWoodDoor placements are fixed at nine words: the common
 * 0x18-byte head followed by this class's 0x0c-byte parameter tail. */
typedef struct Dimwooddoor2Placement
{
    ObjPlacement base;
    s8 rotX; /* byte angle expanded to anim.rotX by << 8 */
    u8 pad19[0x1E - 0x19];
    s16 openedGameBit;
    u8 pad20[0x24 - 0x20];
} Dimwooddoor2Placement;

STATIC_ASSERT(offsetof(Dimwooddoor2Placement, rotX) == 0x18);
STATIC_ASSERT(offsetof(Dimwooddoor2Placement, openedGameBit) == 0x1E);
STATIC_ASSERT(sizeof(Dimwooddoor2Placement) == 0x24);

#endif

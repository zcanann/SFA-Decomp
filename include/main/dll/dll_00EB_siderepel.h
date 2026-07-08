#ifndef MAIN_DLL_DLL_00EB_SIDEREPEL_H_
#define MAIN_DLL_DLL_00EB_SIDEREPEL_H_

#include "global.h"
#include "main/obj_placement.h"

/*
 * SideRepel placement record: the common ObjPlacement head followed by
 * the repel-volume radius at +0x18 (sphere radius >> 3 feeds the hit
 * sphere). Single-owner to siderepel_init.
 */
typedef struct SideRepelPlacement
{
    ObjPlacement head; /* 0x00: common placement head */
    u16 radius;        /* 0x18: hit-sphere radius source */
} SideRepelPlacement;

STATIC_ASSERT(offsetof(SideRepelPlacement, radius) == 0x18);

int siderepel_getExtraSize(void);
void siderepel_free(int obj);
void siderepel_init(int obj, int placement);

#endif /* MAIN_DLL_DLL_00EB_SIDEREPEL_H_ */

#ifndef MAIN_DLL_DLL_018E_MMSHWATERSPIKE_H_
#define MAIN_DLL_DLL_018E_MMSHWATERSPIKE_H_

#include "global.h"
#include "main/game_object.h"

/* placement block read via anim.placementData */
typedef struct MmshWaterspikePlacement
{
    u8 pad0[0xC - 0x0];
    f32 maxHeight; /* 0x0C: Y ceiling the spike cannot exceed */
    u8 pad10[0x14 - 0x10];
    s32 xyzAnimId; /* 0x14: ID of the XYZ-animator driving height (printed on miss) */
} MmshWaterspikePlacement;

/* object-def layout; unk1A/unk1C pack into the 32-bit XYZ-animator object ID */
typedef struct MmshWaterspikeObjectDef
{
    u8 pad0[0x1A - 0x0];
    s16 xyzAnimIdLow;  /* 0x1A: low 16 bits of the animator object ID */
    s16 xyzAnimIdHigh; /* 0x1C: high 16 bits of the animator object ID */
    u8 pad1E[0x24 - 0x1E];
    u8 unk24;
    u8 pad25[0x28 - 0x25];
} MmshWaterspikeObjectDef;

STATIC_ASSERT(offsetof(MmshWaterspikePlacement, maxHeight) == 0x0C);
STATIC_ASSERT(offsetof(MmshWaterspikePlacement, xyzAnimId) == 0x14);
STATIC_ASSERT(sizeof(MmshWaterspikePlacement) == 0x18);
STATIC_ASSERT(offsetof(MmshWaterspikeObjectDef, xyzAnimIdLow) == 0x1A);
STATIC_ASSERT(offsetof(MmshWaterspikeObjectDef, xyzAnimIdHigh) == 0x1C);
STATIC_ASSERT(sizeof(MmshWaterspikeObjectDef) == 0x28);

int mmsh_waterspike_getExtraSize(void);
int mmsh_waterspike_getObjectTypeId(void);
void mmsh_waterspike_free(GameObject* obj);
void mmsh_waterspike_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
void mmsh_waterspike_hitDetect(void);
void mmsh_waterspike_update(GameObject* obj);
void mmsh_waterspike_init(GameObject* obj, MmshWaterspikeObjectDef* def);
void mmsh_waterspike_release(void);
void mmsh_waterspike_initialise(void);

#endif /* MAIN_DLL_DLL_018E_MMSHWATERSPIKE_H_ */

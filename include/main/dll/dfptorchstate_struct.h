#ifndef MAIN_DLL_DFPTORCHSTATE_STRUCT_H_
#define MAIN_DLL_DFPTORCHSTATE_STRUCT_H_

#include "types.h"
#include "main/obj_placement.h"

/*
 * Placement/def record the map loader hands to DFP_Torch_init. Embeds the
 * common ObjPlacement head (position / mapId), then the torch's
 * class-specific setup fields - matching the <Family>Placement convention
 * used by the other object DLLs (e.g. FirePipeMapData, ExplodablePlacement).
 */
typedef struct DfpTorchPlacement
{
    ObjPlacement base; /* 0x00: common placement head */
    s8 rotPitch;       /* 0x18: low 6 bits seed anim.rotX (<<10) */
    u8 mode;           /* 0x19: torch mode selector */
    s16 motionRate;    /* 0x1A: root-motion scale numerator (0 = default) */
    s16 colorIdx;      /* 0x1C: flame color index */
    s16 gameBit;       /* 0x1E: lit-state gamebit, -1 = none */
} DfpTorchPlacement;

STATIC_ASSERT(offsetof(DfpTorchPlacement, rotPitch) == 0x18);
STATIC_ASSERT(offsetof(DfpTorchPlacement, mode) == 0x19);
STATIC_ASSERT(offsetof(DfpTorchPlacement, motionRate) == 0x1A);
STATIC_ASSERT(offsetof(DfpTorchPlacement, colorIdx) == 0x1C);
STATIC_ASSERT(offsetof(DfpTorchPlacement, gameBit) == 0x1E);

typedef struct DfpTorchState
{
    int gameBit; /* lit-state gamebit, -1 = none (def+0x1E) */
    s16 flickerTimer; /* 0x04 */
    s16 litTimer; /* 0x06: 0x7D0 countdown while lit */
    u8 visibleLatch; /* 0x08 */
    u8 mode; /* 0x09: def+0x19 */
    u8 lit; /* 0x0A */
    u8 sfxPending; /* 0x0B */
    u8 prevLit; /* 0x0C */
    u8 colorIdx; /* 0x0D: def+0x1C */
    u8 unk0E[2];
} DfpTorchState;


/* extern-cleanup: consolidated prototypes */
void fn_80202EF0(int obj, int p2);

#endif

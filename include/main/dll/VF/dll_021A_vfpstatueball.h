#ifndef MAIN_DLL_VF_DLL_021A_VFPSTATUEBALL_H_
#define MAIN_DLL_VF_DLL_021A_VFPSTATUEBALL_H_

#include "ghidra_import.h"
#include "global.h"

typedef struct VfpStatueBallPlacement
{
    u8 pad00[0x1a];
    s16 variant;    /* 0x1A: 0..2, selects model and matched against the striker */
    s16 modelScale; /* 0x1C: >1 scales the model's root motion up */
    s16 gameBit;    /* 0x1E */
} VfpStatueBallPlacement;

typedef struct VfpStatueBallState
{
    s16 gameBit;        /* 0x00 */
    s16 timer;          /* 0x02: decremented each tick, never tested */
    u8 unk4;            /* 0x04 */
    u8 active;          /* 0x05 */
    u8 playActivateSfx; /* 0x06 */
    u8 prevActive;      /* 0x07 */
    u8 unk8;            /* 0x08 */
    u8 particleIdx;     /* 0x09 */
    u8 particleAlpha;   /* 0x0A */
    u8 particleChance;  /* 0x0B */
} VfpStatueBallState;

STATIC_ASSERT(sizeof(VfpStatueBallState) == 0xc);
STATIC_ASSERT(offsetof(VfpStatueBallPlacement, variant) == 0x1A);
STATIC_ASSERT(offsetof(VfpStatueBallPlacement, gameBit) == 0x1E);

int VFP_statueball_getExtraSize(void);
int VFP_statueball_getObjectTypeId(void);
void VFP_statueball_free(int obj);
void VFP_statueball_render(void);
void VFP_statueball_hitDetect(void);
void VFP_statueball_update(int* obj);
void VFP_statueball_init(int* obj, u8* init);
void VFP_statueball_release(void);
void VFP_statueball_initialise(void);

#endif /* MAIN_DLL_VF_DLL_021A_VFPSTATUEBALL_H_ */

#ifndef MAIN_DLL_DLL_017F_MOONSEEDBUSH_H_
#define MAIN_DLL_DLL_017F_MOONSEEDBUSH_H_

#include "global.h"
#include "main/obj_placement.h"
#include "main/objanim_update.h"

typedef struct MoonSeedBushPlacement
{
    ObjPlacement base;
    s16 triggerGameBit; /* 0x18 */
    s16 grownGameBit;   /* 0x1A: seedState gamebit (-1 = none) */
    s16 preemptSeq;     /* 0x1C */
    s8 sequence;        /* 0x1E: sequence slot index (-1 = none) */
    u8 rotXByte;        /* 0x1F: rotX in 1/256 turns */
    u8 preemptSlot;     /* 0x20: preempt sequence slot */
    u8 scaleByte;       /* 0x21: model scale param */
    u8 pad22[0x28 - 0x22];
} MoonSeedBushPlacement;

int MoonSeedBush_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);
int MoonSeedBush_getExtraSize(void);
int MoonSeedBush_getObjectTypeId(void);
void MoonSeedBush_free(void);
void MoonSeedBush_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void MoonSeedBush_hitDetect(void);
void MoonSeedBush_update(int obj);
void MoonSeedBush_init(int obj, int data);
void MoonSeedBush_release(void);
void MoonSeedBush_initialise(void);

#endif /* MAIN_DLL_DLL_017F_MOONSEEDBUSH_H_ */

#ifndef MAIN_DLL_WM_DLL_020D_WMSEQPOINT_H_
#define MAIN_DLL_WM_DLL_020D_WMSEQPOINT_H_

#include "global.h"
#include "main/objanim_update.h"
#include "main/obj_placement.h"

typedef struct WmSeqPointState
{
    f32 triggerRadius;    /* 0x00: proximity radius, from placement */
    s16 conditionGameBit; /* 0x04: game bit arming the trigger (-1 = none) */
    s16 disableGameBit;   /* 0x06: set once fired; disables the point when set externally (-1 = none) */
    s16 sequenceId;       /* 0x08: trigger sequence to run */
    s16 unk0A;            /* 0x0A: cleared at init, never read */
    u8 command;           /* 0x0C: last sequence-0 event opcode handled */
    u8 doneLatch;         /* 0x0D: sequence has run; cleared by a spirit reset */
    u8 triggerMode;       /* 0x0E: WMSEQPOINT_TRIGGER_* */
    u8 skyEnabledLatch;   /* 0x0F: sky state cached when the sky-toggle sequence starts */
} WmSeqPointState;

typedef struct WmSeqPointMapData
{
    ObjPlacement base;
    s8 rotXByte;          /* 0x18: rotX in 1/256 turns */
    u8 triggerMode;       /* 0x19: WMSEQPOINT_TRIGGER_* */
    s16 triggerRadius;    /* 0x1A */
    s16 sequenceId;       /* 0x1C */
    s16 conditionGameBit; /* 0x1E */
    s16 disableGameBit;   /* 0x20 */
} WmSeqPointMapData;

STATIC_ASSERT(offsetof(WmSeqPointState, triggerRadius) == 0x0);
STATIC_ASSERT(offsetof(WmSeqPointState, conditionGameBit) == 0x4);
STATIC_ASSERT(offsetof(WmSeqPointState, disableGameBit) == 0x6);
STATIC_ASSERT(offsetof(WmSeqPointState, sequenceId) == 0x8);
STATIC_ASSERT(offsetof(WmSeqPointState, command) == 0xC);
STATIC_ASSERT(offsetof(WmSeqPointState, doneLatch) == 0xD);
STATIC_ASSERT(offsetof(WmSeqPointState, triggerMode) == 0xE);
STATIC_ASSERT(offsetof(WmSeqPointState, skyEnabledLatch) == 0xF);
STATIC_ASSERT(sizeof(WmSeqPointState) == 0x10);
STATIC_ASSERT(offsetof(WmSeqPointMapData, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(WmSeqPointMapData, triggerMode) == 0x19);
STATIC_ASSERT(offsetof(WmSeqPointMapData, triggerRadius) == 0x1A);
STATIC_ASSERT(offsetof(WmSeqPointMapData, sequenceId) == 0x1C);
STATIC_ASSERT(offsetof(WmSeqPointMapData, conditionGameBit) == 0x1E);
STATIC_ASSERT(offsetof(WmSeqPointMapData, disableGameBit) == 0x20);
STATIC_ASSERT(sizeof(WmSeqPointMapData) == 0x24);

void wmseqpoint_onSeqFree(int obj);
int wmseqpoint_SeqFn(int obj, int unused, ObjAnimUpdateState* actor);
int wmseqpoint_getExtraSize(void);
int wmseqpoint_getObjectTypeId(void);
void wmseqpoint_free(void);
void wmseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);
void wmseqpoint_hitDetect(void);
void wmseqpoint_update(struct GameObject *obj);
void wmseqpoint_init(struct GameObject *obj, int setup);
void wmseqpoint_release(void);
void wmseqpoint_initialise(void);

#endif /* MAIN_DLL_WM_DLL_020D_WMSEQPOINT_H_ */

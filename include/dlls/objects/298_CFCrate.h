#ifndef DLLS_OBJECTS_298_CFCRATE_H_
#define DLLS_OBJECTS_298_CFCRATE_H_

#include "dlls/object_descriptor.h"
#include "game/objects/object_fwd.h"
#include "game/objects/object_setup.h"
#include "main/objseq.h"

#define CFCRATE_OBJ_SCALESSWORD 0x1B8
#define CFCRATE_OBJ_DFP_WATER_HI 0x71B

/*
 * Every retail EN placement for this family has a fixed 0x0C-byte parameter
 * tail, proving the complete 0x24-byte layout.
 */
typedef struct CFCratePlacement {
    ObjPlacement base; /* 0x00 */
    s8 initialRotX;    /* 0x18: shifted left by eight */
    u8 bankIndex;      /* 0x19 */
    union {
        s16 param1A;      /* 0x1A: object-specific */
        s16 lingerFrames; /* 0x1A: DFP_WaterHi lifetime */
    };
    s16 param1C;       /* 0x1C: object-specific */
    s16 gameBitA;      /* 0x1E: unused by this TU */
    s16 gameBitB;      /* 0x20 */
    u8 pad22[2];       /* 0x22 */
} CFCratePlacement;

/* CFCrate_getExtraSize proves the complete 0x4C-byte runtime allocation. */
typedef struct CFCrateState {
    u8 unk00[4];       /* 0x00 */
    f32 homeX;         /* 0x04 */
    f32 homeY;         /* 0x08 */
    f32 homeZ;         /* 0x0C */
    u8 pad10[4];       /* 0x10 */
    f32 oscPosA;       /* 0x14: SB_Galleon bounded oscillator */
    f32 oscPosB;       /* 0x18: SB_Galleon bounded oscillator */
    f32 oscVelA;       /* 0x1C */
    f32 unk20;         /* 0x20 */
    f32 oscVelB;       /* 0x24: also LinkF_cog spin rate */
    f32 unk28;         /* 0x28 */
    f32 unusedValue;   /* 0x2C: initialized to 1.0 but otherwise unused */
    u8 pad30[2];       /* 0x30 */
    s16 lampValue;     /* 0x32: SB_Lamp */
    s16 lampRandom;    /* 0x34: SB_Lamp random value */
    s16 lingerTimer;   /* 0x36: DFP_WaterHi frame countdown */
    s16 gameBitA;      /* 0x38: primary object-specific game bit */
    s16 gameBitB;      /* 0x3A: render/sequence object-specific game bit */
    s16 sfxTimer;      /* 0x3C: DIM2IceFloe frames until its next SFX */
    u8 gameBitBLatch;  /* 0x3E: one-shot sequence latch */
    u8 proximityLatch; /* 0x3F: SB_Lamp distance hysteresis */
    u8 sfxCount;       /* 0x40: entries in sfxTable */
    u8 pad41[3];       /* 0x41 */
    u16* sfxTable;     /* 0x44 */
    u16 sfxPeriod;     /* 0x48: DIM2IceFloe base interval */
    u8 pad4A[2];       /* 0x4A */
} CFCrateState;

STATIC_ASSERT(offsetof(CFCratePlacement, base) == 0x00);
STATIC_ASSERT(offsetof(CFCratePlacement, initialRotX) == 0x18);
STATIC_ASSERT(offsetof(CFCratePlacement, bankIndex) == 0x19);
STATIC_ASSERT(offsetof(CFCratePlacement, param1A) == 0x1A);
STATIC_ASSERT(offsetof(CFCratePlacement, lingerFrames) == 0x1A);
STATIC_ASSERT(offsetof(CFCratePlacement, param1C) == 0x1C);
STATIC_ASSERT(offsetof(CFCratePlacement, gameBitA) == 0x1E);
STATIC_ASSERT(offsetof(CFCratePlacement, gameBitB) == 0x20);
STATIC_ASSERT(offsetof(CFCratePlacement, pad22) == 0x22);
STATIC_ASSERT(sizeof(CFCratePlacement) == 0x24);

STATIC_ASSERT(offsetof(CFCrateState, unk00) == 0x00);
STATIC_ASSERT(offsetof(CFCrateState, homeX) == 0x04);
STATIC_ASSERT(offsetof(CFCrateState, homeY) == 0x08);
STATIC_ASSERT(offsetof(CFCrateState, homeZ) == 0x0C);
STATIC_ASSERT(offsetof(CFCrateState, pad10) == 0x10);
STATIC_ASSERT(offsetof(CFCrateState, oscPosA) == 0x14);
STATIC_ASSERT(offsetof(CFCrateState, oscPosB) == 0x18);
STATIC_ASSERT(offsetof(CFCrateState, oscVelA) == 0x1C);
STATIC_ASSERT(offsetof(CFCrateState, unk20) == 0x20);
STATIC_ASSERT(offsetof(CFCrateState, oscVelB) == 0x24);
STATIC_ASSERT(offsetof(CFCrateState, unk28) == 0x28);
STATIC_ASSERT(offsetof(CFCrateState, unusedValue) == 0x2C);
STATIC_ASSERT(offsetof(CFCrateState, pad30) == 0x30);
STATIC_ASSERT(offsetof(CFCrateState, lampValue) == 0x32);
STATIC_ASSERT(offsetof(CFCrateState, lampRandom) == 0x34);
STATIC_ASSERT(offsetof(CFCrateState, lingerTimer) == 0x36);
STATIC_ASSERT(offsetof(CFCrateState, gameBitA) == 0x38);
STATIC_ASSERT(offsetof(CFCrateState, gameBitB) == 0x3A);
STATIC_ASSERT(offsetof(CFCrateState, sfxTimer) == 0x3C);
STATIC_ASSERT(offsetof(CFCrateState, gameBitBLatch) == 0x3E);
STATIC_ASSERT(offsetof(CFCrateState, proximityLatch) == 0x3F);
STATIC_ASSERT(offsetof(CFCrateState, sfxCount) == 0x40);
STATIC_ASSERT(offsetof(CFCrateState, pad41) == 0x41);
STATIC_ASSERT(offsetof(CFCrateState, sfxTable) == 0x44);
STATIC_ASSERT(offsetof(CFCrateState, sfxPeriod) == 0x48);
STATIC_ASSERT(offsetof(CFCrateState, pad4A) == 0x4A);
STATIC_ASSERT(sizeof(CFCrateState) == 0x4C);

int CFCrate_getExtraSize(void);
int CFCrate_getObjectTypeId(void);
void CFCrate_free(GameObject* obj);
void CFCrate_render(GameObject* obj, int renderArg2, int renderArg3, int renderArg4, int renderArg5, s8 visible);
int CFCrate_sequenceCallback(GameObject* obj, int unused, ObjSeqState* animUpdate);
void CFCrate_hitDetect(void);
void CFCrate_update(GameObject* obj);
void CFCrate_init(GameObject* obj, CFCratePlacement* placement);
void CFCrate_release(void);
void CFCrate_initialise(void);

extern ObjectDescriptor gCFCrateObjDescriptor;

#endif /* DLLS_OBJECTS_298_CFCRATE_H_ */

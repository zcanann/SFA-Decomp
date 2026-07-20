#ifndef MAIN_DLL_CF_DLL_012A_CFCRATE_H_
#define MAIN_DLL_CF_DLL_012A_CFCRATE_H_

#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/objanim_update.h"

/*
 * Per-object extra state for the cfccrate multi-prop handler
 * (CFCrate_getExtraSize == 0x4C). Fields are per-objType scratch.
 */
typedef struct CfCcrateState
{
    u8 unk00[4];
    f32 homeX; /* aux+8 spawn position (types 0x8E / 0xD7) */
    f32 homeY;
    f32 homeZ;
    u8 pad10[4];
    f32 oscPosA; /* type 0x8E bounded drift oscillator */
    f32 oscPosB;
    f32 oscVelA; /* negated at the A bounds */
    f32 unk20;
    f32 oscVelB; /* negated at the B bounds; also spin rate for 0x7DE */
    f32 unk28;
    f32 unk2C; /* zeroed for every type at init */
    u8 pad30[2];
    s16 unk32;
    s16 unk34;         /* rand(1000,5000) at init (type 0x125) */
    s16 lingerTimer;   /* type 0x71B frame countdown */
    s16 gameBit;       /* primary on/off bit */
    s16 gameBit2;      /* secondary (render/SeqFn visibility) */
    s16 sfxTimer;      /* frames until next ambient sfx (type 0x10D) */
    u8 gameBit2Latch;  /* rising-edge latch on gameBit2 (runs sequence once) */
    u8 proximityLatch; /* type 0x125 player-distance hysteresis */
    u8 sfxCount;       /* entries in sfxTable */
    u8 pad41[3];
    u16* sfxTable; /* &gCfCrateDefaultSfxTable when aux+0x1A == 0 */
    u16 sfxPeriod; /* base frames between ambient sfx */
    u8 pad4A[2];
} CfCcrateState;

STATIC_ASSERT(sizeof(CfCcrateState) == 0x4C);
STATIC_ASSERT(offsetof(CfCcrateState, sfxTable) == 0x44);

int CFCrate_getExtraSize(void);
int CFCrate_getObjectTypeId(void);
void CFCrate_free(int obj);
void CFCrate_render(GameObject* obj, int p2, int p3, int p4, int p5, s8 visible);
int CFCrate_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);
void CFCrate_hitDetect(void);
void CFCrate_update(GameObject* obj);
void CFCrate_init(GameObject* obj, int aux);
void CFCrate_release(void);
void CFCrate_initialise(void);

#endif /* MAIN_DLL_CF_DLL_012A_CFCRATE_H_ */

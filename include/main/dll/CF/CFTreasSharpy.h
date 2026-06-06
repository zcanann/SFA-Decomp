#ifndef MAIN_DLL_CF_CFTREASSHARPY_H_
#define MAIN_DLL_CF_CFTREASSHARPY_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * Per-object extra state for the fxemit particle emitter
 * (fxemit_getExtraSize == 0x20). init lives in CFchuckobj.c,
 * the rest of the family in CFTreasSharpy.c.
 */
typedef struct FxEmitState {
    f32 triggerRadius; /* (s8)setup[0x18] << 2; sentinel value = always emit */
    f32 unk04; /* obj X at init */
    s16 effectMode; /* 0 partfx, 1 resource id+0x58, 2 resource id+0xAB */
    s16 effectId;
    s16 altEffectId; /* spawned instead when emitCount <= 0 on the args path */
    s16 emitCount; /* >0: spawns per emit; <=0: negated re-emit cooldown frames */
    u8 pad10[2];
    s16 startDelay; /* rand(0,10), counts down by timeDelta */
    s16 enableBit; /* gamebit gate, -1 = always on */
    s16 stopBit; /* gamebit; once set the emitter suppresses */
    s16 suppressed;
    s16 sfxTimer; /* def[0x29]*100, counts down by framesThisStep */
    u8 seqToggle; /* flipped by anim event 2 */
    u8 pad1D[3];
} FxEmitState;

STATIC_ASSERT(sizeof(FxEmitState) == 0x20);

/*
 * Per-object extra state for the cfccrate multi-prop handler
 * (cfccrate_getExtraSize == 0x4C). Fields are per-objType scratch:
 * init in CFTreasSharpy.c, update in CFlevelControl.c, SeqFn/render
 * in dll_179.c.
 */
typedef struct CfCcrateState {
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
    s16 unk34; /* rand(1000,5000) at init (type 0x125) */
    s16 lingerTimer; /* type 0x71B frame countdown */
    s16 gameBit; /* primary on/off bit */
    s16 gameBit2; /* secondary (render/SeqFn visibility) */
    s16 sfxTimer; /* frames until next ambient sfx (type 0x10D) */
    u8 latch3E;
    u8 proximityLatch; /* type 0x125 player-distance hysteresis */
    u8 sfxCount; /* entries in sfxTable */
    u8 pad41[3];
    u16 *sfxTable; /* &lbl_803DBDE8 when aux+0x1A == 0 */
    u16 sfxPeriod; /* base frames between ambient sfx */
    u8 pad4A[2];
} CfCcrateState;

STATIC_ASSERT(sizeof(CfCcrateState) == 0x4C);
STATIC_ASSERT(offsetof(CfCcrateState, sfxTable) == 0x44);

void cfccrate_init(int obj, int aux);
void fxemit_emitEffect(int obj);
int fxemit_SeqFn(int obj, int unused, int events);
void cfccrate_release(void);
void cfccrate_initialise(void);
int fxemit_getExtraSize(void);
int fxemit_getObjectTypeId(void);
void fxemit_free(int obj);
void fxemit_hitDetect(void);

#endif /* MAIN_DLL_CF_CFTREASSHARPY_H_ */

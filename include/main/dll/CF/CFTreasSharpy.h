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

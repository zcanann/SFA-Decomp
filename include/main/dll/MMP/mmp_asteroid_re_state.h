#ifndef MAIN_DLL_MMP_MMP_ASTEROID_RE_STATE_H_
#define MAIN_DLL_MMP_MMP_ASTEROID_RE_STATE_H_

#include "global.h"

/* MmpAsteroidReState.eventFlags bits */
#define ASTEROIDRE_FX_SMOKE 0x1     /* triple 0x716 smoke burst */
#define ASTEROIDRE_FX_DEBRIS 0x8    /* 0x71A debris burst */
#define ASTEROIDRE_FX_EXPLODE 0x10  /* big explosion + shake/rumble (self-clearing) */
#define ASTEROIDRE_FX_IMPACT 0x20   /* double 0x71D impact fx */
#define ASTEROIDRE_FX_PERIODIC 0x40 /* timed 0x71E periodic fx */
#define ASTEROIDRE_SEQ_TICK 0x80    /* per-frame seq-ran latch */

/* partfx ids, each gated by the matching eventFlags bit above (roles pinned by
 * the flag branch that spawns them). Dust is emitted every rise/bob frame. */
#define MMPASTEROIDRE_PARTFX_DUST 0x722         /* rise/bob-frame ground dust (height param) */
#define MMPASTEROIDRE_PARTFX_DUST_CLOUD 0x723   /* rise/bob-frame dust cloud (spawn params, 2x) */
#define MMPASTEROIDRE_PARTFX_SMOKE 0x716        /* ASTEROIDRE_FX_SMOKE (3x) */
#define MMPASTEROIDRE_PARTFX_DEBRIS 0x71A       /* ASTEROIDRE_FX_DEBRIS */
#define MMPASTEROIDRE_PARTFX_EXPLODE 0x71B      /* ASTEROIDRE_FX_EXPLODE flash (once) */
#define MMPASTEROIDRE_PARTFX_EXPLODE_DEBRIS 0x71C /* ASTEROIDRE_FX_EXPLODE debris (0x28x) */
#define MMPASTEROIDRE_PARTFX_IMPACT 0x71D       /* ASTEROIDRE_FX_IMPACT (2x) */
#define MMPASTEROIDRE_PARTFX_PERIODIC 0x71E     /* ASTEROIDRE_FX_PERIODIC */

/* MmpAsteroidReState.phase - rise-event progression, persisted to gamebit 0x87B.
 * Field is u8 (see below); these keep u8 storage, so naming the case/assignment
 * constants is byte-neutral. Only 1 and 2 are assigned in code; 0 is the initial
 * (unset gamebit) state and 3 is a persisted risen state restored from the save. */
enum MmpAsteroidRePhase {
    MMP_ASTEROID_PHASE_HIDDEN = 0,       /* dormant: alpha 0, model bank 0, not yet risen */
    MMP_ASTEROID_PHASE_RISING = 1,       /* active rise, visible (bank 1), periodic fx armed */
    MMP_ASTEROID_PHASE_RISEN = 2,        /* settled after rising, visible (bank 1) */
    MMP_ASTEROID_PHASE_RISEN_SAVED = 3   /* risen state restored from save gamebit (bank 1) */
};

typedef struct MmpAsteroidReState {
    u8 eventFlags; /* 1/8/0x10/0x20 fx bursts, 0x40 periodic fx, 0x80 seq-ran latch */
    u8 phase; /* enum MmpAsteroidRePhase, persisted to gamebit 0x87B (value 0..3) */
    u8 intensity; /* gamebit 0x88C / 0xD52; scales rise height + sfx volume */
    u8 pad03;
    f32 stateTimer; /* counts down; clears gamebit 0x88B on expiry */
    f32 periodicFxTimer; /* rand(10,60); flag 0x40 fx cadence */
    f32 baseY; /* obj Y at init */
    f32 baseY2;
    u16 bobPhase; /* angle accumulators for the float wobble */
    u16 rollPhase;
    u16 pitchPhase;
    u8 pad1A[2];
} MmpAsteroidReState;

#endif

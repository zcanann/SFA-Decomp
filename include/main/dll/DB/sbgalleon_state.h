#ifndef MAIN_DLL_DB_SBGALLEON_STATE_H_
#define MAIN_DLL_DB_SBGALLEON_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/* Per-object extra state for the SB_Galleon boss (SB_Galleon_getExtraSize ==
 * 0xB4). Shared by the SB_Galleon handlers in DBstealerworm.c and the
 * protection-spirit phase handlers in DBprotection.c (fn_801DFA28,
 * DBprotection_updateShield, DBprotection_storeHomePosition), which run on
 * the same object. Offsets re-derived independently from both TUs' deref
 * censuses (task #4 redo). */
typedef struct SBGalleonState {
    f32 driftX;      /* 0x00: wander offset integrated each step */
    f32 driftY;      /* 0x04 */
    f32 driftZ;      /* 0x08 */
    f32 refZ;        /* 0x0c: tricky Z latched at dive start */
    u8 pad10[0xC];
    f32 speed;       /* 0x1c */
    s16 bobPhase;    /* 0x20 */
    s16 rollLatch;   /* 0x22 */
    s16 turnRate;    /* 0x24 */
    s16 timer26;     /* 0x26 */
    s8 cycleKind;    /* 0x28 */
    s8 phase;        /* 0x29 */
    s8 sweepDir;     /* 0x2a */
    s8 stage;        /* 0x2b */
    f32 posX;        /* 0x2c */
    f32 posY;        /* 0x30 */
    f32 posZ;        /* 0x34 */
    f32 swayX;       /* 0x38 */
    f32 swayY;       /* 0x3c */
    f32 swayZ;       /* 0x40 */
    f32 moveScale;   /* 0x44 */
    u8 *targetObj;   /* 0x48 */
    int linkedActor; /* 0x4c: 0xf7-type object found on msg case 3 */
    f32 homeX;       /* 0x50 */
    f32 homeY;       /* 0x54 */
    f32 homeZ;       /* 0x58 */
    f32 unk5C;       /* 0x5c */
    f32 unk60;       /* 0x60 */
    f32 unk64;       /* 0x64 */
    u16 shieldAngle; /* 0x68 */
    u8 pad6A[2];
    s16 fadeTimer;   /* 0x6c */
    s16 phaseTimer;  /* 0x6e */
    u8 cameraState;  /* 0x70 */
    u8 pad71;
    s16 mapLayer;    /* 0x72: latched from obj+0xac at init */
    f32 textAlpha;   /* 0x74: gameText 0x4b1 fade */
    u8 textRising;   /* 0x78 */
    u8 damagePhase;  /* 0x79 head fire-damage state, read via SB_Galleon_getDamagePhase:
                        the ship head renders on fire (partfx 0x7aa) when this is nonzero
                        (and != 2) during the firing anim. Set from stage (7/8/9 -> 3/4/5)
                        and toggled by the victory-cinematic anim events (0/1/2/8); stays 0
                        through the fight, so the head-fire escalation is dormant in retail.
                        (The guns fast-fire on `stage`, not this.) */
    u8 flightPattern;/* 0x7a */
    u8 unk7B;        /* 0x7b */
    s8 phaseCounter;        /* 0x7c */
    u8 pad7D[3];
    u8 musicLatch;   /* 0x80: one-shot latch armed when the boss cutscene/music
                        is entered (cameraState>0 or the victory fade completes);
                        cleared on free so the music gate fires once per fight */
    u8 shieldSfxLatch;/* 0x81 */
    s16 headingLatch;/* 0x82 */
    u8 unk84;        /* 0x84 */
    u8 sprayActive;  /* 0x85: gates the hitDetect particle loop */
    u8 pad86[2];
    f32 wanderA;     /* 0x88 */
    f32 wanderB;     /* 0x8c */
    f32 wanderTimerA;/* 0x90 */
    f32 wanderTimerB;/* 0x94 */
    int musicIdA;    /* 0x98 */
    int musicIdB;    /* 0x9c */
    u8 wanderFlagA;  /* 0xa0 */
    u8 wanderFlagB;  /* 0xa1 */
    u16 envfxCycle;  /* 0xa2 */
    u8 envfxIndex;   /* 0xa4: index into the envfx action table below */
    u8 envfxActs[6]; /* 0xa5..0xaa */
    u8 skyFlag;      /* 0xab: selects the sky light direction vector */
    f32 textTimer;   /* 0xac: countdown keeping the gameText shown */
    u8 gameBitLatch[4]; /* 0xb0: SCGameBitLatch_Update block (address-used) */
} SBGalleonState;
STATIC_ASSERT(sizeof(SBGalleonState) == 0xB4);
STATIC_ASSERT(offsetof(SBGalleonState, phase) == 0x29);
STATIC_ASSERT(offsetof(SBGalleonState, targetObj) == 0x48);
STATIC_ASSERT(offsetof(SBGalleonState, shieldAngle) == 0x68);
STATIC_ASSERT(offsetof(SBGalleonState, textAlpha) == 0x74);
STATIC_ASSERT(offsetof(SBGalleonState, headingLatch) == 0x82);
STATIC_ASSERT(offsetof(SBGalleonState, musicIdA) == 0x98);
STATIC_ASSERT(offsetof(SBGalleonState, envfxActs) == 0xA5);
STATIC_ASSERT(offsetof(SBGalleonState, textTimer) == 0xAC);

#endif /* MAIN_DLL_DB_SBGALLEON_STATE_H_ */

#ifndef MAIN_DLL_LARGECRATE_STATE_H_
#define MAIN_DLL_LARGECRATE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * LargeCrateState - the obj+0xB8 extra record for dll_0105_largecrate.c.
 *
 * Field meanings were recovered by live debugging (Dolphin MCP): reading the
 * struct on a live crate, breaking the crate to fire the spawn path, and
 * confirming the drop -> collectible -> player-health pickup chain.
 *
 * unkC / unk12 are written by init but never read inside this TU, so their
 * meaning is left unverified.
 */
typedef struct LargeCrateState {
    s32 breakTimeBonus;  /* 0x00 amount passed to mapEvent addTime() on break;
                            init = id*SCALE, or sentinel (disabled) / -1 (forever) */
    f32 animTimer;       /* 0x04 respawn/fade-in animation progress (1.0 -> 0.0) */
    s16 breakTimer;      /* 0x08 post-break hide/respawn countdown (set to 0x32 on break) */
    s16 idleTimer;       /* 0x0A idle random re-roll timer */
    s16 unkC;            /* 0x0C init-only (set to 0x190), unread here */
    s16 brokenGameBit;   /* 0x0E persistent "already broken" game bit: set on break,
                            checked at init to start the crate broken/disabled (-1 = none) */
    u8 unk10;            /* 0x10 */
    u8 dropType;         /* 0x11 contents selector for largecrate_spawnDropContents */
    u8 unk12;            /* 0x12 init-only (from placement+0x1a), unread here */
    u8 damageTaken;      /* 0x13 accumulated hit damage this break cycle */
    s16 hitSfxId;        /* 0x14 sfx played on a non-breaking hit */
    s16 explodeSfxId;    /* 0x16 sfx played when the crate breaks */
    s16 spinSpeed;       /* 0x18 hit-reaction spin applied to anim.rotY, decays each frame */
    u8 unk1A[0x1C - 0x1A];
    f32 slidePhase;      /* 0x1C conveyor/bob phase seed (parented crates) */
    u16 slideOffset;     /* 0x20 conveyor slide offset addend */
    u8 unk22[0x24 - 0x22];
    f32 homeX;           /* 0x24 placement/home local X (conveyor leash origin) */
    u8 damageThreshold;  /* 0x28 damage needed to break (hit count) */
    u8 unk29[0x2C - 0x29];
} LargeCrateState;

STATIC_ASSERT(offsetof(LargeCrateState, hitSfxId) == 0x14);
STATIC_ASSERT(offsetof(LargeCrateState, homeX) == 0x24);
STATIC_ASSERT(offsetof(LargeCrateState, damageThreshold) == 0x28);

#endif /* MAIN_DLL_LARGECRATE_STATE_H_ */

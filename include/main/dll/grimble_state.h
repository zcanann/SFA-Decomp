#ifndef MAIN_DLL_GRIMBLE_STATE_H_
#define MAIN_DLL_GRIMBLE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * GrimbleControl - the grimble family's per-family control record (the
 * GroundBaddieState 'control' slot at +0x40C), as observed in barrel.c.
 * Span 0x5C covers every observed access - the true allocation may be
 * larger.
 */
typedef struct GrimbleControl {
    f32 unk0;
    f32 unk4;
    f32 unk8;
    u8 unkC[0x20 - 0xC];
    f32 unk20;
    u8 unk24[0x34 - 0x24];
    int candidatePathObj;
    int pathObj;
    f32 nearestDist;
    f32 candidateProgress;
    u8 unk44[0x45 - 0x44];
    s8 reversed;
    u8 unk46;
    u8 unk47[0x48 - 0x47];
    f32 pathProgress;
    f32 unk4C;
    f32 unk50;
    f32 targetProgress;
    s16 baseRotX;
    u8 unk5A[0x5C - 0x5A];
} GrimbleControl;

STATIC_ASSERT(offsetof(GrimbleControl, pathObj) == 0x38);
STATIC_ASSERT(offsetof(GrimbleControl, pathProgress) == 0x48);

#endif /* MAIN_DLL_GRIMBLE_STATE_H_ */

#ifndef MAIN_GAME_OBJECT_H_
#define MAIN_GAME_OBJECT_H_

#include "global.h"
#include "main/objanim_internal.h"

/*
 * GameObject - the engine-wide object record passed around as "obj" /
 * "int obj" / "u8 *obj" throughout src/main and the DLLs. Its head
 * (0x00..0xAF) is exactly ObjAnimComponent (rot @0/2/4, localPos
 * @0xC/10/14, worldPos @0x18/1C/20, velocity @0x24/28/2C, classId @0x44,
 * placementData @0x4C, modelInstance @0x50, ... - see
 * objanim_internal.h, layout STATIC_ASSERTed there). The tail below is
 * named from engine-side evidence only:
 *  - 0xB0 u16: anim.c/audio.c/backpack.c (*(u16 *)(obj + 0xb0), 74 sites)
 *  - 0xB4 s16: baddieControl.c/object.c/objseq.c
 *  - 0xB8 ptr: the per-class extra state block (BaddieState /
 *    ObjSeqState / GroundBaddieState live here - see baddie_state.h)
 *  - 0xBC..0xC8 ptrs: anim.c/object.c/objseq.c list links + callbacks
 *  - 0xE4/0xE5/0xE6/0xEB: object.c bookkeeping bytes
 *  - 0xF4/0xF8 s32: anim.c/campfire.c flag words (*(int *) sites)
 *  - 0xFC/0x100/0x104 f32: object.c
 * The record extends past 0x108; total size unverified - do not take
 * sizeof(GameObject) or index arrays of it.
 *
 * Width discipline (per CLAUDE.md recipe #77): the pointer fields here
 * are routinely null-tested through *(int *) in matched code (cmpwi).
 * Keep those spellings via launders - *(int *)&obj->extra != 0 - rather
 * than retyping the test to a pointer compare.
 */
typedef struct GameObject {
    ObjAnimComponent anim;
    u16 unkB0;
    u8 unkB2[2];
    s16 unkB4;
    u8 unkB6[2];
    void *extra; /* per-class state block */
    void *animEventCallback; /* obj+0xBC anim-event callback slot;
        LinkALevelControlObject/EarthWalkerObject STATIC_ASSERT this at 0xBC */
    void *unkC0;
    void *unkC4;
    void *unkC8;
    u8 unkCC[0x10];
    void *unkDC;
    u8 unkE0[4];
    u8 unkE4;
    u8 unkE5;
    s16 unkE6;
    u8 unkE8;
    s8 unkE9;
    u8 unkEA;
    u8 unkEB;
    u8 unkEC[3];
    s8 unkEF;
    u8 unkF0;
    u8 unkF1[3];
    s32 unkF4;
    s32 unkF8;
    f32 unkFC;
    f32 unk100;
    f32 unk104;
} GameObject;

STATIC_ASSERT(offsetof(GameObject, unkB0) == 0xB0);
STATIC_ASSERT(offsetof(GameObject, extra) == 0xB8);
STATIC_ASSERT(offsetof(GameObject, unkE4) == 0xE4);
STATIC_ASSERT(offsetof(GameObject, unkEF) == 0xEF);
STATIC_ASSERT(offsetof(GameObject, unkF4) == 0xF4);
STATIC_ASSERT(offsetof(GameObject, unk104) == 0x104);

#endif

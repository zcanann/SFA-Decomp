#include "ghidra_import.h"
#include "main/dll/SC/SCtotemlogpuz.h"

extern int GameBit_Get(int bit);
extern int GameBit_Set(int bit, int value);
extern int mapUnload(int id, int flags);
extern int Music_Trigger(int id, int value);
extern void fn_801D80F4(void *p);

typedef struct SCTotemLogPuzzleEventInterface {
    u8 pad00[0x50];
    void (*setAnimEvent)(int animId, int eventId, int value);
} SCTotemLogPuzzleEventInterface;

typedef struct SCTotemLogPuzzleRuntime {
    u8 pad00[7];
    u8 eventCountdown;
} SCTotemLogPuzzleRuntime;

typedef struct SCTotemLogPuzzleObject {
    u8 pad00[0xAC];
    s8 animId;
    u8 padAD[0xB8 - 0xAD];
    SCTotemLogPuzzleRuntime *runtime;
} SCTotemLogPuzzleObject;

typedef struct SCTotemLogPuzzleUpdateState {
    u8 pad00[0x81];
    u8 eventHandled[10];
    u8 eventCount;
} SCTotemLogPuzzleUpdateState;

#define SCTOTEMLOGPUZ_RESET_GAMEBIT 0xBF8
#define SCTOTEMLOGPUZ_EVENT_COUNTDOWN_RESET 5
#define SCTOTEMLOGPUZ_EVENT_COUNTDOWN_ENABLE 1
#define SCTOTEMLOGPUZ_MAP_UNLOAD_FLAGS 0x20000000

extern SCTotemLogPuzzleEventInterface **lbl_803DCAAC;

/*
 * --INFO--
 *
 * Function: fn_801D7C14
 * EN v1.0 Address: 0x801D7C14
 * EN v1.0 Size: 128b
 */
#pragma peephole off
#pragma scheduling off
int fn_801D7C14(void *obj, void *unused, void *p3)
{
    SCTotemLogPuzzleObject *puzzleObj;
    SCTotemLogPuzzleUpdateState *updateState;
    int i;
    puzzleObj = (SCTotemLogPuzzleObject *)obj;
    updateState = (SCTotemLogPuzzleUpdateState *)p3;
    i = 0;
    while (i < (int)updateState->eventCount) {
        if (updateState->eventHandled[i] != 0) {
            i++;
            continue;
        }
        fn_801D80F4(puzzleObj->runtime);
        i++;
    }
    fn_801D7C94(obj, puzzleObj->runtime);
    return 0;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_801D7C94
 * EN v1.0 Address: 0x801D7C94
 * EN v1.0 Size: 576b
 */
#pragma peephole off
#pragma scheduling off
void fn_801D7C94(void *obj, void *p2)
{
    SCTotemLogPuzzleObject *puzzleObj;
    SCTotemLogPuzzleRuntime *runtime;
    s8 ac;
    puzzleObj = (SCTotemLogPuzzleObject *)obj;
    runtime = (SCTotemLogPuzzleRuntime *)p2;

    if (GameBit_Get(SCTOTEMLOGPUZ_RESET_GAMEBIT) != 0) {
        runtime->eventCountdown = SCTOTEMLOGPUZ_EVENT_COUNTDOWN_RESET;
        GameBit_Set(SCTOTEMLOGPUZ_RESET_GAMEBIT, 0);
    }
    if (runtime->eventCountdown == 0) return;

    if (runtime->eventCountdown == SCTOTEMLOGPUZ_EVENT_COUNTDOWN_RESET) {
        ac = puzzleObj->animId;
        (*lbl_803DCAAC)->setAnimEvent(ac, 1, 0);
        ac = puzzleObj->animId;
        (*lbl_803DCAAC)->setAnimEvent(ac, 4, 0);
        ac = puzzleObj->animId;
        (*lbl_803DCAAC)->setAnimEvent(ac, 6, 0);
        ac = puzzleObj->animId;
        (*lbl_803DCAAC)->setAnimEvent(ac, 7, 0);
        ac = puzzleObj->animId;
        (*lbl_803DCAAC)->setAnimEvent(ac, 8, 0);
        ac = puzzleObj->animId;
        (*lbl_803DCAAC)->setAnimEvent(ac, 9, 0);
        mapUnload(0x13, SCTOTEMLOGPUZ_MAP_UNLOAD_FLAGS);
        mapUnload(0x41, SCTOTEMLOGPUZ_MAP_UNLOAD_FLAGS);
        mapUnload(0x43, SCTOTEMLOGPUZ_MAP_UNLOAD_FLAGS);
        mapUnload(0x45, SCTOTEMLOGPUZ_MAP_UNLOAD_FLAGS);
    }
    if (runtime->eventCountdown != SCTOTEMLOGPUZ_EVENT_COUNTDOWN_ENABLE) {
        goto dec;
    }
    ac = puzzleObj->animId;
    (*lbl_803DCAAC)->setAnimEvent(ac, 0, 1);
    ac = puzzleObj->animId;
    (*lbl_803DCAAC)->setAnimEvent(ac, 2, 1);
    ac = puzzleObj->animId;
    (*lbl_803DCAAC)->setAnimEvent(ac, 3, 1);
    ac = puzzleObj->animId;
    (*lbl_803DCAAC)->setAnimEvent(ac, 5, 1);
    ac = puzzleObj->animId;
    (*lbl_803DCAAC)->setAnimEvent(ac, 0xa, 1);
dec:
    runtime->eventCountdown--;
}
#pragma scheduling reset
#pragma peephole reset

/*
 * --INFO--
 *
 * Function: fn_801D7ED4
 * EN v1.0 Address: 0x801D7ED4
 * EN v1.0 Size: 396b
 */
#pragma peephole off
#pragma scheduling off
void fn_801D7ED4(int *p1, int p2, s16 a, s16 b, s16 c, int musicId)
{
    int has_a = (a + 1) | (-1 - a);
    int has_b = (b + 1) | (-1 - b);
    u8 ah = (u8)((u32)has_a >> 31);
    u8 bh = (u8)((u32)has_b >> 31);

    if ((*p1 & p2) != 0) {
        if (ah == 0 || GameBit_Get(a) == 0) {
            if (GameBit_Get(c) != 0) goto end;
        }
        if (ah != 0) {
            GameBit_Set(a, 0);
        }
        if (bh != 0) {
            GameBit_Set(b, 0);
        }
        GameBit_Set(c, 0);
        if (musicId != -1) {
            Music_Trigger(musicId, 0);
        }
        *p1 = *p1 & ~p2;
    } else {
        if (bh == 0 || GameBit_Get(b) == 0) {
            if (GameBit_Get(c) == 0) goto end;
        }
        if (ah != 0) {
            GameBit_Set(a, 0);
        }
        if (bh != 0) {
            GameBit_Set(b, 0);
        }
        GameBit_Set(c, 1);
        if (musicId != -1) {
            Music_Trigger(musicId, 1);
        }
        *p1 = *p1 | p2;
    }
end:
    return;
}
#pragma scheduling reset
#pragma peephole reset

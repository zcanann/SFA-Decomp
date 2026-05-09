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
    int i;
    i = 0;
    while (i < (int)*(u8 *)((char *)p3 + 0x8b)) {
        if (((u8 *)p3)[i + 0x81] != 0) {
            i++;
            continue;
        }
        fn_801D80F4(*(void **)((char *)obj + 0xb8));
        i++;
    }
    fn_801D7C94(obj, *(void **)((char *)obj + 0xb8));
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
    s8 ac;

    if (GameBit_Get(0xbf8) != 0) {
        *(u8 *)((char *)p2 + 7) = 5;
        GameBit_Set(0xbf8, 0);
    }
    if (*(u8 *)((char *)p2 + 7) == 0) return;

    if (*(u8 *)((char *)p2 + 7) == 5) {
        ac = *(s8 *)((char *)obj + 0xac);
        (*lbl_803DCAAC)->setAnimEvent(ac, 1, 0);
        ac = *(s8 *)((char *)obj + 0xac);
        (*lbl_803DCAAC)->setAnimEvent(ac, 4, 0);
        ac = *(s8 *)((char *)obj + 0xac);
        (*lbl_803DCAAC)->setAnimEvent(ac, 6, 0);
        ac = *(s8 *)((char *)obj + 0xac);
        (*lbl_803DCAAC)->setAnimEvent(ac, 7, 0);
        ac = *(s8 *)((char *)obj + 0xac);
        (*lbl_803DCAAC)->setAnimEvent(ac, 8, 0);
        ac = *(s8 *)((char *)obj + 0xac);
        (*lbl_803DCAAC)->setAnimEvent(ac, 9, 0);
        mapUnload(0x13, 0x20000000);
        mapUnload(0x41, 0x20000000);
        mapUnload(0x43, 0x20000000);
        mapUnload(0x45, 0x20000000);
    }
    if (*(u8 *)((char *)p2 + 7) != 1) {
        goto dec;
    }
    ac = *(s8 *)((char *)obj + 0xac);
    (*lbl_803DCAAC)->setAnimEvent(ac, 0, 1);
    ac = *(s8 *)((char *)obj + 0xac);
    (*lbl_803DCAAC)->setAnimEvent(ac, 2, 1);
    ac = *(s8 *)((char *)obj + 0xac);
    (*lbl_803DCAAC)->setAnimEvent(ac, 3, 1);
    ac = *(s8 *)((char *)obj + 0xac);
    (*lbl_803DCAAC)->setAnimEvent(ac, 5, 1);
    ac = *(s8 *)((char *)obj + 0xac);
    (*lbl_803DCAAC)->setAnimEvent(ac, 0xa, 1);
dec:
    *(u8 *)((char *)p2 + 7) = *(u8 *)((char *)p2 + 7) - 1;
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

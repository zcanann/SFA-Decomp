#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802765AC.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_8026fc8c();
extern undefined4 FUN_80271a2c();
extern undefined4 FUN_80271ad4();
extern int FUN_80275364();
extern int FUN_8027566c();
extern uint FUN_802757d4();
extern undefined4 FUN_802757dc();
extern undefined4 FUN_802757e0();
extern undefined4 FUN_802757e4();
extern undefined4 FUN_802757e8();
extern undefined4 FUN_802763c0();
extern uint FUN_80279008();
extern undefined4 FUN_8027975c();
extern uint FUN_8027976c();
extern undefined4 FUN_80279c7c();
extern undefined4 FUN_8027a2b4();
extern undefined4 FUN_8027a664();
extern int FUN_8027a8fc();
extern undefined4 FUN_8027a904();
extern undefined4 FUN_8027ac38();
extern undefined4 FUN_8027afc0();
extern undefined4 FUN_8028134c();
extern undefined4 FUN_80281a30();
extern uint FUN_80282070();
extern void* FUN_80282078();
extern undefined4 FUN_80282588();
extern undefined4 FUN_8028261c();
extern char FUN_80282620();
extern uint FUN_802827f8();
extern undefined4 FUN_80282fe0();
extern uint FUN_8028343c();
extern undefined4 FUN_80283444();
extern uint FUN_8028348c();
extern undefined4 FUN_802836ac();
extern undefined4 FUN_802836e8();
extern uint FUN_80283710();
extern bool FUN_80283844();
extern undefined4 FUN_80283850();
extern undefined4 FUN_80283ba0();
extern undefined4 FUN_80283bd4();
extern undefined4 FUN_80283e04();
extern undefined4 FUN_80283e08();
extern int FUN_80284468();
extern int FUN_80286718();
extern uint countLeadingZeros();

extern undefined4 DAT_8032fa4c;
extern undefined4 DAT_8032fc50;
extern undefined4 DAT_8032fc54;
extern undefined4 DAT_8032fc80;
extern undefined4 DAT_8032fc84;
extern undefined4 DAT_803303fc;
extern undefined4 DAT_803307fc;
extern undefined4 DAT_803bdfc0;
extern undefined4 DAT_803be654;
extern undefined4 DAT_803be694;
extern undefined DAT_803be6d4;
extern undefined DAT_803beb54;
extern undefined4 DAT_803deee8;
extern undefined4* DAT_803deeec;
extern undefined4 DAT_803def50;
extern int* DAT_803def54;
extern int* DAT_803def58;
extern undefined4 DAT_803def60;
extern undefined4 DAT_803def64;
extern undefined4 DAT_803def68;
extern f64 DOUBLE_803e8498;
extern f64 DOUBLE_803e84a0;
extern f32 FLOAT_803e8488;
extern f32 FLOAT_803e848c;
extern f32 FLOAT_803e8490;
extern f32 FLOAT_803e84a8;
extern f32 FLOAT_803e84ac;
extern void* PTR_DAT_8032fc70;
extern void* PTR_DAT_8032fca0;
extern undefined4 uRam803def6c;

extern u8 *lbl_803DE268;
extern u8 lbl_803BD150[];
extern int lbl_803DE2D4;
extern int lbl_803DE2D8;
extern int lbl_803DE2E0;
extern int lbl_803DE2E4;
extern void fn_8027132C(void *state);
extern void *fn_80274E7C(u32 key);
extern u16 seqGetMIDIPriority(u8 slot, u8 event);
extern u32 voiceAllocate(u8 priority, u8 maxInstances, s16 key, s8 streamKind);
extern void fn_80279038(int state);
extern void voiceSetPriority(int state, u8 newGroup);
extern u32 vidMakeNew(int state, int returnNewId);
extern int hwIsActive(int slot);
extern void hwBreak(int slot);
extern void fn_80279B98(int state);
extern void inpResetMidiCtrl(u8 a, u8 b, u32 mode);
extern void inpResetChannelDefaults(u8 a, u8 b);
void fn_80278990(int state);
void fn_802788B4(int state, int skipFadeReset);

/*
 * --INFO--
 *
 * Function: FUN_8027656c
 * EN v1.0 Address: 0x8027656C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802765AC
 * EN v1.1 Size: 600b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8027656c(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276570
 * EN v1.0 Address: 0x80276570
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276804
 * EN v1.1 Size: 640b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80276570(int param_1,undefined4 *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276574
 * EN v1.0 Address: 0x80276574
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276A84
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80276574(int param_1,uint *param_2,uint param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276578
 * EN v1.0 Address: 0x80276578
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80276B24
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80276578(uint param_1,short param_2)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80276580
 * EN v1.0 Address: 0x80276580
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276BA4
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80276580(int param_1,uint *param_2,int param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276584
 * EN v1.0 Address: 0x80276584
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276CD0
 * EN v1.1 Size: 416b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80276584(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276588
 * EN v1.0 Address: 0x80276588
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276E70
 * EN v1.1 Size: 308b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80276588(int param_1,int param_2,uint *param_3,undefined4 param_4,uint param_5,uint param_6
                 ,uint param_7)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8027658c
 * EN v1.0 Address: 0x8027658C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80276FA4
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8027658c(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80276590
 * EN v1.0 Address: 0x80276590
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80277108
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80276590(int param_1,int param_2,uint param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80276598
 * EN v1.0 Address: 0x80276598
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x8027716C
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_80276598(int param_1,int param_2,uint param_3)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802765a0
 * EN v1.0 Address: 0x802765A0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802771D4
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765a0(int param_1,int param_2,uint param_3,undefined4 param_4)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765a4
 * EN v1.0 Address: 0x802765A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80277238
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765a4(int param_1,uint *param_2,byte param_3)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765a8
 * EN v1.0 Address: 0x802765A8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80277368
 * EN v1.1 Size: 564b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765a8(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765ac
 * EN v1.0 Address: 0x802765AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8027759C
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765ac(int param_1,uint *param_2)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765b0
 * EN v1.0 Address: 0x802765B0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80277670
 * EN v1.1 Size: 5388b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765b0(int *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765b4
 * EN v1.0 Address: 0x802765B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80278B7C
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765b4(uint param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765b8
 * EN v1.0 Address: 0x802765B8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80278CC4
 * EN v1.1 Size: 176b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765b8(int *param_1)
{
}

/*
 * --INFO--
 *
 * Function: FUN_802765bc
 * EN v1.0 Address: 0x802765BC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80278D74
 * EN v1.1 Size: 244b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_802765bc(int *param_1)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802765c4
 * EN v1.0 Address: 0x802765C4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80278E68
 * EN v1.1 Size: 268b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_802765c4(int *param_1,int param_2)
{
}

/*
 * Large per-voice command dispatcher. Stubbed, but named so callers can
 * reference the recovered current EN boundary.
 */
#pragma dont_inline on
void fn_80276F0C(int state)
{
    (void)state;
}
#pragma dont_inline reset

/*
 * Advance the synth voice timer queue and process active voices.
 */
void fn_80278418(u32 delta)
{
    int timer;
    int active;
    u32 wakeLo;
    int wakeHi;
    int nextTimer;
    int hasAlt;

    timer = lbl_803DE2D8;
    while (active = lbl_803DE2D4, timer != 0) {
        wakeLo = *(u32 *)(timer + 0x9c);
        wakeHi = *(int *)(timer + 0x98);
        if (lbl_803DE2E0 < (u32)(lbl_803DE2E4 < wakeLo) + wakeHi) {
            break;
        }
        nextTimer = *(int *)(timer + 0x44);
        fn_80278990(timer);
        *(u32 *)(timer + 0xa4) = wakeLo;
        *(int *)(timer + 0xa0) = wakeHi;
        timer = nextTimer;
    }

    for (; active != 0; active = *(int *)(active + 0x3c)) {
        if (*(s8 *)(active + 0x68) == 0) {
            hasAlt = 0;
        } else {
            hasAlt = *(int *)(active + 0x54) != 0;
        }
        if (hasAlt && ((*(u32 *)(active + 0x118) & 0x20) == 0) &&
            hwIsActive(*(u32 *)(active + 0xf4) & 0xff) == 0 &&
            (*(s8 *)(active + 0x68) != 0 && *(int *)(active + 0x54) != 0)) {
            *(int *)(active + 0x38) = *(int *)(active + 0x60);
            *(int *)(active + 0x34) = *(int *)(active + 0x54);
            *(int *)(active + 0x54) = 0;
            fn_80278990(active);
        }
        fn_80276F0C(active);
    }
    lbl_803DE2E0 += CARRY4(lbl_803DE2E4, delta);
    lbl_803DE2E4 += delta;
}

/*
 * Resume an active voice from its alternate command stream when needed.
 */
void fn_80278560(int state)
{
    int resumed;

    if (*(int *)(state + 0x4c) == 1) {
        if (*(s8 *)(state + 0x68) == 0 || *(int *)(state + 0x54) == 0) {
            resumed = 0;
        } else {
            *(int *)(state + 0x38) = *(int *)(state + 0x60);
            *(int *)(state + 0x34) = *(int *)(state + 0x54);
            *(int *)(state + 0x54) = 0;
            fn_80278990(state);
            resumed = 1;
        }
        if (!resumed && ((*(u32 *)(state + 0x118) & 0x40000) != 0)) {
            fn_80278990(state);
        }
    }
}

/*
 * Mark a voice for key-off/release, falling back to its release stream.
 */
u32 fn_80278610(int state)
{
    int resumed;
    u32 result;

    result = *(u32 *)(state + 0x114);
    *(u32 *)(state + 0x118) |= 8;
    if (*(int *)(state + 0x34) != 0) {
        result = 0;
        if ((*(u32 *)(state + 0x114) & 0x100) == 0) {
            if (*(s8 *)(state + 0x68) == 0 || *(int *)(state + 0x50) == 0) {
                resumed = 0;
            } else {
                *(int *)(state + 0x38) = *(int *)(state + 0x5c);
                *(int *)(state + 0x34) = *(int *)(state + 0x50);
                *(int *)(state + 0x50) = 0;
                fn_80278990(state);
                resumed = 1;
            }
            if (!resumed) {
                result = *(u32 *)(state + 0x118) & 4;
                if (result != 0) {
                    fn_80278990(state);
                }
            }
        } else {
            *(u32 *)(state + 0x118) = *(u32 *)(state + 0x118);
            *(u32 *)(state + 0x114) |= 0x400;
        }
    }
    return result;
}

/*
 * Clear or defer the release request flag.
 */
void fn_80278704(int state, int defer)
{
    int resumed;

    if (defer == 0) {
        if (*(int *)(state + 0x34) != 0 && ((*(u32 *)(state + 0x114) & 0x400) != 0)) {
            if (*(s8 *)(state + 0x68) == 0 || *(int *)(state + 0x50) == 0) {
                resumed = 0;
            } else {
                *(int *)(state + 0x38) = *(int *)(state + 0x5c);
                *(int *)(state + 0x34) = *(int *)(state + 0x50);
                *(int *)(state + 0x50) = 0;
                fn_80278990(state);
                resumed = 1;
            }
            if (!resumed && ((*(u32 *)(state + 0x118) & 4) != 0)) {
                fn_80278990(state);
            }
        }
        *(u32 *)(state + 0x118) = *(u32 *)(state + 0x118);
        *(u32 *)(state + 0x114) &= 0xfffffaff;
    } else {
        *(u32 *)(state + 0x114) |= 0x100;
    }
}

/*
 * Insert a voice into the 64-bit wake-time queue sorted by 0x98:0x9c.
 */
void TimeQueueAdd(int state)
{
    int next;
    int prev;
    int cur;

    next = lbl_803DE2D8;
    prev = 0;
    while ((cur = next) != 0 &&
           (*(u32 *)(cur + 0x98) <
            (u32)(*(u32 *)(cur + 0x9c) < *(u32 *)(state + 0x9c)) +
                *(u32 *)(state + 0x98))) {
        prev = cur;
        next = *(int *)(cur + 0x44);
    }

    if (cur != 0) {
        *(int *)(state + 0x44) = cur;
        prev = *(int *)(cur + 0x48);
        *(int *)(state + 0x48) = prev;
        next = state;
        if (prev != 0) {
            *(int *)(*(int *)(cur + 0x48) + 0x44) = state;
            next = lbl_803DE2D8;
        }
        lbl_803DE2D8 = next;
        *(int *)(cur + 0x48) = state;
        return;
    }

    if (prev != 0) {
        *(int *)(prev + 0x44) = state;
        *(int *)(state + 0x48) = prev;
        *(int *)(state + 0x44) = 0;
        return;
    }

    lbl_803DE2D8 = state;
    *(int *)(state + 0x44) = 0;
    *(int *)(state + 0x48) = 0;
}

/*
 * Remove a voice from the time queue and clear its scheduled wake time.
 */
void fn_802788B4(int state, int skipFadeReset)
{
    int activeTimeHi;

    if ((*(u32 *)(state + 0x9c) | *(u32 *)(state + 0x98)) != 0) {
        if ((*(u32 *)(state + 0x9c) ^ 0xffffffff |
             *(u32 *)(state + 0x98) ^ 0xffffffff) != 0) {
            if (*(int *)(state + 0x48) == 0) {
                lbl_803DE2D8 = *(int *)(state + 0x44);
            } else {
                *(int *)(*(int *)(state + 0x48) + 0x44) = *(int *)(state + 0x44);
            }
            if (*(int *)(state + 0x44) != 0) {
                *(int *)(*(int *)(state + 0x44) + 0x48) = *(int *)(state + 0x48);
            }
        }
        if (skipFadeReset == 0) {
            fn_8027132C((void *)state);
        }
        *(int *)(state + 0x9c) = 0;
        *(int *)(state + 0x98) = 0;
        activeTimeHi = lbl_803DE2E0;
        *(int *)(state + 0xa4) = lbl_803DE2E4;
        *(int *)(state + 0xa0) = activeTimeHi;
        *(u32 *)(state + 0x118) &= 0xfffbfffb;
        *(u32 *)(state + 0x114) = *(u32 *)(state + 0x114);
    }
}

/*
 * Move a live voice back onto the active voice list.
 */
void fn_80278990(int state)
{
    int activeTimeHi;
    int hadHead;

    if (*(int *)(state + 0x4c) != 0) {
        if ((*(u32 *)(state + 0x9c) | *(u32 *)(state + 0x98)) != 0) {
            if ((*(u32 *)(state + 0x9c) ^ 0xffffffff |
                 *(u32 *)(state + 0x98) ^ 0xffffffff) != 0) {
                if (*(int *)(state + 0x48) == 0) {
                    lbl_803DE2D8 = *(int *)(state + 0x44);
                } else {
                    *(int *)(*(int *)(state + 0x48) + 0x44) = *(int *)(state + 0x44);
                }
                if (*(int *)(state + 0x44) != 0) {
                    *(int *)(*(int *)(state + 0x44) + 0x48) = *(int *)(state + 0x48);
                }
            }
            fn_8027132C((void *)state);
            *(int *)(state + 0x9c) = 0;
            *(int *)(state + 0x98) = 0;
            activeTimeHi = lbl_803DE2E0;
            *(int *)(state + 0xa4) = lbl_803DE2E4;
            *(int *)(state + 0xa0) = activeTimeHi;
            *(u32 *)(state + 0x118) &= 0xfffbfffb;
            *(u32 *)(state + 0x114) = *(u32 *)(state + 0x114);
        }
        hadHead = lbl_803DE2D4 != 0;
        *(int *)(state + 0x3c) = lbl_803DE2D4;
        if (hadHead) {
            *(int *)(lbl_803DE2D4 + 0x40) = state;
        }
        *(int *)(state + 0x40) = 0;
        lbl_803DE2D4 = state;
        *(int *)(state + 0x4c) = 0;
    }
}

/*
 * Change a voice list state, unlinking it from active or timer queues as needed.
 */
void fn_80278A98(int state, int mode)
{
    int activeTimeHi;

    if (*(int *)(state + 0x4c) == mode) {
        return;
    }
    if (*(int *)(state + 0x4c) == 0) {
        if (*(int *)(state + 0x40) == 0) {
            lbl_803DE2D4 = *(int *)(state + 0x3c);
        } else {
            *(int *)(*(int *)(state + 0x40) + 0x3c) = *(int *)(state + 0x3c);
        }
        if (*(int *)(state + 0x3c) != 0) {
            *(int *)(*(int *)(state + 0x3c) + 0x40) = *(int *)(state + 0x40);
        }
    }
    if (mode == 2) {
        if ((*(u32 *)(state + 0x9c) | *(u32 *)(state + 0x98)) != 0) {
            if ((*(u32 *)(state + 0x9c) ^ 0xffffffff |
                 *(u32 *)(state + 0x98) ^ 0xffffffff) != 0) {
                if (*(int *)(state + 0x48) == 0) {
                    lbl_803DE2D8 = *(int *)(state + 0x44);
                } else {
                    *(int *)(*(int *)(state + 0x48) + 0x44) = *(int *)(state + 0x44);
                }
                if (*(int *)(state + 0x44) != 0) {
                    *(int *)(*(int *)(state + 0x44) + 0x48) = *(int *)(state + 0x48);
                }
            }
            *(int *)(state + 0x9c) = 0;
            *(int *)(state + 0x98) = 0;
            activeTimeHi = lbl_803DE2E0;
            *(int *)(state + 0xa4) = lbl_803DE2E4;
            *(int *)(state + 0xa0) = activeTimeHi;
            *(u32 *)(state + 0x118) &= 0xfffbfffb;
            *(u32 *)(state + 0x114) = *(u32 *)(state + 0x114);
        }
    }
    *(int *)(state + 0x4c) = mode;
}

/*
 * Allocate and initialize a synth voice from an instrument/sample command.
 */
int fn_80278B94(u16 instrumentKey, u32 priority, u32 maxInstances, u32 baseSample,
                u8 keyFlags, u8 volume, u8 pan, u32 midiSlot, u8 midiEvent, u8 midiLayer,
                u16 sampleOffsetIndex, u8 studio, u8 returnNewId, u8 auxA, u8 auxB,
                int startImmediately)
{
    int instrument;
    u8 streamKey;
    u32 midiPriority;
    u32 voiceId;
    int wasActive;
    int vid;
    int state;
    int hadHead;

    instrument = (int)fn_80274E7C(instrumentKey);
    if (instrument != 0) {
        streamKey = keyFlags & 0x80;
        if (streamKey == 0) {
            midiPriority = seqGetMIDIPriority(midiEvent, midiSlot);
            if ((midiPriority & 0xffff) != 0xffff) {
                priority = midiPriority & 0xff;
            }
        }
        voiceId = voiceAllocate(priority, maxInstances, baseSample, streamKey != 0);
        if (voiceId != 0xffffffff) {
            state = (int)(lbl_803DE268 + voiceId * 0x404);
            fn_80279038(state);
            if (*(int *)(state + 0x4c) != 2) {
                if (*(int *)(state + 0x4c) == 0) {
                    if (*(int *)(state + 0x40) == 0) {
                        lbl_803DE2D4 = *(int *)(state + 0x3c);
                    } else {
                        *(int *)(*(int *)(state + 0x40) + 0x3c) = *(int *)(state + 0x3c);
                    }
                    if (*(int *)(state + 0x3c) != 0) {
                        *(int *)(*(int *)(state + 0x3c) + 0x40) = *(int *)(state + 0x40);
                    }
                }
                fn_802788B4(state, 1);
                *(int *)(state + 0x4c) = 2;
            }

            *(u32 *)(state + 0x118) = (*(u32 *)(state + 0x118) & 0x10) | 2;
            *(int *)(state + 0x114) = 0;
            wasActive = hwIsActive(voiceId);
            if (wasActive != 0) {
                *(u32 *)(state + 0x118) |= 1;
            }
            *(int *)(state + 0x9c) = 0;
            *(int *)(state + 0x98) = 0;
            if (streamKey == 0) {
                *(u8 *)(state + 0x11d) = 0;
                *(u8 *)(state + 0x20a) = (u8)midiSlot;
                *(u8 *)(state + 0x20b) = midiEvent;
                *(u8 *)(state + 0x20c) = midiLayer;
            } else {
                *(u8 *)(state + 0x11d) = 1;
                keyFlags &= 0x7f;
                inpResetMidiCtrl(voiceId & 0xff, 0xff, 1);
                inpResetChannelDefaults(voiceId & 0xff, 0xff);
                *(u8 *)(state + 0x20a) = voiceId;
                *(u8 *)(state + 0x20b) = 0xff;
                *(u8 *)(state + 0x20c) = 0;
            }

            *(u16 *)(state + 0x102) = instrumentKey;
            *(s16 *)(state + 0x100) = (s16)baseSample;
            *(u32 *)(state + 0x110) = 0x75300000;
            *(u16 *)(state + 0x10e) = 0x400;
            *(int *)(state + 0x34) = instrument;
            *(u32 *)(state + 0x38) = instrument + (u32)sampleOffsetIndex * 8;
            *(u8 *)(state + 0x12f) = keyFlags;
            *(u16 *)(state + 0x12c) = keyFlags;
            *(u8 *)(state + 0x12e) = 0;
            *(u8 *)(state + 0x208) = volume;
            *(u8 *)(state + 0x209) = pan;
            *(u8 *)(state + 0x20d) = studio;
            *(u8 *)(state + 0x8c) = 0;
            *(u8 *)(state + 0x8d) = 0;
            *(int *)(state + 0xec) = -1;
            *(int *)(state + 0xf0) = -1;
            *(int *)(state + 0x108) = -1;
            *(u8 *)(state + 0x20e) = auxA;
            *(u8 *)(state + 0x20f) = auxB;
            *(u8 *)(state + 0x210) = startImmediately == 0;
            *(u8 *)(state + 0x3ee) = 0;
            *(u8 *)(state + 0x3ed) = 0;
            *(u8 *)(state + 0x3ec) = 0;
            *(u32 *)(state + 0xf4) = voiceId | ((u32)instrumentKey << 0x10) |
                                      ((u32)keyFlags << 8);
            voiceSetPriority(state, priority);
            vid = vidMakeNew(state, returnNewId);
            if (vid != -1) {
                if (*(int *)(state + 0x4c) == 0) {
                    return vid;
                }
                fn_802788B4(state, 0);
                hadHead = lbl_803DE2D4 != 0;
                *(int *)(state + 0x3c) = lbl_803DE2D4;
                if (hadHead) {
                    *(int *)(lbl_803DE2D4 + 0x40) = state;
                }
                *(int *)(state + 0x40) = 0;
                lbl_803DE2D4 = state;
                *(int *)(state + 0x4c) = 0;
                return vid;
            }
            wasActive = hwIsActive(voiceId);
            if (wasActive != 0) {
                hwBreak(voiceId);
            }
            fn_80279B98(state);
        }
    }
    return -1;
}

/*
 * Reset the global voice list heads and per-voice list bookkeeping.
 */
void fn_80278EA4(void)
{
    int offset;
    u32 i;

    lbl_803DE2E4 = 0;
    offset = 0;
    lbl_803DE2D4 = 0;
    lbl_803DE2D8 = 0;
    lbl_803DE2E0 = 0;
    for (i = 0; i < *(u32 *)(lbl_803BD150 + 0x210); i++) {
        *(u32 *)(lbl_803DE268 + offset + 0x34) = 0;
        *(u32 *)(lbl_803DE268 + offset + 0x4c) = 2;
        *(u16 *)(lbl_803DE268 + offset + 0xaa) = 0;
        offset += 0x404;
    }
}

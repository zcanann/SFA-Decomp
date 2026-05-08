#include "src/main/audio/synth_internal.h"

#ifndef NULL
#define NULL ((void*)0)
#endif

extern void* fn_80275128(int sceneId, void* outBuf);
extern int inpGetMidiCtrl(int ctrl, int slot, int key);
extern int fn_8026F630(int key, int slot, int chan, int unk, int* outFlags);
extern int fn_8026FC8C(u8 a0, u8 a1, int a2, int a3, int a4, u32 a5, u32 a6,
                        u8 a7, u32 a8, int a9, u32 aA, u32 aB, u32 aC, u32 aD,
                        u32 aE, u32 aF);
extern int fn_80278B94(u8 a0, u8 a1, int a2, int a3, int a4, u32 a5, u32 a6,
                        u8 a7, u32 a8, int a9, u32 aA, u32 aB, u32 aC, u32 aD,
                        u32 aE, u32 aF);
extern int vidMakeRoot(void* slotPtr);

extern u8* lbl_803DE268;

typedef struct SynthBuf {
    u16 count;
    u16 pad;
} SynthBuf;

int fn_8026F8B8(
    int sceneId, int chan, int slot, int unk4,
    int velPair, char unk6, int prog, int unkR10,
    char arg9, char arg10, short arg11, short arg12,
    int arg13, char arg14, char arg15, int arg16
) {
    SynthBuf buf;
    int hoist40, hoist3c, hoist48, hoist44;
    char* p;
    int handle = -1;
    int subResult;
    int range_lo;
    int chosen_key;
    int useFlag;

    p = (char*)fn_80275128(sceneId, &buf);
    if (p == NULL) {
        return handle;
    }

    hoist40 = (u8)prog;
    hoist3c = (u8)unk6;
    hoist48 = 0x8000;
    hoist44 = 0x81020409;
    range_lo = velPair & 0x7F;
    velPair = velPair & 0x80;

    while (buf.count != 0) {
        u16 rec0;
        rec0 = *(u16*)p;
        if (rec0 != 0xFFFF) {
            if ((u32)*((u8*)p + 2) <= (u32)range_lo &&
                (u32)*((u8*)p + 3) >= (u32)range_lo) {
                int off = (signed char)*((u8*)p + 4);
                chosen_key = range_lo + off;
                if (chosen_key > 0x7F) chosen_key = 0x7F;
                else if (chosen_key < 0) chosen_key = 0;

                useFlag = 1;
                if ((rec0 & 0xC000) == 0) {
                    if ((u16)inpGetMidiCtrl(0x41, arg9, unkR10) > 0x1F80) {
                        int outVal = 0;
                        subResult = fn_8026F630(chosen_key & 0x7F, arg9, 0, unkR10, &outVal);
                        useFlag = (outVal == 0);
                    } else {
                        subResult = -1;
                        useFlag = 1;
                    }
                    if (useFlag != 0 && (subResult & 0xFFFF0000) != 0xFFFF0000) {
                        goto skipDispatch;
                    }
                }

                /* dispatch via 0xC000 mask */
                {
                    u8 flag8 = *((u8*)p + 8);
                    int v;
                    if ((flag8 & 0x80) == 0) {
                        v = (flag8 - 0x40) + hoist40;
                        if (v < 0) v = 0;
                        else if (v > 0x7F) v = 0x7F;
                    } else {
                        v = 0x80;
                    }
                    {
                        u8 e5 = *((u8*)p + 5);
                        s16 e67 = *(s16*)(p + 6);
                        int prod = hoist3c * e5;
                        int magic = (int)(((long long)hoist44 * prod) >> 32);
                        magic = magic + prod;
                        unk4 = unk4 + e67;
                        magic = (magic >> 6) + ((unsigned)magic >> 31);
                        magic = (u8)magic;
                        if ((short)unk4 > 0xFF) unk4 = 0xFF;
                        else if ((short)unk4 < 0) unk4 = 0;
                        unk4 = (short)unk4;

                        switch (rec0 & 0xC000) {
                        case 0x4000:
                            subResult = fn_8026FC8C((u8)arg9, (u8)arg10, chan, slot, (u8)unk4,
                                                    (u32)(chosen_key | velPair), 0, (u8)magic,
                                                    arg11, (int)unkR10, arg14, arg13, arg12,
                                                    arg15, 0, arg16);
                            break;
                        case 0:
                            subResult = fn_8026F8B8(arg9, chan, slot, (u8)unk4, velPair,
                                                    unk6, chosen_key, unkR10, arg11,
                                                    (char)magic, arg12, arg13, 0, arg14,
                                                    arg15, arg16);
                            break;
                        case 0x8000:
                        default:
                            subResult = fn_80278B94((u8)arg9, (u8)arg10, chan, slot, (u8)unk4,
                                                    (u32)(chosen_key | velPair), 0, (u8)magic,
                                                    arg11, (int)unkR10, arg14, arg13, arg12,
                                                    arg15, 0, arg16);
                            break;
                        }
                    }
                    if ((subResult & 0xFFFF0000) == 0xFFFF0000) goto nextIter;
                }

skipDispatch:
                if ((handle & 0xFFFF0000) == 0xFFFF0000) {
                    if (arg13 != 0) {
                        u8 idx = (u8)subResult;
                        u32* slotData = (u32*)(lbl_803DE268 + idx * 0x404);
                        handle = vidMakeRoot(slotData);
                    } else {
                        handle = subResult;
                    }
                } else {
                    u8 prevIdx = (u8)handle;
                    u8 newIdx = (u8)subResult;
                    *(int*)(lbl_803DE268 + prevIdx * 0x404 + 0xEC) = subResult;
                    *(int*)(lbl_803DE268 + newIdx * 0x404 + 0xF0) = handle;
                }
                {
                    u32 cur = (u32)handle;
                    while (1) {
                        u8 idx = (u8)cur;
                        u32 next = *(u32*)(lbl_803DE268 + idx * 0x404 + 0xEC);
                        if ((next & 0xFFFF0000) == 0xFFFF0000) {
                            *(u8*)(lbl_803DE268 + idx * 0x404 + 0x11C) = 1;
                            break;
                        }
                        *(u8*)(lbl_803DE268 + idx * 0x404 + 0x11C) = 1;
                        cur = next;
                    }
                }
            }
        }
nextIter:
        p += 0xC;
        buf.count--;
    }

    return handle;
}

#include "ghidra_import.h"

extern int synthGetNextChannelEvent(u8 i);
extern void synthInsertChannelEvent(int slot, int item);

extern int gSynthCurrentVoice;
extern int gSynthCurrentVoiceSlotIndex;
extern u32 *gSynthFreeCallbacks;

extern u8 *synthReadVariablePair(u8 *p, u16 *tagOut, s16 *valueOut);
extern void inpSetMidiCtrl(int controller, u8 slot, u8 key, u8 value);
extern void inpSetMidiCtrl14(int controller, u8 slot, u8 key, u16 data);
extern void inpResetMidiCtrl(u8 a, u8 b, u32 mode);
extern void synthStartHandleFromRequest(int request, u32 *outHandle, u8 noLock);
extern void synthFlushCallbacks(void);
extern u32 *synthAllocCallback(s32 triggerValue, u8 controllerIndex);
extern int audioFn_8026feec(u32 sampleId, char key, u32 velocity, u32 flags, u32 volume, u32 pan,
                            u32 param_7, u32 param_8, u8 param_9, u16 param_10, u16 param_11,
                            u8 auxIndex, int keyOffset, u8 studio, u32 studioAux);

extern u8 lbl_803AF550[];
extern u8 lbl_803BDA24[];
extern u8 lbl_803DE224;

typedef struct {
    u16 macroId; // 0x0
    u8 a;        // 0x2
    u8 b;        // 0x3
    u16 unk4;    // 0x4
} SynthPatchEntry; // size 0x6

typedef struct {
    u16 macroId; // 0x0
    u8 a;        // 0x2
    u8 b;        // 0x3
} SynthChanPatch; // size 0x4

typedef struct {
    u16 tag;  // 0x0
    u16 unk2; // 0x2
    u16 unk4; // 0x4
} SynthVarTag; // size 0x6

typedef struct {
    u32 unk0;     // 0x0
    u32 unk4;     // 0x4
    u32 dataPtr;  // 0x8
    u32 eventPtr; // 0xc
    u32 pitchCur; // 0x10
    u16 pitchVal; // 0x14
    s16 pitchStep; // 0x16
    u32 pitchTime; // 0x18
    u32 modCur;   // 0x1c
    u16 modVal;   // 0x20
    s16 modStep;  // 0x22
    u32 modTime;  // 0x24
    u8 chan;      // 0x28
    u8 pad29[3];  // 0x29
} SynthChanRec; // size 0x2c

typedef struct {
    u8 pad0[0x10];               // 0x0
    SynthPatchEntry *patchTable; // 0x10
    u8 progs[0x80];              // 0x14
    SynthPatchEntry *drumTable;  // 0x94
    u8 drumProgs[0x80];          // 0x98
    u8 *seqData;                 // 0x118
    u32 chanBits[8];             // 0x11c
    u8 pad13C[0x1e8];            // 0x13c
    u8 chanMap[0x40];            // 0x324
    SynthChanRec records[0x40];  // 0x364
    u32 cbHeads[3];              // 0xe64
    SynthChanPatch chanPatch[16]; // 0xe70
    u8 padEB0[4];                // 0xeb0
    u8 startRequest[0x28];       // 0xeb4
    u32 *handleOut;              // 0xedc
    u8 startPending;             // 0xee0
    u8 studioIndex;              // 0xee1
} SynthMidiState;

typedef struct {
    u8 pad0[0xd740];
    u16 midiCtrl[8][16]; // 0xd740
} SynthMidiCtrlBlock;

/*
 * Dispatch a queued voice/MIDI channel event by type, then pull the next
 * event for the channel.
 */
#pragma dont_inline on
int fn_8026E0E4(int event, u8 voice, u32 *flag)
{
    SynthMidiCtrlBlock *base = (SynthMidiCtrlBlock *)lbl_803AF550;
    u16 timeVal2;
    u16 timeVal;
    u16 pbVal2;
    u16 pbVal1;

    switch (*(u8 *)(event + 0x14)) {
    case 4: {
        u8 *d = *(u8 **)(event + 0xc);
        SynthMidiState *sv = (SynthMidiState *)gSynthCurrentVoice;
        u8 *seq = sv->seqData;
        SynthChanRec *rec = &sv->records[*(u8 *)(event + 0x15)];
        u8 *t = seq + *(u32 *)(seq + *(u16 *)(d + 8) * 4 + *(u32 *)(seq + 4));
        u8 prog;

        rec->dataPtr = (u32)(t + 0xc);
        rec->unk0 = 0;
        rec->unk4 = *(u32 *)d;
        rec->eventPtr = (u32)d;
        if (*(u32 *)(t + 4) != 0) {
            if ((rec->pitchCur =
                     (u32)synthReadVariablePair((u8 *)(*(u32 *)(t + 4) +
                                                       (u32)((SynthMidiState *)gSynthCurrentVoice)->seqData),
                                                &timeVal2, &rec->pitchStep)) != 0) {
                rec->pitchTime = timeVal2;
            } else {
                rec->pitchTime = 0x7fffffff;
            }
        } else {
            rec->pitchTime = 0x7fffffff;
        }
        rec->pitchVal = 0x2000;
        if (*(u32 *)(t + 8) != 0) {
            if ((rec->modCur =
                     (u32)synthReadVariablePair((u8 *)(*(u32 *)(t + 8) +
                                                       (u32)((SynthMidiState *)gSynthCurrentVoice)->seqData),
                                                &timeVal, &rec->modStep)) != 0) {
                rec->modTime = timeVal;
            } else {
                rec->modTime = 0x7fffffff;
            }
        } else {
            rec->modTime = 0x7fffffff;
        }
        rec->modVal = 0;
        rec->chan = *(u8 *)((u32)((SynthMidiState *)gSynthCurrentVoice)->seqData + *(u8 *)(event + 0x15) +
                            *(u32 *)(((SynthMidiState *)gSynthCurrentVoice)->seqData + 8));
        prog = *(u8 *)(d + 4);
        if (prog != 0xff) {
            SynthMidiState *sv2 = (SynthMidiState *)gSynthCurrentVoice;
            u8 chan = rec->chan;
            u32 idx;

            base->midiCtrl[gSynthCurrentVoiceSlotIndex][chan] = 0xFFFF;
            if (chan != 9) {
                idx = sv2->progs[prog];
                if (idx != 0xff) {
                    sv2->chanPatch[chan].macroId = sv2->patchTable[idx].macroId;
                    sv2->chanPatch[chan].a = sv2->patchTable[idx].a;
                    sv2->chanPatch[chan].b = sv2->patchTable[idx].b;
                }
            } else {
                idx = sv2->drumProgs[prog];
                if (idx != 0xff) {
                    sv2->chanPatch[chan].macroId = sv2->drumTable[idx].macroId;
                    sv2->chanPatch[chan].a = sv2->drumTable[idx].a;
                    sv2->chanPatch[chan].b = sv2->drumTable[idx].b;
                }
            }
        }
        if (*(u8 *)(d + 5) != 0xff) {
            inpSetMidiCtrl(7, rec->chan, gSynthCurrentVoiceSlotIndex & 0xff, *(u8 *)(d + 5));
        }
        break;
    }
    case 0: {
        u32 chan;
        u8 *d = *(u8 **)(event + 0xc);
        u8 *t = *(u8 **)(event + 0x10);
        u8 d2 = *(u8 *)(d + 2);
        u8 d3 = *(u8 *)(d + 3);

        chan = *(u8 *)(t + 0x28);
        if (d2 & 0x80) {
            switch (d3) {
            case 0: {
                SynthMidiState *sv = (SynthMidiState *)gSynthCurrentVoice;
                u32 p7;
                u32 idx;

                base->midiCtrl[gSynthCurrentVoiceSlotIndex][chan] = 0xFFFF;
                p7 = d2 & 0x7f;
                if (chan != 9) {
                    idx = sv->progs[p7];
                    if (idx != 0xff) {
                        sv->chanPatch[chan].macroId = sv->patchTable[idx].macroId;
                        sv->chanPatch[chan].a = sv->patchTable[idx].a;
                        sv->chanPatch[chan].b = sv->patchTable[idx].b;
                    }
                } else {
                    idx = sv->drumProgs[p7];
                    if (idx != 0xff) {
                        sv->chanPatch[chan].macroId = sv->drumTable[idx].macroId;
                        sv->chanPatch[chan].a = sv->drumTable[idx].a;
                        sv->chanPatch[chan].b = sv->drumTable[idx].b;
                    }
                }
                break;
            }
            case 1:
                inpSetMidiCtrl(0x82, chan, gSynthCurrentVoiceSlotIndex & 0xff, d2 & 0x7f);
                break;
            default:
                if ((d3 & 0x80) == 0x80) {
                    switch (d3 & 0x7f) {
                    case 0x68:
                        if (((SynthMidiState *)gSynthCurrentVoice)->startPending != 0) {
                            synthStartHandleFromRequest((int)((SynthMidiState *)gSynthCurrentVoice)->startRequest,
                                                        ((SynthMidiState *)gSynthCurrentVoice)->handleOut, 1);
                            ((SynthMidiState *)gSynthCurrentVoice)->startPending = 0;
                        }
                        break;
                    case 0x69:
                        base->midiCtrl[gSynthCurrentVoiceSlotIndex][chan] = d2 & 0x7f;
                        break;
                    case 0x6a:
                        base->midiCtrl[gSynthCurrentVoiceSlotIndex][chan] = (d2 & 0x7f) + 0x80;
                        break;
                    case 0x79:
                        inpResetMidiCtrl(chan, gSynthCurrentVoiceSlotIndex & 0xff, 0);
                        break;
                    case 0x7b:
                        synthFlushCallbacks();
                        break;
                    default:
                        inpSetMidiCtrl(d3 & 0x7f, chan, gSynthCurrentVoiceSlotIndex & 0xff, d2 & 0x7f);
                        break;
                    }
                }
                break;
            }
        } else {
            SynthMidiState *sv = (SynthMidiState *)gSynthCurrentVoice;
            if (sv->chanBits[*(u8 *)(event + 0x15) / 32] & (1 << (*(u8 *)(event + 0x15) & 0x1f))) {
                u16 macroId = sv->chanPatch[chan].macroId;
                if (macroId != 0xFFFF) {
                    u8 *d6 = *(u8 **)(t + 0xc);
                    int sum = d2 + *(s8 *)(d6 + 0xa);
                    int key;
                    int sum2;
                    int vel;
                    u32 *cb;

                    if (sum > 0x7f) {
                        key = 0x7f;
                    } else if (sum < 0) {
                        key = 0;
                    } else {
                        key = sum;
                    }
                    sum2 = d3 + *(s8 *)(d6 + 0xb);
                    if (sum2 > 0x7f) {
                        vel = 0x7f;
                    } else if (sum2 < 0) {
                        vel = 0;
                    } else {
                        vel = sum2;
                    }
                    cb = synthAllocCallback(*(u32 *)(event + 8) + *(u16 *)(d + 4), voice);
                    if (cb != NULL) {
                        SynthMidiState *sv2;
                        s16 mod;
                        u8 vt;
                        u32 vid;
                        u32 *head;

                        if (lbl_803DE224 != 0) {
                            mod = -1;
                        } else {
                            mod = 0;
                        }
                        sv2 = (SynthMidiState *)gSynthCurrentVoice;
                        vt = sv2->studioIndex;
                        vid = audioFn_8026feec(macroId, sv2->chanPatch[chan].a, sv2->chanPatch[chan].b,
                                               key & 0xff, vel & 0xff, 0x40, chan,
                                               gSynthCurrentVoiceSlotIndex & 0xff, voice, 0,
                                               *(u8 *)(event + 0x15), sv2->chanMap[*(u8 *)(event + 0x15)],
                                               mod, vt, lbl_803BDA24[vt * 2]);
                        cb[2] = vid;
                        if (vid == 0xFFFFFFFF) {
                            if (cb[0] != 0) {
                                *(u32 *)(cb[0] + 4) = cb[1];
                            }
                            if (cb[1] != 0) {
                                *(u32 *)cb[1] = cb[0];
                            } else {
                                SynthMidiState *sv3 = (SynthMidiState *)gSynthCurrentVoice;
                                sv3->cbHeads[*((u8 *)cb + 0x11)] = cb[0];
                            }
                            head = gSynthFreeCallbacks;
                            cb[0] = (u32)head;
                            if (head != NULL) {
                                gSynthFreeCallbacks[1] = (u32)cb;
                            }
                            cb[1] = 0;
                            gSynthFreeCallbacks = cb;
                        }
                    }
                }
            }
        }
        break;
    }
    case 2: {
        u8 *t = *(u8 **)(event + 0x10);

        *(u16 *)(t + 0x14) += *(s16 *)(t + 0x16);
        if (*(u8 **)(t + 0x10) != NULL) {
            if ((*(u32 *)(t + 0x10) = (u32)synthReadVariablePair(*(u8 **)(t + 0x10), &pbVal2,
                                                                 (s16 *)(t + 0x16))) != 0) {
                *(u32 *)(t + 0x18) += pbVal2;
            } else {
                *(u32 *)(t + 0x18) = 0x7fffffff;
            }
        } else {
            *(u32 *)(t + 0x18) = 0x7fffffff;
        }
        inpSetMidiCtrl14(0x80, *(u8 *)(t + 0x28), gSynthCurrentVoiceSlotIndex & 0xff, *(u16 *)(t + 0x14));
        break;
    }
    case 1: {
        u8 *t = *(u8 **)(event + 0x10);

        *(u16 *)(t + 0x20) += *(s16 *)(t + 0x22);
        if (*(u8 **)(t + 0x1c) != NULL) {
            if ((*(u32 *)(t + 0x1c) = (u32)synthReadVariablePair(*(u8 **)(t + 0x1c), &pbVal1,
                                                                 (s16 *)(t + 0x22))) != 0) {
                *(u32 *)(t + 0x24) += pbVal1;
            } else {
                *(u32 *)(t + 0x24) = 0x7fffffff;
            }
        } else {
            *(u32 *)(t + 0x24) = 0x7fffffff;
        }
        inpSetMidiCtrl14(1, *(u8 *)(t + 0x28), gSynthCurrentVoiceSlotIndex & 0xff, *(u16 *)(t + 0x20));
        break;
    }
    case 3:
        *flag |= 1;
        return 0;
    }
    return synthGetNextChannelEvent(*(u8 *)(event + 0x15));
}
#pragma dont_inline reset

/*
 * Iterate 64 voice slots: for each active one, append it to the studio's
 * voice list. Uses an indirection table when present.
 *
 * EN v1.1 Address: 0x8026E864, size 168b
 */
void fn_8026E864(void)
{
    u32 i;
    u32 x;
    if (*(u32 *)(gSynthCurrentVoice + 0x14e4) == 0) {
        for (i = 0; i < 0x40; i++) {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0) {
                synthInsertChannelEvent(gSynthCurrentVoice + 0x14e8, x);
            }
        }
    } else {
        for (i = 0; i < 0x40; i++) {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0) {
                u8 *table = *(u8 **)(gSynthCurrentVoice + 0x14e4);
                synthInsertChannelEvent(gSynthCurrentVoice + table[i] * 0x38 + 0x14e8, x);
            }
        }
    }
}

void fn_8026E90C(u8 voice)
{
    u32 group;
    u32 queueOffset;
    u32 i;
    u32 x;

    if (*(u32 *)(gSynthCurrentVoice + 0x14e4) == 0) {
        for (i = 0; i < 0x40; i++) {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0) {
                synthInsertChannelEvent(gSynthCurrentVoice + 0x14e8, x);
            }
        }
    } else {
        group = voice & 0xff;
        queueOffset = group * 0x38;
        for (i = 0; i < 0x40; i++) {
            if (group == *(u8 *)(*(u32 *)(gSynthCurrentVoice + 0x14e4) + i)) {
                x = synthGetNextChannelEvent((u8)i);
                if (x != 0) {
                    synthInsertChannelEvent(gSynthCurrentVoice + queueOffset + 0x14e8, x);
                }
            }
        }
    }
}

extern int fn_8026CF78(u8 voice);

extern void fn_8026E90C(u8 voice);
extern f32 floorf(f32 x);
extern f32 lbl_803E7780;
extern f32 lbl_803E7784;
extern f32 lbl_803E7788;

#pragma dont_inline on
#pragma fp_contract off
int fn_8026E9D0(u8 voice, u32 param)
{
    u8 *vp;
    u8 *vp2;
    u8 *event;
    u32 v;
    int res;
    f32 k80;
    f32 k84;
    f32 k88;
    f64 k88abs;
    f32 ftotal;
    f32 fm;
    u32 flag;

    flag = 0;
    k88 = lbl_803E7788;
    k88abs = __fabs(k88);
    k80 = lbl_803E7780;
    k84 = lbl_803E7784;
    vp = (u8 *)(gSynthCurrentVoice + voice * 56 + 0x14e8);
    while (((event = *(u8 **)(vp + 0x1c)) == NULL ? 0 : *(u32 *)(event + 8))
           <= *(u32 *)(vp + *(u8 *)(vp + 0x30) * 8 + 0x24)) {
        if (event != NULL) {
            *(u8 **)(vp + 0x1c) = *(u8 **)event;
            if (*(int *)event != 0) {
                *(int *)(*(int *)(vp + 0x1c) + 4) = 0;
            }
        }
        if (event != NULL) {
            res = fn_8026E0E4((int)event, voice, &flag);
            if (res != 0) {
                synthInsertChannelEvent((int)vp, res);
            }
        } else {
            if (flag == 0) {
                return 0;
            }
            flag = 0;
            *(u8 *)(vp + 0x30) ^= 1;
            *(u32 *)(vp + *(u8 *)(vp + 0x30) * 8 + 0x24) = *(u32 *)(*(int *)(gSynthCurrentVoice + 0x118) + voice * 4 + 0x14);
            *(u32 *)(vp + *(u8 *)(vp + 0x30) * 8 + 0x20) = *(u32 *)(vp + (*(u8 *)(vp + 0x30) ^ 1) * 8 + 0x20);
            if (*(void **)(gSynthCurrentVoice + voice * 56 + 0x14e8) != NULL) {
                *(int *)(gSynthCurrentVoice + voice * 56 + 0x14ec) = *(int *)(gSynthCurrentVoice + voice * 56 + 0x14e8);
                fn_8026CF78(voice);
                vp2 = (u8 *)(gSynthCurrentVoice + voice * 56 + 0x14e8);
                fm = k80 * ((f32)*(u32 *)(vp2 + 8) * (f32)param) * (k84 * (f32)*(u16 *)(vp2 + 0x32));
                ftotal = k88 * fm;
                if (k88abs > __fabs(ftotal)) {
                } else {
                    ftotal -= k88 * (f32)(s64)(u64)(ftotal / k88);
                }
                *(u32 *)(vp2 + *(u8 *)(vp2 + 0x30) * 8 + 0xc) = (u32)ftotal;
                *(u32 *)(vp2 + *(u8 *)(vp2 + 0x30) * 8 + 0x10) = (int)floorf(fm);
            }
            *(u16 *)(vp + 0x34) += 1;
            fn_8026E90C(voice);
        }
    }
    return 1;
}
#pragma fp_contract reset
#pragma dont_inline reset

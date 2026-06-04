#include "ghidra_import.h"
#include "main/audio/inp_ctrl.h"
#include "main/audio/inp_midi.h"

typedef struct SynthDelayedNode {
    struct SynthDelayedNode *next;
    struct SynthDelayedNode *prev;
    u8 voiceIndex;
    u8 bucketIndex;
    u8 pad[2];
} SynthDelayedNode;

typedef void (*SynthDelayedBucketCallback)(int voiceIndex);

typedef struct SynthDelayStorageLocal {
    u32 studioChannelScales[9][0x10];
    SynthDelayedNode *bucketHeads[0x20][3];
} SynthDelayStorageLocal;

#define SYNTH_FADE_COUNT 0x20
#define SYNTH_FADE_TABLE_OFFSET 0x5d4
#define SYNTH_FADE_DELAY_ACTION_FREE_HANDLE 1
#define SYNTH_FADE_DELAY_ACTION_QUEUE_HANDLE 2
#define SYNTH_FADE_DELAY_ACTION_CLEAR_MIX 3
#define SYNTH_VOICE_SLOT_SIZE 0x404
#define SYNTH_VOICE_CALLBACK_ACTIVE_OFFSET 0x11c

typedef struct SynthFade {
    f32 current;
    f32 target;
    f32 start;
    f32 progress;
    f32 progressStep;
    f32 auxCurrent;
    f32 auxTarget;
    f32 auxStart;
    f32 auxProgress;
    f32 auxProgressStep;
    u32 handle;
    u8 delayAction;
    u8 type;
    u8 pad[2];
} SynthFade;

extern SynthDelayStorageLocal gSynthDelayStorage;
extern u8 gSynthDelayBucketCursor;
extern void synthQueueDelayedUpdate(SynthDelayedNode *fade, int mode, u32 delay);
extern void synthQueueHandle(u32 handle);
extern void synthFreeHandle(u32 handle);
extern void synthSetHandleMixData(u32 handle, u32 mixValue0, u32 mixValue1);
extern void macHandle(u32 delta);
extern u8 hwGetTimeOffset(void);
extern void hwFrameDone(void);
extern u8 lbl_803BCD90[];
extern u32 synthMasterFaderPauseActiveFlags;
extern u32 synthMasterFaderActiveFlags;
extern u8 synthAuxBMIDI;
extern u8 synthAuxBIndex;
extern u8 synthAuxAMIDI;
extern u8 synthAuxAIndex;
extern u8 *synthVoice;
extern int synthRealTimeHi;
extern int synthRealTimeLo;
extern f32 lbl_803E77D0;

typedef void (*SynthAuxCallback)(int active, u16 *samples, u32 user);

extern u8 *dataGetKeymap(u32 sampleId);
extern int audioFn_8026f630(u32 key, u32 slot, u32 channel, u32 voiceGroup, u32 *outFlags);
extern int audioLayerFn_8026f8b8(u32 sampleId, int key, u32 velocity, u32 baseSample, u32 flags, u32 volume,
                       u32 pan, u32 param_8, u32 param_9, u32 param_10, u32 param_11,
                       u32 param_12, u32 param_13, u32 param_14, u32 param_15, u32 param_16);
extern int audioFn_80278b94(u32 sampleId, int key, u32 velocity, u32 baseSample, u32 flags, u32 volume,
                       u32 pan, u32 param_8, u32 param_9, u32 param_10, u32 param_11,
                       u32 param_12, u32 param_13, u32 param_14, u32 param_15, u32 param_16);
extern u32 vidGetInternalId(u32 handle);

/*
 * Resolve an indirection-table sample entry, then dispatch the resolved
 * sample or nested sample group.
 */
int audioKeymapFn_8026fc8c(u32 sampleId, s16 key, u32 velocity, u32 baseSample, u32 flags, u32 volume,
                u32 pan, u32 param_8, u32 param_9, u32 param_10, u32 param_11, u32 param_12,
                u32 param_13, u32 param_14, u32 param_15, u32 param_16)
{
    u8 *table;
    u8 *entry;
    u16 resolvedSample;
    u32 adjustedPan;
    s32 adjustedKey;
    u32 allow;
    int handle;
    u32 outFlags;

    table = dataGetKeymap(sampleId);
    if (table != 0) {
        entry = table + ((flags & 0x7f) * 8);
        if (*(s16 *)entry != -1) {
            resolvedSample = *(u16 *)entry;
            if ((resolvedSample & 0xc000) != 0x4000) {
                if ((entry[3] & 0x80) == 0) {
                    adjustedPan = (entry[3] - 0x40) + (pan & 0xff);
                    if ((s32)adjustedPan < 0) {
                        adjustedPan = 0;
                    } else if ((s32)adjustedPan < 0x80) {
                        adjustedPan &= 0xff;
                    } else {
                        adjustedPan = 0x7f;
                    }
                } else {
                    adjustedPan = 0x80;
                }
                adjustedKey = (flags & 0x7f) + *(s8 *)(entry + 2);
                if (adjustedKey >= 0x80) {
                    adjustedKey = 0x7f;
                } else if (adjustedKey < 0) {
                    adjustedKey = 0;
                }
                key = key + *(s16 *)(entry + 4);
                if (key >= 0x100) {
                    key = 0xff;
                } else if (key < 0) {
                    key = 0;
                }
                if ((resolvedSample & 0xc000) == 0) {
                    if ((u16)inpGetMidiCtrl(0x41, param_8, param_9) < 0x1f81) {
                        handle = -1;
                        allow = 1;
                    } else {
                        handle = audioFn_8026f630(adjustedKey & 0x7f, param_8, param_9, param_13,
                                             &outFlags);
                        allow = __cntlzw(outFlags) >> 5;
                    }
                    if (allow == 0) {
                        return -1;
                    }
                    if (handle != -1) {
                        return handle;
                    }
                    return audioFn_80278b94(resolvedSample, key & 0xff, velocity, baseSample,
                                       adjustedKey | (flags & 0x80), volume, adjustedPan, param_8,
                                       param_9, param_10, param_11, param_12, param_13 & 0xff,
                                       param_14, param_15, param_16);
                }
                return audioLayerFn_8026f8b8(resolvedSample, key, velocity, baseSample,
                                   adjustedKey | (flags & 0x80), volume, adjustedPan, param_8,
                                   param_9, param_10, param_11, param_12, param_13 & 0xff,
                                   param_14, param_15, param_16);
            }
        }
    }
    return -1;
}

/*
 * Start a sample/FX id, handling direct samples, table-expanded sample
 * groups, and already-linked voice chains.
 */
int audioFn_8026feec(u32 sampleId, char key, u32 velocity, u32 flags, u32 volume, u32 pan, u32 param_7,
                u32 param_8, u8 param_9, u16 param_10, u16 param_11, u8 auxIndex, s16 keyOffset,
                u8 studio, u32 studioAux)
{
    u32 sampleClass;
    int handle;
    u32 voice;
    u8 *slot;
    u32 outFlags;
    u32 adjustedKey;

    adjustedKey = key + keyOffset;
    if ((u8)adjustedKey > 0xff) {
        adjustedKey = 0xff;
    }
    adjustedKey &= 0xff;
    sampleClass = sampleId & 0xc000;
    if (sampleClass == 0x4000) {
        handle = audioKeymapFn_8026fc8c(sampleId, adjustedKey, velocity, sampleId, flags, volume, pan, param_7,
                             param_8, param_9, param_10, param_11, 1, auxIndex, studio,
                             studioAux);
        if (handle != -1) {
            voice = vidGetInternalId(handle);
            while (voice != 0xffffffff) {
                slot = synthVoice + ((voice & 0xff) * 0x404);
                slot[0x11c] = 0;
                voice = *(u32 *)(slot + 0xec);
            }
        }
    } else {
        if (sampleClass == 0) {
            if ((u16)inpGetMidiCtrl(0x41, param_7, param_8) < 0x1f81) {
                handle = -1;
                sampleClass = 1;
            } else {
                handle = audioFn_8026f630(flags & 0x7f, param_7, param_8, 1, &outFlags);
                sampleClass = __cntlzw(outFlags) >> 5;
            }
            if (sampleClass == 0) {
                return -1;
            }
            if (handle != -1) {
                return handle;
            }
            return audioFn_80278b94(sampleId, adjustedKey, velocity, sampleId, flags, volume, pan, param_7,
                               param_8, param_9, param_10, param_11, 1, auxIndex, studio,
                               studioAux);
        }
        if (sampleClass == 0x8000) {
            handle = audioLayerFn_8026f8b8(sampleId, adjustedKey, velocity, sampleId, flags, volume, pan, param_7,
                                 param_8, param_9, param_10, param_11, 1, auxIndex, studio,
                                 studioAux);
            if (handle == -1) {
                return -1;
            }
            voice = vidGetInternalId(handle);
            while (voice != 0xffffffff) {
                slot = synthVoice + ((voice & 0xff) * 0x404);
                slot[0x11c] = 0;
                voice = *(u32 *)(slot + 0xec);
            }
            return handle;
        }
        handle = -1;
    }
    return handle;
}

typedef struct SynthVoiceLfo {
    s32 time;
    u32 period;
    s16 value;
    s16 lastValue;
} SynthVoiceLfo;

typedef struct SynthVoiceAdsr {
    u8 unk00[8];
    s32 currentVolume;
    u8 unk0C[0x28 - 0x0C];
} SynthVoiceAdsr;

/* Hardware synth voice state (MusyX SYNTH_VOICE), one 0x404-byte slot per voice. */
typedef struct SynthHwVoice {
    u8 unk000[0x24];
    u32 lastLowCallTimeHi;   /* 0x024 */
    u32 lastLowCallTimeLo;   /* 0x028 */
    u32 lastZeroCallTimeHi;  /* 0x02C */
    u32 lastZeroCallTimeLo;  /* 0x030 */
    u8* addr;                /* 0x034 */
    u8 unk038[0xA8 - 0x38];
    u8 timeUsedByInput;      /* 0x0A8 */
    u8 unk0A9[0x10C - 0xA9];
    u8 prio;                 /* 0x10C */
    u8 unk10D;
    u16 ageSpeed;            /* 0x10E */
    u32 age;                 /* 0x110 */
    u32 cFlagsHi;            /* 0x114 */
    u32 cFlagsLo;            /* 0x118 */
    u8 callbackActive;       /* 0x11C */
    u8 fxFlag;               /* 0x11D */
    u8 vGroup;               /* 0x11E */
    u8 studio;               /* 0x11F */
    u8 track;                /* 0x120 */
    u8 midi;                 /* 0x121 */
    u8 midiSet;              /* 0x122 */
    u8 unk123;
    u32 sInfo;               /* 0x124 */
    u8 unk128[4];
    u16 curNote;             /* 0x12C */
    s8 curDetune;            /* 0x12E */
    u8 unk12F;
    u8 lastNote;             /* 0x130 */
    u8 portType;             /* 0x131 */
    u16 portLastCtrlState;   /* 0x132 */
    u32 portDuration;        /* 0x134 */
    u32 portCurPitch;        /* 0x138 */
    u32 portTime;            /* 0x13C */
    u8 vibKeyRange;          /* 0x140 */
    u8 vibCentRange;         /* 0x141 */
    u8 unk142[2];
    u32 vibPeriod;           /* 0x144 */
    u32 vibCurTime;          /* 0x148 */
    s32 vibCurOffset;        /* 0x14C */
    s16 vibModAddScale;      /* 0x150 */
    u8 unk152[2];
    u32 volume;              /* 0x154 */
    u8 unk158[4];
    f32 lastVolFaderScale;   /* 0x15C */
    u32 lastPan;             /* 0x160 */
    u32 lastSPan;            /* 0x164 */
    f32 treCurScale;         /* 0x168 */
    u16 treScale;            /* 0x16C */
    u16 treModAddScale;      /* 0x16E */
    u32 panning[2];          /* 0x170 */
    u32 panDelta[2];         /* 0x178 */
    u32 panTarget[2];        /* 0x180 */
    u32 panTime[2];          /* 0x188 */
    u8 revVolScale;          /* 0x190 */
    u8 revVolOffset;         /* 0x191 */
    u8 volTable;             /* 0x192 */
    u8 unk193;
    s32 envDelta;            /* 0x194 */
    s32 envTarget;           /* 0x198 */
    s32 envCurrent;          /* 0x19C */
    s32 sweepOff[2];         /* 0x1A0 */
    s32 sweepAdd[2];         /* 0x1A8 */
    s32 sweepCnt[2];         /* 0x1B0 */
    u8 sweepNum[2];          /* 0x1B8 */
    u8 unk1BA[2];
    SynthVoiceLfo lfo[2];    /* 0x1BC */
    u8 lfoUsedByInput[2];    /* 0x1D4 */
    u8 pbLowerKeyRange;      /* 0x1D6 */
    u8 pbUpperKeyRange;      /* 0x1D7 */
    u16 pbLast;              /* 0x1D8 */
    u8 unk1DA[2];
    SynthVoiceAdsr pitchADSR; /* 0x1DC */
    s16 pitchADSRRange;      /* 0x204 */
    u16 curPitch;            /* 0x206 */
    u8 unk208[0x214 - 0x208];
    u32 midiDirtyFlags;      /* 0x214 */
    u8 unk218[0x400 - 0x218];
    u16 curOutputVolume;     /* 0x400 */
    u8 unk402[2];
} SynthHwVoice;

#define HWVOICE(i) ((SynthHwVoice*)(synthVoice + (i) * 0x404))
#define HWVOICE_FLAGS(sv) (*(u64*)&(sv)->cFlagsHi)

typedef struct SynthMasterFader {
    f32 volume;
    u8 unk04[0x10];
    f32 pauseVol;
    u8 unk18[0x30 - 0x18];
} SynthMasterFader;

#define SYNTH_MASTER_FADERS ((SynthMasterFader*)(lbl_803BCD90 + 0x5D4))
#define SYNTH_TRACK_VOLUME (lbl_803BCD90 + 0xBD4)

extern u32 voiceGetPitchRatio(u8 note, u32 sInfo);
extern u16 voiceScaleSampleRate(u32 rate);
extern void hwSetPitch(u32 voice, u16 pitch);
extern void hwSetVolume(u32 voice, u8 table, f32 vol, u32 pan, u32 span, f32 auxa, f32 auxb);
extern void hwSetPriority(u32 voice, u32 prio);
extern void hwStart(u32 voice, u8 studio);
extern void hwKeyOff(u32 voice);
extern void macSetPedalState(SynthHwVoice* sv, u32 state);
extern u32 fn_8027AC34(SynthVoiceAdsr* adsr, u16* start, u16* delta);
extern u32 fn_8027AA50(SynthVoiceAdsr* adsr);
extern u32 synthFlags;
extern const f32 lbl_803E7798;
extern const f32 lbl_803E779C;
extern const f32 lbl_803E77A0;
extern const f32 lbl_803E77A4;
extern const f32 lbl_803E77A8;
extern const f32 lbl_803E77AC;
extern const f32 lbl_803E77B0;
extern const f32 lbl_803E77B4;
extern const f32 lbl_803E77B8;

/*
 * Low-precision per-voice update: LFOs, vibrato, pitch sweeps, pan ramps,
 * pitch bend/portamento and final pitch computation (LowPrecisionHandler).
 *
 * EN v1.0 Address: 0x80270184, size 1972b
 */
void audioFn_80270184(int voice)
{
    u32 j;
    s32 pbend;
    u32 ccents;
    u32 cpitch;
    u16 Modulation;
    u16 portamento;
    u32 lowDeltaTime;
    SynthHwVoice* sv;
    u32 cntDelta;
    u32 addFactor;
    u16 adsr_start;
    u16 adsr_delta;
    s32 vrange;
    s32 voff;

    sv = HWVOICE(voice);
    if (!hwIsActive(voice) && sv->addr == 0) {
        goto end;
    }

    lowDeltaTime = synthRealTimeLo - sv->lastLowCallTimeLo;
    sv->lastLowCallTimeLo = synthRealTimeLo;
    sv->lastLowCallTimeHi = synthRealTimeHi;

    for (j = 0; j < 2; ++j) {
        if (sv->lfo[j].period == 0) {
            continue;
        }
        sv->lfo[j].time += lowDeltaTime;
        sv->lfo[j].value = sndSin((sv->lfo[j].time % sv->lfo[j].period * 16) / (sv->lfo[j].period / 256));
        if (sv->lfo[j].value != sv->lfo[j].lastValue) {
            sv->lfo[j].lastValue = sv->lfo[j].value;
            if (sv->lfoUsedByInput[j]) {
                sv->lfoUsedByInput[j] = 0;
                sv->midiDirtyFlags |= 0x1FFF;
            }
        }
    }

    if ((HWVOICE_FLAGS(sv) & 0x2000) != 0) {
        sv->vibCurTime += lowDeltaTime;
        sv->vibCurOffset = sndSin((sv->vibCurTime % sv->vibPeriod * 16) / (sv->vibPeriod / 256));
    }

    if (sv->sweepNum[0] | sv->sweepNum[1]) {
        cntDelta = (lowDeltaTime << 8) >> 4;
        addFactor = (lowDeltaTime << 4) >> 4;
        for (j = 0; j < 2; ++j) {
            if (sv->sweepNum[j] == 0) {
                continue;
            }
            sv->sweepCnt[j] -= cntDelta;
            if (sv->sweepCnt[j] <= 0) {
                sv->sweepCnt[j] = sv->sweepNum[j] << 16;
                sv->sweepOff[j] = 0;
            } else {
                sv->sweepOff[j] += (sv->sweepAdd[j] >> 12) * addFactor;
            }
        }
    }

    for (j = 0; j < 2; ++j) {
        u32 p;
        if (sv->panning[j] == sv->panTarget[j]) {
            continue;
        }
        sv->panTime[j] -= lowDeltaTime;
        if ((s32)sv->panTime[j] <= 0) {
            sv->panning[j] = sv->panTarget[j];
            sv->panTime[j] = 0;
        } else {
            sv->panning[j] = sv->panTarget[j] - (sv->panTime[j] / 256) * sv->panDelta[j];
            p = sv->panning[j];
            if ((s32)p < 0) {
                p = 0;
            } else if (p > 0x7F0000) {
                p = 0x7F0000;
            }
            sv->panning[j] = p;
        }
        HWVOICE_FLAGS(sv) |= 0x200000000000ULL;
    }

    if ((HWVOICE_FLAGS(sv) & 0x20000000000ULL) != 0 &&
        fn_8027AC34(&sv->pitchADSR, &adsr_start, &adsr_delta)) {
        HWVOICE_FLAGS(sv) &= ~0x20000000000ULL;
    }

    ccents = (sv->curNote << 16) + (sv->curDetune * 0x10000) / 100;
    if ((HWVOICE_FLAGS(sv) & 0x10030) != 0) {
        if (sv->midi != 0xFF) {
            pbend = (u16)inpGetPitchBend((McmdVoiceState*)sv);
            sv->pbLast = pbend;
            goto pbend_adjust;
        }
    } else {
        pbend = sv->pbLast;
    pbend_adjust:
        if (pbend != 0x2000) {
            pbend -= 0x2000;
            if (pbend < 0) {
                ccents += sv->pbLowerKeyRange * pbend * 8;
            } else {
                ccents += sv->pbUpperKeyRange * pbend * 8;
            }
        }
    }

    if ((HWVOICE_FLAGS(sv) & 0x2000) != 0) {
        Modulation = inpGetModulation((McmdVoiceState*)sv);
        vrange = sv->vibKeyRange * 256 + (sv->vibCentRange * 256) / 100;
        if (sv->vibModAddScale != 0) {
            vrange += (sv->vibModAddScale * ((Modulation >> 7) & 0x1FF)) >> 7;
        }
        if ((HWVOICE_FLAGS(sv) & 0x4000) != 0) {
            voff = (sv->vibCurOffset * ((Modulation >> 7) & 0x1FF)) >> 7;
        } else {
            voff = sv->vibCurOffset;
        }
        ccents += (vrange * voff) >> 4;
    }

    if (sv->midi != 0xFF) {
        portamento = inpGetMidiCtrl(0x41, sv->midi, sv->midiSet);
        if (portamento != sv->portLastCtrlState || (HWVOICE_FLAGS(sv) & 0x21000) == 0x20000) {
            if (portamento <= 0x1F80) {
                HWVOICE_FLAGS(sv) &= ~0x400;
            } else {
                if ((HWVOICE_FLAGS(sv) & 0x400) == 0) {
                    /* synthInitPortamento, inlined */
                    if ((HWVOICE_FLAGS(sv) & 0x20000) == 0) {
                        if (sv->portType == 1) {
                            if ((HWVOICE_FLAGS(sv) & 0x1000) == 0) {
                                sv->portTime = 0;
                            } else {
                                sv->portTime = sv->portDuration;
                            }
                        } else {
                            sv->portTime = sv->portDuration;
                        }
                        sv->portCurPitch = sv->lastNote << 16;
                    }
                }
                HWVOICE_FLAGS(sv) |= 0x400;
            }
            HWVOICE_FLAGS(sv) |= 0x1000;
            sv->portLastCtrlState = portamento;
        }
    }

    /* apply_portamento, inlined */
    if ((HWVOICE_FLAGS(sv) & 0x400) != 0 && (s32)((sv->portDuration - sv->portTime) >> 8) > 0) {
        u32 old_portCurPitch = sv->portCurPitch;
        sv->portCurPitch += (s32)lowDeltaTime * ((s32)(ccents - sv->portCurPitch) >> 8) /
                            (s32)((sv->portDuration - sv->portTime) >> 8);
        if ((old_portCurPitch < ccents && sv->portCurPitch < ccents) ||
            (old_portCurPitch > ccents && sv->portCurPitch > ccents)) {
            ccents = sv->portCurPitch;
            sv->portTime += lowDeltaTime;
        } else {
            sv->portTime = sv->portDuration;
        }
    }

    if ((HWVOICE_FLAGS(sv) & 0x20000000000ULL) != 0) {
        ccents += sv->pitchADSRRange * (sv->pitchADSR.currentVolume >> 16) >> 7;
    }

    /* convert_cents, inlined */
    cpitch = voiceGetPitchRatio(ccents >> 16, sv->sInfo) << 16;
    if ((j = ccents & 0xFFFF) != 0) {
        cpitch += j * (voiceScaleSampleRate(cpitch >> 16) - (cpitch >> 16));
    }

    cpitch += sv->sweepOff[0] + sv->sweepOff[1];
    hwSetPitch(voice, sv->curPitch = ((cpitch >> 16) * inpGetDoppler((McmdVoiceState*)sv)) >> 13);
    synthQueueDelayedUpdate((SynthDelayedNode*)sv, 0, 0xF00);

end:
    /* UpdateTimeMIDICtrl, inlined */
    if (sv->timeUsedByInput != 0) {
        sv->timeUsedByInput = 0;
        sv->midiDirtyFlags = 0x1FFF;
    }
}

/*
 * Zero-offset per-voice update: volume envelope, tremolo, panning and final
 * volume/aux sends (ZeroOffsetHandler).
 *
 * EN v1.0 Address: 0x80270938, size 1712b
 */
void fn_80270938(int voice)
{
    SynthHwVoice* sv;
    u32 lowDeltaTime;
    u16 Modulation;
    f32 vol;
    f32 auxa;
    f32 auxb;
    f32 f;
    f32 voiceVol;
    u32 volUpdate;
    f32 lfo;
    f32 scale;
    s32 pan;
    f32 preVol;
    f32 postVol;
    s32 lfoInt;

    sv = HWVOICE(voice);
    if (!hwIsActive(voice) && sv->addr == 0) {
        goto end;
    }

    lowDeltaTime = synthRealTimeLo - sv->lastZeroCallTimeLo;
    sv->lastZeroCallTimeLo = synthRealTimeLo;
    sv->lastZeroCallTimeHi = synthRealTimeHi;

    if ((HWVOICE_FLAGS(sv) & 0x8000) != 0) {
        sv->envCurrent += sv->envDelta * (lowDeltaTime >> 8);
        if (sv->envDelta < 0) {
            if (sv->envTarget >= sv->envCurrent) {
                sv->envCurrent = sv->envTarget;
                HWVOICE_FLAGS(sv) &= ~0x8000;
            }
        } else if (sv->envTarget <= sv->envCurrent) {
            sv->envCurrent = sv->envTarget;
            HWVOICE_FLAGS(sv) &= ~0x8000;
        }
        sv->volume = sv->envCurrent;
        volUpdate = 1;
    } else {
        volUpdate = (HWVOICE_FLAGS(sv) & 0x100000000000ULL) != 0;
    }

    HWVOICE_FLAGS(sv) &= ~0x100000000000ULL;

    f = SYNTH_MASTER_FADERS[sv->vGroup].pauseVol * SYNTH_MASTER_FADERS[sv->vGroup].volume *
        SYNTH_MASTER_FADERS[sv->fxFlag ? 22 : 21].volume;

    if (sv->track != 0xFF) {
        vol = lbl_803E7798 * (f * (f32)SYNTH_TRACK_VOLUME[sv->track]);
    } else {
        vol = f;
    }

    if (vol != sv->lastVolFaderScale) {
        sv->lastVolFaderScale = vol;
        volUpdate = 1;
    }

    voiceVol = lbl_803E779C * (f32)sv->volume;

    if ((sv->treScale | sv->treModAddScale) != 0) {
        Modulation = inpGetModulation((McmdVoiceState*)sv);
        lfoInt = 0x2000 - ((0x2000 - ((s16)inpGetTremolo((McmdVoiceState*)sv) - 0x2000)) >> 1);
        lfo = lbl_803E77A0 * (f32)lfoInt;
        scale = lbl_803E77A4 *
                ((f32)sv->treScale *
                 (lbl_803E77A8 - lbl_803E77AC * ((f32)Modulation * (f32)(0x1000 - sv->treModAddScale))));
        if (sv->treCurScale < scale) {
            if ((sv->treCurScale += lbl_803E77B0) > scale) {
                sv->treCurScale = scale;
            }
        } else if (sv->treCurScale > scale) {
            if ((sv->treCurScale -= lbl_803E77B0) < scale) {
                sv->treCurScale = scale;
            }
        }
        voiceVol = voiceVol * (lbl_803E77A8 - lfo * (lbl_803E77A8 - sv->treCurScale));
        volUpdate = 1;
    }

    if ((synthFlags & 1) == 0) {
        if ((HWVOICE_FLAGS(sv) & 0x200000000000ULL) != 0 || (sv->midiDirtyFlags & 0x6) != 0) {
            HWVOICE_FLAGS(sv) &= ~0x200000000000ULL;
            pan = sv->panning[0] + (inpGetPanning((McmdVoiceState*)sv) - 0x2000) * 0x200;
            if (pan < 0) {
                pan = 0;
            } else if (pan > 0x7F0000) {
                pan = 0x7F0000;
            }
            sv->lastPan = pan;

            if ((synthFlags & 2) != 0) {
                if ((sv->lastSPan = sv->panning[1] + (u16)inpGetSurPanning((McmdVoiceState*)sv) * 0x200) > 0x7F0000) {
                    sv->lastSPan = 0x7F0000;
                }
            } else {
                sv->lastSPan = 0;
            }
            volUpdate = 1;
        } else if ((synthFlags & 2) == 0) {
            sv->lastSPan = 0;
        }
    } else {
        sv->lastPan = 0x400000;
        sv->lastSPan = 0;
        volUpdate |= (HWVOICE_FLAGS(sv) & 0x200000000000ULL) != 0;
        HWVOICE_FLAGS(sv) &= ~0x200000000000ULL;
    }

    if (volUpdate || (sv->midiDirtyFlags & 0xF01) != 0) {
        preVol = voiceVol;
        postVol = lbl_803E77B4 * (voiceVol * vol * (f32)inpGetVolume((McmdVoiceState*)sv));
        auxa = lbl_803E7798 * (f32)sv->revVolOffset +
               (lbl_803E77B4 * (preVol * (f32)inpGetPreAuxA((McmdVoiceState*)sv)) +
                lbl_803E7798 * ((f32)sv->revVolScale * (lbl_803E77B4 * (postVol * (f32)inpGetReverb((McmdVoiceState*)sv)))));
        auxb = lbl_803E77B4 * (preVol * (f32)inpGetPreAuxB((McmdVoiceState*)sv)) +
               lbl_803E77B4 * (postVol * (f32)inpGetPostAuxB((McmdVoiceState*)sv));
        sv->curOutputVolume = (u16)(lbl_803E77B8 * postVol);
        hwSetVolume(voice, sv->volTable, postVol, sv->lastPan, sv->lastSPan, auxa, auxb);
    }

    if (sv->age != 0) {
        if ((s32)(sv->age -= sv->ageSpeed * lowDeltaTime) < 0) {
            sv->age = 0;
        }
        hwSetPriority(voice, sv->prio << 24 | sv->age >> 15);
    }

    synthQueueDelayedUpdate((SynthDelayedNode*)sv, 1, (5 - hwGetTimeOffset()) * 256);

end:
    if (sv->timeUsedByInput != 0) {
        sv->timeUsedByInput = 0;
        sv->midiDirtyFlags = 0x1FFF;
    }
}

/*
 * Event per-voice update: pedal state, deferred hardware start and key-off
 * (EventHandler).
 *
 * EN v1.0 Address: 0x80270FE8, size 400b
 */
void fn_80270FE8(int voice)
{
    SynthHwVoice* sv;

    sv = HWVOICE(voice);
    if (!hwIsActive(voice) && sv->addr == 0) {
        goto end;
    }

    macSetPedalState(sv, inpGetPedal((McmdVoiceState*)sv) > 0x1F80);

    if ((HWVOICE_FLAGS(sv) & 0x20) != 0) {
        HWVOICE_FLAGS(sv) &= ~0x20;
        HWVOICE_FLAGS(sv) |= 0x10;
        hwStart(voice, sv->studio);
    }

    if ((HWVOICE_FLAGS(sv) & 0x10000000090ULL) == 0x90) {
        HWVOICE_FLAGS(sv) &= ~0x90;
        hwKeyOff(voice);
        if ((HWVOICE_FLAGS(sv) & 0x20000000000ULL) != 0 && fn_8027AA50(&sv->pitchADSR)) {
            HWVOICE_FLAGS(sv) &= ~0x20000000000ULL;
        }
    }

end:
    if (sv->timeUsedByInput != 0) {
        sv->timeUsedByInput = 0;
        sv->midiDirtyFlags = 0x1FFF;
    }
}

/*
 * Queue one of a fade's embedded delayed-action nodes into the 32-bucket
 * scheduler ring.
 *
 * EN v1.1 Address: 0x80271178, size 336b
 */
void synthQueueDelayedUpdate(SynthDelayedNode *fade, int mode, u32 delay)
{
    u32 bucket;
    SynthDelayStorageLocal *storage;
    SynthDelayedNode *node;
    SynthDelayedNode **head;

    bucket = gSynthDelayBucketCursor + (delay >> 8);
    bucket &= 0x1f;
    storage = &gSynthDelayStorage;
    head = &storage->bucketHeads[bucket][0];
    switch (mode) {
    case 0:
        node = fade;
        if (node->bucketIndex != 0xff) {
            if (node->bucketIndex == bucket) {
                return;
            }
            if (node->next != 0) {
                node->next->prev = node->prev;
            }
            if (node->prev == 0) {
                storage->bucketHeads[node->bucketIndex][0] = node->next;
            } else {
                node->prev->next = node->next;
            }
        }
        break;
    case 1:
        node = fade + 1;
        if (node->bucketIndex != 0xff) {
            if (node->bucketIndex == bucket) {
                return;
            }
            if (node->next != 0) {
                node->next->prev = node->prev;
            }
            if (node->prev == 0) {
                storage->bucketHeads[node->bucketIndex][2] = node->next;
            } else {
                node->prev->next = node->next;
            }
        }
        head = &storage->bucketHeads[bucket][2];
        break;
    case 2:
        node = fade + 2;
        if (node->bucketIndex != 0xff) {
            return;
        }
        head = &storage->bucketHeads[bucket][1];
        break;
    default:
        return;
    }
    node->bucketIndex = bucket;
    node->next = *head;
    if (*head != 0) {
        (*head)->prev = node;
    }
    node->prev = 0;
    *head = node;
}

/*
 * Reset four pos/timer fields on the handle, then advance both
 * channels (modes 0 and 1).
 *
 * EN v1.1 Address: 0x802712C8, size 100b
 */
void fn_802712C8(SynthDelayedNode *fade)
{
    {
        int a = synthRealTimeHi;
        int b = synthRealTimeLo;
        *(int *)((u8 *)fade + 0x24) = a;
        *(int *)((u8 *)fade + 0x28) = b;
    }
    {
        int a = synthRealTimeHi;
        int b = synthRealTimeLo;
        *(int *)((u8 *)fade + 0x2c) = a;
        *(int *)((u8 *)fade + 0x30) = b;
    }
    synthQueueDelayedUpdate(fade, 0, 0);
    synthQueueDelayedUpdate(fade, 1, 0);
}

/*
 * Advance both channels (modes 0 and 1) of the handle.
 *
 * EN v1.1 Address: 0x8027132C, size 68b
 */
void synthQueueVoicePrimaryUpdates(SynthDelayedNode *fade)
{
    synthQueueDelayedUpdate(fade, 0, 0);
    synthQueueDelayedUpdate(fade, 1, 0);
}

/*
 * Wrapper for synthQueueDelayedUpdate(handle, 2, 0).
 *
 * EN v1.1 Address: 0x80271370, size 40b
 */
void synthQueueVoiceInputUpdate(SynthDelayedNode *fade)
{
    synthQueueDelayedUpdate(fade, 2, 0);
}

/*
 * Walk a voice linked-list, marking each entry's slot 9 as 0xff and
 * invoking the callback for entries whose voice's 0x11c field is 0.
 *
 * EN v1.1 Address: 0x80271398, size 148b
 */
#pragma dont_inline on
void synthDrainDelayedBucket(SynthDelayedNode **head, SynthDelayedBucketCallback callback)
{
    SynthDelayedNode *node = *head;
    while (node != 0) {
        SynthDelayedNode *next = node->next;
        node->bucketIndex = 0xff;
        {
            int voiceIndex = node->voiceIndex;
            if (*(u8 *)(synthVoice + voiceIndex * SYNTH_VOICE_SLOT_SIZE +
                        SYNTH_VOICE_CALLBACK_ACTIVE_OFFSET) == 0) {
                callback(voiceIndex);
            }
        }
        node = next;
    }
    *head = 0;
}
#pragma dont_inline reset

/*
 * Dispatch a completed fade action based on its type byte.
 *
 * EN v1.1 Address: 0x8027142C, size 108b
 */
void synthDispatchFadeAction(SynthFade *fade)
{
    u8 action;

    action = fade->delayAction;
    switch (action) {
    case SYNTH_FADE_DELAY_ACTION_FREE_HANDLE:
        synthFreeHandle(fade->handle);
        break;
    case SYNTH_FADE_DELAY_ACTION_QUEUE_HANDLE:
        synthQueueHandle(fade->handle);
        break;
    case SYNTH_FADE_DELAY_ACTION_CLEAR_MIX:
        synthSetHandleMixData(fade->handle, 0, 0);
        break;
    }
}

/*
 * Periodic synth tick: drains delayed-action buckets, advances fade ramps,
 * runs AUX callbacks, and advances the global synth timer.
 *
 * EN v1.1 Address: 0x80271498, size 792b
 */
void audioFn_80271498(u32 delta)
{
    u8 *stateBase;
    SynthDelayStorageLocal *storage;
    u32 bucket;
    u32 fadeIndex;
    u32 mask;
    f32 *fade;
    f32 zeroThreshold;
    f32 fadeDelta;
    u32 i;
    u32 channel;
    u16 auxSamplesA[8];
    u16 auxSamplesB[6];

    stateBase = lbl_803BCD90;
    if (*(u32 *)(stateBase + 0x3c4) != 0) {
        storage = (SynthDelayStorageLocal *)stateBase;
        macHandle(delta);
        bucket = gSynthDelayBucketCursor;
        synthDrainDelayedBucket(&storage->bucketHeads[bucket][0], audioFn_80270184);
        synthDrainDelayedBucket(&storage->bucketHeads[bucket][1], fn_80270FE8);
        synthDrainDelayedBucket(&storage->bucketHeads[bucket][2], fn_80270938);
        gSynthDelayBucketCursor = (gSynthDelayBucketCursor + 1) & 0x1f;
        if (hwGetTimeOffset() == 0) {
            if ((synthMasterFaderActiveFlags | synthMasterFaderPauseActiveFlags) != 0) {
                zeroThreshold = lbl_803E77D0;
                fade = (f32 *)(stateBase + SYNTH_FADE_TABLE_OFFSET);
                mask = 1;
                for (fadeIndex = 0; fadeIndex < SYNTH_FADE_COUNT; fadeIndex++) {
                    if ((synthMasterFaderActiveFlags & mask) != 0) {
                        fadeDelta = fade[3] * (fade[1] - fade[2]);
                        fade[0] = fade[1] - fadeDelta;
                        fade[3] = fade[3] - fade[4];
                        if (fade[3] <= zeroThreshold) {
                            fade[0] = fade[1];
                            synthDispatchFadeAction((SynthFade *)fade);
                            synthMasterFaderActiveFlags &= ~mask;
                            if ((synthMasterFaderActiveFlags == 0) && (synthMasterFaderPauseActiveFlags == 0)) {
                                break;
                            }
                        }
                    }
                    if ((synthMasterFaderPauseActiveFlags & mask) != 0) {
                        fadeDelta = fade[8] * (fade[6] - fade[7]);
                        fade[5] = fade[6] - fadeDelta;
                        fade[8] = fade[8] - fade[9];
                        if (fade[8] <= zeroThreshold) {
                            fade[5] = fade[6];
                            synthMasterFaderPauseActiveFlags &= ~mask;
                            if ((synthMasterFaderPauseActiveFlags == 0) && (synthMasterFaderActiveFlags == 0)) {
                                break;
                            }
                        }
                    }
                    mask <<= 1;
                    fade += 12;
                }
            }
            for (i = 0; i < 8; i++) {
                if ((&synthAuxAIndex)[i] != 0xff) {
                    for (channel = 0; channel < 4; channel++) {
                        auxSamplesA[channel] =
                            inpGetAuxA(i & 0xff, channel & 0xff, (&synthAuxAIndex)[i],
                                         (&synthAuxAMIDI)[i]);
                    }
                    (*(SynthAuxCallback *)(stateBase + 0xc34 + i * 4))(
                        1, auxSamplesA, *(u32 *)(stateBase + 0xc14 + i * 4));
                }
                if ((&synthAuxBIndex)[i] != 0xff) {
                    for (channel = 0; channel < 4; channel++) {
                        auxSamplesB[channel] =
                            inpGetAuxB(i & 0xff, channel & 0xff, (&synthAuxBIndex)[i],
                                         (&synthAuxBMIDI)[i]);
                    }
                    (*(SynthAuxCallback *)(stateBase + 0xc74 + i * 4))(
                        1, auxSamplesB, *(u32 *)(stateBase + 0xc54 + i * 4));
                }
            }
        }
        hwFrameDone();
        {
            u32 carry = CARRY4(synthRealTimeLo, delta);
            synthRealTimeLo += delta;
            synthRealTimeHi += carry;
        }
    }
}

/*
 * synthFXStart - start an FX sample by id, applying default volume/pan sentinels.
 */
typedef struct SynthFxSampleInfo {
    u8 pad00[2];
    u16 sampleId;
    u8 velocity;
    u8 key;
    u8 defaultVolume;
    u8 defaultPan;
    u8 flags;
    u8 auxIndex;
} SynthFxSampleInfo;

extern SynthFxSampleInfo *dataGetFX(u32 fxId);

int synthFXStart(u32 fxId, u32 volume, u32 pan, u32 studio, u8 studioAux)
{
    SynthFxSampleInfo *sampleInfo;
    u32 handle;

    handle = 0xFFFFFFFF;
    sampleInfo = dataGetFX(fxId);
    if (sampleInfo != (SynthFxSampleInfo *)0x0) {
        if ((volume & 0xff) == 0xff) {
            volume = sampleInfo->defaultVolume;
        }
        if ((pan & 0xff) == 0xff) {
            pan = sampleInfo->defaultPan;
        }
        handle = audioFn_8026feec(sampleInfo->sampleId, sampleInfo->key, sampleInfo->velocity,
                             sampleInfo->flags | 0x80, volume, pan, 0xff, 0xff, 0, 0, 0xff,
                             sampleInfo->auxIndex, 0, studio, studioAux);
    }
    return handle;
}

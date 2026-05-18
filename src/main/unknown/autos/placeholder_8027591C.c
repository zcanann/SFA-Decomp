#include "ghidra_import.h"
#include "main/audio/mcmd.h"

extern u8 *synthVoice;
extern u32 lbl_8032EDD0[];
extern int audioFn_80278b94(u16 instrumentKey, u32 priority, u32 maxInstances, u32 baseSample,
                            u8 keyFlags, u8 volume, u8 pan, u32 midiSlot, u8 midiEvent,
                            u8 midiLayer, u16 sampleOffsetIndex, u8 studio, u8 returnNewId,
                            u8 auxA, u8 auxB, int startImmediately);
extern void synthFXCloneMidiSetup(McmdVoiceState *voice, McmdVoiceState *state);
void DoSetPitch(McmdVoiceState *state);
extern void sndConvertMs(u32 *p);
extern void sndConvertTicks(u32 *p, McmdVoiceState *state);
extern int dataGetSample(u16 key, u32 *out);
extern void hwInitSamplePlayback(u32 voice, u32 sampleId, u32 *sampleInfo, u32 noKeySync,
                                 u32 priority, u32 handle, u32 noStartOffset, u8 restart);
extern void synthQueueVoiceInputUpdate(McmdVoiceState *state);
extern u32 dataSampleInfo[];
extern void *dataGetCurve(u16 key);
extern u32 voiceConvertDbToLinear(u32 value);
extern int fn_8027A8D4(int state);
extern void hwSetADSR(int slot, u32 *adsr, u8 mode);
extern u8 voiceAdsrDecayTable[];
extern f32 voiceAdsrSustainTable[];
extern f32 lbl_803E77F0;
extern f32 lbl_803E77F4;
extern f32 lbl_803E77F8;
extern f64 lbl_803E7800;
extern f64 lbl_803E7808;

/*
 * mcmdPlayMacro - voice param/key/velocity processor.
 *
 * EN v1.0 Address: 0x802757C4
 * EN v1.0 Size: 408b
 */
void mcmdPlayMacro(McmdVoiceState *state, McmdCommandArgs *args)
{
    int sum;
    u8 key;
    int result;

    sum = (s32)state->keyBase + (s32)(s8)((args->flags >> 8) & 0xff);
    if (sum < 0) {
        key = 0;
    } else if (sum > 0x7f) {
        key = 0x7f;
    } else {
        key = (u8)sum;
    }
    if (state->streamKind != 0) {
        key |= 0x80;
    }
    state->macroAllocating = 1;

    result = audioFn_80278b94(args->flags >> 16, (args->value >> 8) & 0xff,
                              args->value >> 24, state->baseSample, key,
                              (state->volume >> 8) & 0xff, (state->pan >> 8) & 0xff,
                              state->midiSlot, state->midiEvent, state->midiLayer,
                              args->value & 0xffff, state->studio, 0, state->auxA,
                              state->auxB, *(u8 *)((u8 *)state + 0x193) == 0);

    state->macroAllocating = 0;

    if (result == -1) {
        state->cloneVidListNode = (void *)-1;
        return;
    }

    {
        u8 voice = (u8)result;
        McmdVoiceState *voiceState = (McmdVoiceState *)(synthVoice + voice * 0x404);
        state->cloneVidListNode = voiceState->vidListNode;
        voiceState->voicePrevHandle = state->voiceHandle;

        if (state->voiceNextHandle != -1) {
            u32 prev = state->voiceNextHandle;
            voiceState->voiceNextHandle = prev;
            ((McmdVoiceState *)(synthVoice + (prev & 0xff) * 0x404))->voicePrevHandle = result;
        }
        state->voiceNextHandle = result;

        if (state->streamKind != 0) {
            synthFXCloneMidiSetup(voiceState, state);
        }
    }
}

/*
 * Resolve a sample descriptor and start hardware playback for a voice.
 */
void mcmdStartSample(McmdVoiceState *state, McmdCommandArgs *args)
{
    int found;
    int mode;
    u32 noStartOffset;
    u32 noKeySync;
    u32 sampleId;

    sampleId = (args->flags >> 8) & 0xffff;
    found = dataGetSample(sampleId, dataSampleInfo);
    if (found == 0) {
        mode = args->flags >> 0x18;
        if (mode == 1) {
            dataSampleInfo[3] =
                (args->value * (0x7f - ((*(u32 *)((u8 *)state + 0x154) >> 0x10) & 0xff))) / 0x7f;
        } else if (mode == 0) {
            dataSampleInfo[3] = args->value;
        } else if (mode < 3) {
            dataSampleInfo[3] =
                (args->value * ((*(u32 *)((u8 *)state + 0x154) >> 0x10) & 0xff)) / 0x7f;
        } else {
            dataSampleInfo[3] = 0;
        }
        if (dataSampleInfo[3] >= dataSampleInfo[4]) {
            dataSampleInfo[3] = dataSampleInfo[4] - 1;
        }
        noStartOffset = __cntlzw(state->inputFlags & MCMD_VOICE_START_OFFSET_INPUT_FLAG);
        noKeySync = __cntlzw(state->outputFlags & MCMD_VOICE_KEY_SYNC_OUTPUT_FLAG);
        hwInitSamplePlayback(state->voiceHandle & 0xff, sampleId,
                             dataSampleInfo,
                             noKeySync >> 5,
                             ((u32)state->priorityGroup << 0x18) |
                                 (state->priorityValue >> 0xf),
                             state->voiceHandle, noStartOffset >> 5,
                             *(u8 *)((u8 *)state + 0x193));
        state->prevSampleId = dataSampleInfo[0];
        if (state->targetPitch != 0xffffffff) {
            DoSetPitch(state);
        }
        state->outputFlags |= MCMD_VOICE_ACTIVE_OUTPUT_FLAG;
        synthQueueVoiceInputUpdate(state);
    }
}

/*
 * Configure the voice pitch bend ramp and curve flags.
 */
void mcmdVibrato(McmdVoiceState *state, McmdCommandArgs *args)
{
    s8 start;
    s8 target;
    u32 duration[2];

    if (((args->flags >> 0x18) & 3) == 0) {
        state->outputFlags &= ~MCMD_VOICE_VIBRATO_CURVE_OUTPUT_FLAG;
        state->inputFlags = state->inputFlags;
    } else {
        state->outputFlags |= MCMD_VOICE_VIBRATO_CURVE_OUTPUT_FLAG;
    }

    duration[0] = args->value >> 0x10;
    if ((args->value & MCMD_WAIT_TIME_UNIT_MS_FLAG) == 0) {
        sndConvertTicks(duration, state);
    } else {
        sndConvertMs(duration);
    }
    if (duration[0] == 0) {
        state->outputFlags &= ~MCMD_VOICE_VIBRATO_RAMP_OUTPUT_FLAG;
        state->inputFlags = state->inputFlags;
    } else {
        state->outputFlags |= MCMD_VOICE_VIBRATO_RAMP_OUTPUT_FLAG;
        state->vibratoDuration = duration[0];
        start = (s8)(args->flags >> 8);
        target = (s8)(args->flags >> 0x10);
        if (start < 0) {
            if (target < 0) {
                state->vibratoTarget = -target;
            } else {
                state->vibratoTarget = target;
            }
            state->vibratoStart = -start;
            state->vibratoHalfDuration = state->vibratoDuration >> 1;
        } else {
            if (target < 0) {
                if (start == 0) {
                    state->vibratoTarget = -target;
                    state->vibratoHalfDuration = state->vibratoDuration >> 1;
                } else {
                    state->vibratoTarget = 100 - target;
                    start--;
                    state->vibratoHalfDuration = 0;
                }
            } else {
                state->vibratoTarget = target;
                state->vibratoHalfDuration = 0;
            }
            state->vibratoStart = start;
        }
    }
}

/*
 * Map the previous sample pitch toward the requested pitch, splitting the
 * result into key and fine-tune cents.
 */
#pragma dont_inline on
void DoSetPitch(McmdVoiceState *state)
{
    u16 *pitchRatioTable;
    u16 *ratioPtr;
    u32 sampleKey;
    u32 targetPitch;
    u32 ratio;
    u32 samplePitch;
    u32 sourcePitch;
    int octave;
    int semitone;
    int shiftLimit;

    pitchRatioTable = (u16 *)lbl_8032EDD0;
    targetPitch = state->targetPitch & 0xffffff;
    samplePitch = state->prevSampleId;
    sourcePitch = samplePitch & 0xffffff;
    sampleKey = samplePitch >> 0x18;

    if (sourcePitch == targetPitch) {
        state->key = sampleKey;
        state->fineTune = 0;
        return;
    }

    if (sourcePitch < targetPitch) {
        ratio = (targetPitch << 0xc) / sourcePitch;
        shiftLimit = 0xb;
        octave = 0;
        do {
            if ((ratio >> 0xc) < (u32)(1 << (octave + 1))) {
                break;
            }
            octave++;
            shiftLimit--;
        } while (shiftLimit != 0);

        ratio = ratio / (u32)(1 << octave);
        semitone = 0xb;
        for (ratioPtr = pitchRatioTable + 0xb; ratio <= *ratioPtr; ratioPtr--) {
            semitone--;
        }

        state->key = sampleKey + (s16)octave * 0xc + (s16)semitone;
        targetPitch = (u32)pitchRatioTable[semitone];
        state->fineTune =
            (s8)(((ratio - targetPitch) * 100) /
                 (pitchRatioTable[semitone + 1] - targetPitch));
        return;
    }

    ratio = (sourcePitch << 0xc) / targetPitch;
    shiftLimit = 0xb;
    octave = 0;
    do {
        if ((ratio >> 0xc) < (u32)(1 << (octave + 1))) {
            break;
        }
        octave++;
        shiftLimit--;
    } while (shiftLimit != 0);

    ratio = ratio / (u32)(1 << octave);
    semitone = 0xb;
    for (ratioPtr = pitchRatioTable + 0xb; ratio <= *ratioPtr; ratioPtr--) {
        semitone--;
    }

    octave = semitone + octave * 0xc;
    if ((int)(samplePitch >> 0x18) < octave) {
        state->fineTune = 0;
        state->key = 0;
        return;
    }
    state->key = sampleKey - octave;
    sourcePitch = (u32)pitchRatioTable[semitone];
    state->fineTune =
        (s8)(((sourcePitch - ratio) * 100) /
             (pitchRatioTable[semitone + 1] - sourcePitch));
}
#pragma dont_inline reset

/*
 * Resolve ADSR parameters and send them to the hardware voice.
 */
void mcmdSetADSR(McmdVoiceState *state, McmdCommandArgs *args)
{
    u8 *table;
    u16 *words;
    u16 sustainIndex;
    u32 velCurve;
    u32 keyCurve;
    int bend;
    u32 adsr[3];
    union {
        struct {
            u32 hi;
            u32 lo;
        } word;
        f64 d;
    } conv;
    union {
        struct {
            u32 hi;
            u32 lo;
        } word;
        f64 d;
    } curve;

    table = dataGetCurve((args->flags >> 8) & 0xffff);
    if (table != 0) {
        words = (u16 *)table;
        if ((args->flags >> 0x18) == 0) {
            adsr[0] = (((u16)((words[0] << 8) | ((u32)words[0] >> 8))) << 16) |
                      (u16)((words[1] << 8) | ((u32)words[1] >> 8));
            adsr[1] = (((u16)((words[2] << 8) | ((u32)words[2] >> 8))) << 16) |
                      (u16)((words[3] << 8) | ((u32)words[3] >> 8));
            hwSetADSR(state->voiceHandle & 0xff, adsr, 0);
        } else {
            adsr[0] = ((u32)table[3] << 24) | ((u32)table[2] << 16) |
                      ((u32)table[1] << 8) | table[0];
            adsr[1] = ((u32)table[7] << 24) | ((u32)table[6] << 16) |
                      ((u32)table[5] << 8) | table[4];
            sustainIndex = (u16)((words[4] << 8) | ((u32)words[4] >> 8));
            *(u16 *)((u8 *)adsr + 8) =
                (u16)(int)(lbl_803E77F0 *
                           *(f32 *)((u8 *)voiceAdsrSustainTable + ((sustainIndex >> 3) & 0x1ffc)));
            *(u16 *)((u8 *)adsr + 10) =
                (u16)((words[5] << 8) | ((u32)words[5] >> 8));
            velCurve = ((u32)table[15] << 24) | ((u32)table[14] << 16) |
                       ((u32)table[13] << 8) | table[12];
            keyCurve = ((u32)table[19] << 24) | ((u32)table[18] << 16) |
                       ((u32)table[17] << 8) | table[16];
            if (velCurve != 0x80000000) {
                conv.word.hi = 0x43300000;
                conv.word.lo = *(u32 *)((u8 *)state + 0x158);
                curve.word.hi = 0x43300000;
                curve.word.lo = velCurve ^ 0x80000000;
                bend = (int)(lbl_803E77F4 * (f32)(conv.d - lbl_803E7800) *
                             (f32)(curve.d - lbl_803E7808));
                adsr[0] += bend;
            }
            if (keyCurve != 0x80000000) {
                conv.word.hi = 0x43300000;
                conv.word.lo = state->keyBase;
                curve.word.hi = 0x43300000;
                curve.word.lo = keyCurve ^ 0x80000000;
                bend = (int)(lbl_803E77F8 * (f32)(conv.d - lbl_803E7800) *
                             (f32)(curve.d - lbl_803E7808));
                adsr[1] += bend;
            }
            hwSetADSR(state->voiceHandle & 0xff, adsr, 1);
        }
        state->outputFlags |= MCMD_VOICE_KEY_SYNC_OUTPUT_FLAG;
    }
}

/*
 * Configure the per-voice envelope state from an ADSR/keygroup table.
 */
void mcmdSetPitchADSR(int state, u32 *args)
{
    s16 basePan;
    u16 decayRaw;
    u16 releaseRaw;
    u32 velCurve;
    u32 keyCurve;
    u32 decayIndex;
    u32 panDelta;
    u32 panScaled;
    int attack;
    int decay;
    int delta;
    u8 *table;
    union {
        struct {
            u32 hi;
            u32 lo;
        } word;
        f64 d;
    } conv;
    union {
        struct {
            u32 hi;
            u32 lo;
        } word;
        f64 d;
    } curve;

    table = dataGetCurve((*args >> 8) & 0xffff);
    if (table != 0) {
        *(s16 *)(state + 0x204) = (s16)((s8)args[1] << 8);
        basePan = *(s16 *)(state + 0x204);
        panDelta = (u32)(s16)(s8)(args[1] >> 8);
        panScaled = panDelta << 8;
        delta = (int)panScaled / 100 + ((int)(panScaled | (panDelta >> 24)) >> 31);
        delta = (s16)delta - (s16)(delta >> 31);
        if (basePan < 0) {
            *(s16 *)(state + 0x204) = basePan - (s16)delta;
        } else {
            *(s16 *)(state + 0x204) = basePan + (s16)delta;
        }

        decayRaw = *(u16 *)(table + 8);
        releaseRaw = *(u16 *)(table + 10);
        attack = ((u32)table[3] << 24) | ((u32)table[2] << 16) | ((u32)table[1] << 8) |
                 table[0];
        decay = ((u32)table[7] << 24) | ((u32)table[6] << 16) | ((u32)table[5] << 8) |
                table[4];
        velCurve = ((u32)table[15] << 24) | ((u32)table[14] << 16) |
                   ((u32)table[13] << 8) | table[12];
        keyCurve = ((u32)table[19] << 24) | ((u32)table[18] << 16) |
                   ((u32)table[17] << 8) | table[16];

        if (velCurve != 0x80000000) {
            conv.word.hi = 0x43300000;
            conv.word.lo = *(u32 *)(state + 0x158);
            curve.word.hi = 0x43300000;
            curve.word.lo = velCurve ^ 0x80000000;
            attack += (int)(lbl_803E77F4 * (f32)(conv.d - lbl_803E7800) *
                            (f32)(curve.d - lbl_803E7808));
        }
        if (keyCurve != 0x80000000) {
            conv.word.hi = 0x43300000;
            conv.word.lo = *(u8 *)(state + 0x12f);
            curve.word.hi = 0x43300000;
            curve.word.lo = keyCurve ^ 0x80000000;
            decay += (int)(lbl_803E77F8 * (f32)(conv.d - lbl_803E7800) *
                           (f32)(curve.d - lbl_803E7808));
        }

        *(u8 *)(state + 0x1dc) = 1;
        *(u8 *)(state + 0x202) = 0;
        *(u32 *)(state + 0x1f0) = voiceConvertDbToLinear(attack);
        *(u32 *)(state + 0x1f4) = voiceConvertDbToLinear(decay);
        decayIndex = ((decayRaw & 0xff) << 8 | ((u32)decayRaw >> 8)) >> 2;
        if (decayIndex > 0x3ff) {
            decayIndex = 0x3ff;
        }
        *(u16 *)(state + 0x1f8) = 0xc1 - voiceAdsrDecayTable[decayIndex];
        *(u32 *)(state + 0x1fc) = ((releaseRaw & 0xff) << 8) | ((u32)releaseRaw >> 8);
        fn_8027A8D4(state + 0x1dc);
        *(u32 *)(state + MCMD_VOICE_INPUT_FLAGS_OFFSET) |= MCMD_VOICE_PITCH_ADSR_INPUT_FLAG;
    }
}

/*
 * voiceConfigureParamRamp - voice param store with magic-divide (~160 instructions).
 * Stubbed.
 */
void voiceConfigureParamRamp(int state, u32 *args, u32 idx)
{
    u32 *duration;
    int offset;
    u32 packed;
    u32 initial;
    int stepBase;
    int base;

    offset = (idx & 0xff) * 4;
    packed = *args;
    duration = (u32 *)(state + offset + 0x188);
    *duration = packed >> 0x10;
    sndConvertMs(duration);
    initial = args[1];
    *(u32 *)(state + offset + 0x170) = (*args & 0xff00) << 8;
    stepBase = (s8)initial * 0x10000;
    base = state + offset;
    *(int *)(base + 0x180) = *(int *)(state + offset + 0x170) + stepBase;
    if (*duration == 0) {
        *(int *)(base + 0x178) = stepBase;
    } else {
        *(int *)(base + 0x178) = stepBase / (int)(packed >> 0x10);
    }
    *(u32 *)(state + MCMD_VOICE_INPUT_FLAGS_OFFSET) |= MCMD_VOICE_PARAM_RAMP_INPUT_FLAG;
}

#ifndef MAIN_AUDIO_MCMD_H_
#define MAIN_AUDIO_MCMD_H_

#define MCMD_VOICE_PLAY_PTR_OFFSET 0x38
#define MCMD_VOICE_LOOP_COUNTER_OFFSET 0xAA
#define MCMD_VOICE_ID_OFFSET 0xF4
#define MCMD_VOICE_PREV_SAMPLE_ID_OFFSET 0x124
#define MCMD_VOICE_INPUT_FLAGS_OFFSET 0x114
#define MCMD_VOICE_OUTPUT_FLAGS_OFFSET 0x118
#define MCMD_VOICE_HANDLE_SLOT_BYTE 0

#define MCMD_LOOP_RANDOM_DELAY_FLAG 0x00010000
#define MCMD_LOOP_WAIT_FOR_KEYOFF_FLAG 0x00000100
#define MCMD_LOOP_WAIT_FOR_INACTIVE_FLAG 0x01000000
#define MCMD_LOOP_COUNTER_FOREVER 0xFFFF
#define MCMD_WAIT_ABSOLUTE_TIME_FLAG 0x00000001
#define MCMD_WAIT_TIME_UNIT_MS_FLAG 0x00000100

#define MCMD_VOICE_KEYOFF_INPUT_FLAG 0x100
#define MCMD_VOICE_PITCH_ADSR_INPUT_FLAG 0x200
#define MCMD_VOICE_DEFERRED_KEYOFF_INPUT_FLAG 0x400
#define MCMD_VOICE_START_OFFSET_INPUT_FLAG 0x800
#define MCMD_VOICE_PARAM_RAMP_INPUT_FLAG 0x2000
#define MCMD_VOICE_KEYOFF_WAIT_OUTPUT_FLAG 0x4
#define MCMD_VOICE_KEYOFF_OUTPUT_FLAG 0x8
#define MCMD_VOICE_ACTIVE_OUTPUT_FLAG 0x20
#define MCMD_VOICE_KEY_SYNC_OUTPUT_FLAG 0x100
#define MCMD_VOICE_PORTAMENTO_OUTPUT_FLAG 0x400
#define MCMD_VOICE_ALLOCATED_OUTPUT_FLAG 0x2
#define MCMD_VOICE_VOLUME_RAMP_OUTPUT_FLAG 0x8000
#define MCMD_VOICE_INACTIVE_WAIT_OUTPUT_FLAG 0x40000
#define MCMD_VOICE_VIBRATO_RAMP_OUTPUT_FLAG 0x2000
#define MCMD_VOICE_VIBRATO_CURVE_OUTPUT_FLAG 0x4000

#define MCMD_INPUT_DIRTY_VOLUME 0x0001
#define MCMD_INPUT_DIRTY_PANNING 0x0002
#define MCMD_INPUT_DIRTY_SUR_PANNING 0x0004
#define MCMD_INPUT_DIRTY_PITCH_BEND 0x0008
#define MCMD_INPUT_DIRTY_DOPPLER 0x0010
#define MCMD_INPUT_DIRTY_MODULATION 0x0020
#define MCMD_INPUT_DIRTY_PEDAL 0x0040
#define MCMD_INPUT_DIRTY_PORTAMENTO 0x0080
#define MCMD_INPUT_DIRTY_PRE_AUX_A 0x0100
#define MCMD_INPUT_DIRTY_REVERB 0x0200
#define MCMD_INPUT_DIRTY_PRE_AUX_B 0x0400
#define MCMD_INPUT_DIRTY_POST_AUX_B 0x0800
#define MCMD_INPUT_DIRTY_TREMOLO 0x1000
#define MCMD_INPUT_DIRTY_ALL 0x1FFF

typedef struct McmdCommandArgs {
    u32 flags;
    u32 value;
} McmdCommandArgs;

typedef struct McmdInputEntry {
    u8 controller;
    u8 combineModeFlags;
    u8 unk2[2];
    s32 scale;
} McmdInputEntry;

typedef struct McmdInputSlot {
    McmdInputEntry entries[4];
    s16 cachedValue;
    u8 entryCount;
    u8 unk23;
} McmdInputSlot;

typedef struct McmdExCtrlState {
    u32 unk00;
    u32 rampFrames;
    s16 value;
    u16 limit;
} McmdExCtrlState;

typedef struct McmdEnvelopeState {
    u8 mode;
    u8 submode;
    u8 unk02[2];
    u32 duration;
    u32 value;
    u32 target;
    s32 step;
    u32 attack;
    u32 decay;
    u16 sustain;
    u16 unk1E;
    u32 release;
    u8 unk24[4];
} McmdEnvelopeState;

typedef struct McmdVidListNode {
    struct McmdVidListNode *next;
    struct McmdVidListNode *prev;
    u32 id;
    u32 internalId;
} McmdVidListNode;

typedef struct McmdMacroStackEntry {
    u8 *macroBase;
    u8 *macroCursor;
} McmdMacroStackEntry;

typedef struct McmdVoiceState {
    u8 unk00[0x34];
    u8 *macroBase;
    u8 *macroCursor;
    struct McmdVoiceState *activeNext;
    struct McmdVoiceState *activePrev;
    struct McmdVoiceState *timeNext;
    struct McmdVoiceState *timePrev;
    u32 queueMode;
    u8 *keyoffMacroBase;
    u8 *sampleEndMacroBase;
    u8 *messageMacroBase;
    u8 *keyoffMacroCursor;
    u8 *sampleEndMacroCursor;
    u8 *messageMacroCursor;
    u8 hasTriggerMacros;
    u8 unk69[3];
    McmdMacroStackEntry macroStack[4];
    u8 macroStackDepth;
    u8 macroStackIndex;
    u8 unk8E[2];
    u32 startTimeHi;
    u32 startTimeLo;
    u32 wakeTimeHi;
    u32 wakeTimeLo;
    u32 activeTimeHi;
    u32 activeTimeLo;
    u8 unkA8[MCMD_VOICE_LOOP_COUNTER_OFFSET - 0xA8];
    u16 loopCounter;
    u32 localRegs[16];
    u32 voiceNextHandle;
    u32 voicePrevHandle;
    union {
        u32 voiceHandle;
        u8 voiceHandleBytes[4];
    };
    McmdVidListNode *vidListNode;
    u32 unkFC;
    u16 baseSample;
    u16 instrumentKey;
    u8 keyGroup;
    u8 unk105[3];
    McmdVidListNode *cloneVidListNode;
    u8 priorityGroup;
    u8 unk10D;
    u16 priorityScale;
    u32 priorityValue;
    u32 inputFlags;
    u32 outputFlags;
    u8 macroAllocating;
    u8 streamKind;
    u8 auxA;
    u8 auxB;
    u8 studio;
    u8 midiSlot;
    u8 midiEvent;
    u8 midiLayer;
    u32 prevSampleId;
    u32 targetPitch;
    u16 key;
    s8 fineTune;
    u8 keyBase;
    u8 registeredKey;
    u8 portamentoMode;
    u16 portamentoCtrlValue;
    u32 portamentoDuration;
    u8 unk138[0x140 - 0x138];
    s8 vibratoStart;
    s8 vibratoTarget;
    u8 unk142[2];
    u32 vibratoDuration;
    u32 vibratoHalfDuration;
    u8 unk14C[0x154 - 0x14C];
    u32 volume;
    u32 volumeBase;
    u8 unk15C[0x170 - 0x15C];
    union {
        struct {
            u32 pan;
            u32 unkParamCurrent1;
        };
        u32 paramCurrent[2];
    };
    s32 paramStep[2];
    u32 paramTarget[2];
    u32 paramDuration[2];
    u8 unk190[3];
    u8 deferStart;
    s32 volumeStep;
    u32 volumeTarget;
    u32 volumeStart;
    u8 unk1A0[0x1BC - 0x1A0];
    union {
        struct {
            McmdExCtrlState exCtrlA0;
            McmdExCtrlState exCtrlA1;
        };
        McmdExCtrlState exCtrls[2];
        struct {
            u8 unk1BC[8];
            s16 exCtrlA0Value;
            u16 exCtrlA0Limit;
            u8 unk1C8[8];
            s16 exCtrlA1Value;
            u16 exCtrlA1Limit;
        };
    };
    u8 unk1D4[2];
    u8 pitchBendRangeUp;
    u8 pitchBendRangeDown;
    u16 pitchBend;
    u8 unk1DA[0x1DC - 0x1DA];
    McmdEnvelopeState pitchAdsr;
    s16 pitchAdsrPan;
    u8 unk206[0x208 - 0x206];
    u8 startupVolume;
    u8 startupPan;
    u8 startupMidiSlot;
    u8 startupMidiEvent;
    u8 startupMidiLayer;
    u8 startupStudio;
    u8 startupAuxA;
    u8 startupAuxB;
    u8 startupDeferStart;
    u8 unk211[3];
    u32 inputDirtyFlags;
    union {
        struct {
            McmdInputSlot volumeInput;
            McmdInputSlot panningInput;
            McmdInputSlot surPanningInput;
            McmdInputSlot pitchBendInput;
            McmdInputSlot dopplerInput;
            McmdInputSlot modulationInput;
            McmdInputSlot pedalInput;
            McmdInputSlot portamentoInput;
            McmdInputSlot preAuxAInput;
            McmdInputSlot reverbInput;
            McmdInputSlot preAuxBInput;
            McmdInputSlot postAuxBInput;
            McmdInputSlot tremoloInput;
        };
        McmdInputSlot inputSlots[13];
    };
    u8 queuedMessageCount;
    u8 queuedMessageReadIndex;
    u8 queuedMessageWriteIndex;
    u8 unk3EF;
    u32 queuedMessages[4];
    u8 unk400[4];
} McmdVoiceState;

#endif /* MAIN_AUDIO_MCMD_H_ */

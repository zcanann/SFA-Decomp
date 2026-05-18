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
#define MCMD_VOICE_VOLUME_RAMP_OUTPUT_FLAG 0x8000
#define MCMD_VOICE_INACTIVE_WAIT_OUTPUT_FLAG 0x40000
#define MCMD_VOICE_VIBRATO_RAMP_OUTPUT_FLAG 0x2000
#define MCMD_VOICE_VIBRATO_CURVE_OUTPUT_FLAG 0x4000

typedef struct McmdCommandArgs {
    u32 flags;
    u32 value;
} McmdCommandArgs;

typedef struct McmdVoiceState {
    u8 unk00[0x34];
    u8 *macroBase;
    u8 *macroCursor;
    struct McmdVoiceState *activeNext;
    struct McmdVoiceState *activePrev;
    struct McmdVoiceState *timeNext;
    struct McmdVoiceState *timePrev;
    u32 queueMode;
    u8 unk50[0x90 - 0x50];
    u32 startTimeHi;
    u32 startTimeLo;
    u32 wakeTimeHi;
    u32 wakeTimeLo;
    u32 activeTimeHi;
    u32 activeTimeLo;
    u8 unkA8[MCMD_VOICE_LOOP_COUNTER_OFFSET - 0xA8];
    u16 loopCounter;
    u8 unkAC[MCMD_VOICE_ID_OFFSET - 0xAC];
    union {
        u32 voiceHandle;
        u8 voiceHandleBytes[4];
    };
    u8 unkF8[0x10C - 0xF8];
    u8 priorityGroup;
    u8 unk10D[3];
    u32 priorityValue;
    u32 inputFlags;
    u32 outputFlags;
    u8 unk11C[MCMD_VOICE_PREV_SAMPLE_ID_OFFSET - 0x11C];
    u32 prevSampleId;
    u32 targetPitch;
    u16 key;
    s8 fineTune;
    u8 keyBase;
    u8 unk130[0x140 - 0x130];
    s8 vibratoStart;
    s8 vibratoTarget;
    u8 unk142[2];
    u32 vibratoDuration;
    u32 vibratoHalfDuration;
    u8 unk14C[0x154 - 0x14C];
    u32 volume;
    u8 unk158[0x194 - 0x158];
    s32 volumeStep;
    u32 volumeTarget;
    u32 volumeStart;
} McmdVoiceState;

#endif /* MAIN_AUDIO_MCMD_H_ */

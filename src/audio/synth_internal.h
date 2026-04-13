#ifndef SFA_AUDIO_SYNTH_INTERNAL_H
#define SFA_AUDIO_SYNTH_INTERNAL_H

typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef int s32;
typedef short s16;
typedef float f32;

#define SYNTH_MAX_VOICES 8
#define SYNTH_CALLBACK_COUNT 0x100
#define SYNTH_VOICE_NOTE_COUNT 0x10
#define SYNTH_STUDIO_CHANNEL_SCALE_STUDIO_COUNT 9
#define SYNTH_DELAY_BUCKET_COUNT 0x20
#define SYNTH_DELAY_BUCKET_INVALID 0xFF

typedef struct SynthCallbackLink {
    struct SynthCallbackLink* next;
    struct SynthCallbackLink* prev;
    u32 callbackId;
    s32 triggerValue;
    u8 controllerIndex;
    u8 listIndex;
    u8 unk12[2];
} SynthCallbackLink;

typedef struct SynthPendingUpdate {
    u8 studio;
    u8 unk01[3];
    u32 mixValue0;
    u32 mixValue1;
    u16 value16;
    u8 flags;
    u8 unk0F;
    u32 output;
} SynthPendingUpdate;

typedef struct SynthDelayedNode {
    struct SynthDelayedNode* next;
    struct SynthDelayedNode* prev;
    u8 voiceIndex;
    u8 bucketIndex;
    u8 pad[2];
} SynthDelayedNode;

typedef union SynthDelayedActionWord {
    u32 word;
    struct {
        u8 action;
        u8 pad[3];
    } bytes;
} SynthDelayedActionWord;

typedef struct SynthDelayedEntry {
    SynthDelayedNode nodes[3];
    u32 word0;
    u32 word1;
    SynthDelayedActionWord word2;
    u32 word3;
} SynthDelayedEntry;

typedef struct SynthDelayStorage {
    u32 studioChannelScales[SYNTH_STUDIO_CHANNEL_SCALE_STUDIO_COUNT][SYNTH_VOICE_NOTE_COUNT];
    SynthDelayedNode* bucketHeads[SYNTH_DELAY_BUCKET_COUNT][3];
} SynthDelayStorage;

typedef struct SynthVoiceSlot {
    u8 unk000[0xEC];
    u32 callbackNext;
    u8 unk0F0[4];
    u32 callbackLinkId;
    u8 unk0F8[0x24];
    u8 callbackActive;
    u8 unk11D[5];
    u8 studioIndex;
    u8 channelIndex;
    u8 unk124[0x404 - 0x124];
} SynthVoiceSlot;

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

typedef struct SynthPitchPoint {
    u32 threshold;
    u32 value;
} SynthPitchPoint;

typedef struct SynthChannelState {
    s32 eventActive;
    SynthPitchPoint* eventCursor;
    u32 currentValue;
    u8 unk0C[0x24 - 0x0C];
    u32 threshold0;
    u32 unk28;
    u32 threshold1;
    u8 thresholdIndex;
    u8 unk31[0x38 - 0x31];
} SynthChannelState;

typedef struct SynthTrackCursor {
    u8* base;
    void* current;
} SynthTrackCursor;

typedef struct SynthSequenceEvent {
    struct SynthSequenceEvent* next;
    struct SynthSequenceEvent* prev;
    u32 value;
    void* eventData;
    void* state;
    u8 type;
    u8 channel;
    u8 pad16[2];
} SynthSequenceEvent;

typedef struct SynthSequenceState {
    u32 currentValue;
    u32 valueOffset;
    u8* stream;
    void* eventData;
    u8* primaryStream;
    u16 primaryValue;
    s16 primaryStep;
    u32 primaryLimit;
    u8* secondaryStream;
    u16 secondaryValue;
    s16 secondaryStep;
    u32 secondaryLimit;
    u8 controller;
    u8 pad29[3];
} SynthSequenceState;

typedef struct SynthSequenceQueue {
    u8 unk00[0x1C];
    SynthSequenceEvent* eventList;
} SynthSequenceQueue;

typedef struct SynthTrackCommand {
    u32 value0;
    u32 value1;
    u16 command;
    u16 arg;
} SynthTrackCommand;

typedef struct SynthKeyGroupState {
    u8 unk00[0x36];
    u8 active;
    u8 pad37;
} SynthKeyGroupState;

typedef struct SynthVoice {
    struct SynthVoice* next;
    struct SynthVoice* prev;
    u8 state;
    u8 slotIndex;
    u8 unk0A[2];
    u32 handle;
    u8 unk10[0x10C];
    u32 immediateMixValue0;
    u32 immediateMixValue1;
    u8 unk124[0x200];
    u8 studioMap[0x40];
    u8 unk364[0xB00];
    SynthCallbackLink* callbackLists[3];
    u8 unkE70[0x40];
    u8 currentStudio;
    u8 unkEB1[0x1B];
    SynthPendingUpdate pendingUpdate;
    u8 unkEE0[0x638];
    u8 channelData[0x350];
} SynthVoice;

#define SYNTH_CHANNEL_STATE(voice, channel) \
    ((SynthChannelState*)&(voice)->unkEE0[0x608 + (((channel) & 0xFF) * sizeof(SynthChannelState))])
#define SYNTH_CHANNEL_THRESHOLD(state, index) (*(u32*)((u8*)(state) + 0x24 + ((index) * 8)))
#define SYNTH_CHANNEL_EVENT(voice, channel) ((SynthSequenceEvent*)&(voice)->unkEE0[0x4 + ((channel) * 0x18)])
#define SYNTH_KEYGROUP_MAP(voice) (*(u8**)&(voice)->unkEE0[0x604])
#define SYNTH_KEYGROUP_STATE(voice, index) ((SynthKeyGroupState*)&(voice)->unkEE0[0x608 + ((index) * 0x38)])
#define SYNTH_SEQUENCE_STATE(voice, channel) ((SynthSequenceState*)&(voice)->unk364[(channel) * 0x2C])
#define SYNTH_TRACK_CURSOR(voice, channel) ((SynthTrackCursor*)&(voice)->unk124[(channel) * 8])

extern SynthDelayStorage gSynthDelayStorage;
extern SynthCallbackLink gSynthCallbacks[SYNTH_CALLBACK_COUNT];
extern u8 gSynthInitialized;
extern u8 gSynthDelayBucketCursor;
extern SynthCallbackLink* gSynthFreeCallbacks;
extern SynthVoice* gSynthCurrentVoice;
extern SynthVoiceSlot* gSynthVoiceSlots;
extern u32 gSynthDelayedActionWord0;
extern u32 gSynthDelayedActionWord1;
extern SynthFade gSynthFades[0x20];
extern u32 gSynthFadeMask;

extern SynthVoice gSynthVoices[SYNTH_MAX_VOICES];
extern u16 gSynthVoiceNotes[SYNTH_MAX_VOICES][SYNTH_VOICE_NOTE_COUNT];
extern SynthVoice* gSynthFreeVoices;
extern SynthVoice* gSynthQueuedVoices;
extern SynthVoice* gSynthAllocatedVoices;
extern u32 gSynthNextHandle;

void synthInitVoices(void);
void synthSetStudioChannelScale(s32 value, u8 studioIndex, u32 channelIndex);
u32 synthGetVoiceSlotChannelScale(SynthVoiceSlot* slot);
void synthRecycleVoiceCallbacks(SynthVoice* voice);
SynthCallbackLink* synthAllocCallback(s32 triggerValue, u8 controllerIndex);
s32 synthUpdateCallbacks(void);
void synthFlushCallbacks(void);
void synthFreeCallback(SynthCallbackLink* callback);
s32 synthTriggerCallback(u32 callbackId);
u32 synthAssignHandle(s32 voiceIndex);
u32 synthResolveHandle(u32 handle);
void synthDispatchDelayedAction(SynthFade* fade);
void synthSetFade(u8 value, u16 time, u8 selector, u8 action, u32 handle);
u32 synthIsFadeActive(u32 fadeIndex);
void synthSetFadeAction(u32 fadeIndex, u8 action);
void synthQueueVoice(SynthVoice* voice);
void synthQueueHandle(u32 handle);
void synthFreeHandle(u32 handle);
void synthSetHandleValue16(u32 handle, u16 value);
void synthRestoreQueuedHandle(u32 handle);
void synthSetHandleMixData(u32 handle, u32 value0, u32 value1);
void synthUpdateHandle(u32 value0, u32 value1, u32 handle, u8 mode);
u32 synthCancelCallbackVoices(u32 callbackId);

#endif

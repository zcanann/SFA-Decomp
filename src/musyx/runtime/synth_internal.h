#ifndef SFA_AUDIO_SYNTH_INTERNAL_H
#define SFA_AUDIO_SYNTH_INTERNAL_H

#ifndef SYNTH_INTERNAL_USE_PROJECT_TYPES
#include "types.h"
#endif

#include "musyx/mcmd.h"
#include "musyx/snd_core.h"
#include "musyx/synth_queue.h"
#include "musyx/synth_master_fader.h"
#include "global.h"

#define SYNTH_CALLBACK_COUNT 0x100
#define SYNTH_SEQUENCE_TRACK_COUNT 0x40
#define SYNTH_STUDIO_CHANNEL_SCALE_STUDIO_COUNT 9
#define SYNTH_DELAY_BUCKET_COUNT 0x20
#define SYNTH_DELAY_BUCKET_INVALID 0xFF
#define SYNTH_HANDLE_INVALID 0xFFFFFFFF
#define SYNTH_HANDLE_ID_MASK 0x7FFFFFFF
#define SYNTH_HANDLE_QUEUED_FLAG 0x80000000
#define SND_CROSSFADE_STOP 0
#define SND_CROSSFADE_PAUSE 1
#define SND_CROSSFADE_CONTINUE 2
#define SND_CROSSFADE_START 0
#define SND_CROSSFADE_SYNC 4
#define SND_CROSSFADE_PAUSENEW 8
#define SND_CROSSFADE_TRACKMUTE 16
#define SND_CROSSFADE_SPEED 32
#define SND_CROSSFADE_MUTE 64
#define SND_CROSSFADE_MUTENEW 128
#define SYNTH_VARIABLE_PAIR_EXTENDED_FLAG 0x80
#define SYNTH_VARIABLE_PAIR_VALUE_MASK 0x7F
#define SYNTH_VARIABLE_PAIR_END_LOW 0x00
#define SYNTH_INVALID_LINK_ID 0xFFFFFFFF

typedef struct SynthCallbackLink
{
    struct SynthCallbackLink* next;
    struct SynthCallbackLink* prev;
    u32 callbackId;
    s32 triggerValue;
    u8 controllerIndex;
    u8 listIndex;
    u8 unk12[2];
} SynthCallbackLink;

typedef struct SynthDelayedNode
{
    struct SynthDelayedNode* next;
    struct SynthDelayedNode* prev;
    u8 voiceIndex;
    u8 jobTabIndex;
    u8 pad[2];
} SynthDelayedNode;

typedef struct SynthPitchPoint
{
    u32 threshold;
    u32 value;
} SynthPitchPoint;

typedef struct SynthChannelState
{
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

typedef struct SynthTrackCursor
{
    u8* base;
    void* current;
} SynthTrackCursor;

typedef struct SynthSequenceState SynthSequenceState;

typedef struct SynthSequenceEvent
{
    struct SynthSequenceEvent* next;
    struct SynthSequenceEvent* prev;
    u32 time;
    void* data;
    SynthSequenceState* state;
    u8 type;
    u8 trackId;
    u8 pad16[2];
} SynthSequenceEvent;

typedef struct SynthSequenceStream
{
    u8* cursor;
    u16 value;
    s16 step;
    u32 nextTime;
} SynthSequenceStream;

struct SynthSequenceState
{
    u32 lastTime;
    u32 baseTime;
    u8* noteData;
    void* patternInfo;
    SynthSequenceStream pitchBend;
    SynthSequenceStream modulation;
    u8 midi;
    u8 pad29[3];
};

typedef struct SynthTimeWord
{
    u32 low;
    u32 high;
} SynthTimeWord;

typedef struct SynthMasterTrackEvent
{
    u32 time;
    u32 bpm;
} SynthMasterTrackEvent;

typedef struct SynthSequenceQueue
{
    u8* masterTrackBase;
    u8* masterTrackCursor;
    u32 bpm;
    SynthTimeWord tickDelta[2];
    SynthSequenceEvent* eventList;
    SynthTimeWord time[2];
    u8 timeIndex;
    u8 unk31;
    u16 speed;
    u16 loopCount;
    u8 loopDisable;
    u8 unk37;
} SynthSequenceQueue;

STATIC_ASSERT(sizeof(SynthSequenceQueue) == 0x38);
STATIC_ASSERT(offsetof(SynthSequenceQueue, speed) == 0x32);

typedef struct SynthTrackCommand
{
    u32 value0;
    u32 value1;
    u16 command;
    u16 arg;
} SynthTrackCommand;

typedef struct SynthStartRequest
{
    u32 seqId1;
    u16 time1;
    u8 pad06[2];
    u32 seqId2;
    u16 time2;
    u8 pad0E[2];
    u32 arr2;
    u16 gid2;
    u16 sid2;
    u8 vol2;
    u8 studio2;
    u8 pad1A[2];
    u32 trackMute2[2];
    u16 speed2;
    u8 flags;
    u8 pad27;
} SynthStartRequest;

typedef struct SynthProgramState
{
    u16 macId;
    u8 priority;
    u8 maxVoices;
} SynthProgramState;

typedef struct SynthVoice
{
    struct SynthVoice* next;
    struct SynthVoice* prev;
    u8 state;
    u8 slotIndex;
    u16 groupId;
    u32 handle;
    SynthPage* normtab;
    u8 normTrans[0x80];
    SynthPage* drumtab;
    u8 drumTrans[0x80];
    u8* arrbase;
    u32 trackMute[2];
    SynthTrackCursor track[0x40];
    u8 trackVolumeGroup[0x40];
    SynthSequenceState pattern[0x40];
    SynthCallbackLink* callbackLists[3];
    SynthProgramState prgState[0x10];
    u8 defaultVolumeGroup;
    u8 unkEB1[3];
    SynthStartRequest syncCrossInfo;
    u32* syncSeqIdPtr;
    u8 syncActive;
    u8 defStudio;
    u8 keyOffCheck;
    u8 unkEE3;
    SynthSequenceEvent channelEvents[SYNTH_SEQUENCE_TRACK_COUNT];
    u8* keyGroupMap;
    SynthSequenceQueue section[SYNTH_VOICE_NOTE_COUNT];
} SynthVoice;

typedef struct SynthVoiceRuntime
{
    SynthCallbackLink callbacks[SYNTH_CALLBACK_COUNT];
    SynthVoice voices[SYNTH_MAX_VOICES];
    u16 voiceNotes[SYNTH_MAX_VOICES][SYNTH_VOICE_NOTE_COUNT];
} SynthVoiceRuntime;

STATIC_ASSERT(sizeof(SynthVoice) == 0x1868);
STATIC_ASSERT(offsetof(SynthVoiceRuntime, voices) == 0x1400);
STATIC_ASSERT(offsetof(SynthVoiceRuntime, voices[0].section[0].speed) == 0x291A);
STATIC_ASSERT(offsetof(SynthVoiceRuntime, voices[0].syncCrossInfo.speed2) == 0x22D8);
STATIC_ASSERT(offsetof(SynthVoiceRuntime, voices[0].syncCrossInfo.flags) == 0x22DA);

extern SynthCallbackLink seqNote[SYNTH_CALLBACK_COUNT];
extern u8 synthJobTableIndex;
extern SynthCallbackLink* noteFree;
extern SynthVoice* cseq;
extern u32 curSeqId;
extern u8 curFadeOutState;

extern SynthVoice seqInstance[SYNTH_MAX_VOICES];
extern u8 synthTrackVolume[64];
extern SynthVoice* seqFreeRoot;
extern SynthVoice* seqActiveRoot;
extern SynthVoice* seqPausedRoot;
extern u32 seq_next_id;

#define SYNTH_VOICE_RUNTIME() ((SynthVoiceRuntime*)(void*)seqNote)


void synthSetBpm(int bpm, u8 set, u8 section);
int synthGetTicksPerSecond(McmdVoiceState *slot);
SynthSequenceEvent* GenerateNextTrackEvent(u8 channel);
void InsertGlobalEvent(SynthSequenceQueue* queue, SynthSequenceEvent* event);
SynthSequenceEvent* HandleEvent(SynthSequenceEvent* event, u8 groupIndex, u32* output);
void synthInitChannelEventQueues(void);
void synthRefreshChannelEventQueue(u8 groupIndex);
u32 HandleTrackEvents(u8 groupIndex, u32 delta);
void ResetNotes(SynthVoice* voice);
SynthCallbackLink* AllocateNote(s32 triggerValue, u8 controllerIndex);
s32 HandleNotes(void);
void KeyOffNotes(void);
void seqFreeKeyOffNote(SynthCallbackLink* callback);
u32 GetPublicId(s32 voiceIndex);
u32 seqGetPrivateId(u32 seqId);

static inline u32 seqGetPrivateIdInline(u32 handle)
{
    u32 resolvedHandle;
    SynthVoice* walker;

    resolvedHandle = handle & SYNTH_HANDLE_ID_MASK;

    for (walker = seqActiveRoot; walker != 0; walker = walker->next)
    {
        if (walker->handle == resolvedHandle)
        {
            return walker->slotIndex | (handle & SYNTH_HANDLE_QUEUED_FLAG);
        }
    }

    for (walker = seqPausedRoot; walker != 0; walker = walker->next)
    {
        if (walker->handle == resolvedHandle)
        {
            return walker->slotIndex | (handle & SYNTH_HANDLE_QUEUED_FLAG);
        }
    }

    return SYNTH_HANDLE_INVALID;
}
void seqPause(u32 seqId);
void seqStop(u32 seqId);
void seqSpeed(u32 seqId, u16 speed);
void seqContinue(u32 seqId);
void seqMute(u32 seqId, u32 mask1, u32 mask2);
u32 synthFXSetCtrl(u32 handle, u8 controller, u8 value);
u32 synthFXSetCtrl14(u32 handle, u8 controller, u16 value);
void synthFXCloneMidiSetup(McmdVoiceState *dstVoice, McmdVoiceState *srcVoice);
u32 synthSendKeyOff(u32 handle);
void seqVolume(u8 volume, u16 time, u32 seqId, u8 mode);

#endif

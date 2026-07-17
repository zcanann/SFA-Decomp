#include "main/audio/voice_manage.h"
#include "main/audio/mcmd.h"
#include "main/audio/hw_init.h"
#include "main/audio/synth_jobs.h"
#include "main/audio/synth_config.h"

#pragma exceptions on

typedef struct VoiceListNode
{
    u8 prev;
    u8 next;
    u16 time;
} VoiceListNode;

#define SYNTH_VOICE_STATE(voice) (&synthVoice[voice])

extern u8 gSynthInitialized;
extern u8 voiceDirectSlots[];
extern u8 voiceMidiKeySlots[][SYNTH_VOICE_MIDI_KEY_COUNT];
extern u16 voicePrioSortRootListRoot;
extern u8 voiceMusicRunning;
extern u8 voiceFxRunning;
extern u8 voiceListInsert;
extern u8 voiceListRoot;
extern u32 get_vidlist(u32 id);

static u8 vidListNodes[0x800];
static u8 midiKeySlots[0x80];
static u8 directSlots[0x40];
static VoiceListNode priorityLinks[0x40];
static u8 priorityGroupHeads[0x100];
static u16 prioritySortLinks[0x200];
static VoiceListNode freeList[0x40];

static inline void voiceInitFreeList(void)
{
    u32 i;

    for (i = 0; i < synthInfo.voiceCount; i++)
    {
        freeList[i].prev = i - 1;
        freeList[i].next = i + 1;
        freeList[i].time = 1;
    }
    freeList[0].prev = 0xff;
    freeList[synthInfo.voiceCount - 1].next = 0xff;
    voiceListRoot = 0;
    voiceListInsert = synthInfo.voiceCount - 1;
}

static inline void voiceInitPrioSort(void)
{
    u32 i;

    for (i = 0; i < synthInfo.voiceCount; i++)
    {
        priorityLinks[i].time = 0;
    }
    for (i = 0; i < 0x100; i++)
    {
        priorityGroupHeads[i] = 0xff;
    }
    voicePrioSortRootListRoot = 0xffff;
}

/*
 * Initialize the voice priority and group linked-list tables.
 */
void voiceInitPriorityTables(void)
{
    voiceInitFreeList();
    voiceInitPrioSort();
    voiceFxRunning = 0;
    voiceMusicRunning = 0;
}

/*
 * Voice cleanup: if voice handle is valid, break the active voice and
 * reset its id slot.
 */
void voiceBreakAndFree(u32 voice)
{
    if (voice == SYNTH_INVALID_VOICE)
        return;
    if (hwIsActive(voice) != 0)
    {
        hwBreak(voice);
    }
    synthVoice[voice].handle = voice;
    voiceFree((int)&synthVoice[voice]);
    synthVoice[voice].callbackActive = 0;
}

/*
 * Voice teardown: clears state flags then breaks the voice.
 */
void voiceKill(u32 voice)
{
    McmdVoiceState* voiceState = SYNTH_VOICE_STATE(voice);

    if (voiceState->activeHandle != 0)
    {
        vidRemoveVoice(voiceState);
        *(u64*)&voiceState->inputFlags &= ~3;
        voiceState->priorityTick = 0;
        voiceFree((int)voiceState);
    }
    if (voiceState->callbackActive != 0)
    {
        streamKill(voice);
    }
    hwBreak(voice);
}

/*
 * Walk the synth's voice list for the given id, breaking each match.
 * Returns 0 if at least one match was broken, else -1.
 */
int voiceKillById(u32 id)
{
    int result = -1;
    u32 nextHandle;
    u32 i;

    if (gSynthInitialized != 0)
    {
        u32 listEntry;
        if ((id != SYNTH_INVALID_VOICE) && ((listEntry = get_vidlist(id)) != 0))
        {
            id = *(u32*)(listEntry + 0xc);
        }
        else
        {
            id = SYNTH_INVALID_VOICE;
        }

        for (; id != SYNTH_INVALID_VOICE; id = nextHandle)
        {
            i = (u8)id;
            nextHandle = SYNTH_VOICE_STATE(i)->nextHandle;
            if (id == SYNTH_VOICE_STATE(i)->handle)
            {
                voiceKill(i);
                result = 0;
            }
        }
    }

    return result;
}

/*
 * Returns 1 if state's voice id is currently registered in the
 * appropriate slot table, else 0.
 */
int voiceIsRegistered(int state)
{
    McmdVoiceState* voiceState = (McmdVoiceState*)state;
    u32 voice = voiceState->handle;
    u8 slot;
    u8 channel;
    u8 voiceIdx;
    if (voice == SYNTH_INVALID_VOICE)
        goto fail;
    slot = voiceState->midiSlot;
    if (slot == SYNTH_INVALID_VOICE_U8)
        goto fail;
    channel = voiceState->midiChannel;
    voiceIdx = voice;
    if (channel == SYNTH_INVALID_VOICE_U8)
    {
        if (voiceDirectSlots[voiceIdx] == voiceIdx)
            return 1;
        goto fail;
    }
    if (voiceIdx == voiceMidiKeySlots[channel][slot])
        return 1;
fail:
    return 0;
}

/*
 * Register the state's voice id in either the 1D or 2D slot table.
 */
void voiceRegister(McmdVoiceState* state)
{
    McmdVoiceState* voiceState = state;
    u32 voice = voiceState->handle;
    u8 slot;
    u8 channel;
    u8 voiceIdx;
    if (voice == SYNTH_INVALID_VOICE)
        return;
    slot = voiceState->midiSlot;
    if (slot == SYNTH_INVALID_VOICE_U8)
        return;
    channel = voiceState->midiChannel;
    voiceIdx = voice;
    if (channel == SYNTH_INVALID_VOICE_U8)
    {
        voiceDirectSlots[voiceIdx] = voiceIdx;
    }
    else
    {
        voiceMidiKeySlots[channel][slot] = voiceIdx;
    }
}

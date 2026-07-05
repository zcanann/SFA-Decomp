#include "main/audio/voice_manage.h"
#include "main/audio/hw_init.h"
#include "main/audio/synth_jobs.h"
extern u32 get_vidlist(u32 id);

typedef struct VoiceListNode
{
    u8 prev;
    u8 next;
    u16 time;
} VoiceListNode;

typedef struct VidListBlock
{
    u8 vidLists[0x800];
    u8 midiKeySlots[0x80];
    u8 directSlots[0x40];
    VoiceListNode priorityLinks[0x40];
    u8 priorityGroupHeads[0x100];
    u16 prioritySortLinks[0x200];
    VoiceListNode freeList[0x40];
} VidListBlock;

extern SynthVoiceState* synthVoice;
extern VidListBlock vidListNodes;
extern u8 lbl_803BD150[];
extern u8 gSynthInitialized;
extern u8 voiceDirectSlots[];
extern u8 voiceMidiKeySlots[][SYNTH_VOICE_MIDI_KEY_COUNT];
extern u16 voicePrioSortRootListRoot;
extern u8 voiceMusicRunning;
extern u8 voiceFxRunning;
extern u8 voiceListInsert;
extern u8 voiceListRoot;

#define SYNTH_VOICE_STATE(voice) (&synthVoice[voice])

/*
 * Initialize the voice priority and group linked-list tables.
 */
void voiceInitPriorityTables(void)
{
    VidListBlock* vb = &vidListNodes;
    u8* np = &lbl_803BD150[0x210];
    u32 i;
    u32 n;

    n = *np;
    for (i = 0; i < n; i++)
    {
        ((VoiceListNode*)(u32)vb->freeList)[i].prev = i - 1;
        ((VoiceListNode*)(u32)vb->freeList)[i].next = i + 1;
        ((VoiceListNode*)(u32)vb->freeList)[i].time = 1;
    }
    vb->freeList[0].prev = 0xff;
    n = *np;
    vb->freeList[n - 1].next = 0xff;
    voiceListRoot = 0;
    voiceListInsert = n - 1;
    for (i = 0; i < n; i++)
    {
        ((VoiceListNode*)(u32)vb->priorityLinks)[i].time = 0;
    }
    for (i = 0; i < 0x100; i++)
    {
        ((u8*)(u32)vb->priorityGroupHeads)[i] = 0xff;
    }
    voicePrioSortRootListRoot = 0xffff;
    voiceFxRunning = 0;
    voiceMusicRunning = 0;
}

/*
 * Voice cleanup: if voice handle is valid, break the active voice and
 * reset its id slot.
 *
 * EN v1.1 Address: 0x80279FAC, size 128b
 */
void voiceBreakAndFree(u32 voice)
{
    if (voice == SYNTH_INVALID_VOICE) return;
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
 *
 * EN v1.1 Address: 0x8027A02C, size 160b
 */
void voiceKill(u32 voice)
{
    SynthVoiceState* voiceState = SYNTH_VOICE_STATE(voice);

    if (voiceState->activeHandle != 0)
    {
        vidRemoveVoice((int)voiceState);
        voiceState->cFlags &= ~3;
        voiceState->priorityTick = 0;
        voiceFree((int)voiceState);
    }
    if (voiceState->callbackActive != 0)
    {
        synthCancelJob(voice);
    }
    hwBreak(voice);
}

/*
 * Walk the synth's voice list for the given id, breaking each match.
 * Returns 0 if at least one match was broken, else -1.
 *
 * EN v1.1 Address: 0x8027A0CC, size 272b
 */
int voiceKillById(u32 id)
{
    int result = -1;
    u32 nextHandle;
    u32 i;

    if (gSynthInitialized != 0)
    {
        u32 s;
        if ((id != SYNTH_INVALID_VOICE) && ((s = get_vidlist(id)) != 0))
        {
            id = *(u32*)(s + 0xc);
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
 *
 * EN v1.1 Address: 0x8027A1DC, size 124b
 */
int voiceIsRegistered(int state)
{
    SynthVoiceState* voiceState = (SynthVoiceState*)state;
    u32 voice = voiceState->handle;
    u8 a;
    u8 b;
    u8 v;
    if (voice == SYNTH_INVALID_VOICE) goto fail;
    a = voiceState->midiSlot;
    if (a == SYNTH_INVALID_VOICE_U8) goto fail;
    b = voiceState->midiChannel;
    v = voice;
    if (b == SYNTH_INVALID_VOICE_U8)
    {
        if (voiceDirectSlots[v] == v) return 1;
        goto fail;
    }
    if (v == voiceMidiKeySlots[b][a]) return 1;
fail:
    return 0;
}

/*
 * Register the state's voice id in either the 1D or 2D slot table.
 *
 * EN v1.1 Address: 0x8027A258, size 92b
 */
void voiceRegister(int state)
{
    SynthVoiceState* voiceState = (SynthVoiceState*)state;
    u32 voice = voiceState->handle;
    u8 a;
    u8 b;
    u8 v;
    if (voice == SYNTH_INVALID_VOICE) return;
    a = voiceState->midiSlot;
    if (a == SYNTH_INVALID_VOICE_U8) return;
    b = voiceState->midiChannel;
    v = voice;
    if (b == SYNTH_INVALID_VOICE_U8)
    {
        voiceDirectSlots[v] = v;
    }
    else
    {
        voiceMidiKeySlots[b][a] = v;
    }
}

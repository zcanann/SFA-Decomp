#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/floorf.h"
#include "main/audio/inp_midi.h"
#include "main/audio/synth_callback.h"
#include "main/audio/synth_handle.h"
#include "main/audio/synth_queue.h"
#include "main/audio/synth_seq_dispatch.h"
#include "main/audio/synth_seq_events.h"
#include "main/audio/synth_voice.h"

typedef struct
{
    u32 time;       // 0x0
    u8 prgChange;   // 0x4
    u8 velocity;    // 0x5
    u8 res[2];      // 0x6
    u16 pattern;    // 0x8
    s8 transpose;   // 0xa
    s8 velocityAdd; // 0xb
} SeqTrackEntry;    // size 0xc

typedef struct
{
    u16 time;    // 0x0
    u8 key;      // 0x2
    u8 velocity; // 0x3
    u16 length;  // 0x4
} SeqNoteData;   // size 0x6

/* Standard MIDI controller (CC) numbers dispatched by the sequencer. */
#define MCMD_CTRL_MODULATION 0x01
#define MCMD_CTRL_VOLUME     0x07
#define MCMD_CTRL_PITCH_BEND 0x80

/* Sequencer meta-command sub-codes (carried in the high nibble of a note event). */
#define SEQ_META_KEY_OFF       0x82
#define SEQ_META_START_PENDING 0x68
#define SEQ_META_LOOP_MARK     0x69
#define SEQ_META_LOOP_MARK_HI  0x6a
#define SEQ_META_RESET_CTRL    0x79
#define SEQ_META_ALL_NOTES_OFF 0x7b

/* Empty double-buffered time slot marker. */
#define SEQ_TIME_EMPTY 0x7fffffff

extern u8 synthITDDefault[];

static inline void seqInitStream(SynthSequenceStream* stream, u32 streamDataOffset)
{
    u16 delta;

    if (streamDataOffset != 0)
    {
        if ((stream->cursor = synthReadVariablePair(
                 (u8*)(streamDataOffset + (u32)gSynthCurrentVoice->arrbase), &delta,
                 &stream->step)) != 0)
        {
            stream->nextTime = delta;
        }
        else
        {
            stream->nextTime = SEQ_TIME_EMPTY;
        }
    }
    else
    {
        stream->nextTime = SEQ_TIME_EMPTY;
    }
}

static inline u16 seqHandleStream(SynthSequenceStream* stream)
{
    u16 delta;

    stream->value += stream->step;
    if (stream->cursor != 0)
    {
        if ((stream->cursor = synthReadVariablePair(stream->cursor, &delta, &stream->step)) != 0)
        {
            stream->nextTime += delta;
        }
        else
        {
            stream->nextTime = SEQ_TIME_EMPTY;
        }
    }
    else
    {
        stream->nextTime = SEQ_TIME_EMPTY;
    }
    return stream->value;
}

static inline void seqDoPrgChange(SynthVoiceRuntime* rt, SynthVoice* voice, u8 program, u32 midi)
{
    rt->voiceNotes[gSynthCurrentVoiceSlotIndex][midi] = 0xFFFF;
    if (midi != 9)
    {
        program = voice->normTrans[program];
        if (program == 0xff)
        {
            return;
        }
        voice->prgState[midi].macId = voice->normtab[program].macro;
        voice->prgState[midi].priority = voice->normtab[program].priority;
        voice->prgState[midi].maxVoices = voice->normtab[program].maxVoices;
        return;
    }
    program = voice->drumTrans[program];
    if (program == 0xff)
    {
        return;
    }
    voice->prgState[midi].macId = voice->drumtab[program].macro;
    voice->prgState[midi].priority = voice->drumtab[program].priority;
    voice->prgState[midi].maxVoices = voice->drumtab[program].maxVoices;
}

/*
 * Dispatch a queued voice/MIDI channel event by type, then pull the next
 * event for the channel.
 */
SynthSequenceEvent* synthHandleSequenceEvent(SynthSequenceEvent* event, u8 voice, u32* flag)
{
    SynthSequenceState* pa;
    SeqNoteData* pe;
    int velocity;
    int key;
    u32 midi;
    u16 macId;
    SynthCallbackLink* note;
    SeqTrackEntry* tEntry;
    SynthSequenceState* pattern;
    SynthVoiceRuntime* rt;

    rt = SYNTH_VOICE_RUNTIME();
    switch (event->type)
    {
    case 4:
    {
        SynthVoice* sv;
        u8* seq;
        u8* pptr;
        u8 prog;

        tEntry = (SeqTrackEntry*)event->data;
        sv = gSynthCurrentVoice;
        seq = sv->arrbase;
        pattern = SYNTH_SEQUENCE_STATE(sv, event->trackId);
        pptr = (u8*)(*(u32*)(*(u32*)(seq + 4) + (u32)seq + tEntry->pattern * 4) + (u32)seq);
        pattern->noteData = pptr + 0xc;
        pattern->lastTime = 0;
        pattern->baseTime = tEntry->time;
        pattern->patternInfo = tEntry;
        seqInitStream(&pattern->pitchBend, *(u32*)(pptr + 4));
        pattern->pitchBend.value = 0x2000;
        seqInitStream(&pattern->modulation, *(u32*)(pptr + 8));
        pattern->modulation.value = 0;
        pattern->midi = *(u8*)(*(u32*)(gSynthCurrentVoice->arrbase + 8) +
                               (u32)gSynthCurrentVoice->arrbase + event->trackId);
        prog = tEntry->prgChange;
        if (prog != 0xff)
        {
            seqDoPrgChange(rt, gSynthCurrentVoice, prog, pattern->midi);
        }
        if (tEntry->velocity != 0xff)
        {
            inpSetMidiCtrl(MCMD_CTRL_VOLUME, pattern->midi, gSynthCurrentVoiceSlotIndex & 0xff, tEntry->velocity);
        }
        break;
    }
    case 0:
        pe = (SeqNoteData*)event->data;
        pa = event->state;
        key = pe->key;
        velocity = pe->velocity;
        midi = pa->midi;

        if (key & 0x80)
        {
            switch (velocity)
            {
            case 0:
                seqDoPrgChange(rt, gSynthCurrentVoice, key & 0x7f, midi);
                break;
            case 1:
                inpSetMidiCtrl(SEQ_META_KEY_OFF, midi, gSynthCurrentVoiceSlotIndex & 0xff, key & 0x7f);
                break;
            default:
                if ((velocity & 0x80) == 0x80)
                {
                    switch (velocity & 0x7f)
                    {
                    case SEQ_META_START_PENDING:
                        if (gSynthCurrentVoice->pendingStartActive != 0)
                        {
                            synthStartHandleFromRequest(SYNTH_VOICE_PENDING_START_REQUEST(gSynthCurrentVoice),
                                                        SYNTH_VOICE_PENDING_START_OUT_HANDLE(gSynthCurrentVoice), 1);
                            gSynthCurrentVoice->pendingStartActive = 0;
                        }
                        break;
                    case SEQ_META_LOOP_MARK:
                        rt->voiceNotes[gSynthCurrentVoiceSlotIndex][midi] = key & 0x7f;
                        break;
                    case SEQ_META_LOOP_MARK_HI:
                        rt->voiceNotes[gSynthCurrentVoiceSlotIndex][midi] = (key & 0x7f) + 0x80;
                        break;
                    case SEQ_META_RESET_CTRL:
                        inpResetMidiCtrl(midi, gSynthCurrentVoiceSlotIndex & 0xff, 0);
                        break;
                    case SEQ_META_ALL_NOTES_OFF:
                        synthFlushCallbacks();
                        break;
                    default:
                        inpSetMidiCtrl(velocity & 0x7f, midi, gSynthCurrentVoiceSlotIndex & 0xff, key & 0x7f);
                        break;
                    }
                }
                break;
            }
        }
        else
        {
            SynthVoice* sv = gSynthCurrentVoice;
            if (((u32*)&sv->immediateMixValue0)[event->trackId / 32] & (1 << (event->trackId & 0x1f)))
            {
                if ((macId = sv->prgState[midi].macId) != 0xFFFF)
                {
                    key += ((SeqTrackEntry*)pa->patternInfo)->transpose;
                    key = key > 0x7f ? 0x7f : key < 0 ? 0 : key;
                    velocity += ((SeqTrackEntry*)pa->patternInfo)->velocityAdd;
                    velocity = velocity > 0x7f ? 0x7f : velocity < 0 ? 0 : velocity;
                    if ((note = synthAllocCallback(event->time + pe->length, voice)) != NULL)
                    {
                        SynthVoice* sv2;
                        s16 mod;
                        u8 vt;
                        u8 tid;

                        if (gSynthCurrentFadeOutState != 0)
                        {
                            mod = -1;
                        }
                        else
                        {
                            mod = 0;
                        }
                        sv2 = gSynthCurrentVoice;
                        tid = event->trackId;
                        vt = sv2->defStudio;
                        if ((note->callbackId =
                                 synthStartSound(macId, sv2->prgState[midi].priority,
                                                 sv2->prgState[midi].maxVoices, key & 0xff,
                                                 velocity & 0xff, 0x40, midi, gSynthCurrentVoiceSlotIndex & 0xff,
                                                 voice, 0, tid, sv2->trackVolumeGroup[tid], mod, vt,
                                                 synthITDDefault[vt * 2])) == 0xFFFFFFFF)
                        {
                            if (note->next != 0)
                            {
                                note->next->prev = note->prev;
                            }
                            if (note->prev != 0)
                            {
                                note->prev->next = note->next;
                            }
                            else
                            {
                                SynthVoice* sv3 = gSynthCurrentVoice;
                                sv3->callbackLists[note->listIndex] = note->next;
                            }
                            if ((note->next = gSynthFreeCallbacks) != 0)
                            {
                                gSynthFreeCallbacks->prev = note;
                            }
                            note->prev = 0;
                            gSynthFreeCallbacks = note;
                        }
                    }
                }
            }
        }
        break;
    case 2:
        pa = event->state;
        inpSetMidiCtrl14(MCMD_CTRL_PITCH_BEND, pa->midi, gSynthCurrentVoiceSlotIndex & 0xff,
                         seqHandleStream(&pa->pitchBend));
        break;
    case 1:
        pa = event->state;
        inpSetMidiCtrl14(MCMD_CTRL_MODULATION, pa->midi, gSynthCurrentVoiceSlotIndex & 0xff,
                         seqHandleStream(&pa->modulation));
        break;
    case 3:
        *flag |= 1;
        return 0;
    }
    return synthGetNextChannelEvent(event->trackId);
}

/*
 * Iterate 64 voice slots: for each active one, append it to the studio's
 * voice list. Uses an indirection table when present.
 */
void fn_8026E864(void)
{
    u32 i;
    SynthSequenceEvent* event;

    if (gSynthCurrentVoice->keyGroupMap == 0)
    {
        for (i = 0; i < 0x40; i++)
        {
            event = synthGetNextChannelEvent((u8)i);
            if (event != 0)
            {
                synthInsertChannelEvent(&gSynthCurrentVoice->section[0], event);
            }
        }
    }
    else
    {
        for (i = 0; i < 0x40; i++)
        {
            event = synthGetNextChannelEvent((u8)i);
            if (event != 0)
            {
                synthInsertChannelEvent(&gSynthCurrentVoice->section[gSynthCurrentVoice->keyGroupMap[i]], event);
            }
        }
    }
}

void fn_8026E90C(u8 voice)
{
    u32 group;
    u32 i;
    SynthSequenceEvent* event;

    if (gSynthCurrentVoice->keyGroupMap == 0)
    {
        for (i = 0; i < 0x40; i++)
        {
            event = synthGetNextChannelEvent((u8)i);
            if (event != 0)
            {
                synthInsertChannelEvent(&gSynthCurrentVoice->section[0], event);
            }
        }
    }
    else
    {
        group = voice & 0xff;
        for (i = 0; i < 0x40; i++)
        {
            if (group == gSynthCurrentVoice->keyGroupMap[i])
            {
                event = synthGetNextChannelEvent((u8)i);
                if (event != 0)
                {
                    synthInsertChannelEvent(&gSynthCurrentVoice->section[group], event);
                }
            }
        }
    }
}

static inline u32 seqGetNextEventTime(SynthSequenceQueue* section)
{
    return section->eventList == NULL ? 0 : section->eventList->time;
}

static inline SynthSequenceEvent* seqGetGlobalEvent(SynthSequenceQueue* section)
{
    SynthSequenceEvent* ev;

    ev = section->eventList;
    if (ev != NULL && (section->eventList = ev->next) != NULL)
    {
        section->eventList->prev = NULL;
    }
    return ev;
}

static inline f32 seq_fmod(f32 x, f32 y)
{
    f32 ay;
    f32 ax;

    ay = __fabsf(y);
    ax = __fabsf(x);
    if (ay > ax)
    {
        return x;
    }
    return x - y * (f32)(s64)(u64)(x / y);
}

static inline void seqSetTickDelta(SynthSequenceQueue* section, u32 deltaTime)
{
    f32 tickDelta;

    tickDelta = (1.f / 40960000.f) * ((f32)section->bpm * deltaTime);
    tickDelta *= (1.f / 256.f) * (f32)section->speed;
    section->tickDelta[section->timeIndex].low = seq_fmod(65536.f * tickDelta, 65536.f);
    section->tickDelta[section->timeIndex].high = (int)floorf(tickDelta);
}

u32 synthProcessChannelEventQueue(u8 voice, u32 param)
{
    SynthSequenceQueue* vp;
    SynthSequenceEvent* event;
    SynthSequenceEvent* res;
    u32 flag;
    SynthTimeWord unusedTime;

    flag = 0;
    vp = (SynthSequenceQueue*)((u8*)gSynthCurrentVoice + voice * 56 + 0x14e8);
    while ((vp->eventList == NULL ? 0 : vp->eventList->time) <= vp->time[vp->timeIndex].high)
    {
        SynthSequenceEvent* ev = vp->eventList;
        if (ev != NULL && (vp->eventList = ev->next) != NULL)
        {
            vp->eventList->prev = NULL;
        }
        if ((event = ev) == NULL)
        {
            if (flag == 0)
            {
                return 0;
            }
            flag = 0;
            vp->timeIndex ^= 1;
            vp->time[vp->timeIndex].high = ((SynthArrangement*)gSynthCurrentVoice->arrbase)->loopPoint[voice];
            vp->time[vp->timeIndex].low = vp->time[vp->timeIndex ^ 1].low;
            {
                u8* voiceState = (u8*)(voice * 56);
                voiceState += (u32)gSynthCurrentVoice;
                if (*(void**)(voiceState + 0x14e8) != NULL)
                {
                    *(int*)(voiceState + 0x14ec) = *(int*)(voiceState + 0x14e8);
                    seqHandleMasterTrack(voice);
                    seqSetTickDelta((SynthSequenceQueue*)((u8*)gSynthCurrentVoice + voice * 56 + 0x14e8), param);
                }
            }
            vp->loopCount += 1;
            fn_8026E90C(voice);
            continue;
        }
        res = synthHandleSequenceEvent(event, voice, &flag);
        if (res != 0)
        {
            synthInsertChannelEvent(vp, res);
        }
    }
    return 1;
}

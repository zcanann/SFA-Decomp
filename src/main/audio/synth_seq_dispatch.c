#include "ghidra_import.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/floorf.h"

#pragma exceptions on

typedef struct
{
    u16 macroId;   // 0x0
    u8 a;          // 0x2
    u8 b;          // 0x3
    u16 unk4;      // 0x4
} SynthPatchEntry; // size 0x6

typedef struct
{
    u16 macroId;  // 0x0
    u8 a;         // 0x2
    u8 b;         // 0x3
} SynthChanPatch; // size 0x4

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

typedef struct
{
    u8* next;    // 0x0
    u8* prev;    // 0x4
    u32 time;    // 0x8
    u8* data;    // 0xc -- SeqTrackEntry (track event) or SeqNoteData (pattern note)
    u8* chanRec; // 0x10 -- SynthChanRec of the dispatching channel
    u8 type;     // 0x14
    u8 trackId;  // 0x15
    u8 pad16[2]; // 0x16
} SeqEvent;      // size 0x18

typedef struct
{
    u32 cur;    // 0x0 -- stream data cursor
    u16 val;    // 0x4 -- current controller value
    s16 step;   // 0x6 -- pending value delta
    u32 time;   // 0x8 -- next event time
} SeqStream;    // size 0xc

typedef struct
{
    u32 unk0;             // 0x0
    u32 entryTime;        // 0x4
    u32 dataPtr;          // 0x8
    u32 eventPtr;         // 0xc
    SeqStream pitchBend;  // 0x10
    SeqStream modulation; // 0x1c
    u8 chan;              // 0x28
    u8 pad29[3];          // 0x29
} SynthChanRec;           // size 0x2c

typedef struct
{
    u8 pad0[0x10];                // 0x0
    SynthPatchEntry* patchTable;  // 0x10
    u8 progs[0x80];               // 0x14
    SynthPatchEntry* drumTable;   // 0x94
    u8 drumProgs[0x80];           // 0x98
    u8* seqData;                  // 0x118
    u32 chanBits[8];              // 0x11c
    u8 pad13C[0x1e8];             // 0x13c
    u8 chanMap[0x40];             // 0x324
    SynthChanRec records[0x40];   // 0x364
    u32 cbHeads[3];               // 0xe64
    SynthChanPatch chanPatch[16]; // 0xe70
    u8 padEB0[4];                 // 0xeb0
    u8 startRequest[0x28];        // 0xeb4
    u32* handleOut;               // 0xedc
    u8 startPending;              // 0xee0
    u8 studioIndex;               // 0xee1
} SynthMidiState;

typedef struct
{
    u8 pad0[0xd740];
    u16 midiCtrl[8][16]; // 0xd740
} SynthMidiCtrlBlock;

typedef struct
{
    u32 unk0;          // 0x0
    u32 pTab;          // 0x4
    u32 tmTab;         // 0x8
    u32 unkC;          // 0xc
    u32 unk10;         // 0x10
    u32 loopPoint[16]; // 0x14
} SeqArrBase;

typedef struct
{
    u32 low;   // 0x0
    u32 high;  // 0x4
} SeqTimeWord; // size 0x8

typedef struct
{
    u8* trackBase;          // 0x0
    u8* trackCursor;        // 0x4
    u32 bpm;                // 0x8
    SeqTimeWord scratch[2]; // 0xc
    SeqEvent* eventList;    // 0x1c
    SeqTimeWord time[2];    // 0x20
    u8 timeIndex;           // 0x30
    u8 unk31;               // 0x31
    u16 speed;              // 0x32
    u16 loopCount;          // 0x34
    u8 unk36[2];            // 0x36
} SeqQueue;                 // size 0x38

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

extern int gSynthCurrentVoice;
extern int gSynthCurrentVoiceSlotIndex;
extern u32* gSynthFreeCallbacks;
extern u8 lbl_803AF550[];
extern u8 lbl_803BDA24[];
extern u8 lbl_803DE224;

extern int synthGetNextChannelEvent(u8 i);
extern void synthInsertChannelEvent(int slot, int item);
extern u8* synthReadVariablePair(u8* p, u16* tagOut, s16* valueOut);
extern void inpSetMidiCtrl(u8 ctrl, u8 channel, u8 set, u8 value);
extern void inpSetMidiCtrl14(u8 ctrl, u8 channel, u8 set, u16 value);
extern void inpResetMidiCtrl(u8 a, u8 b, u32 mode);
extern void synthStartHandleFromRequest(int request, u32* outHandle, u8 noLock);
extern void synthFlushCallbacks(void);
extern u32* synthAllocCallback(s32 triggerValue, u8 controllerIndex);
extern int synthStartSound(u32 sampleId, char key, u32 velocity, u32 flags, u32 volume, u32 pan, u32 midi, u32 midiSet,
                           u8 section, u16 step, u16 trackid, u8 auxIndex, int keyOffset, u8 studio, u32 studioAux);
extern int fn_8026CF78(u8 voice);

static inline void seqInitStream(SeqStream* stream, u32 streamDataOffset)
{
    u16 delta;

    if (streamDataOffset != 0)
    {
        if ((stream->cur = (u32)synthReadVariablePair(
                 (u8*)(streamDataOffset + (u32)((SynthMidiState*)gSynthCurrentVoice)->seqData), &delta,
                 &stream->step)) != 0)
        {
            stream->time = delta;
        }
        else
        {
            stream->time = SEQ_TIME_EMPTY;
        }
    }
    else
    {
        stream->time = SEQ_TIME_EMPTY;
    }
}

static inline u16 seqHandleStream(SeqStream* stream)
{
    u16 delta;

    stream->val += stream->step;
    if (stream->cur != 0)
    {
        if ((stream->cur = (u32)synthReadVariablePair((u8*)stream->cur, &delta, &stream->step)) != 0)
        {
            stream->time += delta;
        }
        else
        {
            stream->time = SEQ_TIME_EMPTY;
        }
    }
    else
    {
        stream->time = SEQ_TIME_EMPTY;
    }
    return stream->val;
}

static inline void seqDoPrgChange(SynthMidiState* seq, u8 prg, u32 midi)
{
    ((SynthMidiCtrlBlock*)lbl_803AF550)->midiCtrl[gSynthCurrentVoiceSlotIndex][midi] = 0xFFFF;
    if (midi != 9)
    {
        prg = seq->progs[prg];
        if (prg == 0xff)
        {
            return;
        }
        seq->chanPatch[midi].macroId = seq->patchTable[prg].macroId;
        seq->chanPatch[midi].a = seq->patchTable[prg].a;
        seq->chanPatch[midi].b = seq->patchTable[prg].b;
        return;
    }
    prg = seq->drumProgs[prg];
    if (prg == 0xff)
    {
        return;
    }
    seq->chanPatch[midi].macroId = seq->drumTable[prg].macroId;
    seq->chanPatch[midi].a = seq->drumTable[prg].a;
    seq->chanPatch[midi].b = seq->drumTable[prg].b;
}

/*
 * Dispatch a queued voice/MIDI channel event by type, then pull the next
 * event for the channel.
 */
int fn_8026E0E4(SeqEvent* event, u8 voice, u32* flag)
{
    SynthMidiCtrlBlock* base = (SynthMidiCtrlBlock*)lbl_803AF550;
    SynthChanRec* pa;
    SeqNoteData* pe;
    int velocity;
    int key;
    u32 midi;
    u16 macId;
    u32* note;
    SeqTrackEntry* tEntry;
    SynthChanRec* pattern;

    switch (event->type)
    {
    case 4:
    {
        SynthMidiState* sv;
        u8* seq;
        u8* pptr;
        u8 prog;

        tEntry = (SeqTrackEntry*)event->data;
        sv = (SynthMidiState*)gSynthCurrentVoice;
        seq = sv->seqData;
        pattern = &sv->records[event->trackId];
        pptr = (u8*)(*(u32*)(*(u32*)(seq + 4) + (u32)seq + tEntry->pattern * 4) + (u32)seq);
        pattern->dataPtr = (u32)(pptr + 0xc);
        pattern->unk0 = 0;
        pattern->entryTime = tEntry->time;
        pattern->eventPtr = (u32)tEntry;
        seqInitStream(&pattern->pitchBend, *(u32*)(pptr + 4));
        pattern->pitchBend.val = 0x2000;
        seqInitStream(&pattern->modulation, *(u32*)(pptr + 8));
        pattern->modulation.val = 0;
        pattern->chan = *(u8*)(*(u32*)(((SynthMidiState*)gSynthCurrentVoice)->seqData + 8) +
                               (u32)((SynthMidiState*)gSynthCurrentVoice)->seqData + event->trackId);
        prog = tEntry->prgChange;
        if (prog != 0xff)
        {
            SynthMidiState* sv2 = (SynthMidiState*)gSynthCurrentVoice;
            u8 chan = pattern->chan;
            u32 idx;

            base->midiCtrl[gSynthCurrentVoiceSlotIndex][chan] = 0xFFFF;
            if (chan != 9)
            {
                idx = sv2->progs[prog];
                if (idx != 0xff)
                {
                    sv2->chanPatch[chan].macroId = sv2->patchTable[idx].macroId;
                    sv2->chanPatch[chan].a = sv2->patchTable[idx].a;
                    sv2->chanPatch[chan].b = sv2->patchTable[idx].b;
                }
            }
            else
            {
                idx = sv2->drumProgs[prog];
                if (idx != 0xff)
                {
                    sv2->chanPatch[chan].macroId = sv2->drumTable[idx].macroId;
                    sv2->chanPatch[chan].a = sv2->drumTable[idx].a;
                    sv2->chanPatch[chan].b = sv2->drumTable[idx].b;
                }
            }
        }
        if (tEntry->velocity != 0xff)
        {
            inpSetMidiCtrl(MCMD_CTRL_VOLUME, pattern->chan, gSynthCurrentVoiceSlotIndex & 0xff, tEntry->velocity);
        }
        break;
    }
    case 0:
        pe = (SeqNoteData*)event->data;
        pa = (SynthChanRec*)event->chanRec;
        key = pe->key;
        velocity = pe->velocity;
        midi = pa->chan;

        if (key & 0x80)
        {
            switch (velocity)
            {
            case 0:
                seqDoPrgChange((SynthMidiState*)gSynthCurrentVoice, key & 0x7f, midi);
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
                        if (((SynthMidiState*)gSynthCurrentVoice)->startPending != 0)
                        {
                            synthStartHandleFromRequest((int)((SynthMidiState*)gSynthCurrentVoice)->startRequest,
                                                        ((SynthMidiState*)gSynthCurrentVoice)->handleOut, 1);
                            ((SynthMidiState*)gSynthCurrentVoice)->startPending = 0;
                        }
                        break;
                    case SEQ_META_LOOP_MARK:
                        base->midiCtrl[gSynthCurrentVoiceSlotIndex][midi] = key & 0x7f;
                        break;
                    case SEQ_META_LOOP_MARK_HI:
                        base->midiCtrl[gSynthCurrentVoiceSlotIndex][midi] = (key & 0x7f) + 0x80;
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
            SynthMidiState* sv = (SynthMidiState*)gSynthCurrentVoice;
            if (sv->chanBits[event->trackId / 32] & (1 << (event->trackId & 0x1f)))
            {
                if ((macId = sv->chanPatch[midi].macroId) != 0xFFFF)
                {
                    key += ((SeqTrackEntry*)pa->eventPtr)->transpose;
                    key = key > 0x7f ? 0x7f : key < 0 ? 0 : key;
                    velocity += ((SeqTrackEntry*)pa->eventPtr)->velocityAdd;
                    velocity = velocity > 0x7f ? 0x7f : velocity < 0 ? 0 : velocity;
                    if ((note = synthAllocCallback(event->time + pe->length, voice)) != NULL)
                    {
                        SynthMidiState* sv2;
                        s16 mod;
                        u8 vt;

                        if (lbl_803DE224 != 0)
                        {
                            mod = -1;
                        }
                        else
                        {
                            mod = 0;
                        }
                        sv2 = (SynthMidiState*)gSynthCurrentVoice;
                        vt = sv2->studioIndex;
                        if ((note[2] = synthStartSound(macId, sv2->chanPatch[midi].a, sv2->chanPatch[midi].b,
                                                       key & 0xff, velocity & 0xff, 0x40, midi,
                                                       gSynthCurrentVoiceSlotIndex & 0xff, voice, 0, event->trackId,
                                                       sv2->chanMap[event->trackId], mod, vt,
                                                       lbl_803BDA24[vt * 2])) == 0xFFFFFFFF)
                        {
                            if (note[0] != 0)
                            {
                                *(u32*)(note[0] + 4) = note[1];
                            }
                            if (note[1] != 0)
                            {
                                *(u32*)note[1] = note[0];
                            }
                            else
                            {
                                SynthMidiState* sv3 = (SynthMidiState*)gSynthCurrentVoice;
                                sv3->cbHeads[*((u8*)note + 0x11)] = note[0];
                            }
                            if ((note[0] = (u32)gSynthFreeCallbacks) != 0)
                            {
                                gSynthFreeCallbacks[1] = (u32)note;
                            }
                            note[1] = 0;
                            gSynthFreeCallbacks = note;
                        }
                    }
                }
            }
        }
        break;
    case 2:
        pa = (SynthChanRec*)event->chanRec;
        inpSetMidiCtrl14(MCMD_CTRL_PITCH_BEND, pa->chan, gSynthCurrentVoiceSlotIndex & 0xff,
                         seqHandleStream(&pa->pitchBend));
        break;
    case 1:
        pa = (SynthChanRec*)event->chanRec;
        inpSetMidiCtrl14(MCMD_CTRL_MODULATION, pa->chan, gSynthCurrentVoiceSlotIndex & 0xff,
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
    u32 x;
    if (*(u32*)(gSynthCurrentVoice + 0x14e4) == 0)
    {
        for (i = 0; i < 0x40; i++)
        {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0)
            {
                synthInsertChannelEvent(gSynthCurrentVoice + 0x14e8, x);
            }
        }
    }
    else
    {
        for (i = 0; i < 0x40; i++)
        {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0)
            {
                u8* table = *(u8**)(gSynthCurrentVoice + 0x14e4);
                synthInsertChannelEvent(gSynthCurrentVoice + table[i] * 0x38 + 0x14e8, x);
            }
        }
    }
}

void fn_8026E90C(u8 voice)
{
    u32 group;
    u32 i;
    u32 x;

    if (*(u32*)(gSynthCurrentVoice + 0x14e4) == 0)
    {
        for (i = 0; i < 0x40; i++)
        {
            x = synthGetNextChannelEvent((u8)i);
            if (x != 0)
            {
                synthInsertChannelEvent(gSynthCurrentVoice + 0x14e8, x);
            }
        }
    }
    else
    {
        group = voice & 0xff;
        for (i = 0; i < 0x40; i++)
        {
            if (group == *(u8*)(*(u32*)(gSynthCurrentVoice + 0x14e4) + i))
            {
                x = synthGetNextChannelEvent((u8)i);
                if (x != 0)
                {
                    synthInsertChannelEvent(gSynthCurrentVoice + group * 0x38 + 0x14e8, x);
                }
            }
        }
    }
}

static inline u32 seqGetNextEventTime(SeqQueue* section)
{
    return section->eventList == NULL ? 0 : section->eventList->time;
}

static inline SeqEvent* seqGetGlobalEvent(SeqQueue* section)
{
    SeqEvent* ev;

    ev = section->eventList;
    if (ev != NULL && (section->eventList = (SeqEvent*)ev->next) != NULL)
    {
        section->eventList->prev = NULL;
    }
    return ev;
}

#pragma fp_contract off
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

static inline void seqSetTickDelta(SeqQueue* section, u32 deltaTime)
{
    f32 tickDelta;

    tickDelta = (1.f / 40960000.f) * ((f32)section->bpm * deltaTime);
    tickDelta *= (1.f / 256.f) * (f32)section->speed;
    section->scratch[section->timeIndex].low = seq_fmod(65536.f * tickDelta, 65536.f);
    section->scratch[section->timeIndex].high = (int)floorf(tickDelta);
}

int fn_8026E9D0(u8 voice, u32 param)
{
    SeqQueue* vp;
    u8* event;
    int res;
    u32 flag;
    SeqTimeWord unusedTime;

    flag = 0;
    vp = (SeqQueue*)(gSynthCurrentVoice + voice * 56 + 0x14e8);
    while ((vp->eventList == NULL ? 0 : vp->eventList->time) <= vp->time[vp->timeIndex].high)
    {
        SeqEvent* ev = vp->eventList;
        if (ev != NULL && (vp->eventList = (SeqEvent*)ev->next) != NULL)
        {
            vp->eventList->prev = NULL;
        }
        if ((event = (u8*)ev) == NULL)
        {
            if (flag == 0)
            {
                return 0;
            }
            flag = 0;
            vp->timeIndex ^= 1;
            vp->time[vp->timeIndex].high =
                ((SeqArrBase*)((SynthMidiState*)gSynthCurrentVoice)->seqData)->loopPoint[voice];
            vp->time[vp->timeIndex].low = vp->time[vp->timeIndex ^ 1].low;
            {
                u8* voiceState = (u8*)(voice * 56);
                voiceState += gSynthCurrentVoice;
                if (*(void**)(voiceState + 0x14e8) != NULL)
                {
                    *(int*)(voiceState + 0x14ec) = *(int*)(voiceState + 0x14e8);
                    fn_8026CF78(voice);
                    seqSetTickDelta((SeqQueue*)(gSynthCurrentVoice + voice * 56 + 0x14e8), param);
                }
            }
            vp->loopCount += 1;
            fn_8026E90C(voice);
            continue;
        }
        res = fn_8026E0E4((SeqEvent*)event, voice, &flag);
        if (res != 0)
        {
            synthInsertChannelEvent((int)vp, res);
        }
    }
    return 1;
}
#pragma fp_contract reset

#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/hw_init.h"
#include "main/audio/snd_synth_legacy.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

#pragma exceptions on

#ifndef SYNTH_VOICE_STRIDE
#define SYNTH_VOICE_STRIDE 0x404
#endif

typedef struct
{
    u32* base; /* 0x00 */
    u32* evt;  /* 0x04 */
    u32 cur;   /* 0x08 */
    struct
    {
        u32 step;  /* +0x0 */
        u32 delta; /* +0x4 */
    } d[2];        /* 0x0c */
    u32 unk1c;     /* 0x1c */
    struct
    {
        u32 acc; /* +0x0 */
        u32 out; /* +0x4 */
    } o[2];      /* 0x20 */
    u8 idx;      /* 0x30 */
    u8 pad31;
    u16 vol;   /* 0x32 */
    u32 pad34; /* 0x34 */
} SynthStream; /* 0x38 */

typedef struct SynthSong
{
    struct SynthSong* next; /* 0x000 */
    struct SynthSong* prev; /* 0x004 */
    u8 active;              /* 0x008 */
    u8 index;               /* 0x009 */
    u8 pad0a[0x118 - 0xa];
    u32* seqWnd; /* 0x118 */
    u8 pad11c[0xe6c - 0x11c];
    u32* cbList; /* 0xe6c */
    u8 pad_e70[0xeb0 - 0xe70];
    u8 fadeIdx; /* 0xeb0 */
    u8 pad_eb1[0x31];
    u8 counter; /* 0xee2 */
    u8 pad_ee3[0x14e4 - 0xee3];
    u32 multiMode;           /* 0x14e4 */
    SynthStream streams[16]; /* 0x14e8 */
} SynthSong;

typedef struct
{
    u8 callbacks[0x1400]; /* 0x0000: 0x100 nodes of 0x14 */
    SynthSong songs[8];   /* 0x1400 */
    u16 lastNotes[8][16]; /* 0xd740 */
} SynthPool;

#define fabs __fabs

extern u8 lbl_803BCD90[];
extern u8 lbl_803BD150[];
extern u8* synthVoice;
extern SynthSong* gSynthQueuedVoices;
extern SynthSong* gSynthFreeVoices;
extern SynthSong* gSynthCurrentVoice;
extern u32 gSynthCurrentVoiceSlotIndex;
extern u8 lbl_803DE224;
extern u32 gSynthAllocatedVoices;
extern u32 gSynthNextHandle;
extern u32* gSynthFreeCallbacks;
extern f32 lbl_803E7780;
extern f32 lbl_803E7784;
extern f32 lbl_803E7788;
extern SynthPool lbl_803AF550;

extern u32 vidMakeNew(McmdVoiceState* svoice, u32 isMaster);
extern void vidRemoveVoice(McmdVoiceState* svoice);
extern void voiceRegister(McmdVoiceState* svoice);
extern u8 synthIsFadeOutActive(u8 idx);
extern u32 fn_8026E9D0(u8 ch, u32 dt);
extern int synthUpdateCallbacks(void);
extern void synthFreeCallback(void* cb);
extern void synthRecycleVoiceCallbacks(void* song);
extern float floorf(float x);

void synthSetStudioChannelScale(int value, u8 bank, u8 key);

/*
 * fn_8026EC44 - per-song pitch/mod LFO + event update pass.
 */
#pragma fp_contract off
static inline f32 sal_fmod(f32 x, f32 y, f64 absy)
{
    s64 n;

    if (absy > fabs(x))
    {
        return x;
    }
    n = (s64)(u64)(x / y);
    return x - y * (f32)n;
}

static inline void synthHandleKeyOffCallbacks(void)
{
    u32* node;
    u32* nnode;

    if (gSynthCurrentVoice->counter == 0)
    {
        node = gSynthCurrentVoice->cbList;
        while (node != NULL)
        {
            nnode = (u32*)*node;
            if ((node[2] != 0xffffffff) && (sndFXCheck(node[2]) == 0xffffffff))
            {
                synthFreeCallback(node);
            }
            node = nnode;
        }
    }
    gSynthCurrentVoice->counter = (gSynthCurrentVoice->counter + 1) % 5;
}

void fn_8026EC44(u32 dt)
{
    SynthSong* cs;
    u32* evt;
    int i;
    int hasFree;
    u32 sum;
    int cnt;
    SynthStream* st;
    u32 ch;
    u32 ret;
    u32 cb;
    SynthSong* song;
    SynthSong* next;
    f32 c0;
    f64 absRange;
    f32 range;
    f32 c1;
    f32 val;
    f32 freq;
    u8 fade;
    /* never referenced; reserves stack to match the retail frame (0xB0) */
    f32 unusedA[4];

    if (dt != 0)
    {
        range = lbl_803E7788;
        song = gSynthQueuedVoices;
        absRange = fabs(range);
        c0 = lbl_803E7780;
        c1 = lbl_803E7784;
        for (; song != NULL; song = next)
        {
            next = song->next;
            gSynthCurrentVoice = song;
            gSynthCurrentVoiceSlotIndex = song->index;
            fade = synthIsFadeOutActive(song->fadeIdx);
            cs = gSynthCurrentVoice;
            lbl_803DE224 = fade;
            if (cs->multiMode == 0)
            {
                st = (SynthStream*)((u8*)cs + 0x14E8);
                if (st->base != NULL)
                {
                    while (*(evt = st->evt) != 0xffffffff)
                    {
                        if (*evt > st->o[st->idx].out)
                        {
                            break;
                        }
                        if ((gSynthCurrentVoice->seqWnd[4] & 0x40000000) != 0)
                        {
                            synthSetStudioChannelScale((st->cur = evt[1]) >> 10, gSynthCurrentVoiceSlotIndex, 0);
                        }
                        else
                        {
                            synthSetStudioChannelScale(evt[1], gSynthCurrentVoiceSlotIndex, 0);
                            st->cur = st->evt[1] << 10;
                        }
                        st->evt = st->evt + 2;
                    }
                }
                cs = gSynthCurrentVoice;
                st = &cs->streams[0];
                freq = c0 * ((f32)st->cur * dt);
                freq = freq * (c1 * (f32)(u32)st->vol);
                val = range * freq;
                val = sal_fmod(val, range, absRange);
                st->d[st->idx].step = val;
                *(int*)&st->d[st->idx].delta = floorf(freq);
                ret = fn_8026E9D0(0, dt);
                cb = synthUpdateCallbacks();
                synthHandleKeyOffCallbacks();
                sum = gSynthCurrentVoice->streams[0].o[0].acc + gSynthCurrentVoice->streams[0].d[0].step;
                gSynthCurrentVoice->streams[0].o[0].acc = sum & 0xffff;
                sum = sum >> 16;
                gSynthCurrentVoice->streams[0].o[0].out += sum + gSynthCurrentVoice->streams[0].d[0].delta;
                sum = gSynthCurrentVoice->streams[0].o[1].acc + gSynthCurrentVoice->streams[0].d[1].step;
                gSynthCurrentVoice->streams[0].o[1].acc = sum & 0xffff;
                sum = sum >> 16;
                gSynthCurrentVoice->streams[0].o[1].out += sum + gSynthCurrentVoice->streams[0].d[1].delta;
            }
            else
            {
                ret = 0;
                for (ch = 0; ch < 0x10; ch++)
                {
                    st = &gSynthCurrentVoice->streams[(u8)ch];
                    if (st->base != NULL)
                    {
                        while (*(evt = st->evt) != 0xffffffff)
                        {
                            if (*evt > st->o[st->idx].out)
                            {
                                break;
                            }
                            if ((gSynthCurrentVoice->seqWnd[4] & 0x40000000) != 0)
                            {
                                synthSetStudioChannelScale((st->cur = evt[1]) >> 10, gSynthCurrentVoiceSlotIndex, ch);
                            }
                            else
                            {
                                synthSetStudioChannelScale(evt[1], gSynthCurrentVoiceSlotIndex, ch);
                                st->cur = st->evt[1] << 10;
                            }
                            st->evt = st->evt + 2;
                        }
                    }
                    cs = gSynthCurrentVoice;
                    st = &cs->streams[ch];
                    freq = c0 * ((f32)st->cur * dt);
                    freq = freq * (c1 * (f32)(u32)st->vol);
                    val = range * freq;
                    val = sal_fmod(val, range, absRange);
                    st->d[st->idx].step = val;
                    *(int*)&st->d[st->idx].delta = floorf(freq);
                    ret |= fn_8026E9D0(ch, dt);
                }
                cb = synthUpdateCallbacks();
                synthHandleKeyOffCallbacks();
                for (i = 0; i < 16; i++)
                {
                    sum = gSynthCurrentVoice->streams[i].o[0].acc + gSynthCurrentVoice->streams[i].d[0].step;
                    gSynthCurrentVoice->streams[i].o[0].acc = sum & 0xffff;
                    sum = sum >> 16;
                    gSynthCurrentVoice->streams[i].o[0].out += sum + gSynthCurrentVoice->streams[i].d[0].delta;
                    sum = gSynthCurrentVoice->streams[i].o[1].acc + gSynthCurrentVoice->streams[i].d[1].step;
                    gSynthCurrentVoice->streams[i].o[1].acc = sum & 0xffff;
                    sum = sum >> 16;
                    gSynthCurrentVoice->streams[i].o[1].out += sum + gSynthCurrentVoice->streams[i].d[1].delta;
                }
            }
            if ((ret == 0) && (cb == 0))
            {
                if (song->prev != NULL)
                {
                    *(SynthSong**)song->prev = next;
                }
                else
                {
                    gSynthQueuedVoices = next;
                }
                if (next != NULL)
                {
                    next->prev = song->prev;
                }
                synthRecycleVoiceCallbacks(song);
                song->active = 0;
                song->prev = NULL;
                if ((song->next = gSynthFreeVoices) != NULL)
                {
                    gSynthFreeVoices->prev = song;
                }
                gSynthFreeVoices = song;
            }
        }
    }
}
#pragma fp_contract reset

/*
 * fn_8026F30C - synth song/callback pool init.
 */
void fn_8026F30C(void)
{
    SynthSong* sp;
    u16* np;
    SynthPool* pool;
    u32 i;
    int j;
    u32 prev[1];

    pool = (SynthPool*)(u8*)&lbl_803AF550;
    gSynthQueuedVoices = NULL;
    np = pool->lastNotes[0];
    gSynthAllocatedVoices = 0;
    sp = &pool->songs[0];
    for (i = 0; i < 8; i++)
    {
        if (i == 0)
        {
            gSynthFreeVoices = sp;
            sp->prev = NULL;
        }
        else
        {
            (sp - 1)->next = sp;
            sp->prev = (SynthSong*)((u8*)pool->songs + (i - 1) * sizeof(SynthSong));
        }
        sp->index = i;
        sp->active = 0;
        for (j = 0; j < 16; j++)
        {
            np[j] = 0xffff;
        }
        np += 16;
        sp++;
    }
    prev[0] = 0;
    pool->songs[i - 1].next = (SynthSong*)prev[0];
    gSynthFreeCallbacks = (u32*)pool;
    for (i = prev[0]; i < 0x100; i++)
    {
        ((u32*)pool)[1] = prev[0];
        if (prev[0] != 0)
        {
            *(u32*)prev[0] = (u32)pool;
        }
        prev[0] = (u32)pool;
        pool = (SynthPool*)((u32*)pool + 5);
    }
    *(u32*)prev[0] = 0;
    gSynthNextHandle = 0;
}

/*
 * Set one studio/channel scale entry.
 */
void synthSetStudioChannelScale(int value, u8 bank, u8 key)
{
    if (bank == 0xff)
    {
        bank = 8;
    }
    *(u32*)(lbl_803BCD90 + bank * 0x40 + (key & 0xff) * 4) = (u32)((value << 3) * 0x600) / 0xf0;
}

/*
 * Look up an int from a 2D table indexed by state's ID bytes.
 */
int synthGetVoiceSlotChannelScale(u8* state)
{
    McmdVoiceState* v = (McmdVoiceState*)state;
    u32 bank;
    int key;
    if ((bank = v->midiEvent) == 0xff)
        bank = 8;
    key = v->midiLayer;
    return *(int*)(lbl_803BCD90 + bank * 64 + key * 4);
}

/*
 * Flag-check and conditional store.
 */
void fn_8026F5B8(int state)
{
    McmdVoiceState* v = (McmdVoiceState*)state;
    u64 flags;

    flags = *(u64*)&v->inputFlags;
    if ((flags & 0x20000) != 0)
    {
        return;
    }
    if (v->portamentoMode == 1)
    {
        if ((flags & 0x1000) == 0)
        {
            v->portamentoTime = 0;
        }
        else
        {
            v->portamentoTime = v->portamentoDuration;
        }
    }
    else
    {
        v->portamentoTime = v->portamentoDuration;
    }
    v->portamentoCurPitch = v->registeredKey << 0x10;
}

/*
 * Reuse an active voice matching the requested MIDI slot/channel.
 */
int audioFn_8026f630(u8 key, u8 slot, u8 channel, u32 voiceGroup, u32* outFlags)
{
    u32 i;
    u32 result;
    u32 previousId;
    McmdVoiceState* voice;
    McmdVoiceState* selectedVoice;
    u32 sawHeldVoice;

    sawHeldVoice = 0;
    result = -1;
    for (i = 0, voice = (McmdVoiceState*)synthVoice; i < lbl_803BD150[0x210]; ++i, ++voice)
    {
        if (voice->macroAllocating == 0 && voice->voiceHandle != 0xffffffff && voice->midiSlot == slot &&
            voice->midiEvent == channel)
        {
            if ((*(u64*)&voice->inputFlags & 2) != 0)
            {
                sawHeldVoice = 1;
            }
            if ((*(u64*)&voice->inputFlags & 0x10) != 0 && (*(u64*)&voice->inputFlags & 0x10000000008) != 8 &&
                hwIsActive(i) != 0)
            {
                if (result == 0xffffffff && (*(u64*)&voice->inputFlags & 0x20002) == 0x20002)
                {
                    *outFlags = 1;
                    return -1;
                }

                selectedVoice = voice;
                voice->portamentoCurPitch = ((u32)voice->key << 16) + ((s32)voice->fineTune << 16) / 100;
                voice->registeredKey = voice->key;
                voice->key = key + ((voice->key & 0xff) - voice->keyBase);
                voice->keyBase = key;
                voice->fineTune = 0;
                voice->portamentoTime = 0;
                voice->outputFlags = voice->outputFlags | 0x20000LL;
                vidRemoveVoice((McmdVoiceState*)(synthVoice + i * SYNTH_VOICE_STRIDE));
                if (result == 0xffffffff)
                {
                    voice->voiceNextHandle = 0xffffffff;
                    voice->voicePrevHandle = 0xffffffff;
                    result = vidMakeNew((McmdVoiceState*)(synthVoice + i * SYNTH_VOICE_STRIDE), voiceGroup);
                    previousId = voice->voiceHandle;
                }
                else
                {
                    ((McmdVoiceState*)synthVoice)[previousId & 0xff].voiceNextHandle = voice->voiceHandle;
                    voice->voicePrevHandle = previousId;
                    previousId = voice->voiceHandle;
                    vidMakeNew((McmdVoiceState*)(synthVoice + i * SYNTH_VOICE_STRIDE), 0);
                }
            }
        }
    }

    if (result != 0xffffffff)
    {
        voiceRegister(selectedVoice);
        inpSetMidiLastNote(selectedVoice->midiSlot, selectedVoice->midiEvent, selectedVoice->key & 0xff);
        *outFlags = 0;
    }
    else
    {
        *outFlags = sawHeldVoice;
    }
    return result;
}

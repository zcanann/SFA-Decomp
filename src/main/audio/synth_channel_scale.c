#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/hw_init.h"
#include "sfa_light_decls.h"

#ifndef SYNTH_VOICE_STRIDE
#define SYNTH_VOICE_STRIDE 0x404
#endif

extern u8 lbl_803BCD90[];
extern u8 lbl_803BD150[];
extern u8* synthVoice;
extern u32 vidMakeNew(McmdVoiceState* svoice, u32 isMaster);
extern void vidRemoveVoice(McmdVoiceState * svoice);
extern void voiceRegister(McmdVoiceState * svoice);

typedef struct
{
    u32* base; /* 0x00 */
    u32* evt; /* 0x04 */
    u32 cur; /* 0x08 */
    struct
    {
        u32 step; /* +0x0 */
        u32 delta; /* +0x4 */
    } d[2]; /* 0x0c */
    u32 unk1c; /* 0x1c */
    struct
    {
        u32 acc; /* +0x0 */
        u32 out; /* +0x4 */
    } o[2]; /* 0x20 */
    u8 idx; /* 0x30 */
    u8 pad31;
    u16 vol; /* 0x32 */
    u32 pad34; /* 0x34 */
} SynthStream; /* 0x38 */

typedef struct SynthSong
{
    struct SynthSong* next; /* 0x000 */
    struct SynthSong* prev; /* 0x004 */
    u8 active; /* 0x008 */
    u8 index; /* 0x009 */
    u8 pad0a[0x118 - 0xa];
    u32* seqWnd; /* 0x118 */
    u8 pad11c[0xe6c - 0x11c];
    u32* cbList; /* 0xe6c */
    u8 pad_e70[0xeb0 - 0xe70];
    u8 fadeIdx; /* 0xeb0 */
    u8 pad_eb1[0x31];
    u8 counter; /* 0xee2 */
    u8 pad_ee3[0x14e4 - 0xee3];
    u32 multiMode; /* 0x14e4 */
    SynthStream streams[16]; /* 0x14e8 */
} SynthSong;

extern SynthSong* gSynthQueuedVoices;
extern SynthSong* gSynthFreeVoices;
extern SynthSong* gSynthCurrentVoice;
extern u32 gSynthCurrentVoiceSlotIndex;
extern u8 lbl_803DE224;
extern u32 gSynthAllocatedVoices;
extern u32 gSynthNextHandle;
extern u32* gSynthFreeCallbacks;
extern u8 synthIsFadeOutActive(u8 idx);
extern u32 fn_8026E9D0(u32 ch, u32 dt);
extern int synthUpdateCallbacks(void);
extern u32 sndFXCheck(void);
extern void synthFreeCallback(void* cb);
extern void synthRecycleVoiceCallbacks(void* song);
extern f32 lbl_803E7780;
extern f32 lbl_803E7784;
extern f32 lbl_803E7788;

#define fabs __fabs
void synthSetStudioChannelScale(int value, u8 bank, u32 key);

/*
 * fn_8026EC44 - per-song pitch/mod LFO + event update pass.
 * EN v1.0 Address: 0x8026EC44, size 1736b
 */
#pragma fp_contract off
void fn_8026EC44(u32 dt)
{
    extern float floorf(float x); /* #57 */
    SynthSong* song;
    SynthSong* next;
    SynthSong* cs;
    SynthStream* st;
    u32* evt;
    u32 ret;
    u32 cb;
    int i;
    int hasFree;
    u32 sum;
    int cnt;
    u32 ch;
    f32 c0;
    f64 absRange;
    f32 range;
    f32 c1;
    f32 val;
    f32 freq;
    u8 fade;
    u32* node;
    u32* nnode;

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
                st = &cs->streams[0];
                if (st->base != NULL)
                {
                    while (*(evt = st->evt) != 0xffffffff)
                    {
                        if (*evt > *(u32*)((u8*)st + st->idx * 8 + 0x24))
                        {
                            break;
                        }
                        if ((gSynthCurrentVoice->seqWnd[4] & 0x40000000) != 0)
                        {
                            u32* cv = (u32*)evt[1];
                            st->cur = (u32)cv;
                            synthSetStudioChannelScale((u32)cv >> 10, gSynthCurrentVoiceSlotIndex, 0);
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
                if (!(absRange > fabs(val)))
                {
                    val = val - range * (f32)(s64)(u64)(val / range);
                }
                *(u32*)((u8*)st + st->idx * 8 + 0xc) = val;
                *(int*)((u8*)st + st->idx * 8 + 0x10) = floorf(freq);
                ret = fn_8026E9D0(0, dt);
                cb = synthUpdateCallbacks();
                if (gSynthCurrentVoice->counter == 0)
                {
                    for (node = gSynthCurrentVoice->cbList; node != NULL; node = nnode)
                    {
                        nnode = (u32*)*node;
                        if ((node[2] != 0xffffffff) && (sndFXCheck() == 0xffffffff))
                        {
                            synthFreeCallback(node);
                        }
                    }
                }
                cnt = gSynthCurrentVoice->counter + 1;
                gSynthCurrentVoice->counter = cnt - (cnt / 5) * 5;
                sum = gSynthCurrentVoice->streams[0].o[0].acc + gSynthCurrentVoice->streams[0].d[0].step;
                gSynthCurrentVoice->streams[0].o[0].acc = sum & 0xffff;
                gSynthCurrentVoice->streams[0].o[0].out +=
                    gSynthCurrentVoice->streams[0].d[0].delta + (sum >> 16);
                sum = gSynthCurrentVoice->streams[0].o[1].acc + gSynthCurrentVoice->streams[0].d[1].step;
                gSynthCurrentVoice->streams[0].o[1].acc = sum & 0xffff;
                gSynthCurrentVoice->streams[0].o[1].out +=
                    gSynthCurrentVoice->streams[0].d[1].delta + (sum >> 16);
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
                            if (*evt > *(u32*)((u8*)st + st->idx * 8 + 0x24))
                            {
                                break;
                            }
                            if ((gSynthCurrentVoice->seqWnd[4] & 0x40000000) != 0)
                            {
                                u32* cv = (u32*)evt[1];
                                st->cur = (u32)cv;
                                synthSetStudioChannelScale((u32)cv >> 10,
                                                           gSynthCurrentVoiceSlotIndex, ch & 0xff);
                            }
                            else
                            {
                                synthSetStudioChannelScale(evt[1], gSynthCurrentVoiceSlotIndex,
                                                           ch & 0xff);
                                st->cur = st->evt[1] << 10;
                            }
                            st->evt = st->evt + 2;
                        }
                    }
                    cs = gSynthCurrentVoice;
                    st = &cs->streams[ch];
                    freq = (c0 * ((f32)st->cur * dt)) * (c1 * (f32)(u32)
                    st->vol
                    )
                    ;
                    val = range * freq;
                    if (!(absRange > fabs(val)))
                    {
                        val = val - range * (f32)(s64)(u64)(val / range);
                    }
                    *(u32*)((u8*)st + st->idx * 8 + 0xc) = val;
                    *(int*)((u8*)st + st->idx * 8 + 0x10) = floorf(freq);
                    ret |= fn_8026E9D0(ch & 0xff, dt);
                }
                cb = synthUpdateCallbacks();
                if (gSynthCurrentVoice->counter == 0)
                {
                    for (node = gSynthCurrentVoice->cbList; node != NULL; node = nnode)
                    {
                        nnode = (u32*)*node;
                        if ((node[2] != 0xffffffff) && (sndFXCheck() == 0xffffffff))
                        {
                            synthFreeCallback(node);
                        }
                    }
                }
                cnt = gSynthCurrentVoice->counter + 1;
                gSynthCurrentVoice->counter = cnt - (cnt / 5) * 5;
                for (i = 0; i < 16; i++)
                {
                    sum = gSynthCurrentVoice->streams[i].o[0].acc + gSynthCurrentVoice->streams[i].d[0].step;
                    gSynthCurrentVoice->streams[i].o[0].acc = sum & 0xffff;
                    gSynthCurrentVoice->streams[i].o[0].out +=
                        gSynthCurrentVoice->streams[i].d[0].delta + (sum >> 16);
                    sum = gSynthCurrentVoice->streams[i].o[1].acc + gSynthCurrentVoice->streams[i].d[1].step;
                    gSynthCurrentVoice->streams[i].o[1].acc = sum & 0xffff;
                    gSynthCurrentVoice->streams[i].o[1].out +=
                        gSynthCurrentVoice->streams[i].d[1].delta + (sum >> 16);
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
                song->next = gSynthFreeVoices;
                if (gSynthFreeVoices != NULL)
                {
                    gSynthFreeVoices->prev = song;
                }
                gSynthFreeVoices = song;
            }
        }
    }
}
#pragma fp_contract reset

typedef struct
{
    u8 callbacks[0x1400]; /* 0x0000: 0x100 nodes of 0x14 */
    SynthSong songs[8]; /* 0x1400 */
    u16 lastNotes[8][16]; /* 0xd740 */
} SynthPool;

extern SynthPool lbl_803AF550;

/*
 * fn_8026F30C - synth song/callback pool init.
 * EN v1.0 Address: 0x8026F30C, size 560b
 */
int fn_8026F30C(void)
{
    SynthPool* pool;
    u16* np;
    SynthSong* sp;
    u32 i;
    int j;
    int n;
    u32* prev;
    u32* cb;

    pool = &lbl_803AF550;
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
    pool->songs[i - 1].next = NULL;
    prev = NULL;
    cb = (u32*)pool;
    gSynthFreeCallbacks = cb;
    for (n = 0; n < 0x100; n++)
    {
        cb[1] = (u32)prev;
        if (prev != NULL)
        {
            *prev = (u32)cb;
        }
        prev = cb;
        cb += 5;
    }
    *prev = 0;
    gSynthNextHandle = 0;
    return n;
}

/*
 * Set one studio/channel scale entry.
 */
void synthSetStudioChannelScale(int value, u8 bank, u32 key)
{
    if (bank == 0xff)
    {
        bank = 8;
    }
    *(u32*)(lbl_803BCD90 + bank * 0x40 + (key & 0xff) * 4) =
        (u32)((value << 3) * 0x600) / 0xf0;
}

/*
 * Look up an int from a 2D table indexed by state's ID bytes.
 *
 * EN v1.1 Address: 0x8026F584, size 52b
 */
int synthGetVoiceSlotChannelScale(u8* state)
{
    McmdVoiceState* v = (McmdVoiceState*)state;
    u32 a;
    int b;
    if ((a = v->midiEvent) == 0xff) a = 8;
    b = v->midiLayer;
    return *(int*)(lbl_803BCD90 + a * 64 + b * 4);
}

/*
 * fn_8026F5B8 - flag-check and conditional store (~120 instructions).
 * Stubbed.
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
        if (voice->macroAllocating == 0 && voice->voiceHandle != 0xffffffff &&
            voice->midiSlot == slot && voice->midiEvent == channel)
        {
            if ((*(u64*)&voice->inputFlags & 2) != 0)
            {
                sawHeldVoice = 1;
            }
            if ((*(u64*)&voice->inputFlags & 0x10) != 0 &&
                (*(u64*)&voice->inputFlags & 0x10000000008) != 8 && hwIsActive(i) != 0)
            {
                if (result == 0xffffffff && (*(u64*)&voice->inputFlags & 0x20002) == 0x20002)
                {
                    *outFlags = 1;
                    return -1;
                }

                selectedVoice = voice;
                voice->portamentoCurPitch =
                    ((u32)voice->key << 16) + ((s32)voice->fineTune << 16) / 100;
                voice->registeredKey = voice->key;
                voice->key =
                    key + ((voice->key & 0xff) - voice->keyBase);
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
        inpSetMidiLastNote(selectedVoice->midiSlot, selectedVoice->midiEvent,
                           selectedVoice->key & 0xff);
        *outFlags = 0;
    }
    else
    {
        *outFlags = sawHeldVoice;
    }
    return result;
}

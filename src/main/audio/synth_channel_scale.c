#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/hw_init.h"
#include "main/audio/snd_synth_legacy.h"
#include "main/audio/voice_id.h"
#include "main/audio/voice_manage.h"
#include "main/audio/synth_config.h"
#include "main/audio/synth_job_queue.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"

#pragma exceptions on

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
extern u8 lbl_803AF550[];

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
    x = x - y * (f32)n;
    return x;
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

static inline void synthSetTickDelta(SynthStream* section, u32 deltaTime, f32 c0, f32 c1, f32 range, f64 absRange)
{
    f32 tickDelta = c0 * ((f32)section->cur * deltaTime);
    tickDelta = tickDelta * (c1 * (f32)(u32)section->vol);

    section->d[section->idx].step = sal_fmod(range * tickDelta, range, absRange);
    *(int*)&section->d[section->idx].delta = floorf(tickDelta);
}

static inline void synthHandleMasterTrack(u8 secIndex)
{
    SynthStream* section;
    u32* evt;

    section = &gSynthCurrentVoice->streams[secIndex];
    if (section->base != NULL)
    {
        while (*(evt = section->evt) != 0xffffffff)
        {
            if (*evt > section->o[section->idx].out)
            {
                break;
            }
            if ((gSynthCurrentVoice->seqWnd[4] & 0x40000000) != 0)
            {
                synthSetStudioChannelScale((section->cur = evt[1]) >> 10, gSynthCurrentVoiceSlotIndex, secIndex);
            }
            else
            {
                synthSetStudioChannelScale(evt[1], gSynthCurrentVoiceSlotIndex, secIndex);
                section->cur = section->evt[1] << 10;
            }
            section->evt = section->evt + 2;
        }
    }
}

void fn_8026EC44(u32 dt)
{
    u32 sum;
    u32 i;
    u32 j;
    u32 ret;
    u32 cb;
    SynthSong* song;
    SynthSong* next;
    SynthSong* cs;
    u8 fade;
    f32 c0;
    f64 absRange;
    f32 range;
    f32 c1;

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
                synthHandleMasterTrack(0);
                synthSetTickDelta(gSynthCurrentVoice->streams, dt, c0, c1, range, absRange);
                ret = fn_8026E9D0(0, dt);
                cb = synthUpdateCallbacks();
                synthHandleKeyOffCallbacks();
                for (i = 0; i < 2; ++i)
                {
                    sum = gSynthCurrentVoice->streams[0].o[i].acc + gSynthCurrentVoice->streams[0].d[i].step;
                    gSynthCurrentVoice->streams[0].o[i].acc = sum & 0xffff;
                    sum = sum >> 16;
                    gSynthCurrentVoice->streams[0].o[i].out += sum + gSynthCurrentVoice->streams[0].d[i].delta;
                }
            }
            else
            {
                ret = 0;
                for (i = 0; i < 0x10; i++)
                {
                    synthHandleMasterTrack(i);
                    synthSetTickDelta(&gSynthCurrentVoice->streams[i], dt, c0, c1, range, absRange);
                    ret |= fn_8026E9D0(i, dt);
                }
                cb = synthUpdateCallbacks();
                synthHandleKeyOffCallbacks();
                for (i = 0; i < 16; i++)
                {
                    for (j = 0; j < 2; ++j)
                    {
                        sum = gSynthCurrentVoice->streams[i].o[j].acc + gSynthCurrentVoice->streams[i].d[j].step;
                        gSynthCurrentVoice->streams[i].o[j].acc = sum & 0xffff;
                        sum = sum >> 16;
                        gSynthCurrentVoice->streams[i].o[j].out += sum + gSynthCurrentVoice->streams[i].d[j].delta;
                    }
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
    SynthPool* pool = (SynthPool*)lbl_803AF550;
    u32 i;
    int j;
    u32 prev[1];

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

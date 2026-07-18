#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/hw_init.h"
#include "main/audio/snd_synth_api.h"
#include "main/audio/voice_id.h"
#include "main/audio/voice_manage.h"
#include "main/audio/synth_config.h"
#include "main/audio/synth_job_queue.h"
#include "main/audio/synth_channel_scale.h"
#include "main/audio/synth_seq_dispatch.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/floorf.h"
#include "main/audio/synth_volume.h"


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
    u8* trackSectionTab;     /* 0x14e4 */
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

extern int synthUpdateCallbacks(void);
extern void synthFreeCallback(void* cb);
extern void synthRecycleVoiceCallbacks(void* song);

/*
 * fn_8026EC44 - per-sequence tick and event update pass.
 */
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

void fn_8026EC44(u32 deltaTime)
{
    u32 tickSum;
    u32 sectionIndex;
    u32 timeIndex;
    u32 eventsActive;
    u32 callbacksActive;
    SynthSong* song;
    SynthSong* nextSong;
    f32 tickRateScale;
    f64 absoluteTickRange;
    f32 tickRange;
    f32 speedScale;

    if (deltaTime != 0)
    {
        tickRange = lbl_803E7788;
        song = gSynthQueuedVoices;
        absoluteTickRange = fabs(tickRange);
        tickRateScale = lbl_803E7780;
        speedScale = lbl_803E7784;
        for (; song != NULL; song = nextSong)
        {
            nextSong = song->next;
            gSynthCurrentVoice = song;
            gSynthCurrentVoiceSlotIndex = song->index;
            lbl_803DE224 = synthIsFadeOutActive(song->fadeIdx);
            if (gSynthCurrentVoice->trackSectionTab == NULL)
            {
                synthHandleMasterTrack(0);
                synthSetTickDelta(gSynthCurrentVoice->streams, deltaTime, tickRateScale, speedScale, tickRange,
                                  absoluteTickRange);
                eventsActive = synthProcessChannelEventQueue(0, deltaTime);
                callbacksActive = synthUpdateCallbacks();
                synthHandleKeyOffCallbacks();
                for (sectionIndex = 0; sectionIndex < 2; ++sectionIndex)
                {
                    tickSum = gSynthCurrentVoice->streams[0].o[sectionIndex].acc +
                              gSynthCurrentVoice->streams[0].d[sectionIndex].step;
                    gSynthCurrentVoice->streams[0].o[sectionIndex].acc = tickSum & 0xffff;
                    tickSum = tickSum >> 16;
                    gSynthCurrentVoice->streams[0].o[sectionIndex].out +=
                        tickSum + gSynthCurrentVoice->streams[0].d[sectionIndex].delta;
                }
            }
            else
            {
                eventsActive = 0;
                for (sectionIndex = 0; sectionIndex < 0x10; sectionIndex++)
                {
                    synthHandleMasterTrack(sectionIndex);
                    synthSetTickDelta(&gSynthCurrentVoice->streams[sectionIndex], deltaTime, tickRateScale,
                                      speedScale, tickRange, absoluteTickRange);
                    eventsActive |= synthProcessChannelEventQueue(sectionIndex, deltaTime);
                }
                callbacksActive = synthUpdateCallbacks();
                synthHandleKeyOffCallbacks();
                for (sectionIndex = 0; sectionIndex < 16; sectionIndex++)
                {
                    for (timeIndex = 0; timeIndex < 2; ++timeIndex)
                    {
                        tickSum = gSynthCurrentVoice->streams[sectionIndex].o[timeIndex].acc +
                                  gSynthCurrentVoice->streams[sectionIndex].d[timeIndex].step;
                        gSynthCurrentVoice->streams[sectionIndex].o[timeIndex].acc = tickSum & 0xffff;
                        tickSum = tickSum >> 16;
                        gSynthCurrentVoice->streams[sectionIndex].o[timeIndex].out +=
                            tickSum + gSynthCurrentVoice->streams[sectionIndex].d[timeIndex].delta;
                    }
                }
            }
            if ((eventsActive == 0) && (callbacksActive == 0))
            {
                if (song->prev != NULL)
                {
                    song->prev->next = nextSong;
                }
                else
                {
                    gSynthQueuedVoices = nextSong;
                }
                if (nextSong != NULL)
                {
                    nextSong->prev = song->prev;
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

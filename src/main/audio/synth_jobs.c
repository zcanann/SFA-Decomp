#include "main/audio/data_ref.h"
#include "main/audio/synth_job.h"
#include "main/audio/sal_dsp.h"
#include "main/audio/voice_manage.h"
#include "dolphin/os/OSCache.h"
extern u8 lbl_803BD150[];
extern u8 dataSmpSDirTable[];
extern SynthJob synthJobTable[];
extern u32 synthFlags;
extern u16 dataKeymapNum;
extern f32 lbl_803E77D8;

typedef u32 (*SynthStreamUpdateFn)(u8* buffer, u32 length, u8* buffer2, u32 length2, u32 user);

typedef struct SynthSampleInfo
{
    u32 info;
    void* addr;
    void* extraData;
    u32 offset;
    u32 length;
    u32 loop;
    u32 loopLength;
    u8 compType;
} SynthSampleInfo;

extern u8 synthJobTableCountdown;
extern u8 synthJobTablePeriod;
extern u8* synthVoice;
extern void* hwFlushStream(u8 handle); /* gets the stream play buffer */
extern int hwChangeStudio(int slot); /* gets the stream playback position */
extern void hwGetPos(u8* buffer, u32 offset, u32 length, u8 handle, u32 callback, u32 user); /* flushes stream data */
extern void hwInitSamplePlayback(u32 voice, u32 keyInfo, SynthSampleInfo* sample, u32 a, s32 b, u32 voiceId, u32 c,
                                 u32 d);
extern void hwSetPitch(u32 voice, s32 pitch);
extern void hwStart(u32 voice, u8 studio);
extern void hwSetStreamLoopPS(u32 voice, u32 ps);
extern f32 lbl_803E77E8;

void synthUpdateJobTable(void)
{
    u32 cpos;
    u32 len;
    u32 off;
    SynthSampleInfo newsmp;
    u32 i;
    SynthJob* si;
    f32 volScale;
    f32 freqScale;

    if (synthJobTableCountdown != 0)
    {
        --synthJobTableCountdown;
        return;
    }
    synthJobTableCountdown = synthJobTablePeriod;
    volScale = lbl_803E77D8;
    freqScale = lbl_803E77E8;
    si = synthJobTable;
    for (i = 0; i < lbl_803BD150[0x210]; ++i, ++si)
    {
        switch (si->state)
        {
        case SYNTH_JOB_STATE_PENDING:
            newsmp.info = si->frq | 0x40000000;
            newsmp.addr = hwFlushStream(si->streamHandle);
            newsmp.offset = 0;
            newsmp.length = si->size;
            newsmp.loop = 0;
            newsmp.loopLength = si->size;
            si->adpcm.loopPS = si->adpcm.initialPS = *si->buffer;
            DCInvalidateRange(si->buffer, 1);
            switch (si->format)
            {
            case SYNTH_JOB_FORMAT_PCM:
                newsmp.compType = 2;
                break;
            case SYNTH_JOB_FORMAT_ADPCM:
                newsmp.extraData = &si->adpcm;
                newsmp.compType = 4;
                break;
            }
            hwInitSamplePlayback(si->voice, 0xFFFF, &newsmp, 1, -1,
                                 *(u32*)(synthVoice + si->voice * SYNTH_VOICE_STRIDE + 0xF4), 1, 1);
            hwSetPitch(si->voice, freqScale * ((f32)si->frq / (f32) * (u32*)lbl_803BD150));
            hwSetVolume(si->voice, 0, volScale * si->volume, volScale * si->leftVolume,
                        volScale * si->rightVolume, si->pan << 16, si->surroundPan << 16);
            hwStart(si->voice, si->studio);
            si->state = SYNTH_JOB_STATE_PLAYING;
            if (!(si->flags & 0x20000))
            {
                hwGetPos(si->buffer, 0, si->bytes, si->streamHandle, 0, 0);
            }
            break;
        case SYNTH_JOB_STATE_PLAYING:
            cpos = hwChangeStudio(si->voice);

            if (si->format == 1)
            {
                cpos = (cpos / 14) * 14;
            }

            if (si->last != cpos)
            {
                if (si->last < cpos)
                {
                    switch (si->format)
                    {
                    case 0:
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + si->last * 2,
                                                                       cpos - si->last, 0, 0,
                                                                       si->callbackUser)) != 0 &&
                            si->state == SYNTH_JOB_STATE_PLAYING)
                        {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000))
                            {
                                if (cpos != 0)
                                {
                                    hwGetPos(si->buffer, si->last * 2, (cpos - si->last) * 2,
                                             si->streamHandle, 0, 0);
                                }
                                else
                                {
                                    hwGetPos(si->buffer, si->last * 2, (si->size - si->last) * 2,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    case 1:
                        off = (si->last / 14) * 8;
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + off, cpos - si->last,
                                                                       0, 0, si->callbackUser)) != 0 &&
                            si->state == SYNTH_JOB_STATE_PLAYING)
                        {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000))
                            {
                                if (cpos != 0)
                                {
                                    hwGetPos(si->buffer, off, ((cpos + 13) / 14) * 8 - off,
                                             si->streamHandle, 0, 0);
                                }
                                else
                                {
                                    hwGetPos(si->buffer, off, si->bytes - off, si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    }
                }
                else if (cpos == 0)
                {
                    switch (si->format)
                    {
                    case 0:
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + si->last * 2,
                                                                       si->size - si->last, 0, 0,
                                                                       si->callbackUser)) != 0 &&
                            si->state == SYNTH_JOB_STATE_PLAYING)
                        {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000))
                            {
                                if (cpos == 0)
                                {
                                    hwGetPos(si->buffer, si->last * 2, si->bytes - si->last * 2,
                                             si->streamHandle, 0, 0);
                                }
                                else
                                {
                                    hwGetPos(si->buffer, si->last * 2, (cpos - si->last) * 2,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    case 1:
                        off = (si->last / 14) * 8;
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + off,
                                                                       si->size - si->last, 0, 0,
                                                                       si->callbackUser)) != 0 &&
                            si->state == SYNTH_JOB_STATE_PLAYING)
                        {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000))
                            {
                                if (cpos == 0)
                                {
                                    hwGetPos(si->buffer, off, si->bytes - off, si->streamHandle, 0, 0);
                                }
                                else
                                {
                                    hwGetPos(si->buffer, off, ((cpos + 13) / 14) * 8 - off,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    }
                }
                else
                {
                    switch (si->format)
                    {
                    case 0:
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + si->last * 2,
                                                                       si->size - si->last, si->buffer,
                                                                       cpos, si->callbackUser)) != 0 &&
                            si->state == SYNTH_JOB_STATE_PLAYING)
                        {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000))
                            {
                                if (len > si->size - si->last)
                                {
                                    hwGetPos(si->buffer, si->last * 2, si->bytes - si->last * 2,
                                             si->streamHandle, 0, 0);
                                    hwGetPos(si->buffer, 0, cpos * 2, si->streamHandle, 0, 0);
                                }
                                else if (cpos == 0)
                                {
                                    hwGetPos(si->buffer, si->last * 2, si->bytes - si->last * 2,
                                             si->streamHandle, 0, 0);
                                }
                                else
                                {
                                    hwGetPos(si->buffer, si->last * 2, (cpos - si->last) * 2,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    case 1:
                        off = (si->last / 14) * 8;
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + off,
                                                                       si->size - si->last, si->buffer,
                                                                       cpos, si->callbackUser)) != 0 &&
                            si->state == SYNTH_JOB_STATE_PLAYING)
                        {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000))
                            {
                                if (len > si->size - si->last)
                                {
                                    hwGetPos(si->buffer, off, si->bytes - off, si->streamHandle, 0, 0);
                                    hwGetPos(si->buffer, 0, (cpos / 14) * 8, si->streamHandle, 0, 0);
                                }
                                else if (cpos == 0)
                                {
                                    hwGetPos(si->buffer, off, si->bytes - off, si->streamHandle, 0, 0);
                                }
                                else
                                {
                                    hwGetPos(si->buffer, off, ((cpos + 13) / 14) * 8 - off,
                                             si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    }
                }

                if (si->state == SYNTH_JOB_STATE_PLAYING && !(si->flags & 0x20000) && si->format == SYNTH_JOB_FORMAT_ADPCM)
                {
                    hwSetStreamLoopPS(si->voice, *(u32*)((u32)si->buffer + 0x40000000) >> 24);
                }
            }
            break;
        }
    }
}

void doNothing_802737E8(void)
{
}

void synthCancelJob(int voice)
{
    SynthJob* job;
    int state;

    job = synthJobTable + voice;
    state = job->state;
    if (state < SYNTH_JOB_STATE_DONE)
    {
        if (state >= SYNTH_JOB_STATE_PENDING)
        {
            goto cancel;
        }
    }
    return;
cancel:
    if ((u32)state == SYNTH_JOB_STATE_PLAYING)
    {
        voiceBreakAndFree(job->voice);
    }
    job->state = SYNTH_JOB_STATE_DONE;
    job->callback(0, 0, 0, 0, job->callbackUser);
}

void synthRefreshJobVolumes(void)
{
    u32 i;
    f32 volumeScale;

    sndBegin();
    volumeScale = lbl_803E77D8;
    for (i = 0; i < lbl_803BD150[0x210]; i++)
    {
        if (synthJobTable[i].state != SYNTH_JOB_STATE_FREE)
        {
            synthJobTable[i].pan = synthJobTable[i].savedPan;
            synthJobTable[i].surroundPan = synthJobTable[i].savedSurroundPan;
            if ((synthFlags & 1) != 0)
            {
                synthJobTable[i].pan = 0x40;
                synthJobTable[i].surroundPan = 0;
            }
            else if ((synthFlags & 2) == 0)
            {
                synthJobTable[i].surroundPan = 0;
            }
            if (synthJobTable[i].state != SYNTH_JOB_STATE_DONE)
            {
                hwSetVolume(synthJobTable[i].voice, 0, volumeScale * synthJobTable[i].volume,
                            volumeScale * synthJobTable[i].leftVolume,
                            volumeScale * synthJobTable[i].rightVolume,
                            synthJobTable[i].pan << 0x10, synthJobTable[i].surroundPan << 0x10);
            }
        }
    }
    sndEnd();
}

#define DATA_KEYMAP_TAB ((DataRefEntry *)(base + 0x4600))

int dataInsertKeymap(u16 keymapId, void* keymapData)
{
    u8* base = dataSmpSDirTable;
    long i;
    long j;

    sndBegin();
    for (i = 0; i < dataKeymapNum && DATA_KEYMAP_TAB[i].key < keymapId; ++i);
    if (i < dataKeymapNum)
    {
        if (keymapId != ((DataRefEntry *)(base + i * 8))[0x8C0].key)
        {
            if (dataKeymapNum < 256)
            {
                for (j = dataKeymapNum - 1; j >= i; --j)
                    DATA_KEYMAP_TAB[j + 1] = DATA_KEYMAP_TAB[j];
                ++dataKeymapNum;
            }
            else
            {
                sndEnd();
                return 0;
            }
        }
        else
        {
            ((DataRefEntry *)(base + i * 8))[0x8C0].refCount++;
            sndEnd();
            return 0;
        }
    }
    else if (dataKeymapNum < 256)
    {
        ++dataKeymapNum;
    }
    else
    {
        sndEnd();
        return 0;
    }

    DATA_KEYMAP_TAB[i].key = keymapId;
    DATA_KEYMAP_TAB[i].data = keymapData;
    DATA_KEYMAP_TAB[i].refCount = 1;
    sndEnd();
    return 1;
}

int dataRemoveKeymap(u16 keymapId)
{
    u8* base = dataSmpSDirTable;
    long i;
    long j;
    long n;

    sndBegin();
    n = dataKeymapNum;
    for (i = 0; i < n && keymapId != DATA_KEYMAP_TAB[i].key; ++i);
    if (i != n && --DATA_KEYMAP_TAB[i].refCount == 0)
    {
        for (j = i + 1; j < n; j++)
        {
            DATA_KEYMAP_TAB[j - 1] = DATA_KEYMAP_TAB[j];
        }
        --dataKeymapNum;
        sndEnd();
        return 1;
    }
    sndEnd();
    return 0;
}

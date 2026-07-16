#include "main/audio/data_ref.h"
#include "main/audio/mcmd.h"
#include "main/audio/synth_job.h"
#include "main/audio/synth_config.h"
#include "main/audio/sal_dsp.h"
#include "main/audio/voice_manage.h"
#include "main/audio/hw_voice_start.h"
#include "dolphin/os/OSCache.h"

#pragma exceptions on

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

extern SynthJob streamInfo[];
extern u32 synthFlags;
extern f32 lbl_803E77D8;
extern u8 streamCallCnt;
extern u8 streamCallDelay;
extern void* hwFlushStream(u8 handle); /* gets the stream play buffer */
extern int hwChangeStudio(int slot);   /* gets the stream playback position */
extern void hwGetPos(u8* buffer, u32 offset, u32 length, u8 handle, u32 callback, u32 user); /* flushes stream data */
extern void hwInitSamplePlayback(u32 voice, u32 keyInfo, SynthSampleInfo* sample, u32 a, s32 b, u32 voiceId, u32 c,
                                 u32 d);
extern void hwSetPitch(u32 voice, s32 pitch);
extern void hwSetVolume(u32 voice, u8 table, f32 vol, u32 pan, u32 span, f32 auxa, f32 auxb);
extern void hwSetStreamLoopPS(u32 voice, u32 ps);

void streamHandle(void)
{
    u32 i;
    u32 cpos;
    u32 len;
    SynthSampleInfo newsmp;
    SynthJob* si;
    f32 f;

    if (streamCallCnt != 0)
    {
        --streamCallCnt;
        return;
    }
    streamCallCnt = streamCallDelay;
    si = streamInfo;
    for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; ++i, ++si)
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
                                 synthVoice[si->voice].voiceHandle, 1, 1);
            f = (f32)si->frq / (f32)SYNTH_CONFIGURATION->sampleRate;
            hwSetPitch(si->voice, f * 4096.0f);
            hwSetVolume(si->voice, 0, si->volume * (1 / 127.0f), si->pan << 16, si->surroundPan << 16,
                        si->leftVolume * (1 / 127.0f), si->rightVolume * (1 / 127.0f));
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
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + si->last * 2, cpos - si->last, 0, 0,
                                                                       si->callbackUser)) != 0 &&
                            si->state == SYNTH_JOB_STATE_PLAYING)
                        {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000))
                            {
                                if (cpos != 0)
                                {
                                    hwGetPos(si->buffer, si->last * 2, (cpos - si->last) * 2, si->streamHandle, 0, 0);
                                }
                                else
                                {
                                    hwGetPos(si->buffer, si->last * 2, (si->size - si->last) * 2, si->streamHandle, 0,
                                             0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    case 1:
                    {
                        u32 off = (si->last / 14) * 8;
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + off, cpos - si->last, 0, 0,
                                                                       si->callbackUser)) != 0 &&
                            si->state == SYNTH_JOB_STATE_PLAYING)
                        {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000))
                            {
                                if (cpos != 0)
                                {
                                    hwGetPos(si->buffer, off, ((cpos + 13) / 14) * 8 - off, si->streamHandle, 0, 0);
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
                }
                else if (cpos == 0)
                {
                    switch (si->format)
                    {
                    case 0:
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + si->last * 2, si->size - si->last,
                                                                       0, 0, si->callbackUser)) != 0 &&
                            si->state == SYNTH_JOB_STATE_PLAYING)
                        {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000))
                            {
                                if (cpos == 0)
                                {
                                    hwGetPos(si->buffer, si->last * 2, si->bytes - si->last * 2, si->streamHandle, 0,
                                             0);
                                }
                                else
                                {
                                    hwGetPos(si->buffer, si->last * 2, (cpos - si->last) * 2, si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    case 1:
                    {
                        u32 off = (si->last / 14) * 8;
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + off, si->size - si->last, 0, 0,
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
                                    hwGetPos(si->buffer, off, ((cpos + 13) / 14) * 8 - off, si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    }
                    }
                }
                else
                {
                    switch (si->format)
                    {
                    case 0:
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + si->last * 2, si->size - si->last,
                                                                       si->buffer, cpos, si->callbackUser)) != 0 &&
                            si->state == SYNTH_JOB_STATE_PLAYING)
                        {
                            cpos = (si->last + len) % si->size;
                            if (!(si->flags & 0x20000))
                            {
                                if (len > si->size - si->last)
                                {
                                    hwGetPos(si->buffer, si->last * 2, si->bytes - si->last * 2, si->streamHandle, 0,
                                             0);
                                    hwGetPos(si->buffer, 0, cpos * 2, si->streamHandle, 0, 0);
                                }
                                else if (cpos == 0)
                                {
                                    hwGetPos(si->buffer, si->last * 2, si->bytes - si->last * 2, si->streamHandle, 0,
                                             0);
                                }
                                else
                                {
                                    hwGetPos(si->buffer, si->last * 2, (cpos - si->last) * 2, si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    case 1:
                    {
                        u32 off = (si->last / 14) * 8;
                        if ((len = ((SynthStreamUpdateFn)si->callback)(si->buffer + off, si->size - si->last,
                                                                       si->buffer, cpos, si->callbackUser)) != 0 &&
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
                                    hwGetPos(si->buffer, off, ((cpos + 13) / 14) * 8 - off, si->streamHandle, 0, 0);
                                }
                            }
                            si->last = cpos;
                        }
                        break;
                    }
                    }
                }

                if (si->state == SYNTH_JOB_STATE_PLAYING && !(si->flags & 0x20000) &&
                    si->format == SYNTH_JOB_FORMAT_ADPCM)
                {
                    hwSetStreamLoopPS(si->voice, *(u32*)((u32)si->buffer + 0x40000000) >> 24);
                }
            }
            break;
        }
    }
}

void streamCorrectLoops(void)
{
}

void streamKill(u32 voice)
{
    SynthJob* job;
    int state;

    job = streamInfo + voice;
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

void streamOutputModeChanged(void)
{
    u32 i;
    f32 volumeScale;

    sndBegin();
    volumeScale = lbl_803E77D8;
    for (i = 0; i < SYNTH_CONFIGURATION->voiceCount; i++)
    {
        if (streamInfo[i].state != SYNTH_JOB_STATE_FREE)
        {
            streamInfo[i].pan = streamInfo[i].savedPan;
            streamInfo[i].surroundPan = streamInfo[i].savedSurroundPan;
            if ((synthFlags & 1) != 0)
            {
                streamInfo[i].pan = 0x40;
                streamInfo[i].surroundPan = 0;
            }
            else if ((synthFlags & 2) == 0)
            {
                streamInfo[i].surroundPan = 0;
            }
            if (streamInfo[i].state != SYNTH_JOB_STATE_DONE)
            {
                hwSetVolume(streamInfo[i].voice, 0, volumeScale * streamInfo[i].volume,
                            streamInfo[i].pan << 0x10, streamInfo[i].surroundPan << 0x10,
                            volumeScale * streamInfo[i].leftVolume, volumeScale * streamInfo[i].rightVolume);
            }
        }
    }
    sndEnd();
}

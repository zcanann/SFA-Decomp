#include "main/audio/hw_samplemem.h"
#include "main/audio/dsp_voice_state.h"
#include "main/audio/aram.h"
#include "main/audio/aram_queue.h"


extern u32 dspHRTFOn;

void hwSaveSample(SAMPLE_HEADER** sample, void** ptr)
{
    u32 size;
    s32 type;
    u32 adjusted;
    u32 header;

    header = (*sample)->length;
    type = header >> 24;
    size = header & 0xffffff;
    switch (type)
    {
    case SAMPLE_TYPE_ADPCM:
    case SAMPLE_TYPE_ADPCM_PLUS:
    case SAMPLE_TYPE_STREAM_ADPCM:
    case SAMPLE_TYPE_VIRTUAL_ADPCM:
        adjusted = size + 0xd;
        size = (adjusted / 7 * 4) & ~7;
        break;
    case SAMPLE_TYPE_PCM16:
        size <<= 1;
        break;
    }
    *ptr = (void*)aramStoreData(*ptr, size);
}

void hwRemoveSample(SAMPLE_HEADER* sample, void* ptr)
{
    u32 size;
    s32 type;
    u32 adjusted;
    u32 header;

    header = sample->length;
    type = header >> 24;
    size = header & 0xffffff;
    switch (type)
    {
    case SAMPLE_TYPE_ADPCM:
    case SAMPLE_TYPE_ADPCM_PLUS:
    case SAMPLE_TYPE_STREAM_ADPCM:
    case SAMPLE_TYPE_VIRTUAL_ADPCM:
        adjusted = size + 0xd;
        size = (adjusted / 7 * 4) & ~7;
        break;
    case SAMPLE_TYPE_PCM16:
        size <<= 1;
        break;
    }
    aramRemoveData(ptr, size);
}

void hwSyncSampleMem(void)
{
    aramSyncTransferQueue();
}

void hwFrameDone(void)
{
}

void sndSetHooks(const SalHooks* hooks)
{
    salHooks = *hooks;
}

void hwDisableHRTF(void)
{
    dspHRTFOn = 0;
}

u32 hwGetVirtualSampleID(u32 voice)
{
    DSPvoice* entry;

    entry = &dspVoice[voice];
    if (entry->state == DSP_VOICE_STATE_INACTIVE)
    {
        return -1;
    }
    return entry->virtualSampleID;
}

u32 hwVoiceInStartup(u32 voice)
{
    return dspVoice[voice].state == DSP_VOICE_STATE_STARTUP;
}

#include "main/audio/hw_init.h"
#include "main/audio/hw_dspctrl.h"

#include "main/audio/dsp_voice_state.h"
#include "main/audio/sal_dsp.h"
#include "main/audio/sal_studio.h"
#include "main/audio/synth_jobs.h"
#include "main/audio/synth_voice.h"
#include "main/audio/synth_virtual_sample.h"
#include "main/audio/synth_channel_scale.h"
#include "main/audio/snd_core.h"

extern u8 salTimeOffset;
extern u8 salNumVoices;
extern u8 salAuxFrame;
extern u8 salFrame;
void snd_handle_irq(void)
{
    u32 timeOffset;
    u8 voiceIndex;
    u8 i;

    if (gSynthInitialized == 0)
    {
        return;
    }

    streamCorrectLoops();
    hwIRQEnterCritical();
    salCtrlDsp(salAiGetDest());
    hwIRQLeaveCritical();
    hwIRQEnterCritical();
    salHandleAuxProcessing();
    hwIRQLeaveCritical();
    hwIRQEnterCritical();

    salFrame ^= 1;
    salAuxFrame = (salAuxFrame + 1) % 3;

    for (voiceIndex = 0; voiceIndex < salNumVoices; voiceIndex++)
    {
        for (i = 0; i < 5; i++)
        {
            dspVoice[voiceIndex].changed[i] = 0;
        }
    }

    hwIRQLeaveCritical();

    for (timeOffset = 0; (u8)timeOffset < 5; timeOffset++)
    {
        hwIRQEnterCritical();
        hwSetTimeOffset(timeOffset);
        seqHandle(0x100);
        synthHandle(0x100);
        hwIRQLeaveCritical();
    }

    hwIRQEnterCritical();
    hwSetTimeOffset(0);
    s3dHandle();
    hwIRQLeaveCritical();
    hwIRQEnterCritical();
    streamHandle();
    hwIRQLeaveCritical();
    hwIRQEnterCritical();
    synthUpdateVirtualSamples();
    hwIRQLeaveCritical();
}

int hwInit(u32* sampleRate, u16 numVoices, u16 numStudios, u32 flags)
{
    hwInitIrq();
    salFrame = 0;
    salAuxFrame = 0;
    salMessageCallback = 0;

    if ((u32)salInitAi(snd_handle_irq, flags, sampleRate) != 0 &&
        salInitDspCtrl(numVoices, numStudios, (flags & 1) != 0) != 0 && (u32)salInitDsp(flags) != 0)
    {
        sndEnd();
        salStartAi();
        return 0;
    }

    return -1;
}

void hwExit(void)
{
    sndBegin();
    salStartDsp();
    salExitDspCtrl();
    salExitAi();
    sndEnd();
    hwEnableIrq();
}

void hwSetTimeOffset(int value)
{
    salTimeOffset = value;
}

u8 hwGetTimeOffset(void)
{
    return salTimeOffset;
}

u32 hwIsActive(u32 slot)
{
    u8* entry;
    int active;

    slot *= 0xf4;
    entry = (u8*)dspVoice;
    entry += slot;
    active = entry[0xec];
    return active != 0;
}

void hwSetMesgCallback(SndMessageCallback callback)
{
    salMessageCallback = callback;
}

void hwSetPriority(int slot, u32 value)
{
    u8* entry;

    slot *= 0xf4;
    entry = (u8*)dspVoice;
    entry += slot;
    ((DSPvoice*)entry)->prio = value;
}

void hwInitSamplePlayback(u32 voice, u16 sampleId, SAMPLE_INFO* sampleInfo, u32 resetAdsr, u32 priority,
                          u32 callbackUserValue, u32 resetSrc, u32 itdMode)
{
    u8 i;
    u32 flags;

    flags = 0;
    for (i = 0; i <= salTimeOffset; i++)
    {
        flags |= dspVoice[voice].changed[i] & 0x20;
        dspVoice[voice].changed[i] = 0;
    }

    dspVoice[voice].changed[0] = flags;
    dspVoice[voice].prio = priority;
    dspVoice[voice].mesgCallBackUserValue = callbackUserValue;
    dspVoice[voice].flags = 0;
    dspVoice[voice].smp_id = sampleId;
    dspVoice[voice].smp_info = *sampleInfo;

    if (resetAdsr != 0)
    {
        dspVoice[voice].adsr.mode = 0;
        dspVoice[voice].adsr.aTime = 0;
        dspVoice[voice].adsr.dTime = 0;
        dspVoice[voice].adsr.sLevel = 0x7fff;
        dspVoice[voice].adsr.rTime = 0;
    }

    dspVoice[voice].lastUpdate.pitch = 0xff;
    dspVoice[voice].lastUpdate.vol = 0xff;
    dspVoice[voice].lastUpdate.volA = 0xff;
    dspVoice[voice].lastUpdate.volB = 0xff;

    if (resetSrc != 0)
    {
        hwSetSRCType(voice, 0);
        hwSetPolyPhaseFilter(voice, 1);
    }
    hwSetITDMode(voice, itdMode);
}

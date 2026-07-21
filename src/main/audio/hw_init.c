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
    salAuxFrame = (salAuxFrame + 1) % DSP_STUDIO_AUX_BUFFER_COUNT;

    for (voiceIndex = 0; voiceIndex < salNumVoices; voiceIndex++)
    {
        for (i = 0; i < DSP_VOICE_UPDATE_COUNT; i++)
        {
            dspVoice[voiceIndex].changed[i] = 0;
        }
    }

    hwIRQLeaveCritical();

    for (timeOffset = 0; (u8)timeOffset < DSP_VOICE_UPDATE_COUNT; timeOffset++)
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

u32 hwIsActive(u32 voiceIndex)
{
    return dspVoice[voiceIndex].state != DSP_VOICE_STATE_INACTIVE;
}

void hwSetMesgCallback(SndMessageCallback callback)
{
    salMessageCallback = callback;
}

void hwSetPriority(int voiceIndex, u32 priority)
{
    dspVoice[voiceIndex].prio = priority;
}

void hwInitSamplePlayback(u32 voiceIndex, u16 sampleId, SAMPLE_INFO* sampleInfo, u32 resetAdsr, u32 priority,
                          u32 callbackUserValue, u32 resetSrc, u32 itdMode)
{
    u8 timeOffset;
    u32 breakFlags;

    breakFlags = 0;
    for (timeOffset = 0; timeOffset <= salTimeOffset; timeOffset++)
    {
        breakFlags |= dspVoice[voiceIndex].changed[timeOffset] & DSP_VOICE_CHANGE_BREAK;
        dspVoice[voiceIndex].changed[timeOffset] = 0;
    }

    dspVoice[voiceIndex].changed[0] = breakFlags;
    dspVoice[voiceIndex].prio = priority;
    dspVoice[voiceIndex].mesgCallBackUserValue = callbackUserValue;
    dspVoice[voiceIndex].flags = 0;
    dspVoice[voiceIndex].smp_id = sampleId;
    dspVoice[voiceIndex].smp_info = *sampleInfo;

    if (resetAdsr != 0)
    {
        dspVoice[voiceIndex].adsr.mode = ADSR_MODE_LINEAR;
        dspVoice[voiceIndex].adsr.aTime = 0;
        dspVoice[voiceIndex].adsr.dTime = 0;
        dspVoice[voiceIndex].adsr.sLevel = 0x7fff;
        dspVoice[voiceIndex].adsr.rTime = 0;
    }

    dspVoice[voiceIndex].lastUpdate.pitch = 0xff;
    dspVoice[voiceIndex].lastUpdate.vol = 0xff;
    dspVoice[voiceIndex].lastUpdate.volA = 0xff;
    dspVoice[voiceIndex].lastUpdate.volB = 0xff;

    if (resetSrc != 0)
    {
        hwSetSRCType(voiceIndex, 0);
        hwSetPolyPhaseFilter(voiceIndex, 1);
    }
    hwSetITDMode(voiceIndex, itdMode);
}

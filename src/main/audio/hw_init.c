#include "main/audio/hw_init.h"
#include "main/audio/hw_dspctrl.h"

#pragma exceptions on
#include "main/audio/dsp_voice_state.h"
#include "main/audio/sal_dsp.h"
#include "main/audio/synth_jobs.h"
#include "main/audio/synth_virtual_sample.h"

extern u8 gSynthInitialized;
extern u8 salTimeOffset;
extern u8 salNumVoices;
extern u8 salAuxFrame;
extern u8 salFrame;
extern u32 salMessageCallback;
extern void salExitDspCtrl(void);
extern u32 salInitDspCtrl(u32 valueA, u32 valueB, u32 enabled);
extern void fn_8026EC44(u32 value);
extern void audioFn_80271498(u32 value);

void snd_handle_irq(void)
{
    u32 timeOffset;
    u8 voiceIndex;
    u8 i;

    if (gSynthInitialized == 0)
    {
        return;
    }

    doNothing_802737E8();
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
        fn_8026EC44(0x100);
        audioFn_80271498(0x100);
        hwIRQLeaveCritical();
    }

    hwIRQEnterCritical();
    hwSetTimeOffset(0);
    s3dHandle();
    hwIRQLeaveCritical();
    hwIRQEnterCritical();
    synthUpdateJobTable();
    hwIRQLeaveCritical();
    hwIRQEnterCritical();
    synthUpdateVirtualSamples();
    hwIRQLeaveCritical();
}

int hwInit(u32* sampleRate, u8 valueA, u8 valueB, u32 flags)
{
    hwInitIrq();
    salFrame = 0;
    salAuxFrame = 0;
    salMessageCallback = 0;

    if ((u32)salInitAi(snd_handle_irq, flags, sampleRate) != 0 &&
        salInitDspCtrl(valueA, valueB, (flags & 1) != 0) != 0 && (u32)salInitDsp(flags) != 0)
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

void hwSetMesgCallback(u32 value)
{
    salMessageCallback = value;
}

void hwSetPriority(int slot, u32 value)
{
    u8* entry;

    slot *= 0xf4;
    entry = (u8*)dspVoice;
    entry += slot;
    ((DSPvoice*)entry)->prio = value;
}

void hwInitSamplePlayback(int slot, u16 value70, u32* values, u32 resetAdsr, u32 priority, u32 value18, u32 resetSrc,
                          u32 itdMode)
{
    u8 i;
    u32 flags;

    flags = 0;
    for (i = 0; i <= salTimeOffset; i++)
    {
        flags |= dspVoice[slot].changed[i] & 0x20;
        dspVoice[slot].changed[i] = 0;
    }

    dspVoice[slot].changed[0] = flags;
    dspVoice[slot].prio = priority;
    dspVoice[slot].mesgCallBackUserValue = value18;
    dspVoice[slot].flags = 0;
    dspVoice[slot].smp_id = value70;
    dspVoice[slot].smp_info = *(SAMPLE_INFO*)values;

    if (resetAdsr != 0)
    {
        dspVoice[slot].adsr.mode = 0;
        dspVoice[slot].adsr.aTime = 0;
        dspVoice[slot].adsr.dTime = 0;
        dspVoice[slot].adsr.sLevel = 0x7fff;
        dspVoice[slot].adsr.rTime = 0;
    }

    dspVoice[slot].lastUpdate.pitch = 0xff;
    dspVoice[slot].lastUpdate.vol = 0xff;
    dspVoice[slot].lastUpdate.volA = 0xff;
    dspVoice[slot].lastUpdate.volB = 0xff;

    if (resetSrc != 0)
    {
        hwSetSRCType(slot, 0);
        hwSetPolyPhaseFilter(slot, 1);
    }
    hwSetITDMode(slot, itdMode);
}

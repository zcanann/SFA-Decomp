#include "main/audio/hw_init.h"
#include "main/audio/dsp_voice.h"
#include "main/audio/sal_dsp.h"
#include "main/audio/synth_jobs.h"
#include "main/audio/synth_virtual_sample.h"
#include "main/sfa_extern_decls.h"
extern u8 gSynthInitialized;
extern u8 salTimeOffset;
extern u8 salNumVoices;
extern u8 salAuxFrame;
extern u8 salFrame;
extern u32 salMessageCallback;
extern u8* dspVoice;
extern void salExitDspCtrl(void);
extern u32 salInitDspCtrl(u32 valueA, u32 valueB, u32 enabled);

extern void fn_8026EC44(u32 value);
extern void audioFn_80271498(u32 value);

void snd_handle_irq(void)
{
    u32 offset;
    u32 voiceIndex;
    u32 timeOffset;
    u32 zero0;
    u32 zero1;
    u32 zero2;
    u32 zero3;
    u32 zero4;
    u8* entry;

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

    salAuxFrame = (salAuxFrame + 1) % 3;
    salFrame ^= 1;

    offset = 0;
    zero0 = offset;
    zero1 = offset;
    zero2 = offset;
    zero3 = offset;
    zero4 = offset;
    voiceIndex = 0;
    while ((u8)voiceIndex < salNumVoices)
    {
        entry = dspVoice;
        ((DSPvoice*)(entry + offset))->changed[0] = zero0;
        entry = dspVoice;
        ((DSPvoice*)(entry + offset))->changed[1] = zero1;
        entry = dspVoice;
        ((DSPvoice*)(entry + offset))->changed[2] = zero2;
        entry = dspVoice;
        ((DSPvoice*)(entry + offset))->changed[3] = zero3;
        entry = dspVoice;
        ((DSPvoice*)(entry + offset))->changed[4] = zero4;
        offset += 0xf4;
        voiceIndex++;
    }

    hwIRQLeaveCritical();

    timeOffset = 0;
    while ((u8)timeOffset < 5)
    {
        hwIRQEnterCritical();
        hwSetTimeOffset(timeOffset);
        fn_8026EC44(0x100);
        audioFn_80271498(0x100);
        hwIRQLeaveCritical();
        timeOffset++;
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
        salInitDspCtrl(valueA, valueB, (flags & 1) != 0) != 0 &&
        (u32)salInitDsp(flags) != 0)
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
    entry = dspVoice;
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
    entry = dspVoice;
    entry += slot;
    ((DSPvoice*)entry)->prio = value;
}

void hwInitSamplePlayback(int slot, u16 value70, u32* values, u32 resetAdsr, u32 priority, u32 value18, u32 resetSrc,
                          u32 itdMode)
{
    u32 zero;
    u32 valueB;
    u32 inputOffset;
    u8* entry;
    u32 i;
    u32 flags;
    u32 valueA;
    u32 offset;

    inputOffset = 0;
    zero = inputOffset;
    flags = 0;
    i = 0;
    offset = slot * 0xf4;

    while ((u8)i <= salTimeOffset)
    {
        entry = dspVoice;
        entry += inputOffset;
        entry += 0x24;
        entry += offset;
        flags |= *(u32*)entry & 0x20;
        *(u32*)entry = zero;
        inputOffset += 4;
        i++;
    }

    entry = dspVoice;
    entry += offset;
    ((DSPvoice*)entry)->changed[0] = flags;
    entry = dspVoice;
    entry += offset;
    ((DSPvoice*)entry)->prio = priority;
    entry = dspVoice;
    entry += offset;
    ((DSPvoice*)entry)->mesgCallBackUserValue = value18;
    entry = dspVoice;
    entry += offset;
    ((DSPvoice*)entry)->flags = zero;
    entry = dspVoice;
    entry += offset;
    ((DSPvoice*)entry)->smp_id = value70;

    entry = dspVoice;
    entry += offset;
    valueA = values[0];
    valueB = values[1];
    ((u32*)entry)[0x74 / 4 + 0] = valueA;
    ((u32*)entry)[0x74 / 4 + 1] = valueB;
    valueA = values[2];
    valueB = values[3];
    ((u32*)entry)[0x74 / 4 + 2] = valueA;
    ((u32*)entry)[0x74 / 4 + 3] = valueB;
    valueA = values[4];
    valueB = values[5];
    ((u32*)entry)[0x74 / 4 + 4] = valueA;
    ((u32*)entry)[0x74 / 4 + 5] = valueB;
    valueA = values[6];
    valueB = values[7];
    ((u32*)entry)[0x74 / 4 + 6] = valueA;
    ((u32*)entry)[0x74 / 4 + 7] = valueB;

    if (resetAdsr != 0)
    {
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.mode = zero;
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.aTime = zero;
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.dTime = zero;
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.sLevel = 0x7fff;
        entry = dspVoice;
        entry += offset;
        ((DSPvoice*)entry)->adsr.rTime = zero;
    }

    entry = dspVoice;
    entry += offset;
    ((DSPvoice*)entry)->lastUpdate.pitch = 0xff;
    entry = dspVoice;
    entry += offset;
    ((DSPvoice*)entry)->lastUpdate.vol = 0xff;
    entry = dspVoice;
    entry += offset;
    ((DSPvoice*)entry)->lastUpdate.volA = 0xff;
    entry = dspVoice;
    entry += offset;
    ((DSPvoice*)entry)->lastUpdate.volB = 0xff;

    if (resetSrc != 0)
    {
        hwSetSRCType(slot, 0);
        hwSetPolyPhaseFilter(slot, 1);
    }
    hwSetITDMode(slot, itdMode);
}

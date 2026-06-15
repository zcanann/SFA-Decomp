#include "main/audio/hw_init.h"
#include "main/audio/dsp_voice.h"

extern u8 gSynthInitialized;
extern u8 salTimeOffset;
extern u8 salNumVoices;
extern u8 salAuxFrame;
extern u8 salFrame;
extern u32 salMessageCallback;
extern u8* dspVoice;

extern void salExitDspCtrl(void);
extern int salStartDsp(void);
extern void sndBegin(void);
extern void hwInitIrq(void);
extern u32 salInitDspCtrl(u32 valueA, u32 valueB, u32 enabled);
extern int salInitDsp(u32 flags);
extern void doNothing_802737E8(void);
extern void salCtrlDsp(u32 dest);
extern void salHandleAuxProcessing(void);
extern void fn_8026EC44(u32 value);
extern void audioFn_80271498(u32 value);
extern void synthUpdateJobTable(void);
extern void synthUpdateVirtualSamples(void);

void snd_handle_irq(void)
{
    u32 offset;
    u32 voiceIndex;
    u32 timeOffset;
    u32 clearValue;
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

    clearValue = 0;
    offset = 0;
    voiceIndex = 0;
    while ((u8)voiceIndex < salNumVoices)
    {
        entry = dspVoice;
        ((DSPvoice*)(entry + offset))->changed[0] = clearValue;
        entry = dspVoice;
        ((DSPvoice*)(entry + offset))->changed[1] = clearValue;
        entry = dspVoice;
        ((DSPvoice*)(entry + offset))->changed[2] = clearValue;
        entry = dspVoice;
        ((DSPvoice*)(entry + offset))->changed[3] = clearValue;
        entry = dspVoice;
        ((DSPvoice*)(entry + offset))->changed[4] = clearValue;
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

void hwSetTimeOffset(u8 value)
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
    u8* entry;
    u32 offset;
    u32 inputOffset;
    u32 flags;
    u32 i;
    u32 zero;
    u32 valueA;
    u32 valueB;
    u32* dst;

    zero = 0;
    inputOffset = 0;
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
    dst = (u32*)&((DSPvoice*)entry)->smp_info;
    valueA = values[0];
    valueB = values[1];
    dst[0] = valueA;
    dst[1] = valueB;
    valueA = values[2];
    valueB = values[3];
    dst[2] = valueA;
    dst[3] = valueB;
    valueA = values[4];
    valueB = values[5];
    dst[4] = valueA;
    dst[5] = valueB;
    valueA = values[6];
    valueB = values[7];
    dst[6] = valueA;
    dst[7] = valueB;

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

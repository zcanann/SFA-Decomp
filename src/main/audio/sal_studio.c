#include "main/unknown/autos/musyx_dsp.h"
#include "string.h"
#include "dolphin/os/OSCache.h"
#include "main/audio/sal_dsp.h"
#include "main/audio/aram.h"

/* MusyX runtime DSP control (hw_dspctrl.c, MUSY_VERSION <= 2.0.0 paths),
 * recovered against the public MusyX runtime source. */

extern void* dspCmdBuffer; /* dspHrtfHistoryBuffer */
extern DSPvoice* dspVoice;
extern void* dspITDBuffer;
extern s32* dspSurround;
extern void* dspCmdList;
extern u32 dspARAMZeroBuffer; /* dspARAMZeroBuffer */
u8 lbl_803CC1E0[0x6E0];
extern u8 salMaxStudioNum;
extern u8 salNumVoices;

#define dspStudio ((DSPstudioinfo*)lbl_803CC1E0)

void salInitHRTFBuffer(void); /* salInitHRTFBuffer */
void salActivateStudio(u8 studio, u32 isMaster, u32 type); /* salActivateStudio */

/*
 * salInitDspCtrl
 *
 * EN v1.0 Address: 0x8027BA04, size 932b
 */
u32 salInitDspCtrl(u8 numVoices, u8 numStudios, u32 defaultStudioDPL2)
{
    u32 i;
    u32 j;
    u32 itdPtr;

    salNumVoices = numVoices;
    salMaxStudioNum = numStudios;

    dspARAMZeroBuffer = aramGetBaseAddress();
    if ((dspCmdList = salMalloc(1024 * sizeof(u16))))
    {
        if ((dspSurround = salMalloc(160 * sizeof(s32))))
        {
            memset(dspSurround, 0, 160 * sizeof(s32));
            DCFlushRange(dspSurround, 160 * sizeof(s32));
            if ((dspVoice = salMalloc(salNumVoices * sizeof(DSPvoice))))
            {
                if ((dspITDBuffer = salMalloc(salNumVoices * 64)))
                {
                    DCInvalidateRange(dspITDBuffer, salNumVoices * 64);
                    itdPtr = (u32)dspITDBuffer;
                    for (i = 0; i < salNumVoices; ++i)
                    {
                        dspVoice[i].state = 0;
                        dspVoice[i].postBreak = 0;
                        dspVoice[i].startupBreak = 0;
                        dspVoice[i].lastUpdate.pitch = 0xff;
                        dspVoice[i].lastUpdate.vol = 0xff;
                        dspVoice[i].lastUpdate.volA = 0xff;
                        dspVoice[i].lastUpdate.volB = 0xff;
                        dspVoice[i].pb = salMalloc(sizeof(_PB));
                        memset(dspVoice[i].pb, 0, sizeof(_PB));
                        dspVoice[i].patchData = salMalloc(0x80);
                        dspVoice[i].pb->currHi = ((u32)dspVoice[i].pb >> 16);
                        dspVoice[i].pb->currLo = (u16)(u32)
                        dspVoice[i].pb;
                        dspVoice[i].pb->update.dataHi = ((u32)dspVoice[i].patchData >> 16);
                        dspVoice[i].pb->update.dataLo = (u16)(u32)
                        dspVoice[i].patchData;
                        dspVoice[i].pb->itd.bufferHi = (itdPtr >> 16);
                        dspVoice[i].pb->itd.bufferLo = itdPtr;
                        dspVoice[i].itdBuffer = (void*)itdPtr;
                        itdPtr += 0x40;
                        dspVoice[i].virtualSampleID = 0xFFFFFFFF;
                        DCStoreRangeNoSync(dspVoice[i].pb, sizeof(_PB));
                        for (j = 0; j < 5; ++j)
                        {
                            dspVoice[i].changed[j] = 0;
                        }
                    }

                    for (i = 0; i < salMaxStudioNum; ++i)
                    {
                        dspStudio[i].state = 0;
                        if (!(dspStudio[i].spb = salMalloc(sizeof(_SPB))))
                        {
                            return 0;
                        }
                        if (!(dspStudio[i].main[0] = salMalloc(0x3c00)))
                        {
                            return 0;
                        }
                        memset(dspStudio[i].main[0], 0, 0x3c00);
                        DCFlushRangeNoSync(dspStudio[i].main[0], 0x3c00);
                        dspStudio[i].main[1] = dspStudio[i].main[0] + 0x1e0;
                        dspStudio[i].auxA[0] = dspStudio[i].main[1] + 0x1e0;
                        dspStudio[i].auxA[1] = dspStudio[i].auxA[0] + 0x1e0;
                        dspStudio[i].auxA[2] = dspStudio[i].auxA[1] + 0x1e0;
                        dspStudio[i].auxB[0] = dspStudio[i].auxA[2] + 0x1e0;
                        dspStudio[i].auxB[1] = dspStudio[i].auxB[0] + 0x1e0;
                        dspStudio[i].auxB[2] = dspStudio[i].auxB[1] + 0x1e0;
                        memset(dspStudio[i].spb, 0, sizeof(_SPB));
                        dspStudio[i].hostDPopSum.l = dspStudio[i].hostDPopSum.r =
                            dspStudio[i].hostDPopSum.s = 0;
                        dspStudio[i].hostDPopSum.lA = dspStudio[i].hostDPopSum.rA =
                            dspStudio[i].hostDPopSum.sA = 0;
                        dspStudio[i].hostDPopSum.lB = dspStudio[i].hostDPopSum.rB =
                            dspStudio[i].hostDPopSum.sB = 0;
                        DCFlushRangeNoSync(dspStudio[i].spb, sizeof(_SPB));
                    }

                    salActivateStudio(0, 1, defaultStudioDPL2 != 0 ? 1 : 0);
                    if (!(dspCmdBuffer = salMalloc(0x100)))
                    {
                        return 0;
                    }
                    salInitHRTFBuffer();
                    return 1;
                }
            }
        }
    }

    return 0;
}

/*
 * salInitHRTFBuffer
 *
 * EN v1.0 Address: 0x8027BDA8, size 56b
 */
void salInitHRTFBuffer(void)
{
    memset(dspCmdBuffer, 0, 0x100);
    DCFlushRangeNoSync(dspCmdBuffer, 0x100);
}

/*
 * salExitDspCtrl
 *
 * EN v1.0 Address: 0x8027BDE0, size 220b
 */
int salExitDspCtrl(void)
{
    u8 i;

    salFree(dspCmdBuffer);
    for (i = 0; i < salNumVoices; ++i)
    {
        salFree(dspVoice[i].pb);
        salFree(dspVoice[i].patchData);
    }
    for (i = 0; i < salMaxStudioNum; ++i)
    {
        salFree(dspStudio[i].spb);
        salFree(dspStudio[i].main[0]);
    }
    salFree(dspITDBuffer);
    salFree(dspVoice);
    salFree(dspSurround);
    salFree(dspCmdList);
    return 1;
}

/*
 * salActivateStudio
 *
 * EN v1.0 Address: 0x8027BEBC, size 264b
 */
void salActivateStudio(u8 studio, u32 isMaster, u32 type)
{
    DSPstudioinfo* base = dspStudio;

    memset(base[studio].main[0], 0, 0x3c00);
    DCFlushRangeNoSync(base[studio].main[0], 0x3c00);
    memset(base[studio].spb, 0, sizeof(_SPB));
    base[studio].hostDPopSum.l = base[studio].hostDPopSum.r =
        base[studio].hostDPopSum.s = 0;
    base[studio].hostDPopSum.lA = base[studio].hostDPopSum.rA =
        base[studio].hostDPopSum.sA = 0;
    base[studio].hostDPopSum.lB = base[studio].hostDPopSum.rB =
        base[studio].hostDPopSum.sB = 0;
    DCFlushRangeNoSync(base[studio].spb, sizeof(_SPB));
    memset(base[studio].auxA[0], 0, 0x780);
    DCFlushRangeNoSync(base[studio].auxA[0], 0x780);
    memset(base[studio].auxB[0], 0, 0x780);
    DCFlushRangeNoSync(base[studio].auxB[0], 0x780);
    base[studio].voiceRoot = NULL;
    base[studio].alienVoiceRoot = NULL;
    base[studio].state = 1;
    base[studio].isMaster = isMaster;
    base[studio].numInputs = 0;
    base[studio].type = type;
    base[studio].auxAHandler = base[studio].auxBHandler = NULL;
}

/*
 * salDeactivateStudio
 *
 * EN v1.0 Address: 0x8027BFC4, size 32b
 */
void salDeactivateStudio(u8 studio)
{
    dspStudio[studio].state = 0;
}

/*
 * salCheckVolErrorAndResetDelta
 *
 * EN v1.0 Address: 0x8027BFE4, size 244b
 */
int salCheckVolErrorAndResetDelta(u16* dsp_vol, u16* dsp_delta, u16* last_vol, u16 targetVol, u16* resetFlags,
                                  u16 resetMask)
{
    int delta;
    int step;

    if (targetVol != *last_vol)
    {
        delta = (s16)targetVol - (s16) * last_vol;
        delta = (s16)delta;
        if ((delta >= 0x20) && (delta < 0xa0))
        {
            step = (s16)(delta >> 5);
            if (step < 5)
            {
                resetFlags[step] |= resetMask;
            }
            *dsp_delta = 1;
            *last_vol += step << 5;
            return 1;
        }
        if ((delta <= -0x20) && (delta > -0xa0))
        {
            step = (s16)(-delta >> 5);
            if (step < 5)
            {
                resetFlags[step] |= resetMask;
            }
            *dsp_delta = 0xffff;
            *last_vol -= step << 5;
            return 1;
        }
        if ((targetVol == 0) && (delta > -0x20))
        {
            *last_vol = 0;
            *dsp_vol = 0;
        }
    }
    *dsp_delta = 0;
    return 0;
}

static void AddDpop(s32* sum, s16 delta)
{
    *sum += delta;
    *sum = (*sum > 0x7fffff) ? 0x7fffff : (*sum < -0x7fffff ? -0x7fffff : *sum);
}

/*
 * HandleDepopVoice
 *
 * EN v1.0 Address: 0x8027C0D8, size 696b
 */
void HandleDepopVoice(DSPstudioinfo* stp, DSPvoice* dsp_vptr)
{
    _PB* pb;

    dsp_vptr->postBreak = 0;
    dsp_vptr->pb->state = 0;
    pb = dsp_vptr->pb;

    AddDpop(&stp->hostDPopSum.l, pb->dpop.aL);
    AddDpop(&stp->hostDPopSum.r, pb->dpop.aR);

    if ((pb->mixerCtrl & 0x04) != 0)
    {
        AddDpop(&stp->hostDPopSum.s, pb->dpop.aS);
    }

    if ((pb->mixerCtrl & 0x01) != 0)
    {
        AddDpop(&stp->hostDPopSum.lA, pb->dpop.aAuxAL);
        AddDpop(&stp->hostDPopSum.rA, pb->dpop.aAuxAR);

        if ((pb->mixerCtrl & 0x14) != 0)
        {
            AddDpop(&stp->hostDPopSum.sA, pb->dpop.aAuxAS);
        }
    }

    if ((pb->mixerCtrl & 0x12) != 0)
    {
        AddDpop(&stp->hostDPopSum.lB, pb->dpop.aAuxBL);
        AddDpop(&stp->hostDPopSum.rB, pb->dpop.aAuxBR);

        if ((pb->mixerCtrl & 0x4) != 0)
        {
            AddDpop(&stp->hostDPopSum.sB, pb->dpop.aAuxBS);
        }
    }
}

/*
 * SortVoices
 *
 * EN v1.0 Address: 0x8027C390, size 252b
 */
void SortVoices(DSPvoice** voices, int l, int r)
{
    int i;
    int last;
    DSPvoice* tmp;

    if (l >= r)
    {
        return;
    }

    tmp = voices[l];
    voices[l] = voices[(l + r) / 2];
    voices[(l + r) / 2] = tmp;
    last = l;
    i = l + 1;

    for (; i <= r; ++i)
    {
        if (voices[i]->prio < voices[l]->prio)
        {
            last += 1;
            tmp = voices[last];
            voices[last] = voices[i];
            voices[i] = tmp;
        }
    }

    tmp = voices[l];
    voices[l] = voices[last];
    voices[last] = tmp;
    SortVoices(voices, l, last - 1);
    SortVoices(voices, last + 1, r);
}

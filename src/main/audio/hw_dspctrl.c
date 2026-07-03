#include "main/audio/hw_dspctrl.h"
extern u8 lbl_803CC1E0[];
extern u8 salAuxFrame;
extern u8 salMaxStudioNum;

typedef struct SalVoice
{
    u8 pad0[0xc];
    struct SalVoice* next;
    struct SalVoice* prev;
    u8 pad14[0x10];
    u32 flags;
    u8 pad28[0xc4];
    u8 active;
    u8 pendingDeactivate;
    u8 needsUpdate;
    u8 studioIndex;
} SalVoice;

typedef struct SalStudioInputSource
{
    u8 volume;
    u8 panning;
    u8 surroundPanning;
    u8 auxBus;
} SalStudioInputSource;

typedef struct SalStudioInput
{
    u8 auxBus;
    u8 pad1;
    u16 volume;
    u16 panning;
    u16 surroundPanning;
    SalStudioInputSource* source;
} SalStudioInput;

typedef struct SalStudio
{
    u8 pad0[0x48];
    SalVoice* voiceList;
    SalVoice* deferredVoiceList;
    u8 pad50[2];
    u8 inputCount;
    u8 pad53[5];
    SalStudioInput inputs[7];
    u8 padAC[0x10];
} SalStudio;

/* ================= MusyX hardware DSP control (hw_dspctrl.c) =================
 * salBuildCommandList (was fn_8027C48C) (EN v1.0 0x8027C48C, 10828b).
 * Recovered against the public MusyX runtime source (hw_dspctrl.c,
 * MUSY_VERSION <= 2.0.0 paths), adapted to SFA's symbol set. */

#include "main/unknown/autos/musyx_dsp.h"
#include "dolphin/os/OSCache.h"
#include "string.h"

#define dspStudio ((DSPstudioinfo *)lbl_803CC1E0)
#define dspSortedVoices ((DSPvoice **)(lbl_803CC1E0 + 0x5e0))

extern u16* dspCmdLastLoad; /* dspCmdLastLoad */
extern u16* dspCmdLastBase; /* dspCmdLastBase */
extern u16 dspCmdLastSize; /* dspCmdLastSize */
extern u16* dspCmdCurBase; /* dspCmdCurBase */
extern u16* dspCmdMaxPtr; /* dspCmdMaxPtr */
extern u16* dspCmdPtr; /* dspCmdPtr */
extern u16 dspCmdFirstSize;
extern u16* dspCmdList;
extern u32 dspHRTFOn;
extern u32 dspARAMZeroBuffer; /* dspARAMZeroBuffer */
extern s32* dspSurround;
extern u8 salFrame;
extern u16 dspMixerCycles[]; /* dspMixerCycles[32] */
extern u16 pbOffsets[]; /* pbOffsets[9] */
extern u16 dspSRCCycles[4][3]; /* dspSRCCycles */

#define __OSBusClock (*(u32 *)0x800000F8)

extern int salCheckVolErrorAndResetDelta(u16* dsp_vol, u16* dsp_delta, u16* last_vol, u16 targetVol,
                                         u16* resetFlags, u16 resetMask); /* salCheckVolErrorAndResetDelta */
extern void HandleDepopVoice(DSPstudioinfo * stp, DSPvoice * dsp_vptr); /* HandleDepopVoice */
extern void SortVoices(DSPvoice** voices, int l, int r); /* SortVoices */
extern int adsrSetup(ADSR_VARS * adsr); /* adsrSetup */
extern u32 adsrStartRelease(ADSR_VARS* adsr, u32 rtime); /* adsrStartRelease */
extern int adsrRelease(ADSR_VARS * adsr); /* adsrRelease */
extern u32 adsrHandle(ADSR_VARS * adsr, u16 * adsr_start, u16 * adsr_delta); /* adsrHandle */

int salSynthSendMessage(int synth, int msg);
void salDeactivateVoice(SalVoice* voice);

extern int (*salMessageCallback)(int msg, int arg);
extern void salDeactivateVoice(SalVoice* voice);

static void sal_setup_dspvol(u16* dsp_delta, u16* last_vol, u16 vol)
{
    *dsp_delta = ((s16)vol - (s16) * last_vol) / 160;
    *last_vol += (s16) * dsp_delta * 160;
}

static void sal_update_hostplayinfo(DSPvoice* dsp_vptr)
{
    u32 old_lo;
    u32 pitch;

    if (dsp_vptr->smp_info.loopLength != 0)
    {
        return;
    }
    if (dsp_vptr->pb->srcSelect != 2)
    {
        pitch = dsp_vptr->playInfo.pitch << 5;
    }
    else
    {
        pitch = 0x200000;
    }
    old_lo = dsp_vptr->playInfo.posLo;
    dsp_vptr->playInfo.posLo += pitch * 0x10000;
    if (old_lo > dsp_vptr->playInfo.posLo)
    {
        dsp_vptr->playInfo.posHi += (pitch >> 16) + 1;
    }
    else
    {
        dsp_vptr->playInfo.posHi += (pitch >> 16);
    }
}

static void AddDpop(s32* sum, s16 delta)
{
    *sum += delta;
    *sum = (*sum > 0x7fffff) ? 0x7fffff : (*sum < -0x7fffff ? -0x7fffff : *sum);
}

static void DoDepopFade(s32* dspStart, s16* dspDelta, s32* hostSum)
{
    if (*hostSum <= -160)
    {
        *dspDelta = (*hostSum <= -3200) ? 0x14 : (s16)(-*hostSum / 160);
    }
    else if (*hostSum >= 160)
    {
        *dspDelta = (*hostSum >= 3200) ? -0x14 : (s16)(-*hostSum / 160);
    }
    else
    {
        *dspDelta = 0;
    }
    *dspStart = *hostSum;
    *hostSum += *dspDelta * 160;
}

#define SAL_CHECK_CMD_SPACE(n)                                                          \
    if ((dspCmdPtr + (n)) > (dspCmdMaxPtr - 4)) {                                       \
        u16 size;                                                                       \
        dspCmdPtr[0] = 13;                                                              \
        dspCmdPtr[1] = (u32)dspCmdMaxPtr >> 16;                                         \
        dspCmdPtr[2] = (u32)dspCmdMaxPtr;                                               \
        size = (((u32)(dspCmdPtr + 4) - (u32)dspCmdCurBase) + 3) & 0xFFFC;              \
        if (dspCmdLastLoad) {                                                           \
            dspCmdLastLoad[3] = size;                                                   \
            DCStoreRangeNoSync(dspCmdLastBase, dspCmdLastSize);                         \
        } else {                                                                        \
            dspCmdFirstSize = size;                                                     \
        }                                                                               \
        dspCmdLastLoad = dspCmdPtr;                                                     \
        dspCmdLastSize = size;                                                          \
        dspCmdLastBase = dspCmdCurBase;                                                 \
        dspCmdCurBase = dspCmdPtr = dspCmdMaxPtr;                                       \
        dspCmdMaxPtr = dspCmdPtr + 0xC0;                                                \
    }

void salBuildCommandList(s16* dest, u32 nsDelay)
{
    u8 s;
    u8 mix_start;
    u8 st;
    u8 st1;
    u8 getAuxFrame;
    u16 rampResetOffsetFlags[5];
    DSPvoice* dsp_vptr;
    DSPvoice* next_dsp_vptr;
    u32 tmp_addr;
    u32 addr;
    u32 base;
    u32 in;
    u32 voiceNum;
    u32 cyclesUsed;
    u16* pptr;
    u16* pend;
    u16 adsr_start;
    u16 adsr_delta;
    u16 old_adsr_delta;
    s32 current_delta;
    s32 v;
    _PB* pb;
    _PB* last_pb;
    u32 VoiceDone;
    u32 needsDelta;
    u32 newVoice;
    _SPB* spb;
    DSPstudioinfo* stp;
    DSPstudioinfo* msp;
    u32 procVoiceFlag;
    u32 offset;
    u32 endAddr;
    u32 loopAddr;
    u32 zeroAddr;
    u32 frameCycles;

    msp = &dspStudio[0];
    dspCmdCurBase = dspCmdPtr = dspCmdList;
    dspCmdMaxPtr = dspCmdPtr + 0xC0;
    dspCmdLastLoad = 0;
    if (nsDelay < 200)
    {
        cyclesUsed = 10430;
    }
    else
    {
        cyclesUsed = ((nsDelay - 200) * ((__OSBusClock / 400) / 5000)) + 10430;
    }
    if (dspHRTFOn != 0)
    {
        cyclesUsed += 45000;
    }
    rampResetOffsetFlags[0] = 0;
    frameCycles = __OSBusClock / 400;
    for (st = 0, stp = &dspStudio[0]; st < salMaxStudioNum; st++, stp++)
    {
        if (stp->state == 1)
        {
            for (dsp_vptr = stp->voiceRoot; dsp_vptr; dsp_vptr = next_dsp_vptr)
            {
                next_dsp_vptr = dsp_vptr->next;
                if ((dsp_vptr->postBreak != 0) || ((dsp_vptr->changed[0] & 0x20) != 0))
                {
                    HandleDepopVoice(stp, dsp_vptr);
                    if (dsp_vptr->virtualSampleID != -1)
                    {
                        salSynthSendMessage((int)dsp_vptr, 3);
                    }
                    if ((dsp_vptr->state != 1) || (dsp_vptr->startupBreak != 0))
                    {
                        salDeactivateVoice((SalVoice*)dsp_vptr);
                        dsp_vptr->startupBreak = 0;
                    }
                }
            }
            for (dsp_vptr = stp->alienVoiceRoot; dsp_vptr; dsp_vptr = dsp_vptr->nextAlien)
            {
                HandleDepopVoice(stp, dsp_vptr);
            }
            stp->alienVoiceRoot = 0;
            SAL_CHECK_CMD_SPACE(3);
            dspCmdPtr[0] = 0;
            cyclesUsed += 0x2C62;
            dspCmdPtr[1] = (u32)stp->spb >> 16;
            dspCmdPtr[2] = (u32)stp->spb;
            dspCmdPtr += 3;
            for (in = 0; in < stp->numInputs; in++)
            {
                SAL_CHECK_CMD_SPACE(6);
                dspCmdPtr[0] = 1;
                dspCmdPtr[1] = (u32)msp[stp->in[in].studio].main[salFrame ^ 1] >> 16;
                dspCmdPtr[2] = (u32)msp[stp->in[in].studio].main[salFrame ^ 1];
                dspCmdPtr[3] = stp->in[in].vol;
                dspCmdPtr[4] = stp->in[in].volA;
                dspCmdPtr[5] = stp->in[in].volB;
                dspCmdPtr += 6;
                cyclesUsed += 0x294D;
            }
            last_pb = 0;
            v = 0;
            for (dsp_vptr = stp->voiceRoot; dsp_vptr; dsp_vptr = dsp_vptr->next)
            {
                dspSortedVoices[v] = dsp_vptr;
                v++;
            }
            voiceNum = v;
            SortVoices(dspSortedVoices, 0, voiceNum - 1);
            procVoiceFlag = 0;
            for (v = voiceNum; v > 0; v--)
            {
                dsp_vptr = dspSortedVoices[v - 1];
                if (dsp_vptr->state != 0)
                {
                    u8 i;
                    pb = dsp_vptr->pb;
                    for (s = 1; s < 5; s++)
                    {
                        rampResetOffsetFlags[s] = 0;
                    }
                    if (dsp_vptr->state == 1)
                    {
                        dsp_vptr->virtualSampleID = -1;
                        dsp_vptr->pb->ve.currentDelta = 0x8000;
                        if (adsrSetup(&dsp_vptr->adsr) != 0)
                        {
                            salSynthSendMessage((int)dsp_vptr, 0);
                            salDeactivateVoice((SalVoice*)dsp_vptr);
                            continue;
                        }
                        dsp_vptr->virtualSampleID = -1;
                        switch (dsp_vptr->smp_info.compType)
                        {
                        case 5:
                            dsp_vptr->vSampleInfo.loopBufferLength = 0;
                            dsp_vptr->virtualSampleID = salSynthSendMessage((int)dsp_vptr, 2);
                            if (dsp_vptr->vSampleInfo.loopBufferLength == 0)
                            {
                                salSynthSendMessage((int)dsp_vptr, 1);
                                salDeactivateVoice((SalVoice*)dsp_vptr);
                                continue;
                            }
                            break;
                        }
                        pb->src.currentAddressFrac = 0;
                        pb->src.last_samples[0] = 0;
                        pb->src.last_samples[1] = 0;
                        pb->src.last_samples[2] = 0;
                        pb->src.last_samples[3] = 0;
                        if ((dsp_vptr->flags & 0x80000000) != 0)
                        {
                            memset(dsp_vptr->itdBuffer, 0, 0x40);
                            DCFlushRange(dsp_vptr->itdBuffer, 0x40);
                            pb->itd.targetShiftL = dsp_vptr->itdShiftL;
                            pb->itd.shiftL = dsp_vptr->itdShiftL;
                            pb->itd.targetShiftR = dsp_vptr->itdShiftR;
                            pb->itd.shiftR = dsp_vptr->itdShiftR;
                            pb->itd.flag = 1;
                        }
                        else
                        {
                            pb->itd.flag = 0;
                        }
                        switch (dsp_vptr->smp_info.compType)
                        {
                        case 0:
                        case 4:
                        case 5:
                            {
                                SNDADPCMinfo* adpcmInfo;
                                pb->addr.format = 0;
                                pb->adpcm.gain = 0;
                                adpcmInfo = dsp_vptr->smp_info.extraData;
                                pb->adpcm.yn2 = 0;
                                pb->adpcm.yn1 = 0;
                                pb->adpcm.pred_scale = adpcmInfo->initialPS;
                                for (i = 0; i < 8; i++)
                                {
                                    pb->adpcm.a[i][0] = adpcmInfo->coefTab[i][0];
                                    pb->adpcm.a[i][1] = adpcmInfo->coefTab[i][1];
                                }
                                base = (u32)dsp_vptr->smp_info.addr * 2;
                                addr = base + 2;
                                dsp_vptr->playInfo.posHi = dsp_vptr->playInfo.posLo = 0;
                                if ((dsp_vptr->smp_info.compType == 4) ||
                                    (dsp_vptr->smp_info.compType == 5))
                                {
                                    pb->loopType = 1;
                                }
                                else
                                {
                                    pb->adpcmLoop.loop_yn2 = adpcmInfo->loopY1;
                                    pb->adpcmLoop.loop_yn1 = adpcmInfo->loopY2;
                                    pb->adpcmLoop.loop_pred_scale = adpcmInfo->loopPS;
                                    pb->loopType = 0;
                                }
                            }
                            break;
                        case 1:
                            {
                                DSPADPCMplusInfo* adpcmInfo;
                                pb->addr.format = 0;
                                pb->adpcm.gain = 0;
                                offset = (dsp_vptr->smp_info.offset + 0xD) / 14;
                                adpcmInfo = dsp_vptr->smp_info.extraData;
                                pb->adpcm.yn2 = adpcmInfo->blk[offset].Y0;
                                pb->adpcm.yn1 = adpcmInfo->blk[offset].Y1;
                                pb->adpcm.pred_scale = adpcmInfo->blk[offset].PS;
                                pb->adpcmLoop.loop_yn2 = adpcmInfo->loopY0;
                                pb->adpcmLoop.loop_yn1 = adpcmInfo->loopY1;
                                pb->adpcmLoop.loop_pred_scale = adpcmInfo->loopPS;
                                for (i = 0; i < 8; i++)
                                {
                                    pb->adpcm.a[i][0] = adpcmInfo->coefTab[i][0];
                                    pb->adpcm.a[i][1] = adpcmInfo->coefTab[i][1];
                                }
                                base = (u32)dsp_vptr->smp_info.addr * 2;
                                addr = base + offset * 16 + 2;
                                dsp_vptr->playInfo.posHi = offset * 0xE;
                                dsp_vptr->playInfo.posLo = 0;
                            }
                            break;
                        case 3:
                            {
                                pb->addr.format = 0x19;
                                pb->adpcm.gain = 0x100;
                                for (i = 0; i < 8; i++)
                                {
                                    pb->adpcm.a[i][0] = 0;
                                    pb->adpcm.a[i][1] = 0;
                                }
                                addr = dsp_vptr->smp_info.offset +
                                    (base = (u32)dsp_vptr->smp_info.addr);
                                dsp_vptr->playInfo.posHi = dsp_vptr->smp_info.offset;
                                dsp_vptr->playInfo.posLo = 0;
                            }
                            break;
                        case 2:
                            {
                                pb->addr.format = 0xA;
                                pb->adpcm.gain = 0x800;
                                for (i = 0; i < 8; i++)
                                {
                                    pb->adpcm.a[i][0] = 0;
                                    pb->adpcm.a[i][1] = 0;
                                }
                                addr = dsp_vptr->smp_info.offset +
                                    (base = (u32)dsp_vptr->smp_info.addr >> 1);
                                dsp_vptr->playInfo.posHi = dsp_vptr->smp_info.offset;
                                dsp_vptr->playInfo.posLo = 0;
                            }
                            break;
                        }
                        pb->addr.currentAddressHi = addr >> 0x10;
                        pb->addr.currentAddressLo = addr;
                        dsp_vptr->currentAddr = addr;
                        if (dsp_vptr->smp_info.loopLength != 0)
                        {
                            pb->addr.loopFlag = 1;
                            switch (dsp_vptr->smp_info.compType)
                            {
                            case 0:
                            case 1:
                            case 4:
                                {
                                    u32 bn;
                                    u32 bo;
                                    bn = dsp_vptr->smp_info.loop / 14;
                                    bo = dsp_vptr->smp_info.loop - (bn * 0xE);
                                    loopAddr = base + bn * 16 + 2 + bo;
                                    endAddr = dsp_vptr->smp_info.loop + dsp_vptr->smp_info.loopLength - 1;
                                    bn = endAddr / 14;
                                    bo = endAddr - (bn * 0xE);
                                    endAddr = base + bn * 16 + 2 + bo;
                                }
                                break;
                            case 5:
                                {
                                    u32 bn;
                                    u32 bo;
                                    loopAddr = ((u32)dsp_vptr->vSampleInfo.loopBufferAddr * 2) + 2;
                                    endAddr = dsp_vptr->smp_info.loop + dsp_vptr->smp_info.loopLength - 1;
                                    bn = endAddr / 14;
                                    bo = endAddr - (bn * 0xE);
                                    endAddr = base + bn * 16 + 2 + bo;
                                    dsp_vptr->vSampleInfo.inLoopBuffer = 0;
                                }
                                break;
                            case 2:
                            case 3:
                            default:
                                loopAddr = base + dsp_vptr->smp_info.loop;
                                endAddr = base + dsp_vptr->smp_info.loop +
                                    dsp_vptr->smp_info.loopLength - 1;
                                break;
                            }
                            pb->addr.loopAddressHi = loopAddr >> 16;
                            pb->addr.loopAddressLo = loopAddr;
                            pb->addr.endAddressHi = endAddr >> 16;
                            pb->addr.endAddressLo = endAddr;
                            pb->streamLoopCnt = 0;
                        }
                        else
                        {
                            pb->addr.loopFlag = 0;
                            switch (dsp_vptr->smp_info.compType)
                            {
                            case 0:
                            case 1:
                            case 4:
                            case 5:
                                {
                                    u32 bn;
                                    u32 bo;
                                    bn = dsp_vptr->smp_info.length / 14;
                                    bo = dsp_vptr->smp_info.length - (bn * 0xE);
                                    tmp_addr = base + bn * 16 + 2 + bo;
                                    zeroAddr = (dspARAMZeroBuffer * 2) + 2;
                                }
                                break;
                            case 3:
                                tmp_addr = base + dsp_vptr->smp_info.length;
                                zeroAddr = dspARAMZeroBuffer;
                                break;
                            case 2:
                                tmp_addr = base + dsp_vptr->smp_info.length;
                                zeroAddr = dspARAMZeroBuffer >> 1;
                                break;
                            }
                            pb->addr.loopAddressHi = zeroAddr >> 16;
                            pb->addr.loopAddressLo = zeroAddr;
                            pb->addr.endAddressHi = tmp_addr >> 16;
                            pb->addr.endAddressLo = tmp_addr;
                        }
                        pb->srcSelect = dsp_vptr->srcTypeSelect;
                        pb->coefSelect = dsp_vptr->srcCoefSelect;
                        pb->state = (mix_start = dsp_vptr->singleOffset) ? 0 : 1;
                        pb->mix.vL = dsp_vptr->lastVolL = dsp_vptr->volL;
                        pb->mix.vR = dsp_vptr->lastVolR = dsp_vptr->volR;
                        pb->mix.vS = dsp_vptr->lastVolS = dsp_vptr->volS;
                        pb->mix.vAuxAL = dsp_vptr->lastVolLa = dsp_vptr->volLa;
                        pb->mix.vAuxAR = dsp_vptr->lastVolRa = dsp_vptr->volRa;
                        pb->mix.vAuxAS = dsp_vptr->lastVolSa = dsp_vptr->volSa;
                        pb->mixerCtrl =
                            (pb->mix.vAuxAS | (pb->mix.vAuxAL | pb->mix.vAuxAR)) != 0 ? 1 : 0;
                        pb->mix.vAuxBL = dsp_vptr->lastVolLb = dsp_vptr->volLb;
                        pb->mix.vAuxBR = dsp_vptr->lastVolRb = dsp_vptr->volRb;
                        pb->mix.vAuxBS = dsp_vptr->lastVolSb = dsp_vptr->volSb;
                        pb->mix.vDeltaL = 0;
                        pb->mix.vDeltaR = 0;
                        pb->mix.vDeltaS = 0;
                        pb->mix.vDeltaAuxAL = 0;
                        pb->mix.vDeltaAuxAR = 0;
                        pb->mix.vDeltaAuxAS = 0;
                        pb->mix.vDeltaAuxBL = 0;
                        pb->mix.vDeltaAuxBR = 0;
                        pb->mix.vDeltaAuxBS = 0;
                        if (stp->type == 0)
                        {
                            if ((pb->mix.vAuxBS | (pb->mix.vAuxBL | pb->mix.vAuxBR)) != 0)
                            {
                                pb->mixerCtrl |= 2;
                            }
                            if ((pb->mix.vAuxBS | (pb->mix.vS | pb->mix.vAuxAS)) != 0)
                            {
                                pb->mixerCtrl |= 4;
                            }
                        }
                        else if ((pb->mix.vAuxAS | (pb->mix.vAuxBL | pb->mix.vAuxBR)) != 0)
                        {
                            pb->mixerCtrl |= 0x10;
                        }
                        dsp_vptr->state = 2;
                        newVoice = 1;
                        goto block_186;
                    }
                    if ((dsp_vptr->smp_info.compType == 4) || (dsp_vptr->smp_info.compType == 5))
                    {
                        pb->adpcmLoop.loop_pred_scale = dsp_vptr->streamLoopPS;
                        if ((dsp_vptr->smp_info.compType == 5) &&
                            (dsp_vptr->vSampleInfo.inLoopBuffer == 0) && (pb->streamLoopCnt != 0))
                        {
                            u32 bn;
                            u32 bo;
                            bn = (dsp_vptr->vSampleInfo.loopBufferLength - 1) / 14;
                            bo = (dsp_vptr->vSampleInfo.loopBufferLength - 1) - (bn * 14);
                            tmp_addr = ((u32)dsp_vptr->vSampleInfo.loopBufferAddr * 2) + bn * 16 +
                                2 + bo;
                            dsp_vptr->smp_info.addr = dsp_vptr->vSampleInfo.loopBufferAddr;
                            pb->addr.endAddressHi = tmp_addr >> 0x10;
                            pb->addr.endAddressLo = tmp_addr;
                            dsp_vptr->vSampleInfo.inLoopBuffer = 1;
                        }
                    }
                    if ((dsp_vptr->smp_info.loopLength == 0) &&
                        (dsp_vptr->playInfo.posHi >= dsp_vptr->smp_info.length))
                    {
                        salSynthSendMessage((int)dsp_vptr, 0);
                        salDeactivateVoice((SalVoice*)dsp_vptr);
                        continue;
                    }
                    if (((dsp_vptr->changed[0] & 0x10) != 0) &&
                        (adsrSetup(&dsp_vptr->adsr) != 0))
                    {
                        salSynthSendMessage((int)dsp_vptr, 0);
                        salDeactivateVoice((SalVoice*)dsp_vptr);
                        continue;
                    }
                    if ((dsp_vptr->changed[0] & 1) != 0)
                    {
                        sal_setup_dspvol(&pb->mix.vDeltaL, &dsp_vptr->lastVolL, dsp_vptr->volL);
                        sal_setup_dspvol(&pb->mix.vDeltaR, &dsp_vptr->lastVolR, dsp_vptr->volR);
                        sal_setup_dspvol(&pb->mix.vDeltaS, &dsp_vptr->lastVolS, dsp_vptr->volS);
                        needsDelta = 1;
                    }
                    else
                    {
                        needsDelta = salCheckVolErrorAndResetDelta(&pb->mix.vL, &pb->mix.vDeltaL, &dsp_vptr->lastVolL,
                                                                   dsp_vptr->volL, rampResetOffsetFlags, 1);
                        needsDelta |= salCheckVolErrorAndResetDelta(&pb->mix.vR, &pb->mix.vDeltaR,
                                                                    &dsp_vptr->lastVolR, dsp_vptr->volR,
                                                                    rampResetOffsetFlags, 2);
                        needsDelta |= salCheckVolErrorAndResetDelta(&pb->mix.vS, &pb->mix.vDeltaS,
                                                                    &dsp_vptr->lastVolS, dsp_vptr->volS,
                                                                    rampResetOffsetFlags, 4);
                    }
                    if ((dsp_vptr->changed[0] & 2) != 0)
                    {
                        sal_setup_dspvol(&pb->mix.vDeltaAuxAL, &dsp_vptr->lastVolLa,
                                         dsp_vptr->volLa);
                        sal_setup_dspvol(&pb->mix.vDeltaAuxAR, &dsp_vptr->lastVolRa,
                                         dsp_vptr->volRa);
                        sal_setup_dspvol(&pb->mix.vDeltaAuxAS, &dsp_vptr->lastVolSa,
                                         dsp_vptr->volSa);
                        if ((pb->mix.vDeltaAuxAS | (pb->mix.vDeltaAuxAL | pb->mix.vDeltaAuxAR)) !=
                            0)
                        {
                            pb->mixerCtrl |= 1;
                            needsDelta = 1;
                        }
                        else if ((pb->mix.vAuxAS | (pb->mix.vAuxAL | pb->mix.vAuxAR)) != 0)
                        {
                            pb->mixerCtrl |= 1;
                        }
                        else
                        {
                            pb->mixerCtrl &= ~1;
                        }
                    }
                    else if ((pb->mixerCtrl & 1) != 0)
                    {
                        u32 localNeedsDelta;
                        localNeedsDelta = salCheckVolErrorAndResetDelta(&pb->mix.vAuxAL, &pb->mix.vDeltaAuxAL,
                                                                        &dsp_vptr->lastVolLa, dsp_vptr->volLa,
                                                                        rampResetOffsetFlags, 8);
                        localNeedsDelta |= salCheckVolErrorAndResetDelta(&pb->mix.vAuxAR, &pb->mix.vDeltaAuxAR,
                                                                         &dsp_vptr->lastVolRa, dsp_vptr->volRa,
                                                                         rampResetOffsetFlags, 0x10);
                        localNeedsDelta |= salCheckVolErrorAndResetDelta(&pb->mix.vAuxAS, &pb->mix.vDeltaAuxAS,
                                                                         &dsp_vptr->lastVolSa, dsp_vptr->volSa,
                                                                         rampResetOffsetFlags, 0x20);
                        if ((localNeedsDelta |
                            (pb->mix.vAuxAS | (pb->mix.vAuxAL | pb->mix.vAuxAR))) == 0)
                        {
                            pb->mixerCtrl &= ~1;
                        }
                        else
                        {
                            needsDelta = 1;
                        }
                    }
                    else
                    {
                        pb->mix.vDeltaAuxAL = 0;
                        pb->mix.vDeltaAuxAR = 0;
                        pb->mix.vDeltaAuxAS = 0;
                    }
                    if ((dsp_vptr->changed[0] & 4) != 0)
                    {
                        if (stp->type == 0)
                        {
                            sal_setup_dspvol(&pb->mix.vDeltaAuxBL, &dsp_vptr->lastVolLb,
                                             dsp_vptr->volLb);
                            sal_setup_dspvol(&pb->mix.vDeltaAuxBR, &dsp_vptr->lastVolRb,
                                             dsp_vptr->volRb);
                            sal_setup_dspvol(&pb->mix.vDeltaAuxBS, &dsp_vptr->lastVolSb,
                                             dsp_vptr->volSb);
                            if ((pb->mix.vDeltaAuxBS |
                                (pb->mix.vDeltaAuxBL | pb->mix.vDeltaAuxBR)) != 0)
                            {
                                pb->mixerCtrl |= 2;
                                needsDelta = 1;
                            }
                            else if ((pb->mix.vAuxBS | (pb->mix.vAuxBL | pb->mix.vAuxBR)) != 0)
                            {
                                pb->mixerCtrl |= 2;
                            }
                            else
                            {
                                pb->mixerCtrl &= ~2;
                            }
                        }
                        else
                        {
                            sal_setup_dspvol(&pb->mix.vDeltaAuxBL, &dsp_vptr->lastVolLb,
                                             dsp_vptr->volLb);
                            sal_setup_dspvol(&pb->mix.vDeltaAuxBR, &dsp_vptr->lastVolRb,
                                             dsp_vptr->volRb);
                            if ((pb->mix.vDeltaAuxBL | pb->mix.vDeltaAuxBR) != 0)
                            {
                                pb->mixerCtrl |= 0x10;
                                needsDelta = 1;
                            }
                            else if ((pb->mix.vDeltaAuxAS |
                                    (pb->mix.vAuxAS | (pb->mix.vAuxBL | pb->mix.vAuxBR))) !=
                                0)
                            {
                                pb->mixerCtrl |= 0x10;
                            }
                            else
                            {
                                pb->mixerCtrl &= ~0x10;
                            }
                        }
                    }
                    else if (stp->type == 0)
                    {
                        if ((pb->mixerCtrl & 2) != 0)
                        {
                            u32 localNeedsDelta;
                            localNeedsDelta = salCheckVolErrorAndResetDelta(&pb->mix.vAuxBL, &pb->mix.vDeltaAuxBL,
                                                                            &dsp_vptr->lastVolLb, dsp_vptr->volLb,
                                                                            rampResetOffsetFlags, 0x40);
                            localNeedsDelta |= salCheckVolErrorAndResetDelta(&pb->mix.vAuxBR, &pb->mix.vDeltaAuxBR,
                                                                             &dsp_vptr->lastVolRb, dsp_vptr->volRb,
                                                                             rampResetOffsetFlags, 0x80);
                            localNeedsDelta |= salCheckVolErrorAndResetDelta(&pb->mix.vAuxBS, &pb->mix.vDeltaAuxBS,
                                                                             &dsp_vptr->lastVolSb, dsp_vptr->volSb,
                                                                             rampResetOffsetFlags, 0x100);
                            if ((localNeedsDelta |
                                (pb->mix.vAuxBS | (pb->mix.vAuxBL | pb->mix.vAuxBR))) == 0)
                            {
                                pb->mixerCtrl &= ~2;
                            }
                            else
                            {
                                needsDelta = 1;
                            }
                        }
                        else
                        {
                            pb->mix.vDeltaAuxBL = 0;
                            pb->mix.vDeltaAuxBR = 0;
                            pb->mix.vDeltaAuxBS = 0;
                        }
                    }
                    else if ((pb->mixerCtrl & 0x10) != 0)
                    {
                        u32 localNeedsDelta;
                        localNeedsDelta = salCheckVolErrorAndResetDelta(&pb->mix.vAuxBL, &pb->mix.vDeltaAuxBL,
                                                                        &dsp_vptr->lastVolLb, dsp_vptr->volLb,
                                                                        rampResetOffsetFlags, 0x40);
                        localNeedsDelta |= salCheckVolErrorAndResetDelta(&pb->mix.vAuxBR, &pb->mix.vDeltaAuxBR,
                                                                         &dsp_vptr->lastVolRb, dsp_vptr->volRb,
                                                                         rampResetOffsetFlags, 0x80);
                        if ((localNeedsDelta | (pb->mix.vAuxBL | pb->mix.vAuxBR)) == 0)
                        {
                            if ((pb->mix.vAuxAS | pb->mix.vDeltaAuxAS) == 0)
                            {
                                pb->mixerCtrl &= ~0x10;
                            }
                        }
                        else
                        {
                            needsDelta = 1;
                        }
                    }
                    else
                    {
                        pb->mix.vDeltaAuxBL = 0;
                        pb->mix.vDeltaAuxBR = 0;
                        if ((pb->mix.vAuxAS | pb->mix.vDeltaAuxAS) != 0)
                        {
                            pb->mixerCtrl |= 0x10;
                        }
                    }
                    if (needsDelta != 0)
                    {
                        pb->mixerCtrl |= 8;
                    }
                    else
                    {
                        pb->mixerCtrl &= ~8;
                    }
                    if (stp->type == 0)
                    {
                        if ((pb->mix.vS != 0) || (pb->mix.vDeltaS != 0) || (pb->mix.vAuxAS != 0) ||
                            (pb->mix.vDeltaAuxAS != 0) || (pb->mix.vAuxBS != 0) ||
                            (pb->mix.vDeltaAuxBS != 0))
                        {
                            pb->mixerCtrl |= 4;
                        }
                        else
                        {
                            pb->mixerCtrl &= ~4;
                        }
                    }
                    if ((dsp_vptr->changed[0] & 0x200) != 0)
                    {
                        pb->itd.targetShiftL = dsp_vptr->itdShiftL;
                        pb->itd.targetShiftR = dsp_vptr->itdShiftR;
                    }
                    if ((dsp_vptr->changed[0] & 0x100) != 0)
                    {
                        pb->srcSelect = dsp_vptr->srcTypeSelect;
                    }
                    if ((dsp_vptr->changed[0] & 0x80) != 0)
                    {
                        pb->coefSelect = dsp_vptr->srcCoefSelect;
                    }
                    mix_start = 0;
                    newVoice = 0;
                    dsp_vptr->currentAddr =
                        (pb->addr.currentAddressHi << 0x10) | pb->addr.currentAddressLo;
                block_186:
                    if ((dsp_vptr->changed[mix_start] & 0x40) != 0)
                    {
                        adsrRelease(&dsp_vptr->adsr);
                    }
                    if ((dsp_vptr->changed[mix_start] & 8) != 0)
                    {
                        pb->src.ratioHi = dsp_vptr->pitch[mix_start] >> 0x10;
                        pb->src.ratioLo = dsp_vptr->pitch[mix_start];
                        dsp_vptr->playInfo.pitch = dsp_vptr->pitch[mix_start];
                    }
                    VoiceDone = adsrHandle(&dsp_vptr->adsr, &pb->ve.currentVolume,
                                           &pb->ve.currentDelta);
                    old_adsr_delta = pb->ve.currentDelta;
                    for (s = 0; s < 5; s++)
                    {
                        pb->update.updNum[s] = 0;
                    }
                    pptr = dsp_vptr->patchData;
                    pend = (u16*)((u32)dsp_vptr->patchData + 0x80);
                    if (mix_start != 0)
                    {
                        pptr[0] = 7;
                        pptr[1] = 1;
                        pptr += 2;
                        pb->update.updNum[mix_start]++;
                    }
                    sal_update_hostplayinfo(dsp_vptr);
                    for (s = mix_start + 1; s < 5; s++)
                    {
                        if (VoiceDone != 0)
                        {
                            pptr[0] = 7;
                            pptr[1] = 0;
                            pptr += 2;
                            pb->update.updNum[s]++;
                            salSynthSendMessage((int)dsp_vptr, 0);
                            salDeactivateVoice((SalVoice*)dsp_vptr);
                            break;
                        }
                        else
                        {
                            if (rampResetOffsetFlags[s] != 0)
                            {
                                for (i = 0; i < 9; i++)
                                {
                                    if (((1 << i) & rampResetOffsetFlags[s]) != 0)
                                    {
                                        pptr[0] = pbOffsets[i];
                                        pptr[1] = 0;
                                        pptr += 2;
                                        pb->update.updNum[s]++;
                                    }
                                }
                            }
                            if ((dsp_vptr->changed[s] & 0x20) != 0)
                            {
                                adsrStartRelease(&dsp_vptr->adsr, 10);
                                dsp_vptr->postBreak = 1;
                            }
                            else if (dsp_vptr->postBreak == 0)
                            {
                                if ((dsp_vptr->changed[s] & 0x40) != 0)
                                {
                                    adsrRelease(&dsp_vptr->adsr);
                                }
                                if ((dsp_vptr->changed[s] & 8) != 0)
                                {
                                    pptr[0] = 0x53;
                                    pptr[1] = dsp_vptr->pitch[s] >> 16;
                                    pptr[2] = 0x54;
                                    pptr[3] = dsp_vptr->pitch[s];
                                    pptr += 4;
                                    pb->update.updNum[s] += 2;
                                    dsp_vptr->playInfo.pitch = dsp_vptr->pitch[s];
                                }
                            }
                            current_delta = dsp_vptr->adsr.currentDelta;
                            VoiceDone = adsrHandle(&dsp_vptr->adsr, &adsr_start, &adsr_delta);
                            if (old_adsr_delta == adsr_delta)
                            {
                                if (current_delta != 0)
                                {
                                    pptr[0] = 0x32;
                                    pptr[1] = adsr_start;
                                    pptr += 2;
                                    pb->update.updNum[s]++;
                                }
                            }
                            else
                            {
                                pptr[0] = 0x32;
                                pptr[1] = adsr_start;
                                pptr[2] = 0x33;
                                pptr[3] = adsr_delta;
                                pptr += 4;
                                pb->update.updNum[s] += 2;
                                old_adsr_delta = adsr_delta;
                            }
                            sal_update_hostplayinfo(dsp_vptr);
                        }
                    }
                    if (VoiceDone != 0)
                    {
                        salSynthSendMessage((int)dsp_vptr, 0);
                        salDeactivateVoice((SalVoice*)dsp_vptr);
                    }
                    DCStoreRangeNoSync(dsp_vptr->patchData,
                                       (u32)pptr - (u32)dsp_vptr->patchData);
                    cyclesUsed += dspMixerCycles[pb->mixerCtrl] + 0x4FE;
                    switch (pb->src.ratioHi)
                    {
                    case 0:
                    case 1:
                        cyclesUsed += dspSRCCycles[pb->src.ratioHi][pb->srcSelect];
                        break;
                    default:
                        cyclesUsed += dspSRCCycles[2][pb->srcSelect];
                        break;
                    }
                    for (s = 0; s < 5; s++)
                    {
                        cyclesUsed += pb->update.updNum[s] * 4;
                    }
                    if (cyclesUsed > frameCycles)
                    {
                        if ((newVoice == 0) && (VoiceDone == 0))
                        {
                            HandleDepopVoice(stp, dsp_vptr);
                        }
                        salDeactivateVoice((SalVoice*)dsp_vptr);
                        salSynthSendMessage((int)dsp_vptr, 1);
                        for (v = v - 1; v > 0; v--)
                        {
                            if (dspSortedVoices[v - 1]->state == 2)
                            {
                                HandleDepopVoice(stp, dspSortedVoices[v - 1]);
                            }
                            salDeactivateVoice((SalVoice*)dspSortedVoices[v - 1]);
                            salSynthSendMessage((int)dspSortedVoices[v - 1], 1);
                        }
                        for (st1 = st + 1; st1 < salMaxStudioNum; st1++)
                        {
                            if (dspStudio[st1].state == 1)
                            {
                                for (dsp_vptr = dspStudio[st1].voiceRoot; dsp_vptr;
                                     dsp_vptr = next_dsp_vptr)
                                {
                                    next_dsp_vptr = dsp_vptr->next;
                                    if (dsp_vptr->state == 2)
                                    {
                                        HandleDepopVoice(&dspStudio[st1], dsp_vptr);
                                    }
                                    salDeactivateVoice((SalVoice*)dsp_vptr);
                                    salSynthSendMessage((int)dsp_vptr, 1);
                                }
                            }
                        }
                        break;
                    }
                    else
                    {
                        if (!last_pb)
                        {
                            SAL_CHECK_CMD_SPACE(3);
                            dspCmdPtr[0] = 2;
                            dspCmdPtr[1] = (u32)pb >> 0x10;
                            dspCmdPtr[2] = (u32)pb;
                            dspCmdPtr += 3;
                            procVoiceFlag = 1;
                        }
                        else
                        {
                            last_pb->nextHi = (u32)pb >> 16;
                            last_pb->nextLo = (u32)pb;
                            procVoiceFlag = 1;
                            DCFlushRangeNoSync(last_pb, sizeof(_PB));
                        }
                        last_pb = pb;
                    }
                }
            }
            if (procVoiceFlag != 0)
            {
                SAL_CHECK_CMD_SPACE(1);
                *dspCmdPtr++ = 3;
            }
            if (last_pb)
            {
                last_pb->nextHi = 0;
                last_pb->nextLo = 0;
                DCFlushRangeNoSync(last_pb, sizeof(_PB));
            }
            getAuxFrame = (salAuxFrame + 1) % 3;
            if (stp->auxAHandler)
            {
                SAL_CHECK_CMD_SPACE(5);
                dspCmdPtr[0] = 4;
                dspCmdPtr[1] = (u32)stp->auxA[salAuxFrame] >> 16;
                dspCmdPtr[2] = (u32)stp->auxA[salAuxFrame];
                dspCmdPtr[3] = (u32)stp->auxA[getAuxFrame] >> 16;
                dspCmdPtr[4] = (u32)stp->auxA[getAuxFrame];
                dspCmdPtr += 5;
            }
            if (stp->type == 0)
            {
                if (stp->auxBHandler)
                {
                    SAL_CHECK_CMD_SPACE(5);
                    dspCmdPtr[0] = 5;
                    dspCmdPtr[1] = (u32)stp->auxB[salAuxFrame] >> 16;
                    dspCmdPtr[2] = (u32)stp->auxB[salAuxFrame];
                    dspCmdPtr[3] = (u32)stp->auxB[getAuxFrame] >> 16;
                    dspCmdPtr[4] = (u32)stp->auxB[getAuxFrame];
                    dspCmdPtr += 5;
                }
            }
            else
            {
                SAL_CHECK_CMD_SPACE(5);
                dspCmdPtr[0] = 16;
                dspCmdPtr[1] = (u32)stp->auxB[salFrame] >> 16;
                dspCmdPtr[2] = (u32)stp->auxB[salFrame];
                dspCmdPtr[3] = (u32)stp->auxB[salFrame ^ 1] >> 16;
                dspCmdPtr[4] = (u32)stp->auxB[salFrame ^ 1];
                dspCmdPtr += 5;
            }
            SAL_CHECK_CMD_SPACE(3);
            dspCmdPtr[0] = 6;
            dspCmdPtr[1] = (u32)stp->main[salFrame] >> 16;
            dspCmdPtr[2] = (u32)stp->main[salFrame];
            dspCmdPtr += 3;
            spb = stp->spb;
            DoDepopFade((s32*)&spb->dpopLHi, (s16*)&spb->dpopLDelta, &stp->hostDPopSum.l);
            DoDepopFade((s32*)&spb->dpopRHi, (s16*)&spb->dpopRDelta, &stp->hostDPopSum.r);
            DoDepopFade((s32*)&spb->dpopSHi, (s16*)&spb->dpopSDelta, &stp->hostDPopSum.s);
            DoDepopFade((s32*)&spb->dpopALHi, (s16*)&spb->dpopALDelta, &stp->hostDPopSum.lA);
            DoDepopFade((s32*)&spb->dpopARHi, (s16*)&spb->dpopARDelta, &stp->hostDPopSum.rA);
            DoDepopFade((s32*)&spb->dpopASHi, (s16*)&spb->dpopASDelta, &stp->hostDPopSum.sA);
            DoDepopFade((s32*)&spb->dpopBLHi, (s16*)&spb->dpopBLDelta, &stp->hostDPopSum.lB);
            DoDepopFade((s32*)&spb->dpopBRHi, (s16*)&spb->dpopBRDelta, &stp->hostDPopSum.rB);
            DoDepopFade((s32*)&spb->dpopBSHi, (s16*)&spb->dpopBSDelta, &stp->hostDPopSum.sB);
            DCFlushRangeNoSync(spb, sizeof(_SPB));
        }
    }
    SAL_CHECK_CMD_SPACE(3);
    dspCmdPtr[0] = 17;
    dspCmdPtr[1] = (u32)dspSurround >> 16;
    dspCmdPtr[2] = (u32)dspSurround;
    dspCmdPtr += 3;
    for (st = 0; st < salMaxStudioNum; st++, msp++)
    {
        if ((msp->state == 1) && (msp->isMaster != 0))
        {
            SAL_CHECK_CMD_SPACE(3);
            dspCmdPtr[0] = 9;
            dspCmdPtr[1] = (u32)msp->main[salFrame] >> 16;
            dspCmdPtr[2] = (u32)msp->main[salFrame];
            dspCmdPtr += 3;
        }
    }
    SAL_CHECK_CMD_SPACE(5);
    {
        u16 size;
        dspCmdPtr[0] = 14;
        dspCmdPtr[1] = (u32)dspSurround >> 16;
        dspCmdPtr[2] = (u32)dspSurround;
        dspCmdPtr[3] = (u32)dest >> 16;
        dspCmdPtr[4] = (u32)dest;
        dspCmdPtr += 5;
        *dspCmdPtr++ = 15;
        size = (((u32)dspCmdPtr - (u32)dspCmdCurBase) + 3) & 0xFFFC;
        if (dspCmdLastLoad)
        {
            dspCmdLastLoad[3] = size;
            DCStoreRangeNoSync(dspCmdLastBase, dspCmdLastSize);
        }
        else
        {
            dspCmdFirstSize = size;
        }
    }
    DCStoreRangeNoSync(dspCmdCurBase, (u32)dspCmdPtr - (u32)dspCmdCurBase);
}

int salSynthSendMessage(int synth, int msg)
{
    if (salMessageCallback == NULL)
    {
        return 0;
    }
    return salMessageCallback(msg, ((DSPvoice*)synth)->mesgCallBackUserValue);
}

void salActivateVoice(SalVoice* voice, u8 idx)
{
    u8* st;

    if (voice->active != 0)
    {
        salDeactivateVoice(voice);
        voice->flags |= 0x20;
    }
    st = lbl_803CC1E0 + idx * 0xbc;
    voice->pendingDeactivate = 0;
    if ((voice->next = *(SalVoice**)(st += 0x48)) != NULL)
    {
        voice->next->prev = voice;
    }
    voice->prev = NULL;
    *(SalVoice**)st = voice;
    voice->needsUpdate = 0;
    voice->active = 1;
    voice->studioIndex = idx;
}

void salDeactivateVoice(SalVoice* voice)
{
    SalVoice* prev;
    SalVoice* next;

    if (voice->active == 0)
    {
        return;
    }
    prev = voice->prev;
    if (prev != NULL)
    {
        prev->next = voice->next;
    }
    else
    {
        *(SalVoice**)(lbl_803CC1E0 + voice->studioIndex * 0xbc + 0x48) = voice->next;
    }
    next = voice->next;
    if (next != NULL)
    {
        next->prev = voice->prev;
    }
    voice->active = 0;
}

int salAddStudioInput(SalStudio* studio, SalStudioInputSource* input)
{
    if (studio->inputCount < 7)
    {
        studio->inputs[studio->inputCount].auxBus = input->auxBus;
        studio->inputs[studio->inputCount].volume = (input->volume << 8) | (input->volume << 1);
        studio->inputs[studio->inputCount].panning = (input->panning << 8) | (input->panning << 1);
        studio->inputs[studio->inputCount].surroundPanning =
            (input->surroundPanning << 8) | (input->surroundPanning << 1);
        studio->inputs[studio->inputCount].source = input;
        studio->inputCount++;
        return 1;
    }
    return 0;
}

int salRemoveStudioInput(SalStudio* studio, SalStudioInputSource* input)
{
    int n;
    int idx = 0;
    u8* p = (u8*)studio;

    for (n = studio->inputCount; n > 0; n--)
    {
        if (*(SalStudioInputSource**)(p + 0x60) == input)
        {
            p = (u8*)studio + idx * 0xc;
            for (; idx <= studio->inputCount - 2; idx++)
            {
                *(SalStudioInput*)(p + 0x58) = *(SalStudioInput*)(p + 0x64);
                p += 0xc;
            }
            studio->inputCount--;
            return 1;
        }
        p += 0xc;
        idx++;
    }
    return 0;
}

void salHandleAuxProcessing(void)
{
    int i;
    DSPstudioinfo* studio;
    int buf;
    void* bufs[3];

    studio = (DSPstudioinfo*)lbl_803CC1E0;
    for (i = 0; (u8)i < salMaxStudioNum; i++, studio++)
    {
        if (studio->state == 1)
        {
            if (studio->auxAHandler != NULL)
            {
                buf = (int)studio->auxA[(salAuxFrame + 2) % 3];
                bufs[0] = (void*)buf;
                bufs[1] = (void*)(buf + 0x280);
                bufs[2] = (void*)(buf + 0x500);
                ((void (*)(int, void*, int))studio->auxAHandler)(0, bufs, (int)studio->auxAUser);
                DCFlushRangeNoSync((void*)buf, 0x780);
            }
            if (*(int*)&studio->type == 0 && studio->auxBHandler != NULL)
            {
                buf = (int)studio->auxB[(salAuxFrame + 2) % 3];
                bufs[0] = (void*)buf;
                bufs[1] = (void*)(buf + 0x280);
                bufs[2] = (void*)(buf + 0x500);
                ((void (*)(int, void*, int))studio->auxBHandler)(0, bufs, (int)studio->auxBUser);
                DCFlushRangeNoSync((void*)buf, 0x780);
            }
        }
    }
}

u16 dspSRCCycles[4][3] = {
    {0x0BAE, 0x0BAE, 0x045B},
    {0x0CE4, 0x0CE4, 0x045B},
    {0x0E74, 0x0E74, 0x045B},
    {0x0000, 0x0000, 0x0000},
};

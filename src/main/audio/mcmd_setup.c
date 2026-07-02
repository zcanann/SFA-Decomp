#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/mcmd_exec.h"
#include "main/audio/voice_conv.h"
#include "main/audio/data_tables.h"
extern McmdVoiceState* synthVoice;
extern void synthFXCloneMidiSetup(McmdVoiceState * voice, McmdVoiceState * state);
void DoSetPitch(McmdVoiceState * svoice);
extern void sndConvertMs(u32 * p);
extern void sndConvertTicks(u32 * p, McmdVoiceState * state);
extern void synthQueueVoiceInputUpdate(McmdVoiceState * state);
extern int adsrSetup(McmdEnvelopeState * state);
extern u8 voiceAdsrDecayTable[];
extern f32 voiceAdsrSustainTable[];
extern u8 lbl_8032EDD0[]; /* pitch ratio table (u16[13]) heads the macro data tables */
extern f32 lbl_803E77F0; /* 4096.0f */
extern f32 lbl_803E77F4; /* attack scale epsilon */
extern f32 lbl_803E77F8; /* decay scale epsilon */

typedef struct SampleInfo
{
    u32 info;
    u32 unk04;
    u32 unk08;
    u32 offset;
    u32 length;
    u32 unk14;
    u32 unk18;
    u32 unk1C;
} SampleInfo;

extern SampleInfo dataSampleInfo;
extern int dataGetSample(u16 key, SampleInfo* out);
extern void hwInitSamplePlayback(u32 voice, u16 sampleId, SampleInfo* sampleInfo, u32 noKeySync,
                                 u32 priority, u32 handle, u32 noStartOffset, u8 itdMode);

typedef union McmdAdsrData
{
    struct
    {
        u16 atime;
        u16 dtime;
        u16 slevel;
        u16 rtime;
    } linear;

    struct
    {
        s32 atime;
        s32 dtime;
        u16 slevel;
        u16 rtime;
    } dls;
} McmdAdsrData;

typedef union McmdAdsrCurve
{
    struct
    {
        u16 atime;
        u16 dtime;
        u16 slevel;
        u16 rtime;
    } linear;

    struct
    {
        s32 atime;
        s32 dtime;
        u16 slevel;
        u16 rtime;
        s32 ascale;
        s32 dscale;
    } dls;
} McmdAdsrCurve;

/* 64-bit control-flag word overlaying inputFlags(hi)/outputFlags(lo). */
#define MAC_CFLAGS(sv) (*(u64 *)&(sv)->inputFlags)
#define MAC_FLAG64(hi, lo) (((u64)(hi) << 32) | (u64)(lo))

/*
 * Spawn a child macro voice, key-shifted relative to this voice, and link
 * it into the voice's child chain.
 */
void mcmdPlayMacro(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    s32 key;
    u32 new_child;

    key = svoice->keyBase + (s8)(u8)(cstep->flags >> 8);
    key = (key < 0) ? 0 : key > 0x7f ? 0x7f : key;

    if (svoice->streamKind != 0)
    {
        key |= 0x80;
    }

    svoice->macroAllocating = 1;
    new_child = macStart(cstep->flags >> 0x10, (u8)(cstep->value >> 0x10),
                         (u8)(cstep->value >> 0x18), svoice->baseSample, key,
                         (u8)(svoice->volume >> 0x10), (u8)(svoice->pan >> 0x10),
                         svoice->midiSlot, svoice->midiEvent, svoice->midiLayer,
                         cstep->value, svoice->track, 0, svoice->vGroup, svoice->studio,
                         svoice->itdMode == 0);
    svoice->macroAllocating = 0;
    if (new_child != 0xFFFFFFFF)
    {
        svoice->cloneVidListNode =
            (McmdVidListNode*)synthVoice[(u8)new_child].vidListNode->id;
        synthVoice[(u8)new_child].voicePrevHandle = svoice->voiceHandle;
        if (svoice->voiceNextHandle != -1)
        {
            synthVoice[(u8)new_child].voiceNextHandle = svoice->voiceNextHandle;
            synthVoice[(u8)svoice->voiceNextHandle].voicePrevHandle = new_child;
        }
        svoice->voiceNextHandle = new_child;
        if (svoice->streamKind != 0)
        {
            synthFXCloneMidiSetup(&synthVoice[(u8)new_child], svoice);
        }
    }
    else
    {
        svoice->cloneVidListNode = (McmdVidListNode*)0xFFFFFFFF;
    }
}

/*
 * Resolve a sample descriptor and start hardware playback for a voice.
 */
void mcmdStartSample(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    SampleInfo* newsmp = &dataSampleInfo;
    u16 smp;

    smp = cstep->flags >> 8;

    if (dataGetSample(smp, newsmp) != 0)
    {
        return;
    }
    switch ((u8)(cstep->flags >> 0x18))
    {
    case 0:
        newsmp->offset = cstep->value;
        break;
    case 1:
        newsmp->offset = ((u8)(0x7f - (svoice->volume >> 0x10)) * cstep->value) / 0x7f;
        break;
    case 2:
        newsmp->offset = ((u8)(svoice->volume >> 0x10) * cstep->value) / 0x7f;
        break;
    default:
        newsmp->offset = 0;
        break;
    }

    {
        u32* offset = &newsmp->offset;
        u32 length = newsmp->length;
        if (*offset >= length)
        {
            *offset = length - 1;
        }
    }

    hwInitSamplePlayback(svoice->voiceHandle & 0xFF, smp, newsmp,
                         (MAC_CFLAGS(svoice) & MAC_FLAG64(0, 0x100)) == 0,
                         ((u32)svoice->priorityGroup << 24) | (svoice->priorityValue >> 15),
                         svoice->voiceHandle, (MAC_CFLAGS(svoice) & MAC_FLAG64(0x800, 0)) == 0,
                         svoice->itdMode);

    svoice->prevSampleId = newsmp->info;

    if (svoice->targetPitch != -1)
    {
        DoSetPitch(svoice);
    }
    MAC_CFLAGS(svoice) |= MAC_FLAG64(0, 0x20);
    synthQueueVoiceInputUpdate(svoice);
}

/*
 * Configure the voice vibrato ramp and curve flags.
 */
void mcmdVibrato(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    u32 time;
    s8 kr;
    s8 cr;

    if ((u8)(cstep->flags >> 0x18) & 3)
    {
        MAC_CFLAGS(svoice) |= MAC_FLAG64(0, 0x4000);
    }
    else
    {
        MAC_CFLAGS(svoice) &= ~MAC_FLAG64(0, 0x4000);
    }

    time = (u16)(cstep->value >> 0x10);
    if ((u8)(cstep->value >> 8) & 1)
    {
        sndConvertMs(&time);
    }
    else
    {
        sndConvertTicks(&time, svoice);
    }

    if (time)
    {
        MAC_CFLAGS(svoice) |= MAC_FLAG64(0, 0x2000);
        svoice->vibratoDuration = time;

        kr = (s8)(cstep->flags >> 8);
        cr = (s8)(cstep->flags >> 16);

        if (kr < 0)
        {
            if (cr < 0)
            {
                svoice->vibratoTarget = -cr;
            }
            else
            {
                svoice->vibratoTarget = cr;
            }

            svoice->vibratoStart = -kr;
            svoice->vibratoHalfDuration = svoice->vibratoDuration / 2;
        }
        else
        {
            if (cr < 0)
            {
                if (kr == 0)
                {
                    svoice->vibratoTarget = -cr;
                    svoice->vibratoHalfDuration = svoice->vibratoDuration / 2;
                }
                else
                {
                    --kr;
                    svoice->vibratoTarget = 100 - cr;
                    svoice->vibratoHalfDuration = 0;
                }
            }
            else
            {
                svoice->vibratoTarget = cr;
                svoice->vibratoHalfDuration = 0;
            }
            svoice->vibratoStart = kr;
        }
    }
    else
    {
        MAC_CFLAGS(svoice) &= ~MAC_FLAG64(0, 0x2000);
    }
}

/*
 * Map the previous sample pitch toward the requested pitch, splitting the
 * result into key and fine-tune cents.
 */
void DoSetPitch(McmdVoiceState* svoice)
{
    u32 f;
    u32 of;
    u32 i;
    u32 frq;
    u32 ofrq;
    u32 no;
    s32 key;
    u8 oKey;
    u16* kf = (u16*)lbl_8032EDD0;

    frq = svoice->targetPitch & 0xFFFFFF;
    ofrq = svoice->prevSampleId & 0xFFFFFF;

    if (ofrq == frq)
    {
        svoice->key = (u8)(svoice->prevSampleId >> 24);
        svoice->fineTune = 0;
    }
    else if (ofrq < frq)
    {
        f = (frq << 12) / ofrq;
        of = f >> 12;

        for (no = 0; no < 11; no++)
        {
            if (of < (1 << (no + 1)))
            {
                break;
            }
        }

        f /= (1 << no);

        for (i = 11;; i--)
        {
            if (f > kf[i])
            {
                break;
            }
        }

        svoice->key = (svoice->prevSampleId >> 24) + (no * 12) + i;
        svoice->fineTune = ((f - kf[i]) * 100) / (kf[i + 1] - kf[i]);
    }
    else
    {
        f = (ofrq << 12) / frq;
        of = f >> 12;

        for (no = 0; no < 11; no++)
        {
            if (of < (1 << (no + 1)))
            {
                break;
            }
        }

        f /= (1 << no);

        for (i = 11;; i--)
        {
            if (f > kf[i])
            {
                break;
            }
        }

        key = i + (no * 12);
        oKey = (svoice->prevSampleId >> 24);
        if (key > oKey)
        {
            svoice->key = svoice->fineTune = 0;
        }
        else
        {
            svoice->key = oKey - key;
            svoice->fineTune = ((kf[i] - f) * 100) / (kf[i + 1] - kf[i]);
        }
    }
}

/*
 * Resolve ADSR parameters and send them to the hardware voice.
 */
void mcmdSetADSR(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    McmdAdsrData adsr;
    McmdAdsrCurve* adsr_ptr;
    s32 ascale;
    s32 dscale;

    if ((adsr_ptr = (McmdAdsrCurve*)dataGetCurve(cstep->flags >> 8)) != NULL)
    {
        if (!(u8)(cstep->flags >> 24))
        {
            adsr.linear.atime = adsr_ptr->linear.atime >> 8 | adsr_ptr->linear.atime << 8;
            adsr.linear.dtime = adsr_ptr->linear.dtime >> 8 | adsr_ptr->linear.dtime << 8;
            adsr.linear.slevel = adsr_ptr->linear.slevel >> 8 | adsr_ptr->linear.slevel << 8;
            adsr.linear.rtime = adsr_ptr->linear.rtime >> 8 | adsr_ptr->linear.rtime << 8;
            hwSetADSR(svoice->voiceHandle & 0xFF, &adsr, 0);
        }
        else
        {
            f32 sScale = voiceAdsrSustainTable[(u16)(adsr_ptr->dls.slevel >> 8 |
                adsr_ptr->dls.slevel << 8) >> 5];
            adsr.dls.atime = ((u8*)&adsr_ptr->dls.atime)[0] << 0 |
                ((u8*)&adsr_ptr->dls.atime)[1] << 8 |
                ((u8*)&adsr_ptr->dls.atime)[2] << 16 |
                ((u8*)&adsr_ptr->dls.atime)[3] << 24;
            adsr.dls.dtime = ((u8*)&adsr_ptr->dls.dtime)[0] << 0 |
                ((u8*)&adsr_ptr->dls.dtime)[1] << 8 |
                ((u8*)&adsr_ptr->dls.dtime)[2] << 16 |
                ((u8*)&adsr_ptr->dls.dtime)[3] << 24;
            adsr.dls.slevel = lbl_803E77F0 * sScale;
            adsr.dls.rtime = adsr_ptr->dls.rtime >> 8 | adsr_ptr->dls.rtime << 8;
            ascale = ((u8*)&adsr_ptr->dls.ascale)[0] << 0 |
                ((u8*)&adsr_ptr->dls.ascale)[1] << 8 |
                ((u8*)&adsr_ptr->dls.ascale)[2] << 16 |
                ((u8*)&adsr_ptr->dls.ascale)[3] << 24;
            dscale = ((u8*)&adsr_ptr->dls.dscale)[0] << 0 |
                ((u8*)&adsr_ptr->dls.dscale)[1] << 8 |
                ((u8*)&adsr_ptr->dls.dscale)[2] << 16 |
                ((u8*)&adsr_ptr->dls.dscale)[3] << 24;

            if (ascale != 0x80000000)
            {
                f32 prod = lbl_803E77F4 * svoice->volumeBase;
                adsr.dls.atime += (s32)(prod * ascale);
            }

            if (dscale != 0x80000000)
            {
                f32 prod = lbl_803E77F8 * svoice->keyBase;
                adsr.dls.dtime += (s32)(prod * dscale);
            }

            hwSetADSR(svoice->voiceHandle & 0xFF, &adsr, 1);
        }

        MAC_CFLAGS(svoice) |= MAC_FLAG64(0, 0x100);
    }
}

/*
 * Configure the per-voice pitch envelope state from a DLS ADSR table.
 */
void mcmdSetPitchADSR(McmdVoiceState* svoice, McmdCommandArgs* cstep)
{
    McmdAdsrData adsr;
    McmdAdsrCurve* adsr_ptr;
    u32 sl;
    s32 ascale;
    s32 dscale;

    if ((adsr_ptr = (McmdAdsrCurve*)dataGetCurve(cstep->flags >> 8)) == NULL)
    {
        return;
    }

    svoice->pitchAdsrPan = (s8)cstep->value << 8;

    if (svoice->pitchAdsrPan >= 0)
    {
        svoice->pitchAdsrPan += ((s16)(s8)(cstep->value >> 8) << 8) / 100;
    }
    else
    {
        svoice->pitchAdsrPan -= ((s16)(s8)(cstep->value >> 8) << 8) / 100;
    }

    adsr.dls.atime = ((u8*)&adsr_ptr->dls.atime)[0] << 0 |
        ((u8*)&adsr_ptr->dls.atime)[1] << 8 |
        ((u8*)&adsr_ptr->dls.atime)[2] << 16 |
        ((u8*)&adsr_ptr->dls.atime)[3] << 24;
    adsr.dls.dtime = ((u8*)&adsr_ptr->dls.dtime)[0] << 0 |
        ((u8*)&adsr_ptr->dls.dtime)[1] << 8 |
        ((u8*)&adsr_ptr->dls.dtime)[2] << 16 |
        ((u8*)&adsr_ptr->dls.dtime)[3] << 24;
    adsr.dls.slevel = adsr_ptr->dls.slevel >> 8 | adsr_ptr->dls.slevel << 8;
    adsr.dls.rtime = adsr_ptr->dls.rtime >> 8 | adsr_ptr->dls.rtime << 8;
    ascale = ((u8*)&adsr_ptr->dls.ascale)[0] << 0 | ((u8*)&adsr_ptr->dls.ascale)[1] << 8 |
        ((u8*)&adsr_ptr->dls.ascale)[2] << 16 | ((u8*)&adsr_ptr->dls.ascale)[3] << 24;
    dscale = ((u8*)&adsr_ptr->dls.dscale)[0] << 0 | ((u8*)&adsr_ptr->dls.dscale)[1] << 8 |
        ((u8*)&adsr_ptr->dls.dscale)[2] << 16 | ((u8*)&adsr_ptr->dls.dscale)[3] << 24;

    if (ascale != 0x80000000)
    {
        f32 prod = lbl_803E77F4 * svoice->volumeBase;
        adsr.dls.atime += (s32)(prod * ascale);
    }
    if (dscale != 0x80000000)
    {
        f32 prod = lbl_803E77F8 * svoice->keyBase;
        adsr.dls.dtime += (s32)(prod * dscale);
    }

    svoice->pitchAdsr.mode = 1;
    svoice->pitchAdsr.unk24[2] = 0;
    svoice->pitchAdsr.attack = voiceConvertDbToLinear(adsr.dls.atime);
    svoice->pitchAdsr.decay = voiceConvertDbToLinear(adsr.dls.dtime);
    if ((sl = adsr.dls.slevel >> 2) > 0x3ff)
    {
        sl = 0x3ff;
    }
    svoice->pitchAdsr.sustain = 0xc1 - voiceAdsrDecayTable[sl];
    svoice->pitchAdsr.release = adsr.dls.rtime;
    adsrSetup(&svoice->pitchAdsr);
    MAC_CFLAGS(svoice) |= MAC_FLAG64(0x200, 0);
}

/*
 * Configure a panning/surround-panning parameter ramp for the voice.
 */
void voiceConfigureParamRamp(McmdVoiceState* svoice, McmdCommandArgs* cstep, u8 pi)
{
    s32 mstime;
    s32 width;

    width = cstep->flags >> 16;
    svoice->paramDuration[pi] = width;
    sndConvertMs(&svoice->paramDuration[pi]);
    mstime = (s8)cstep->value;
    svoice->paramCurrent[pi] = ((u8)(cstep->flags >> 8)) << 16;
    svoice->paramTarget[pi] = svoice->paramCurrent[pi] + (mstime << 16);
    if (svoice->paramDuration[pi] != 0)
    {
        svoice->paramStep[pi] = (s32)(mstime << 16) / width;
    }
    else
    {
        svoice->paramStep[pi] = (s32)(mstime << 16);
    }

    MAC_CFLAGS(svoice) |= MAC_FLAG64(0x2000, 0);
}

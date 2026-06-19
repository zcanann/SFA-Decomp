#include "ghidra_import.h"
#include "main/audio/mcmd.h"
#include "main/audio/data_tables.h"


extern void sndConvertMs(u32 * p);
extern void sndConvertTicks(u32 * p, McmdVoiceState * state);
extern s32 sndConvert2Ms(u32 v);

/* 64-bit control-flag word overlaying inputFlags(hi)/outputFlags(lo). */
#define MAC_CFLAGS(sv) (*(u64 *)&(sv)->inputFlags)
#define MAC_FLAG64(hi, lo) (((u64)(hi) << 32) | (u64)(lo))

/*
 * Translate a 16.16 volume through a curve table (MusyX TranslateVolume).
 */
u32 TranslateVolume(u32 volume, u16 curve)
{
    u8* ptr;
    u32 vlow;
    u32 vhigh;
    s32 d;

    if (curve != 0xFFFF)
    {
        if ((ptr = dataGetCurve(curve)))
        {
            vhigh = (volume >> 16) & 0xFFFF;
            vlow = volume & 0xFFFF;

            if (vhigh < 0x7f)
            {
                d = vlow * (ptr[vhigh + 1] - ptr[vhigh]);
                volume = d + ((u16)ptr[vhigh] << 16);
            }
            else
            {
                volume = ptr[vhigh] << 16;
            }
        }
    }

    return volume;
}

/*
 * Compute a volume envelope ramp toward a curve-translated target
 * (MusyX DoEnvelopeCalculation).
 */
void mcmdScaleVolume(McmdVoiceState* svoice, McmdCommandArgs* cstep, s32 start_vol)
{
    u32 tvol;
    u32 time;
    s32 mstime;
    u16 curve;

    time = (u16)(cstep->value >> 16);

    if ((u8)(cstep->value >> 8) & 1)
    {
        sndConvertMs(&time);
    }
    else
    {
        sndConvertTicks(&time, svoice);
    }

    mstime = sndConvert2Ms(time);
    if (mstime == 0)
    {
        mstime = 1;
    }

    tvol = (svoice->volume * (u8)(cstep->flags >> 8) >> 7);
    tvol += (u8)(cstep->flags >> 16) << 16;

    if (tvol > 0x7f0000)
    {
        tvol = 0x7f0000;
    }

    curve = (u16)(u8)(cstep->flags >> 0x18);
    curve |= (((u16)(u8)
    cstep->value
    )
    <<
    8
    )
    ;
    tvol = TranslateVolume(tvol, curve);
    svoice->volumeTarget = tvol;
    svoice->volumeStart = start_vol;
    svoice->volumeStep = (s32)(tvol - start_vol) / mstime;
    svoice->volume = start_vol;
    MAC_CFLAGS(svoice) |= MAC_FLAG64(0, 0x8000);
}

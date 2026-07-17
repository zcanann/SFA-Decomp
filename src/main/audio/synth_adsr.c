#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "main/audio/adsr.h"

extern u8 voiceAdsrDecayTable[];
extern u16 lbl_8032F618[];
extern asm u32 __cvt_fp2unsigned(register f64 d);

u32 voiceConvertDbToLinear(u32 timeCents)
{
    return __cvt_fp2unsigned(1000.0f *
                             powf(2.0f, 1.2715658e-08f * (f32)(s32)timeCents));
}

int fn_8027A660(int state)
{
    ADSR_VARS* adsr = (ADSR_VARS*)state;
    int ret = 0;

    switch (adsr->mode)
    {
    case ADSR_MODE_LINEAR:
        switch (adsr->state)
        {
        case ADSR_STATE_ATTACK:
            if ((adsr->cnt = adsr->aTime) != 0)
            {
                adsr->state = ADSR_STATE_DECAY;
                adsr->currentVolume = 0;
                adsr->currentDelta = 0x7fff0000 / adsr->aTime;
                break;
            }
        case ADSR_STATE_DECAY:
            if ((adsr->cnt = adsr->dTime) != 0)
            {
                adsr->state = ADSR_STATE_SUSTAIN;
                adsr->currentVolume = 0x7fff0000;
                adsr->currentDelta = -((0x7fff0000 - (adsr->sLevel << 16)) / adsr->dTime);
                break;
            }
        case ADSR_STATE_SUSTAIN:
            if (adsr->sLevel != 0)
            {
                adsr->state = ADSR_STATE_HOLD;
                adsr->currentVolume = adsr->sLevel << 16;
                adsr->currentDelta = 0;
                break;
            }
        case ADSR_STATE_RELEASE:
            adsr->currentVolume = 0;
            ret = 1;
            break;
        }
        break;
    case ADSR_MODE_DLS:
        switch (adsr->state)
        {
        case ADSR_STATE_ATTACK:
            if ((adsr->cnt = adsr->aTime) != 0)
            {
                adsr->state = ADSR_STATE_DECAY;
                if (adsr->aMode == 0)
                {
                    adsr->currentVolume = 0;
                    adsr->currentDelta = 0x7fff0000 / adsr->cnt;
                }
                else
                {
                    adsr->currentIndex = 0;
                    adsr->currentVolume = 0;
                    adsr->currentDelta = 0xc10000 / adsr->cnt;
                }
                break;
            }
        case ADSR_STATE_DECAY:
            adsr->cnt = adsr->dTime * (((0xc1 - (u32)adsr->sLevel) << 16) / 0xc1) >> 16;
            if (adsr->cnt != 0)
            {
                adsr->state = ADSR_STATE_SUSTAIN;
                adsr->currentVolume = 0x7fff0000;
                adsr->currentIndex = 0xc10000;
                adsr->currentDelta = -(((0xc1 - (u32)adsr->sLevel) << 16) / adsr->cnt);
                break;
            }
        case ADSR_STATE_SUSTAIN:
            if (adsr->sLevel != 0)
            {
                int idx;

                adsr->state = ADSR_STATE_HOLD;
                adsr->currentIndex = adsr->sLevel << 16;
                if ((idx = 0xc1 - ((*(s32*)(state + 0xc) + 0x8000) >> 16)) < 0)
                {
                    idx = 0;
                }
                adsr->currentVolume = lbl_8032F618[idx] << 16;
                adsr->currentDelta = 0;
                break;
            }
        case ADSR_STATE_RELEASE:
            adsr->currentVolume = 0;
            ret = 1;
            break;
        }
        break;
    }
    return ret;
}

int adsrSetup(int state)
{
    ADSR_VARS* adsr = (ADSR_VARS*)state;
    adsr->state = ADSR_STATE_ATTACK;
    return fn_8027A660(state);
}

int adsrStartRelease(int state, u32 divisor)
{
    ADSR_VARS* adsr = (ADSR_VARS*)state;
    switch (adsr->mode)
    {
    case ADSR_MODE_LINEAR:
        adsr->state = ADSR_STATE_RELEASE;
        adsr->cnt = divisor;
        if (divisor == 0)
        {
            adsr->cnt = 1;
            adsr->currentDelta = 0;
            return 1;
        }
        adsr->currentDelta = -(adsr->currentVolume / divisor);
        break;
    case ADSR_MODE_DLS:
        if (adsr->aMode == 0 && adsr->state == ADSR_STATE_DECAY)
        {
            adsr->currentIndex = (u32)(193 - voiceAdsrDecayTable[*(int*)&adsr->currentVolume >> 21]) << 16;
        }
        {
            f32 ci = 3.238342e-4f * (f32)(s32)adsr->currentIndex;
            adsr->cnt = __cvt_fp2unsigned(ci * (f32)(u32)divisor) >> 12;
        }
        adsr->state = ADSR_STATE_RELEASE;
        if (adsr->cnt == 0)
        {
            adsr->cnt = 1;
            adsr->currentVolume = 0;
            adsr->currentIndex = 0;
            adsr->currentDelta = 0;
            return 1;
        }
        adsr->currentDelta = -(adsr->currentIndex / adsr->cnt);
        break;
    }
    return 0;
}

int adsrRelease(int state)
{
    ADSR_VARS* adsr = (ADSR_VARS*)state;
    switch (adsr->mode)
    {
    case ADSR_MODE_LINEAR:
    case ADSR_MODE_DLS:
        return adsrStartRelease(state, *(int*)&adsr->rTime);
    }
    return 0;
}

u32 adsrHandle(int state, u16* out1, u16* out2)
{
    ADSR_VARS* adsr = (ADSR_VARS*)state;
    int ret = 0;
    int m = adsr->mode;
    int v8;
    int idx;
    u16 outVal;

    switch (m)
    {
    case ADSR_MODE_LINEAR:
        if (adsr->state != ADSR_STATE_HOLD)
        {
            v8 = *(int*)&adsr->currentVolume;
            *(int*)&adsr->currentVolume = v8 + *(int*)&adsr->currentDelta;
            outVal = v8 >> 16;
            *out1 = outVal;
            if (*(int*)&adsr->currentDelta >= 0)
            {
                outVal = *(int*)&adsr->currentDelta >> 21;
                *out2 = outVal;
            }
            else
            {
                outVal = -(-*(int*)&adsr->currentDelta >> 21);
                *out2 = outVal;
            }
            if (--*(int*)&adsr->cnt == 0)
            {
                ret = fn_8027A660(state);
            }
        }
        else
        {
            outVal = *(int*)&adsr->currentVolume >> 16;
            *out1 = outVal;
            *out2 = 0;
        }
        break;
    case ADSR_MODE_DLS:
    {
        if (adsr->state != ADSR_STATE_HOLD)
        {
            v8 = *(int*)&adsr->currentVolume;
            if (adsr->aMode == 0 && adsr->state == ADSR_STATE_DECAY)
            {
                *(int*)&adsr->currentVolume = v8 + *(int*)&adsr->currentDelta;
            }
            else
            {
                *(int*)&adsr->currentIndex = *(int*)&adsr->currentIndex + *(int*)&adsr->currentDelta;
                idx = (*(int*)&adsr->currentIndex + 0x8000) >> 16;
                idx = 193 - idx;
                if (idx < 0)
                {
                    idx = 0;
                }
                *(int*)&adsr->currentVolume = lbl_8032F618[idx] << 16;
            }
            outVal = v8 >> 16;
            *out1 = outVal;
            if (*(int*)&adsr->currentVolume - v8 >= 0)
            {
                outVal = (*(int*)&adsr->currentVolume - v8) >> 21;
                *out2 = outVal;
            }
            else
            {
                outVal = -(-(*(int*)&adsr->currentVolume - v8) >> 21);
                *out2 = outVal;
            }
            if (--*(int*)&adsr->cnt == 0)
            {
                ret = fn_8027A660(state);
            }
        }
        else
        {
            outVal = *(int*)&adsr->currentVolume >> 16;
            *out1 = outVal;
            *out2 = 0;
        }
        break;
    }
    }
    return ret;
}

u32 adsrHandleLowPrecision(int state, u16* out1, u16* out2)
{
    u8 i;

    for (i = 0; i < 15; i++)
    {
        if (adsrHandle(state, out1, out2) != 0)
        {
            return 1;
        }
    }
    return 0;
}

#include "main/audio/adsr.h"
#include "main/audio/adsr_setup.h"
extern asm u32 __cvt_fp2unsigned(register f64 d);
extern int adsrStartRelease(int state, u32 divisor);
extern u8 voiceAdsrDecayTable[];
extern f32 lbl_803E7848;
extern u16 lbl_8032F618[];

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
            f32 ci = lbl_803E7848 * (f32)(s32)adsr->currentIndex;
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

/*
 * Wrapper for adsrStartRelease: dispatches when state mode is 0 or 1.
 *
 * EN v1.1 Address: 0x8027AA50, size 68b
 */
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

int adsrHandle(int state, u16* out1, u16* out2)
{
    ADSR_VARS* adsr = (ADSR_VARS*)state;
    int ret = 0;
    int m = adsr->mode;
    int v8;
    int idx;
    u16 o;

    switch (m)
    {
    case ADSR_MODE_LINEAR:
        if (adsr->state != ADSR_STATE_HOLD)
        {
            v8 = *(int*)&adsr->currentVolume;
            *(int*)&adsr->currentVolume = v8 + *(int*)&adsr->currentDelta;
            o = v8 >> 16;
            *out1 = o;
            if (*(int*)&adsr->currentDelta >= 0)
            {
                o = *(int*)&adsr->currentDelta >> 21;
                *out2 = o;
            }
            else
            {
                o = -(-*(int*)&adsr->currentDelta >> 21);
                *out2 = o;
            }
            if (--*(int*)&adsr->cnt == 0)
            {
                ret = fn_8027A660(state);
            }
        }
        else
        {
            o = *(int*)&adsr->currentVolume >> 16;
            *out1 = o;
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
            o = v8 >> 16;
            *out1 = o;
            if (*(int*)&adsr->currentVolume - v8 >= 0)
            {
                o = (*(int*)&adsr->currentVolume - v8) >> 21;
                *out2 = o;
            }
            else
            {
                o = -(-(*(int*)&adsr->currentVolume - v8) >> 21);
                *out2 = o;
            }
            if (--*(int*)&adsr->cnt == 0)
            {
                ret = fn_8027A660(state);
            }
        }
        else
        {
            o = *(int*)&adsr->currentVolume >> 16;
            *out1 = o;
            *out2 = 0;
        }
        break;
    }
    }
    return ret;
}

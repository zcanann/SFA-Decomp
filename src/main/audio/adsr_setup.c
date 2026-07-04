#include "main/audio/adsr.h"
#include "main/audio/adsr_setup.h"
extern u16 lbl_8032F618[];

/*
 * Advance an ADSR envelope state machine: phase 0 = attack setup,
 * 1 = decay setup, 2 = sustain setup, 4 = done. Mode 1 scales levels
 * by the 0xC1-step volume curve.
 */
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
                adsr->currentDelta =
                    -((0x7fff0000 - (adsr->sLevel << 16)) / adsr->dTime);
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
            adsr->cnt =
                adsr->dTime * (((0xc1 - (u32)adsr->sLevel) << 16) / 0xc1) >> 16;
            if (adsr->cnt != 0)
            {
                adsr->state = ADSR_STATE_SUSTAIN;
                adsr->currentVolume = 0x7fff0000;
                adsr->currentIndex = 0xc10000;
                adsr->currentDelta =
                    -(((0xc1 - (u32)adsr->sLevel) << 16) / adsr->cnt);
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

/*
 * Reset state's submode and call fn_8027A660.
 *
 * EN v1.1 Address: 0x8027A8D4, size 40b
 */
int adsrSetup(int state)
{
    ADSR_VARS* adsr = (ADSR_VARS*)state;
    adsr->state = ADSR_STATE_ATTACK;
    return fn_8027A660(state);
}

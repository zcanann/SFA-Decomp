#include "dolphin/axfx/reverb_std_create.h"
#include "string.h"
#include "main/audio/sal_dsp.h"
extern f32 powf(f32 x, f32 y);
s32 sReverbStdDelayLengths[4] = { 1789, 1999, 433, 149 };

static void DLsetdelay(AXFX_REVSTD_DELAYLINE *dl, s32 lag)
{
    dl->outPoint = dl->inPoint - (lag * 4);
    while (dl->outPoint < 0) {
        dl->outPoint += dl->length;
    }
}

static void DLcreate(AXFX_REVSTD_DELAYLINE *dl, s32 len)
{
    dl->length = len * 4;
    dl->inputs = salMalloc(len * 4);
    memset(dl->inputs, 0, len * 4);
    dl->lastOutput = 0.0f;
    DLsetdelay(dl, len >> 1);
    dl->inPoint = 0;
    dl->outPoint = 0;
}

#pragma exceptions on

int ReverbSTDCreate(AXFX_REVSTD_WORK *rv, f32 coloration, f32 time, f32 mix, f32 damping, f32 predelay)
{
    u8 i;
    u8 k;
    f32 timeFactor;

    if ((coloration < 0.0f) || (coloration > 1.0f) ||
        (time < 0.01f) || (time > 10.0f) ||
        (mix < 0.0f) || (mix > 1.0f) ||
        (damping < 0.0f) || (damping > 1.0f) ||
        (predelay < 0.0f) || (predelay > 0.1f)) {
        return 0;
    }

    memset(rv, 0, sizeof(AXFX_REVSTD_WORK));
    timeFactor = 32000.0f * time;

    for (k = 0; k < 3; k++) {
        for (i = 0; i < 2; i++) {
            DLcreate(&rv->C[i + k * 2], sReverbStdDelayLengths[i] + 2);
            DLsetdelay(&rv->C[i + k * 2], sReverbStdDelayLengths[i]);
            rv->combCoef[i + k * 2] =
                powf(10.0f, (sReverbStdDelayLengths[i] * -3) / timeFactor);
        }

        for (i = 0; i < 2; i++) {
            DLcreate(&rv->AP[i + k * 2], sReverbStdDelayLengths[i + 2] + 2);
            DLsetdelay(&rv->AP[i + k * 2], sReverbStdDelayLengths[i + 2]);
        }
        rv->lpLastout[k] = 0.0f;
    }

    rv->allPassCoeff = coloration;
    rv->level = mix;
    rv->damping = damping;
    if (rv->damping < 0.05f) {
        rv->damping = 0.05f;
    }
    {
        f32 damp = 0.8f * rv->damping;
        rv->damping = 1.0f - (0.05f + damp);
    }

    if (0.0f != predelay) {
        rv->preDelayTime = 32000.0f * predelay;
        for (i = 0; i < 3; i++) {
            rv->preDelayLine[i] = salMalloc(rv->preDelayTime * 4);
            memset(rv->preDelayLine[i], 0, rv->preDelayTime * 4);
            rv->preDelayPtr[i] = rv->preDelayLine[i];
        }
    } else {
        rv->preDelayTime = 0;
        for (i = 0; i < 3; i++) {
            rv->preDelayPtr[i] = 0;
            rv->preDelayLine[i] = 0;
        }
    }

    return 1;
}

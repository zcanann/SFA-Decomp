#include "ghidra_import.h"
#include "dolphin/axfx.h"

extern void *memset(void *dest, int val, u32 count);
extern void *salMalloc(u32 size);
extern f32 powf(f32 x, f32 y);
extern const s32 sReverbStdDelayLengths[4];
extern const f32 axfx_reverb_std_f32_0;
extern const f32 axfx_reverb_std_f32_1;
extern const f32 axfx_reverb_std_f32_0p01;
extern const f32 axfx_reverb_std_f32_10;
extern const f32 axfx_reverb_std_f32_0p1;
extern const f32 axfx_reverb_std_f32_32000;
extern const f32 axfx_reverb_std_f32_0p05;
extern const f32 axfx_reverb_std_f32_0p8;

int ReverbSTDCreate(AXFX_REVSTD_WORK *rv, f32 coloration, f32 time, f32 mix, f32 damping, f32 predelay)
{
    u8 i;
    u8 k;
    f32 timeFactor;
    s32 delay;
    AXFX_REVSTD_DELAYLINE *delayLine;

    if ((coloration < axfx_reverb_std_f32_0) || (coloration > axfx_reverb_std_f32_1) ||
        (time < axfx_reverb_std_f32_0p01) || (time > axfx_reverb_std_f32_10) ||
        (mix < axfx_reverb_std_f32_0) || (mix > axfx_reverb_std_f32_1) ||
        (damping < axfx_reverb_std_f32_0) || (damping > axfx_reverb_std_f32_1) ||
        (predelay < axfx_reverb_std_f32_0) || (predelay > axfx_reverb_std_f32_0p1)) {
        return 0;
    }

    memset(rv, 0, sizeof(AXFX_REVSTD_WORK));
    timeFactor = axfx_reverb_std_f32_32000 * time;

    for (k = 0; k < 3; k++) {
        for (i = 0; i < 2; i++) {
            delay = sReverbStdDelayLengths[i];
            delayLine = &rv->C[i + k * 2];
            delayLine->length = (delay + 2) * 4;
            delayLine->inputs = salMalloc(delayLine->length);
            memset(delayLine->inputs, 0, delayLine->length);
            delayLine->lastOutput = axfx_reverb_std_f32_0;
            delayLine->outPoint = delayLine->inPoint - (((delay + 2) >> 1) * 4);
            while (delayLine->outPoint < 0) {
                delayLine->outPoint += delayLine->length;
            }
            delayLine->inPoint = 0;
            delayLine->outPoint = 0;
            delayLine->outPoint = delayLine->inPoint - (delay * 4);
            while (delayLine->outPoint < 0) {
                delayLine->outPoint += delayLine->length;
            }
            rv->combCoef[i + k * 2] = powf(axfx_reverb_std_f32_10, (delay * -3) / timeFactor);
        }

        for (i = 0; i < 2; i++) {
            delay = sReverbStdDelayLengths[i + 2];
            delayLine = &rv->AP[i + k * 2];
            delayLine->length = (delay + 2) * 4;
            delayLine->inputs = salMalloc(delayLine->length);
            memset(delayLine->inputs, 0, delayLine->length);
            delayLine->lastOutput = axfx_reverb_std_f32_0;
            delayLine->outPoint = delayLine->inPoint - (((delay + 2) >> 1) * 4);
            while (delayLine->outPoint < 0) {
                delayLine->outPoint += delayLine->length;
            }
            delayLine->inPoint = 0;
            delayLine->outPoint = 0;
            delayLine->outPoint = delayLine->inPoint - (delay * 4);
            while (delayLine->outPoint < 0) {
                delayLine->outPoint += delayLine->length;
            }
        }
        rv->lpLastout[k] = axfx_reverb_std_f32_0;
    }

    rv->allPassCoeff = coloration;
    rv->level = mix;
    rv->damping = damping;
    if (rv->damping < axfx_reverb_std_f32_0p05) {
        rv->damping = axfx_reverb_std_f32_0p05;
    }
    rv->damping = axfx_reverb_std_f32_1 - (axfx_reverb_std_f32_0p05 + axfx_reverb_std_f32_0p8 * rv->damping);

    if (predelay == axfx_reverb_std_f32_0) {
        rv->preDelayTime = 0;
        for (i = 0; i < 3; i++) {
            rv->preDelayPtr[i] = 0;
            rv->preDelayLine[i] = 0;
        }
    } else {
        rv->preDelayTime = axfx_reverb_std_f32_32000 * predelay;
        for (i = 0; i < 3; i++) {
            rv->preDelayLine[i] = salMalloc(rv->preDelayTime * 4);
            memset(rv->preDelayLine[i], 0, rv->preDelayTime * 4);
            rv->preDelayPtr[i] = rv->preDelayLine[i];
        }
    }

    return 1;
}

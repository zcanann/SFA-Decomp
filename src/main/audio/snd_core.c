#include "main/audio/snd_core.h"
#include "main/audio/hw_init.h"
#include "main/audio/synth_control.h"

extern u8 lbl_803BD150[];
extern u8 lbl_803D3CA0[];
extern u8 gSynthInitialized;


extern void IFFifoAlloc(void);

extern double __frsqrte(double x);

#define MIDI_DIRTY_GROUP_STRIDE 0x40
#define MIDI_DIRTY_ENTRY_STRIDE 4

void sndQuit(void)
{
    hwExit();
    IFFifoAlloc();
    s3dExit();
    synthExit();
    gSynthInitialized = 0;
}

void sndSetMaxVoices(u8 valueA, u8 valueB)
{
    lbl_803BD150[0x211] = valueA;
    lbl_803BD150[0x212] = valueB;
}

u8 sndIsInstalled(void)
{
    return gSynthInitialized;
}

#pragma fp_contract off
void salApplyMatrix(f32* matrix, f32* vec, f32* out)
{
    out[0] = matrix[9] + (matrix[0] * vec[0] + matrix[1] * vec[1] + matrix[2] * vec[2]);
    out[1] = matrix[10] + (matrix[3] * vec[0] + matrix[4] * vec[1] + matrix[5] * vec[2]);
    out[2] = matrix[11] + (matrix[6] * vec[0] + matrix[7] * vec[1] + matrix[8] * vec[2]);
}
#pragma fp_contract reset

#pragma fp_contract off
extern inline f32 sqrtf(f32 x)
{
    static const f64 _half = .5;
    static const f64 _three = 3.0;
    volatile f32 y;
    if (x > 0.0f)
    {
        f64 guess = __frsqrte((f64)x);
        guess = _half * guess * (_three - guess * guess * x);
        guess = _half * guess * (_three - guess * guess * x);
        guess = _half * guess * (_three - guess * guess * x);
        y = (f32)(x * guess);
        return y;
    }
    return x;
}

f32 salNormalizeVector(f32* v)
{
    f32 len = sqrtf(v[0] * v[0] + v[1] * v[1] + v[2] * v[2]);
    v[0] /= len;
    v[1] /= len;
    v[2] /= len;
    return len;
}
#pragma fp_contract reset

void inpSetGlobalMIDIDirtyFlag(u8 index, u8 group, u32 flags)
{
    u8* groupBase;
    u8* entry;
    u32 offset;

    groupBase = lbl_803D3CA0 + group * MIDI_DIRTY_GROUP_STRIDE;
    offset = index * MIDI_DIRTY_ENTRY_STRIDE;
    entry = groupBase + offset;
    *(u32*)entry |= flags;
}

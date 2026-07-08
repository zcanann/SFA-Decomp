#include "main/audio/snd_reverb.h"

#pragma exceptions on

extern u32 gSalMallocHook[2];
extern void ReverbSTDCallback(int a, int b, int c, void* state);
extern int ReverbSTDCreate(void* state, f32 a, f32 b, f32 c, f32 d, f32 e);

void salFree(void* ptr)
{
    ((void (*)(void*))gSalMallocHook[1])(ptr);
}

void sndAuxCallbackReverbSTD(u8 mode, ReverbParams* params, ReverbState* state)
{
    switch ((int)mode)
    {
    case 0:
        if (state->enabled == 0)
        {
            ReverbSTDCallback(params->p0, params->p4, params->p8, state);
        }
        break;
    case 1:
        break;
    }
}

void sndAuxCallbackUpdateSettingsReverbSTD(ReverbState* state)
{
    state->enabled = 0;
    ReverbSTDCreate(state, state->a, state->b, state->c, state->d, state->e);
}

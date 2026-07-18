#include "dolphin/axfx/reverb_std_callback.h"
#include "dolphin/axfx/reverb_std_create.h"
#include "main/audio/snd_reverb.h"


extern u32 gSalMallocHook[2];

void salFree(void* ptr)
{
    ((void (*)(void*))gSalMallocHook[1])(ptr);
}

void sndAuxCallbackReverbSTD(u8 mode, ReverbParams* params, ReverbState* state)
{
    switch ((int)mode)
    {
    case 0:
        if (state->tempDisableFX == 0)
        {
            ReverbSTDCallback(params->left, params->right, params->surround, &state->rv);
        }
        break;
    case 1:
        break;
    }
}

void sndAuxCallbackUpdateSettingsReverbSTD(ReverbState* state)
{
    state->tempDisableFX = 0;
    ReverbSTDCreate(&state->rv, state->coloration, state->time, state->mix, state->damping, state->preDelay);
}

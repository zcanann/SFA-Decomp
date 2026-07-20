#include "dolphin/axfx/reverb_std_callback.h"
#include "dolphin/axfx/reverb_std_create.h"
#include "main/audio/hw_samplemem.h"
#include "main/audio/snd_reverb.h"

void salFree(void* ptr)
{
    salHooks.freeHook(ptr);
}

void sndAuxCallbackReverbSTD(u8 mode, SynthAuxInfo* info, void* user)
{
    ReverbState* state = user;

    switch ((int)mode)
    {
    case 0:
        if (state->tempDisableFX == 0)
        {
            ReverbSTDCallback(info->data.bufferUpdate.left, info->data.bufferUpdate.right,
                              info->data.bufferUpdate.surround, &state->rv);
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

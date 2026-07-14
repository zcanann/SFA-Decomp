#include "src/main/audio/synth_internal.h"

#pragma exceptions on

extern int vidGetInternalId(u32 id);
extern void inpSetMidiCtrl(u8 ctrl, u8 channel, u8 set, u8 value);
extern void inpSetMidiCtrl14(u8 ctrl, u8 channel, u8 set, u16 value);
extern void inpFXCopyCtrl(u8 controller, u32 dstHandle, u32 srcHandle);
extern void macSetExternalKeyoff(McmdVoiceState* slot);

/*
 * synthFXSetCtrl - sndFXCtrl underlying impl.
 * Walks the handle's voice-slot chain, dispatching inpSetMidiCtrl per slot.
 */
u32 synthFXSetCtrl(u32 handle, u8 controller, u8 value)
{
    u32 found;
    u8 idx;
    McmdVoiceState* slot;

    found = 0;
    handle = vidGetInternalId(handle);
    while (handle != 0xFFFFFFFFu)
    {
        idx = handle;
        if (handle == synthVoice[idx].voiceHandle)
        {
            slot = &synthVoice[idx];
            if ((SYNTH_VOICE_SLOT_FLAGS64(slot) & 2) != 0)
            {
                inpSetMidiCtrl(controller, idx, slot->startupMidiEvent, value);
            }
            else
            {
                inpSetMidiCtrl(controller, idx, slot->midiEvent, value);
            }
            found = 1;
            handle = synthVoice[idx].voiceNextHandle;
        }
        else
        {
            return found;
        }
    }
    return found;
}

/*
 * synthFXSetCtrl14 - sndFXCtrl14 underlying impl.
 */
u32 synthFXSetCtrl14(u32 handle, u8 controller, u16 value)
{
    u32 found;
    u8 idx;
    McmdVoiceState* slot;

    found = 0;
    handle = vidGetInternalId(handle);
    while (handle != 0xFFFFFFFFu)
    {
        idx = handle;
        if (handle == synthVoice[idx].voiceHandle)
        {
            slot = &synthVoice[idx];
            if ((SYNTH_VOICE_SLOT_FLAGS64(slot) & 2) != 0)
            {
                inpSetMidiCtrl14(controller, idx, slot->startupMidiEvent, value);
            }
            else
            {
                inpSetMidiCtrl14(controller, idx, slot->midiEvent, value);
            }
            found = 1;
            handle = synthVoice[idx].voiceNextHandle;
        }
        else
        {
            return found;
        }
    }
    return found;
}

/*
 * synthFXCloneMidiSetup - copies the five FX-stage controllers
 * (volume, pan, expression, reverb, chorus) between two handles.
 */
void synthFXCloneMidiSetup(u32 dstHandle, u32 srcHandle)
{
    inpFXCopyCtrl(0x07, dstHandle, srcHandle);
    inpFXCopyCtrl(0x0A, dstHandle, srcHandle);
    inpFXCopyCtrl(0x5B, dstHandle, srcHandle);
    inpFXCopyCtrl(0x80, dstHandle, srcHandle);
    inpFXCopyCtrl(0x84, dstHandle, srcHandle);
}

/*
 * synthSendKeyOff - sndFXKeyOff underlying impl.
 * Walks the handle's voice-slot chain and signals key-off on each slot.
 */
u32 synthSendKeyOff(u32 handle)
{
    u32 found;
    u32 idx;

    found = 0;
    if (gSynthInitialized != 0)
    {
        handle = vidGetInternalId(handle);
        while (handle != 0xFFFFFFFFu)
        {
            idx = (u8)handle;
            if (handle == synthVoice[idx].voiceHandle)
            {
                macSetExternalKeyoff(&synthVoice[idx]);
                found = 1;
            }
            handle = synthVoice[idx].voiceNextHandle;
        }
    }
    return found;
}

static inline void synthDispatchDelayedAction(SynthFade* fade)
{
    (void)fade;
}

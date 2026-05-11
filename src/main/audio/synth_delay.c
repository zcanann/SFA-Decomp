#include "src/main/audio/synth_internal.h"

extern s32 vidGetInternalId(u32 handle);
extern void inpSetMidiCtrl(u8 controller, u8 slot, u8 key, u8 value);
extern void inpSetMidiCtrl14(u8 controller, u8 slot, u8 key, u16 value);
extern void inpFXCopyCtrl(u8 controller, u32 dstHandle, u32 srcHandle);
extern void macSetExternalKeyoff(SynthVoiceSlot* slot);

extern u8* synthVoice;

/*
 * synthFXSetCtrl - sndFXCtrl underlying impl.
 * Walks the handle's voice-slot chain, dispatching inpSetMidiCtrl per slot.
 *
 * EN v1.0 Address: 0x8027186C, size 0xE8
 */
u32 synthFXSetCtrl(u32 handle, u8 controller, u8 value) {
    u32 found;
    u8 idx;
    SynthVoiceSlot* slot;

    found = 0;
    handle = vidGetInternalId(handle);
    while (handle != 0xFFFFFFFFu) {
        idx = (u8)handle;
        if (handle == *(u32*)(synthVoice + idx * 0x404 + 0xF4)) {
            slot = (SynthVoiceSlot*)(synthVoice + idx * 0x404);
            if ((SYNTH_VOICE_SLOT_FLAGS64(slot) & 2) != 0) {
                inpSetMidiCtrl(controller, idx, *(u8*)((u8*)slot + 0x20B), value);
            } else {
                inpSetMidiCtrl(controller, idx, *(u8*)((u8*)slot + 0x122), value);
            }
            found = 1;
            handle = *(u32*)(synthVoice + idx * 0x404 + 0xEC);
        } else {
            return found;
        }
    }
    return found;
}

/*
 * synthFXSetCtrl14 - sndFXCtrl14 underlying impl.
 *
 * EN v1.0 Address: 0x80271954, size 0xE8
 */
u32 synthFXSetCtrl14(u32 handle, u8 controller, u16 value) {
    u32 found;
    u8 idx;
    SynthVoiceSlot* slot;

    found = 0;
    handle = vidGetInternalId(handle);
    while (handle != 0xFFFFFFFFu) {
        idx = (u8)handle;
        if (handle == *(u32*)(synthVoice + idx * 0x404 + 0xF4)) {
            slot = (SynthVoiceSlot*)(synthVoice + idx * 0x404);
            if ((SYNTH_VOICE_SLOT_FLAGS64(slot) & 2) != 0) {
                inpSetMidiCtrl14(controller, idx, *(u8*)((u8*)slot + 0x20B), value);
            } else {
                inpSetMidiCtrl14(controller, idx, *(u8*)((u8*)slot + 0x122), value);
            }
            found = 1;
            handle = *(u32*)(synthVoice + idx * 0x404 + 0xEC);
        } else {
            return found;
        }
    }
    return found;
}

/*
 * synthFXCloneMidiSetup - copies the five FX-stage controllers
 * (volume, pan, expression, reverb, chorus) between two handles.
 *
 * EN v1.0 Address: 0x80271A3C, size 0x84
 */
void synthFXCloneMidiSetup(u32 dstHandle, u32 srcHandle) {
    inpFXCopyCtrl(0x07, dstHandle, srcHandle);
    inpFXCopyCtrl(0x0A, dstHandle, srcHandle);
    inpFXCopyCtrl(0x5B, dstHandle, srcHandle);
    inpFXCopyCtrl(0x80, dstHandle, srcHandle);
    inpFXCopyCtrl(0x84, dstHandle, srcHandle);
}

/*
 * synthSendKeyOff - sndFXKeyOff underlying impl.
 * Walks the handle's voice-slot chain and signals key-off on each slot.
 *
 * EN v1.0 Address: 0x80271AC0, size 0x8C
 */
u32 synthSendKeyOff(u32 handle) {
    u32 found;
    u32 idx;

    found = 0;
    if (gSynthInitialized != 0) {
        handle = vidGetInternalId(handle);
        while (handle != 0xFFFFFFFFu) {
            idx = (u8)handle;
            if (handle == *(u32*)(synthVoice + idx * 0x404 + 0xF4)) {
                macSetExternalKeyoff((SynthVoiceSlot*)(synthVoice + idx * 0x404));
                found = 1;
            }
            handle = *(u32*)(synthVoice + idx * 0x404 + 0xEC);
        }
    }
    return found;
}

/* Stub kept so synth_control.c can link; not in v1.0 binary at this address. */
#pragma dont_inline on
void synthDispatchDelayedAction(SynthFade* fade) {
    (void)fade;
}
#pragma dont_inline reset

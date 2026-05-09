#include "src/main/audio/synth_internal.h"

extern s32 vidGetInternalId(u32 handle);
extern void inpSetMidiCtrl(u8 controller, u8 slot, u8 key, u8 value);
extern void inpSetMidiCtrl14(u8 controller, u8 slot, u8 key, u32 value);
extern void inpFXCopyCtrl(u8 controller, u32 dstHandle, u32 srcHandle);
extern void audioFn_80278610(SynthVoiceSlot* slot);

extern u8* synthVoice;

/*
 * synthSetHandleControllerValue - sndFXCtrl underlying impl.
 * Walks the handle's voice-slot chain, dispatching inpSetMidiCtrl per slot.
 *
 * EN v1.0 Address: 0x8027186C, size 0xE8
 */
u32 synthSetHandleControllerValue(u32 handle, u8 controller, u8 value) {
    u32 found;
    u8 idx;
    u8* slotPtr;

    found = 0;
    handle = vidGetInternalId(handle);
    while (handle != 0xFFFFFFFFu) {
        idx = (u8)handle;
        if (handle == *(u32*)(synthVoice + idx * 0x404 + 0xF4)) {
            slotPtr = synthVoice + idx * 0x404;
            if ((*(u32*)(slotPtr + 0x118) & 2) != 0) {
                inpSetMidiCtrl(controller, idx, *(u8*)(slotPtr + 0x20B), value);
            } else {
                inpSetMidiCtrl(controller, idx, *(u8*)(slotPtr + 0x122), value);
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
 * synthSetHandleControllerValue14Bit - sndFXCtrl14 underlying impl.
 *
 * EN v1.0 Address: 0x80271954, size 0xE8
 */
u32 synthSetHandleControllerValue14Bit(u32 handle, u8 controller, u32 value) {
    u32 found;
    u8 idx;
    u8* slotPtr;

    found = 0;
    handle = vidGetInternalId(handle);
    while (handle != 0xFFFFFFFFu) {
        idx = (u8)handle;
        if (handle == *(u32*)(synthVoice + idx * 0x404 + 0xF4)) {
            slotPtr = synthVoice + idx * 0x404;
            if ((*(u32*)(slotPtr + 0x118) & 2) != 0) {
                inpSetMidiCtrl14(controller, idx, *(u8*)(slotPtr + 0x20B), value);
            } else {
                inpSetMidiCtrl14(controller, idx, *(u8*)(slotPtr + 0x122), value);
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
 * synthCopyHandleFXState - copies the five FX-stage controllers
 * (volume, pan, expression, reverb, chorus) between two handles.
 *
 * EN v1.0 Address: 0x80271A3C, size 0x84
 */
void synthCopyHandleFXState(u32 dstHandle, u32 srcHandle) {
    inpFXCopyCtrl(0x07, dstHandle, srcHandle);
    inpFXCopyCtrl(0x0A, dstHandle, srcHandle);
    inpFXCopyCtrl(0x5B, dstHandle, srcHandle);
    inpFXCopyCtrl(0x80, dstHandle, srcHandle);
    inpFXCopyCtrl(0x84, dstHandle, srcHandle);
}

/*
 * synthHandleKeyOff - sndFXKeyOff underlying impl.
 * Walks the handle's voice-slot chain and signals key-off on each slot.
 *
 * EN v1.0 Address: 0x80271AC0, size 0x8C
 */
u32 synthHandleKeyOff(u32 handle) {
    u32 found;
    u32 idx;

    found = 0;
    if (gSynthInitialized != 0) {
        handle = vidGetInternalId(handle);
        while (handle != 0xFFFFFFFFu) {
            idx = (u8)handle;
            if (handle == *(u32*)(synthVoice + idx * 0x404 + 0xF4)) {
                audioFn_80278610((SynthVoiceSlot*)(synthVoice + idx * 0x404));
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

#include "src/main/audio/synth_internal.h"

extern s32 vidGetInternalId(u32 handle);
extern void inpSetMidiCtrl(u8 controller, u8 slot, u8 key, u8 value);
extern void inpSetMidiCtrl14(u8 controller, u8 slot, u8 key, u32 value);
extern void inpFXCopyCtrl(u8 controller, u32 dstHandle, u32 srcHandle);
extern void fn_80278610(SynthVoiceSlot* slot);

extern u8* lbl_803DE268;

/*
 * synthSetHandleControllerValue — sndFXCtrl underlying impl.
 * Walks the handle's voice-slot chain, dispatching inpSetMidiCtrl per slot.
 *
 * EN v1.0 Address: 0x8027186C, size 0xE8
 */
u32 fn_8027186C(u32 handle, u8 controller, u8 value) {
    u32 found;
    u32 idx;
    u32 slotOffset;
    u8* base;

    found = 0;
    handle = vidGetInternalId(handle);
    while (handle != 0xFFFFFFFFu) {
        idx = (u8)handle;
        slotOffset = idx * 0x404;
        base = lbl_803DE268 + slotOffset;
        if (handle != *(u32*)(base + 0xF4)) {
            return found;
        }
        if (((*(u32*)(base + 0x114) & 0) ^ 0) | ((*(u32*)(base + 0x118) & 2) ^ 0)) {
            inpSetMidiCtrl(controller, idx, *(u8*)(base + 0x20B), value);
        } else {
            inpSetMidiCtrl(controller, idx, *(u8*)(base + 0x122), value);
        }
        found = 1;
        handle = *(u32*)(lbl_803DE268 + slotOffset + 0xEC);
    }
    return found;
}

/*
 * synthSetHandleControllerValue14Bit — sndFXCtrl14 underlying impl.
 *
 * EN v1.0 Address: 0x80271954, size 0xE8
 */
u32 fn_80271954(u32 handle, u8 controller, u32 value) {
    u32 found;
    u32 idx;
    u32 slotOffset;
    u8* base;

    found = 0;
    handle = vidGetInternalId(handle);
    while (handle != 0xFFFFFFFFu) {
        idx = (u8)handle;
        slotOffset = idx * 0x404;
        base = lbl_803DE268 + slotOffset;
        if (handle != *(u32*)(base + 0xF4)) {
            return found;
        }
        if (((*(u32*)(base + 0x114) & 0) ^ 0) | ((*(u32*)(base + 0x118) & 2) ^ 0)) {
            inpSetMidiCtrl14(controller, idx, *(u8*)(base + 0x20B), value);
        } else {
            inpSetMidiCtrl14(controller, idx, *(u8*)(base + 0x122), value);
        }
        found = 1;
        handle = *(u32*)(lbl_803DE268 + slotOffset + 0xEC);
    }
    return found;
}

/*
 * synthCopyHandleFXState — copies the five FX-stage controllers
 * (volume, pan, expression, reverb, chorus) between two handles.
 *
 * EN v1.0 Address: 0x80271A3C, size 0x84
 */
void fn_80271A3C(u32 dstHandle, u32 srcHandle) {
    inpFXCopyCtrl(0x07, dstHandle, srcHandle);
    inpFXCopyCtrl(0x0A, dstHandle, srcHandle);
    inpFXCopyCtrl(0x5B, dstHandle, srcHandle);
    inpFXCopyCtrl(0x80, dstHandle, srcHandle);
    inpFXCopyCtrl(0x84, dstHandle, srcHandle);
}

/*
 * synthHandleKeyOff — sndFXKeyOff underlying impl.
 * Walks the handle's voice-slot chain and signals key-off on each slot.
 *
 * EN v1.0 Address: 0x80271AC0, size 0x8C
 */
u32 fn_80271AC0(u32 handle) {
    u32 found;
    u32 idx;
    u32 slotOffset;
    u8* base;

    found = 0;
    if (gSynthInitialized != 0) {
        handle = vidGetInternalId(handle);
        while (handle != 0xFFFFFFFFu) {
            idx = (u8)handle;
            slotOffset = idx * 0x404;
            base = lbl_803DE268 + slotOffset;
            if (handle == *(u32*)(base + 0xF4)) {
                fn_80278610((SynthVoiceSlot*)base);
                found = 1;
            }
            handle = *(u32*)(lbl_803DE268 + slotOffset + 0xEC);
        }
    }
    return found;
}

/* Stub kept so synth_control.c can link — not in v1.0 binary at this address. */
#pragma dont_inline on
void synthDispatchDelayedAction(SynthFade* fade) {
    (void)fade;
}
#pragma dont_inline reset

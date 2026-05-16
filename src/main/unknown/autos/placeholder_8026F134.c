#include "ghidra_import.h"

extern u8 lbl_803BCD90[];
extern u8 lbl_803BD150[];
extern u8 *synthVoice;

extern u32 vidMakeNew(int state, int returnNewId);
extern void vidRemoveVoice(int state);
extern void voiceRegister(int state);
extern void inpSetMidiLastNote(u8 a, u8 b, u8 v);
extern u32 hwIsActive(u32 slot);

/*
 * fn_8026EC44 - large pre-pitch processing (~1736 instructions). Stubbed.
 */
#pragma dont_inline on
void fn_8026EC44(void) {}
#pragma dont_inline reset

/*
 * fn_8026F30C - 560-instr voice param helper. Stubbed.
 */
#pragma dont_inline on
void fn_8026F30C(void) {}
#pragma dont_inline reset

/*
 * Set one studio/channel scale entry.
 */
void synthSetStudioChannelScale(int value, u8 bank, u32 key)
{
    if (bank == 0xff) {
        bank = 8;
    }
    *(u32 *)(lbl_803BCD90 + bank * 0x40 + (key & 0xff) * 4) =
        (u32)((value << 3) * 0x600) / 0xf0;
}

/*
 * Look up an int from a 2D table indexed by state's ID bytes.
 *
 * EN v1.1 Address: 0x8026F584, size 52b
 */
int synthGetVoiceSlotChannelScale(u8 *state)
{
    u32 a = state[0x122];
    int b;
    if (a == 0xff) a = 8;
    b = state[0x123];
    return *(int *)(lbl_803BCD90 + a * 64 + b * 4);
}

/*
 * fn_8026F5B8 - flag-check and conditional store (~120 instructions).
 * Stubbed.
 */
void fn_8026F5B8(int state)
{
    u64 flags;

    flags = *(u64 *)(state + 0x114);
    if ((flags & 0x20000) != 0) {
        return;
    }
    if (*(u8 *)(state + 0x131) == 1) {
        if ((flags & 0x1000) == 0) {
            *(u32 *)(state + 0x13c) = 0;
        } else {
            *(u32 *)(state + 0x13c) = *(u32 *)(state + 0x134);
        }
    } else {
        *(u32 *)(state + 0x13c) = *(u32 *)(state + 0x134);
    }
    *(u32 *)(state + 0x138) = (u32)*(u8 *)(state + 0x130) << 0x10;
}

/*
 * Reuse an active voice matching the requested MIDI slot/channel.
 */
int audioFn_8026f630(u32 key, u32 slot, u32 channel, u32 voiceGroup, u32 *outFlags)
{
    u32 sawHeldVoice;
    int result;
    int offset;
    u32 i;
    u8 *voice;
    u8 *selectedVoice;
    u32 previousId;
    u64 flags;
    s32 bend;

    sawHeldVoice = 0;
    selectedVoice = 0;
    previousId = 0;
    result = -1;
    offset = 0;
    i = 0;
    voice = synthVoice;
    while (i < lbl_803BD150[0x210]) {
        if (*(u8 *)(voice + 0x11c) == 0 && *(u32 *)(voice + 0xf4) != 0xffffffff &&
            *(u8 *)(voice + 0x121) == (u8)slot && *(u8 *)(voice + 0x122) == (u8)channel) {
            flags = *(u64 *)(voice + 0x114);
            if ((flags & 2) != 0) {
                sawHeldVoice = 1;
            }
            if ((flags & 0x10) != 0 && (((flags & 8) ^ 8) | (flags & 0x10000000000ULL)) != 0 &&
                hwIsActive(i) != 0) {
                if (result == -1 && (flags & 0x20002) == 0x20002) {
                    *outFlags = 1;
                    return -1;
                }

                bend = ((s32)*(s8 *)(voice + 0x12e) << 16) / 100;
                *(u32 *)(voice + 0x138) = ((u32)*(u16 *)(voice + 0x12c) << 16) +
                                          (bend - (bend >> 31));
                *(u8 *)(voice + 0x130) = *(u16 *)(voice + 0x12c);
                *(u16 *)(voice + 0x12c) =
                    (u16)key + ((*(u16 *)(voice + 0x12c) & 0xff) - *(u8 *)(voice + 0x12f));
                *(u8 *)(voice + 0x12f) = key;
                *(u8 *)(voice + 0x12e) = 0;
                *(u32 *)(voice + 0x13c) = 0;
                *(u32 *)(voice + 0x118) |= 0x20000;
                vidRemoveVoice((int)(synthVoice + offset));
                selectedVoice = voice;
                if (result == -1) {
                    *(u32 *)(voice + 0xec) = 0xffffffff;
                    *(u32 *)(voice + 0xf0) = 0xffffffff;
                    result = vidMakeNew((int)(synthVoice + offset), voiceGroup);
                    previousId = *(u32 *)(voice + 0xf4);
                } else {
                    *(u32 *)(synthVoice + (previousId & 0xff) * 0x404 + 0xec) = *(u32 *)(voice + 0xf4);
                    *(u32 *)(voice + 0xf0) = previousId;
                    previousId = *(u32 *)(voice + 0xf4);
                    vidMakeNew((int)(synthVoice + offset), 0);
                }
            }
        }
        offset += 0x404;
        i++;
        voice += 0x404;
    }

    if (result == -1) {
        *outFlags = sawHeldVoice;
    } else {
        voiceRegister((int)selectedVoice);
        inpSetMidiLastNote(*(u8 *)(selectedVoice + 0x121), *(u8 *)(selectedVoice + 0x122),
                           *(u16 *)(selectedVoice + 0x12c) & 0xff);
        *outFlags = 0;
    }
    return result;
}

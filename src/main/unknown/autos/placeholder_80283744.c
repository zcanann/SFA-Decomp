#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283744.h"

extern u8 *volatile dspVoice;
extern u8 salTimeOffset;
extern u16 lbl_803DC618[4];
extern u16 lbl_803DC620[4];

#define DSP_VOICE_STRIDE 0xf4
#define DSP_VOICE_PITCH_CHANGE_FLAG 0x8
#define DSP_VOICE_SRC_TYPE_CHANGE_FLAG 0x100
#define DSP_VOICE_POLYPHASE_CHANGE_FLAG 0x80
#define DSP_VOICE_ITD_ENABLED_FLAG 0x80000000
#define DSP_VOICE_ITD_DISABLED_MASK 0x7fffffff
#define DSP_VOICE_ITD_CENTER 0x10

/*
 * --INFO--
 *
 * Function: hwSetPitch
 * EN v1.0 Address: 0x80283710
 * EN v1.0 Size: 120b
 */
void hwSetPitch(int slot, u32 pitch)
{
    u8 *entry;
    u8 *channelEntry;
    u32 val;
    u32 channel;

    entry = dspVoice + slot * DSP_VOICE_STRIDE;
    if ((u16)pitch >= 0x4000) {
        pitch = 0x3fff;
    }
    channel = entry[0xe4];
    if (channel != 0xff) {
        channel = channel << 2;
        channelEntry = entry + channel;
        val = *(u32 *)(channelEntry + 0x38);
        if (val == ((u16)pitch << 4)) {
            return;
        }
    }
    channel = salTimeOffset;
    pitch = (u16)pitch << 4;
    channel = channel << 2;
    channelEntry = entry + channel;
    *(u32 *)(channelEntry + 0x38) = pitch;
    channel = salTimeOffset;
    channel = channel << 2;
    channelEntry = entry + channel;
    val = *(u32 *)(channelEntry + 0x24);
    *(u32 *)(channelEntry + 0x24) = val | DSP_VOICE_PITCH_CHANGE_FLAG;
    entry[0xe4] = salTimeOffset;
}

/*
 * --INFO--
 *
 * Function: hwSetSRCType
 * EN v1.0 Address: 0x80283788
 * EN v1.0 Size: 44b
 */
void hwSetSRCType(int slot, u32 value)
{
    u8 *entry = dspVoice + slot * DSP_VOICE_STRIDE;
    *(u16 *)(entry + 0xcc) = lbl_803DC618[(u8)value];
    *(u32 *)(entry + 0x24) |= DSP_VOICE_SRC_TYPE_CHANGE_FLAG;
}

/*
 * --INFO--
 *
 * Function: hwSetPolyPhaseFilter
 * EN v1.0 Address: 0x802837B4
 * EN v1.0 Size: 44b
 */
void hwSetPolyPhaseFilter(int slot, u32 value)
{
    u8 *entry = dspVoice + slot * DSP_VOICE_STRIDE;
    *(u16 *)(entry + 0xce) = lbl_803DC620[(u8)value];
    *(u32 *)(entry + 0x24) |= DSP_VOICE_POLYPHASE_CHANGE_FLAG;
}

/*
 * --INFO--
 *
 * Function: hwSetITDMode
 * EN v1.0 Address: 0x802837E0
 * EN v1.0 Size: 92b
 */
asm void hwSetITDMode(register int slot, register u32 value)
{
    nofralloc
    clrlwi. r0, r4, 24
    bne disabled
    mulli r5, r3, 0xf4
    lwz r0, dspVoice(r0)
    add r3, r0, r5
    lwz r0, 0xf0(r3)
    li r4, 0x10
    oris r0, r0, 0x8000
    stw r0, 0xf0(r3)
    lwz r0, dspVoice(r0)
    add r3, r0, r5
    sth r4, 0xd0(r3)
    lwz r0, dspVoice(r0)
    add r3, r0, r5
    sth r4, 0xd2(r3)
    blr
disabled:
    mulli r0, r3, 0xf4
    lwz r3, dspVoice(r0)
    add r3, r3, r0
    lwz r0, 0xf0(r3)
    clrlwi r0, r0, 1
    stw r0, 0xf0(r3)
    blr
}

#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283744.h"

extern u8 *volatile lbl_803DE344;
extern u8 lbl_803DE370;
extern u16 lbl_803DC618[4];
extern u16 lbl_803DC620[4];

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

    entry = lbl_803DE344 + slot * 0xf4;
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
    channel = lbl_803DE370;
    pitch = (u16)pitch << 4;
    channel = channel << 2;
    channelEntry = entry + channel;
    *(u32 *)(channelEntry + 0x38) = pitch;
    channel = lbl_803DE370;
    channel = channel << 2;
    channelEntry = entry + channel;
    val = *(u32 *)(channelEntry + 0x24);
    *(u32 *)(channelEntry + 0x24) = val | 0x8;
    entry[0xe4] = lbl_803DE370;
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
    u8 *entry = lbl_803DE344 + slot * 0xf4;
    *(u16 *)(entry + 0xcc) = lbl_803DC618[(u8)value];
    *(u32 *)(entry + 0x24) |= 0x100;
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
    u8 *entry = lbl_803DE344 + slot * 0xf4;
    *(u16 *)(entry + 0xce) = lbl_803DC620[(u8)value];
    *(u32 *)(entry + 0x24) |= 0x80;
}

/*
 * --INFO--
 *
 * Function: hwSetITDMode
 * EN v1.0 Address: 0x802837E0
 * EN v1.0 Size: 92b
 */
void hwSetITDMode(int slot, u32 value)
{
    u32 offset;
    u8 *entry;
    u32 flags;
    u16 center;

    if ((u8)value == 0) {
        offset = slot * 0xf4;
        entry = lbl_803DE344 + offset;
        flags = *(u32 *)(entry + 0xf0);
        center = 0x10;
        *(u32 *)(entry + 0xf0) = flags | 0x80000000;
        entry = lbl_803DE344 + offset;
        *(u16 *)(entry + 0xd0) = center;
        entry = lbl_803DE344 + offset;
        *(u16 *)(entry + 0xd2) = center;
    } else {
        entry = lbl_803DE344 + slot * 0xf4;
        *(u32 *)(entry + 0xf0) &= 0x7fffffff;
    }
}

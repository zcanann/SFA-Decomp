#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802836F4.h"

extern u8 *lbl_803DE344;
extern u8 lbl_803DE370;

/*
 * --INFO--
 *
 * Function: hwKeyOff
 * EN v1.0 Address: 0x802836E8
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802836F4
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off
void hwKeyOff(int slot)
{
  u8 *entry;
  u32 offset;

  slot *= 0xf4;
  entry = lbl_803DE344 + slot;
  offset = lbl_803DE370 << 2;
  entry += offset;
  *(u32 *)(entry + 0x24) |= 0x40;
}
#pragma peephole reset
#pragma scheduling reset

#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283488.h"

extern undefined4 FUN_80281a34();
extern uint FUN_80282070();
extern uint FUN_80282fe4();
extern u8 *lbl_803DE344;
extern u8 lbl_803DE370;

/*
 * --INFO--
 *
 * Function: hwBreak
 * EN v1.0 Address: 0x8028343C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80283488
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwBreak(int slot)
{
  u8 *entry;
  u32 offset;
  u32 channel;

  offset = slot * 0xf4;
  entry = lbl_803DE344 + offset;
  if ((entry[0xec] == 1) && (lbl_803DE370 == 0)) {
    entry[0xee] = 1;
  }
  entry = lbl_803DE344;
  channel = lbl_803DE370;
  channel <<= 2;
  entry += offset;
  entry += channel;
  *(u32 *)(entry + 0x24) |= 0x20;
}

/*
 * --INFO--
 *
 * Function: FUN_80283444
 * EN v1.0 Address: 0x80283444
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283528
 * EN v1.1 Size: 152b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80283444(int param_1,uint param_2,short param_3)
{
}

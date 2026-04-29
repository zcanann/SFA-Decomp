#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283BA0.h"

extern u8 lbl_803CC1E0[];
extern void fn_8027F020(void *entry);

/*
 * --INFO--
 *
 * Function: fn_80283BA0
 * EN v1.0 Address: 0x80283BA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283BA0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void fn_80283BA0(u8 index)
{
  fn_8027F020(lbl_803CC1E0 + index * 0xbc);
}
#pragma scheduling reset

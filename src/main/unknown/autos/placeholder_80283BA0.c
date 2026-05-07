#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80283BA0.h"

extern u8 lbl_803CC1E0[];
extern void salAddStudioInput(void *entry);

/*
 * --INFO--
 *
 * Function: hwAddInput
 * EN v1.0 Address: 0x80283BA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80283BA0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwAddInput(u8 index)
{
  salAddStudioInput(lbl_803CC1E0 + index * 0xbc);
}

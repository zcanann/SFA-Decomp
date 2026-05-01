#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_802836E4.h"

extern void fn_8027EF1C(void *entry);
extern u8 *lbl_803DE344;
extern u8 lbl_803DE370;

/*
 * --INFO--
 *
 * Function: hwStart
 * EN v1.0 Address: 0x802836AC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802836E4
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void hwStart(int slot)
{
  u8 *entry;
  u32 offset;

  offset = slot * 0xf4;
  entry = lbl_803DE344;
  entry += offset;
  entry[0xd4] = lbl_803DE370;
  entry = lbl_803DE344;
  entry += offset;
  fn_8027EF1C(entry);
}

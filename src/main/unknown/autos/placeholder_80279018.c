#include "ghidra_import.h"
#include "main/unknown/autos/placeholder_80279018.h"

extern undefined4 FUN_80271a90();

extern u32 *lbl_803DE2F4;
extern undefined4 DAT_803def58;
extern undefined4 DAT_803def60;
extern undefined4 DAT_803def64;

/*
 * --INFO--
 *
 * Function: fn_80279004
 * EN v1.0 Address: 0x80279004
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80279018
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
u32 *fn_80279004(u32 key)
{
  u32 *node;
  u32 value;

  node = lbl_803DE2F4;
  while (node != NULL) {
    value = node[2];
    if (value == key) {
      return node;
    }
    if (value > key) {
      break;
    }
    node = (u32 *)node[0];
  }
  return NULL;
}

/*
 * --INFO--
 *
 * Function: FUN_80279008
 * EN v1.0 Address: 0x80279008
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x802790F4
 * EN v1.1 Size: 264b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80279008(int *param_1)
{
}

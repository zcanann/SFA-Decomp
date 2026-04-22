#include "ghidra_import.h"
#include "main/dll/dll_C5.h"

extern undefined4 FUN_8000fb0c();

extern undefined4 DAT_803de19c;

/*
 * --INFO--
 *
 * Function: FUN_80102354
 * EN v1.0 Address: 0x80102354
 * EN v1.0 Size: 84b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80102354(int param_1,int param_2)
{
  if (*(char *)(DAT_803de19c + 0x13b) < param_1) {
    *(char *)(DAT_803de19c + 0x13b) = (char)param_1;
    *(undefined *)(DAT_803de19c + 0x13c) = 2;
    if (param_2 != 0) {
      FUN_8000fb0c((short)param_1);
    }
  }
  return;
}

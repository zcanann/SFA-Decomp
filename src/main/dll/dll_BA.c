#include "ghidra_import.h"
#include "main/dll/dll_BA.h"

extern undefined4 DAT_803de19c;

/*
 * --INFO--
 *
 * Function: FUN_80101c10
 * EN v1.0 Address: 0x80101C10
 * EN v1.0 Size: 12b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80101c10(undefined param_1)
{
  *(undefined *)(DAT_803de19c + 0x139) = param_1;
  return;
}

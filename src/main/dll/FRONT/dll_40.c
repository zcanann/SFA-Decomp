#include "ghidra_import.h"
#include "main/dll/FRONT/dll_40.h"

extern undefined4 FUN_80244758();

extern undefined4 DAT_803a694c;

/*
 * --INFO--
 *
 * Function: FUN_80118e30
 * EN v1.0 Address: 0x80118C88
 * EN v1.0 Size: 44b
 * EN v1.1 Address: 0x80118E30
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80118e30(undefined4 param_1)
{
  FUN_80244758((int *)&DAT_803a694c,param_1,1);
  return;
}

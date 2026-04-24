#include "ghidra_import.h"
#include "main/expr.h"

extern undefined4 FUN_8003b9ec();

/*
 * --INFO--
 *
 * Function: FUN_801ff044
 * EN v1.0 Address: 0x801FEB30
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x801FF044
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801ff044(int param_1)
{
  char cVar1;
  char in_r8;
  
  if ((((in_r8 != '\0') && (cVar1 = *(char *)(*(int *)(param_1 + 0xb8) + 0x118), cVar1 != '\f')) &&
      (cVar1 != '\x04')) && (cVar1 != '\v')) {
    FUN_8003b9ec(param_1);
  }
  return;
}

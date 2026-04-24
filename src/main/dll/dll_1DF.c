#include "ghidra_import.h"
#include "main/dll/dll_1DF.h"

extern undefined4 FUN_80038524();
extern undefined4 FUN_8003b9ec();

/*
 * --INFO--
 *
 * Function: FUN_801d23ac
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x801D23AC
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d23ac(int param_1)
{
  char in_r8;
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
    FUN_80038524(param_1,0,(float *)(iVar1 + 0x20),(undefined4 *)(iVar1 + 0x24),
                 (float *)(iVar1 + 0x28),0);
  }
  return;
}

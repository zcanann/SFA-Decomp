#include "ghidra_import.h"
#include "main/dll/CR/CRfueltank.h"

extern undefined4 FUN_8003b9ec();

/*
 * --INFO--
 *
 * Function: FUN_801e3a44
 * EN v1.0 Address: 0x801E3A44
 * EN v1.0 Size: 108b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e3a44(int param_1)
{
  char in_r8;
  
  if ((((*(int *)(param_1 + 0x30) == 0) || (*(short *)(*(int *)(param_1 + 0x30) + 0x46) != 0x139))
      && (in_r8 != '\0')) &&
     ((*(char *)(*(int *)(param_1 + 0xb8) + 0xc) != '\0' &&
      (*(char *)(*(int *)(param_1 + 0xb8) + 0xd) != '\0')))) {
    FUN_8003b9ec(param_1);
  }
  return;
}

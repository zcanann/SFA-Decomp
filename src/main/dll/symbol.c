#include "ghidra_import.h"
#include "main/dll/symbol.h"

extern undefined4 FUN_8003b9ec();

extern undefined4* DAT_803dd6f0;
extern undefined4* DAT_803dd6fc;

/*
 * --INFO--
 *
 * Function: FUN_801cb298
 * EN v1.0 Address: 0x801CB298
 * EN v1.0 Size: 104b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cb298(void)
{
  (**(code **)(*DAT_803dd6fc + 0x18))();
  (**(code **)(*DAT_803dd6f0 + 0x38))(3,0);
  (**(code **)(*DAT_803dd6f0 + 0x38))(2,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801cb300
 * EN v1.0 Address: 0x801CB300
 * EN v1.0 Size: 52b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801cb300(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b9ec(param_1);
  }
  return;
}

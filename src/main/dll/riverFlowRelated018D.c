#include "ghidra_import.h"
#include "main/dll/riverFlowRelated018D.h"

extern undefined4 FUN_80017620();
extern undefined4 FUN_80037180();

extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de810;

/*
 * --INFO--
 *
 * Function: FUN_801bec70
 * EN v1.0 Address: 0x801BEC70
 * EN v1.0 Size: 112b
 * EN v1.1 Address: 0x801BEE40
 * EN v1.1 Size: 108b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801bec70(int param_1)
{
  undefined4 uVar1;
  
  uVar1 = *(undefined4 *)(param_1 + 0xb8);
  FUN_80037180(param_1,3);
  (**(code **)(*DAT_803dd738 + 0x40))(param_1,uVar1,1);
  if (DAT_803de810 != 0) {
    FUN_80017620(DAT_803de810);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: dimbosstonsil_release
 * EN v1.0 Address: 0x801BEE60
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void dimbosstonsil_release(void)
{
}
